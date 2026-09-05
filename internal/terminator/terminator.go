package terminator

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/principal"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/risk"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// Outcome describes one terminated request's admission decision. It never
// carries a raw secret (INV-3).
type Outcome struct {
	RequestID  string
	Authorized bool
	Reason     string // safe, non-secret denial/status reason
	DenialErr  error
	Principal  principal.Principal
	Context    principal.AuthorizedContext
	Assertion  *Assertion
	Lease      *resource.LeaseHandle // non-nil when authorized; proxy releases on completion
	RiskAfter  int
	Evidence   []string // evidence codes that contributed (explainability)
	LaneNew    bool
}

// Dependencies are the seams the terminator needs. Provider-specific behavior
// lives behind these interfaces (spec §66-69) so the security core stays
// agnostic.
type Dependencies struct {
	Registry credential.Registry
	Peppers  *credential.PepperRing
	Lanes    *lane.Store
	Policy   *policy.Policy
	Signer   AssertionSigner
	Audience string

	RiskNow func() time.Time
	LaneNow func() time.Time

	// Concurrency is the hard-limit seam: acquire and release concurrency for a
	// scope. Implementations bound per scope, keyed by scope id. INV-9: hard
	// limits remain active even if adaptive risk is unavailable.
	Concurrency resourceController
}

// resourceController abstracts concurrency admission per scope.
type resourceController interface {
	Acquire(scope string) *resource.LeaseHandle
}

// Terminator is the credential-termination admission engine.
type Terminator struct {
	dep  Dependencies
	rand func() string // injectable request-id generator for deterministic tests
}

// New builds a Terminator and validates the critical seams.
func New(dep Dependencies) (*Terminator, error) {
	if dep.Registry == nil {
		return nil, errors.New("terminator: registry required")
	}
	if dep.Peppers == nil {
		return nil, errors.New("terminator: pepper ring required")
	}
	if dep.Policy == nil {
		return nil, errors.New("terminator: policy required")
	}
	if dep.Signer == nil {
		return nil, errors.New("terminator: signer required")
	}
	if dep.Audience == "" {
		return nil, errors.New("terminator: audience required (INV-11)")
	}
	if !dep.Policy.IsValid() {
		// §57: the data plane loads only authenticated + validated policy. An
		// invalid revision (bad threshold ordering, TTL out of bounds) must
		// fail construction, not silently enforce garbage.
		return nil, errors.New("terminator: policy revision invalid (§57)")
	}
	if dep.RiskNow == nil {
		dep.RiskNow = time.Now
	}
	if dep.LaneNow == nil {
		dep.LaneNow = time.Now
	}
	return &Terminator{dep: dep, rand: newRequestID}, nil
}

// seqGen is a concurrency-safe monotonic counter for request-id uniqueness.
type seqGen struct {
	mu sync.Mutex
	n  int64
}

func (s *seqGen) next() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return s.n
}

// newRequestID returns a unique, non-secret request id (§71).
func newRequestID() string {
	return fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), seqShared.next())
}

// seqShared is the package-level counter behind the default request-id generator.
var seqShared = &seqGen{}

// Admit runs the fast-path admission flow (spec §53) for a request's secret
// carriers and normalized feature set. The returned Outcome carries the
// AuthorizedContext (no secret) and, when authorized, the signed internal
// assertion plus the concurrency lease for the proxy to release on completion.
//
// On exit the presented secret is always zeroed (deferred), regardless of
// outcome (INV-3).
func (t *Terminator) Admit(headers map[string][]string, feat lane.Features) *Outcome {
	reqID := t.rand()
	out := &Outcome{RequestID: reqID}

	presented, _, err := ExtractExternalCredential(headers)
	// Strip secret headers immediately after the extraction attempt, in every
	// outcome, so no downstream view (including an error path) carries them (§18,
	// INV-12). This runs before the error return below.
	StripSecretHeaders(headers)
	if err != nil {
		out.Authorized = false
		out.Reason = safeReason(err)
		out.DenialErr = err
		return out
	}
	// The raw secret lives only within this call and is destroyed on exit.
	defer presented.Zero()

	cred, err := t.authenticate(presented)
	if err != nil {
		out.Authorized = false
		out.Reason = safeReason(err)
		out.DenialErr = err
		return out
	}

	prin := principal.Principal{
		AccountID:          cred.AccountID,
		CredentialID:       cred.CredentialID,
		PolicyID:           cred.PolicyID,
		PlanID:             cred.PlanID,
		CredentialStatus:   cred.Status.String(),
		CredentialRevision: cred.Revision,
	}

	laneID, laneRec, laneNew, lerr := t.classifyLane(cred.CredentialID, feat)
	laneState := laneStateName(laneRec)
	// Lane explosion (§28) and lane-id collisions (§24, insert-only) are attack
	// signals: fail closed, not open.
	if lerr != nil {
		out.Authorized = false
		if errors.Is(lerr, lane.ErrLaneConflict) {
			out.Reason = "lane_conflict"
		} else {
			out.Reason = "lane_limit_exceeded"
		}
		out.DenialErr = lerr
		return out
	}

	// Policy gates with fixed precedence (§58). Synchronous evidence and risk
	// are derived first so the risk-state gate sees the current request; the
	// resolver then picks the most severe applicable denial, and a more
	// permissive lower-level rule can never override it.
	syncEv := t.synchronousEvidence(laneNew)
	val := risk.Evaluate(syncEv, t.dep.RiskNow())
	out.RiskAfter = val
	out.Evidence = evCodes(syncEv)

	if denial := t.evaluatePolicy(laneRec, cred, val); denial != nil {
		out.Authorized = false
		out.Reason = denialReason(denial)
		out.DenialErr = denial
		return out
	}

	ctx := principal.AuthorizedContext{
		Principal:          prin,
		LaneID:             laneID,
		LaneState:          laneState,
		AuthorizationScope: principal.ScopeLane,
		RiskState:          val,
		AuthorizedAt:       time.Now(),
	}
	out.Principal = prin
	out.Context = ctx
	out.LaneNew = laneNew

	// Hard concurrency admission (INV-6, INV-9): verify before lease.
	if t.dep.Concurrency != nil {
		lease := t.dep.Concurrency.Acquire("cred:" + cred.CredentialID)
		if lease == nil {
			out.Authorized = false
			out.Reason = "concurrency_limit"
			out.DenialErr = ErrorConcurrencyLimit
			return out
		}
		out.Lease = lease
		// INV-15 / §48: a failure after lease acquisition must not leak the
		// slot. If assertion issuance fails, release before returning.
		assertion, err := t.issueAssertion(ctx, reqID, cred)
		if err != nil {
			lease.Release()
			out.Lease = nil
			out.Authorized = false
			out.Reason = "internal_identity_failure"
			out.DenialErr = err
			return out
		}
		out.Assertion = assertion
	} else {
		assertion, err := t.issueAssertion(ctx, reqID, cred)
		if err != nil {
			out.Authorized = false
			out.Reason = "internal_identity_failure"
			out.DenialErr = err
			return out
		}
		out.Assertion = assertion
	}
	out.Authorized = true
	out.Reason = "authorized"
	return out
}

// SDK-facing errors.
var (
	ErrorPolicyDenied     = errors.New("terminator: denied by policy")
	ErrorConcurrencyLimit = errors.New("terminator: concurrency limit")
)

// authenticate derives the verifier under each active pepper version and
// resolves the credential. INV-13 (revoked never authenticates), §30
// (quarantined denied at authentication), and §75 (expired denied) all gate
// BEFORE any lane/resource/policy state — a credential that fails its own gate
// cannot ride on permissive downstream state (INV-6).
func (t *Terminator) authenticate(presented *secret.SealedSecret) (*credential.Credential, error) {
	latest := t.dep.Peppers.Latest()
	if latest < 0 {
		return nil, errors.New("terminator: no active pepper keys")
	}
	key, ok := t.dep.Peppers.Get(latest)
	if !ok {
		return nil, errors.New("terminator: missing latest pepper")
	}
	verifier := presented.DigestHMAC(key)
	if rec, found := t.dep.Registry.FindByVerifier(verifier, latest); found {
		if err := rec.Authenticatable(t.dep.RiskNow()); err != nil {
			return nil, err
		}
		return credFrom(rec), nil
	}
	// During pepper rotation, try older active versions.
	for v := 0; v < latest; v++ {
		if k, ok := t.dep.Peppers.Get(v); ok {
			vv := presented.DigestHMAC(k)
			if rec, found := t.dep.Registry.FindByVerifier(vv, v); found {
				if err := rec.Authenticatable(t.dep.RiskNow()); err != nil {
					return nil, err
				}
				return credFrom(rec), nil
			}
		}
	}
	return nil, credential.UnknownError
}

func credFrom(rec *credential.CredentialRecord) *credential.Credential {
	return &credential.Credential{
		CredentialID: rec.CredentialID,
		AccountID:    rec.AccountID,
		PolicyID:     rec.PolicyID,
		PlanID:       rec.PlanID,
		Status:       rec.Status,
		Revision:     rec.Revision,
	}
}

// classifyLane assigns/creates a lane for the request, deterministic on the
// feature vector + policy revision (§26).
func (t *Terminator) classifyLane(credID string, feat lane.Features) (string, *lane.LaneRecord, bool, error) {
	if t.dep.Lanes == nil {
		return "lane_" + credID, nil, false, nil
	}
	laneID := "lane_" + credID + "_" + shortTag(feat)
	rec, created, err := t.dep.Lanes.BorrowOrCreate(credID, laneID, feat, lane.DefaultThresholds())
	if err != nil {
		return laneID, nil, false, err
	}
	return rec.LaneID, rec, created, nil
}

// shortTag derives a stable tag for lane IDs from the full feature vector.
// It hashes every feature (not just the dominant one, and without truncating
// the dominant one) so two distinct feature sets cannot derive the same lane
// id — a truncation collision would either overwrite an existing lane's state
// (a state-reset laundering attack, §24) or wedge the store. Lane ids remain
// deterministic for a given feature vector (§26); the tag is opaque, and the
// authoritative lane record keeps the readable feature classes.
func shortTag(f lane.Features) string {
	var b strings.Builder
	for _, part := range []string{
		f.NetworkASN, f.NetworkType, f.RegionClass, f.ClientFamily,
		f.SDKFamily, f.HTTPVersion, f.Streaming, f.ModelFamily,
		f.ConcurrencyPattern, f.EndpointFamily,
	} {
		b.WriteString(part)
		b.WriteByte(0x1f) // unit separator: unambiguous field delimiter
	}
	sum := sha256.Sum256([]byte(b.String()))
	return base64.RawURLEncoding.EncodeToString(sum[:10]) // 80-bit tag
}

// evaluatePolicy applies the fixed-precedence enforcement resolver (§58). It
// consults only the state the fast path has already resolved: credential status
// (revoked/quarantined were already denied at authentication), lane state
// (BLOCKED → lane hard denial), and the current risk score against the
// policy's risk-state boundaries (§31 thresholds from policy, not constants).
func (t *Terminator) evaluatePolicy(laneRec *lane.LaneRecord, cred *credential.Credential, riskScore int) error {
	thresholds := t.dep.Policy.Risk
	in := policy.EvalInput{
		CredentialRevoked: cred.Status == credential.StatusRevoked,
		// QUARANTINED credential → credential-scope denial (§30).
		Emergency: cred.Status == credential.StatusQuarantined,
		// A BLOCKED lane is a lane-scope hard denial (§24).
		LaneOverLimit: laneRec != nil && laneRec.State == lane.StateBlocked,
		// Risk-state restriction: risk at/above the policy's constrained
		// boundary restricts; at/above quarantine denies outright.
		RiskDenied: riskScore >= thresholds.Quarantine,
	}
	return t.dep.Policy.Evaluate(in)
}

// denialReason maps a policy denial to a safe external reason string (§70: no
// detailed security reasoning is disclosed).
func denialReason(err error) string {
	switch {
	case errors.Is(err, policy.ErrRevoked):
		return "credential_revoked"
	case errors.Is(err, policy.ErrEmergencyBlock):
		return "credential_restricted"
	case errors.Is(err, policy.ErrSourceBlock):
		return "source_restricted"
	case errors.Is(err, policy.ErrAccountLimit):
		return "rate_limit"
	case errors.Is(err, policy.ErrCredentialLimit):
		return "rate_limit"
	case errors.Is(err, policy.ErrLaneLimit):
		return "lane_restricted"
	case errors.Is(err, policy.ErrRiskDenial):
		return "temporarily_restricted"
	default:
		return "denied_by_policy"
	}
}

func safeReason(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, credential.RevokedError):
		return "credential_revoked"
	case errors.Is(err, credential.CredentialQuarantinedError):
		return "credential_restricted"
	case errors.Is(err, credential.CredentialExpiredError):
		return "credential_expired"
	case errors.Is(err, credential.UnknownError):
		return "invalid_credential"
	case isExtractionError(err):
		return "invalid_authentication"
	default:
		return "denied"
	}
}

func laneStateName(rec *lane.LaneRecord) string {
	if rec == nil {
		return "NEW"
	}
	return rec.State.String()
}

// issueAssertion mints and signs the internal identity for the context.
func (t *Terminator) issueAssertion(ctx principal.AuthorizedContext, reqID string, cred *credential.Credential) (*Assertion, error) {
	ttl := time.Duration(t.dep.Policy.MaxIdentityTTLSeconds()) * time.Second
	return t.dep.Signer.Issue(Claims{
		Subject:   ctx.Principal.AccountID,
		CredID:    ctx.Principal.CredentialID,
		LaneID:    ctx.LaneID,
		Audience:  t.dep.Audience,
		JTI:       reqID,
		PolicyRev: t.dep.Policy.Revision,
		CredRev:   cred.Revision,
		Scope:     []string{"inference"},
	}, ttl)
}

// synchronousEvidence derives the minimal request-shaped evidence for the MVP:
// a novelty signal when a new lane was first observed. Evidence parameters come
// from the versioned evidence table — not hardcoded — so policy tuning applies
// (§38: offline recommendations become explicit versioned policy before they
// affect authorization).
func (t *Terminator) synchronousEvidence(laneNew bool) []evidence.Evidence {
	if !laneNew {
		return nil
	}
	now := t.dep.RiskNow()
	rule, ok := evidence.DefaultTable()["NEW_LANE"]
	if !ok {
		// The table removed the rule → no evidence; never invent parameters here.
		return nil
	}
	ev := evidence.Evidence{
		EvidenceID:     t.rand(),
		Code:           rule.Code,
		Family:         rule.Family,
		Scope:          rule.Scope,
		Score:          rule.Score,
		Severity:       rule.Severity,
		Confidence:     rule.Confidence,
		CreatedAt:      now,
		PolicyRevision: t.dep.Policy.Revision,
	}
	// rule.TTL <= 0 means "does not self-expire": mint a zero ExpiresAt, which
	// Evidence.Valid treats as unbounded. Minting now.Add(0) would instead
	// create evidence that expires immediately after creation.
	if rule.TTL > 0 {
		ev.ExpiresAt = now.Add(rule.TTL)
	}
	return []evidence.Evidence{ev}
}

// evCodes reduces evidence to their codes for the Outcome's explainability.
func evCodes(items []evidence.Evidence) []string {
	out := make([]string, 0, len(items))
	for _, e := range items {
		out = append(out, e.Code)
	}
	return out
}
