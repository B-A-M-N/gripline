package terminator

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/freeinference/gripline/internal/credential"
	"github.com/freeinference/gripline/internal/evidence"
	"github.com/freeinference/gripline/internal/lane"
	"github.com/freeinference/gripline/internal/policy"
	"github.com/freeinference/gripline/internal/principal"
	"github.com/freeinference/gripline/internal/resource"
	"github.com/freeinference/gripline/internal/risk"
	"github.com/freeinference/gripline/internal/secret"
)

// Outcome describes one terminated request's admission decision. It never
// carries a raw secret (INV-3).
type Outcome struct {
	RequestID  string
	Authorized bool
	Reason     string       // safe, non-secret denial/status reason
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
	Signer   *Signer
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
	seq  *seqGen
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
	if dep.RiskNow == nil {
		dep.RiskNow = time.Now
	}
	if dep.LaneNow == nil {
		dep.LaneNow = time.Now
	}
	return &Terminator{dep: dep, rand: newRequestID, seq: &seqGen{}}, nil
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
	_ = lerr

	// Policy gates with fixed precedence (§58): blocked lane → deny.
	if !t.policyOk(laneRec, cred) {
		out.Authorized = false
		out.Reason = "denied_by_policy"
		out.DenialErr = ErrorPolicyDenied
		return out
	}

	// Synchronous evidence + deterministic risk (§38).
	syncEv := t.synchronousEvidence(laneNew)
	val := risk.Evaluate(syncEv, t.dep.RiskNow())
	out.RiskAfter = val
	out.Evidence = evCodes(syncEv)

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
	}

	assertion, err := t.issueAssertion(ctx, reqID, cred)
	if err != nil {
		out.Authorized = false
		out.Reason = "internal_identity_failure"
		out.DenialErr = err
		return out
	}
	out.Assertion = assertion
	out.Authorized = true
	out.Reason = "authorized"
	return out
}

// SDK-facing errors.
var (
	ErrorPolicyDenied       = errors.New("terminator: denied by policy")
	ErrorConcurrencyLimit   = errors.New("terminator: concurrency limit")
)

// authenticate derives the verifier under each active pepper version and
// resolves the credential (INV-13: revoked never authenticates).
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
		if rec.Status == credential.StatusRevoked {
			return nil, credential.RevokedError
		}
		return credFrom(rec), nil
	}
	// During pepper rotation, try older active versions.
	for v := 0; v < latest; v++ {
		if k, ok := t.dep.Peppers.Get(v); ok {
			vv := presented.DigestHMAC(k)
			if rec, found := t.dep.Registry.FindByVerifier(vv, v); found {
				if rec.Status == credential.StatusRevoked {
					return nil, credential.RevokedError
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

// shortTag derives a stable short tag from the dominant feature for lane IDs.
func shortTag(f lane.Features) string {
	if f.NetworkASN != "" {
		return safeTag(f.NetworkASN)
	}
	if f.RegionClass != "" {
		return safeTag(f.RegionClass)
	}
	return "n"
}

func safeTag(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('x')
		}
		if b.Len() >= 12 {
			break
		}
	}
	return b.String()
}

// policyOk applies fixed-precedence policy gates (§58): a BLOCKED lane denies.
func (t *Terminator) policyOk(laneRec *lane.LaneRecord, _ *credential.Credential) bool {
	return laneRec == nil || laneRec.State != lane.StateBlocked
}

func safeReason(err error) string {
	if err == nil {
		return ""
	}
	switch err {
	case credential.RevokedError:
		return "credential_revoked"
	case credential.UnknownError:
		return "invalid_credential"
	default:
		if isExtractionError(err) {
			return "invalid_authentication"
		}
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
// a novelty signal when a new lane was first observed.
func (t *Terminator) synchronousEvidence(laneNew bool) []evidence.Evidence {
	if !laneNew {
		return nil
	}
	now := t.dep.RiskNow()
	return []evidence.Evidence{{
		Code: "NEW_LANE", Family: evidence.FamilyClientNovelty, Scope: evidence.ScopeLane,
		Score: 5, Confidence: 40, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}}
}

// evCodes reduces evidence to their codes for the Outcome's explainability.
func evCodes(items []evidence.Evidence) []string {
	out := make([]string, 0, len(items))
	for _, e := range items {
		out = append(out, e.Code)
	}
	return out
}