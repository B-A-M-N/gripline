package terminator

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/principal"
	"github.com/B-A-M-N/gripline/internal/producers"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
)

func resourceSpec(l policy.Limits) resource.BucketSpec {
	return resource.BucketSpec{
		ConcurrencyCap: l.ConcurrencyCap,
		RequestsBurst: resource.BucketConfig{
			Capacity: float64(l.Requests.Capacity), RefillPer: float64(l.Requests.RefillPer), RefillIn: l.Requests.RefillIn,
		},
		TokensBurst: resource.BucketConfig{
			Capacity: float64(l.Tokens.Capacity), RefillPer: float64(l.Tokens.RefillPer), RefillIn: l.Tokens.RefillIn,
		},
		CostBurst: resource.BucketConfig{
			Capacity: float64(l.Cost.Capacity), RefillPer: float64(l.Cost.RefillPer), RefillIn: l.Cost.RefillIn,
		},
	}
}

func resourceSpecEnabled(spec resource.BucketSpec) bool {
	return spec.ConcurrencyCap > 0 || spec.RequestsBurst.Capacity > 0 || spec.TokensBurst.Capacity > 0 || spec.CostBurst.Capacity > 0
}

// pruneEvidence prunes expired evidence for the relevant subjects. It is a
// no-op on failure — pruning is optimization-only.
// P0.7 fix: accepts source subjects too.
func (t *Terminator) pruneEvidence(ctx context.Context, now time.Time, credSubjects, laneSubjects []evidence.SubjectKey, sourceSubjects ...evidence.SubjectKey) {
	if t.dep.Evidence == nil {
		return
	}
	allSubjects := make([]evidence.SubjectKey, 0, len(credSubjects)+len(laneSubjects)+len(sourceSubjects))
	allSubjects = append(allSubjects, credSubjects...)
	allSubjects = append(allSubjects, laneSubjects...)
	for _, s := range sourceSubjects {
		if s.ID != "" {
			allSubjects = append(allSubjects, s)
		}
	}
	_, _ = pruneEvidenceContext(ctx, t.dep.Evidence, allSubjects, now)
}

// finalizeBaseline applies one deferred clean-activity credit (P0.27): counters
// advance and promotion is evaluated — including the P0.26 disqualifying-
// evidence veto, computed NOW (at completion) against live evidence, not at
// admission. Called only from BaselineToken.Finalize, which owns idempotency.
func (t *Terminator) finalizeBaseline(ctx context.Context, b *BaselineToken) {
	now := t.dep.RiskNow()
	pol := b.policy
	if pol == nil {
		pol = t.pol
	}
	promCrit := lane.PromotionCriteria{
		MinCleanAge:              pol.Learning.MinCleanAge,
		MinCleanRequests:         pol.Learning.MinCleanRequests,
		MinCleanActiveDays:       pol.Learning.MinCleanActiveDays,
		MaxEstablishmentRisk:     pol.Learning.MaxEstablishmentRisk,
		AllowNewLanes:            pol.Learning.AllowNewLanes,
		AllowSuspicious:          pol.Learning.AllowSuspiciousLanes,
		HasDisqualifyingEvidence: t.hasActiveDisqualifyingEvidence(ctx, pol, b.CredentialID, b.LaneID, now),
	}
	meta := lane.TransitionMetadata{RequestID: b.RequestID, PolicyRevision: b.PolicyRevision, EvidenceCodes: b.EvidenceCodes}
	lanePolicy := lanePolicyContext(pol)
	var err error
	if aware, ok := t.dep.Lanes.(lane.PolicyAwareRepository); ok {
		_, _, err = aware.RecordCleanAuthorizedAndPromoteWithPolicy(ctx, b.CredentialID, b.LaneID, b.LaneRisk, promCrit, now, lanePolicy, meta)
	} else if aware, ok := t.dep.Lanes.(lane.MetadataAwareRepository); ok {
		_, _, err = aware.RecordCleanAuthorizedAndPromoteWithMetadata(b.CredentialID, b.LaneID, b.LaneRisk, promCrit, now, meta)
	} else if aware, ok := t.dep.Lanes.(lane.RequestAwareRepository); ok {
		_, _, err = aware.RecordCleanAuthorizedAndPromoteWithRequestID(b.CredentialID, b.LaneID, b.LaneRisk, promCrit, now, b.RequestID)
	} else {
		_, _, err = t.dep.Lanes.RecordCleanAuthorizedAndPromote(b.CredentialID, b.LaneID, b.LaneRisk, promCrit, now)
	}
	if err != nil && t.baselineFinalizeFailure != nil {
		t.baselineFinalizeFailure.Add(1)
	}
}

// scopedSignals is the result of resolving one batch of signal CODES into
// minted, scoped evidence: a flattened persist set plus per-scope current
// request sets, so a signal crossed ON THIS REQUEST can restrict the same
// request at the correct scope (P0.8) without waiting for a later snapshot.
type scopedSignals struct {
	persisted  []evidence.Evidence
	source     []evidence.Evidence
	lane       []evidence.Evidence
	credential []evidence.Evidence
}

// resolveSignals is the ONE signal-to-evidence path (P0.8). Spray and producer
// signals both reduce to a code; each code's scope and parameters come from the
// CURRENT compiled policy (P0.12) and the subject is resolved from the request
// context — the caller of a signal never decides the eventual evidence subject.
// A code with no rule in this revision, or whose scope's subject is unavailable
// (e.g. no source configured), resolves to nothing (fail-closed).
func (t *Terminator) resolveSignals(codes []string, subjects producers.SubjectContext, now time.Time) scopedSignals {
	var out scopedSignals
	for _, code := range codes {
		rule, ok := t.pol.EvidenceRules[code]
		if !ok {
			continue
		}
		subjectID, ok := producers.ResolveSubject(rule.Scope, subjects)
		if !ok {
			continue
		}
		ev, err := evidence.Mint(t.pol.EvidenceRules, code, subjectID, now, t.pol.Revision)
		if err != nil {
			continue
		}
		out.persisted = append(out.persisted, ev)
		switch rule.Scope {
		case evidence.ScopeSource:
			out.source = append(out.source, ev)
		case evidence.ScopeLane:
			out.lane = append(out.lane, ev)
		case evidence.ScopeCredential:
			out.credential = append(out.credential, ev)
		}
	}
	return out
}

// producerCodes flattens producer signals to their evidence codes.
func producerCodes(sigs []producers.Signal) []string {
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s.Code)
	}
	return out
}

// sprayCodes flattens spray-detector signals to their evidence codes.
func sprayCodes(sigs []anomaly.Signal) []string {
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s.Code)
	}
	return out
}

// observeCompletion drives the completion-time producers (P0.4A) with the
// ACTUAL usage of a finished request and persists any scoped evidence they emit.
// Completion signals affect SUBSEQUENT admissions — never the request that just
// finished. Persistence is best-effort: an evidence store outage or a
// non-compiled rule simply skips that signal; the finished request is not
// re-evaluated (it already ran).
func (t *Terminator) observeCompletion(ctx context.Context, pol *policy.CompiledPolicy, subjects producers.SubjectContext, actual resource.UsageEstimate, success bool) CompletionResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(t.dep.Producers) == 0 {
		return CompletionResult{}
	}
	if pol == nil {
		pol = t.pol
	}
	behavior := producers.CompletionBehavior{
		Subjects: subjects,
		Actual: producers.UsageEstimate{
			// resource.UsageEstimate is the settled governor amount; the producer
			// surface exposes the token/cost dims as int64.
			Combined: actual.CombinedTokens,
			Cost:     actual.CostMicrounits,
		},
		Success: success,
	}
	var codes []string
	persisted := false
	var minted []evidence.Evidence
	if t.dep.Evidence != nil {
		minted = make([]evidence.Evidence, 0, 4)
	}
	for _, prod := range t.dep.Producers {
		var sigs []producers.Signal
		if contextual, ok := prod.(producers.ContextProducer); ok {
			sigs = contextual.ObserveCompletionContext(ctx, behavior)
		} else {
			sigs = prod.ObserveCompletion(behavior)
		}
		for _, sig := range sigs {
			rule, ok := pol.EvidenceRules[sig.Code]
			if !ok {
				continue // not compiled into the active policy — ignore
			}
			subjectID, ok := producers.ResolveSubject(rule.Scope, subjects)
			if !ok {
				continue // scope's subject unavailable (e.g. no source) — skip
			}
			ev, err := evidence.Mint(pol.EvidenceRules, sig.Code, subjectID, t.dep.RiskNow(), pol.Revision)
			if err != nil {
				continue
			}
			codes = append(codes, sig.Code)
			if minted != nil {
				minted = append(minted, ev)
			}
		}
	}
	if len(minted) > 0 {
		if err := appendEvidenceContext(ctx, t.dep.Evidence, minted...); err == nil {
			persisted = true
		} else if t.evidenceAppendFailure != nil {
			t.evidenceAppendFailure.Add(1)
		}
	}
	result := CompletionResult{EvidenceCodes: codes, Persisted: persisted}
	if codes != nil && t.dep.Evidence != nil && !persisted {
		// Signals were produced but the durable append failed — surface it so the
		// caller can observe the liveness/monitoring concern, without treating it
		// as a control-plane error for an already-finished request.
		result.Err = evidenceAppendError{}
	}
	return result
}

// evidenceAppendError is a sentinel wrapper for a completion whose signals could
// not be persisted. It is observational, not a re-evaluation error.
type evidenceAppendError struct{}

func (evidenceAppendError) Error() string { return "terminator: completion evidence append failed" }

// hasActiveDisqualifyingEvidence reports whether any currently-active evidence
// against the lane or its credential carries a code on the policy's
// disqualifying list (P0.26). A store outage here must NOT fail open into
// "no disqualifying evidence" — it conservatively vetoes (fail-closed): an
// unavailable history is unknown, and unknown blocks trust-building.
func (t *Terminator) hasActiveDisqualifyingEvidence(ctx context.Context, pol *policy.CompiledPolicy, credID, laneID string, now time.Time) bool {
	if pol == nil {
		pol = t.pol
	}
	if len(pol.Learning.DisqualifyingEvidenceCodes) == 0 {
		return false
	}
	if t.dep.Evidence == nil {
		// No evidence store configured: no ACTIVE evidence exists anywhere, so
		// there is nothing to disqualify — this is a real answer, not an outage.
		return false
	}
	subjects := []evidence.SubjectKey{
		{Scope: evidence.ScopeLane, ID: laneID},
		{Scope: evidence.ScopeCredential, ID: credID},
	}
	snap, err := snapshotEvidenceContext(ctx, t.dep.Evidence, subjects, now)
	if err != nil {
		// History unavailable → unknown → veto. Trust-building stops during an
		// evidence outage; it resumes when the store is readable again.
		return true
	}
	dq := make(map[string]struct{}, len(pol.Learning.DisqualifyingEvidenceCodes))
	for _, c := range pol.Learning.DisqualifyingEvidenceCodes {
		dq[c] = struct{}{}
	}
	for _, ev := range snap {
		if _, hit := dq[ev.Code]; hit {
			return true
		}
	}
	return false
}

// selectLimits chooses resource limits based on the resulting credential state.
// Only CONSTRAINED gets the constrained limits. WATCH stays on normal limits
// per requirement #7 — collapsing WATCH into resource restriction would lose
// the semantic distinction between the two states.
func (t *Terminator) selectLimits(status credential.Status) policy.Limits {
	switch status {
	case credential.StatusConstrained:
		return t.pol.Limits.Constrained
	default:
		return t.pol.Limits.Normal
	}
}

// emergencyLimits returns the policy's Emergency limit set (P0.48), falling
// back to Constrained when the policy leaves it zero (a deployment that did
// not author an emergency profile must never see lockdown grant MORE headroom
// than the constrained posture).
func (t *Terminator) emergencyLimits() policy.Limits {
	if t.pol.Limits.Emergency != nil {
		return *t.pol.Limits.Emergency
	}
	return t.pol.Limits.Constrained
}

// SDK-facing errors.
var (
	ErrorPolicyDenied     = errors.New("terminator: denied by policy")
	ErrorConcurrencyLimit = errors.New("terminator: concurrency limit")
	// ErrorLaneBlocked is returned when a lane's risk-driven security status is
	// BLOCKED (lane-scoped block, P0.7).
	ErrorLaneBlocked = errors.New("terminator: lane blocked")
	// ErrorEmergencyLockdown is returned when the operator control plane is in
	// EMERGENCY_LOCKDOWN and the request demands a NEW lane (P0.40).
	ErrorEmergencyLockdown = errors.New("terminator: emergency lockdown denies new lanes")
)

// authenticate derives the verifier under each active pepper version and
// resolves the credential. INV-13 (revoked never authenticates), §30
// (quarantined denied at authentication), and §75 (expired denied) all gate
// BEFORE any lane/resource/policy state.
//
// P0.29: verifiers are derived via PepperRing.DeriveVerifier — the ring folds
// the presented secret internally; the terminator never extracts pepper key
// bytes to call DigestHMAC itself.
//
// P0.28: when the registry implements the typed VerifierLookup seam, an
// outage/timeout/corruption is DISTINCT from an unknown credential. An
// unavailable registry is a degraded-admission signal: unknown credentials
// fail closed as before (ErrUnknown), but the error is typed
// LookupUnavailableError so callers/policy can distinguish spray traffic from
// a backend outage instead of treating every miss as "no such credential".
func (t *Terminator) authenticate(ctx context.Context, presented *secret.SealedSecret) (*credential.Credential, error) {
	latest := t.dep.Peppers.Latest()
	if latest < 0 {
		return nil, errors.New("terminator: no active pepper keys")
	}
	verifier := t.dep.Peppers.DeriveVerifier(presented, latest)
	if rec, err := t.lookupVerifier(ctx, verifier, latest); err == nil {
		if aerr := rec.Authenticatable(t.dep.RiskNow()); aerr != nil {
			// P0.50: the credential WAS identified even though its status
			// denies authentication (revoked/quarantined/expired). Return the
			// record alongside the error so the decision trace can attribute
			// the denial to the principal — the most audit-critical denials
			// were previously anonymous.
			return credFrom(rec), aerr
		}
		return credFrom(rec), nil
	} else if !errors.Is(err, credential.ErrNotFound) {
		// Unavailable/timeout/corrupt: NOT an unknown credential. Fail closed
		// with the typed error — degraded posture, never "no such credential".
		return nil, err
	}
	versions := t.dep.Peppers.Versions()
	for i := len(versions) - 2; i >= 0; i-- {
		v := versions[i]
		vv := t.dep.Peppers.DeriveVerifier(presented, v)
		if rec, err := t.lookupVerifier(ctx, vv, v); err == nil {
			if aerr := rec.Authenticatable(t.dep.RiskNow()); aerr != nil {
				return credFrom(rec), aerr
			}
			// Opportunistically migrate a successful legacy match into the
			// latest pepper version. The CAS update is best-effort for the
			// current request; authentication remains valid if a concurrent
			// lifecycle mutation wins the race.
			return credFrom(t.migrateVerifier(ctx, rec, verifier, latest)), nil
		} else if !errors.Is(err, credential.ErrNotFound) {
			return nil, err
		}
	}
	return nil, credential.ErrUnknown
}

func (t *Terminator) migrateVerifier(ctx context.Context, rec *credential.CredentialRecord, verifier []byte, latest int) *credential.CredentialRecord {
	if rec == nil || rec.PepperVersion == latest {
		return rec
	}
	if rotator, ok := t.dep.Registry.(credential.ContextVerifierRotator); ok {
		updated, err := rotator.RotateVerifierCASContext(ctx, rec.CredentialID, rec.Revision, latest, verifier)
		if err == nil {
			return updated
		}
		return rec
	}
	rotator, ok := t.dep.Registry.(credential.VerifierRotator)
	if !ok {
		return rec
	}
	updated, err := rotator.RotateVerifierCAS(rec.CredentialID, rec.Revision, latest, verifier)
	if err != nil {
		return rec
	}
	return updated
}

// lookupVerifier resolves a derived verifier through the typed seam (P0.28)
// when the registry implements it, else through the legacy bool API (all
// misses become ErrNotFound — the legacy semantics).
func (t *Terminator) lookupVerifier(ctx context.Context, verifier []byte, pepperVersion int) (*credential.CredentialRecord, error) {
	if lu, ok := t.dep.Registry.(credential.VerifierLookup); ok {
		return lu.FindByVerifierContext(ctx, verifier, pepperVersion)
	}
	if rec, found := t.dep.Registry.FindByVerifier(verifier, pepperVersion); found {
		return rec, nil
	}
	return nil, credential.ErrNotFound
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

// cleanupRemovedLaneResources mirrors lane retention with the governor's
// resource-table lifecycle. Lane rows may be deleted by BorrowOrCreate while
// resolving an incoming request; their resource objects must be removed only
// after the row disappears and only when all accounting is idle.
func cleanupRemovedLaneResources(ctx context.Context, g resource.Authority, before, after []string) {
	if g == nil || len(before) == 0 {
		return
	}
	remaining := make(map[string]struct{}, len(after))
	for _, id := range after {
		remaining[id] = struct{}{}
	}
	for _, id := range before {
		if _, ok := remaining[id]; !ok {
			if diagnostic, ok := g.(resource.ContextDiagnosticsAuthority); ok {
				_, _ = diagnostic.RemoveScopeContext(ctx, resource.ScopeLane, id)
				continue
			}
			_ = g.RemoveScope(resource.ScopeLane, id)
		}
	}
}

// classifyLane assigns/creates a lane for the request, deterministic on the
// feature vector + policy revision (§26).
func (t *Terminator) classifyLane(ctx context.Context, credID string, feat lane.Features) (string, *lane.LaneRecord, bool, []string, bool, error) {
	if t.dep.Lanes == nil {
		return "lane_" + credID, nil, false, nil, false, nil
	}
	// P0.21: the lane ID hashes the feature schema AND the classification
	// universe revision, not just the feature vector. Re-keying classification
	// semantics therefore creates a NEW lane universe (new IDs) instead of
	// silently reusing lanes matched under different thresholds.
	laneID := "lane_" + credID + "_" + laneTag(lane.FeatSchemaVersion, t.pol.ClassificationRevision, feat)
	// P0.11: classify against the COMPILED policy revision's cutoffs AND its
	// classification universe, not the package-global
	// lane.DefaultThresholds(), so anti-laundering sensitivity
	// (MinComparableWeight etc.) and re-keying are policy-tunable and versioned.
	classification := lanePolicyContext(t.pol)
	var rec *lane.LaneRecord
	var created bool
	var deleted []string
	changeAware := false
	var err error
	if aware, ok := t.dep.Lanes.(lane.ChangeAwareRepository); ok {
		rec, created, deleted, err = aware.BorrowOrCreateWithPolicyChanges(ctx, credID, laneID, feat, classification)
		changeAware = true
	} else if aware, ok := t.dep.Lanes.(lane.PolicyAwareRepository); ok {
		rec, created, err = aware.BorrowOrCreateWithPolicy(ctx, credID, laneID, feat, classification)
	} else {
		rec, created, err = t.dep.Lanes.BorrowOrCreate(credID, laneID, feat, classification.Classification)
	}
	if err != nil {
		return laneID, nil, false, deleted, changeAware, err
	}
	return rec.LaneID, rec, created, deleted, changeAware, nil
}

// laneTag derives a deterministic tag for lane IDs from the feature schema
// revision, the classification-universe revision (P0.21), and the full feature
// vector. Including the two revisions means a schema or classification change
// re-keys the lane universe; requesting the same vector under a new universe
// legitimately produces a new lane rather than reusing a mismatchable record.
func laneTag(featureSchema, classificationRevision int, f lane.Features) string {
	var b strings.Builder
	fmt.Fprintf(&b, "schema=%d;classrev=%d;", featureSchema, classificationRevision)
	for _, part := range []string{
		f.NetworkASN, f.NetworkType, f.RegionClass, f.ClientFamily,
		f.SDKFamily, f.HTTPVersion, f.Streaming, f.ModelFamily,
		f.ConcurrencyPattern, f.EndpointFamily,
	} {
		b.WriteString(part)
		b.WriteByte(0x1f)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return base64.RawURLEncoding.EncodeToString(sum[:10])
}

// shortTag derives a stable tag for lane IDs from the full feature vector
// alone (legacy compatibility: some callers / tests still key lane IDs on the
// vector without a classification universe). Prefer laneTag.
func shortTag(f lane.Features) string {
	return laneTag(lane.FeatSchemaVersion, currentClassificationRevisionLegacy, f)
}

// currentClassificationRevisionLegacy keeps legacy shortTag callers aligned
// with the default lane universe so pre-P0.21 lane IDs remain stable.
const currentClassificationRevisionLegacy = 1

// denialReason maps a policy denial to a safe external reason string (§70).
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
	case errors.Is(err, credential.ErrRevoked):
		return "credential_revoked"
	case errors.Is(err, credential.ErrQuarantined):
		return "credential_restricted"
	case errors.Is(err, credential.ErrExpired):
		return "credential_expired"
	case errors.Is(err, credential.ErrUnknown):
		return "invalid_credential"
	case isExtractionError(err):
		return "invalid_authentication"
	default:
		return "denied"
	}
}

// issueAssertion mints and signs the internal identity for the context.
func (t *Terminator) issueAssertion(ctx principal.AuthorizedContext, reqID string, cred *credential.Credential) (*Assertion, error) {
	ttl := time.Duration(t.pol.MaxIdentityTTLSeconds()) * time.Second
	return t.dep.Signer.Issue(Claims{
		Subject:     ctx.Principal.AccountID,
		CredID:      ctx.Principal.CredentialID,
		LaneID:      ctx.LaneID,
		Audience:    t.dep.Audience,
		JTI:         reqID,
		PolicyRev:   t.pol.Revision,
		PolicyEpoch: t.policyEpoch,
		CredRev:     cred.Revision,
		Scope:       []string{"inference"},
	}, ttl)
}

// synchronousEvidence derives evidence for a new lane. Evidence parameters
// come from the versioned evidence table (not hardcoded). The SubjectID is
// set to the actual lane ID so evidence is properly scoped.
func (t *Terminator) synchronousEvidence(laneNew bool, laneID string) []evidence.Evidence {
	if !laneNew {
		return nil
	}
	now := t.dep.RiskNow()
	// Mint (P0.4) is the ONLY sanctioned producer: every security-relevant field
	// — family, scope, score, severity, confidence, correlation group, TTL — is
	// populated from the versioned rule table, never hand-built here.
	//
	// P0.11: the rule table comes from the COMPILED policy revision
	// (t.pol.EvidenceRules), not the package-global evidence.DefaultTable, so a
	// policy author's evidence tuning is enforced. Fail-closed: if the compiled
	// policy somehow carries no table, refuse to mint (a missing rule must never
	// be invented) rather than silently fall back to defaults.
	table := t.pol.EvidenceRules
	if len(table) == 0 {
		return nil
	}
	ev, err := evidence.Mint(table, "NEW_LANE", laneID, now, t.pol.Revision)
	if err != nil {
		return nil
	}
	// Mint (P0.15) already stamps a CSPRNG-derived id (un-predictable, un-collidable),
	// so no terminator override is needed — every evidence id across all producers
	// is uniform (ev_...) and non-forgeable.
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

// currentConcurrency returns the live lane concurrency for producer behavior
// (P0.4B). Returns 0 when no resource governor is configured.
func (t *Terminator) currentConcurrency(ctx context.Context, laneID string) (int, error) {
	if t.dep.Resource == nil || laneID == "" {
		return 0, nil
	}
	if diagnostic, ok := t.dep.Resource.(resource.ContextDiagnosticsAuthority); ok {
		used, err := diagnostic.InUseForContext(ctx, resource.ScopeLane, laneID)
		if err != nil {
			return 0, err
		}
		return used + 1, nil
	}
	return t.dep.Resource.InUseFor(resource.ScopeLane, laneID) + 1, nil
}
