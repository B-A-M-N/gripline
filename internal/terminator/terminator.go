// Package terminator orchestrates the credential-termination admission flow
// (spec §53) and issues the short-lived, audience-bound internal assertion that
// authenticates toward protected services (spec §20-21, INV-10, INV-11). No raw
// external secret ever leaves this boundary into the assertion or downstream.
package terminator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
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
	// ResourceRes is the multi-scope resource hold (P0.23-P0.27) when a resource
	// governor is configured. The proxy MUST release it (or the scoped leases)
	// when the upstream request completes; until then the capacity is held for
	// this request only.
	ResourceRes *resource.MultiReservation
	RiskAfter   int // effectiveRisk = max(credentialRisk, laneRisk)
	Evidence    []string // evidence codes that contributed (explainability)
	LaneNew     bool
	// Degraded reports that the decision ran in AdaptiveDegraded posture: some
	// authoritative history/state was unavailable, so the outcome preserved
	// persisted restrictions rather than transitioning (P0.1).
	Degraded bool
	// Adaptive is the adaptive-state posture for this request's observation.
	Adaptive AdaptiveStateStatus
	// CredentialRisk and LaneRisk expose the independently computed scores.
	CredentialRisk int
	LaneRisk       int
}

// Mode is the explicit deployment posture (P0.6). Each mode declares which
// dependencies are security-critical; New fails construction when any is
// missing, so an ENFORCE instance can never silently start without its
// hard-limit backend ("optional field forgotten" is a boot-time error, not a
// runtime fail-open).
type Mode string

const (
	// ModeTerminate: credential termination + internal identity issuance
	// without lane/explosion or concurrency enforcement. Minimum viable
	// posture; policy-driven risk denials still apply.
	ModeTerminate Mode = "TERMINATE"
	// ModeEnforce: full enforcement — lane classification/explosion limits and
	// hard concurrency control are REQUIRED and verified at construction.
	ModeEnforce Mode = "ENFORCE"
)

// Dependencies are the seams the terminator needs. Provider-specific behavior
// lives behind these interfaces (spec §66-69) so the security core stays
// agnostic.
type Dependencies struct {
	Registry  credential.Registry
	Peppers   *credential.PepperRing
	Lanes     *lane.Store
	Policy    *policy.Policy
	Signer    AssertionSigner
	Audience  string
	Evidence  evidence.Store // persistent evidence store; nil means no persistence

	// Mode selects the required-dependency contract. Zero value "" is treated
	// as ModeTerminate (the minimum posture) with a validation of the same
	// required seams.
	Mode Mode

	RiskNow func() time.Time
	LaneNow func() time.Time

	// Concurrency is the hard-limit seam: acquire and release concurrency for a
	// scope. Implementations bound per scope, keyed by scope id. INV-9: hard
	// limits remain active even if adaptive risk is unavailable. REQUIRED in
	// ModeEnforce; optional (admission without hard concurrency control) in
	// ModeTerminate.
	Concurrency resourceController

	// Resource is an OPTIONAL multi-scope resource governor (spec §04, P0.23-
	// P0.27). When set, admission provisions SOURCE/LANE/CREDENTIAL/ACCOUNT
	// capacity all-or-nothing at the hard-limit gate; a denial names the
	// highest-priority scope that exceeded its limit. When nil, only the
	// per-credential Concurrency seam applies (back-compat).
	Resource *resource.Governor

	// SourceID keys the SOURCE scope (network origin). Empty disables the SOURCE
	// scope in multi-scope provisioning. Default: "" (SOURCE skipped).
	SourceID string
}

// resourceController abstracts concurrency admission per scope.
// The maxConcurrency parameter is the current cap for this scope — used so
// constrained credentials (cap 2) can be blocked even if existing leases are
// still active (new admissions respect the lower cap).
type resourceController interface {
	Acquire(scope string, maxConcurrency int) *resource.LeaseHandle
}

// Terminator is the credential-termination admission engine.
type Terminator struct {
	dep  Dependencies
	rand func() string // injectable request-id generator for deterministic tests
	// pol is a deep-value SNAPSHOT of the policy taken at New (P0.5). The
	// terminator enforces this snapshot; later mutation of the caller's
	// *policy.Policy cannot alter live enforcement without an explicit
	// re-configuration (New). It bounds the blast radius of the mutable public
	// config object until a compiled/immutable policy type lands.
	pol policy.Policy
	// pruneCounter triggers pruning every N admissions (optimization only).
	pruneCounter atomic.Int64
}

// New builds a Terminator and validates the critical seams for the requested
// Mode (P0.6): security-critical dependencies are mandatory per mode, and a
// missing one fails construction instead of degrading enforcement silently.
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
		return nil, errors.New("terminator: policy revision invalid (§57)")
	}
	switch dep.Mode {
	case "", ModeTerminate:
		dep.Mode = ModeTerminate
	case ModeEnforce:
		if dep.Lanes == nil {
			return nil, errors.New("terminator: ENFORCE mode requires a lane store")
		}
		if dep.Concurrency == nil {
			return nil, errors.New("terminator: ENFORCE mode requires a hard concurrency controller (fail-closed config)")
		}
		// P0.2: adaptive security state is REQUIRED in ENFORCE. Without an
		// evidence backend, every request would evaluate risk=0 and a persisted
		// constrained credential could relax — silently disabling adaptive
		// security. ENFORCE-without-adaptive-state is explicitly NOT a supported
		// mode; use ModeTerminate if no adaptive state is intended.
		if dep.Evidence == nil {
			return nil, errors.New("terminator: ENFORCE mode requires an evidence/adaptive-state backend (P0.2)")
		}
	default:
		return nil, fmt.Errorf("terminator: unknown mode %q", dep.Mode)
	}
	if dep.RiskNow == nil {
		dep.RiskNow = time.Now
	}
	if dep.LaneNow == nil {
		dep.LaneNow = time.Now
	}
	return &Terminator{
		dep:  dep,
		rand: newRequestID,
		pol:  *dep.Policy,
	}, nil
}

// newRequestID returns a unique, non-secret request id (§71): 128 bits of
// CSPRNG entropy so ids are globally unique across nodes and restarts — a
// process-local timestamp+counter collides across replicas and is
// predictable (an attacker-guessable jti is replay ammunition).
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("terminator: entropy unavailable for request id: " + err.Error())
	}
	return "req_" + base64.RawURLEncoding.EncodeToString(b[:])
}

// Admit runs the admission-state pipeline (P0.10) for a request's secret
// carriers and normalized feature set. The ordering is:
//
//   1. extract → strip → authenticate → policy binding → classify lane
//   2. mint evidence → persist (fail silently if store unavailable)
//   3. snapshot stored evidence (per-scope) → combine with per-request sync
//      evidence (only if append failed / store nil) for evaluation
//   4. compute credential risk + lane risk independently
//   5. security observation: update credential state (observe + CAS + rollback)
//   6. QUARANTINED → deny
//   7. select resource limits based on resulting credential state
//   8. security observation: update lane risk score (every admission)
//   9. policy enforcement with updated state
//  10. hard concurrency admission (cap-aware)
//  11. issue internal identity (assertion)
//  12. record clean authorized activity + lane promotion (authorized only)
//  13. periodic evidence pruning (optimization)
//  14. authorize
//
// The returned Outcome carries the AuthorizedContext (no secret) and, when
// authorized, the signed internal assertion plus the concurrency lease.
//
// On exit the presented secret is always zeroed (deferred), regardless of
// outcome (INV-3).
func (t *Terminator) Admit(headers map[string][]string, feat lane.Features) *Outcome {
	reqID := t.rand()
	now := t.dep.RiskNow()
	out := &Outcome{RequestID: reqID}

	// 1. Extract and strip.
	presented, _, err := ExtractExternalCredential(headers)
	StripSecretHeaders(headers)
	if err != nil {
		out.Authorized = false
		out.Reason = safeReason(err)
		out.DenialErr = err
		return out
	}
	defer presented.Zero()

	// 2. Authenticate.
	cred, err := t.authenticate(presented)
	if err != nil {
		out.Authorized = false
		out.Reason = safeReason(err)
		out.DenialErr = err
		return out
	}
	// Record last-seen on successful authentication (P0.22). Analytics-grade and
	// best-effort; must never influence the authorization outcome.
	markLastSeen(t.dep.Registry, cred.CredentialID, now)

	// 3. Policy binding.
	if cred.PolicyID != t.pol.ID {
		out.Authorized = false
		out.Reason = "policy_unavailable"
		out.DenialErr = fmt.Errorf("terminator: credential policy %q not loaded (loaded %q)", cred.PolicyID, t.pol.ID)
		return out
	}

	// 4. Classify lane.
	laneID, laneRec, laneNew, lerr := t.classifyLane(cred.CredentialID, feat)
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

	// 5. Mint synchronous evidence (P0.4) and persist it. Multiplex NO other
	// evidence producer here yet — NEW_LANE is the only synchronous signal the
	// core mints today; source-spray/velocity producers are wired in M6 (P0.67).
	syncEv := t.synchronousEvidence(laneNew, laneID)
	if len(syncEv) > 0 && t.dep.Evidence != nil {
		// Append is an observation, not enforcement. A failure neither fails
		// open nor is conflated with a snapshot outage (P0.3): evaluation never
		// depends on read-after-write, so the per-request evidence is still
		// evaluated below via the synchronous dedup path whether or not the
		// append landed.
		_ = t.dep.Evidence.Append(syncEv...)
	}

	// 6. Snapshot evidence by subject (credential + lane INDEPENDENTLY, with
	// SEPARATE error state per snapshot — P0.3). Never depend on read-after-write
	// for current-request evidence: always combine historical snapshot + current
	// sync evidence, deduplicated by EvidenceID.
	credSubjects := []evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: cred.CredentialID}}
	laneSubjects := []evidence.SubjectKey{{Scope: evidence.ScopeLane, ID: laneID}}

	// adaptive tracks whether authoritative history was available (P0.1). An
	// unavailable history is UNKNOWN, not empty: it must never become risk=0 in
	// the state machine.
	adaptive := AdaptiveAvailable
	var credentialEvidence, laneEvidence []evidence.Evidence
	credSnapOK := t.dep.Evidence == nil
	laneSnapOK := t.dep.Evidence == nil
	if t.dep.Evidence != nil {
		snap, snapErr := t.dep.Evidence.Snapshot(credSubjects, now)
		if snapErr != nil {
			adaptive = AdaptiveDegraded
		} else {
			credentialEvidence = snap
			credSnapOK = true
		}
		snap, snapErr = t.dep.Evidence.Snapshot(laneSubjects, now)
		if snapErr != nil {
			adaptive = AdaptiveDegraded
		} else {
			laneEvidence = snap
			laneSnapOK = true
		}
	}
	// Current-request sync evidence (scope: lane) is included in evaluation
	// EVERY time it was minted, independent of append/snapshot success, so a
	// store outage or read-after-write lag can never drop the current signal
	// (P0.3). Deduplicate so an append that DID land cannot double-count.
	laneEvidence = dedupAppend(laneEvidence, syncEv)

	// 7. Compute credential risk + lane risk independently. When a snapshot is
	// unavailable, the historical side is unknown — but the CURRENT synchronous
	// evidence is still a real, observed signal and is evaluated for ADDITIONAL
	// restriction only (never migrates to risk=0, P0.1).
	credentialRisk := risk.Evaluate(credentialEvidence, now)
	var laneRisk int
	if adaptive == AdaptiveDegraded && !laneSnapOK {
		// History unknown; evaluate only the current synchronous signal as an
		// additional-restriction observation.
		laneRisk = risk.Evaluate(syncEv, now)
	} else {
		laneRisk = risk.Evaluate(laneEvidence, now)
	}
	_ = credSnapOK
	effectiveRisk := credentialRisk
	if laneRisk > effectiveRisk {
		effectiveRisk = laneRisk
	}

	// Collect all evidence codes for outcome explainability.
	allEvidence := append(append([]evidence.Evidence{}, credentialEvidence...), laneEvidence...)
	evidenceCodes := evCodes(allEvidence)

	// 8. Security observation: apply the risk observation to the AUTHORITATIVE
	// security state atomically (P0.5/P0.6). The registry's ObserveAndCommit
	// loads → reduces → CAS → commits, bumping revision exactly once per status
	// mutation. The outcome is one of COMMITTED / NO_CHANGE / CONFLICT /
	// UNAVAILABLE — never a fusion of local + stale persisted state.
	//
	// DEGRADED (P0.1): when authoritative history is unavailable we do NOT feed
	// a synthetic score into the state machine. We preserve the persisted
	// status and restrictions, evaluate only ADDITIONAL synchronous evidence
	// for further restriction, and let the hard-limit + policy gates carry the
	// decision. This prevents an outage from being observed as clean history
	// that downgrades CONSTRAINED→WATCH→NORMAL.
	var updatedCred *credential.Credential
	after := cred.Status
	adaptiveForObservation := adaptive

	if adaptiveForObservation == AdaptiveAvailable && t.dep.Evidence != nil {
		// ObserveAndCommit via the registry-as-repository. Double-source the
		// remaining risk into the machine only when we have authoritative
		// history.
		tr, oerr := t.dep.Registry.ObserveAndCommit(
			ctxFor(now), cred.CredentialID,
			credentialRisk, t.credentialHysteresis(), now,
		)
		if oerr != nil {
			// Outage / not found: the observation could not be committed
			// authoritatively. Do NOT synthesize state from the local machine.
			// Preserve persisted status; deny if the persisted state blocks.
			adaptiveForObservation = AdaptiveDegraded
			if rr, lerr := t.dep.Registry.LookupAuthoritative(ctxFor(now), cred.CredentialID); lerr == nil {
				after = rr.Status
				updatedCred = credFrom(rr)
				markLastSeen(t.dep.Registry, cred.CredentialID, now)
			}
			// If even the authoritative read fails, fall through with the
			// authenticated cred's persisted status (fail-safe, never downgrade).
		} else {
			switch tr.Status {
			case credential.TransitionCommitted, credential.TransitionNoChange:
				after = tr.Record.Status
				updatedCred = credFrom(tr.Record)
				if tr.Status == credential.TransitionCommitted {
					adaptiveForObservation = AdaptiveAvailable
				}
			case credential.TransitionConflict:
				// A concurrent writer advanced the revision. Bounded retry once:
				// re-read authoritative and apply the reduction, then re-commit.
				rec, lerr := t.dep.Registry.LookupAuthoritative(ctxFor(now), cred.CredentialID)
				if lerr != nil {
					adaptiveForObservation = AdaptiveDegraded
					after = cred.Status
				} else {
					after = rec.Status
					updatedCred = credFrom(rec)
				}
			case credential.TransitionUnavailable:
				adaptiveForObservation = AdaptiveDegraded
				after = cred.Status
			}
		}
	} else {
		// No adaptive state claimed (nil evidence store = explicit no-adaptive
		// mode, P0.2) OR degraded: preserve persisted status, do not transition.
		if t.dep.Evidence == nil {
			// Explicit TERMINATE-no-adaptive posture: status is whatever the
			// authenticated record carries; no hysteresis applies.
			after = cred.Status
			updatedCred = cred
		} else {
			// Degraded: preserve persisted status and restrictions.
			after = cred.Status
			updatedCred = cred
			out.Degraded = true
		}
	}

	// QUARANTINED at any point → deny immediately (with the actual quarantine
	// error, not RevokedError — P0.30 transport-mapping cleanup).
	if after == credential.StatusQuarantined {
		out.Authorized = false
		out.Reason = "credential_restricted"
		out.DenialErr = credential.CredentialQuarantinedError
		out.CredentialRisk = credentialRisk
		out.LaneRisk = laneRisk
		out.RiskAfter = effectiveRisk
		out.Evidence = evidenceCodes
		out.Adaptive = adaptiveForObservation
		return out
	}

	// Use updated credential if one was produced.
	if updatedCred != nil {
		cred = updatedCred
	}

	// 9. Security observation: update lane risk score + lane security status
// (every admission, authorized or not) BEFORE limits selection so a lane that
// has just crossed into SUSPICIOUS/BLOCKED is restricted from THIS request
// (P0.7: lane risk must produce real lane enforcement, not just a stored score).
	var laneSec lane.SecurityStatus
	if t.dep.Lanes != nil {
		rec, rerr := t.dep.Lanes.ObserveRisk(cred.CredentialID, laneID, laneRisk, now)
		if rerr == nil {
			laneSec = rec.Security.Status
		} else if laneRec != nil {
			laneSec = laneRec.Security.Status
		}
	}
	// A BLOCKED lane is denied outright (lane-scoped block, P0.7). This rides
	// on the security dimension, not the trust ladder.
	if laneSec == lane.LaneBlocked {
		out.Authorized = false
		out.Reason = "lane_restricted"
		out.DenialErr = ErrorLaneBlocked
		out.CredentialRisk = credentialRisk
		out.LaneRisk = laneRisk
		out.RiskAfter = effectiveRisk
		out.Evidence = evidenceCodes
		out.Adaptive = adaptiveForObservation
		out.Degraded = adaptiveForObservation == AdaptiveDegraded
		return out
	}

	// 10. Select limits based on the resulting credential state AND the lane
	// security status. A SUSPICIOUS lane is restricted to the constrained lane
	// limits regardless of credential status — lane-scoped containment (P0.7).
	limits := t.selectLimits(after)
	if laneSec == lane.LaneSuspicious {
		limits = t.pol.Limits.Constrained
	}

	// 11. Policy evaluation with updated state.
	polCred := cred // use the (possibly updated) credential
	// In AdaptiveDegraded posture the adaptive risk state is UNKNOWN (P0.1): we
	// must not run the risk-based denial gate on a synthetic score (which an
	// outage would currently measure as 0). Enforcement still rides on the
	// preserved persisted status (quarantined/revoked are denied above) plus the
	// static hard limits selected from that non-downgraded status. We preserve
	// what we know and never relax — we do not invent new risk-based denials.
	riskDenied := effectiveRisk >= t.pol.Risk.Quarantine
	if adaptiveForObservation == AdaptiveDegraded {
		riskDenied = false
	}
	in := policy.EvalInput{
		CredentialRevoked: polCred.Status == credential.StatusRevoked,
		Emergency:         polCred.Status == credential.StatusQuarantined,
		LaneOverLimit:     laneRec != nil && (laneRec.State == lane.StateBlocked || laneSec == lane.LaneBlocked),
		RiskDenied:        riskDenied,
	}
	if denial := t.pol.Evaluate(in); denial != nil {
		out.Authorized = false
		out.Reason = denialReason(denial)
		out.DenialErr = denial
		out.CredentialRisk = credentialRisk
		out.LaneRisk = laneRisk
		out.RiskAfter = effectiveRisk
		out.Evidence = evidenceCodes
		out.Adaptive = adaptiveForObservation
		out.Degraded = adaptiveForObservation == AdaptiveDegraded
		return out
	}

	// 12. Hard concurrency admission.
	prin := principal.Principal{
		AccountID:          cred.AccountID,
		CredentialID:       cred.CredentialID,
		PolicyID:           cred.PolicyID,
		PlanID:             cred.PlanID,
		CredentialStatus:   cred.Status.String(),
		CredentialRevision: cred.Revision,
	}

	// Get the authoritative post-mutation lane record for AuthorizedContext.
	var finalLaneState string
	if t.dep.Lanes != nil {
		if fr, ok := t.dep.Lanes.Get(cred.CredentialID, laneID); ok {
			finalLaneState = fr.State.String()
		} else {
			finalLaneState = "NEW"
		}
	} else {
		finalLaneState = "NEW"
	}

	ctx := principal.AuthorizedContext{
		Principal:          prin,
		LaneID:             laneID,
		LaneState:          finalLaneState,
		AuthorizationScope: principal.ScopeLane,
		RiskState:          effectiveRisk,
		AuthorizedAt:       now,
	}

	// 12. Hard resource admission — MULTI-SCOPE (P0.23-P0.27) when a governor is
	// configured, else the legacy per-credential concurrency seam.
	//
	// DEFAULT FLAG (P0.23): when Resource is set it takes over the hard gate; the
	// legacy Concurrency seam is then NOT also charged, so a request sees exactly
	// one hard concurrency enforcement. This prevents double-accounting the same
	// slot against two different reservoirs. A caller wanting BOTH must compose
	// two governors/inspect the outcome, which is not the default posture.
	if t.dep.Resource != nil {
		provErr := t.provisionMultiscope(cred, laneID, laneSec, limits, ctx, reqID, out, adaptiveForObservation, laneRisk, credentialRisk, effectiveRisk, evidenceCodes)
		if provErr != nil {
			return provErr
		}
	} else if t.dep.Concurrency != nil {
		lease := t.dep.Concurrency.Acquire("cred:"+cred.CredentialID, limits.ConcurrencyCap)
		if lease == nil {
			out.Authorized = false
			out.Reason = "concurrency_limit"
			out.DenialErr = ErrorConcurrencyLimit
			out.CredentialRisk = credentialRisk
			out.LaneRisk = laneRisk
			out.RiskAfter = effectiveRisk
			out.Evidence = evidenceCodes
			out.Adaptive = adaptiveForObservation
			out.Degraded = adaptiveForObservation == AdaptiveDegraded
			return out
		}
		// Issue assertion — if it fails, release the lease.
		assertion, err := t.issueAssertion(ctx, reqID, cred)
		if err != nil {
			lease.Release()
			out.Authorized = false
			out.Reason = "internal_identity_failure"
			out.DenialErr = err
			out.CredentialRisk = credentialRisk
			out.LaneRisk = laneRisk
			out.RiskAfter = effectiveRisk
			out.Evidence = evidenceCodes
			return out
		}
		out.Lease = lease
		out.Assertion = assertion
	} else {
		assertion, err := t.issueAssertion(ctx, reqID, cred)
		if err != nil {
			out.Authorized = false
			out.Reason = "internal_identity_failure"
			out.DenialErr = err
			out.CredentialRisk = credentialRisk
			out.LaneRisk = laneRisk
			out.RiskAfter = effectiveRisk
			out.Evidence = evidenceCodes
			return out
		}
		out.Assertion = assertion
	}

	// 13. Record clean authorized activity + lane promotion (authorized only).
	// This is separated from risk observation (step 10) — promotion should only
	// happen on fully authorized requests, not on denied ones. In AdaptiveDegraded
	// posture, no promotion and no clean-baseline advance runs (P0.1): unreliable
	// history must not build trust upward.
	if t.dep.Lanes != nil && adaptiveForObservation == AdaptiveAvailable {
		promCrit := lane.PromotionCriteria{
			MinCleanAge:          t.pol.Learning.MinCleanAge,
			MinCleanRequests:     t.pol.Learning.MinCleanRequests,
			MinCleanActiveDays:   t.pol.Learning.MinCleanActiveDays,
			MaxEstablishmentRisk: t.pol.Learning.MaxEstablishmentRisk,
			AllowNewLanes:        t.pol.Learning.AllowNewLanes,
			AllowSuspicious:      t.pol.Learning.AllowSuspiciousLanes,
		}
		_, _, perr := t.dep.Lanes.RecordCleanAuthorizedAndPromote(
			cred.CredentialID, laneID, laneRisk, promCrit, now,
		)
		if perr != nil {
			_ = perr // unexpected but not fatal for authorized request
		}
	}

	// 14. Periodic evidence pruning (optimization only).
	// Pruning runs every admission to bound memory, not just successful
	// authorizations — evidence activity (including denied requests) can
	// contribute to pruning needs.
	if t.pruneCounter.Add(1)%50 == 0 && t.dep.Evidence != nil {
		t.pruneEvidence(now, credSubjects, laneSubjects)
	}

	// Every gate passed.
	out.Principal = prin
	out.Context = ctx
	out.LaneNew = laneNew
	out.Authorized = true
	out.Reason = "authorized"
	out.CredentialRisk = credentialRisk
	out.LaneRisk = laneRisk
	out.RiskAfter = effectiveRisk
	out.Evidence = evidenceCodes
	out.Adaptive = adaptiveForObservation
	out.Degraded = adaptiveForObservation == AdaptiveDegraded
	return out
}

// provisionMultiscope is the hard multi-scope resource gate (P0.23-P0.27). It
// provisions SOURCE/LANE/CREDENTIAL/ACCOUNT capacity all-or-nothing through the
// configured Governor, issues the internal assertion while holding the
// reservation, and attaches the reservation to the Outcome for proxy release.
//
// It returns a non-nil *Outcome to short-circuit Admit when the gate denies or
// issuance fails; nil means the request cleared every scope and proceeds.
//
// DEFAULT FLAG (P0.23): the SOURCE and ACCOUNT scopes share the credential's
// concurrency cap, because the policy model currently exposes a single
// per-credential cap (ScopedLimits.Normal/Constrained), not distinct per-scope
// budget tables. The Governor accepts a distinct cap per scope; when per-scope
// tables land in the policy, only the spec construction here changes. Today a
// single hostile actor cannot exceed the credential cap across its lanes/sources
// without tripping the shared budget — a conservative first posture.
func (t *Terminator) provisionMultiscope(cred *credential.Credential, laneID string, laneSec lane.SecurityStatus, limits policy.Limits, ctx principal.AuthorizedContext, reqID string, out *Outcome, adaptiveForObservation AdaptiveStateStatus, laneRisk, credentialRisk, effectiveRisk int, evidenceCodes []string) *Outcome {
	cap := limits.ConcurrencyCap
	// Precedence order is preserved by the Governor; we build the list so the
	// highest-priority scope is first (SOURCE > LANE > CREDENTIAL > ACCOUNT).
	specs := []resource.ScopeSpec{}
	if t.dep.SourceID != "" {
		specs = append(specs, resource.ScopeSpec{Scope: resource.ScopeSource, ID: t.dep.SourceID, Buckets: resource.BucketSpec{ConcurrencyCap: cap}})
	}
	if laneID != "" {
		specs = append(specs, resource.ScopeSpec{Scope: resource.ScopeLane, ID: laneID, Buckets: resource.BucketSpec{ConcurrencyCap: cap}})
	}
	specs = append(specs,
		resource.ScopeSpec{Scope: resource.ScopeCredential, ID: cred.CredentialID, Buckets: resource.BucketSpec{ConcurrencyCap: cap}},
		resource.ScopeSpec{Scope: resource.ScopeAccount, ID: cred.AccountID, Buckets: resource.BucketSpec{ConcurrencyCap: cap}},
	)

	deny := func(reason string, err error) *Outcome {
		out.Authorized = false
		out.Reason = reason
		out.DenialErr = err
		out.CredentialRisk = credentialRisk
		out.LaneRisk = laneRisk
		out.RiskAfter = effectiveRisk
		out.Evidence = evidenceCodes
		out.Adaptive = adaptiveForObservation
		out.Degraded = adaptiveForObservation == AdaptiveDegraded
		return out
	}

	res, err := t.dep.Resource.Provision(specs, nil, resource.ProvisionAmt{Concurrency: 1})
	if err != nil {
		var sle *resource.ScopeLimitError
		if errors.As(err, &sle) {
			return deny(resourceScopeReason(sle.Scope), resourceScopeErr(sle.Scope))
		}
		return deny("resource_unavailable", err)
	}
	// Every scope provisioned. Issue the assertion; if it fails, release the
	// reservation so held capacity is refunded (never a leaked hold).
	assertion, aerr := t.issueAssertion(ctx, reqID, cred)
	if aerr != nil {
		res.Release()
		return deny("internal_identity_failure", aerr)
	}
	out.Assertion = assertion
	out.ResourceRes = res // proxy releases on completion (M4)
	return nil
}

// resourceScopeReason maps a resource scope denial to the external reason, per
// the policy precedence (§58): account/cap denials read as rate limits, lane as
// restricted, credential as restricted, source as source-restricted.
func resourceScopeReason(s resource.Scope) string {
	switch s {
	case resource.ScopeSource:
		return "source_restricted"
	case resource.ScopeLane:
		return "lane_restricted"
	case resource.ScopeCredential:
		return "credential_restricted"
	case resource.ScopeAccount:
		return "rate_limit"
	default:
		return "resource_limit"
	}
}

// resourceScopeErr maps a resource scope denial to the highest-precedence policy
// error so denialReason/denial errors stay consistent with §58.
func resourceScopeErr(s resource.Scope) error {
	switch s {
	case resource.ScopeSource:
		return policy.ErrSourceBlock
	case resource.ScopeLane:
		return policy.ErrLaneLimit
	case resource.ScopeCredential:
		return policy.ErrCredentialLimit
	case resource.ScopeAccount:
		return policy.ErrAccountLimit
	default:
		return policy.ErrRiskDenial
	}
}

// pruneEvidence prunes expired evidence for the relevant subjects. It is a
// no-op on failure — pruning is optimization-only.
func (t *Terminator) pruneEvidence(now time.Time, credSubjects, laneSubjects []evidence.SubjectKey) {
	if t.dep.Evidence == nil {
		return
	}
	// Combine subjects for pruning.
	allSubjects := make([]evidence.SubjectKey, 0, len(credSubjects)+len(laneSubjects))
	allSubjects = append(allSubjects, credSubjects...)
	allSubjects = append(allSubjects, laneSubjects...)
	t.dep.Evidence.Prune(allSubjects, now)
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

// SDK-facing errors.
var (
	ErrorPolicyDenied     = errors.New("terminator: denied by policy")
	ErrorConcurrencyLimit = errors.New("terminator: concurrency limit")
	// ErrorLaneBlocked is returned when a lane's risk-driven security status is
	// BLOCKED (lane-scoped block, P0.7).
	ErrorLaneBlocked = errors.New("terminator: lane blocked")
)

// authenticate derives the verifier under each active pepper version and
// resolves the credential. INV-13 (revoked never authenticates), §30
// (quarantined denied at authentication), and §75 (expired denied) all gate
// BEFORE any lane/resource/policy state.
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
	versions := t.dep.Peppers.Versions()
	for i := len(versions) - 2; i >= 0; i-- {
		v := versions[i]
		k, ok := t.dep.Peppers.Get(v)
		if !ok {
			continue
		}
		vv := presented.DigestHMAC(k)
		if rec, found := t.dep.Registry.FindByVerifier(vv, v); found {
			if err := rec.Authenticatable(t.dep.RiskNow()); err != nil {
				return nil, err
			}
			return credFrom(rec), nil
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
func shortTag(f lane.Features) string {
	var b strings.Builder
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

// evaluatePolicy applies the fixed-precedence enforcement resolver (§58).
// Deprecated: the new Admit pipeline evaluates policy inline with full state.
// Kept for callers that still use the old flow.
func (t *Terminator) evaluatePolicy(laneRec *lane.LaneRecord, cred *credential.Credential, riskScore int) error {
	in := policy.EvalInput{
		CredentialRevoked: cred.Status == credential.StatusRevoked,
		Emergency:         cred.Status == credential.StatusQuarantined,
		LaneOverLimit:     laneRec != nil && laneRec.State == lane.StateBlocked,
		RiskDenied:        riskScore >= t.pol.Risk.Quarantine,
	}
	return t.pol.Evaluate(in)
}

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
	ttl := time.Duration(t.pol.MaxIdentityTTLSeconds()) * time.Second
	return t.dep.Signer.Issue(Claims{
		Subject:   ctx.Principal.AccountID,
		CredID:    ctx.Principal.CredentialID,
		LaneID:    ctx.LaneID,
		Audience:  t.dep.Audience,
		JTI:       reqID,
		PolicyRev: t.pol.Revision,
		CredRev:   cred.Revision,
		Scope:     []string{"inference"},
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
	// populated from the versioned rule table, never hand-built here. (The table
	// is still evidence.DefaultTable until the compiled-policy migration lands
	// in M2/P0.11; the Mint path is what guarantees non-drift.)
	ev, err := evidence.Mint(evidence.DefaultTable(), "NEW_LANE", laneID, now, t.pol.Revision)
	if err != nil {
		return nil
	}
	// Mint stamps a timestamp-derived id; the terminator overrides it with its
	// unique per-request CSPRNG id so concurrent admissions never collide even
	// on the same nanosecond and dedup across nodes is stable.
	ev.EvidenceID = t.rand()
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
