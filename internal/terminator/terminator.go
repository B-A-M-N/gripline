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

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/control"
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
	// Baseline (P0.27) is non-nil on an authorized outcome when a lane store is
	// configured. It is the deferred clean-activity credit: the proxy calls
	// FinalizeBaseline ONCE after the upstream request has actually succeeded
	// (backend accepted / response complete). An admitted-but-never-completed
	// request earns no baseline trust.
	Baseline *BaselineToken
}

// BaselineToken carries the deferred clean-activity credit from an authorized
// admission to the proxy-side completion event (P0.27). It is a value token:
// the proxy cannot forge extra counts, only present or not-present the one it
// was given. Finalize is idempotent.
type BaselineToken struct {
	CredentialID string
	LaneID       string
	LaneRisk     int
	// Eligible reports whether the admission ran in AdaptiveAvailable posture
	// — a degraded admission never builds baseline trust (P0.1).
	Eligible bool

	// done guards idempotent finalization: a request completed and then
	// double-released (error path + defer) must count once.
	done bool

	// term is the issuing terminator (back-pointer, set at issuance) — the
	// completion event lands on the same authority that admitted the request.
	term *Terminator
}

// Finalize records ONE clean successful observation against the lane baseline
// (counters + promotion evaluation) at the moment the proxy has proof the
// upstream request succeeded. It is a no-op when the token was already spent,
// when the admission ran degraded, or when no lane store is configured.
// Returns whether a baseline credit was applied.
func (b *BaselineToken) Finalize() bool {
	if b == nil || !b.Eligible || b.done || b.term == nil || b.term.dep.Lanes == nil {
		return false
	}
	b.done = true
	b.term.finalizeBaseline(b)
	return true
}

// FinalizeBaseline spends this outcome's BaselineToken (P0.27 convenience for
// the proxy lifecycle). Safe to call on a denied outcome (no token) and
// idempotent.
func (o *Outcome) FinalizeBaseline() bool {
	if o == nil {
		return false
	}
	return o.Baseline.Finalize()
}

// Reservation returns the ONE lifecycle handle for whatever this admission is
// holding (P0.8): the multi-scope governor reservation when one was taken,
// otherwise the legacy single-scope concurrency lease, otherwise a no-op. The
// proxy (or any caller) defers Release on this — it never needs to know which
// reservation shape was used, and no error/panic path can leak the hold.
func (o *Outcome) Reservation() resource.AdmissionReservation {
	if o == nil {
		return resource.NoopReservation{}
	}
	if o.ResourceRes != nil {
		return o.ResourceRes
	}
	if o.Lease != nil {
		return o.Lease
	}
	return resource.NoopReservation{}
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

	// Control is an OPTIONAL operator control plane (P0.39-P0.41). When set, the
	// admission pipeline consults it: EMERGENCY_LOCKDOWN denies NEW lane creation
	// and throttles traffic, and every decision is written to its audit trail
	// (P0.35). Nil disables both. Keep it nil unless a control plane is wired.
	Control *control.ControlPlane

	// SourceID was REMOVED (P0.4): a Terminator serves many clients, and a
	// process-global source id either disabled source security (empty) or
	// collapsed every client into one bucket. Source identity now rides the
	// REQUEST — see AdmitSource/TrustedSource.

	// Spray is an OPTIONAL source-spray / velocity detector (P0.67). When set,
	// each admission observes (SourceID, credential, feature ASN) and any spray
	// signature that crosses its window threshold is minted into the evidence
	// store — feeding the risk engine. Nil disables (no spray evidence).
	Spray *anomaly.Detector
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
	// pol is the COMPILED policy snapshot taken at New (P0.10). Compile
	// deep-copies every reference-bearing field (the EvidenceRules map), so
	// later mutation of the caller's *policy.Policy — including its rule
	// table — cannot alter live enforcement without an explicit
	// re-configuration (New). The old shallow struct copy shared the evidence
	// map: a caller writing dep.Policy.EvidenceRules["NEW_LANE"] after
	// construction rewrote live enforcement.
	pol *policy.CompiledPolicy
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
	compiled, err := policy.Compile(dep.Policy)
	if err != nil {
		return nil, fmt.Errorf("terminator: compile policy: %w", err)
	}
	// P0.13: the compiled policy's lane security hysteresis — including the
	// EnableAutomaticBlock gate — overrides whatever the lane store was built
	// with, so policy revision is the one authority for lane security behavior.
	if dep.Lanes != nil {
		dep.Lanes.SetSecurityHysteresis(compiled.LaneSecurity)
	}
	return &Terminator{
		dep:  dep,
		rand: newRequestID,
		pol:  compiled,
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
//
// Admit is the no-source entry point: it admits with an UNKNOWN source
// (P0.4). Source-scoped features — spray detection, SOURCE resource scope,
// source-scoped risk — are inactive for that request, because there is no
// identity to attribute them to. Use AdmitSource with a TrustedSource derived
// at trusted ingress (peer address → pseudonym, ASN, network type) to enable
// them; a Terminator serves many clients and must never carry one process-wide
// source identity.
func (t *Terminator) Admit(headers map[string][]string, feat lane.Features) *Outcome {
	return t.AdmitUsage(headers, feat, TrustedSource{}, resource.UsageEstimate{Requests: 1})
}

// TrustedSource is the per-request source identity, derived at TRUSTED ingress
// (P0.4) — transport peer metadata (RealIP → pseudonym, ASN lookup, network
// classification), never client-asserted headers. It keys the SOURCE resource
// scope, source-spray detection, and source-scoped risk for this request only.
// The zero value means "source unknown for this request": source-scoped
// features are inactive rather than attributed to a shared bucket.
type TrustedSource struct {
	// Pseudonym is the privacy-preserving source key (pseudonym.Ring output over
	// the peer address). Empty disables source attribution for the request.
	Pseudonym string
	// ASN, NetworkType, RegionClass are the trusted source dimensions, when the
	// deployment has a trusted source resolver. Empty = unknown.
	ASN         string
	NetworkType string
	Region      string
}

// sourceID returns the key this request attributes to for SOURCE-scope
// decisions, or "" when the request carries no trusted source identity.
func (s TrustedSource) sourceID() string { return s.Pseudonym }

// AdmitSource is the full entry point (P0.4): admission with the per-request
// trusted source identity. The source lives on the REQUEST — a Terminator is a
// long-lived engine shared by every client, and a process-global SourceID made
// every client one source (or disabled source security entirely when empty).
func (t *Terminator) AdmitSource(headers map[string][]string, feat lane.Features, src TrustedSource) *Outcome {
	return t.AdmitUsage(headers, feat, src, resource.UsageEstimate{Requests: 1})
}

// AdmitUsage is the full entry point including the typed usage estimate (P0.3):
// the estimate is reserved atomically across every scope at the hard gate, and
// the returned Outcome's reservation is SETTLED with actuals after execution
// (proxy lifecycle). Admit/AdmitSource delegate here with {Requests: 1}.
func (t *Terminator) AdmitUsage(headers map[string][]string, feat lane.Features, src TrustedSource, est resource.UsageEstimate) *Outcome {
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

	// Audit each decision once, at exit, from the fully-populated outcome
	// (P0.35). Non-secret fields only; the audit trail never sees a raw secret
	// or the internal assertion (INV-3).
	if t.dep.Control != nil {
		credID, acctID := cred.CredentialID, cred.AccountID
		defer func() {
			t.dep.Control.RecordAdmission(control.Event{
				RequestID:    out.RequestID,
				CredentialID: credID,
				AccountID:    acctID,
				LaneID:       out.Context.LaneID,
				Authorized:   out.Authorized,
				Reason:       out.Reason,
			})
		}()
	}

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

	// 5. Mint synchronous evidence (P0.4) and persist it. NEW_LANE is the
	// synchronous lane-establishment signal; an optional source-spray detector
	// (P0.67) contributes its signature evidence when a threshold crosses.
	//
	// SCOPING (P0.11): syncEv is the lane-scoped evidence that feeds THIS
	// request's lane-risk evaluation (dedup'd into the lane snapshot below).
	// Spray evidence is CREDENTIAL/SOURCE-scoped — it is a pattern observed OVER
	// TIME, not an instantaneous per-request signal — so it is persisted for
	// future credential/source snapshots but NOT folded into the current request's
	// lane evaluation set (risk.Evaluate scores whatever it's given regardless of
	// scope, so mixing scopes here would over-attribute a credential-spray to the
	// lane).
	syncEv := t.synchronousEvidence(laneNew, laneID)
	var persistOnly []evidence.Evidence
	if t.dep.Spray != nil && src.sourceID() != "" {
		if sigs := t.dep.Spray.Observe(src.sourceID(), cred.CredentialID, feat.NetworkASN, now); len(sigs) > 0 {
			// P0.12: the detector returns signals; THIS compiled policy is the
			// one policy authority. Each signal resolves against the current
			// compiled rule table — score/family/scope/TTL and the minting
			// revision all come from here, never from the detector. A signal
			// with no rule in this revision resolves to nothing (fail-closed).
			for _, sig := range sigs {
				ev, err := evidence.Mint(t.pol.EvidenceRules, sig.Code, sig.SubjectID, now, t.pol.Revision)
				if err != nil {
					continue // unknown code in this revision: no invented parameters
				}
				persistOnly = append(persistOnly, ev)
			}
		}
	}
	if (len(syncEv) > 0 || len(persistOnly) > 0) && t.dep.Evidence != nil {
		// Append is an observation, not enforcement. A failure neither fails
		// open nor is conflated with a snapshot outage (P0.3): evaluation never
		// depends on read-after-write, so the per-request evidence is still
		// evaluated below via the synchronous dedup path whether or not the
		// append landed.
		allEv := append(append([]evidence.Evidence{}, syncEv...), persistOnly...)
		_ = t.dep.Evidence.Append(allEv...)
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
	// P0.45: only evidence minted under the CURRENT policy revision may drive the
	// authoritative state machine. Evidence from an older revision was scored
	// under a different rule table; evaluating it after a policy change would
	// apply old-era risk to new-era thresholds. Filter fail-closed (stale-revision
	// evidence is dropped); current-request sync evidence is always current-rev.
	credentialEvidence = policyRevisionFilter(credentialEvidence, t.pol.Revision)
	laneEvidence = policyRevisionFilter(laneEvidence, t.pol.Revision)
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
		// Gate H / §102 phase 6: automatic quarantine is DISABLED until shadow
		// validation. P0.14: the ceiling is expressed as MaxAutomaticStatus on
		// the machine — the REAL score always flows into the authoritative
		// state (a falsified low score stuck hot credentials at WATCH forever
		// and recorded a lie in the risk history). The request-level policy
		// denial below still uses the UNclamped risk to reject a genuinely hot
		// credential via temporarily_restricted; we just do not commit an
		// operator-unvalidated QUARANTINED status — the credential escalates to
		// CONSTRAINED instead, resource-restricted immediately.
		hy := t.credentialHysteresis()
		if !t.pol.Risk.EnableAutomaticQuarantine {
			hy.MaxAutomaticStatus = credential.StatusConstrained
		}
		// ObserveAndCommit via the registry-as-repository. Double-source the
		// remaining risk into the machine only when we have authoritative
		// history.
		tr, oerr := t.dep.Registry.ObserveAndCommit(
			ctxFor(now), cred.CredentialID,
			credentialRisk, hy, now,
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

	// Emergency-lockdown gate (P0.40/P0.41): in EMERGENCY_LOCKDOWN the operator
	// switch denies NEW lane creation outright (reduce attack surface immediately)
	// while ESTABLISHED lanes and persisted restrictions remain in force. The
	// authoritative risk observation above still ran (so elevation is durable even
	// during the firefight); only NEW lanes are refused.
	if laneNew && t.dep.Control != nil && t.dep.Control.InEmergency() {
		out.Authorized = false
		out.Reason = "emergency_lockdown"
		out.DenialErr = ErrorEmergencyLockdown
		out.CredentialRisk = credentialRisk
		out.LaneRisk = laneRisk
		out.RiskAfter = effectiveRisk
		out.Evidence = evidenceCodes
		out.Adaptive = adaptiveForObservation
		out.Degraded = adaptiveForObservation == AdaptiveDegraded
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
	// EMERGENCY_LOCKDOWN (P0.48) overrides BOTH: every admission — established
	// lanes included — is provisioned against the policy's Emergency limit set,
	// which is what "emergency throttles all traffic" concretely means. The
	// emergency set defaults tighter than constrained, so lockdown never grants
	// more headroom than the posture it overrides.
	limits := t.selectLimits(after)
	if laneSec == lane.LaneSuspicious {
		limits = t.pol.Limits.Constrained
	}
	if t.dep.Control != nil && t.dep.Control.InEmergency() {
		limits = t.emergencyLimits()
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
		provErr := t.provisionMultiscope(cred, laneID, laneSec, limits, ctx, reqID, out, adaptiveForObservation, laneRisk, credentialRisk, effectiveRisk, evidenceCodes, src, est)
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

	// 13. BASELINE FINALIZATION MOVED TO THE PROXY LIFECYCLE (P0.27). Admit no
	// longer counts a request as "clean authorized activity" at admission time:
	// at this point the backend may be unreachable, reject the request, or the
	// client may cancel before any useful workload — none of which is trust-
	// building activity. The Outcome instead carries a BaselineToken holding
	// everything needed to finalize the lane baseline AFTER the upstream proves
	// the request actually worked. The proxy calls Outcome.FinalizeBaseline
	// (via CompleteAuthorized) when the backend has accepted the response.
	// Nothing here mutates lane clean counters.
	if t.dep.Lanes != nil {
		out.Baseline = &BaselineToken{
			CredentialID: cred.CredentialID,
			LaneID:       laneID,
			LaneRisk:     laneRisk,
			// Baseline finalization requires AVAILABLE adaptive posture (P0.1):
			// unreliable history must not build trust upward, so a degraded
			// admission's token is issued but the proxy-side finalize is a
			// no-op for it (flagged in the token).
			Eligible: adaptiveForObservation == AdaptiveAvailable,
			term:     t,
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
func (t *Terminator) provisionMultiscope(cred *credential.Credential, laneID string, laneSec lane.SecurityStatus, limits policy.Limits, ctx principal.AuthorizedContext, reqID string, out *Outcome, adaptiveForObservation AdaptiveStateStatus, laneRisk, credentialRisk, effectiveRisk int, evidenceCodes []string, src TrustedSource, est resource.UsageEstimate) *Outcome {
	cap := limits.ConcurrencyCap
	// P0.35: the selected limits' per-dimension gauges (requests/tokens/cost)
	// ride EVERY scope's spec — requests, tokens and spend are different
	// resources with different buckets, and each scope enforces the same
	// policy-authored gauge parameters. Zero-capacity gauges are inert at every
	// scope (the governor skips them), so a policy that only authors
	// ConcurrencyCap behaves exactly as before.
	gauges := resource.BucketSpec{
		ConcurrencyCap: cap,
		RequestsBurst:  resource.BucketConfig{Capacity: float64(limits.RequestsPerWindow.Capacity), RefillPer: float64(limits.RequestsPerWindow.RefillPer), RefillIn: limits.RequestsPerWindow.RefillIn},
		TokensBurst:    resource.BucketConfig{Capacity: float64(limits.TokensPerWindow.Capacity), RefillPer: float64(limits.TokensPerWindow.RefillPer), RefillIn: limits.TokensPerWindow.RefillIn},
		CostBurst:      resource.BucketConfig{Capacity: float64(limits.CostPerWindow.Capacity), RefillPer: float64(limits.CostPerWindow.RefillPer), RefillIn: limits.CostPerWindow.RefillIn},
	}
	// Precedence order is the policy enum (P0.33): SOURCE → ACCOUNT →
	// CREDENTIAL → LANE, GLOBAL last as the whole-plane gauge (P0.34). The
	// SOURCE scope keys on this REQUEST's source pseudonym (P0.4) — empty
	// means no trusted source identity for the request, so SOURCE is skipped
	// rather than bucketed under a shared process-global id.
	specs := []resource.ScopeSpec{}
	if src.sourceID() != "" {
		specs = append(specs, resource.ScopeSpec{Scope: resource.ScopeSource, ID: src.sourceID(), Buckets: gauges})
	}
	specs = append(specs,
		resource.ScopeSpec{Scope: resource.ScopeAccount, ID: cred.AccountID, Buckets: gauges},
		resource.ScopeSpec{Scope: resource.ScopeCredential, ID: cred.CredentialID, Buckets: gauges},
	)
	if laneID != "" {
		specs = append(specs, resource.ScopeSpec{Scope: resource.ScopeLane, ID: laneID, Buckets: gauges})
	}
	// GLOBAL scope (P0.34): the whole-plane gauge, keyed "fleet". Without it
	// the governor's ScopeGlobal was implemented but never provisioned, so no
	// fleet-wide bound existed. A fleet cap of 0 (unset) skips the gauge.
	if fleetCap := t.pol.Limits.Normal.ConcurrencyCap * 1024; fleetCap > 0 {
		specs = append(specs, resource.ScopeSpec{Scope: resource.ScopeGlobal, ID: "fleet", Buckets: resource.BucketSpec{ConcurrencyCap: fleetCap}})
	}

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

	// Typed per-dimension usage (P0.3): the estimate is reserved atomically
	// across every scope; the proxy settles the reservation with ACTUALS after
	// the backend responds. Dimensions the policy doesn't gauge (zero capacity)
	// are inert; dimensions the estimate leaves zero reserve nothing.
	res, err := t.dep.Resource.ProvisionUsage(specs, est)
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
	case resource.ScopeGlobal:
		return "resource_limit"
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
	case resource.ScopeGlobal:
		return policy.ErrGlobalLimit
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

// finalizeBaseline applies one deferred clean-activity credit (P0.27): counters
// advance and promotion is evaluated — including the P0.26 disqualifying-
// evidence veto, computed NOW (at completion) against live evidence, not at
// admission. Called only from BaselineToken.Finalize, which owns idempotency.
func (t *Terminator) finalizeBaseline(b *BaselineToken) {
	now := t.dep.RiskNow()
	promCrit := lane.PromotionCriteria{
		MinCleanAge:          t.pol.Learning.MinCleanAge,
		MinCleanRequests:     t.pol.Learning.MinCleanRequests,
		MinCleanActiveDays:   t.pol.Learning.MinCleanActiveDays,
		MaxEstablishmentRisk: t.pol.Learning.MaxEstablishmentRisk,
		AllowNewLanes:        t.pol.Learning.AllowNewLanes,
		AllowSuspicious:      t.pol.Learning.AllowSuspiciousLanes,
		HasDisqualifyingEvidence: t.hasActiveDisqualifyingEvidence(b.CredentialID, b.LaneID, now),
	}
	_, _, _ = t.dep.Lanes.RecordCleanAuthorizedAndPromote(
		b.CredentialID, b.LaneID, b.LaneRisk, promCrit, now,
	)
}

// hasActiveDisqualifyingEvidence reports whether any currently-active evidence
// against the lane or its credential carries a code on the policy's
// disqualifying list (P0.26). A store outage here must NOT fail open into
// "no disqualifying evidence" — it conservatively vetoes (fail-closed): an
// unavailable history is unknown, and unknown blocks trust-building.
func (t *Terminator) hasActiveDisqualifyingEvidence(credID, laneID string, now time.Time) bool {
	if len(t.pol.Learning.DisqualifyingEvidenceCodes) == 0 {
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
	snap, err := t.dep.Evidence.Snapshot(subjects, now)
	if err != nil {
		// History unavailable → unknown → veto. Trust-building stops during an
		// evidence outage; it resumes when the store is readable again.
		return true
	}
	dq := make(map[string]struct{}, len(t.pol.Learning.DisqualifyingEvidenceCodes))
	for _, c := range t.pol.Learning.DisqualifyingEvidenceCodes {
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
	if t.pol.Limits.Emergency.ConcurrencyCap > 0 {
		return t.pol.Limits.Emergency
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
	// P0.11: classify against the COMPILED policy revision's cutoffs, not the
	// package-global lane.DefaultThresholds(), so anti-laundering sensitivity
	// (MinComparableWeight etc.) is policy-tunable and versioned.
	rec, created, err := t.dep.Lanes.BorrowOrCreate(credID, laneID, feat, t.pol.Classification)
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
