// Package terminator orchestrates the credential-termination admission flow
// (spec §53) and issues the short-lived, audience-bound internal assertion that
// authenticates toward protected services (spec §20-21, INV-10, INV-11). No raw
// external secret ever leaves this boundary into the assertion or downstream.
package terminator

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/principal"
	"github.com/B-A-M-N/gripline/internal/producers"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/risk"
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
	// ResourceReservation is the backend-neutral resource hold (P0.23-P0.27).
	// The proxy releases it when the upstream request completes; until then the
	// capacity is held for this request only.
	ResourceReservation resource.UsageReservation
	// ResourceRes and UsageRes are deprecated compatibility views for callers
	// that still inspect the pre-abstraction fields. New code must use
	// ResourceReservation or Reservation().
	ResourceRes *resource.MultiReservation
	UsageRes    resource.UsageReservation
	RiskAfter   int      // effectiveRisk = max(credentialRisk, laneRisk)
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
	// Completion (P0.4A) is non-nil on an authorized outcome when completion-time
	// producers are wired. It carries the deferred completion observation: the
	// proxy calls Complete(actual, success) at end-of-stream so token/cost
	// velocity producers fire against the ACTUAL usage, not the estimate.
	Completion *CompletionToken
	// Trace (P0.50) is the INTERNAL decision record: full state transitions,
	// evidence ids, selected limits, and the policy revision (P0.51 — stamped
	// for denied requests too, from the compiled policy rather than the
	// assertion). It is internal: audit consumes it; the public response never
	// serializes it.
	Trace *DecisionTrace
}

// BaselineToken carries the deferred clean-activity credit from an authorized
// admission to the proxy-side completion event (P0.27). It is a value token:
// the proxy cannot forge extra counts, only present or not-present the one it
// was given. Finalize is idempotent.
type BaselineToken struct {
	CredentialID   string
	LaneID         string
	LaneRisk       int
	RequestID      string
	PolicyRevision int
	EvidenceCodes  []string
	// Eligible reports whether the admission ran in AdaptiveAvailable posture
	// — a degraded admission never builds baseline trust (P0.1).
	Eligible bool
	policy   *policy.CompiledPolicy

	// done guards idempotent finalization: a request completed and then
	// double-released (error path + defer) must count once.
	// P0.13 fix: atomic.Bool for concurrent safety.
	done atomic.Bool

	// term is the issuing terminator (back-pointer, set at issuance) — the
	// completion event lands on the same authority that admitted the request.
	term *Terminator
	// runtimeCtx is detached from client cancellation but bounded. Completion
	// accounting must finish even when the downstream disconnects, without
	// allowing a remote authority call to live forever.
	runtimeCtx context.Context
}

// Finalize records ONE clean successful observation against the lane baseline.
func (b *BaselineToken) Finalize() bool {
	if b == nil || !b.Eligible || b.term == nil || b.term.dep.Lanes == nil {
		return false
	}
	// CAS ensures idempotent finalization even under concurrent calls.
	if !b.done.CompareAndSwap(false, true) {
		return false
	}
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

// CompletionResult is the outcome of spending a CompletionToken. Completion
// signals affect SUBSEQUENT admissions, never the request that just finished.
type CompletionResult struct {
	// EvidenceCodes are the scoped evidence codes persisted for this completion.
	EvidenceCodes []string
	// Persisted reports whether at least one completion signal was durably
	// appended to the evidence store (a store may be nil/persist-failed).
	Persisted bool
	// Err is a non-nil if the completion observation itself failed hard (e.g.
	// the terminating authority was unavailable). Producer best-effort skips are
	// not errors.
	Err error
}

// CompletionToken (P0.4A) carries the deferred completion observation from an
// authorized admission to the proxy-side end-of-stream event. It mirrors
// BaselineToken: a value token the proxy can only present or omit — it cannot
// fabricate completion evidence for a request it was never given the token for.
// Complete is idempotent.
type CompletionToken struct {
	subjects   producers.SubjectContext
	policy     *policy.CompiledPolicy
	done       atomic.Bool
	term       *Terminator
	runtimeCtx context.Context
}

// Complete records the ACTUAL resource consumption and outcome of a finished
// request, driving completion-time producers (token/cost velocity) and
// persisting their scoped evidence. It is safe to call on nil and idempotent.
// `actual` uses the resource governor's settlement units; `success` reports
// whether the upstream stream finished cleanly.
func (c *CompletionToken) Complete(actual resource.UsageEstimate, success bool) CompletionResult {
	if c == nil || c.term == nil {
		return CompletionResult{}
	}
	if !c.done.CompareAndSwap(false, true) {
		return CompletionResult{} // already observed
	}
	return c.term.observeCompletion(c.runtimeCtx, c.policy, c.subjects, actual, success)
}

// Complete is the Outcome convenience for the proxy lifecycle (P0.4A): spend the
// completion token with the finished request's actual usage. Safe on a denied
// outcome (nil token → empty result) and idempotent.
func (o *Outcome) Complete(actual resource.UsageEstimate, success bool) CompletionResult {
	if o == nil {
		return CompletionResult{}
	}
	return o.Completion.Complete(actual, success)
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
	if o.ResourceReservation != nil {
		return o.ResourceReservation
	}
	if o.ResourceRes != nil {
		return o.ResourceRes
	}
	if o.UsageRes != nil {
		return o.UsageRes
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
	Registry credential.Registry
	Peppers  *credential.PepperRing
	Lanes    lane.Repository
	Policy   *policy.Policy
	Signer   AssertionSigner
	Audience string
	Evidence evidence.Store // persistent evidence store; nil means no persistence

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
	Resource resource.ResourceAuthority

	// SourceID keys the SOURCE scope (network origin). Empty disables the SOURCE
	// scope in multi-scope provisioning. Default: "" (SOURCE skipped).
	SourceID string

	// Control is an OPTIONAL operator control plane (P0.39-P0.41). When set, the
	// admission pipeline consults it: EMERGENCY_LOCKDOWN denies NEW lane creation
	// and throttles traffic, and every decision is written to its audit trail
	// (P0.35). Nil disables both. Keep it nil unless a control plane is wired.
	Control *control.ControlPlane

	// Posture is the explicit authoritative posture reader for admission. In a
	// cluster this must be the shared state authority, not a process-local
	// ControlPlane cache. Control is retained separately for audit recording and
	// operator lifecycle compatibility; when Posture is nil, Control remains the
	// legacy fallback for standalone embedders.
	Posture control.PostureAuthority

	// SourceID was REMOVED (P0.4): a Terminator serves many clients, and a
	// process-global source id either disabled source security (empty) or
	// collapsed every client into one bucket. Source identity now rides the
	// REQUEST — see AdmitSource/TrustedSource.

	// Spray is an OPTIONAL source-spray / velocity detector (P0.67). When set,
	// each admission observes (SourceID, credential, feature ASN) and any spray
	// signature that crosses its window threshold is minted into the evidence
	// store — feeding the risk engine. Nil disables (no spray evidence).
	Spray *anomaly.Detector

	// Producers is an OPTIONAL set of live signal producers (BETA-07). When
	// set, each admission observes request behavior through every producer and
	// mints any resulting signals into the evidence store — feeding the risk
	// engine from REAL request behavior rather than manually seeded evidence.
	// Nil/empty disables live evidence production.
	Producers []producers.Producer

	// AdaptiveHealth reports durable checkpoint failures for adaptive state.
	// A failed checkpoint does not rewrite an already-authorized response, but
	// it prevents trust promotion and marks subsequent decisions degraded until
	// persistence recovers.
	AdaptiveHealth []AdaptivePersistenceHealth

	// Policies is the live policy authority. When set, each admission takes one
	// immutable snapshot from Current at its start; the snapshot is retained by
	// baseline/completion tokens so an activation cannot create a mixed-revision
	// decision for an in-flight request. Policy is still required as the initial
	// validated snapshot for construction and compatibility.
	Policies PolicyProvider
}

// resourceController abstracts concurrency admission per scope.
// The maxConcurrency parameter is the current cap for this scope — used so
// constrained credentials (cap 2) can be blocked even if existing leases are
// still active (new admissions respect the lower cap).
type resourceController interface {
	Acquire(scope string, maxConcurrency int) *resource.LeaseHandle
}

// AdaptivePersistenceHealth is implemented by durable detector wrappers.
// Readiness and admission use it to distinguish a live database from a
// database whose adaptive checkpoints are failing.
type AdaptivePersistenceHealth interface {
	PersistenceError() error
}

// PolicyProvider is the live policy authority consumed by the data plane.
// Implementations must return immutable compiled snapshots.
type PolicyProvider interface {
	Current() *policy.CompiledPolicy
}

// PolicySnapshotProvider is an optional hot-path extension. Snapshot returns
// the immutable compiled policy together with the activation epoch that makes
// policy freshness explicit across nodes.
type PolicySnapshotProvider interface {
	Snapshot() *policy.Snapshot
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
	policies    PolicyProvider
	pol         *policy.CompiledPolicy
	policyEpoch uint64
	// pruneCounter triggers pruning every N admissions (optimization only).
	pruneCounter *atomic.Int64
}

// New builds a Terminator and validates the critical seams for the requested
// Mode (P0.6): security-critical dependencies are mandatory per mode, and a
// missing one fails construction instead of degrading enforcement silently.
func New(dep Dependencies) (*Terminator, error) {
	initialPolicyEpoch := uint64(1)
	if dep.Registry == nil {
		return nil, errors.New("terminator: registry required")
	}
	if dep.Peppers == nil {
		return nil, errors.New("terminator: pepper ring required")
	}
	if dep.Policy == nil {
		if dep.Policies == nil {
			return nil, errors.New("terminator: policy required")
		}
		if snapshots, ok := dep.Policies.(PolicySnapshotProvider); ok {
			snapshot := snapshots.Snapshot()
			if snapshot == nil || snapshot.Policy == nil {
				return nil, errors.New("terminator: policy required")
			}
			dep.Policy = &snapshot.Policy.Policy
			if snapshot.ActivationEpoch > 0 {
				initialPolicyEpoch = snapshot.ActivationEpoch
			}
		} else {
			current := dep.Policies.Current()
			if current == nil {
				return nil, errors.New("terminator: policy required")
			}
			dep.Policy = &current.Policy
		}
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
		if dep.Concurrency == nil && dep.Resource == nil {
			return nil, errors.New("terminator: ENFORCE mode requires a hard concurrency controller or resource governor (fail-closed config)")
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
	return &Terminator{
		dep:          dep,
		policies:     dep.Policies,
		rand:         newRequestID,
		pol:          compiled,
		policyEpoch:  initialPolicyEpoch,
		pruneCounter: &atomic.Int64{},
	}, nil
}

func (t *Terminator) currentPolicySnapshot() (*policy.CompiledPolicy, uint64) {
	if t == nil {
		return nil, 0
	}
	compiled := t.pol
	epoch := t.policyEpoch
	if t.policies != nil {
		if snapshots, ok := t.policies.(PolicySnapshotProvider); ok {
			snapshot := snapshots.Snapshot()
			if snapshot == nil || snapshot.Policy == nil {
				return nil, 0
			}
			compiled = snapshot.Policy
			if snapshot.ActivationEpoch > 0 {
				epoch = snapshot.ActivationEpoch
			}
		} else {
			current := t.policies.Current()
			if current == nil {
				return nil, 0
			}
			compiled = current
		}
	}
	if epoch == 0 {
		epoch = 1
	}
	return compiled, epoch
}

func lanePolicyContext(compiled *policy.CompiledPolicy) lane.PolicyContext {
	if compiled == nil {
		return lane.DefaultPolicyContext()
	}
	return lane.PolicyContext{
		Classification: lane.ClassificationContext{
			Revision:   compiled.ClassificationRevision,
			Thresholds: compiled.Classification,
		},
		Limits:         compiled.LaneLimits,
		Security:       compiled.LaneSecurity,
		PolicyRevision: compiled.Revision,
	}
}

func adaptiveStatus(failed bool) AdaptiveStateStatus {
	if failed {
		return AdaptiveDegraded
	}
	return AdaptiveAvailable
}

func (t *Terminator) adaptivePersistenceFailed() bool {
	if t == nil {
		return false
	}
	for _, health := range t.dep.AdaptiveHealth {
		if health != nil && health.PersistenceError() != nil {
			return true
		}
	}
	return false
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

// NewRequestID creates a request identifier at the outer request boundary.
// The proxy uses it before any authentication, spooling, or adapter work so
// early failures can still be correlated with their decision record.
func NewRequestID() string { return newRequestID() }

// Admit runs the admission-state pipeline (P0.10) for a request's secret
// carriers and normalized feature set. The ordering is:
//
//  1. extract → strip → authenticate → policy binding → classify lane
//  2. mint evidence → persist (fail silently if store unavailable)
//  3. snapshot stored evidence (per-scope) → combine with per-request sync
//     evidence (only if append failed / store nil) for evaluation
//  4. compute credential risk + lane risk independently
//  5. security observation: update credential state (observe + CAS + rollback)
//  6. QUARANTINED → deny
//  7. select resource limits based on resulting credential state
//  8. security observation: update lane risk score (every admission)
//  9. policy enforcement with updated state
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
	return t.AdmitUsageContext(context.Background(), t.rand(), headers, feat, src, est)
}

// AdmitUsageWithRequestID is the request-boundary variant of AdmitUsage. The
// caller supplies the ID generated before ingress authentication; an empty ID
// is replaced with a fresh one for compatibility with internal callers.
func (t *Terminator) AdmitUsageWithRequestID(reqID string, headers map[string][]string, feat lane.Features, src TrustedSource, est resource.UsageEstimate) *Outcome {
	return t.AdmitUsageContext(context.Background(), reqID, headers, feat, src, est)
}

// AdmitUsageContext is the request-boundary admission entry point. Every
// authoritative lookup and mutation performed during admission inherits ctx;
// a remote authority therefore cannot outlive a canceled client request.
func (t *Terminator) AdmitUsageContext(ctx context.Context, reqID string, headers map[string][]string, feat lane.Features, src TrustedSource, est resource.UsageEstimate) *Outcome {
	if ctx == nil {
		ctx = context.Background()
	}
	compiled, policyEpoch := t.currentPolicySnapshot()
	if compiled == nil {
		return &Outcome{RequestID: reqID, Authorized: false, Reason: "policy_unavailable", DenialErr: errors.New("terminator: live policy unavailable")}
	}
	// Keep the existing implementation's receiver-local policy references while
	// ensuring every request uses the one snapshot selected above. The view
	// shares mutable counters and dependencies but has no independent authority.
	view := &Terminator{dep: t.dep, rand: t.rand, pol: compiled, policyEpoch: policyEpoch, pruneCounter: t.pruneCounter}
	out := view.admitUsageWithRequestID(ctx, reqID, headers, feat, src, est)
	if out.Baseline != nil || out.Completion != nil {
		runtimeCtx, _ := boundedRuntimeContext(ctx)
		if out.Baseline != nil {
			out.Baseline.runtimeCtx = runtimeCtx
		}
		if out.Completion != nil {
			out.Completion.runtimeCtx = runtimeCtx
		}
	}
	return out
}

// AdmitUsageWithRequestIDContext is the explicit-name compatibility variant of
// AdmitUsageContext for callers that already use the older API naming.
func (t *Terminator) AdmitUsageWithRequestIDContext(ctx context.Context, reqID string, headers map[string][]string, feat lane.Features, src TrustedSource, est resource.UsageEstimate) *Outcome {
	return t.AdmitUsageContext(ctx, reqID, headers, feat, src, est)
}

func (t *Terminator) admitUsageWithRequestID(ctx context.Context, reqID string, headers map[string][]string, feat lane.Features, src TrustedSource, est resource.UsageEstimate) *Outcome {
	if reqID == "" {
		reqID = t.rand()
	}
	now := t.dep.RiskNow()
	out := &Outcome{RequestID: reqID}
	adaptivePersistenceFailed := t.adaptivePersistenceFailed()
	resourceDiagnosticsFailed := false
	// P0.50: the internal decision trace lives for the whole pipeline and is
	// populated at every gate, so DENIED decisions are as explainable as
	// authorized ones. P0.51: policy identity is stamped from the COMPILED
	// policy here — not from the assertion, which only exists on authorization.
	tr := &DecisionTrace{
		RequestID:              reqID,
		At:                     now.UTC().Format(time.RFC3339Nano),
		PolicyID:               t.pol.ID,
		PolicyRevision:         t.pol.Revision,
		PolicyEpoch:            t.policyEpoch,
		CredentialSnapshotOK:   t.dep.Evidence == nil,
		LaneSnapshotOK:         t.dep.Evidence == nil,
		SourcePseudonym:        src.sourceID(),
		SourceObserved:         src.sourceID() != "",
		Estimate:               est,
		ReservationResult:      "none",
		Adaptive:               adaptiveStatus(adaptivePersistenceFailed),
		CredentialStatusBefore: "unknown",
		CredentialStatusAfter:  "unknown",
	}
	out.Trace = tr
	// P0.50: the trace is finalized at EXIT — every denial path (extraction,
	// authentication, lane, policy, resource) gets its reason and posture
	// stamped, not just the success path.
	defer func() {
		tr.Authorized = out.Authorized
		tr.Reason = out.Reason
		tr.Adaptive = out.Adaptive
		if out.Degraded || tr.Adaptive == AdaptiveDegraded {
			switch {
			case !tr.CredentialSnapshotOK || !tr.LaneSnapshotOK:
				tr.DegradedReason = "evidence_snapshot_unavailable"
			default:
				tr.DegradedReason = "security_observation_unavailable"
			}
		}
		tr.TrimEvidence(defaultTraceEvidenceCap)
	}()

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
	cred, err := t.authenticate(ctx, presented)
	if err != nil {
		out.Authorized = false
		out.Reason = safeReason(err)
		out.DenialErr = err
		// P0.50: a status-denied authentication (revoked/quarantined/expired)
		// still identified the credential — attribute the denial in the trace.
		if cred != nil {
			tr.CredentialID = cred.CredentialID
			tr.AccountID = cred.AccountID
			tr.CredentialStatusBefore = cred.Status.String()
			tr.CredentialStatusAfter = cred.Status.String()
			tr.CredentialRevBefore = cred.Revision
			tr.CredentialRevAfter = cred.Revision
		}
		tr.Reason = out.Reason
		// P0.30: INVALID-credential spray tracking. Before the presented
		// material is destroyed (defer above), derive a short-lived keyed
		// pseudonym INSIDE the sealed boundary and count DISTINCT candidate
		// keys per source. Raw candidate bytes are never retained; the signal
		// resolves through the same one-policy-authority path as all spray
		// signals. No trusted source identity → no attribution (fail-closed).
		if t.dep.Spray != nil && src.sourceID() != "" && errors.Is(err, credential.ErrUnknown) {
			// The spray key is the latest pepper key: SprayPseudonym is
			// domain-separated from verifier derivation inside the sealed
			// boundary, so the same key material never cross-purposes.
			if cand := t.dep.Peppers.DeriveSprayPseudonym(presented, t.dep.Peppers.Latest()); cand != "" {
				if sigs := t.dep.Spray.ObserveInvalidCredentialContext(ctx, src.sourceID(), cand, now); len(sigs) > 0 {
					// P0.8: the detector signals WHAT happened; the compiled policy
					// rule's scope resolves the subject from the request context
					// (here the source — the credential is unknown).
					srcSubjects := producers.SubjectContext{SourceID: src.sourceID()}
					for _, sig := range sigs {
						rule, ok := t.pol.EvidenceRules[sig.Code]
						if !ok {
							continue
						}
						sid, ok := producers.ResolveSubject(rule.Scope, srcSubjects)
						if !ok {
							continue
						}
						if ev, merr := evidence.Mint(t.pol.EvidenceRules, sig.Code, sid, now, t.pol.Revision); merr == nil && t.dep.Evidence != nil {
							_ = appendEvidenceContext(ctx, t.dep.Evidence, ev)
							tr.EvidenceIDs = append(tr.EvidenceIDs, ev.EvidenceID)
							tr.EvidenceCodes = append(tr.EvidenceCodes, ev.Code)
						}
					}
				}
			}
		}
		return out
	}
	tr.CredentialID = cred.CredentialID
	tr.AccountID = cred.AccountID
	tr.CredentialStatusBefore = cred.Status.String()
	tr.CredentialStatusAfter = cred.Status.String()
	tr.CredentialRevBefore = cred.Revision
	tr.CredentialRevAfter = cred.Revision
	controlEmergency := false
	postureAt := time.Time{}
	postureAuthority := t.dep.Posture
	if postureAuthority == nil && t.dep.Control != nil {
		postureAuthority = t.dep.Control
	}
	if postureAuthority != nil {
		var controlErr error
		var posture control.Posture
		if snapshotAuthority, ok := postureAuthority.(control.PostureSnapshotAuthority); ok {
			posture, postureAt, controlErr = snapshotAuthority.PostureSnapshotContext(ctx)
		} else {
			posture, controlErr = postureAuthority.PostureContext(ctx)
		}
		if controlErr != nil {
			out.Authorized = false
			out.Reason = "control_unavailable"
			out.DenialErr = controlErr
			return out
		}
		controlEmergency = posture == control.EmergencyLockdown
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
			auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = t.dep.Control.RecordAdmissionContext(auditCtx, control.Event{
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
	if cred.PolicyID != t.pol.ID && !(t.pol.ID == policy.DefaultPolicyID && cred.PolicyID == policy.LegacyDefaultPolicyID) {
		out.Authorized = false
		out.Reason = "policy_unavailable"
		out.DenialErr = fmt.Errorf("terminator: credential policy %q not loaded (loaded %q)", cred.PolicyID, t.pol.ID)
		return out
	}

	// 4. Classify lane.
	var lanesBefore, lanesAfter []string
	if t.dep.Lanes != nil {
		if reader, ok := t.dep.Lanes.(lane.ReadRepository); ok {
			lanesBefore, err = reader.ListIDs(ctx, cred.CredentialID)
			if err != nil {
				out.Authorized = false
				out.Reason = "lane_unavailable"
				out.DenialErr = err
				out.Degraded = true
				out.Adaptive = AdaptiveDegraded
				return out
			}
		} else {
			lanesBefore = t.dep.Lanes.ListLaneIDs(cred.CredentialID)
		}
	}
	laneID, laneRec, laneNew, lerr := t.classifyLane(ctx, cred.CredentialID, feat)
	if t.dep.Lanes != nil {
		if reader, ok := t.dep.Lanes.(lane.ReadRepository); ok {
			lanesAfter, err = reader.ListIDs(ctx, cred.CredentialID)
			if err != nil {
				out.Authorized = false
				out.Reason = "lane_unavailable"
				out.DenialErr = err
				out.Degraded = true
				out.Adaptive = AdaptiveDegraded
				return out
			}
		} else {
			lanesAfter = t.dep.Lanes.ListLaneIDs(cred.CredentialID)
		}
	}
	if lerr == nil {
		cleanupRemovedLaneResources(ctx, t.dep.Resource, lanesBefore, lanesAfter)
	}
	tr.LaneID = laneID
	tr.LaneNew = laneNew
	if laneRec != nil {
		tr.LaneTrustBefore = laneRec.State.String()
		tr.LaneSecBefore = laneRec.Security.Status.String()
		tr.LaneRevBefore = laneRec.Revision
		tr.LaneTrustAfter = laneRec.State.String()
		tr.LaneSecAfter = laneRec.Security.Status.String()
		tr.LaneRevAfter = laneRec.Revision
	}
	if lerr != nil {
		tr.Reason = "lane_error"
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
	var currentSourceEvidence []evidence.Evidence
	var currentLaneEvidence []evidence.Evidence
	var currentCredentialEvidence []evidence.Evidence
	// The authoritative subject context for resolving scoped signals (P0.8): the
	// same context feeds spray AND producer signal resolution, so both land on
	// the correct current-request subject.
	subjects := producers.SubjectContext{
		RequestID:    out.RequestID,
		SourceID:     src.sourceID(),
		LaneID:       laneID,
		CredentialID: cred.CredentialID,
		AccountID:    cred.AccountID,
	}
	// BETA-07/P0.8: Spray and live producers both emit signal CODES only; the
	// ONE resolveSignals path turns each into scoped evidence against the
	// current compiled policy. A spray threshold crossed on THIS request now
	// contributes to this request's evaluation at the correct scope, not just to
	// a later snapshot.
	if t.dep.Spray != nil && src.sourceID() != "" {
		if sigs := t.dep.Spray.ObserveContext(ctx, src.sourceID(), cred.CredentialID, feat.NetworkASN, now); len(sigs) > 0 {
			res := t.resolveSignals(sprayCodes(sigs), subjects, now)
			persistOnly = append(persistOnly, res.persisted...)
			currentSourceEvidence = append(currentSourceEvidence, res.source...)
			currentCredentialEvidence = append(currentCredentialEvidence, res.credential...)
		}
	}
	if len(t.dep.Producers) > 0 {
		var concurrencyErr error
		tr.ObservedConcurrency, concurrencyErr = t.currentConcurrency(ctx, laneID)
		if concurrencyErr != nil {
			// This is telemetry/adaptive input, not the hard resource gate. Treat
			// an unavailable reading as UNKNOWN so it cannot manufacture a zero
			// baseline or promote trust; the request remains subject to the
			// authoritative reservation below.
			tr.ObservedConcurrency = 0
			resourceDiagnosticsFailed = true
		}
		admissionBehavior := producers.AdmissionBehavior{
			Subjects: subjects,
			Features: producers.Features{
				NetworkASN:   feat.NetworkASN,
				NetworkType:  feat.NetworkType,
				RegionClass:  feat.RegionClass,
				ClientFamily: feat.ClientFamily,
			},
			EndpointFamily: feat.EndpointFamily,
			// P0.4B: live concurrency from the resource governor. Measures lane
			// concurrency (the scope for CONCURRENCY_OVER_* rules) plus this
			// attempted request. Falls back to 0 if no governor is configured.
			Concurrency: tr.ObservedConcurrency,
		}
		for _, prod := range t.dep.Producers {
			var sigs []producers.Signal
			if contextual, ok := prod.(producers.ContextProducer); ok {
				sigs = contextual.ObserveAdmissionContext(ctx, admissionBehavior)
			} else {
				sigs = prod.ObserveAdmission(admissionBehavior)
			}
			if len(sigs) > 0 {
				res := t.resolveSignals(producerCodes(sigs), subjects, now)
				persistOnly = append(persistOnly, res.persisted...)
				currentSourceEvidence = append(currentSourceEvidence, res.source...)
				currentLaneEvidence = append(currentLaneEvidence, res.lane...)
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
		_ = appendEvidenceContext(ctx, t.dep.Evidence, allEv...)
	}

	// 6. Snapshot evidence by subject (credential + lane + source
	// INDEPENDENTLY, with SEPARATE error state per snapshot — P0.3). Never
	// depend on read-after-write for current-request evidence: always combine
	// historical snapshot + current sync evidence, deduplicated by
	// EvidenceID.
	credSubjects := []evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: cred.CredentialID}}
	laneSubjects := []evidence.SubjectKey{{Scope: evidence.ScopeLane, ID: laneID}}

	// BETA-06: Source-scoped evidence snapshot. Source risk is an INDEPENDENT
	// dimension — it must not be blended into lane or credential risk so
	// that source-spray attack evidence can drive source-level enforcement
	// without contaminating the lane/credential risk.
	var sourceSubjects []evidence.SubjectKey
	srcID := src.sourceID()
	if srcID != "" {
		sourceSubjects = []evidence.SubjectKey{{Scope: evidence.ScopeSource, ID: srcID}}
	}

	// adaptive tracks whether authoritative history was available (P0.1). An
	// unavailable history is UNKNOWN, not empty: it must never become risk=0 in
	// the state machine.
	adaptive := adaptiveStatus(adaptivePersistenceFailed)
	if resourceDiagnosticsFailed {
		adaptive = AdaptiveDegraded
	}
	var credentialEvidence, laneEvidence, sourceEvidence []evidence.Evidence
	credSnapOK := t.dep.Evidence == nil
	laneSnapOK := t.dep.Evidence == nil
	sourceSnapOK := t.dep.Evidence == nil || srcID == ""
	if t.dep.Evidence != nil {
		snap, snapErr := snapshotEvidenceContext(ctx, t.dep.Evidence, credSubjects, now)
		if snapErr != nil {
			adaptive = AdaptiveDegraded
		} else {
			credentialEvidence = snap
			credSnapOK = true
		}
		snap, snapErr = snapshotEvidenceContext(ctx, t.dep.Evidence, laneSubjects, now)
		if snapErr != nil {
			adaptive = AdaptiveDegraded
		} else {
			laneEvidence = snap
			laneSnapOK = true
		}
		// BETA-06: source snapshot is independent — an outage degrades
		// adaptive posture but never silently drops source evidence.
		if len(sourceSubjects) > 0 {
			snap, snapErr = snapshotEvidenceContext(ctx, t.dep.Evidence, sourceSubjects, now)
			if snapErr != nil {
				adaptive = AdaptiveDegraded
			} else {
				sourceEvidence = snap
				sourceSnapOK = true
			}
		}
	}
	// P0.50: per-subject evidence detail in the trace (IDs + codes), bounded.
	for _, ev := range credentialEvidence {
		tr.EvidenceIDs = append(tr.EvidenceIDs, ev.EvidenceID)
		tr.EvidenceCodes = append(tr.EvidenceCodes, ev.Code)
	}
	for _, ev := range laneEvidence {
		tr.EvidenceIDs = append(tr.EvidenceIDs, ev.EvidenceID)
		tr.EvidenceCodes = append(tr.EvidenceCodes, ev.Code)
	}
	for _, ev := range sourceEvidence {
		tr.EvidenceIDs = append(tr.EvidenceIDs, ev.EvidenceID)
		tr.EvidenceCodes = append(tr.EvidenceCodes, ev.Code)
	}
	// P0.45: only evidence minted under the CURRENT policy revision may drive the
	// authoritative state machine. Evidence from an older revision was scored
	// under a different rule table; evaluating it after a policy change would
	// apply old-era risk to new-era thresholds. Filter fail-closed (stale-revision
	// evidence is dropped); current-request sync evidence is always current-rev.
	credentialEvidence = activeEvidenceAcrossPolicyRevisions(credentialEvidence, t.pol.Revision)
	laneEvidence = activeEvidenceAcrossPolicyRevisions(laneEvidence, t.pol.Revision)
	// P0.7 fix: source evidence must also be filtered by policy revision.
	sourceEvidence = activeEvidenceAcrossPolicyRevisions(sourceEvidence, t.pol.Revision)
	// Current-request sync evidence (scope: lane) is included in evaluation
	// EVERY time it was minted, independent of append/snapshot success, so a
	// store outage or read-after-write lag can never drop the current signal
	// (P0.3). Deduplicate so an append that DID land cannot double-count.
	laneEvidence = dedupAppend(laneEvidence, syncEv)
	// P0.8 fix: include current signals in evaluation even if append fails, so a
	// spray/producer threshold crossed on THIS request restricts THIS request at
	// the correct scope — not just a later snapshot.
	sourceEvidence = dedupAppend(sourceEvidence, currentSourceEvidence)
	laneEvidence = dedupAppend(laneEvidence, currentLaneEvidence)
	credentialEvidence = dedupAppend(credentialEvidence, currentCredentialEvidence)

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
	tr.CredentialRisk = credentialRisk
	tr.LaneRisk = laneRisk
	tr.CredentialEvidenceCount = len(credentialEvidence)
	tr.LaneEvidenceCount = len(laneEvidence)
	tr.CredentialSnapshotOK = credSnapOK
	tr.LaneSnapshotOK = laneSnapOK

	// Collect all evidence codes for outcome explainability.
	// P0.7 fix: include source evidence.
	allEvidence := append(append([]evidence.Evidence{}, credentialEvidence...), laneEvidence...)
	allEvidence = append(allEvidence, sourceEvidence...)
	evidenceCodes := evCodes(allEvidence)

	// 8. Apply the credential risk observation through the authoritative
	// load/reduce/CAS protocol. This component preserves persisted restrictions
	// when history is unavailable and retries one concurrent-writer conflict.
	observation := t.observeCredentialRisk(ctx, out.RequestID, cred, credentialRisk, evidenceCodes, adaptive, adaptivePersistenceFailed, out, now)
	updatedCred := observation.credential
	after := observation.status
	adaptiveForObservation := observation.adaptive

	// QUARANTINED at any point → deny immediately (with the actual quarantine
	// error, not ErrRevoked — P0.30 transport-mapping cleanup).
	if after == credential.StatusQuarantined {
		out.Authorized = false
		out.Reason = "credential_restricted"
		out.DenialErr = credential.ErrQuarantined
		out.CredentialRisk = credentialRisk
		out.LaneRisk = laneRisk
		out.RiskAfter = effectiveRisk
		out.Evidence = evidenceCodes
		out.Adaptive = adaptiveForObservation
		return out
	}

	// Emergency-lockdown gate (P0.40/P0.41): in EMERGENCY_LOCKDOWN the operator
	// switch denies NEW lanes outright (reduce attack surface immediately) while
	// pre-existing lanes and persisted restrictions remain in force. A denied
	// NEW-lane request may already have materialized a row in the shared
	// authority; comparing its first-seen time with the shared posture epoch
	// prevents another node from laundering that row into an admitted request.
	createdDuringLockdown := false
	if controlEmergency && laneRec != nil && !postureAt.IsZero() {
		createdDuringLockdown = !laneRec.FirstSeenAt.Before(postureAt)
	}
	if controlEmergency && (laneNew || createdDuringLockdown) {
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
	tr.CredentialStatusAfter = cred.Status.String()
	tr.CredentialRevAfter = cred.Revision

	// 9. Security observation: update lane risk score + lane security status
	// (every admission, authorized or not) BEFORE limits selection so a lane that
	// has just crossed into SUSPICIOUS/BLOCKED is restricted from THIS request
	// (P0.7: lane risk must produce real lane enforcement, not just a stored score).
	var laneSec lane.SecurityStatus
	if t.dep.Lanes != nil {
		var rec *lane.LaneRecord
		var rerr error
		laneMeta := lane.TransitionMetadata{RequestID: out.RequestID, PolicyRevision: t.pol.Revision, EvidenceCodes: evidenceCodes}
		lanePolicy := lanePolicyContext(t.pol)
		if aware, ok := t.dep.Lanes.(lane.PolicyAwareRepository); ok {
			rec, rerr = aware.ObserveRiskWithPolicy(ctx, cred.CredentialID, laneID, laneRisk, now, lanePolicy, laneMeta)
		} else if aware, ok := t.dep.Lanes.(lane.MetadataAwareRepository); ok {
			rec, rerr = aware.ObserveRiskWithMetadata(cred.CredentialID, laneID, laneRisk, now, laneMeta)
		} else if aware, ok := t.dep.Lanes.(lane.RequestAwareRepository); ok {
			rec, rerr = aware.ObserveRiskWithRequestID(cred.CredentialID, laneID, laneRisk, now, out.RequestID)
		} else {
			rec, rerr = t.dep.Lanes.ObserveRisk(cred.CredentialID, laneID, laneRisk, now)
		}
		if rerr == nil {
			laneSec = rec.Security.Status
			laneRec = rec
			tr.LaneTrustAfter = rec.State.String()
			tr.LaneSecAfter = rec.Security.Status.String()
			tr.LaneRevAfter = rec.Revision
		} else {
			out.Authorized = false
			out.Reason = "lane_unavailable"
			out.DenialErr = rerr
			out.CredentialRisk = credentialRisk
			out.LaneRisk = laneRisk
			out.RiskAfter = effectiveRisk
			out.Evidence = evidenceCodes
			out.Adaptive = AdaptiveDegraded
			out.Degraded = true
			return out
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
	limitsClass := "normal"
	if after == credential.StatusConstrained {
		limitsClass = "constrained"
	}
	if laneSec == lane.LaneSuspicious {
		limits = t.pol.Limits.Constrained
		limitsClass = "constrained"
	}
	if controlEmergency {
		limits = t.emergencyLimits()
		limitsClass = "emergency"
	}
	tr.LimitsClass = limitsClass
	tr.Limits = limits

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

	// BETA-06 / P0.7: Source risk evaluation. Source evidence is scored
	// independently from credential/lane risk. sourceWouldBlock is the raw
	// threshold crossing (sourceRisk >= SourceBlockThresh). Admission is only
	// actually denied when SourceMode == SourceEnforce; under the default
	// SourceObserve the crossing is recorded in telemetry but never blocks.
	// This is narrow containment: enforcement targets only the attacking
	// source, not the credential globally, and an operator opts into enforcing
	// it only after validating the source heuristics (NAT/VPN/CDN egress are
	// not abuse by themselves).
	sourceRisk := risk.Evaluate(sourceEvidence, now)
	sourceWouldBlock := false
	if srcID != "" && t.pol.Risk.SourceBlockThresh > 0 && sourceRisk >= t.pol.Risk.SourceBlockThresh {
		sourceWouldBlock = true
	}
	// Telemetry truthfully reports whether the source WOULD block under
	// enforcement, regardless of the current mode.
	tr.SourceRisk = sourceRisk
	tr.SourceBlocked = sourceWouldBlock
	tr.SourceSnapshotOK = sourceSnapOK

	in := policy.EvalInput{
		CredentialRevoked: polCred.Status == credential.StatusRevoked,
		Emergency:         polCred.Status == credential.StatusQuarantined,
		LaneOverLimit:     laneRec != nil && (laneRec.State == lane.StateBlocked || laneSec == lane.LaneBlocked),
		RiskDenied:        riskDenied,
		// P0.7: enforcement is gated on the explicit SourceMode. Shadow
		// (default) records the would-block but never denies.
		SourceBlocked: t.pol.Risk.SourceMode == policy.SourceEnforce && sourceWouldBlock,
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
		// classifyLane/ObserveRisk return the committed record. Reuse that
		// snapshot instead of performing a second untyped read that could turn a
		// backend error into a fabricated NEW state.
		if laneRec != nil {
			finalLaneState = laneRec.State.String()
		} else if reader, ok := t.dep.Lanes.(lane.ReadRepository); ok {
			fr, found, rerr := reader.LookupLane(ctx, cred.CredentialID, laneID)
			if rerr != nil {
				out.Authorized = false
				out.Reason = "lane_unavailable"
				out.DenialErr = rerr
				out.Degraded = true
				out.Adaptive = AdaptiveDegraded
				return out
			}
			if !found || fr == nil {
				out.Authorized = false
				out.Reason = "lane_unavailable"
				out.DenialErr = lane.ErrLaneNotFound
				out.Degraded = true
				out.Adaptive = AdaptiveDegraded
				return out
			}
			finalLaneState = fr.State.String()
		} else {
			// Legacy repositories have no strict read seam. Their successful
			// mutation should have returned laneRec; an absent record is not a
			// reason to manufacture authority, so deny conservatively.
			out.Authorized = false
			out.Reason = "lane_unavailable"
			out.DenialErr = lane.ErrLaneNotFound
			out.Degraded = true
			out.Adaptive = AdaptiveDegraded
			return out
		}
	} else {
		finalLaneState = "NEW"
	}

	authCtx := principal.AuthorizedContext{
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
		provErr := t.provisionMultiscope(ctx, cred, laneID, laneSec, limits, authCtx, reqID, out, adaptiveForObservation, laneRisk, credentialRisk, effectiveRisk, evidenceCodes, src, est, tr)
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
		assertion, err := t.issueAssertion(authCtx, reqID, cred)
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
		assertion, err := t.issueAssertion(authCtx, reqID, cred)
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
			CredentialID:   cred.CredentialID,
			LaneID:         laneID,
			LaneRisk:       laneRisk,
			RequestID:      out.RequestID,
			PolicyRevision: t.pol.Revision,
			EvidenceCodes:  append([]string(nil), evidenceCodes...),
			// Baseline finalization requires AVAILABLE adaptive posture (P0.1):
			// unreliable history must not build trust upward, so a degraded
			// admission's token is issued but the proxy-side finalize is a
			// no-op for it (flagged in the token).
			Eligible: adaptiveForObservation == AdaptiveAvailable,
			policy:   t.pol,
			term:     t,
		}
	}

	// P0.4A: issue the completion token when completion producers are wired so
	// token/cost velocity is judged against the ACTUAL usage at end-of-stream,
	// not the admission estimate. It captures the authoritative subjects so the
	// proxy cannot influence the scope a completion signal lands on.
	if len(t.dep.Producers) > 0 {
		out.Completion = &CompletionToken{
			subjects: producers.SubjectContext{
				RequestID:    out.RequestID,
				SourceID:     src.sourceID(),
				LaneID:       laneID,
				CredentialID: cred.CredentialID,
				AccountID:    cred.AccountID,
			},
			policy: t.pol,
			term:   t,
		}
	}

	// 14. Periodic evidence pruning (optimization only).
	// Pruning runs every admission to bound memory, not just successful
	// authorizations — evidence activity (including denied requests) can
	// contribute to pruning needs.
	if t.pruneCounter != nil && t.pruneCounter.Add(1)%50 == 0 && t.dep.Evidence != nil {
		t.pruneEvidence(ctx, now, credSubjects, laneSubjects, sourceSubjects...)
	}

	// Every gate passed.
	out.Principal = prin
	out.Context = authCtx
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

func (t *Terminator) provisionMultiscope(requestCtx context.Context, cred *credential.Credential, laneID string, laneSec lane.SecurityStatus, limits policy.Limits, authCtx principal.AuthorizedContext, reqID string, out *Outcome, adaptiveForObservation AdaptiveStateStatus, laneRisk, credentialRisk, effectiveRisk int, evidenceCodes []string, src TrustedSource, est resource.UsageEstimate, tr *DecisionTrace) *Outcome {
	_ = laneSec
	return resourceAdmission{
		term: t, requestCtx: requestCtx, cred: cred, laneID: laneID,
		limits: limits, authCtx: authCtx, requestID: reqID, out: out,
		adaptive: adaptiveForObservation, laneRisk: laneRisk,
		credentialRisk: credentialRisk, effectiveRisk: effectiveRisk,
		evidenceCodes: evidenceCodes, source: src, estimate: est, trace: tr,
	}.run()
}
