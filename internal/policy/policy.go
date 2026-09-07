// Package policy models the versioned, validated policy that drives
// authorization (spec §56-58). All policy is versioned; the data plane loads
// only authenticated + validated policy and keeps the previous revision for
// rollback (§57). Enforcement follows the fixed precedence of §58 so a more
// permissive lower-level rule can never override a higher-priority denial.
package policy

import (
	"errors"
	"time"

	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
)

// RiskThresholds are the credential/lane risk-state boundaries (§31).
// All thresholds must be strictly ordered: 0 < Watch < Constrained < Quarantine <= 100.
// Down-thresholds govern automatic recovery from elevated states.
type RiskThresholds struct {
	Watch                 int           // escalate to WATCH if risk >= this
	Constrained           int           // escalate to CONSTRAINED if risk >= this
	Quarantine            int           // escalate to QUARANTINED if risk >= this
	ConstrainedDownThresh int           // CONSTRAINED→WATCH if risk < this
	WatchDownThresh       int           // WATCH→NORMAL if risk < this
	ConstrainedDwell      time.Duration // dwell time for CONSTRAINED→WATCH recovery
	WatchDwell            time.Duration // dwell time for WATCH→NORMAL recovery
	WatchObs              int           // qualifying observations needed for WATCH entry

	// EnableAutomaticQuarantine gates the durable QUARANTINED status escalation
	// (§102 phase 6, Gate H). Automatic quarantine MUST be disabled until shadow
	// validation proves the risk model — a high risk score may deny the request
	// (temporarily_restricted) but must NOT persist a quarantine the operator did
	// not validate. Default false = fail-closed shadow-first posture. When false,
	// the risk state machine caps auto-escalation at CONSTRAINED; quarantine is
	// operator-set only.
	EnableAutomaticQuarantine bool

	// SourceBlockThresh is the source-scoped risk threshold above which a
	// source is considered blocked (BETA-06). Source risk is computed
	// independently from credential/lane risk. A source at or above this
	// threshold produces sourceWouldBlock=true in telemetry. Whether that
	// actually denies admission depends on SourceMode: in SourceObserve (the
	// default) it is shadow-only (recorded, not enforced); in SourceEnforce it
	// is evaluated as a denial (P0.7). A zero threshold with SourceEnforce
	// denies nothing (nothing is "at or above" an unset bound).
	SourceBlockThresh int
	// SourceMode selects shadow-only vs. enforcing source blocking (P0.7).
	// Default SourceObserve: a public beta must not silently block a shared
	// NAT / corporate / mobile-carrier / VPN egress behind a source heuristic
	// until an operator has validated it.
	SourceMode SourceEnforcementMode
}

// SourceEnforcementMode controls whether source-risk blocking is enforced or
// shadow-recorded (P0.7). The default is SourceObserve so a shared upstream IP
// (home/corporate/mobile NAT, VPN exit, CDN edge) is never blocked silently on
// a heuristic the operator has not yet validated.
type SourceEnforcementMode int

const (
	// SourceObserve records sourceWouldBlock in telemetry but never denies
	// admission on source risk alone. Safe default for a public beta.
	SourceObserve SourceEnforcementMode = iota
	// SourceEnforce denies admission when a source crosses SourceBlockThresh.
	SourceEnforce
)

// Limits captures hard resource limits per scope as policy (P0.19).
//
// The per-scope gauges are the ONLY limit representation. The legacy burst/rate
// and velocity-multiplier fields (RequestBurstCap, RequestRate,
// TokenVelocityMult, CostVelocityMult) had zero live consumers and were removed
// (P0.19 collapse); actual enforcement uses the Requests/Tokens/Cost windowed
// gauges plus ConcurrencyCap. Tokens and Cost are left disabled (zero capacity)
// until provider-specific per-dimension budgets are authored.
type Limits struct {
	ConcurrencyCap int

	Requests BucketConfig // hard REQUEST gauge (P0.35): burst + refill per scope. Zero disables (velocity left to ConcurrencyCap).
	Tokens   BucketConfig // hard TOKEN gauge across input/output/combined dims (P0.35). Zero disables.
	Cost     BucketConfig // hard SPEND gauge in microunits (P0.35). Zero disables.
}

// BucketConfig is one gauge's burst/rate policy (P0.35). Capacity is the
// burst allowance; RefillPer tokens are credited every RefillIn. A zero
// Capacity disables the gauge.
type BucketConfig struct {
	Capacity  int64
	RefillPer int64
	RefillIn  time.Duration
}

// Learning controls baseline seeding (§29, §42) and lane promotion criteria.
type Learning struct {
	MaximumRisk   int
	AllowNewLanes bool
	// AllowSuspiciousLanes is DEPRECATED and has no effect. SUSPICIOUS/BLOCKED
	// lanes NEVER promote (INV-8). This field is retained for wire compatibility
	// but is ignored by PromoteIfEligible — it remains here so existing policy
	// serializations do not break. Remove in a future breaking change.
	AllowSuspiciousLanes bool // DEPRECATED: no effect, INV-8 forbids suspicious promotion

	// Promotion criteria for lanes. These are policy-controlled, not hardcoded.
	MinCleanAge          time.Duration // minimum continuous clean age
	MinCleanRequests     int64         // minimum authorized clean requests
	MinCleanActiveDays   int           // minimum distinct active days with clean history
	MaxEstablishmentRisk int           // risk below this threshold for promotion

	// DisqualifyingEvidenceCodes (P0.26): evidence codes that independently
	// prevent lane promotion while ACTIVE against the lane's subject — a
	// semantic veto, not a score contribution. A scalar risk bound can
	// under-represent a single severe signal (averaging hides it); this list
	// names the codes whose live presence means the lane must not become
	// trusted baseline material, whatever the aggregate says. Empty list = no
	// code-level veto (the score bound and security-status gate still apply).
	DisqualifyingEvidenceCodes []string
}

// Privacy flags retention policy (§72).
type Privacy struct {
	PromptRetention     bool
	CompletionRetention bool
}

// Identity configures internal-assertion lifetime (INV-10).
type Identity struct {
	MaxTTLSeconds int
}

// ScopedLimits are per-scope policy overrides (plan / credential / lane).
// Emergency (P0.48) is the incident-mode limit set: when the operator control
// plane is in EMERGENCY_LOCKDOWN, EVERY admission (established lanes included)
// is provisioned against these limits — that is what "throttles all traffic"
// means concretely. A nil Emergency falls back to Constrained (fail-closed for
// traffic volume: an unset emergency profile never grants MORE than the
// constrained posture).
type ScopedLimits struct {
	Normal      Limits
	Constrained Limits
	// Emergency is explicit optional configuration. A nil pointer means no
	// emergency profile was authored and therefore falls back to Constrained;
	// zero-valued limits are no longer ambiguous with "present but deny all".
	Emergency *Limits
}

// Policy is one versioned, immutable policy revision.
type Policy struct {
	ID       string
	Revision int

	Risk   RiskThresholds
	Limits ScopedLimits
	// LaneLimits owns lane capacity and retention policy alongside the lane
	// security hysteresis below. The terminator wires this compiled value into
	// both resident and durable lane repositories.
	LaneLimits lane.Limits
	// Global carries the whole-plane (fleet) limits (P0.19). Global replaces
	// the old magic Normal.ConcurrencyCap*1024 derivation; a zero
	// Global.ConcurrencyCap disables the fleet gauge. Leaving Tokens/Cost zero
	// keeps the fleet bound concurrency-only unless a deployment authors them.
	Global   Limits
	Learning Learning
	Privacy  Privacy
	Identity Identity

	// LaneSecurity is the lane risk→security-status hysteresis, policy-
	// controlled (P0.13): the thresholds AND the EnableAutomaticBlock gate live
	// in the versioned policy, not in store defaults — policy_rev=42 must fully
	// describe the transition rules that revision enforces. The terminator
	// applies this to its lane store at construction so the compiled revision is
	// the one authority for lane security behavior. A zero value falls back to
	// lane.DefaultSecurityHysteresis() at use time.
	LaneSecurity lane.SecurityHysteresis

	// EvidenceRules is the VERSIONED evidence rule table (P0.11): every
	// security-relevant field of minted evidence — family, scope, score,
	// severity, confidence, correlation group, TTL — is derived from this table,
	// never from a package-global default. A nil/empty table fails closed at the
	// mint site (Mint rejects a missing rule instead of inventing parameters).
	EvidenceRules evidence.Table

	// Classification carries the lane-similarity cutoffs (Match / Related /
	// MinComparableWeight) as policy (P0.11). The data plane must classify lanes
	// against the COMPILED revision's cutoffs — not lane.DefaultThresholds() —
	// so a policy author can tune anti-laundering sensitivity in the versioned
	// artifact without a code edit.
	Classification lane.ClassificationThresholds

	// ClassificationRevision is a lane-universe revision, distinct from Policy.
	//Revision (P0.21). It must be bumped ONLY when lane classification
	// semantics change in a way that should re-key lanes:
	//
	//	feature schema, feature weighting, classification thresholds,
	//	comparable-mass rules, lane matching semantics.
	//
	// It is hashed into the deterministic lane ID (alongside the feature vector)
	// and persisted on each LaneRecord, so BorrowOrCreate only crosses revisions
	// when both the feature schema AND this revision match. A change that merely
	// tunes an unrelated limit (e.g. a request-rate window) must NOT bump this —
	// it would needlessly fragment the lane universe.
	ClassificationRevision int

	// CreatedAt and signature hooks reserved for authenticated+validated load.
	CreatedAt time.Time
}

// Default returns the spec §56 example defaults.
func Default() *Policy {
	return &Policy{
		ID:       "fi-default-v1",
		Revision: 1,
		Risk: RiskThresholds{
			Watch:                 30,
			Constrained:           55,
			Quarantine:            80,
			ConstrainedDownThresh: 40,
			WatchDownThresh:       20,
			ConstrainedDwell:      15 * time.Minute,
			WatchDwell:            30 * time.Minute,
			WatchObs:              2,
			// P0.7: source blocking is shadow-only by default in the public
			// beta. SourceBlockThresh is recorded so telemetry can truthfully
			// report "would block under enforcement", but SourceMode stays
			// SourceObserve (no automatic source denial) until an operator opts
			// into SourceEnforce for its validated environment.
			SourceBlockThresh: 60,
			SourceMode:        SourceObserve,
		},
		// P0.19: the request gauges translate the old burst/rate representation
		// (burst=Capacity, rate=RefillPer per minute). Tokens/Cost Explicitly
		// left disabled (zero capacity) until provider-specific windows are
		// authored — we do not invent token/spend budgets from the deleted
		// velocity multipliers.
		Limits: ScopedLimits{
			Normal: Limits{
				ConcurrencyCap: 32,
				Requests:       BucketConfig{Capacity: 64, RefillPer: 300, RefillIn: time.Minute},
			},
			Constrained: Limits{
				ConcurrencyCap: 2,
				Requests:       BucketConfig{Capacity: 8, RefillPer: 20, RefillIn: time.Minute},
			},
			// P0.48: incident posture — deliberately tighter than constrained.
			// A credential holds at most ONE in-flight request under lockdown.
			Emergency: &Limits{
				ConcurrencyCap: 1,
				Requests:       BucketConfig{Capacity: 1, RefillPer: 5, RefillIn: time.Minute},
			},
		},
		// P0.19: Global replaces the old magic Normal.ConcurrencyCap*1024 fleet
		// derivation. A modest explicit fleet bound, concurrency-only.
		Global: Limits{ConcurrencyCap: 32 * 1024},
		Learning: Learning{
			MaximumRisk:          20,
			AllowNewLanes:        false,
			AllowSuspiciousLanes: false,
			MinCleanAge:          7 * 24 * time.Hour,
			MinCleanRequests:     200,
			MinCleanActiveDays:   3,
			MaxEstablishmentRisk: 15,
			// P0.26 baseline: the high-severity abuse families veto promotion
			// while active. Source-discontinuity novelty (NEW_ASN etc.) is
			// deliberately NOT disqualifying on its own — it is normal churn;
			// abuse correlation and resource-velocity abuse are.
			DisqualifyingEvidenceCodes: []string{
				"MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN",
				"SIMULTANEOUS_ESTABLISHED_LANE_FROM_UNRELATED_ASN",
				"SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS",
				"CONCURRENCY_OVER_10X_BASELINE",
				"TOKEN_VELOCITY_OVER_10X_BASELINE",
				"COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR",
				"MANUAL_CONFIRMED_COMPROMISE",
			},
		},
		Privacy:  Privacy{PromptRetention: false, CompletionRetention: false},
		Identity: Identity{MaxTTLSeconds: 30},
		// P0.21: initial classification universe. Bump only on a classification
		// semantics change (feature schema/weights, thresholds, comparable-mass,
		// match rules), never on unrelated limit tuning.
		ClassificationRevision: 1,
		// P0.13: lane security hysteresis is policy-owned. Automatic lane BLOCK
		// ships DISABLED (shadow-first default, matching
		// Risk.EnableAutomaticQuarantine); an operator must enable it explicitly
		// in a validated revision.
		LaneSecurity: lane.DefaultSecurityHysteresis(),
		// EvidenceRules + Classification: the compiled-policy baseline is seeded
		// from the spec's illustrative tables (§36, §26) so a default policy is
		// identical to today's behavior; a policy author overrides these fields in
		// the versioned artifact (P0.11). The data plane reads them from the
		// compiled revision, never the package globals.
		EvidenceRules:  evidence.DefaultTable(),
		Classification: lane.DefaultThresholds(),
		LaneLimits:     lane.DefaultLimits(),
	}
}

// CompiledPolicy is a validated, deep-copied policy snapshot (P0.10). The data
// plane stores ONLY a CompiledPolicy: a shallow struct copy of Policy shares
// the EvidenceRules map with the caller, so a post-construction mutation of the
// caller's table would rewrite live enforcement. Compile copies every
// reference-bearing field; the result is the caller's to mutate freely with no
// effect on enforcement.
type CompiledPolicy struct {
	Policy
}

// Compile validates and deep-copies a policy revision. It returns an error on
// an invalid policy rather than compiling one that fails closed later.
func Compile(p *Policy) (*CompiledPolicy, error) {
	if !p.IsValid() {
		return nil, errors.New("policy: invalid policy revision")
	}
	c := &CompiledPolicy{Policy: *p}
	if c.LaneLimits.MaxActiveLanesPerCredential == 0 {
		c.LaneLimits = lane.DefaultLimits()
	}
	if p.Limits.Emergency != nil {
		emergency := *p.Limits.Emergency
		c.Limits.Emergency = &emergency
	}
	// Deep-copy every reference-bearing field (P0.10). EvidenceRules is the
	// map that matters today; Classification and the threshold structs are
	// value types copied by the struct copy above. Any field added to Policy
	// holding a slice or map MUST be added here — the terminator immutability
	// test (TestCompiledPolicyIsImmutableAgainstCallerMutation) fails on a
	// shared map otherwise.
	if p.EvidenceRules != nil {
		c.EvidenceRules = make(evidence.Table, len(p.EvidenceRules))
		for code, rule := range p.EvidenceRules {
			c.EvidenceRules[code] = rule
		}
	}
	// P0.10/P0.26: DisqualifyingEvidenceCodes is a slice — also a
	// reference-bearing field. Deep-copy it so the caller cannot mutate live
	// enforcement's veto list after Compile.
	if len(p.Learning.DisqualifyingEvidenceCodes) > 0 {
		codes := make([]string, len(p.Learning.DisqualifyingEvidenceCodes))
		copy(codes, p.Learning.DisqualifyingEvidenceCodes)
		c.Learning.DisqualifyingEvidenceCodes = codes
	}
	return c, nil
}

// IsValid reports whether a policy revision is structurally valid to load
// (§57: the data plane loads only validated policy). Beyond identity fields it
// checks the risk-threshold ordering, down-thresholds, dwell times, observation
// count, and promotion criteria bounds.
func (p *Policy) IsValid() bool {
	if p == nil || p.ID == "" {
		return false
	}
	if p.Revision < 1 {
		return false
	}
	// INV-10: internal assertions are short-lived, hard-capped at 30s (P0.28
	// closes the doc-vs-code 60s gap; the stated invariant is ≤30).
	if p.Identity.MaxTTLSeconds < 1 || p.Identity.MaxTTLSeconds > 30 {
		return false
	}
	t := p.Risk
	// Escalation thresholds strictly ordered: 0 < Watch < Constrained < Quarantine <= 100.
	if !(0 < t.Watch && t.Watch < t.Constrained && t.Constrained < t.Quarantine && t.Quarantine <= 100) {
		return false
	}
	// Down-thresholds strictly below their escalation thresholds.
	if !(t.WatchDownThresh < t.Watch) {
		return false
	}
	if !(t.ConstrainedDownThresh < t.Constrained) {
		return false
	}
	// All thresholds within 0..100.
	if t.WatchDownThresh < 0 || t.WatchDownThresh > 100 {
		return false
	}
	if t.ConstrainedDownThresh < 0 || t.ConstrainedDownThresh > 100 {
		return false
	}
	// Dwell times must be positive.
	if t.ConstrainedDwell <= 0 || t.WatchDwell <= 0 {
		return false
	}
	// WatchObs must be at least 1.
	if t.WatchObs < 1 {
		return false
	}
	// P1-20: the source-scoped block threshold is a real enforcement gate, so
	// it must be in range 1..100 in BOTH modes — an out-of-range value in
	// SourceObserve would silently promise a block point telemetry can never
	// observe, and in SourceEnforce it would either never fire (0 is
	// unreachable below Watch) or always fire (>100).
	if t.SourceBlockThresh < 1 || t.SourceBlockThresh > 100 {
		return false
	}
	if t.SourceMode != SourceObserve && t.SourceMode != SourceEnforce {
		return false
	}
	// Promotion criteria must be non-negative and within bounds.
	if p.Learning.MaxEstablishmentRisk < 0 || p.Learning.MaxEstablishmentRisk > 100 {
		return false
	}
	if p.Learning.MinCleanAge < 0 || p.Learning.MinCleanRequests < 0 || p.Learning.MinCleanActiveDays < 0 {
		return false
	}
	// P0.26: every disqualifying code must exist in the compiled evidence rule
	// table — a veto naming a code the policy cannot mint is dead configuration
	// (and a typo would silently never fire).
	for _, code := range p.Learning.DisqualifyingEvidenceCodes {
		if _, ok := p.EvidenceRules[code]; !ok {
			return false
		}
	}
	// Concurrency caps must not go negative (global included, P0.19).
	emergency := Limits{}
	if p.Limits.Emergency != nil {
		emergency = *p.Limits.Emergency
	}
	if p.Limits.Normal.ConcurrencyCap < 0 || p.Limits.Constrained.ConcurrencyCap < 0 ||
		emergency.ConcurrencyCap < 0 || p.Global.ConcurrencyCap < 0 {
		return false
	}
	// P0.19: validate every windowed gauge across scopes and the global plane.
	// Capacity/RefillPer/RefillIn must be >= 0; a non-zero refill rate requires
	// a positive interval (zero interval would be a divide-by-zero / mint-every
	// instant). Burst-only (Capacity > 0, RefillPer == 0) remains legal.
	for _, lim := range []Limits{
		p.Limits.Normal, p.Limits.Constrained, emergency, p.Global,
	} {
		if !validBucket(lim.Requests) || !validBucket(lim.Tokens) || !validBucket(lim.Cost) {
			return false
		}
	}
	// P0.21: classification universe must be a positive, explicit revision; the
	// default (zero) is rejected so a mis-configured policy cannot silently
	// create an empty lane universe and borrow nothing.
	if p.ClassificationRevision < 1 {
		return false
	}
	// P0.11: the compiled policy must carry a usable evidence rule table and
	// lane-classification cutoffs. A nil/empty evidence table fails closed (the
	// data plane cannot mint evidence under a policy that defines none), and a
	// degenerate classification (Match below Related, or a negative floor) is
	// rejected rather than silently mis-enforced.
	if len(p.EvidenceRules) == 0 {
		return false
	}
	if p.Classification.Match <= p.Classification.Related {
		return false
	}
	if p.Classification.Related < 0 || p.Classification.Match > 1 ||
		p.Classification.MinComparableWeight < 0 {
		return false
	}
	// P0.7: an explicit enforcement mode must be one of the known values. A
	// negative/garbage value is rejected rather than silently treating an
	// intended SourceEnforce as observe.
	switch p.Risk.SourceMode {
	case SourceObserve, SourceEnforce:
	default:
		return false
	}
	return true
}

// validBucket reports whether a BucketConfig is structurally legal (P0.19).
func validBucket(b BucketConfig) bool {
	if b.Capacity < 0 || b.RefillPer < 0 || b.RefillIn < 0 {
		return false
	}
	// A refill rate with no positive interval is a divide-by-zero / instant
	// mint. Burst-only (Capacity > 0, RefillPer == 0) is fine.
	if b.RefillPer > 0 && b.RefillIn <= 0 {
		return false
	}
	return true
}

// MaxIdentityTTLSeconds returns the assertion lifetime in seconds, clamped to
// INV-10 (short-lived, ≤30s per P0.28). Default 30; config may not exceed 30.
func (p *Policy) MaxIdentityTTLSeconds() int {
	if p == nil || p.Identity.MaxTTLSeconds < 1 {
		return 30
	}
	if p.Identity.MaxTTLSeconds > 30 {
		return 30
	}
	return p.Identity.MaxTTLSeconds
}

// ErrRevoked / ErrEmergency / ErrSourceBlocked / ErrHardLimit / ErrRisk are the
// precedence outcomes (ordered highest → lowest). The evaluator returns the
// most severe applicable denial, or nil.
var (
	ErrRevoked         = errors.New("policy: credential revoked")
	ErrEmergencyBlock  = errors.New("policy: emergency block")
	ErrSourceBlock     = errors.New("policy: source block")
	ErrAccountLimit    = errors.New("policy: account hard limit")
	ErrCredentialLimit = errors.New("policy: credential hard limit")
	ErrLaneLimit       = errors.New("policy: lane hard limit")
	ErrGlobalLimit     = errors.New("policy: global fleet hard limit")
	ErrRiskDenial      = errors.New("policy: risk-state restriction")
)

// Evaluate is the enforcement-precedence resolver (§58). Callers feed a fully
// populated context (status, lane state, whether each scope is at/over its hard
// limit, source-blocked flag, emergency flag, credential status). It returns
// the highest-priority denial.
func (p *Policy) Evaluate(in EvalInput) error {
	if in.CredentialRevoked {
		return ErrRevoked
	}
	if in.Emergency {
		return ErrEmergencyBlock
	}
	if in.SourceBlocked {
		return ErrSourceBlock
	}
	if in.AccountOverLimit {
		return ErrAccountLimit
	}
	if in.CredentialOverLimit {
		return ErrCredentialLimit
	}
	if in.LaneOverLimit {
		return ErrLaneLimit
	}
	if in.RiskDenied {
		return ErrRiskDenial
	}
	return nil
}

// EvalInput carries the state the fast path has resolved, before issuing an
// internal identity.
type EvalInput struct {
	CredentialRevoked   bool
	Emergency           bool
	SourceBlocked       bool
	AccountOverLimit    bool
	CredentialOverLimit bool
	LaneOverLimit       bool
	RiskDenied          bool
}
