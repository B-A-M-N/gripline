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
	Watch             int // escalate to WATCH if risk >= this
	Constrained       int // escalate to CONSTRAINED if risk >= this
	Quarantine        int // escalate to QUARANTINED if risk >= this
	ConstrainedDownThresh int // CONSTRAINED→WATCH if risk < this
	WatchDownThresh   int // WATCH→NORMAL if risk < this
	ConstrainedDwell  time.Duration // dwell time for CONSTRAINED→WATCH recovery
	WatchDwell        time.Duration // dwell time for WATCH→NORMAL recovery
	WatchObs          int           // qualifying observations needed for WATCH entry

	// EnableAutomaticQuarantine gates the durable QUARANTINED status escalation
	// (§102 phase 6, Gate H). Automatic quarantine MUST be disabled until shadow
	// validation proves the risk model — a high risk score may deny the request
	// (temporarily_restricted) but must NOT persist a quarantine the operator did
	// not validate. Default false = fail-closed shadow-first posture. When false,
	// the risk state machine caps auto-escalation at CONSTRAINED; quarantine is
	// operator-set only.
	EnableAutomaticQuarantine bool
}

// Limits captures hard resource limits per scope as policy.
type Limits struct {
	ConcurrencyCap    int
	RequestBurstCap   int
	TokenVelocityMult float64
	CostVelocityMult  float64
	RequestRate       int // requests / minute
}

// Learning controls baseline seeding (§29, §42) and lane promotion criteria.
type Learning struct {
	MaximumRisk          int
	AllowNewLanes        bool
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
type ScopedLimits struct {
	Normal      Limits
	Constrained Limits
}

// Policy is one versioned, immutable policy revision.
type Policy struct {
	ID       string
	Revision int

	Risk     RiskThresholds
	Limits   ScopedLimits
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

	// CreatedAt and signature hooks reserved for authenticated+validated load.
	CreatedAt time.Time
}

// Default returns the spec §56 example defaults.
func Default() *Policy {
	return &Policy{
		ID:       "fi-default-v1",
		Revision: 1,
		Risk: RiskThresholds{
			Watch:                30,
			Constrained:          55,
			Quarantine:           80,
			ConstrainedDownThresh: 40,
			WatchDownThresh:      20,
			ConstrainedDwell:     15 * time.Minute,
			WatchDwell:           30 * time.Minute,
			WatchObs:             2,
		},
		Limits: ScopedLimits{
			Normal:      Limits{ConcurrencyCap: 32, RequestBurstCap: 64, TokenVelocityMult: 1.0, CostVelocityMult: 1.0, RequestRate: 300},
			Constrained: Limits{ConcurrencyCap: 2, RequestBurstCap: 8, TokenVelocityMult: 1.25, CostVelocityMult: 1.25, RequestRate: 20},
		},
		Learning: Learning{
			MaximumRisk:          20,
			AllowNewLanes:        false,
			AllowSuspiciousLanes: false,
			MinCleanAge:          7 * 24 * time.Hour,
			MinCleanRequests:     200,
			MinCleanActiveDays:   3,
			MaxEstablishmentRisk: 15,
		},
		Privacy:  Privacy{PromptRetention: false, CompletionRetention: false},
		Identity: Identity{MaxTTLSeconds: 30},
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
	// Promotion criteria must be non-negative and within bounds.
	if p.Learning.MaxEstablishmentRisk < 0 || p.Learning.MaxEstablishmentRisk > 100 {
		return false
	}
	if p.Learning.MinCleanAge < 0 || p.Learning.MinCleanRequests < 0 || p.Learning.MinCleanActiveDays < 0 {
		return false
	}
	// Hard caps must not go negative.
	if p.Limits.Normal.ConcurrencyCap < 0 || p.Limits.Constrained.ConcurrencyCap < 0 {
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
