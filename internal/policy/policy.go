// Package policy models the versioned, validated policy that drives
// authorization (spec §56-58). All policy is versioned; the data plane loads
// only authenticated + validated policy and keeps the previous revision for
// rollback (§57). Enforcement follows the fixed precedence of §58 so a more
// permissive lower-level rule can never override a higher-priority denial.
package policy

import (
	"errors"
	"time"
)

// RiskThresholds are the credential/lane risk-state boundaries (§31).
type RiskThresholds struct {
	Watch       int
	Constrained int
	Quarantine  int
}

// Limits captures hard resource limits per scope as policy.
type Limits struct {
	ConcurrencyCap     int
	RequestBurstCap    int
	TokenVelocityMult  float64
	CostVelocityMult   float64
	RequestRate        int // requests / minute
}

// Learning controls baseline seeding (§29, §42).
type Learning struct {
	MaximumRisk       int
	AllowNewLanes     bool
	AllowSuspiciousLanes bool
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
	Normal     Limits
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

	// CreatedAt and signature hooks reserved for authenticated+validated load.
	CreatedAt time.Time
}

// Default returns the spec §56 example defaults.
func Default() *Policy {
	return &Policy{
		ID:       "fi-default-v1",
		Revision: 1,
		Risk:     RiskThresholds{Watch: 30, Constrained: 55, Quarantine: 80},
		Limits: ScopedLimits{
			Normal:     Limits{ConcurrencyCap: 32, RequestBurstCap: 64, TokenVelocityMult: 1.0, CostVelocityMult: 1.0, RequestRate: 300},
			Constrained: Limits{ConcurrencyCap: 2, RequestBurstCap: 8, TokenVelocityMult: 1.25, CostVelocityMult: 1.25, RequestRate: 20},
		},
		Learning: Learning{MaximumRisk: 20, AllowNewLanes: false, AllowSuspiciousLanes: false},
		Privacy:  Privacy{PromptRetention: false, CompletionRetention: false},
		Identity: Identity{MaxTTLSeconds: 30},
	}
}

// IsValid reports whether a policy revision is structurally valid to load.
func (p *Policy) IsValid() bool {
	if p == nil || p.ID == "" {
		return false
	}
	if p.Revision < 1 {
		return false
	}
	if p.Identity.MaxTTLSeconds < 1 || p.Identity.MaxTTLSeconds > 60 {
		return false
	}
	return true
}

// MaxIdentityTTLSeconds returns the assertion lifetime in seconds, clamped to
// INV-10 (short-lived). Default 30; config may raise up to 60 for operational
// convenience but never below 1.
func (p *Policy) MaxIdentityTTLSeconds() int {
	if p == nil || p.Identity.MaxTTLSeconds < 1 {
		return 30
	}
	if p.Identity.MaxTTLSeconds > 60 {
		return 60
	}
	return p.Identity.MaxTTLSeconds
}

// ErrRevoked / ErrEmergency / ErrSourceBlocked / ErrHardLimit / ErrRisk are the
// precedence outcomes (ordered highest → lowest). The evaluator returns the
// most severe applicable denial, or nil.
var (
	ErrRevoked        = errors.New("policy: credential revoked")
	ErrEmergencyBlock = errors.New("policy: emergency block")
	ErrSourceBlock    = errors.New("policy: source block")
	ErrAccountLimit   = errors.New("policy: account hard limit")
	ErrCredentialLimit = errors.New("policy: credential hard limit")
	ErrLaneLimit      = errors.New("policy: lane hard limit")
	ErrRiskDenial     = errors.New("policy: risk-state restriction")
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
	CredentialRevoked bool
	Emergency         bool
	SourceBlocked     bool
	AccountOverLimit  bool
	CredentialOverLimit bool
	LaneOverLimit     bool
	RiskDenied        bool
}