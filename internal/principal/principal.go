// Package principal models the authenticated internal identity that replaces
// the raw external credential after termination (spec §19). Principal is what
// the credential terminator emits; AuthorizedContext adds the lane/scope/risk
// state resolved during admission. Neither carries a raw secret.
package principal

import "time"

// Principal is the stable identity resolved from a verified credential.
type Principal struct {
	AccountID          string
	CredentialID       string
	PolicyID           string
	PlanID             string
	CredentialStatus   string // NORMAL / WATCH / CONSTRAINED / QUARANTINED / REVOKED
	CredentialRevision int
}

// Scope is the authorization scope enum.
type Scope string

const (
	ScopeRequest    Scope = "REQUEST"
	ScopeSource     Scope = "SOURCE"
	ScopeLane       Scope = "LANE"
	ScopeCredential Scope = "CREDENTIAL"
	ScopeAccount    Scope = "ACCOUNT"
	ScopeGlobal     Scope = "GLOBAL"
)

// AuthorizedContext is the output of admission: principal + lane + scope +
// risk. It is what the rest of the provider stack is authorized as — with no
// raw external secret present anywhere.
type AuthorizedContext struct {
	Principal          Principal
	LaneID             string
	LaneState          string // NEW / PROBATION / ESTABLISHED / SUSPICIOUS / BLOCKED
	AuthorizationScope Scope
	RiskState          int // 0..100
	AuthorizedAt       time.Time
}

// Resolver resolves a verified credential into a Principal. The terminator
// supplies the implementation (from the credential registry / pepper ring).
type Resolver interface {
	Resolve(principal Principal) (Principal, error)
}

// DefaultResolver is a pass-through resolver used when no additional mapping is
// required (the registry already returned account/policy/plan onto the
// principal).
type DefaultResolver struct{}

// Resolve returns the principal unchanged.
func (DefaultResolver) Resolve(p Principal) (Principal, error) { return p, nil }
