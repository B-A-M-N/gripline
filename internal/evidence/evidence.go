// Package evidence models explicit, machine-readable evidence objects that risk
// decisions consume (spec §33-37). Evidence carries a family, an enforcement
// scope, a bounded score, an optional correlation group (so signals from the
// same root observation are bounded, §35), and an explicit TTL (§37).
package evidence

import "time"

// Family is the bounded risk family an evidence belongs to (§34).
type Family int

const (
	FamilySourceDiscontinuity Family = iota
	FamilyResourceVelocity
	FamilyClientNovelty
	FamilyAbuseCorrelation
	FamilyOperatorIOC
)

// FamilyCap returns the default cap that bounds each family's contribution so
// accidental double-counting cannot span families (§34).
func (f Family) FamilyCap() int {
	switch f {
	case FamilySourceDiscontinuity:
		return 35
	case FamilyResourceVelocity:
		return 35
	case FamilyClientNovelty:
		return 20
	case FamilyAbuseCorrelation:
		return 40
	case FamilyOperatorIOC:
		return 100
	default:
		return 100
	}
}

func (f Family) String() string {
	switch f {
	case FamilySourceDiscontinuity:
		return "SOURCE_DISCONTINUITY"
	case FamilyResourceVelocity:
		return "RESOURCE_VELOCITY"
	case FamilyClientNovelty:
		return "CLIENT_NOVELTY"
	case FamilyAbuseCorrelation:
		return "ABUSE_CORRELATION"
	case FamilyOperatorIOC:
		return "OPERATOR_IOC"
	default:
		return "UNKNOWN"
	}
}

// Scope is the narrowest-defensible enforcement scope (§32).
type Scope int

const (
	ScopeRequest Scope = iota
	ScopeSource
	ScopeLane
	ScopeCredential
	ScopeAccount
	ScopeGlobal
)

func (s Scope) String() string {
	switch s {
	case ScopeRequest:
		return "REQUEST"
	case ScopeSource:
		return "SOURCE"
	case ScopeLane:
		return "LANE"
	case ScopeCredential:
		return "CREDENTIAL"
	case ScopeAccount:
		return "ACCOUNT"
	case ScopeGlobal:
		return "GLOBAL"
	default:
		return "UNKNOWN"
	}
}

// Evidence is one machine-readable justification for a risk contribution.
type Evidence struct {
	EvidenceID      string
	Code            string // e.g. NEW_HOSTING_ASN
	Family          Family
	Scope           Scope
	SubjectID       string
	Score           int // contribution to the family (bounded internally)
	Severity        int
	Confidence      int // 0..100
	CreatedAt       time.Time
	ExpiresAt       time.Time
	CorrelationGroup string // same root observation → bounded reducer
	PolicyRevision  int
}

// Valid reports structural validity (time bounds, score bounds, confidence).
func (e Evidence) Valid(now time.Time) bool {
	if e.Score < 0 {
		return false
	}
	if e.Confidence < 0 || e.Confidence > 100 {
		return false
	}
	if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
		return false // expired evidence no longer counts (§37)
	}
	return true
}

// TTL returns e.ExpiresAt - e.CreatedAt when both set; zero otherwise.
func (e Evidence) TTL() time.Duration {
	if e.CreatedAt.IsZero() || e.ExpiresAt.IsZero() {
		return 0
	}
	return e.ExpiresAt.Sub(e.CreatedAt)
}

// Rule defines the fixed score and metadata for a recognized evidence code.
// Offline analysis may author these; they become explicit versioned policy
// before affecting authorization (§38).
type Rule struct {
	Code            string
	Family          Family
	Scope           Scope
	Score           int
	Severity        int
	Confidence      int
	CorrelationGroup string
	TTL             time.Duration
}

// Table is the deterministic map from a rule/code to its parameters.
type Table map[string]Rule

// DefaultTable returns the spec §36 illustrative defaults. These are initial
// values, policy-tunable and versioned.
func DefaultTable() Table {
	d := 7 * 24 * time.Hour        // new-ASN spans hours→days
	m := 10 * time.Minute          // concurrency/spray spikes: minutes
	h := time.Hour                 // velocity spikes
	none := time.Duration(0)       // manual compromise: until revoked

	mk := func(code string, fam Family, scope Scope, score, sev, conf int, grp string, ttl time.Duration) Rule {
		return Rule{Code: code, Family: fam, Scope: scope, Score: score, Severity: sev, Confidence: conf, CorrelationGroup: grp, TTL: ttl}
	}

	return Table{
		"NEW_ASN":                              mk("NEW_ASN", FamilySourceDiscontinuity, ScopeLane, 10, 2, 60, "location", d),
		"NEW_HOSTING_ASN":                      mk("NEW_HOSTING_ASN", FamilySourceDiscontinuity, ScopeLane, 15, 3, 70, "location", d),
		"NEW_COUNTRY":                          mk("NEW_COUNTRY", FamilySourceDiscontinuity, ScopeLane, 15, 3, 65, "location", d),
		"SIMULTANEOUS_ESTABLISHED_LANE_FROM_UNRELATED_ASN": mk("SIMULTANEOUS_ESTABLISHED_LANE_FROM_UNRELATED_ASN", FamilyAbuseCorrelation, ScopeCredential, 20, 4, 80, "topology", m),
		"MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN": mk("MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN", FamilyAbuseCorrelation, ScopeCredential, 30, 5, 85, "topology", m),
		"CONCURRENCY_OVER_4X_BASELINE":         mk("CONCURRENCY_OVER_4X_BASELINE", FamilyResourceVelocity, ScopeLane, 20, 4, 75, "resource", h),
		"CONCURRENCY_OVER_10X_BASELINE":        mk("CONCURRENCY_OVER_10X_BASELINE", FamilyResourceVelocity, ScopeLane, 30, 5, 85, "resource", h),
		"TOKEN_VELOCITY_OVER_4X_BASELINE":      mk("TOKEN_VELOCITY_OVER_4X_BASELINE", FamilyResourceVelocity, ScopeLane, 15, 3, 70, "resource", h),
		"TOKEN_VELOCITY_OVER_10X_BASELINE":     mk("TOKEN_VELOCITY_OVER_10X_BASELINE", FamilyResourceVelocity, ScopeLane, 25, 4, 80, "resource", h),
		"COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR": mk("COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR", FamilyResourceVelocity, ScopeCredential, 20, 4, 75, "resource", h),
		"RAPID_ENDPOINT_OR_MODEL_ENUMERATION":  mk("RAPID_ENDPOINT_OR_MODEL_ENUMERATION", FamilyClientNovelty, ScopeLane, 15, 3, 60, "enumeration", h),
		"SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS": mk("SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS", FamilyAbuseCorrelation, ScopeSource, 35, 6, 90, "spray", m),
		"NEW_CLIENT_FAMILY":                    mk("NEW_CLIENT_FAMILY", FamilyClientNovelty, ScopeLane, 5, 1, 40, "novelty", d),
		"MANUAL_CONFIRMED_COMPROMISE":          mk("MANUAL_CONFIRMED_COMPROMISE", FamilyOperatorIOC, ScopeCredential, 100, 10, 100, "operator", none),
	}
}