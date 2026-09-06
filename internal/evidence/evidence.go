// Package evidence models explicit, machine-readable evidence objects that risk
// decisions consume (spec §33-37). Evidence carries a family, an enforcement
// scope, a bounded score, an optional correlation group (so signals from the
// same root observation are bounded, §35), and an explicit TTL (§37).
package evidence

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

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
	EvidenceID       string
	Code             string // e.g. NEW_HOSTING_ASN
	Family           Family
	Scope            Scope
	SubjectID        string
	Score            int // contribution to the family (bounded internally)
	Severity         int
	Confidence       int // 0..100
	CreatedAt        time.Time
	ExpiresAt        time.Time
	CorrelationGroup string // same root observation → bounded reducer
	PolicyRevision   int
}

// Valid reports structural validity: recognized enum values, non-empty code
// and subject, sane score/confidence bounds, no future creation, and expiry
// not before creation (§37). It does NOT attest that the parameters match a
// policy rule — that guarantee comes from Mint; hand-constructed evidence can
// still be structurally valid, which is why risk input should only ever come
// from Mint.
func (e Evidence) Valid(now time.Time) bool {
	if e.Code == "" || e.SubjectID == "" {
		return false
	}
	if e.Family < FamilySourceDiscontinuity || e.Family > FamilyOperatorIOC {
		return false
	}
	if e.Scope < ScopeRequest || e.Scope > ScopeGlobal {
		return false
	}
	if e.Score < 0 || e.Score > 100 {
		return false
	}
	if e.Confidence < 0 || e.Confidence > 100 {
		return false
	}
	if e.CreatedAt.IsZero() || e.CreatedAt.After(now) {
		return false // future-minted evidence is never valid (§37)
	}
	if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(e.CreatedAt) {
		return false // impossible TTL
	}
	// Expiry is inclusive-invalid: evidence is expired exactly AT ExpiresAt
	// (now == ExpiresAt fails), matching credential/assertion semantics (P0.14).
	if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
		return false // expired evidence no longer counts (§37)
	}
	return true
}

// NonEvictable reports whether an evidence item is in a security-critical class
// that must survive generic eviction pressure (P0.12): operator IOC
// (manual compromise, explicit block, operator hold) and non-expiring security
// evidence. The store's bounded-fifo compaction MUST NOT drop these.
func (e Evidence) NonEvictable() bool {
	// FamilyOperatorIOC evidence (MANUAL_CONFIRMED_COMPROMISE, operator-hold
	// blocks) is manual/operator-authored and non-expiring; it is authoritative
	// and must never be evicted by low-value churn.
	if e.Family == FamilyOperatorIOC {
		return true
	}
	// Explicit non-expiring security evidence is retained until a lifecycle
	// action revokes it; generic eviction must not silently drop it.
	if e.ExpiresAt.IsZero() {
		return true
	}
	return false
}

// idRandom returns a CSPRNG-derived evidence id (P0.15): unconvergeable and
// un-predictable, so evidence ids can never be guessed, forged, or collided by
// an attacker who can observe timestamps or request ordering. A timestamp-derived
// id (ev_<UnixNano>) is attacker-influenceable and must never be the default.
func idRandom() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Entropy failure is unrecoverable for a security-identity surface; the
		// process must not mint forgeable evidence on a degraded RNG.
		panic("evidence: entropy unavailable for evidence id: " + err.Error())
	}
	return "ev_" + base64.RawURLEncoding.EncodeToString(b[:])
}

// Mint is the ONLY sanctioned way to produce evidence for the risk engine
// (P0.11): every security-relevant field — family, scope, score, severity,
// confidence, correlation group, TTL — is populated from the versioned rule
// table, never from the caller. An unrecognized code is rejected instead of
// invented. Operator IOC rules (e.g. MANUAL_CONFIRMED_COMPROMISE) mint through
// this same path; gating WHO may call it for those codes is a control-plane
// authorization concern enforced at the API that exposes Mint.
func Mint(table Table, code string, subjectID string, now time.Time, policyRevision int) (Evidence, error) {
	return mintID(table, code, subjectID, now, policyRevision, idRandom)
}

// MintID is Mint with an explicit evidence-id generator, so callers can supply a
// deterministic id (tests, replay, operator tools) while the security-critical
// default Mint remains CSPRNG. The supplied idgen is used verbatim; a nil idgen
// refuses to mint rather than silently reverting to an insecure id.
func MintID(table Table, code string, subjectID string, now time.Time, policyRevision int, idgen func() string) (Evidence, error) {
	if idgen == nil {
		return Evidence{}, errors.New("evidence: nil id generator (must supply CSPRNG or explicit dd)")
	}
	return mintID(table, code, subjectID, now, policyRevision, idgen)
}

func mintID(table Table, code string, subjectID string, now time.Time, policyRevision int, idgen func() string) (Evidence, error) {
	if table == nil {
		return Evidence{}, errors.New("evidence: nil rule table")
	}
	rule, ok := table[code]
	if !ok {
		return Evidence{}, fmt.Errorf("evidence: unrecognized code %q", code)
	}
	if subjectID == "" {
		return Evidence{}, errors.New("evidence: subject required")
	}
	ev := Evidence{
		EvidenceID:       idgen(),
		Code:             rule.Code,
		Family:           rule.Family,
		Scope:            rule.Scope,
		SubjectID:        subjectID,
		Score:            rule.Score,
		Severity:         rule.Severity,
		Confidence:       rule.Confidence,
		CorrelationGroup: rule.CorrelationGroup,
		CreatedAt:        now,
		PolicyRevision:   policyRevision,
	}
	// rule.TTL <= 0 means "does not self-expire" (e.g. operator IOC until
	// revoked): a zero ExpiresAt, which Valid treats as unbounded.
	if rule.TTL > 0 {
		ev.ExpiresAt = now.Add(rule.TTL)
	}
	if !ev.Valid(now) {
		return Evidence{}, fmt.Errorf("evidence: rule %q produced invalid evidence", code)
	}
	return ev, nil
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
//
// A TTL of zero (or negative) means the evidence does not expire on its own —
// it stays active until an explicit lifecycle action (e.g. MANUAL_CONFIRMED_
// COMPROMISE holds until the credential is revoked). Minting side: rule.TTL <=
// 0 must produce a zero ExpiresAt, which Evidence.Valid treats as unbounded.
// Minting ExpiresAt = now.Add(0) instead would create evidence that expires
// the moment after creation — an operator IOC that silently evaporates.
type Rule struct {
	Code             string
	Family           Family
	Scope            Scope
	Score            int
	Severity         int
	Confidence       int
	CorrelationGroup string
	TTL              time.Duration
}

// Table is the deterministic map from a rule/code to its parameters.
type Table map[string]Rule

// DefaultTable returns the spec §36 illustrative defaults. These are initial
// values, policy-tunable and versioned.
func DefaultTable() Table {
	d := 7 * 24 * time.Hour  // new-ASN spans hours→days
	m := 10 * time.Minute    // concurrency/spray spikes: minutes
	h := time.Hour           // velocity spikes
	none := time.Duration(0) // manual compromise: until revoked

	mk := func(code string, fam Family, scope Scope, score, sev, conf int, grp string, ttl time.Duration) Rule {
		return Rule{Code: code, Family: fam, Scope: scope, Score: score, Severity: sev, Confidence: conf, CorrelationGroup: grp, TTL: ttl}
	}

	return Table{
		"NEW_ASN":         mk("NEW_ASN", FamilySourceDiscontinuity, ScopeLane, 10, 2, 60, "location", d),
		"NEW_HOSTING_ASN": mk("NEW_HOSTING_ASN", FamilySourceDiscontinuity, ScopeLane, 15, 3, 70, "location", d),
		"NEW_COUNTRY":     mk("NEW_COUNTRY", FamilySourceDiscontinuity, ScopeLane, 15, 3, 65, "location", d),
		"SIMULTANEOUS_ESTABLISHED_LANE_FROM_UNRELATED_ASN":  mk("SIMULTANEOUS_ESTABLISHED_LANE_FROM_UNRELATED_ASN", FamilyAbuseCorrelation, ScopeCredential, 20, 4, 80, "topology", m),
		"MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN":              mk("MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN", FamilyAbuseCorrelation, ScopeCredential, 30, 5, 85, "topology", m),
		"CONCURRENCY_OVER_4X_BASELINE":                      mk("CONCURRENCY_OVER_4X_BASELINE", FamilyResourceVelocity, ScopeLane, 20, 4, 75, "resource", h),
		"CONCURRENCY_OVER_10X_BASELINE":                     mk("CONCURRENCY_OVER_10X_BASELINE", FamilyResourceVelocity, ScopeLane, 30, 5, 85, "resource", h),
		"TOKEN_VELOCITY_OVER_4X_BASELINE":                   mk("TOKEN_VELOCITY_OVER_4X_BASELINE", FamilyResourceVelocity, ScopeLane, 15, 3, 70, "resource", h),
		"TOKEN_VELOCITY_OVER_10X_BASELINE":                  mk("TOKEN_VELOCITY_OVER_10X_BASELINE", FamilyResourceVelocity, ScopeLane, 25, 4, 80, "resource", h),
		"COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR": mk("COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR", FamilyResourceVelocity, ScopeCredential, 20, 4, 75, "resource", h),
		"RAPID_ENDPOINT_OR_MODEL_ENUMERATION":               mk("RAPID_ENDPOINT_OR_MODEL_ENUMERATION", FamilyClientNovelty, ScopeLane, 15, 3, 60, "enumeration", h),
		"SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS":      mk("SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS", FamilyAbuseCorrelation, ScopeSource, 35, 6, 90, "spray", m),
		"NEW_CLIENT_FAMILY":                                 mk("NEW_CLIENT_FAMILY", FamilyClientNovelty, ScopeLane, 5, 1, 40, "novelty", d),
		"NEW_LANE":                                          mk("NEW_LANE", FamilyClientNovelty, ScopeLane, 5, 1, 40, "novelty", d),
		"MANUAL_CONFIRMED_COMPROMISE":                       mk("MANUAL_CONFIRMED_COMPROMISE", FamilyOperatorIOC, ScopeCredential, 100, 10, 100, "operator", none),
	}
}
