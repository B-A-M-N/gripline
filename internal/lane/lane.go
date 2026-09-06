// Package lane models a credential's observed manifestations as independently
// enforceable security lanes (spec §23-29). A lane is derived from metadata —
// not exact device fingerprints — and prompt/completion text is never required
// (§G10). Lane classification is deterministic for a given feature vector,
// lane state, and policy revision (§26).
package lane

import "time"

// State is a lane's lifecycle state (§24).
type State int

const (
	StateNew State = iota
	StateProbation
	StateEstablished
	StateSuspicious
	StateBlocked
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateProbation:
		return "PROBATION"
	case StateEstablished:
		return "ESTABLISHED"
	case StateSuspicious:
		return "SUSPICIOUS"
	case StateBlocked:
		return "BLOCKED"
	default:
		return "UNKNOWN"
	}
}

// LaneRecord is the persisted lane row (§75). It retains the COMPLETE
// normalized classification vector (P0.8): matching against a subset of the
// vector collapses materially different manifestations into one lane (missing
// dimensions drop out of the similarity denominator, so a single shared
// feature can score a false 1.0). FeatSchema records the feature-schema
// revision used at classification time so a future schema change can
// re-classify rather than silently compare across incompatible vectors.
type LaneRecord struct {
	LaneID       string
	CredentialID string
	State        State
	FirstSeenAt  time.Time
	LastSeenAt   time.Time
	Features     Features // full normalized classification vector (P0.8)
	FeatSchema   int      // feature-schema revision the vector was classified under

	RequestCount          int64  // total requests seen (includes denied)
	ActiveDays            int    // distinct active days observed (§29 clean-active-days)
	LastActiveDay         string // "YYYY-MM-DD" of the last request (ActiveDays dedup)
	RiskScore             int
	EstablishmentScore    int
	// Security is the RISK-DRIVEN enforcement dimension (P0.7): a separate axis
	// from the trust ladder (State). It drives lane-scoped limits and denial.
	Security SecurityState

	// Clean counters for promotion — only incremented on fully authorized requests.
	// Denied requests contribute evidence but NOT baseline progress (INV-8).
	AuthorizedCleanRequests int64  // requests that passed all admission gates
	CleanActiveDays         int    // distinct active days with clean history
	LastCleanActiveDay      string // "YYYY-MM-DD" of the last clean active day
	// CleanSince is the start of the current CONTIGUOUS clean window (P0.42).
	// MinCleanAge compares against this, not FirstSeenAt (which measures lane
	// age, not clean age). It is reset when disqualifying security evidence
	// becomes active, or when the lane's security status elevates.
	CleanSince time.Time
	Revision   int
}

// Features is the normalized metadata vector used for classification. Missing
// data is represented by the zero value (empty string / 0) and handled via
// weight renormalization over present features (§27). No prompt or completion
// semantics are included (§G10).
type Features struct {
	NetworkASN         string
	NetworkType        string // residential / hosting / mobile / ...
	RegionClass        string // coarse geographic region
	ClientFamily       string // claude-code / python-sdk / ...
	SDKFamily          string
	HTTPVersion        string // "1.1", "2"
	Streaming          string // "", "streaming", "non-streaming" (empty = unknown)
	ModelFamily        string
	ConcurrencyPattern string // interactive / automation / burst / ...
	EndpointFamily     string
}

// has reports whether a feature atom is present (non-empty). Every feature is a
// string; empty means "unknown/absent" and is never scored as a match or a
// mismatch (§27).
func (f Features) has(field string) bool {
	switch field {
	case "NetworkASN":
		return f.NetworkASN != ""
	case "NetworkType":
		return f.NetworkType != ""
	case "RegionClass":
		return f.RegionClass != ""
	case "ClientFamily":
		return f.ClientFamily != ""
	case "SDKFamily":
		return f.SDKFamily != ""
	case "HTTPVersion":
		return f.HTTPVersion != ""
	case "ModelFamily":
		return f.ModelFamily != ""
	case "ConcurrencyPattern":
		return f.ConcurrencyPattern != ""
	case "EndpointFamily":
		return f.EndpointFamily != ""
	case "Streaming":
		return f.Streaming != ""
	default:
		return false
	}
}

// ClassificationThresholds carries the similarity cutoffs (policy-controlled):
// similarity >= Match → candidate existing lane; >= Related → related context /
// candidate new lane; below Related → novel lane.
//
// MinComparableWeight is the P0.9 anti-laundering floor: a candidate may only
// MATCH an existing lane when BOTH its renormalized similarity is >= Match AND
// ComparableWeight(candidate, stored) is >= MinComparableWeight. Otherwise a
// sparse candidate that omits distinguishing features renormalizes its few
// shared fields (e.g. ASN + region + client all match) to a perfect 1.0 and
// collapses into an established lane. A zero value FAILS CLOSED to the floor
// (no Match for any candidate whose comparable mass is below a believable
// threshold), so omitting the field can never silently reopen the laundering
// strategy.
type ClassificationThresholds struct {
	Match   float64 // >= this → candidate existing lane
	Related float64 // floor; below this → novel lane
	// MinComparableWeight is the minimum comparable feature mass a candidate
	// must share with a stored lane to be a Match (P0.9). The default requires
	// the trusted network-source identity (ASN+Region+NetworkType ≈ 0.70 of the
	// feature space); a candidate refusing those trusted fields cannot Match.
	MinComparableWeight float64
}

// DefaultThresholds are the spec §26 example defaults, hardened per P0.9 with a
// comparable-mass floor that requires the full trusted network-source identity
// (NetworkASN 0.35 + RegionClass 0.20 + NetworkType 0.15 = 0.70) to be present
// before a Match is permitted. A candidate omitting any trusted source field
// drops below this floor and cannot collapse into an established lane.
func DefaultThresholds() ClassificationThresholds {
	return ClassificationThresholds{Match: 0.80, Related: 0.55, MinComparableWeight: 0.70}
}

// Weights multiply per-feature similarity; they are renormalized over present
// features (§27).
var defaultWeights = map[string]float64{
	"NetworkASN":         0.35,
	"NetworkType":        0.15,
	"RegionClass":        0.20,
	"ClientFamily":       0.10,
	"SDKFamily":          0.10,
	"HTTPVersion":        0.05,
	"Streaming":          0.05,
	"ModelFamily":        0.05,
	"ConcurrencyPattern": 0.10,
	"EndpointFamily":     0.05,
}

// comparable returns the matched weight and the comparable total weight between
// two feature vectors, considering only fields present in BOTH vectors (both
// must be present to score a match). Deterministic (fixed field order).
//
// The comparable total is what Similarity renormalizes over. It is exposed so a
// classification can ALSO bound how much feature mass the decision rests on
// (P0.9): a sparse candidate that renormalizes to 1.0 over a tiny comparable
// set must not be allowed to collapse into an established lane unless enough of
// the trusted feature space is actually present.
func comparable(a, b Features) (matchedW, totalW float64) {
	// Iterate over a fixed field order so the result is deterministic.
	fields := []string{
		"NetworkASN", "NetworkType", "RegionClass", "ClientFamily",
		"SDKFamily", "HTTPVersion", "Streaming", "ModelFamily",
		"ConcurrencyPattern", "EndpointFamily",
	}
	for _, f := range fields {
		w := defaultWeights[f]
		av, bv := fieldVal(&a, f), fieldVal(&b, f)
		if av != "" && bv != "" {
			totalW += w
			if av == bv {
				matchedW += w
			}
		}
	}
	return matchedW, totalW
}

// Similarity computes a weighted, renormalized similarity in [0,1] between two
// feature vectors, considering only features present in at least one vector's
// comparable space (both must be present to score a match). Deterministic.
func Similarity(a, b Features) float64 {
	matchedW, totalW := comparable(a, b)
	if totalW == 0 {
		return 0
	}
	return matchedW / totalW
}

// ComparableWeight reports the fraction of the FEATURE SPACE (using fixed
// default weights, out of 1.0) that both vectors populate — i.e. how much
// comparable evidence a Similarity decision actually rests on. Used with
// ClassificationThresholds.MinComparableWeight to stop a sparse candidate from
// collapsing into an established lane on a sliver of shared fields (P0.9).
func ComparableWeight(a, b Features) float64 {
	_, totalW := comparable(a, b)
	if totalW > 1 {
		totalW = 1
	}
	return totalW
}

func fieldVal(f *Features, name string) string {
	switch name {
	case "NetworkASN":
		return f.NetworkASN
	case "NetworkType":
		return f.NetworkType
	case "RegionClass":
		return f.RegionClass
	case "ClientFamily":
		return f.ClientFamily
	case "SDKFamily":
		return f.SDKFamily
	case "HTTPVersion":
		return f.HTTPVersion
	case "ModelFamily":
		return f.ModelFamily
	case "ConcurrencyPattern":
		return f.ConcurrencyPattern
	case "EndpointFamily":
		return f.EndpointFamily
	case "Streaming":
		return f.Streaming
	default:
		return ""
	}
}

// classify maps a similarity score to the classification label.
func (c ClassificationThresholds) classify(sim float64) Classification {
	switch {
	case sim >= c.Match:
		return ClassMatch
	case sim >= c.Related:
		return ClassRelated
	default:
		return ClassNovel
	}
}

// Classification labels.
type Classification int

const (
	ClassNovel Classification = iota
	ClassRelated
	ClassMatch
)

func (c Classification) String() string {
	switch c {
	case ClassMatch:
		return "MATCH"
	case ClassRelated:
		return "RELATED"
	default:
		return "NOVEL"
	}
}

// Classify maps a similarity score to the classification label.
func (c ClassificationThresholds) Classify(sim float64) Classification {
	return c.classify(sim)
}
