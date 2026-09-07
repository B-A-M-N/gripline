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
	// ClassificationRevision is the lane-universe revision the row was classified
	// under (P0.21). BorrowOrCreate never borrows/reuses a row whose
	// ClassificationRevision differs from the current context, preventing a
	// re-keyed classification from silently laundering pre-change history.
	ClassificationRevision int

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
	// MinComparableWeight is the minimum comparable feature mass FRACTION a
	// candidate must share with a stored lane to be a Match (P0.9/P0.21). The
	// default equals the trusted network trio's share of the feature space
	// ((0.35+0.15+0.20)/1.20), computed from the same table ComparableWeight
	// normalizes over — so a candidate refusing those trusted fields cannot
	// Match, and floor and table can never drift apart.
	MinComparableWeight float64
}

// DefaultThresholds are the spec §26 example defaults, hardened per P0.9 with a
// comparable-mass floor that requires the full trusted network-source identity
// (the NetworkASN/RegionClass/NetworkType trio) to be present before a Match is
// permitted. The floor is derived from the weight table itself (P0.21), so
// editing the weights re-derives the floor. A candidate omitting any trusted
// source field drops below this floor and cannot collapse into an established
// lane.
func DefaultThresholds() ClassificationThresholds {
	trustedTrio := defaultWeights["NetworkASN"] + defaultWeights["NetworkType"] + defaultWeights["RegionClass"]
	total := totalFeatureWeight()
	return ClassificationThresholds{
		Match:               0.80,
		Related:             0.55,
		MinComparableWeight: trustedTrio / total,
	}
}

// Weights multiply per-feature similarity; they are renormalized over present
// features (§27). The raw table sums to 1.20, NOT 1.0 (P0.21): similarity is a
// ratio of weights so classification is unaffected, but ComparableWeight must
// divide by the true table total (see totalFeatureWeight) rather than clamping
// at 1.0 — the old clamp silently flattened every mass above 1.0 and made the
// documented "fraction out of 1.0" a lie. The trusted network trio's FRACTION
// of the space is (0.35+0.15+0.20)/1.20 ≈ 0.583; DefaultThresholds derives its
// MinComparableWeight from that same computation so floor and table can never
// drift apart.
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

// featureFields is the fixed iteration order used by comparable (deterministic
// classification, §26).
var featureFields = []string{
	"NetworkASN", "NetworkType", "RegionClass", "ClientFamily",
	"SDKFamily", "HTTPVersion", "Streaming", "ModelFamily",
	"ConcurrencyPattern", "EndpointFamily",
}

// totalFeatureWeight is the exact sum of the weight table. ComparableWeight
// divides the comparable mass by this so the reported fraction is genuinely in
// [0,1] regardless of how the table is edited (P0.21).
func totalFeatureWeight() float64 {
	t := 0.0
	for _, f := range featureFields {
		t += defaultWeights[f]
	}
	return t
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
	for _, f := range featureFields {
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

// ComparableWeight reports the fraction of the FEATURE SPACE (out of 1.0) that
// both vectors populate — i.e. how much comparable evidence a Similarity
// decision actually rests on. The mass is divided by the total weight of the
// table (P0.21): with defaultWeights summing to 1.0 the division is a no-op,
// but an edited table can no longer push the fraction above 1.0 or silently
// shift the MinComparableWeight floor. Used with
// ClassificationThresholds.MinComparableWeight to stop a sparse candidate from
// collapsing into an established lane on a sliver of shared fields (P0.9).
func ComparableWeight(a, b Features) float64 {
	_, totalW := comparable(a, b)
	tw := totalFeatureWeight()
	if tw == 0 {
		return 0
	}
	return totalW / tw
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

// sameFeatures reports exact equality of two feature vectors (every field).
// Used by the store's exact-manifestation reuse path: a candidate re-presenting
// the identical vector its lane was created under reuses that lane. Any
// difference — even one field — means a different manifestation and must go
// through classification, never overwrite.
func sameFeatures(a, b Features) bool {
	for _, f := range featureFields {
		if fieldVal(&a, f) != fieldVal(&b, f) {
			return false
		}
	}
	return true
}

// FeatSchemaVersion is the current classification-vector schema revision.
// Store rows classified under an older schema are never silently compared
// (P0.22); bump when the Features struct changes shape.
const FeatSchemaVersion = featSchemaVersion

// ClassificationContext binds a lane-universe revision to its thresholds
// (P0.21). BorrowOrCreate keys lane identity and cross-revision borrowing on
// BOTH the feature schema AND this revision: a lane stored under an older
// ClassificationRevision is never borrowed by a candidate classified under the
// current one, so re-keying classification semantics (feature schema, weights,
// thresholds, comparable-mass, matching rules) legitimately fragments the lane
// universe instead of silently mixing pre- and post-change rows.
type ClassificationContext struct {
	Revision   int
	Thresholds ClassificationThresholds
}

// CurrentClassificationRevision is the initial lane-universe revision shipped by
// the default policy (policy.Default sets ClassificationRevision to this).
type CurrentClassificationRevision = int

// currentClassificationRevision anchors the initial lane universe. It is the
// store-only default for callers that do not supply an explicit context; a
// policy-authored context always wins and MUST match policy.Default's value for
// the default policy to behave as one universe.
const currentClassificationRevision = 1

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
