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

// LaneRecord is the persisted lane row (§75).
type LaneRecord struct {
	LaneID            string
	CredentialID      string
	State             State
	FirstSeenAt       time.Time
	LastSeenAt        time.Time
	NetworkClass      string
	RegionClass       string
	ClientFamily      string
	RequestCount      int64
	RiskScore         int
	EstablishmentScore int
	Revision          int
}

// Features is the normalized metadata vector used for classification. Missing
// data is represented by the zero value (empty string / 0) and handled via
// weight renormalization over present features (§27). No prompt or completion
// semantics are included (§G10).
type Features struct {
	NetworkASN     string
	NetworkType    string // residential / hosting / mobile / ...
	RegionClass    string // coarse geographic region
	ClientFamily   string // claude-code / python-sdk / ...
	SDKFamily      string
	HTTPVersion    string // "1.1", "2"
	Streaming      string // "", "streaming", "non-streaming" (empty = unknown)
	ModelFamily    string
	ConcurrencyPattern string // interactive / automation / burst / ...
	EndpointFamily string
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

// ClassificationThresholds carries the similarity cutoffs (policy-controlled).
type ClassificationThresholds struct {
	Match    float64 // >= this → candidate existing lane
	Related  float64 // >= this → related context / candidate new lane
	Novel    float64 // < this → novel lane
}

// DefaultThresholds are the spec §26 example defaults.
func DefaultThresholds() ClassificationThresholds {
	return ClassificationThresholds{Match: 0.80, Related: 0.55, Novel: 0.55}
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

// Similarity computes a weighted, renormalized similarity in [0,1] between two
// feature vectors, considering only features present in at least one vector's
// comparable space (both must be present to score a match). Deterministic.
func Similarity(a, b Features) float64 {
	var totalW, matchedW float64
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
	if totalW == 0 {
		return 0
	}
	return matchedW / totalW
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