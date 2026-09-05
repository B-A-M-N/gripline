// Package risk computes the deterministic 0..100 risk score from explicit
// evidence (spec §34, §38). The authorization path is fully deterministic — no
// learned or generative model is permitted here. Risk is bounded per family so
// accidental double-counting across correlated signals cannot inflate it.
package risk

import (
	"time"

	"github.com/freeinference/gripline/internal/evidence"
)

// Evaluate computes the total risk for a credential/lane from a set of active
// (non-expired) evidence. It applies family caps and correlation-group bounded
// reduction, returning a score clamped to [0,100].
//
// now is used to drop expired evidence (their TTL has lapsed, §37).
func Evaluate(items []evidence.Evidence, now time.Time) int {
	familySum := make(map[evidence.Family]int)
	// correlation group best-score per (family,group)
	groupBest := make(map[string]int)

	// First pass: for each correlation group pick the max score per family, so
	// a single root observation (e.g. "moved to a new network") does not add up
	// its NEW_ASN + NEW_HOSTING_ASN + NEW_COUNTRY signals blindly (§35).
	for _, e := range items {
		if !e.Valid(now) {
			continue
		}
		if e.CorrelationGroup != "" {
			key := groupKey(e.Family, e.CorrelationGroup)
			if e.Score > groupBest[key] {
				groupBest[key] = e.Score
			}
		}
		// uncorrelated evidence counts individually below
	}

	// Second pass: accumulate. Correlated items contribute only their group's
	// best score once; uncorrelated items add their own score.
	absorbed := make(map[string]bool)
	for _, e := range items {
		if !e.Valid(now) {
			continue
		}
		key := ""
		if e.CorrelationGroup != "" {
			key = groupKey(e.Family, e.CorrelationGroup)
			if absorbed[key] {
				continue
			}
			absorbed[key] = true
		}
		add := e.Score // correlated uses group best; uncorrelated uses own
		if key != "" {
			add = groupBest[key]
		}
		familySum[e.Family] += add
	}

	total := 0
	for fam, sum := range familySum {
		cap := fam.FamilyCap()
		if sum > cap {
			sum = cap
		}
		total += sum
	}
	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}
	return total
}

func groupKey(fam evidence.Family, grp string) string {
	return fam.String() + ":" + grp
}

// State is a thin over-risk wrapper for a scope's active risk that also yields
// the marginal contribution of a new evidence set (used by the terminator to
// record risk_before/risk_after for explainability).
type State struct {
	current int
}

// NewState wraps an initial risk score.
func NewState(initial int) *State {
	if initial < 0 {
		initial = 0
	}
	if initial > 100 {
		initial = 100
	}
	return &State{current: initial}
}

// Score returns the wrapped risk score.
func (s *State) Score() int { return s.current }

// After recomputes the risk as if `items` were the complete active evidence set
// at `now`, updating current to the result. Returns the new score.
func (s *State) After(items []evidence.Evidence, now time.Time) int {
	s.current = Evaluate(items, now)
	return s.current
}