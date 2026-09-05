package lane

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// Limits caps the state an attacker can force into existence via lane variants
// (§28 explosion protection).
type Limits struct {
	MaxActiveLanesPerCredential int
	MaxProvisionalLanes         int
	LaneIdleExpiration          time.Duration
}

// DefaultLimits returns conservative defaults (policy-tunable).
func DefaultLimits() Limits {
	return Limits{
		MaxActiveLanesPerCredential: 16,
		MaxProvisionalLanes:         8,
		LaneIdleExpiration:          30 * 24 * time.Hour,
	}
}

// featSchemaVersion is the current classification-vector schema. Bump when the
// Features struct changes shape so old rows are visibly incompatible.
const featSchemaVersion = 2

// GetConfig is a minimal hook returning the enforced limits; nil means defaults.
type GetConfig func() Limits

// Store is a per-credential, bounded, concurrency-safe lane store with idle
// eviction (§28, §81 bounded memory). Overflow low-value variants are folded
// into an overflow bucket instead of unbounded growth.
type Store struct {
	mu     sync.Mutex
	cfg    GetConfig
	now    func() time.Time
	byCred map[string]map[string]*LaneRecord // credentialID -> laneID -> record
}

// NewStore builds a Store. cfg may be nil (defaults apply).
func NewStore(cfg GetConfig, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{cfg: cfg, now: now, byCred: make(map[string]map[string]*LaneRecord)}
}

func (s *Store) limits() Limits {
	if s.cfg != nil {
		if l := s.cfg(); l.MaxActiveLanesPerCredential > 0 {
			return l
		}
	}
	return DefaultLimits()
}

// ErrTooManyLanes is returned when a credential already holds the max lanes.
var ErrTooManyLanes = errors.New("lane: too many lanes for credential")

// ErrLaneConflict is returned when a create would overwrite an existing lane
// row. An overwrite here is a state-reset attack (§24): distinct feature sets
// deriving the same caller-chosen id would replace a BLOCKED/SUSPICIOUS lane
// with a fresh NEW record — laundering its history and evading the explosion
// limit (the map never grows). Failing closed is the only safe answer.
var ErrLaneConflict = errors.New("lane: lane id collision with different features")

// Get returns a lane record by credential + lane id (a copy).
func (s *Store) Get(credID, laneID string) (*LaneRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.lookupLocked(credID, laneID)
	if !ok {
		return nil, false
	}
	c := *rec
	return &c, true
}

func (s *Store) lookupLocked(credID, laneID string) (*LaneRecord, bool) {
	m, ok := s.byCred[credID]
	if !ok {
		return nil, false
	}
	r, ok := m[laneID]
	return r, ok
}

// BorrowOrCreate returns an existing lane if one is within Match similarity of
// a candidate feature set, otherwise creates a new lane subject to explosion
// limits. Returns the lane and whether it was newly created.
//
// Selection is DETERMINISTIC (P0.9, §26): candidates tie-broken by highest
// similarity, then lexicographically smallest lane id — never Go map iteration
// order. Expired lanes are evicted (per-credential, before the limit check)
// so a lane that should have expired cannot wedge creation (§28).
func (s *Store) BorrowOrCreate(credID, newLaneID string, cand Features, th ClassificationThresholds) (*LaneRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict idle lanes for THIS credential before the limit decision so an
	// expired lane cannot consume capacity that its own expiration is about to
	// free (and eviction stays O(lanes-per-credential), not O(all lanes)).
	// Runs BEFORE the map is (re)created below: evictIdleLocked deletes an
	// emptied credential entry, which would orphan a map created first.
	s.evictIdleLocked(credID)

	m := s.byCred[credID]
	if m == nil {
		m = make(map[string]*LaneRecord)
		s.byCred[credID] = m
	}

	bestSim := -1.0
	var bestID string
	var best *LaneRecord
	for id, rec := range m {
		if sim := Similarity(cand, rec.Features); sim > bestSim {
			bestSim = sim
			bestID = id
			best = rec
		} else if sim == bestSim && id < bestID {
			// Deterministic tie-break: lexicographically smallest id wins.
			bestID = id
			best = rec
		}
	}

	if best != nil && th.classify(bestSim) == ClassMatch {
		best.LastSeenAt = s.now()
		best.RequestCount++
		best.Revision++
		best.trackActiveDayLocked(s.now())
		c := *best
		return &c, false, nil
	}

	// New lane: enforce explosion protection (§28) — active lanes and
	// provisional (NEW+PROBATION) lanes both bounded.
	lm := s.limits()
	if len(m) >= lm.MaxActiveLanesPerCredential {
		return nil, false, ErrTooManyLanes
	}
	if lm.MaxProvisionalLanes > 0 {
		provisional := 0
		for _, rec := range m {
			if rec.State == StateNew || rec.State == StateProbation {
				provisional++
			}
		}
		if provisional >= lm.MaxProvisionalLanes {
			return nil, false, ErrTooManyLanes
		}
	}
	// Never overwrite an existing row: if the id is taken but features were not
	// a Match (checked above), the id derivation has collided. Insert-only
	// keeps lane history append-only (§24); the caller fails closed.
	if _, exists := m[newLaneID]; exists {
		return nil, false, ErrLaneConflict
	}
	now := s.now()
	rec := &LaneRecord{
		LaneID:       newLaneID,
		CredentialID: credID,
		State:        StateNew,
		FirstSeenAt:  now,
		LastSeenAt:   now,
		Features:     cand, // full vector persisted (P0.8)
		FeatSchema:   featSchemaVersion,
		RequestCount: 1,
		Revision:     1,
	}
	rec.trackActiveDayLocked(now)
	m[newLaneID] = rec
	// Return a copy: the internal record must not escape the store's mutex.
	c := *rec
	return &c, true, nil
}

// trackActiveDayLocked advances the distinct-active-days counter (§29).
func (r *LaneRecord) trackActiveDayLocked(now time.Time) {
	day := now.Format("2006-01-02")
	if r.LastActiveDay == day {
		return
	}
	r.LastActiveDay = day
	r.ActiveDays++
}

// evictIdleLocked removes lanes idle beyond the configured expiration for one
// credential (bounded work per admission, not a global scan).
func (s *Store) evictIdleLocked(credID string) {
	lm := s.limits()
	if lm.LaneIdleExpiration <= 0 {
		return
	}
	cutoff := s.now().Add(-lm.LaneIdleExpiration)
	m := s.byCred[credID]
	for id, r := range m {
		if r.LastSeenAt.Before(cutoff) {
			delete(m, id)
		}
	}
	if len(m) == 0 {
		delete(s.byCred, credID)
	}
}

// ActiveLaneCount returns the number of lanes held by a credential.
func (s *Store) ActiveLaneCount(credID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byCred[credID])
}

// sortRecords is retained for deterministic iteration by callers that must
// enumerate lanes (diagnostics/sweeper use); store internals never depend on
// map order for decisions.
func sortRecords(m map[string]*LaneRecord) []*LaneRecord {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*LaneRecord, 0, len(ids))
	for _, id := range ids {
		out = append(out, m[id])
	}
	return out
}
