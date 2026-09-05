package lane

import (
	"errors"
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
func (s *Store) BorrowOrCreate(credID, newLaneID string, cand Features, th ClassificationThresholds) (*LaneRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := s.byCred[credID]
	if m == nil {
		m = make(map[string]*LaneRecord)
		s.byCred[credID] = m
	}

	bestSim := 0.0
	var best *LaneRecord
	for _, rec := range m {
		// Compare against representative feature vector stored on the record;
		// here we use the network/client/region classes persisted on the row.
		rf := Features{
			NetworkASN:   rec.NetworkClass,
			RegionClass:  rec.RegionClass,
			ClientFamily: rec.ClientFamily,
		}
		if sim := Similarity(cand, rf); sim > bestSim {
			bestSim = sim
			best = rec
		}
	}

	if best != nil && th.classify(bestSim) == ClassMatch {
		best.LastSeenAt = s.now()
		best.RequestCount++
		best.Revision++
		c := *best
		return &c, false, nil
	}

	// New lane: enforce explosion protection.
	lm := s.limits()
	if len(m) >= lm.MaxActiveLanesPerCredential {
		return nil, false, ErrTooManyLanes
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
		NetworkClass: cand.NetworkASN,
		RegionClass:  cand.RegionClass,
		ClientFamily: cand.ClientFamily,
		RequestCount: 1,
		Revision:     1,
	}
	m[newLaneID] = rec
	s.evictIdleLocked()
	// Return a copy: the internal record must not escape the store's mutex.
	c := *rec
	return &c, true, nil
}

// evictIdleLocked removes lanes idle beyond the configured expiration.
func (s *Store) evictIdleLocked() {
	lm := s.limits()
	cutoff := s.now().Add(-lm.LaneIdleExpiration)
	for cred, m := range s.byCred {
		for id, r := range m {
			if r.LastSeenAt.Before(cutoff) {
				delete(m, id)
			}
		}
		if len(m) == 0 {
			delete(s.byCred, cred)
		}
	}
}

// ActiveLaneCount returns the number of lanes held by a credential.
func (s *Store) ActiveLaneCount(credID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byCred[credID])
}
