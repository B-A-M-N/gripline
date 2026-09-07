package lane

import (
	"sync"
	"time"
)

// Limits caps the state an attacker can force into existence via lane variants
// (§28 explosion protection).
type Limits struct {
	MaxActiveLanesPerCredential int
	MaxProvisionalLanes         int
	LaneIdleExpiration          time.Duration
	// Security carries the lane risk→security-status hysteresis (P0.7/P0.11).
	// Zero value falls back to DefaultSecurityHysteresis.
	Security SecurityHysteresis
}

// DefaultLimits returns conservative defaults (policy-tunable).
func DefaultLimits() Limits {
	return Limits{
		MaxActiveLanesPerCredential: 16,
		MaxProvisionalLanes:         8,
		LaneIdleExpiration:          30 * 24 * time.Hour,
		Security:                    DefaultSecurityHysteresis(),
	}
}

// featSchemaVersion is the current classification-vector schema. Bump when the
// Features struct changes shape so old rows are visibly incompatible. Exposed
// read-only as FeatSchemaVersion (P0.22); rows under an older schema are never
// compared against candidates (skip for borrow, reject for same-ID reuse).
const featSchemaVersion = 2

// GetConfig is a minimal hook returning the enforced limits; nil means defaults.
type GetConfig func() Limits

// Repository is the lane-persistence contract the terminator depends on (P0.10:
// the memory Store and the durable Bolt repository both satisfy it, so the
// security core stays database-agnostic). The memory implementation is `Store`;
// the durable implementation lives in internal/statebolt. Both execute the SAME
// pure mutation reducers (reduce.go), so semantics cannot drift between the
// resident and durable backends.
type Repository interface {
	// SetSecurityHysteresis overrides the risk→status hysteresis to the given
	// compiled policy's (P0.13). A zero value falls back to defaults.
	SetSecurityHysteresis(hy SecurityHysteresis)

	// BorrowOrCreate returns an existing lane within Match similarity of a
	// candidate feature set, else creates a new one subject to explosion
	// limits. Returns the lane and whether it was newly created. Cross-revision
	// borrowing is impossible: a stored lane is only reusable when BOTH its
	// feature schema AND its ClassificationRevision match the context (P0.21).
	BorrowOrCreate(credID, candidateID string, features Features, classification ClassificationContext) (*LaneRecord, bool, error)

	// Get returns a lane by credential + lane id (a copy); ok=false if absent.
	Get(credID, laneID string) (*LaneRecord, bool)

	// ObserveRisk atomically updates a lane's risk score AND drives its
	// security status (P0.7), returning the updated record.
	ObserveRisk(credID, laneID string, riskScore int, now time.Time) (*LaneRecord, error)

	// RecordCleanAuthorizedAndPromote increments clean counters and attempts
	// promotion for eligible states, one authoritative mutation (P0.25).
	RecordCleanAuthorizedAndPromote(credID, laneID string, riskScore int, criteria PromotionCriteria, now time.Time) (*LaneRecord, bool, error)

	// ListLaneIDs returns the lane IDs held by a credential (a copy).
	ListLaneIDs(credID string) []string
}

// Store is a per-credential, bounded, concurrency-safe lane store with idle
// eviction (§28, §81 bounded memory). It is the RESIDENT implementation of
// Repository; its every mutation is a pure reducer from reduce.go executed
// under the store mutex. Overflow low-value variants are folded into an
// overflow bucket instead of unbounded growth.
type Store struct {
	mu  sync.Mutex
	cfg GetConfig
	now func() time.Time
	// securityOverride, when non-zero, replaces the Limits.Security hysteresis
	// (P0.13): the compiled policy's hysteresis is applied over whatever config
	// the store was built with, so policy revision is the one authority.
	securityOverride SecurityHysteresis
	// auditSink, when set, durably commits every operator-transition audit
	// entry inside the same transaction as the state change (P0.49). Nil keeps
	// the in-memory default (entry returned to the caller, nothing persisted).
	auditSink AuditSink
	byCred    map[string]map[string]*LaneRecord // credentialID -> laneID -> record
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

// SetSecurityHysteresis overrides the security hysteresis used for lane
// risk→status transitions (P0.13). The terminator calls this at construction
// with its COMPILED policy's LaneSecurity so the policy revision — not store
// construction defaults — is the one authority for lane security behavior.
// A zero hy falls back to defaults (conservative: automatic block off).
func (s *Store) SetSecurityHysteresis(hy SecurityHysteresis) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hy.SuspectThresh > 0 && hy.BlockThresh > 0 {
		s.securityOverride = hy
		return
	}
	s.securityOverride = DefaultSecurityHysteresis()
}

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
// The semantics are the pure ApplyBorrowOrCreate reducer (P0.9/P0.21/P0.22/§28)
// — deterministic selection, retention classes, explosion limits, the P0.9
// anti-laundering floor — executed here under the store mutex so concurrent
// admissions serialize exactly as the Bolt transaction does.
func (s *Store) BorrowOrCreate(credID, newLaneID string, cand Features, ctx ClassificationContext) (*LaneRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := s.byCred[credID]
	if m == nil {
		m = make(map[string]*LaneRecord)
		s.byCred[credID] = m
	}
	// Deterministic input order for the reducer (map iteration is not).
	records := make([]*LaneRecord, 0, len(m))
	for _, id := range sortedLaneIDs(m) {
		records = append(records, m[id])
	}

	lm := s.limits()
	res, err := ApplyBorrowOrCreate(records, credID, newLaneID, cand, ctx, lm, s.now())
	if err != nil {
		// Retention deletions are legitimate even when the mutation fails: an
		// expired lane's capacity is freed regardless of the borrow outcome.
		for _, id := range res.Deletes {
			delete(m, id)
		}
		if len(m) == 0 {
			delete(s.byCred, credID)
		}
		return nil, false, err
	}
	for _, id := range res.Deletes {
		delete(m, id)
	}
	if res.Upsert != nil {
		m[res.Upsert.LaneID] = res.Upsert
	}
	if len(m) == 0 {
		delete(s.byCred, credID)
	}
	// Return a copy: the caller's *LaneRecord must not alias the store's
	// internal map entry, which later mutations (ObserveRisk, promotion)
	// update in place under the mutex (same discipline as Get/ObserveRisk).
	out := *res.Upsert
	return &out, res.Created, nil
}

// sortedLaneIDs returns map keys in lexicographic order so the pure reducer's
// deterministic tie-breaks are actually exercised over deterministic input.
func sortedLaneIDs(m map[string]*LaneRecord) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sortStrings(ids)
	return ids
}

// evictIdleLocked removes lanes idle beyond their RETENTION CLASS's expiration
// for one credential (bounded work per admission, not a global scan). The
// per-record decision is the shared RetentionDecision reducer (P0.23), so the
// resident store and the durable Bolt repository expire lanes identically.
// Must be called while holding s.mu.
func (s *Store) evictIdleLocked(credID string) {
	lm := s.limits()
	if lm.LaneIdleExpiration <= 0 {
		return
	}
	m := s.byCred[credID]
	if m == nil {
		return
	}
	now := s.now()
	for id, r := range m {
		if !RetentionDecision(r, lm.LaneIdleExpiration, now) {
			delete(m, id)
		}
	}
	if len(m) == 0 {
		delete(s.byCred, credID)
	}
}

func sortStrings(s []string) {
	// Small sets (bounded per credential by §28): insertion sort is clear and
	// allocation-free.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ActiveLaneCount returns the number of lanes held by a credential.
func (s *Store) ActiveLaneCount(credID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byCred[credID])
}

// ListLaneIDs returns the lane IDs for a credential (a copy).
func (s *Store) ListLaneIDs(credID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byCred[credID]
	if m == nil {
		return nil
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	return ids
}

// ObserveRisk atomically updates a lane's risk score AND drives the lane
// security-status dimension (P0.7) under the store lock. This prevents lost
// updates from concurrent admissions and ensures lane-scoped enforcement.
// Call this on EVERY admission (authorized or denied) — risk observation is a
// security function that happens before authorization decisions.
//
// The returned LaneRecord carries the updated RiskScore, the resulting
// SecurityStatus, and a bumped Revision (one authoritative mutation).
func (s *Store) ObserveRisk(credID, laneID string, riskScore int, now time.Time) (*LaneRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.lookupLocked(credID, laneID)
	if !ok {
		return nil, ErrLaneNotFound
	}
	ApplyRiskObservation(rec, riskScore, s.securityHys(), now)
	c := *rec
	return &c, nil
}

// securityHys returns the configured lane security hysteresis, defaulting
// conservatively when unset.
func (s *Store) securityHys() SecurityHysteresis {
	return EffectiveSecurityHysteresis(s.securityOverride, s.limits().Security)
}

// RecordCleanAuthorizedAndPromote updates clean counters and checks promotion
// criteria under the store lock. This is called AFTER a request has been fully
// authorized (passed all gates). Denied requests must NOT call this — they
// contribute evidence but not baseline progress.
//
// Revision ownership (P0.25): this call is ONE authoritative mutation
// transaction — counters, and promotion if it fires — and bumps Revision
// exactly once, whether or not a promotion occurred. Callers use Revision for
// optimistic concurrency and evidence-revision checks; a counter update that
// ships without a revision bump is a lost-update window.
//
// Returns whether a promotion occurred. The returned LaneRecord (if any) has
// the updated state and Revision.
func (s *Store) RecordCleanAuthorizedAndPromote(credID, laneID string, riskScore int, crit PromotionCriteria, now time.Time) (*LaneRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.lookupLocked(credID, laneID)
	if !ok {
		return nil, false, ErrLaneNotFound
	}
	promoted := ApplyCleanAuthorizedAndPromote(rec, riskScore, crit, now)
	c := *rec
	return &c, promoted, nil
}

// RecordCleanAuthorized increments the authorized clean request counter and
// tracks the active day for promotion purposes. This is called AFTER a
// request has been fully authorized (passed all gates). Denied requests must
// NOT call this — they contribute evidence but not baseline progress.
// One authoritative mutation: bumps Revision exactly once (P0.25).
func (s *Store) RecordCleanAuthorized(credID, laneID string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.lookupLocked(credID, laneID)
	if !ok {
		return
	}
	ApplyCleanAuthorized(rec, now)
}
