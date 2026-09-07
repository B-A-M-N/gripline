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
// the durable implementation lives in internal/statebolt.
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
// eviction (§28, §81 bounded memory). Overflow low-value variants are folded
// into an overflow bucket instead of unbounded growth.
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
//
// Cross-revision gating (P0.21): a row is only reusable when BOTH its
// FeatSchema AND its ClassificationRevision equal the context's. Re-keying
// classification semantics fragments the lane universe instead of laundering
// pre-change history into the new one.
func (s *Store) BorrowOrCreate(credID, newLaneID string, cand Features, ctx ClassificationContext) (*LaneRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	th := ctx.Thresholds
	// P0.21: a zero/unset context revision means "the store's current
	// universe". The terminator always passes an explicit policy revision; this
	// default keeps legacy store-level callers in the same universe without
	// forcing every test to spell out the revision.
	if ctx.Revision < 1 {
		ctx.Revision = currentClassificationRevision
	}

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

	// Exact-manifestation reuse (P0.1): if the deterministic lane ID derived
	// from this candidate already exists with an IDENTICAL feature vector under
	// the CURRENT schema, the request is re-presenting the same provisional
	// manifestation. It reuses its OWN lane — the same record, whatever its
	// state — without that reuse granting any established-lane trust. This is
	// distinct from borrowing: the 0.70 comparable/trusted-feature floor below
	// governs a candidate matching a DIFFERENT (established) lane, not a client
	// repeating the exact vector its lane ID was derived from. Without this,
	// the default sparse resolver (no trusted network dims) would derive the
	// same ID, fail the borrow floor, and hit ErrLaneConflict on every second
	// request — the proxy would be functionally unusable.
	//
	// A same-ID record with a DIFFERENT vector or an old schema is still the
	// §24 state-reset collision and fails closed (ErrLaneConflict), and a
	// schema-stale record is never silently compared (P0.22).
	if rec, exists := m[newLaneID]; exists {
		if rec.FeatSchema == featSchemaVersion && rec.ClassificationRevision == ctx.Revision && sameFeatures(rec.Features, cand) {
			rec.LastSeenAt = s.now()
			rec.RequestCount++
			rec.Revision++
			rec.trackActiveDayLocked(s.now())
			c := *rec
			return &c, false, nil
		}
		return nil, false, ErrLaneConflict
	}

	bestSim := -1.0
	var bestID string
	var best *LaneRecord
	for id, rec := range m {
		// Never classify across feature-schema revisions (P0.22) or lane-universe
		// revisions (P0.21): a record stored under an older schema has dimensions
		// this schema may score differently, and one stored under an older
		// ClassificationRevision belongs to a different lane universe. Skip both
		// for borrowing; the exact-reuse path above already rejects same-ID
		// stale records.
		if rec.FeatSchema != featSchemaVersion || rec.ClassificationRevision != ctx.Revision {
			continue
		}
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

	// Anti-laundering gate (P0.9): a MATCH (borrowing another lane) requires
	// BOTH enough renormalized similarity AND enough comparable feature mass.
	// A sparse candidate that matches only on a couple of shared fields
	// (renormalized to 1.0) must not collapse into an established lane.
	// Fail-closed: a configured floor of 0 (field forgotten) never permits a
	// Match, so omitting the field cannot silently reopen the laundering
	// strategy. Exact self-reuse was already handled above and does not pass
	// through this gate.
	isMatch := best != nil && th.classify(bestSim) == ClassMatch
	if isMatch && th.MinComparableWeight > 0 {
		isMatch = ComparableWeight(cand, best.Features) >= th.MinComparableWeight
	} else if best != nil {
		// Nonzero comparable mass required; a zero floor is not blanket permission.
		isMatch = false
	}
	if best != nil && isMatch {
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
	// Never overwrite an existing row: same-ID/different-features and
	// schema-stale collisions were rejected above (P0.1/P0.22); this is the
	// unreachable-if-consistent backstop. Insert-only keeps lane history
	// append-only (§24); the caller fails closed.
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
		// P0.21: persist the classification universe the row was created under
		// so a later re-key can never borrow it.
		ClassificationRevision: ctx.Revision,
		RequestCount:           1,
		CleanSince:             now, // the clean window starts at lane creation (P0.42)
		Revision:               1,
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

// evictIdleLocked removes lanes idle beyond their RETENTION CLASS's expiration
// for one credential (bounded work per admission, not a global scan).
//
// Retention classes (P0.23): generic idle eviction must never erase security
// history. Ordinary NEW/PROBATION lanes are cache (expire at the configured
// idle bound); ESTABLISHED lanes carry continuity value and live 4x longer;
// SUSPICIOUS lanes are security history (16x); BLOCKED lanes are tombstones
// that NEVER expire through this path — an operator-controlled state must not
// silently re-arm itself as a fresh lane after enough idle time. A BLOCKED
// lane's reappearance after eviction would launder its entire abuse history
// through generic cache pressure; the retention classing is what keeps the
// security axis durable.
func (s *Store) evictIdleLocked(credID string) {
	lm := s.limits()
	if lm.LaneIdleExpiration <= 0 {
		return
	}
	now := s.now()
	cutoff := now.Add(-lm.LaneIdleExpiration)
	m := s.byCred[credID]
	for id, r := range m {
		if r.LastSeenAt.After(cutoff) {
			continue
		}
		if r.Security.Status == LaneBlocked {
			// Tombstone: never expires through generic eviction (P0.23).
			// Only an explicit operator lifecycle action may remove it.
			continue
		}
		retained := lm.LaneIdleExpiration
		switch {
		case r.Security.Status == LaneSuspicious:
			retained *= 16 // security history outlives the cache bound
		case r.State == StateEstablished:
			retained *= 4 // continuity for established lanes
		}
		if r.LastSeenAt.Before(now.Add(-retained)) {
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
		return nil, errors.New("lane: not found")
	}
	hy := s.securityHys()
	before := rec.Security.Status
	rec.RiskScore = riskScore
	// Persist the risk-driven security state (P0.7): this is what makes a
	// suspicious/blocked lane actually restricted or denied. The reducer is
	// pure over the persisted SecurityState, so restart/multi-node preserve
	// lane elevation history.
	rec.Security = ReduceLaneSecurity(hy, rec.Security, riskScore, now)
	// P0.42: when the lane's security ELEVATES (NORMAL→SUSPICIOUS/BLOCKED), the
	// contiguous clean window is invalidated. MinCleanAge must restart from the
	// next clean period, not include the pre-elevation quiet time.
	if rec.Security.Status != LaneNormal && before == LaneNormal {
		rec.CleanSince = time.Time{}
	}
	// P0.24: the mirror image of P0.42 — when an elevated lane RECOVERS to
	// NORMAL, the clean window restarts at the moment of recovery. Without
	// this, CleanSince stays zero after recovery and PromoteIfEligible's
	// MinCleanAge fallback (FirstSeenAt) silently includes the entire
	// suspicious period, so a lane could promote on the strength of the very
	// quiet time that preceded its abuse.
	if rec.Security.Status == LaneNormal && before != LaneNormal {
		rec.CleanSince = now
		// The disqualifying window also invalidates baseline progress: clean
		// counters epoch so promotion criteria must be re-earned in the new
		// window, not inherited from before the elevation.
		rec.AuthorizedCleanRequests = 0
		rec.CleanActiveDays = 0
		rec.LastCleanActiveDay = ""
	}
	rec.Revision++
	c := *rec
	return &c, nil
}

// securityHys returns the configured lane security hysteresis, defaulting
// conservatively when unset.
func (s *Store) securityHys() SecurityHysteresis {
	// P0.13: the compiled policy's override wins over construction config.
	if s.securityOverride.SuspectThresh > 0 && s.securityOverride.BlockThresh > 0 {
		return s.securityOverride
	}
	lm := s.limits()
	if lm.Security.SuspectThresh > 0 && lm.Security.BlockThresh > 0 {
		return lm.Security
	}
	return DefaultSecurityHysteresis()
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
		return nil, false, errors.New("lane: not found")
	}

	// Update risk score (always).
	rec.RiskScore = riskScore

	// Increment clean counters.
	rec.AuthorizedCleanRequests++
	day := now.Format("2006-01-02")
	if rec.LastCleanActiveDay != day {
		rec.LastCleanActiveDay = day
		rec.CleanActiveDays++
	}
	rec.trackActiveDayLocked(now)

	// Attempt promotion only for eligible states.
	var promoted bool
	var newState State
	switch rec.State {
	case StateNew, StateProbation:
		if newState, promoted = PromoteIfEligible(rec, crit, now); promoted {
			rec.State = newState
		}
	}

	rec.Revision++
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
	rec.AuthorizedCleanRequests++
	day := now.Format("2006-01-02")
	if rec.LastCleanActiveDay != day {
		rec.LastCleanActiveDay = day
		rec.CleanActiveDays++
	}
	rec.trackActiveDayLocked(now)
	rec.Revision++
}
