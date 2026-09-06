package lane

import (
	"sync"
	"testing"
	"time"
)

// --- P0.23: retention classes -------------------------------------------------

func TestEvictionKeepsBlockedTombstone(t *testing.T) {
	now := time.Now()
	s := NewStore(nil, func() time.Time { return now })

	// Create a lane, then drive it to BLOCKED (operator-controlled state).
	rec := newLaneForTest(t, s, "c1", "l_blocked", now)
	blocked := rec
	blocked.Security.Status = LaneBlocked
	blocked.Security.RiskScore = 95
	s.mu.Lock()
	s.byCred["c1"]["l_blocked"] = blocked
	s.mu.Unlock()

	// Long idle: far beyond any retention multiple.
	longGone := now.Add(-365 * 24 * time.Hour)
	s.mu.Lock()
	s.byCred["c1"]["l_blocked"].LastSeenAt = longGone
	s.evictIdleLocked("c1")
	_, stillThere := s.byCred["c1"]["l_blocked"]
	s.mu.Unlock()
	if !stillThere {
		t.Fatal("BLOCKED lane must be a tombstone: generic idle eviction must never erase operator security state (P0.23)")
	}
}

func TestEvictionRetentionClasses(t *testing.T) {
	now := time.Now()
	s := NewStore(nil, func() time.Time { return now })

	mk := func(laneID string, st State, sec SecurityStatus) {
		rec := newLaneForTest(t, s, "c1", laneID, now)
		rec.State = st
		rec.Security.Status = sec
		s.mu.Lock()
		s.byCred["c1"][laneID] = rec
		s.mu.Unlock()
	}
	mk("l_new", StateNew, LaneNormal)
	mk("l_est", StateEstablished, LaneNormal)
	mk("l_susp", StateProbation, LaneSuspicious)

	s.mu.Lock()
	// Idle for 3x the base bound: NEW expires at 1x, ESTABLISHED (4x) survives,
	// SUSPICIOUS (16x) survives.
	idle := now.Add(-3 * 30 * 24 * time.Hour)
	for _, id := range []string{"l_new", "l_est", "l_susp"} {
		s.byCred["c1"][id].LastSeenAt = idle
	}
	s.evictIdleLocked("c1")
	_, newOK := s.byCred["c1"]["l_new"]
	_, estOK := s.byCred["c1"]["l_est"]
	_, suspOK := s.byCred["c1"]["l_susp"]
	s.mu.Unlock()

	if newOK {
		t.Fatal("NEW lane past idle bound must be evicted (cache class)")
	}
	if !estOK {
		t.Fatal("ESTABLISHED lane at 3x must survive (4x continuity retention)")
	}
	if !suspOK {
		t.Fatal("SUSPICIOUS lane at 3x must survive (16x security-history retention)")
	}

	// Push ESTABLISHED past 4x but keep SUSPICIOUS under 16x.
	s.mu.Lock()
	idle2 := now.Add(-10 * 30 * 24 * time.Hour)
	s.byCred["c1"]["l_est"].LastSeenAt = idle2
	s.byCred["c1"]["l_susp"].LastSeenAt = idle2
	s.evictIdleLocked("c1")
	_, estOK = s.byCred["c1"]["l_est"]
	_, suspOK = s.byCred["c1"]["l_susp"]
	s.mu.Unlock()
	if estOK {
		t.Fatal("ESTABLISHED lane past 4x retention must be evicted")
	}
	if !suspOK {
		t.Fatal("SUSPICIOUS lane at 10x must survive (16x retention)")
	}
}

// --- P0.24: clean-window recovery ---------------------------------------------

func TestRecoveryRestartsCleanWindowAndEpochsCounters(t *testing.T) {
	now := time.Now()
	s := NewStore(nil, func() time.Time { return now })
	rec := newLaneForTest(t, s, "c1", "l1", now)

	// Accumulate baseline progress.
	s.mu.Lock()
	rec = s.byCred["c1"]["l1"]
	rec.AuthorizedCleanRequests = 150
	rec.CleanActiveDays = 3
	s.mu.Unlock()

	// Elevate: clean window invalidated (P0.42). SuspectObs = 2: two
	// consecutive qualifying observations enter SUSPICIOUS.
	if _, err := s.ObserveRisk("c1", "l1", 60, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveRisk("c1", "l1", 60, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("c1", "l1")
	if got.Security.Status != LaneSuspicious {
		t.Fatalf("want SUSPICIOUS after risk 60 x2, got %v", got.Security.Status)
	}
	if !got.CleanSince.IsZero() {
		t.Fatal("elevation must invalidate the clean window")
	}

	// Recover: sustained low risk past ClearDwell.
	hy := DefaultSecurityHysteresis()
	recovered := now.Add(hy.ClearDwell + time.Minute)
	if _, err := s.ObserveRisk("c1", "l1", 5, recovered); err != nil {
		t.Fatal(err)
	}
	// One observation only sets ClearSince; a second after dwell recovers.
	final := recovered.Add(hy.ClearDwell + time.Minute)
	if _, err := s.ObserveRisk("c1", "l1", 5, final); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get("c1", "l1")
	if got.Security.Status != LaneNormal {
		t.Fatalf("want NORMAL after sustained clean window, got %v", got.Security.Status)
	}
	// P0.24: recovery restarts the clean window at the recovery moment.
	if got.CleanSince.IsZero() {
		t.Fatal("recovery must restart CleanSince at the recovery observation (P0.24)")
	}
	// P0.24: baseline progress epochs — promotion criteria re-earned.
	if got.AuthorizedCleanRequests != 0 || got.CleanActiveDays != 0 {
		t.Fatalf("recovery must epoch clean counters (P0.24), got req=%d days=%d",
			got.AuthorizedCleanRequests, got.CleanActiveDays)
	}
	// And MinCleanAge must measure from recovery, not FirstSeenAt.
	crit := DefaultPromotionCriteria()
	_, promoted := PromoteIfEligible(got, crit, final.Add(crit.MinCleanAge-time.Second))
	if promoted {
		t.Fatal("lane must not promote before the post-recovery clean window elapses")
	}
}

// --- P0.25: revision ownership -------------------------------------------------

func TestRevisionBumpsExactlyOncePerMutation(t *testing.T) {
	now := time.Now()
	s := NewStore(nil, func() time.Time { return now })
	newLaneForTest(t, s, "c1", "l1", now)

	s.mu.Lock()
	rev0 := s.byCred["c1"]["l1"].Revision
	s.mu.Unlock()

	// Clean-counter mutation with NO promotion still bumps revision once.
	if _, promoted, err := s.RecordCleanAuthorizedAndPromote("c1", "l1", 3, DefaultPromotionCriteria(), now); err != nil || promoted {
		t.Fatalf("promoted=%v err=%v", promoted, err)
	}
	s.mu.Lock()
	rev1 := s.byCred["c1"]["l1"].Revision
	s.mu.Unlock()
	if rev1 != rev0+1 {
		t.Fatalf("no-promotion counter mutation must bump revision exactly once: %d -> %d", rev0, rev1)
	}

	// ObserveRisk bumps exactly once.
	if _, err := s.ObserveRisk("c1", "l1", 10, now); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	rev2 := s.byCred["c1"]["l1"].Revision
	s.mu.Unlock()
	if rev2 != rev1+1 {
		t.Fatalf("risk observation must bump revision exactly once: %d -> %d", rev1, rev2)
	}

	// A promotion transaction is ONE bump, not two (criteria + store).
	crit := DefaultPromotionCriteria()
	crit.MinCleanAge = 0
	crit.MinCleanRequests = 0
	crit.MinCleanActiveDays = 0
	crit.AllowNewLanes = true
	if _, _, err := s.RecordCleanAuthorizedAndPromote("c1", "l1", 3, crit, now); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	rec := s.byCred["c1"]["l1"]
	rev3, state := rec.Revision, rec.State
	s.mu.Unlock()
	if state != StateProbation {
		t.Fatalf("want PROBATION after seeding promotion, got %v", state)
	}
	if rev3 != rev2+1 {
		t.Fatalf("promotion transaction must bump revision exactly once: %d -> %d", rev2, rev3)
	}
}

// --- P0.26: disqualifying evidence veto ----------------------------------------

func TestPromotionVetoedByDisqualifyingEvidence(t *testing.T) {
	now := time.Now()
	rec := &LaneRecord{
		LaneID: "l1", CredentialID: "c1", State: StateProbation,
		FirstSeenAt:             now.Add(-30 * 24 * time.Hour),
		RequestCount:            999,
		AuthorizedCleanRequests: 500,
		CleanActiveDays:         10,
		ActiveDays:              10,
		RiskScore:               0,
		CleanSince:              now.Add(-20 * 24 * time.Hour),
	}
	crit := DefaultPromotionCriteria()
	crit.MinCleanRequests = 0 // all other criteria satisfied
	crit.MinCleanActiveDays = 0
	crit.HasDisqualifyingEvidence = true

	if _, promoted := PromoteIfEligible(rec, crit, now); promoted {
		t.Fatal("active disqualifying evidence must veto promotion regardless of score/counters (P0.26)")
	}
	// And the veto is not sticky state: without it the same record promotes.
	crit.HasDisqualifyingEvidence = false
	if _, promoted := PromoteIfEligible(rec, crit, now); !promoted {
		t.Fatal("same record without the veto should promote")
	}
}

// --- P0.27: finalize idempotency is in the terminator; here, concurrency -------

func TestConcurrentFinalizeCountsOnce(t *testing.T) {
	now := time.Now()
	s := NewStore(nil, func() time.Time { return now })
	newLaneForTest(t, s, "c1", "l1", now)

	crit := DefaultPromotionCriteria()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = s.RecordCleanAuthorizedAndPromote("c1", "l1", 3, crit, now)
		}()
	}
	wg.Wait()

	s.mu.Lock()
	got := s.byCred["c1"]["l1"]
	reqs, rev := got.AuthorizedCleanRequests, got.Revision
	s.mu.Unlock()
	if reqs != 50 {
		t.Fatalf("50 concurrent finalizes must count 50 clean requests, got %d", reqs)
	}
	if rev != 50+1 { // 50 counter mutations + creation
		t.Fatalf("revision must equal mutation count exactly (P0.25), got %d want %d", rev, 51)
	}
}

// newLaneForTest creates a lane via BorrowOrCreate and returns the stored record.
func newLaneForTest(t *testing.T, s *Store, credID, laneID string, now time.Time) *LaneRecord {
	t.Helper()
	if _, _, err := s.BorrowOrCreate(credID, laneID, Features{NetworkASN: "AS1"}, DefaultThresholds()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.byCred[credID][laneID]
	if rec == nil {
		t.Fatal("lane not created")
	}
	return rec
}
