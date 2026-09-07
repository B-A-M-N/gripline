package lane

import (
	"testing"
	"time"
)

func TestReduceLaneSecurityNormalToSuspicious(t *testing.T) {
	hy := DefaultSecurityHysteresis() // SuspectThresh 30, SuspectObs 2, ClearThresh 15
	now := time.Now()

	// One moderate observation → streak 1, stays NORMAL (SuspectObs=2).
	after := ReduceLaneSecurity(hy, SecurityState{}, 40, now)
	if after.Status != LaneNormal || after.SuspectStreak != 1 {
		t.Fatalf("first obs: status=%v streak=%d (want NORMAL 1)", after.Status, after.SuspectStreak)
	}
	// Second moderate observation → SUSPICIOUS.
	after = ReduceLaneSecurity(hy, after, 40, now.Add(time.Second))
	if after.Status != LaneSuspicious {
		t.Fatalf("P0.7: after two qualifying observations want SUSPICIOUS, got %v", after.Status)
	}
}

func TestReduceLaneSecuritySingleHighBlocks(t *testing.T) {
	hy := DefaultSecurityHysteresis() // BlockThresh 70
	hy.EnableAutomaticBlock = true    // P0.13: automatic block is policy-gated
	now := time.Now()
	after := ReduceLaneSecurity(hy, SecurityState{}, 90, now)
	if after.Status != LaneBlocked {
		t.Fatalf("P0.7: a single high-confidence lane observation must BLOCK immediately, got %v", after.Status)
	}
	if !after.Status.Denied() {
		t.Fatal("BLOCKED must report Denied()")
	}
}

func TestReduceLaneSecurityRecoveryNeedsDwell(t *testing.T) {
	hy := DefaultSecurityHysteresis() // ClearDwell 30m, ClearThresh 15
	now := time.Now()

	suspicious := SecurityState{Status: LaneSuspicious, SuspectStreak: 2}
	// One clean observation starts the dwell timer but does not recover yet.
	after := ReduceLaneSecurity(hy, suspicious, 5, now)
	if after.Status != LaneSuspicious {
		t.Fatalf("one low obs: want still SUSPICIOUS (dwell not met), got %v", after.Status)
	}
	if after.ClearSince.IsZero() {
		t.Fatal("P0.7: low observation must start the ClearSince dwell")
	}
	// Dwell not yet elapsed → still suspicious.
	after = ReduceLaneSecurity(hy, after, 5, now.Add(10*time.Minute))
	if after.Status != LaneSuspicious {
		t.Fatalf("dwell under 30m: want still SUSPICIOUS, got %v", after.Status)
	}
	// Dwell elapsed with sustained clean → NORMAL (P0.7 recovery).
	after = ReduceLaneSecurity(hy, after, 5, now.Add(31*time.Minute))
	if after.Status != LaneNormal {
		t.Fatalf("P0.7: sustained clean dwell must recover SUSPICIOUS→NORMAL, got %v", after.Status)
	}
}

func TestBlockedIsTerminalRequiresLifecycle(t *testing.T) {
	hy := DefaultSecurityHysteresis()
	now := time.Now()
	blocked := SecurityState{Status: LaneBlocked}
	// Even a clean observation cannot auto-recover a block.
	after := ReduceLaneSecurity(hy, blocked, 0, now.Add(time.Hour))
	if after.Status != LaneBlocked {
		t.Fatalf("P0.7: BLOCKED must require explicit unlblock, no auto-recovery (%v)", after.Status)
	}
}

// TestPromotionBlockedBySecurityStatus proves a lane whose RISK security status
// is elevated never promotes even with fully-satisfying clean counters (P0.7/P0.43).
func TestPromotionBlockedBySecurityStatus(t *testing.T) {
	now := time.Now()
	crit := PromotionCriteria{
		AllowNewLanes:        true,
		MinCleanAge:          0,
		MinCleanRequests:     0,
		MinCleanActiveDays:   0,
		MaxEstablishmentRisk: 100,
	}
	// A PROBATION lane with all clean criteria met but RISK status SUSPICIOUS.
	rec := &LaneRecord{
		LaneID: "l", State: StateProbation,
		FirstSeenAt:             now.Add(-30 * 24 * time.Hour),
		AuthorizedCleanRequests: 500, CleanActiveDays: 5,
		RiskScore:  2,
		CleanSince: now.Add(-20 * 24 * time.Hour),
		Security:   SecurityState{Status: LaneSuspicious},
	}
	_, promoted := PromoteIfEligible(rec, crit, now)
	if promoted {
		t.Fatal("P0.43: a lane with SUSPICIOUS risk security must never promote")
	}
}

// TestCleanSinceResetOnElevation proves P0.42: the contiguous clean window is
// invalidated when the lane's risk security elevates, so MinCleanAge uses the
// clean window, not lane age.
func TestCleanSinceResetOnElevation(t *testing.T) {
	store := NewStore(nil, time.Now)
	now := time.Now()

	// Create a lane (CleanSince seeded at creation).
	laneID := "lane_clean"
	rec, created, err := store.BorrowOrCreate("cred_c", laneID, Features{NetworkASN: "AS1"}, ClassificationContext{Thresholds: DefaultThresholds()})
	if err != nil || !created {
		t.Fatalf("create: %v", err)
	}
	if !rec.CleanSince.Equal(rec.FirstSeenAt) {
		t.Fatal("P0.42: CleanSince must be seeded at lane creation")
	}

	// A high lane-risk observation elevates → CleanSince resets. P0.13: with
	// automatic block disabled (default), elevation lands SUSPICIOUS; enable
	// the gate here to exercise the BLOCKED transition specifically.
	hy := DefaultSecurityHysteresis()
	hy.EnableAutomaticBlock = true
	store.SetSecurityHysteresis(hy)
	if _, err := store.ObserveRisk("cred_c", laneID, 95, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Get("cred_c", laneID)
	if !rec.CleanSince.IsZero() {
		t.Fatal("P0.42: CleanSince must reset to zero when the lane elevates")
	}
	if rec.Security.Status != LaneBlocked {
		t.Fatalf("P0.7: lane must be BLOCKED after high risk, got %v", rec.Security.Status)
	}
}

// P0.13: automatic lane BLOCK is policy-gated. With the gate disabled (the
// default, shadow-first posture), a block-warranting score may elevate a lane
// to SUSPICIOUS (restricted, non-promoting) but NEVER to BLOCKED — the old
// code committed automatic, operator-unvalidated, durable denials while the
// credential side claimed no-auto-quarantine. An operator block (via Unblock's
// complement) remains available; enabling the gate in a validated revision
// turns the automatic transition on.
func TestAutomaticBlockIsPolicyGated(t *testing.T) {
	now := time.Now()

	// Gate OFF (default): block-warranting score lands SUSPICIOUS immediately,
	// never BLOCKED.
	hyOff := DefaultSecurityHysteresis()
	after := ReduceLaneSecurity(hyOff, SecurityState{}, 95, now)
	if after.Status != LaneSuspicious {
		t.Fatalf("P0.13: gate off + score 95 → %v, want SUSPICIOUS (restricted, not blocked)", after.Status)
	}
	// And a SUSPICIOUS lane with a hot score stays SUSPICIOUS, not BLOCKED.
	after2 := ReduceLaneSecurity(hyOff, SecurityState{Status: LaneSuspicious}, 95, now)
	if after2.Status != LaneSuspicious {
		t.Fatalf("P0.13: gate off + SUSPICIOUS + hot score → %v, want SUSPICIOUS", after2.Status)
	}

	// Gate ON (operator-validated posture): same score blocks.
	hyOn := DefaultSecurityHysteresis()
	hyOn.EnableAutomaticBlock = true
	blocked := ReduceLaneSecurity(hyOn, SecurityState{}, 95, now)
	if blocked.Status != LaneBlocked {
		t.Fatalf("P0.13: gate on + score 95 → %v, want BLOCKED", blocked.Status)
	}
	blocked2 := ReduceLaneSecurity(hyOn, SecurityState{Status: LaneSuspicious}, 95, now)
	if blocked2.Status != LaneBlocked {
		t.Fatalf("P0.13: gate on + SUSPICIOUS + hot score → %v, want BLOCKED", blocked2.Status)
	}

	// An already-BLOCKED lane stays BLOCKED regardless of the gate — the gate
	// guards automatic ESCALATION; it must never silently lift an operator
	// state.
	after3 := ReduceLaneSecurity(hyOff, SecurityState{Status: LaneBlocked}, 5, now)
	if after3.Status != LaneBlocked {
		t.Fatalf("P0.13: gate off must not auto-recover an operator block: %v", after3.Status)
	}
}

// P0.13 end-to-end through the store: a terminator built with the default
// policy (gate off) must not persist a BLOCKED lane even under extreme
// evidence; it persists SUSPICIOUS instead.
func TestStoreObserveRiskRespectsAutomaticBlockGate(t *testing.T) {
	now := time.Now()
	store := NewStore(nil, func() time.Time { return now })
	// Defaults: automatic block OFF.
	if _, _, err := store.BorrowOrCreate("cred_g", "lane_g", Features{NetworkASN: "AS1"}, ClassificationContext{Thresholds: DefaultThresholds()}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ObserveRisk("cred_g", "lane_g", 100, now); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Get("cred_g", "lane_g")
	if rec.Security.Status != LaneSuspicious {
		t.Fatalf("P0.13: default store posture + score 100 → %v, want SUSPICIOUS", rec.Security.Status)
	}
	if rec.Security.Status.Denied() {
		t.Fatal("P0.13: SUSPICIOUS must not deny outright")
	}
	if !rec.Security.Status.Elevated() {
		t.Fatal("P0.13: SUSPICIOUS must restrict")
	}
}
