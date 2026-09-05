package lane

import (
	"errors"
	"testing"
	"time"
)

// TestUnblockExitsBlockedAndReseedsClean is the operator lifecycle proof
// (P0.39): the reducer never auto-recovers a BLOCKED lane; only an explicit
// operator Unblock clears it, and it re-seeds the contiguous-clean window so
// promotion restarts from the operator's action, not the pre-abuse quiet period.
func TestUnblockExitsBlockedAndReseedsClean(t *testing.T) {
	now := time.Now()
	store := NewStore(nil, func() time.Time { return now })

	laneID := "lane_b"
	rec, _, err := store.BorrowOrCreate("cred_c", laneID, Features{NetworkASN: "AS1"}, DefaultThresholds())
	if err != nil {
		t.Fatal(err)
	}
	// Drive to BLOCKED via a single high-risk observation.
	if _, err := store.ObserveRisk("cred_c", laneID, 90, now); err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Get("cred_c", laneID)
	if rec.Security.Status != LaneBlocked {
		t.Fatalf("want BLOCKED, got %v", rec.Security.Status)
	}
	origClean := rec.CleanSince

	// The reducer cannot auto-recover a block (terminal).
	after := ReduceLaneSecurity(DefaultSecurityHysteresis(), rec.Security, 0, now.Add(time.Minute))
	if after.Status != LaneBlocked {
		t.Fatalf("P0.7: a clean observation must not auto-recover a block, got %v", after.Status)
	}

	// Operator unblock clears the lane and re-seeds CleanSince.
	entry, err := store.Unblock("cred_c", laneID, "ops-console", "manual review cleared", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Action != ActionUnblock || entry.Before != LaneBlocked || entry.After != LaneNormal {
		t.Fatalf("P0.35: audit entry wrong: %+v", entry)
	}
	rec, _ = store.Get("cred_c", laneID)
	if rec.Security.Status != LaneNormal {
		t.Fatalf("P0.39: after unblock want NORMAL, got %v", rec.Security.Status)
	}
	if rec.CleanSince.IsZero() || !rec.CleanSince.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("P0.42: unblock must re-seed CleanSince to operator action time")
	}
	if rec.CleanSince.Equal(origClean) && !origClean.IsZero() {
		t.Fatal("CleanSince must move forward from the operator clearing")
	}
}

// TestUnblockFailsOnNonBlockedLane proves ErrActionInvalid: you cannot "clear" a
// lane that never earned a BLOCK — that would let an operator casually launder
// a SUSPICIOUS or NORMAL lane's history.
func TestUnblockFailsOnNonBlockedLane(t *testing.T) {
	now := time.Now()
	store := NewStore(nil, func() time.Time { return now })
	laneID := "lane_n"
	store.BorrowOrCreate("cred_c", laneID, Features{NetworkASN: "AS1"}, DefaultThresholds())

	if _, err := store.Unblock("cred_c", laneID, "ops", "why", now); !errors.Is(err, ErrActionInvalid) {
		t.Fatalf("P0.39: unblocking a NORMAL lane must fail closed (ErrActionInvalid), got %v", err)
	}
}

// TestUnblockAbsentLaneFails proves a missing lane cannot be unblocked.
func TestUnblockAbsentLaneFails(t *testing.T) {
	store := NewStore(nil, time.Now)
	if _, err := store.Unblock("cred_c", "nope", "ops", "", time.Now()); !errors.Is(err, ErrLaneNotFound) {
		t.Fatalf("absent lane unblock must return ErrLaneNotFound, got %v", err)
	}
}