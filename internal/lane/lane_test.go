package lane

import (
	"testing"
	"time"
)

func TestSimilarityMatch(t *testing.T) {
	a := Features{NetworkASN: "AS15169", RegionClass: "north-america-midwest", ClientFamily: "claude-code"}
	b := Features{NetworkASN: "AS15169", RegionClass: "north-america-midwest", ClientFamily: "claude-code"}
	sim := Similarity(a, b)
	if sim < 0.99 {
		t.Fatalf("identical vector similarity = %.3f, want ~1.0", sim)
	}
}

func TestSimilarityNovel(t *testing.T) {
	a := Features{NetworkASN: "AS15169", RegionClass: "north-america-midwest", ClientFamily: "claude-code"}
	b := Features{NetworkASN: "AS14061", NetworkType: "hosting", RegionClass: "europe-west", ClientFamily: "python-sdk"}
	sim := Similarity(a, b)
	if sim > 0.5 {
		t.Fatalf("disjoint vector similarity = %.3f, want <0.5", sim)
	}
}

func TestClassificationThresholds(t *testing.T) {
	th := DefaultThresholds()
	if th.Classify(0.9) != ClassMatch {
		t.Fatal("0.9 should be MATCH")
	}
	if th.Classify(0.7) != ClassRelated {
		t.Fatal("0.7 should be RELATED")
	}
	if th.Classify(0.1) != ClassNovel {
		t.Fatal("0.1 should be NOVEL")
	}
}

func TestMissingFeaturesRenomalize(t *testing.T) {
	// No shared comparable features at all → 0 (not false positive).
	a := Features{NetworkASN: "AS1"}
	b := Features{RegionClass: "earth"}
	sim := Similarity(a, b)
	if sim != 0 {
		t.Fatalf("disjoint feature spaces sim = %.3f, want 0", sim)
	}
	// Same single feature present → 1.0 (renormalized over present features).
	a2 := Features{NetworkASN: "AS1"}
	b2 := Features{NetworkASN: "AS1"}
	if sim := Similarity(a2, b2); sim < 0.99 {
		t.Fatalf("single shared feature sim = %.3f, want 1.0", sim)
	}
}

func TestStoreBorrowOrCreateAndExplosion(t *testing.T) {
	store := NewStore(func() Limits {
		return Limits{MaxActiveLanesPerCredential: 2, MaxProvisionalLanes: 2, LaneIdleExpiration: time.Hour}
	}, time.Now)
	th := DefaultThresholds()

	// two distinct lanes
	l1, created, err := store.BorrowOrCreate("cred_1", "lane_a", Features{NetworkASN: "AS1", RegionClass: "us"}, th)
	if err != nil || !created || l1.LaneID != "lane_a" {
		t.Fatalf("create lane_a: created=%v err=%v", created, err)
	}
	l2, created, err := store.BorrowOrCreate("cred_1", "lane_b", Features{NetworkASN: "AS2", RegionClass: "eu"}, th)
	if err != nil || !created || l2.LaneID != "lane_b" {
		t.Fatalf("create lane_b: created=%v err=%v", created, err)
	}
	// third distinct lane over limit → ErrTooManyLanes
	_, created, err = store.BorrowOrCreate("cred_1", "lane_c", Features{NetworkASN: "AS3", RegionClass: "ap"}, th)
	if err != ErrTooManyLanes {
		t.Fatalf("explosion limit: got err=%v want ErrTooManyLanes", err)
	}

	// a matching re-request borrows lane_a (same ASN+region)
	reuse, created, err := store.BorrowOrCreate("cred_1", "lane_x", Features{NetworkASN: "AS1", RegionClass: "us"}, th)
	if err != nil {
		t.Fatalf("reuse err: %v", err)
	}
	if created {
		t.Fatal("matching request should borrow existing lane, not create")
	}
	if reuse.LaneID != "lane_a" {
		t.Fatalf("borrow returned %s, want lane_a", reuse.LaneID)
	}
}

func TestIdleEviction(t *testing.T) {
	base := time.Now()
	clock := base
	store := NewStore(func() Limits {
		return Limits{MaxActiveLanesPerCredential: 4, MaxProvisionalLanes: 4, LaneIdleExpiration: 10 * time.Minute}
	}, func() time.Time { return clock })
	store.BorrowOrCreate("cred_9", "lane_1", Features{NetworkASN: "AS9"}, DefaultThresholds())
	if store.ActiveLaneCount("cred_9") != 1 {
		t.Fatal("one lane expected")
	}
	// advance past idle and add another lane, triggering eviction
	clock = base.Add(11 * time.Minute)
	store.BorrowOrCreate("cred_9", "lane_2", Features{NetworkASN: "AS8"}, DefaultThresholds())
	if store.ActiveLaneCount("cred_9") != 1 {
		t.Fatalf("idle lane should be evicted, count=%d", store.ActiveLaneCount("cred_9"))
	}
}

func TestPromotionGate(t *testing.T) {
	now := time.Now()
	crit := DefaultPromotionCriteria()
	// New lane must not promote unless seeding allowed.
	rec := &LaneRecord{LaneID: "l", CredentialID: "c", State: StateNew, FirstSeenAt: now.Add(-10 * 24 * time.Hour), RequestCount: 500, RiskScore: 5}
	if _, promoted := PromoteIfEligible(rec, crit, now); promoted {
		t.Fatal("new lane must not auto-promote without AllowNewLanes")
	}
	// With seeding allowed it advances to probation first, then established.
	crit2 := crit
	crit2.AllowNewLanes = true
	state, promoted := PromoteIfEligible(rec, crit2, now)
	if promoted || state != StateProbation {
		t.Fatalf("new→probation expected, got state=%v promoted=%v", state, promoted)
	}
	state, promoted = PromoteIfEligible(rec, crit2, now)
	if !promoted || state != StateEstablished {
		t.Fatalf("probation→established expected, got state=%v promoted=%v", state, promoted)
	}
	// A suspicious lane never promotes (INV-8).
	susp := &LaneRecord{LaneID: "s", State: StateSuspicious, FirstSeenAt: now.Add(-30 * 24 * time.Hour), RequestCount: 9999, RiskScore: 0}
	if _, promoted := PromoteIfEligible(susp, crit2, now); promoted {
		t.Fatal("suspicious lane must never promote")
	}
}

// Regression (§24): a lane id collision must never overwrite the existing row.
// Overwriting would reset a BLOCKED/SUSPICIOUS lane to NEW — laundering its
// history and evading the explosion limit. The store fails closed with
// ErrLaneConflict instead.
func TestLaneIdCollisionDoesNotResetState(t *testing.T) {
	store := NewStore(func() Limits {
		return Limits{MaxActiveLanesPerCredential: 4, MaxProvisionalLanes: 4, LaneIdleExpiration: time.Hour}
	}, time.Now)
	th := DefaultThresholds()

	if _, _, err := store.BorrowOrCreate("cred_1", "lane_a", Features{NetworkASN: "AS1", RegionClass: "us"}, th); err != nil {
		t.Fatalf("create lane_a: %v", err)
	}
	// Same id, dissimilar features (no Match) → must conflict, not overwrite.
	_, created, err := store.BorrowOrCreate("cred_1", "lane_a", Features{NetworkASN: "AS999", RegionClass: "eu"}, th)
	if err == nil {
		t.Fatal("id collision with dissimilar features must error")
	}
	if created {
		t.Fatal("collision must not report created")
	}
	// The original record must be intact.
	rec, ok := store.Get("cred_1", "lane_a")
	if !ok {
		t.Fatal("original lane must survive the collision attempt")
	}
	if rec.NetworkClass != "AS1" || rec.RegionClass != "us" || rec.RequestCount != 1 {
		t.Fatalf("original lane was mutated: %+v", rec)
	}
}
