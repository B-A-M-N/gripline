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

	// two distinct lanes (full trusted source identity so three can coexist)
	l1, created, err := store.BorrowOrCreate("cred_1", "lane_a", Features{NetworkASN: "AS1", NetworkType: "residential", RegionClass: "us"}, ClassificationContext{Thresholds: th})
	if err != nil || !created || l1.LaneID != "lane_a" {
		t.Fatalf("create lane_a: created=%v err=%v", created, err)
	}
	l2, created, err := store.BorrowOrCreate("cred_1", "lane_b", Features{NetworkASN: "AS2", NetworkType: "hosting", RegionClass: "eu"}, ClassificationContext{Thresholds: th})
	if err != nil || !created || l2.LaneID != "lane_b" {
		t.Fatalf("create lane_b: created=%v err=%v", created, err)
	}
	// third distinct lane over limit → ErrTooManyLanes
	_, _, err = store.BorrowOrCreate("cred_1", "lane_c", Features{NetworkASN: "AS3", NetworkType: "hosting", RegionClass: "ap"}, ClassificationContext{Thresholds: th})
	if err != ErrTooManyLanes {
		t.Fatalf("explosion limit: got err=%v want ErrTooManyLanes", err)
	}

	// a matching re-request borrows lane_a (same ASN+type+region)
	reuse, created, err := store.BorrowOrCreate("cred_1", "lane_x", Features{NetworkASN: "AS1", NetworkType: "residential", RegionClass: "us"}, ClassificationContext{Thresholds: th})
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
	store.BorrowOrCreate("cred_9", "lane_1", Features{NetworkASN: "AS9"}, ClassificationContext{Thresholds: DefaultThresholds()})
	if store.ActiveLaneCount("cred_9") != 1 {
		t.Fatal("one lane expected")
	}
	// advance past idle and add another lane, triggering eviction
	clock = base.Add(11 * time.Minute)
	store.BorrowOrCreate("cred_9", "lane_2", Features{NetworkASN: "AS8"}, ClassificationContext{Thresholds: DefaultThresholds()})
	if store.ActiveLaneCount("cred_9") != 1 {
		t.Fatalf("idle lane should be evicted, count=%d", store.ActiveLaneCount("cred_9"))
	}
}

func TestPromotionGate(t *testing.T) {
	now := time.Now()
	crit := DefaultPromotionCriteria()
	// New lane must not promote unless seeding allowed.
	rec := &LaneRecord{
		LaneID: "l", CredentialID: "c", State: StateNew,
		FirstSeenAt:  now.Add(-10 * 24 * time.Hour),
		RequestCount: 500, RiskScore: 5,
		AuthorizedCleanRequests: 500, // Meets MinCleanRequests
		ActiveDays:              5,
		CleanActiveDays:         5, // Meets MinCleanActiveDays
		LastActiveDay:           now.Format("2006-01-02"),
	}
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

	if _, _, err := store.BorrowOrCreate("cred_1", "lane_a", Features{NetworkASN: "AS1", RegionClass: "us"}, ClassificationContext{Thresholds: th}); err != nil {
		t.Fatalf("create lane_a: %v", err)
	}
	// Same id, dissimilar features (no Match) → must conflict, not overwrite.
	_, created, err := store.BorrowOrCreate("cred_1", "lane_a", Features{NetworkASN: "AS999", RegionClass: "eu"}, ClassificationContext{Thresholds: th})
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
	if rec.Features.NetworkASN != "AS1" || rec.Features.RegionClass != "us" || rec.RequestCount != 1 {
		t.Fatalf("original lane was mutated: %+v", rec)
	}
}

// --- P0.8/P0.9 regressions ---------------------------------------------------

// Regression (P0.8): the FULL classification vector must distinguish lanes.
// Previously only ASN/region/client were persisted, so two manifestations
// differing in SDK/model/streaming collapsed into one lane when their three
// stored fields matched — a single shared feature could score a false 1.0.
func TestFullFeatureVectorDistinguishesLanes(t *testing.T) {
	store := NewStore(func() Limits {
		return Limits{MaxActiveLanesPerCredential: 8, MaxProvisionalLanes: 8, LaneIdleExpiration: time.Hour}
	}, time.Now)
	th := DefaultThresholds()

	a := Features{NetworkASN: "AS1", RegionClass: "us", ClientFamily: "claude-code",
		SDKFamily: "ts", ModelFamily: "opus", Streaming: "streaming"}
	b := Features{NetworkASN: "AS1", RegionClass: "us", ClientFamily: "claude-code",
		SDKFamily: "python", ModelFamily: "haiku", Streaming: "non-streaming"}

	la, ca, err := store.BorrowOrCreate("cred_1", "lane_a", a, ClassificationContext{Thresholds: th})
	if err != nil || !ca {
		t.Fatalf("create a: %v", err)
	}
	lb, cb, err := store.BorrowOrCreate("cred_1", "lane_b", b, ClassificationContext{Thresholds: th})
	if err != nil {
		t.Fatalf("create b: %v", err)
	}
	if !cb {
		t.Fatalf("differing full vectors must NOT collapse into lane %s (P0.8)", la.LaneID)
	}
	if lb.LaneID == la.LaneID {
		t.Fatal("distinct vectors must produce distinct lanes")
	}
	// And the persisted record retains the whole vector.
	rec, _ := store.Get("cred_1", "lane_b")
	if rec.Features.SDKFamily != "python" || rec.Features.ModelFamily != "haiku" || rec.Features.Streaming != "non-streaming" {
		t.Fatalf("full vector not persisted: %+v", rec.Features)
	}
	if rec.FeatSchema != featSchemaVersion {
		t.Fatalf("feat schema = %d, want %d", rec.FeatSchema, featSchemaVersion)
	}
}

// Regression (P0.9): lane selection must be deterministic under similarity
// ties. The store previously iterated a Go map (randomized order) with strict
// `>`, so which lane won a tie depended on hash order. Now: highest similarity,
// then lexicographically smallest lane id — stable across store instances.
//
// Note: P0.9's comparable-weight floor means a SPARSE query no longer matches an
// established lane (that was the laundering strategy). Determinism is therefore
// exercised with a full, legitimate query that provably borrows an established
// lane, and the sparse-query case is asserted to create a NEW lane instead.
func TestLaneSelectionDeterministicUnderTies(t *testing.T) {
	th := DefaultThresholds()
	// Full trusted source identity — a legitimate honest client.
	full := Features{NetworkASN: "AS1", RegionClass: "mid", ClientFamily: "cc", NetworkType: "residential"}

	// A sparse query (source identity WITHOUT a trusted field) must NOT borrow a
	// full lane: it creates a new lane instead (P0.9 anti-laundering).
	{
		s := NewStore(func() Limits {
			return Limits{MaxActiveLanesPerCredential: 8, MaxProvisionalLanes: 8, LaneIdleExpiration: time.Hour}
		}, time.Now)
		if _, created, err := s.BorrowOrCreate("cred_1", "lane_full", full, ClassificationContext{Thresholds: th}); err != nil || !created {
			t.Fatalf("seed full: created=%v err=%v", created, err)
		}
		sparse := Features{NetworkASN: "AS1", ClientFamily: "cc"} // omits NetworkType+Region
		if _, created, err := s.BorrowOrCreate("cred_1", "lane_sparse", sparse, ClassificationContext{Thresholds: th}); err != nil {
			t.Fatal(err)
		} else if !created {
			t.Fatal("P0.9: sparse query must create a NEW lane, not borrow the established full lane")
		}
	}

	// Determinism: a full query that legitimately matches the established lane
	// must borrow the SAME lane on every store instance (Go map order must not
	// decide selection).
	want := ""
	for i := 0; i < 200; i++ {
		s := NewStore(func() Limits {
			return Limits{MaxActiveLanesPerCredential: 8, MaxProvisionalLanes: 8, LaneIdleExpiration: time.Hour}
		}, time.Now)
		if _, created, err := s.BorrowOrCreate("cred_1", "lane_alpha", full, ClassificationContext{Thresholds: th}); err != nil || !created {
			t.Fatalf("seed: created=%v err=%v", created, err)
		}
		rec, created, err := s.BorrowOrCreate("cred_1", "lane_query", full, ClassificationContext{Thresholds: th})
		if err != nil {
			t.Fatal(err)
		}
		if created {
			t.Fatalf("iteration %d: full query must borrow, not create", i)
		}
		if want == "" {
			want = rec.LaneID
		} else if rec.LaneID != want {
			t.Fatalf("iteration %d: nondeterministic selection %s, want %s", i, rec.LaneID, want)
		}
		if rec.LaneID != "lane_alpha" {
			t.Fatalf("borrow must deterministically return lane_alpha, got %s", rec.LaneID)
		}
	}
}

// Regression (P0.9 follow-up): expired lanes are evicted BEFORE the explosion
// limit is evaluated, so a lane whose idle expiration has passed cannot wedge
// creation of the request that would have evicted it.
func TestExpiredLanesEvictedBeforeLimitRejection(t *testing.T) {
	base := time.Now()
	clock := base
	store := NewStore(func() Limits {
		return Limits{MaxActiveLanesPerCredential: 2, MaxProvisionalLanes: 2, LaneIdleExpiration: 10 * time.Minute}
	}, func() time.Time { return clock })
	th := DefaultThresholds()

	for _, id := range []string{"lane_1", "lane_2"} {
		if _, _, err := store.BorrowOrCreate("cred_1", id, Features{NetworkASN: id}, ClassificationContext{Thresholds: th}); err != nil {
			t.Fatal(err)
		}
	}
	// At the limit — a third lane must be rejected NOW.
	if _, _, err := store.BorrowOrCreate("cred_1", "lane_3", Features{NetworkASN: "AS3"}, ClassificationContext{Thresholds: th}); err != ErrTooManyLanes {
		t.Fatalf("at-limit create must fail: %v", err)
	}
	// Advance past idle expiration: the same create must now SUCCEED because
	// eviction runs before the limit check.
	clock = base.Add(11 * time.Minute)
	rec, created, err := store.BorrowOrCreate("cred_1", "lane_3", Features{NetworkASN: "AS3"}, ClassificationContext{Thresholds: th})
	if err != nil || !created {
		t.Fatalf("expired lanes must free capacity before limit check: created=%v err=%v", created, err)
	}
	if store.ActiveLaneCount("cred_1") != 1 {
		t.Fatalf("count = %d, want 1", store.ActiveLaneCount("cred_1"))
	}
	_ = rec
}

// Regression: MaxProvisionalLanes must actually bound NEW+PROBATION lanes.
func TestMaxProvisionalLanesEnforced(t *testing.T) {
	store := NewStore(func() Limits {
		return Limits{MaxActiveLanesPerCredential: 10, MaxProvisionalLanes: 2, LaneIdleExpiration: time.Hour}
	}, time.Now)
	th := DefaultThresholds()
	for i, id := range []string{"p1", "p2"} {
		if _, _, err := store.BorrowOrCreate("cred_1", id, Features{NetworkASN: id}, ClassificationContext{Thresholds: th}); err != nil {
			t.Fatalf("provisional %d: %v", i, err)
		}
	}
	if _, _, err := store.BorrowOrCreate("cred_1", "p3", Features{NetworkASN: "p3"}, ClassificationContext{Thresholds: th}); err != ErrTooManyLanes {
		t.Fatalf("third provisional lane must be refused, got %v", err)
	}
}

// Regression: ActiveDays must count DISTINCT active days (§29
// clean-active-days), not requests.
func TestActiveDaysCountDistinctDays(t *testing.T) {
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := base
	store := NewStore(func() Limits {
		return Limits{MaxActiveLanesPerCredential: 4, MaxProvisionalLanes: 4, LaneIdleExpiration: 48 * time.Hour}
	}, func() time.Time { return clock })
	th := DefaultThresholds()
	// A real client presents the full source identity, so a re-request matches
	// the established lane (comparable weight well above the P0.9 floor).
	feat := Features{NetworkASN: "AS1", NetworkType: "residential", RegionClass: "us", ClientFamily: "claude-code"}

	rec, _, err := store.BorrowOrCreate("cred_1", "lane_d", feat, ClassificationContext{Thresholds: th})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ActiveDays != 1 {
		t.Fatalf("first day ActiveDays = %d, want 1", rec.ActiveDays)
	}
	// Same day: no change. The re-request must BORROW lane_d (identical
	// features) and not advance ActiveDays.
	clock = base.Add(2 * time.Hour)
	rec, created, err := store.BorrowOrCreate("cred_1", "lane_d", feat, ClassificationContext{Thresholds: th})
	if err != nil || created {
		t.Fatalf("same-day borrow: created=%v err=%v", created, err)
	}
	if rec.LaneID != "lane_d" {
		t.Fatalf("same-day request must borrow lane_d, got %s", rec.LaneID)
	}
	if rec.ActiveDays != 1 {
		t.Fatalf("same-day ActiveDays = %d, want 1", rec.ActiveDays)
	}
	// Next day: +1 (borrow again, a day later).
	clock = base.Add(26 * time.Hour)
	rec, created, err = store.BorrowOrCreate("cred_1", "lane_d", feat, ClassificationContext{Thresholds: th})
	if err != nil || created {
		t.Fatalf("next-day borrow: created=%v err=%v", created, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if rec.ActiveDays != 2 {
		t.Fatalf("next-day ActiveDays = %d, want 2", rec.ActiveDays)
	}
}

// TestSparseCandidateCannotLaunderIntoEstablishedLane proves P0.9: a candidate
// that omits the trusted source dimensions must NOT renormalize its few shared
// fields to a perfect 1.0 and collapse into an established lane. The
// MinComparableWeight floor blocks the laundering strategy that a generic
// "shared ASN + region + client all match → similarity 1.0" formula permits.
func TestSparseCandidateCannotLaunderIntoEstablishedLane(t *testing.T) {
	clock := time.Now()
	store := NewStore(func() Limits {
		return Limits{MaxActiveLanesPerCredential: 8, MaxProvisionalLanes: 8, LaneIdleExpiration: 48 * time.Hour}
	}, func() time.Time { return clock })
	th := DefaultThresholds()

	// Establish a rich lane with the full trusted source identity.
	rich := Features{NetworkASN: "AS77", NetworkType: "residential", RegionClass: "us",
		ClientFamily: "claude-code", SDKFamily: "go", HTTPVersion: "1.1", Streaming: "non-streaming"}
	rec, created, err := store.BorrowOrCreate("cred_1", "lane_rich", rich, ClassificationContext{Thresholds: th})
	if err != nil || !created {
		t.Fatalf("establish rich lane: created=%v err=%v", created, err)
	}
	// Rich identity matches itself (re-borrow): comparable weight is high.
	if _, created, err := store.BorrowOrCreate("cred_1", "lane_rich", rich, ClassificationContext{Thresholds: th}); err != nil || created {
		t.Fatalf("re-borrow full identity: created=%v err=%v (want borrow, not new)", created, err)
	}

	// A SPARSE candidate omitting the trusted source dimensions (only ASN +
	// client) renormalizes those shared fields to a perfect 1.0 similarity — but
	// its comparable mass (ASN .35 + client .10 = .45) is below the floor, so it
	// must NOT match the established lane (it must be treated as a new lane).
	sparse := Features{NetworkASN: "AS77", ClientFamily: "claude-code"}
	if w := ComparableWeight(sparse, rich); w >= th.MinComparableWeight {
		t.Fatalf("sparse comparable weight %v >= floor %v — laundering not blocked", w, th.MinComparableWeight)
	}
	if s := Similarity(sparse, rich); s < th.Match {
		t.Fatalf("sparse renormalized similarity %v < Match=%v — test is not exercising the collapse", s, th.Match)
	}
	rec2, created2, err := store.BorrowOrCreate("cred_1", "lane_sparse", sparse, ClassificationContext{Thresholds: th})
	if err != nil {
		t.Fatalf("sparse borrow err=%v", err)
	}
	if created2 {
		if rec2.LaneID == rec.LaneID {
			t.Fatal("P0.9: sparse candidate accidentally borrowed the established lane")
		}
		t.Logf("sparse candidate correctly treated as a NEW lane (ID %s), not the established %s", rec2.LaneID, rec.LaneID)
	} else if rec2.LaneID == "lane_rich" {
		t.Fatal("P0.9 FAIL: sparse candidate collapsed into the established lane via renormalization")
	}
}
