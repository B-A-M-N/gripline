package evidence

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryStore_AppendAndSnapshot(t *testing.T) {
	now := time.Now()
	store := NewMemoryStore()

	ev := Evidence{
		EvidenceID:     "ev_1",
		Code:           "NEW_LANE",
		Family:         FamilyClientNovelty,
		Scope:          ScopeLane,
		SubjectID:      "lane_1",
		Score:          5,
		Severity:       1,
		Confidence:     40,
		CreatedAt:      now,
		ExpiresAt:      now.Add(7 * 24 * time.Hour),
		PolicyRevision: 1,
	}

	if err := store.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}

	snap, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_1"}}, now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(snap))
	}
	if snap[0].EvidenceID != "ev_1" {
		t.Fatalf("wrong evidence ID: %s", snap[0].EvidenceID)
	}
	// Snapshot returns a copy.
	snap[0].Score = 99
	snap2, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_1"}}, now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap2[0].Score != 5 {
		t.Fatal("Snapshot must return copies, not internal references")
	}
}

func TestMemoryStore_SubjectsDontMix(t *testing.T) {
	now := time.Now()
	store := NewMemoryStore()

	// Lane evidence.
	laneEv := Evidence{
		EvidenceID: "ev_lane", Code: "NEW_LANE", Family: FamilyClientNovelty,
		Scope: ScopeLane, SubjectID: "lane_1", Score: 5, Confidence: 40,
		CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour),
	}
	// Credential evidence.
	credEv := Evidence{
		EvidenceID: "ev_cred", Code: "NEW_ASN", Family: FamilySourceDiscontinuity,
		Scope: ScopeCredential, SubjectID: "cred_1", Score: 10, Confidence: 60,
		CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour),
	}

	if err := store.Append(laneEv, credEv); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Lane snapshot must not contain credential evidence.
	laneSnap, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_1"}}, now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	for i := range laneSnap {
		if laneSnap[i].Scope == ScopeCredential {
			t.Fatal("lane snapshot must not contain credential evidence")
		}
	}

	// Credential snapshot must not contain lane evidence.
	credSnap, err := store.Snapshot([]SubjectKey{{Scope: ScopeCredential, ID: "cred_1"}}, now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	for i := range credSnap {
		if credSnap[i].Scope == ScopeLane {
			t.Fatal("credential snapshot must not contain lane evidence")
		}
	}

	if len(laneSnap) != 1 || len(credSnap) != 1 {
		t.Fatalf("expected 1 each, got lane=%d cred=%d", len(laneSnap), len(credSnap))
	}
}

func TestMemoryStore_ExpiredEvidenceNeverInSnapshot(t *testing.T) {
	store := NewMemoryStore()

	now := time.Now()
	ev := Evidence{
		EvidenceID: "ev_expired", Code: "NEW_ASN", Family: FamilySourceDiscontinuity,
		Scope: ScopeLane, SubjectID: "lane_1", Score: 10, Confidence: 60,
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}

	if err := store.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Expired evidence must never appear in snapshot even without Prune.
	snap, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_1"}}, now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) != 0 {
		t.Fatalf("expired evidence must never appear in Snapshot, got %d items", len(snap))
	}

	// Prune should count it.
	pruned, err := store.Prune([]SubjectKey{{Scope: ScopeLane, ID: "lane_1"}}, now)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("expected 1 pruned, got %d", pruned)
	}
}

func TestMemoryStore_PruningDoesNotAffectCorrectness(t *testing.T) {
	store := NewMemoryStore()

	now := time.Now()
	ev := Evidence{
		EvidenceID: "ev_1", Code: "NEW_ASN", Family: FamilySourceDiscontinuity,
		Scope: ScopeLane, SubjectID: "lane_1", Score: 10, Confidence: 60,
		CreatedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour),
	}
	if err := store.Append(ev); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Prune everything — even non-expired subjects.
	store.Prune([]SubjectKey{{Scope: ScopeLane, ID: "lane_1"}}, now)

	// Snapshot must still return valid evidence.
	snap, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_1"}}, now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) != 1 {
		t.Fatalf("pruning is optimization only; valid evidence must still appear, got %d", len(snap))
	}
}

func TestMemoryStore_EvidenceBoundedPerSubject(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now()

	// Insert more than maxEvidencePerSubject.
	for i := 0; i < maxEvidencePerSubject+10; i++ {
		ev := Evidence{
			EvidenceID:     fmt.Sprintf("ev_%d", i),
			Code:           "NEW_ASN",
			Family:         FamilySourceDiscontinuity,
			Scope:          ScopeLane,
			SubjectID:      "lane_x",
			Score:          10,
			Confidence:     60,
			CreatedAt:      now.Add(time.Duration(i) * time.Second),
			ExpiresAt:      now.Add(7*24*time.Hour + time.Duration(i)*time.Second),
			PolicyRevision: 1,
		}
		if err := store.Append(ev); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	snap, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_x"}}, now)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) > maxEvidencePerSubject {
		t.Fatalf("evidence must be bounded per subject, got %d (max %d)", len(snap), maxEvidencePerSubject)
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now()
	var wg sync.WaitGroup

	// 10 goroutines each appending 100 evidence items for different subjects.
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				ev := Evidence{
					EvidenceID:     fmt.Sprintf("ev_g%d_%d", gid, i),
					Code:           "NEW_ASN",
					Family:         FamilySourceDiscontinuity,
					Scope:          ScopeLane,
					SubjectID:      fmt.Sprintf("lane_g%d_i%d", gid, i),
					Score:          10,
					Confidence:     60,
					CreatedAt:      now,
					ExpiresAt:      now.Add(time.Hour),
					PolicyRevision: 1,
				}
				if err := store.Append(ev); err != nil {
					t.Errorf("Append: %v", err)
				}
			}
		}(g)
	}

	// 10 goroutines reading snapshots concurrently.
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: fmt.Sprintf("lane_g%d_i%d", gid, i)}}, now)
				// ignore error — concurrent reads may see transient state
			}
		}(g)
	}

	wg.Wait()
}

// --- P0.14: expiry is inclusive-invalid exactly AT ExpiresAt ----------------

func TestExpiryIsInclusiveInvalidAtBoundary(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Minute)
	ev := Evidence{
		EvidenceID: "ev_boundary", Code: "NEW_ASN", Family: FamilySourceDiscontinuity,
		Scope: ScopeLane, SubjectID: "lane_b", Score: 10, Confidence: 60,
		CreatedAt: now, ExpiresAt: exp,
	}
	// Valid before ExpiresAt.
	if !ev.Valid(exp.Add(-time.Second)) {
		t.Fatal("P0.14: evidence must be valid strictly before ExpiresAt")
	}
	// Invalid exactly AT ExpiresAt (inclusive-invalid, P0.14).
	if ev.Valid(exp) {
		t.Fatal("P0.14: evidence must be invalid exactly AT ExpiresAt")
	}
	// Invalid after ExpiresAt.
	if ev.Valid(exp.Add(time.Second)) {
		t.Fatal("P0.14: evidence must be invalid after ExpiresAt")
	}

	// The store must not include it at the exact boundary either.
	store := NewMemoryStore()
	if err := store.Append(ev); err != nil {
		t.Fatal(err)
	}
	snap, _ := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_b"}}, exp)
	if len(snap) != 0 {
		t.Fatalf("P0.14: store snapshot at exact ExpiresAt must be empty, got %d", len(snap))
	}
}

// --- P0.13: EvidenceID dedup — same id cannot contribute twice --------------

func TestAppendDedupsEvidenceID(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now()
	ev := Evidence{
		EvidenceID: "ev_dedup", Code: "NEW_ASN", Family: FamilySourceDiscontinuity,
		Scope: ScopeLane, SubjectID: "lane_d", Score: 10, Confidence: 60,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.Append(ev); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ev); err != nil {
		t.Fatal(err)
	}
	snap, _ := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_d"}}, now)
	if len(snap) != 1 {
		t.Fatalf("P0.13: duplicate EvidenceID must store once, got %d", len(snap))
	}
}

// --- P0.13: batch append is all-or-nothing -----------------------------------

func TestAppendAtomicBatchRejectsPartial(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now()
	good := Evidence{
		EvidenceID: "ev_a_good", Code: "NEW_ASN", Family: FamilySourceDiscontinuity,
		Scope: ScopeLane, SubjectID: "lane_atomic", Score: 10, Confidence: 60,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	bad := Evidence{
		EvidenceID: "ev_a_bad", Code: "NEW_ASN", Family: FamilySourceDiscontinuity,
		Scope: ScopeLane, SubjectID: "lane_atomic", Score: 101, Confidence: 60,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	err := store.Append(good, bad)
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("want ErrInvalidEvidence, got %v", err)
	}
	snap, _ := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_atomic"}}, now)
	if len(snap) != 0 {
		t.Fatalf("P0.13: atomic batch — good item must not persist when any item is invalid, got %d", len(snap))
	}
}
