package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDurableStoreBatchAtomicityAtCap (P0.9A) verifies that when a batch
// would exceed the per-subject cap, the entire batch is rejected and no
// state is modified.
func TestDurableStoreBatchAtomicityAtCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.gob")

	cfg := DurableConfig{Path: path, FlushInterval: time.Hour}
	store, closeFn, err := NewDurableStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFn() }()

	now := time.Now()

	// Fill a subject to just below the cap.
	subjectID := "lane_atomic"
	for i := 0; i < maxEvidencePerSubject-1; i++ {
		err := store.Append(Evidence{
			EvidenceID:     "ev_base_" + string(rune(i)),
			Code:           "NEW_LANE",
			Family:         FamilyClientNovelty,
			Scope:          ScopeLane,
			SubjectID:      subjectID,
			Score:          10,
			Confidence:     60,
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
			PolicyRevision: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// A batch with 3 items where only 1 can fit should fail atomically.
	batch := []Evidence{
		{EvidenceID: "ev_batch_1", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
		{EvidenceID: "ev_batch_2", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
		{EvidenceID: "ev_batch_3", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
	}

	err = store.Append(batch...)
	if err == nil {
		t.Fatal("expected error for batch exceeding cap")
	}

	// Verify the subject still has exactly maxEvidencePerSubject-1 items
	// (none of the batch were stored).
	snap, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: subjectID}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != maxEvidencePerSubject-1 {
		t.Fatalf("expected %d items, got %d (batch was not atomic)", maxEvidencePerSubject-1, len(snap))
	}
}

// TestDurableStoreBatchAtomicityAtCapTwoItems targets the exact overflow shape:
// a subject one below the cap receiving a 2-item batch where item 1 fits and
// item 2 would overflow. The ENTIRE batch must be rejected with NO partial
// items stored (all-or-nothing), so the subject count must stay pinned below the
// cap and the following legitimate single item must still be accepted.
func TestDurableStoreBatchAtomicityAtCapTwoItems(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.gob")

	cfg := DurableConfig{Path: path, FlushInterval: time.Hour}
	store, closeFn, err := NewDurableStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFn() }()

	now := time.Now()
	subjectID := "lane_atomic_two"

	// Fill the subject to maxEvidencePerSubject-1 (one slot free).
	for i := 0; i < maxEvidencePerSubject-1; i++ {
		err := store.Append(Evidence{
			EvidenceID:     "ev_base_" + string(rune(i)),
			Code:           "NEW_LANE",
			Family:         FamilyClientNovelty,
			Scope:          ScopeLane,
			SubjectID:      subjectID,
			Score:          10,
			Confidence:     60,
			CreatedAt:      now,
			ExpiresAt:      now.Add(time.Hour),
			PolicyRevision: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Batch of 2: item 1 fits (slot to 2048), item 2 overflows. Both share the
	// subject, so the whole batch must be refused before anything is stored.
	over := store.Append(
		Evidence{EvidenceID: "ev_fit_1", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
		Evidence{EvidenceID: "ev_overflow_2", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
	)
	if over == nil {
		t.Fatal("expected error for 2-item batch whose second item overflows the cap")
	}

	// Nothing from the rejected batch may have been stored: count stays at
	// maxEvidencePerSubject-1.
	snap, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: subjectID}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != maxEvidencePerSubject-1 {
		t.Fatalf("after rejected batch expected %d items, got %d (partial items stored)", maxEvidencePerSubject-1, len(snap))
	}

	// A subsequent legitimate single item (the one slot that IS free) must be
	// accepted, proving the rejection did not wedge or corrupt the subject.
	ok := store.Append(Evidence{EvidenceID: "ev_legit_after", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1})
	if ok != nil {
		t.Fatalf("expected single item to fit after batch rejection, got %v", ok)
	}
	snap2, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: subjectID}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap2) != maxEvidencePerSubject {
		t.Fatalf("expected %d items after fitting append, got %d", maxEvidencePerSubject, len(snap2))
	}
}

// TestDurableStoreSurfacesStatError verifies that NewDurableStore does NOT
// silently treat a non-ErrNotExist stat failure as "no file exists". Pointing
// the store at a path whose parent is a regular file forces Stat (or the MkdirAll
// that precedes it) to fail with ENOTDIR, which is not os.ErrNotExist — the
// constructor must surface an error rather than hand back an (empty) running
// store as if the file were merely absent.
func TestDurableStoreSurfacesStatError(t *testing.T) {
	dir := t.TempDir()

	parentFile := filepath.Join(dir, "not_a_dir")
	if err := os.WriteFile(parentFile, []byte("i am a file, not a directory"), 0o640); err != nil {
		t.Fatal(err)
	}

	// dir/not_a_dir/evidence.gob — the immediate parent is a file, so Stat on
	// the child yields ENOTDIR, not ErrNotExist.
	path := filepath.Join(parentFile, "evidence.gob")

	store, closeFn, err := NewDurableStore(DurableConfig{Path: path})
	if err == nil {
		if closeFn != nil {
			_ = closeFn()
		}
		t.Fatal("expected NewDurableStore to surface a non-ErrNotExist path error, but it returned a usable store")
	}
	if store != nil {
		t.Fatal("NewDurableStore returned a non-nil store alongside its error")
	}
}
