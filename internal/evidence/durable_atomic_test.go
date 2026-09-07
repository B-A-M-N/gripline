package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDurableStoreBatchCompactionAtCap verifies that a multi-item batch is
// merged and compacted as one subject-level operation.
func TestDurableStoreBatchCompactionAtCap(t *testing.T) {
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

	// A batch with 3 items where only 1 can fit is compacted atomically: all
	// three new items survive and the oldest evictable rows leave the cap.
	batch := []Evidence{
		{EvidenceID: "ev_batch_1", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
		{EvidenceID: "ev_batch_2", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
		{EvidenceID: "ev_batch_3", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
	}

	err = store.Append(batch...)
	if err != nil {
		t.Fatalf("batch append: %v", err)
	}

	// Verify the subject is exactly at the cap and the batch was not partially
	// rejected.
	snap, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: subjectID}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != maxEvidencePerSubject {
		t.Fatalf("expected %d items, got %d", maxEvidencePerSubject, len(snap))
	}
	for _, id := range []string{"ev_batch_1", "ev_batch_2", "ev_batch_3"} {
		found := false
		for _, ev := range snap {
			if ev.EvidenceID == id {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("batch evidence %q was not retained", id)
		}
	}
}

// TestDurableStoreBatchCompactionAtCapTwoItems targets the exact overflow
// shape: a subject one below the cap receives a two-item batch. Both new rows
// must be retained while the oldest evictable row is compacted.
func TestDurableStoreBatchCompactionAtCapTwoItems(t *testing.T) {
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

	// Both share the subject, so the batch is merged before compaction.
	err = store.Append(
		Evidence{EvidenceID: "ev_fit_1", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
		Evidence{EvidenceID: "ev_overflow_2", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1},
	)
	if err != nil {
		t.Fatalf("batch append: %v", err)
	}

	// Both batch items survive and the subject remains at the cap.
	snap, err := store.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: subjectID}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != maxEvidencePerSubject {
		t.Fatalf("expected %d items, got %d", maxEvidencePerSubject, len(snap))
	}
	for _, id := range []string{"ev_fit_1", "ev_overflow_2"} {
		found := false
		for _, ev := range snap {
			if ev.EvidenceID == id {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("batch evidence %q was not retained", id)
		}
	}

	// A subsequent item is also accepted and compacted at the same cap.
	if err := store.Append(Evidence{EvidenceID: "ev_legit_after", Code: "NEW_LANE", Family: FamilyClientNovelty, Scope: ScopeLane, SubjectID: subjectID, Score: 10, Confidence: 60, CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1}); err != nil {
		t.Fatalf("expected subsequent append to fit, got %v", err)
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
