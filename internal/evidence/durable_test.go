package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDurableStorePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.gob")

	cfg := DurableConfig{Path: path, FlushInterval: 100 * time.Millisecond}
	store, close1, err := NewDurableStore(cfg)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	ev := Evidence{
		EvidenceID: "ev_1", Code: "NEW_ASN", Family: FamilySourceDiscontinuity,
		Scope: ScopeLane, SubjectID: "lane_1", Score: 10, Confidence: 60,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1,
	}
	if err := store.Append(ev); err != nil {
		t.Fatal(err)
	}

	// Wait for flush.
	time.Sleep(200 * time.Millisecond)
	if err := close1(); err != nil {
		t.Fatal(err)
	}

	// Reopen from disk.
	store2, close2, err := NewDurableStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer close2()

	snap, err := store2.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_1"}}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 1 || snap[0].EvidenceID != "ev_1" {
		t.Fatalf("expected 1 evidence item ev_1, got %v", snap)
	}
}

func TestDurableStoreRejectsCorruptSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.gob")

	// Write corrupt data.
	if err := os.WriteFile(path, []byte("not gob data"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, _, err := NewDurableStore(DurableConfig{Path: path})
	if err == nil {
		t.Fatal("expected error for corrupt snapshot")
	}
}
