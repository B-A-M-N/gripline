package statebolt

import (
	"strconv"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/evidence"
)

func testEvidence(id string, scope evidence.Scope, subject string, exp time.Time) evidence.Evidence {
	// Keep the test clock ahead of wall time so every row is non-future when
	// Snapshot applies Evidence.Valid across all backends.
	now := time.Now().Add(time.Hour)
	return evidence.Evidence{
		EvidenceID: id, Code: "TEST_SIGNAL", Family: evidence.FamilyAbuseCorrelation,
		Scope: scope, SubjectID: subject, Score: 10, Severity: 1, Confidence: 50,
		CreatedAt: now, ExpiresAt: exp,
	}
}

// TestEvidenceStoreRoundTripAndExpiry proves the Bolt evidence store persists
// across restart, applies the shared inclusive-expiry rule, and prunes
// atomically (P0.2).
func TestEvidenceStoreRoundTripAndExpiry(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/state.db"
	now := time.Now()

	s, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	subj := []evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: "cred_1"}}
	active := testEvidence("ev_1", evidence.ScopeCredential, "cred_1", now.Add(time.Hour))
	active.CreatedAt = now.Add(-time.Second)
	expired := testEvidence("ev_2", evidence.ScopeCredential, "cred_1", now.Add(-time.Minute))
	expired.CreatedAt = now.Add(-2 * time.Minute)
	if err := s.Append(active, expired); err != nil {
		t.Fatal(err)
	}
	got, err := s.Snapshot(subj, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].EvidenceID != "ev_1" {
		t.Fatalf("snapshot = %v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: evidence survives.
	s2, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err = s2.Snapshot(subj, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].EvidenceID != "ev_1" {
		t.Fatalf("evidence LOST across restart: %v", got)
	}
	// Idempotent re-append.
	if err := s2.Append(testEvidence("ev_1", evidence.ScopeCredential, "cred_1", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	got, _ = s2.Snapshot(subj, now.Add(time.Minute))
	if len(got) != 1 {
		t.Fatalf("duplicate append must be a no-op, got %d", len(got))
	}
	// The re-append also applies the shared merge contract and removes the
	// already-expired persisted ev_2 row before pressure is considered.
	pruned, err := s2.Prune(subj, now.Add(2*time.Hour))
	if err != nil || pruned != 1 {
		t.Fatalf("prune=%d err=%v", pruned, err)
	}
	got, _ = s2.Snapshot(subj, now.Add(2*time.Hour))
	if len(got) != 0 {
		t.Fatalf("post-prune snapshot = %v", got)
	}
}

// TestEvidenceStoreSharedSemantics proves the Bolt backend behaves like the
// memory store: atomic batch validation, per-subject compaction that never
// evicts NonEvictable items, and error-on-invalid.
func TestEvidenceStoreSharedSemantics(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	// Invalid batch is all-or-nothing.
	bad := testEvidence("ev_bad", evidence.ScopeCredential, "cred_x", now.Add(time.Hour))
	bad.Score = -5
	if err := s.Append(testEvidence("ev_ok", evidence.ScopeCredential, "cred_x", now.Add(time.Hour)), bad); err == nil {
		t.Fatal("invalid item must reject the batch")
	}
	got0, _ := s.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: "cred_x"}}, now)
	if len(got0) != 0 {
		t.Fatalf("rejected batch must store nothing, got %v", got0)
	}

	// Pressure: fill to the cap with evictable items + one NonEvictable, then
	// overflow. The NonEvictable (non-expiring) item must survive compaction.
	// Appended in batches (one Bolt transaction per Append call keeps this test
	// fast while still exercising per-subject compaction).
	subj := evidence.ScopeCredential
	batch := make([]evidence.Evidence, 0, 256)
	for i := 0; i < evidence.MaxEvidencePerSubject; i++ {
		ev := testEvidence("ev_"+string(rune('a'+i%26))+string(rune('0'+i/26)), subj, "cred_p", now.Add(time.Hour))
		ev.CreatedAt = now.Add(-time.Duration(evidence.MaxEvidencePerSubject-i) * time.Second)
		batch = append(batch, ev)
		if len(batch) == 256 {
			if err := s.Append(batch...); err != nil {
				t.Fatalf("append at %d: %v", i, err)
			}
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		if err := s.Append(batch...); err != nil {
			t.Fatal(err)
		}
	}
	anchor := testEvidence("ev_anchor", subj, "cred_p", time.Time{}) // non-expiring → NonEvictable
	anchor.CreatedAt = now.Add(-time.Second)
	if err := s.Append(anchor); err != nil {
		t.Fatal(err)
	}
	overflow := testEvidence("ev_overflow", subj, "cred_p", now.Add(time.Hour))
	overflow.CreatedAt = now.Add(-time.Second)
	if err := s.Append(overflow); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Snapshot([]evidence.SubjectKey{{Scope: subj, ID: "cred_p"}}, now)
	if len(got) > evidence.MaxEvidencePerSubject+1 {
		t.Fatalf("compaction failed to bound the subject: %d", len(got))
	}
	foundAnchor := false
	for _, ev := range got {
		if ev.EvidenceID == "ev_anchor" {
			foundAnchor = true
		}
	}
	if !foundAnchor {
		t.Fatal("NonEvictable evidence must survive generic pressure compaction (P0.12)")
	}
}

// TestEvidenceBatchCompactsToExactCap proves a near-cap seed plus a 256-item
// batch is compacted to exactly the configured cap, rather than storing only
// the first item or rejecting the whole batch.
func TestEvidenceBatchCompactsToExactCap(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	const subject = "cred_batch_cap"
	seed := make([]evidence.Evidence, 0, evidence.MaxEvidencePerSubject-10)
	for i := 0; i < evidence.MaxEvidencePerSubject-10; i++ {
		ev := testEvidence("seed_"+strconv.Itoa(i), evidence.ScopeCredential, subject, now.Add(time.Hour))
		ev.CreatedAt = now.Add(-2*time.Hour + time.Duration(i)*time.Millisecond)
		seed = append(seed, ev)
	}
	if err := s.Append(seed...); err != nil {
		t.Fatal(err)
	}
	batch := make([]evidence.Evidence, 0, 256)
	for i := 0; i < 256; i++ {
		ev := testEvidence("batch_"+strconv.Itoa(i), evidence.ScopeCredential, subject, now.Add(time.Hour))
		ev.CreatedAt = now.Add(-time.Minute + time.Duration(i)*time.Millisecond)
		batch = append(batch, ev)
	}
	if err := s.Append(batch...); err != nil {
		t.Fatal(err)
	}
	got, err := s.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: subject}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != evidence.MaxEvidencePerSubject {
		t.Fatalf("seed cap-10 + batch 256: got %d rows, want exact cap %d", len(got), evidence.MaxEvidencePerSubject)
	}
	for _, ev := range batch {
		found := false
		for _, retained := range got {
			if retained.EvidenceID == ev.EvidenceID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("batch row %q was not retained", ev.EvidenceID)
		}
	}
	before := append([]evidence.Evidence(nil), got...)
	if err := s.Append(batch...); err != nil {
		t.Fatal(err)
	}
	after, err := s.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: subject}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("repeated batch changed cap: before=%d after=%d", len(before), len(after))
	}
	for _, ev := range before {
		found := false
		for _, retained := range after {
			if retained.EvidenceID == ev.EvidenceID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("repeated batch evicted unrelated evidence %q", ev.EvidenceID)
		}
	}
}

// TestEvidenceNulSubjectRejected proves collision-safe evidence keys.
func TestEvidenceNulSubjectRejected(t *testing.T) {
	s := openTestStore(t)
	if err := s.Append(testEvidence("ev_1", evidence.ScopeCredential, "bad\x00subj", time.Now().Add(time.Hour))); err == nil {
		t.Fatal("NUL in subject id must be rejected")
	}
}
