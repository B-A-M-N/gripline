package statebolt

import (
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/evidence"
)

func testEvidence(id string, scope evidence.Scope, subject string, exp time.Time) evidence.Evidence {
	now := time.Now()
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
	if err := s.Append(
		testEvidence("ev_1", evidence.ScopeCredential, "cred_1", now.Add(time.Hour)),
		testEvidence("ev_2", evidence.ScopeCredential, "cred_1", now.Add(-time.Minute)), // already expired
	); err != nil {
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
	// Prune removes the expired remainder: both rows expire by now+2h
	// (persistence is independent of evaluation, so the already-expired ev_2
	// row was durably stored and is reaped here too).
	pruned, err := s2.Prune(subj, now.Add(2*time.Hour))
	if err != nil || pruned != 2 {
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
		ev.CreatedAt = now.Add(time.Duration(i) * time.Second)
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
	if err := s.Append(anchor); err != nil {
		t.Fatal(err)
	}
	overflow := testEvidence("ev_overflow", subj, "cred_p", now.Add(time.Hour))
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

// TestEvidenceNulSubjectRejected proves collision-safe evidence keys.
func TestEvidenceNulSubjectRejected(t *testing.T) {
	s := openTestStore(t)
	if err := s.Append(testEvidence("ev_1", evidence.ScopeCredential, "bad\x00subj", time.Now().Add(time.Hour))); err == nil {
		t.Fatal("NUL in subject id must be rejected")
	}
}
