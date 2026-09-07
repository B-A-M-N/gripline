package evidence

import (
	"testing"
	"time"
)

// TestStoreContract runs the same behavioral checks against both the in-memory
// and durable implementations, ensuring they satisfy the same Store contract
// (P0.9C).
func TestStoreContract(t *testing.T) {
	factories := []struct {
		name    string
		factory func(t *testing.T) Store
	}{
		{
			name: "memoryStore",
			factory: func(t *testing.T) Store {
				return NewMemoryStore()
			},
		},
		{
			name: "durableStore",
			factory: func(t *testing.T) Store {
				dir := t.TempDir()
				s, closeFn, err := NewDurableStore(DurableConfig{
					Path:          dir + "/evidence.gob",
					FlushInterval: 10 * time.Millisecond,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := closeFn(); err != nil {
						t.Fatal(err)
					}
				})
				return s
			},
		},
	}

	for _, f := range factories {
		t.Run(f.name, func(t *testing.T) {
			now := time.Now()
			s := f.factory(t)

			ev := Evidence{
				EvidenceID: "ev_contract_1", Code: "NEW_LANE", Family: FamilyClientNovelty,
				Scope: ScopeLane, SubjectID: "lane_contract", Score: 10, Confidence: 60,
				CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1,
			}

			// Append and snapshot.
			if err := s.Append(ev); err != nil {
				t.Fatalf("Append: %v", err)
			}
			snap, err := s.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_contract"}}, now.Add(time.Second))
			if err != nil {
				t.Fatalf("Snapshot: %v", err)
			}
			if len(snap) != 1 || snap[0].EvidenceID != "ev_contract_1" {
				t.Fatalf("expected 1 evidence item, got %d", len(snap))
			}

			// Idempotent re-append.
			if err := s.Append(ev); err != nil {
				t.Fatalf("re-Append: %v", err)
			}
			snap2, _ := s.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_contract"}}, now.Add(time.Second))
			if len(snap2) != 1 {
				t.Fatalf("re-append should not duplicate, got %d", len(snap2))
			}

			// Invalid evidence rejected without consuming bound.
			evInvalid := Evidence{EvidenceID: "ev_bad", Code: "", Scope: ScopeLane, SubjectID: "lane_contract"}
			if err := s.Append(evInvalid); err == nil {
				t.Fatal("expected error for invalid evidence")
			}

			// Expired evidence excluded from snapshot.
			evExpired := Evidence{
				EvidenceID: "ev_expired", Code: "NEW_LANE", Family: FamilyClientNovelty,
				Scope: ScopeLane, SubjectID: "lane_contract", Score: 5, Confidence: 60,
				CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), PolicyRevision: 1,
			}
			if err := s.Append(evExpired); err != nil {
				t.Fatalf("Append expired: %v", err)
			}
			snap3, _ := s.Snapshot([]SubjectKey{{Scope: ScopeLane, ID: "lane_contract"}}, now)
			if len(snap3) != 1 {
				t.Fatalf("expired evidence should be excluded, got %d", len(snap3))
			}

			// Prune.
			pruned, err := s.Prune([]SubjectKey{{Scope: ScopeLane, ID: "lane_contract"}}, now)
			if err != nil {
				t.Fatalf("Prune: %v", err)
			}
			if pruned < 1 {
				t.Fatalf("expected at least 1 pruned, got %d", pruned)
			}
		})
	}
}
