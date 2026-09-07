package lane

import (
	"errors"
	"testing"
	"time"
)

// sparse is the default HeaderFeatures-style vector: no trusted network dims,
// only transport/client metadata. Network trio (0.70 of the space) is absent.
func sparse() Features {
	return Features{HTTPVersion: "1.1", ClientFamily: "sdk", Streaming: "non-streaming"}
}

// trusted is a full vector including the network-source identity trio.
func trusted() Features {
	return Features{
		NetworkASN: "AS64512", NetworkType: "residential", RegionClass: "us-east",
		ClientFamily: "sdk", SDKFamily: "openai", HTTPVersion: "1.1",
		Streaming: "non-streaming", ModelFamily: "gpt", ConcurrencyPattern: "interactive",
		EndpointFamily: "chat",
	}
}

// P0.1 regression: the default sparse resolver must be usable. Request 1
// creates the lane; the identical request 2 must reuse the SAME provisional
// lane instead of failing the borrow floor and colliding on ErrLaneConflict.
func TestBorrowOrCreateExactSparseReuse(t *testing.T) {
	store := NewStore(nil, time.Now)
	th := DefaultThresholds()

	r1, created, err := store.BorrowOrCreate("cred1", "lane_x", sparse(), ClassificationContext{Thresholds: th})
	if err != nil || !created {
		t.Fatalf("request 1: created=%v err=%v", created, err)
	}
	if r1.State != StateNew {
		t.Fatalf("request 1 state = %v, want NEW", r1.State)
	}

	r2, created, err := store.BorrowOrCreate("cred1", "lane_x", sparse(), ClassificationContext{Thresholds: th})
	if err != nil {
		t.Fatalf("request 2 denied (P0.1 ErrLaneConflict regression): %v", err)
	}
	if created {
		t.Fatal("request 2 must reuse the existing lane, not create")
	}
	if r2.LaneID != r1.LaneID {
		t.Fatalf("request 2 lane %q != request 1 lane %q", r2.LaneID, r1.LaneID)
	}
	if r2.RequestCount != 2 {
		t.Fatalf("RequestCount = %d, want 2 (reuse counted)", r2.RequestCount)
	}
	// Reuse grants no trust: the lane stays NEW.
	if r2.State != StateNew {
		t.Fatalf("reuse escalated state to %v, want NEW (no trust from exact reuse)", r2.State)
	}
}

// P0.1: a sparse candidate must not BORROW an established lane — the 0.70
// comparable floor still applies to cross-lane matching even after exact
// self-reuse was unblocked.
func TestBorrowOrCreateSparseCannotBorrowEstablished(t *testing.T) {
	store := NewStore(nil, time.Now)
	th := DefaultThresholds()

	// Build a genuinely established lane with the full trusted vector under a
	// different deterministic ID.
	if _, _, err := store.BorrowOrCreate("cred1", "lane_trusted", trusted(), ClassificationContext{Thresholds: th}); err != nil {
		t.Fatalf("seed established lane: %v", err)
	}
	rec, _ := store.Get("cred1", "lane_trusted")
	rec.State = StateEstablished

	// A sparse attacker vector deriving a DIFFERENT id must not collapse into
	// the established lane (similarity over the tiny shared set renormalizes
	// high, but comparable mass is 0.03 < 0.70).
	id := "lane_attacker"
	_, created, err := store.BorrowOrCreate("cred1", id, sparse(), ClassificationContext{Thresholds: th})
	if err != nil {
		t.Fatalf("sparse candidate should create its own provisional lane, err=%v", err)
	}
	if created {
		t.Log("sparse candidate created its own lane (correct)")
	}
	if got, _ := store.Get("cred1", id); got == nil || got.LaneID != id {
		t.Fatalf("expected distinct provisional lane %q", id)
	}
	// The established lane must not have absorbed the request.
	if got, _ := store.Get("cred1", "lane_trusted"); got.RequestCount != 1 {
		t.Fatalf("established lane RequestCount = %d, want 1 (no borrow)", got.RequestCount)
	}
}

// P0.1: a full trusted vector CAN borrow/match per policy — the floor is
// satisfiable when the trusted dims are present.
func TestBorrowOrCreateTrustedVectorCanMatch(t *testing.T) {
	store := NewStore(nil, time.Now)
	th := DefaultThresholds()

	if _, _, err := store.BorrowOrCreate("cred1", "lane_a", trusted(), ClassificationContext{Thresholds: th}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Same trusted manifestation under a different derived ID: full comparable
	// mass (1.0) and similarity 1.0 → Match → borrow, not a new lane.
	alt := trusted()
	alt.ClientFamily = "sdk" // identical anyway; ensure same vector
	rec, created, err := store.BorrowOrCreate("cred1", "lane_b_alt", alt, ClassificationContext{Thresholds: th})
	if err != nil {
		t.Fatalf("trusted match denied: %v", err)
	}
	if created {
		t.Fatal("full trusted vector should MATCH the existing lane, not create")
	}
	if rec.LaneID != "lane_a" {
		t.Fatalf("matched lane = %q, want lane_a", rec.LaneID)
	}
}

// P0.22 regression: a record stored under an older feature schema is never
// silently compared. Same-ID reuse under a stale schema must fail closed
// (ErrLaneConflict), and the stale record must not be borrowable.
func TestBorrowOrCreateSchemaStaleRecordNotCompared(t *testing.T) {
	store := NewStore(nil, time.Now)
	th := DefaultThresholds()

	if _, _, err := store.BorrowOrCreate("cred1", "lane_old", trusted(), ClassificationContext{Thresholds: th}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Force the stored row to a stale schema (simulates a pre-bump record).
	// Same package: reach the internal record directly.
	recOld, _ := store.Get("cred1", "lane_old")
	_ = recOld
	store.mu.Lock()
	internal := store.byCred["cred1"]["lane_old"]
	internal.FeatSchema = FeatSchemaVersion - 1
	store.mu.Unlock()

	// Exact same vector, but the stored row is schema-stale: never compare —
	// fail closed with the collision error rather than reuse or overwrite.
	if _, _, err := store.BorrowOrCreate("cred1", "lane_old", trusted(), ClassificationContext{Thresholds: th}); !errors.Is(err, ErrLaneConflict) {
		t.Fatalf("schema-stale same-ID reuse err = %v, want ErrLaneConflict", err)
	}

	// And a candidate that would otherwise Match the stale row must not borrow
	// it — it creates its own lane instead.
	if _, created, err := store.BorrowOrCreate("cred1", "lane_new_schema", trusted(), ClassificationContext{Thresholds: th}); err != nil || !created {
		t.Fatalf("candidate under current schema should create fresh lane, created=%v err=%v", created, err)
	}
}
