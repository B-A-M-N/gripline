package credential

import (
	"context"
	"testing"
	"time"
)

func TestReduceTransitionPureDeterministic(t *testing.T) {
	hy := DefaultHysteresis()
	now := time.Unix(1_600_000_000, 0)

	// ReduceTransition must be a pure function: the same (current status, state,
	// score, now) always yields the same next state — no hidden mutable state.
	r := ReduceTransition(hy, StatusNormal, SecurityState{}, hy.WatchThresh, now)
	// First qualifying observation: WatchObs defaults to 2, so status stays
	// NORMAL but the streak advances — no transition yet.
	if r.Status != StatusNormal || r.Changed || r.Next.WatchStreak != 1 {
		t.Fatalf("first watch observation: status=%v changed=%v streak=%d (want NORMAL false 1)", r.Status, r.Changed, r.Next.WatchStreak)
	}
	// A second identical call, run as a fresh "replica," must converge to the
	// EXACT same fields (purity = replayable).
	r2 := ReduceTransition(hy, StatusNormal, SecurityState{}, hy.WatchThresh, now)
	if r.Status != r2.Status || r.Next.WatchStreak != r2.Next.WatchStreak ||
		r.Next.BelowSince != r2.Next.BelowSince || r.Next.LastObservedAt != r2.Next.LastObservedAt {
		t.Fatalf("pure reducer not deterministic across identical calls")
	}
}

func TestObserveAndCommitSecondNodeConverges(t *testing.T) {
	// Two "nodes" share one authoritative store. Even though node B never saw
	// node A's observation directly, both transitions applied through the
	// store produce the same authoritative status — the durable record is the
	// single source of truth (P0.5).
	reg := NewMemoryRegistry()
	hy := DefaultHysteresis()
	base := time.Unix(1_600_000_000, 0)

	if err := reg.Insert(&CredentialRecord{
		CredentialID: "cred_node", Verifier: []byte("v"), PepperVersion: 1,
		VerifierVersion: 1, Status: StatusNormal,
		CreatedAt: base.Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// Node A applies observation 1.
	if _, err := reg.ObserveAndCommit(ctx, "cred_node", hy.WatchThresh, hy, base); err != nil {
		t.Fatal(err)
	}
	// Node A applies observation 2 → WATCH.
	if _, err := reg.ObserveAndCommit(ctx, "cred_node", hy.WatchThresh, hy, base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Node B reads authoritative state: must see WATCH with streak 2, even
	// though it never ran those observations itself.
	rec, err := reg.LookupAuthoritative(ctx, "cred_node")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != StatusWatch {
		t.Fatalf("P0.5: node B reads status %v, want WATCH", rec.Status)
	}
	if rec.Security.WatchStreak != 2 {
		t.Fatalf("P0.5: node B reads WatchStreak %d, want 2", rec.Security.WatchStreak)
	}
}