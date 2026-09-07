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
		CredentialID: "cred_node", AccountID: "acct_node", Verifier: []byte("v"), PepperVersion: 1,
		VerifierVersion: 1, Status: StatusNormal,
		PolicyID: "policy_node", PlanID: "plan_node",
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

// P0.14: the automatic-escalation ceiling is expressed as MaxAutomaticStatus,
// not by mutilating the risk score. The old clamp (score = Constrained-1)
// could never cross the CONSTRAINED threshold, so hot credentials stuck at
// WATCH and the recorded risk history was falsified.
func TestReduceTransitionMaxAutomaticStatusCeiling(t *testing.T) {
	hy := DefaultHysteresis()
	hy.MaxAutomaticStatus = StatusConstrained // Gate H default
	now := time.Now()

	// A quarantine-warranting score (100 >= 80) from NORMAL with a ceiling of
	// CONSTRAINED: the REAL score is recorded, escalation stops at CONSTRAINED
	// — not WATCH (the old bug) and not QUARANTINED (the policy gate).
	r := ReduceTransition(hy, StatusNormal, SecurityState{}, 100, now)
	if r.Status != StatusConstrained {
		t.Fatalf("P0.14: ceiling CONSTRAINED from quarantine-level score → %v, want CONSTRAINED (not WATCH, not QUARANTINED)", r.Status)
	}
	if r.Next.RiskScore != 100 {
		t.Fatalf("P0.14: recorded RiskScore = %d, want the real 100 (no score mutilation)", r.Next.RiskScore)
	}

	// Without the ceiling, the same observation quarantines (control).
	r2 := ReduceTransition(DefaultHysteresis(), StatusNormal, SecurityState{}, 100, now)
	if r2.Status != StatusQuarantined {
		t.Fatalf("control: no ceiling → %v, want QUARANTINED", r2.Status)
	}

	// A CONSTRAINED credential under the ceiling with a quarantine-level score
	// stays CONSTRAINED — the CONSTRAINED→QUARANTINED step is withheld.
	r3 := ReduceTransition(hy, StatusConstrained, SecurityState{}, 95, now)
	if r3.Status != StatusConstrained {
		t.Fatalf("P0.14: CONSTRAINED + ceiling with hot score → %v, want CONSTRAINED", r3.Status)
	}

	// A ceiling of WATCH (stricter Gate H posture) permits only WATCH (entry
	// still needs the WatchObs streak: two qualifying observations).
	hyWatch := DefaultHysteresis()
	hyWatch.MaxAutomaticStatus = StatusWatch
	st := SecurityState{}
	cur := StatusNormal
	for i := 0; i < hyWatch.WatchObs; i++ {
		r := ReduceTransition(hyWatch, cur, st, 100, now.Add(time.Duration(i)*time.Second))
		cur, st = r.Status, r.Next
	}
	if cur != StatusWatch {
		t.Fatalf("P0.14: ceiling WATCH after streak → %v, want WATCH", cur)
	}
	// And the quarantine-level score under the WATCH ceiling must NOT escalate
	// beyond WATCH.
	r4 := ReduceTransition(hyWatch, cur, st, 100, now.Add(time.Second))
	if r4.Status != StatusWatch {
		t.Fatalf("P0.14: ceiling WATCH with hot score → %v, want WATCH", r4.Status)
	}

	// Normal intermediate escalation still works under the ceiling: WATCH →
	// CONSTRAINED at score >= ConstrainedThresh (the old clamp made this
	// transition unreachable).
	r5 := ReduceTransition(hy, StatusWatch, SecurityState{}, 60, now)
	if r5.Status != StatusConstrained {
		t.Fatalf("P0.14: WATCH + score 60 under ceiling → %v, want CONSTRAINED (normal escalation preserved)", r5.Status)
	}

	// A zero ceiling means unbounded (backwards-compatible default).
	r6 := ReduceTransition(DefaultHysteresis(), StatusNormal, SecurityState{}, 100, now.Add(time.Second))
	if r6.Status != StatusQuarantined {
		t.Fatalf("P0.14: zero ceiling must not restrict: %v, want QUARANTINED", r6.Status)
	}

	// QUARANTINED/REVOKED are terminal regardless of ceiling.
	r7 := ReduceTransition(hy, StatusQuarantined, SecurityState{}, 10, now)
	if r7.Status != StatusQuarantined {
		t.Fatalf("P0.14: quarantine is terminal regardless of ceiling: %v", r7.Status)
	}
}
