package resource

import (
	"testing"
	"time"
)

// P0.2 regression: a NORMAL→CONSTRAINED cap change must take effect on the
// very next acquisition, without recreating the pool or resetting accounting.
func TestConcurrencyPoolDynamicCapTightenAndExpand(t *testing.T) {
	p := NewConcurrencyPool(32)

	// NORMAL: cap 32, acquire 3.
	for i := 0; i < 3; i++ {
		if p.AcquireNCap(1, 32) == nil {
			t.Fatalf("acquire %d under cap 32 denied", i+1)
		}
	}
	if p.InUse() != 3 {
		t.Fatalf("in use = %d, want 3", p.InUse())
	}

	// CONSTRAINED: cap 2 → all new acquisitions denied (2 in-use >= 2).
	if l := p.AcquireNCap(1, 2); l != nil {
		t.Fatal("acquisition under constrained cap 2 with 2 in-use must be denied")
	}

	// Release to 1 active → exactly one new request permitted, then denied.
	// Redo the scenario with tracked handles for precise release control.
	p2 := NewConcurrencyPool(32)
	var held []*LeaseHandle
	for i := 0; i < 3; i++ {
		l := p2.AcquireNCap(1, 32)
		if l == nil {
			t.Fatalf("warmup acquire %d denied", i+1)
		}
		held = append(held, l)
	}
	held[0].Release()
	held[1].Release()
	if p2.InUse() != 1 {
		t.Fatalf("in use after releases = %d, want 1", p2.InUse())
	}
	l := p2.AcquireNCap(1, 2)
	if l == nil {
		t.Fatal("exactly one new request should be permitted at 1 in-use under cap 2")
	}
	if p2.AcquireNCap(1, 2) != nil {
		t.Fatal("second new request under cap 2 must be denied")
	}

	// CONSTRAINED → NORMAL: capacity expands again, accounting preserved
	// (2 in-use; pool capacity still 32, not reset).
	l.Release()
	if p2.AcquireNCap(1, 32) == nil {
		t.Fatal("expanded cap should admit again")
	}
	if got := p2.Capacity(); got != 32 {
		t.Fatalf("capacity = %d, want 32 (construction capacity preserved)", got)
	}
}

// A cap of 0 denies everything (deny-all scope), and construction capacity
// still bounds acquisition when the policy cap exceeds it.
func TestConcurrencyPoolCapEdges(t *testing.T) {
	p := NewConcurrencyPool(4)
	if p.AcquireNCap(1, 0) != nil {
		t.Fatal("cap 0 must deny")
	}
	// Policy cap above construction capacity: min() applies.
	for i := 0; i < 4; i++ {
		if p.AcquireNCap(1, 100) == nil {
			t.Fatalf("acquire %d within construction capacity denied", i+1)
		}
	}
	if p.AcquireNCap(1, 100) != nil {
		t.Fatal("fifth acquire must be denied by construction capacity 4")
	}
}

// P0.2 regression (buckets): a bucket's rate/capacity must not be frozen at
// first creation. Tightening must reduce available allowance immediately;
// loosening must restore it without resetting spent accounting.
func TestTokenBucketReconfigure(t *testing.T) {
	base := time.Now()
	clock := base
	b := NewTokenBucket(100, 0, 0, func() time.Time { return clock }) // burst-only

	if r := b.Reserve(60); r == nil {
		t.Fatal("reserve 60 of 100 failed")
	}
	if r := b.Reserve(60); r != nil {
		t.Fatal("reserve past capacity must fail")
	}

	// Tighten to 50: spent 60 clamps down to the new capacity (the 10-unit
	// overhang is necessarily refunded — capacity cannot be below spend); the
	// bucket is then full at 50 and nothing more fits.
	b.Reconfigure(50, 0, 0)
	if avail := b.Capacity(); avail != 50 {
		t.Fatalf("capacity after tighten = %.0f, want 50", avail)
	}
	if r := b.Reserve(1); r != nil {
		t.Fatal("reserve over tightened capacity must fail (full at 50)")
	}

	// Loosen to 100: allowance expands without resetting the spent balance
	// (spend stays 50; 50 free).
	b.Reconfigure(100, 0, 0)
	if r := b.Reserve(50); r == nil {
		t.Fatal("loosened bucket should admit the 50 free units")
	}
	if r := b.Reserve(1); r != nil {
		t.Fatal("reserve beyond loosened capacity must still fail")
	}

	// Refill parameters take effect from reconfiguration time forward.
	clock = base.Add(2 * time.Minute)
	b.Reconfigure(100, 30, time.Minute) // credit elapsed under OLD rate (0): none
	if got := b.Available(); got > 0.001 {
		t.Fatalf("elapsed time under old rate 0 must not mint allowance, got %.2f", got)
	}
	clock = base.Add(4 * time.Minute)
	if got := b.Available(); got < 58 || got > 62 {
		t.Fatalf("new refill rate should credit ~60 over 2m, got %.2f", got)
	}
}

// P0.2 regression through the Governor: a scope's constrained cap must apply
// on the next Provision, and restoring the cap must admit again — same pool,
// no accounting reset.
func TestGovernorDynamicScopeCap(t *testing.T) {
	g := NewGovernor(nil)
	spec := func(cap int) []ScopeSpec {
		return []ScopeSpec{{Scope: ScopeCredential, ID: "c1", Buckets: BucketSpec{ConcurrencyCap: cap}}}
	}

	// NORMAL cap 3: two concurrent admissions hold 2 slots.
	r1, err := g.ProvisionUsage(spec(3), UsageEstimate{Requests: 1})
	if err != nil {
		t.Fatalf("provision 1: %v", err)
	}
	r2, err := g.ProvisionUsage(spec(3), UsageEstimate{Requests: 1})
	if err != nil {
		t.Fatalf("provision 2: %v", err)
	}

	// CONSTRAINED cap 2: 2 in-use → denied. The old code built the pool at
	// capacity 3 and ignored this cap forever.
	if _, err := g.ProvisionUsage(spec(2), UsageEstimate{Requests: 1}); err == nil {
		t.Fatal("constrained cap 2 with 2 in-flight must deny (P0.2)")
	}

	// Release one → exactly one new admission fits under the constrained cap.
	r1.Release()
	r3, err := g.ProvisionUsage(spec(2), UsageEstimate{Requests: 1})
	if err != nil {
		t.Fatalf("one slot freed should admit under cap 2: %v", err)
	}
	if _, err := g.ProvisionUsage(spec(2), UsageEstimate{Requests: 1}); err == nil {
		t.Fatal("constrained cap 2 must still deny at 2 in-flight")
	}

	// Back to NORMAL: capacity expands without recreating/resetting accounting.
	r2.Release()
	r4, err := g.ProvisionUsage(spec(3), UsageEstimate{Requests: 1})
	if err != nil {
		t.Fatalf("restored cap should admit: %v", err)
	}
	_ = r3
	_ = r4
}
