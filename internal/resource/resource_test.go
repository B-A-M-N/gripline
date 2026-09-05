package resource

import (
	"sync"
	"testing"
	"time"
)

// --- concurrency leases: INV-15 property tests -------------------------------

func TestConcurrencyNeverNegative(t *testing.T) {
	p := NewConcurrencyPool(4)
	if p.Balance() != 4 {
		t.Fatalf("initial balance %d, want 4", p.Balance())
	}
	// Acquire all
	var leases []*LeaseHandle
	for i := 0; i < 4; i++ {
		l := p.Acquire()
		if l == nil {
			t.Fatal("should acquire")
		}
		leases = append(leases, l)
	}
	if l := p.Acquire(); l != nil {
		t.Fatal("pool at capacity must not over-admit")
	}
	if p.InUse() != 4 {
		t.Fatalf("InUse = %d, want 4", p.InUse())
	}
	// Release one, verify accounting drops to 3 in-use, never negative.
	leases[0].Release()
	if p.InUse() != 3 {
		t.Fatalf("after one release InUse = %d, want 3", p.InUse())
	}
	// Double-release must not refund twice (INV-15).
	leases[0].Release()
	leases[0].Release()
	if p.InUse() != 3 {
		t.Fatalf("double release over-credited; InUse = %d, want 3", p.InUse())
	}
	// Release the rest — final balance must be back to capacity, not above.
	for _, l := range leases[1:] {
		l.Release()
	}
	if p.Balance() != 4 {
		t.Fatalf("final balance = %d, want 4 (accounting must not mint)", p.Balance())
	}
}

func TestConcurrencyInUseClampedAtZero(t *testing.T) {
	p := NewConcurrencyPool(0)
	if p.Acquire() != nil {
		t.Fatal("capacity-0 pool must deny")
	}
	if p.InUse() != 0 {
		t.Fatal("InUse must not go below 0")
	}
}

func TestAcquireNMultiSlot(t *testing.T) {
	p := NewConcurrencyPool(6)
	l := p.AcquireN(3)
	if l == nil || p.InUse() != 3 {
		t.Fatalf("AcquireN(3) inuse=%d want 3", p.InUse())
	}
	// 3 free remain; AcquireN(4) fails atomically.
	if l2 := p.AcquireN(4); l2 != nil {
		t.Fatal("AcquireN(4) must fail when only 3 free")
	}
	l.Release()
	if p.InUse() != 0 {
		t.Fatalf("after release inuse=%d want 0", p.InUse())
	}
	// Zero-slot lease release is a no-op.
	z := p.AcquireN(0)
	z.Release()
	if p.Balance() != 6 {
		t.Fatalf("zero lease must not change balance, got %d", p.Balance())
	}
}

// --- token buckets ----------------------------------------------------------

func TestTokenBucketTakeAndReturn(t *testing.T) {
	base := time.Now()
	b := NewTokenBucket(100, 0, time.Millisecond, func() time.Time { return base })
	if b.Available() != 100 {
		t.Fatalf("available = %v, want 100", b.Available())
	}
	took := b.Take(60)
	if took != 60 {
		t.Fatalf("took = %v, want 60", took)
	}
	if b.Available() != 40 {
		t.Fatalf("available = %v, want 40", b.Available())
	}
	// Over-take clamps to available.
	if took := b.Take(100); took != 40 {
		t.Fatalf("over-take should clamp to 40, got %v", took)
	}
	// Refund can't go below 0.
	if r := b.Return(999); r != 100 {
		t.Fatalf("refund should cap at spent, got %v", r)
	}
}

func TestTokenBucketRefill(t *testing.T) {
	base := time.Now()
	clock := base
	b := NewTokenBucket(100, 10, time.Second, func() time.Time { return clock })
	_ = b.Take(100) // exhaust
	// advance 5s → 50 refilled
	clock = base.Add(5 * time.Second)
	if got := b.Available(); got != 50 {
		t.Fatalf("available after 5s = %v, want 50", got)
	}
	// advance far past → capped at capacity
	clock = base.Add(time.Hour)
	if got := b.Available(); got != 100 {
		t.Fatalf("available after long time = %v, want 100 (cap)", got)
	}
}

func TestTokenBucketConcurrentInvariant(t *testing.T) {
	b := NewTokenBucket(50, 10, time.Second, time.Now)
	var wg sync.WaitGroup
	// Many concurrent Take/Return must leave balance bounded by [0, capacity].
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Take(10)
			b.Return(10)
			b.Take(7)
		}()
	}
	wg.Wait()
	if bal := b.Balance(); bal < 0 || bal > b.Capacity() {
		t.Fatalf("balance %v out of [0,%v]", bal, b.Capacity())
	}
}
