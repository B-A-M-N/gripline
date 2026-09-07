package resource

import (
	"math"
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

// Regression (P0.4): a struct COPY of a lease handle must not carry its own
// release state. Previously the `released` flag lived in the handle itself,
// so copy.Release() after lease.Release() refunded the same slots twice,
// breaking INV-15.
func TestCopiedLeaseCannotDoubleRefund(t *testing.T) {
	pool := NewConcurrencyPool(2)
	lease := pool.Acquire()
	if lease == nil {
		t.Fatal("acquire failed")
	}
	cp := *lease // struct copy

	lease.Release()
	cp.Release()    // through the copy — must be a no-op
	lease.Release() // and again through the original

	if got := pool.Balance(); got != 2 {
		t.Fatalf("balance = %d, want 2 (double refund detected, INV-15)", got)
	}
	if !cp.Released() || !lease.Released() {
		t.Fatal("all copies must report released")
	}
}

// Regression (P0.4): concurrent Release through two copies of the same handle
// must refund exactly once (race-detected).
func TestConcurrentCopiedLeaseSingleRefund(t *testing.T) {
	pool := NewConcurrencyPool(4)
	lease := pool.AcquireN(4)
	if lease == nil {
		t.Fatal("acquire failed")
	}
	copies := make([]LeaseHandle, 8)
	for i := range copies {
		copies[i] = *lease
	}
	var wg sync.WaitGroup
	for i := range copies {
		wg.Add(1)
		go func(h LeaseHandle) {
			defer wg.Done()
			h.Release()
		}(copies[i])
	}
	lease.Release()
	wg.Wait()

	if got := pool.Balance(); got != 4 {
		t.Fatalf("balance = %d, want 4 (INV-15: refund exactly once)", got)
	}
}

// --- P0.11 hardening regressions: reservation semantics ----------------------

// Regression: non-finite bucket parameters must not corrupt accounting.
func TestTokenBucketRejectsNonFinite(t *testing.T) {
	b := NewTokenBucket(math.NaN(), 1, time.Minute, nil)
	if b.Capacity() != 0 {
		t.Fatalf("NaN capacity accepted: %v", b.Capacity())
	}
	b2 := NewTokenBucket(10, math.Inf(1), time.Minute, nil)
	if b2.Reserve(1) == nil {
		t.Fatal("valid reserve on sanitized bucket must succeed")
	}
	if r := b2.Reserve(math.NaN()); r != nil {
		t.Fatal("NaN reservation must be refused")
	}
	if r := b2.Reserve(math.Inf(-1)); r != nil {
		t.Fatal("Inf reservation must be refused")
	}
}

// Regression: Reserve is all-or-nothing — never a partial hold.
func TestReserveAllOrNothing(t *testing.T) {
	b := NewTokenBucket(10, 0, 0, nil)
	if r := b.Reserve(6); r == nil {
		t.Fatal("6 of 10 must reserve fully")
	} else if r.Amount() != 6 {
		t.Fatalf("amount = %v", r.Amount())
	}
	// Only 4 remain: a 6-request must fail entirely (not take 4).
	if r := b.Reserve(6); r != nil {
		t.Fatal("over-capacity reserve must fail, not partially take")
	}
	if avail := b.Available(); avail != 4 {
		t.Fatalf("available = %v, want 4", avail)
	}
}

func TestRetryAfterReportsBucketRefillLowerBound(t *testing.T) {
	now := time.Unix(100, 0)
	b := NewTokenBucket(1, 1, 10*time.Second, func() time.Time { return now })
	r := b.Reserve(1)
	if r == nil {
		t.Fatal("initial reservation should succeed")
	}
	if got := b.RetryAfter(1); got < 10*time.Second || got > 10*time.Second+time.Millisecond {
		t.Fatalf("retry-after=%s, want approximately 10s", got)
	}
	r.Cancel()
}

// Regression: settlement is ownership-safe and idempotent — a reservation
// releases exactly its own amount, exactly once, and Settle/Cancel are
// mutually exclusive (settlement can never mint allowance, INV-15).
func TestReservationSettleCancelIdempotent(t *testing.T) {
	b := NewTokenBucket(10, 0, 0, nil)
	r := b.Reserve(4)
	if r == nil {
		t.Fatal("reserve failed")
	}
	cp := *r     // struct copy shares settlement state
	r.Settle(4)  // full actual: whole hold consumed
	cp.Settle(4) // idempotent
	r.Cancel()   // must be a no-op after settle
	cp.Cancel()  // through the copy too
	if bal := b.Balance(); bal != 4 {
		t.Fatalf("balance after settle+cancel = %v, want 4 (INV-15)", bal)
	}
	if !r.Done() {
		t.Fatal("reservation must report done")
	}
	// A fresh reservation cancels exactly its own amount.
	r2 := b.Reserve(3)
	if r2 == nil {
		t.Fatal("second reserve failed")
	}
	r2.Cancel()
	r2.Cancel()
	if bal := b.Balance(); bal != 4 {
		t.Fatalf("balance after cancel = %v, want 4 (exactly own amount)", bal)
	}
	if avail := b.Available(); avail != 6 {
		t.Fatalf("available = %v, want 6", avail)
	}
}

// TestSettleChargesOverageAsDebt (BETA-05) verifies that when actual usage
// exceeds the reserved amount, the overage is charged against the bucket as
// debt — the bucket's balance may exceed its capacity. Available() returns 0
// while in debt. Future refills reduce the debt over time.
func TestSettleChargesOverageAsDebt(t *testing.T) {
	// No refill so we can observe debt directly.
	b := NewTokenBucket(10, 0, 0, nil)

	// Reserve 5, settle at 15 → 5 consumed + 10 debt → balance = 15 > capacity 10.
	r := b.Reserve(5)
	if r == nil {
		t.Fatal("reserve failed")
	}
	r.Settle(15)

	// Balance should be 5 (reserved) + 10 (overage) = 15.
	if bal := b.Balance(); bal != 15 {
		t.Fatalf("balance after overage settle = %v, want 15", bal)
	}
	// Available should be 0 (in debt: balance > capacity).
	if avail := b.Available(); avail != 0 {
		t.Fatalf("available while in debt = %v, want 0", avail)
	}
	// A new reservation should fail because the bucket is in debt.
	if r2 := b.Reserve(3); r2 != nil {
		t.Fatal("reservation must fail while bucket is in debt")
	}
}

// TestSettleActualBelowEstimateRefunds (BETA-05) verifies the normal case:
// actual < estimate → refund delta.
func TestSettleActualBelowEstimateRefunds(t *testing.T) {
	b := NewTokenBucket(10, 0, 0, nil)
	r := b.Reserve(8)
	if r == nil {
		t.Fatal("reserve failed")
	}
	r.Settle(3)
	// Reserved 8, actual 3 → 5 refunded → balance = 3.
	if bal := b.Balance(); bal != 3 {
		t.Fatalf("balance = %v, want 3", bal)
	}
	if avail := b.Available(); avail != 7 {
		t.Fatalf("available = %v, want 7", avail)
	}
}

// TestSettleActualEqualsEstimate (BETA-05) verifies exact match: no refund,
// no debt.
func TestSettleActualEqualsEstimate(t *testing.T) {
	b := NewTokenBucket(10, 0, 0, nil)
	r := b.Reserve(6)
	if r == nil {
		t.Fatal("reserve failed")
	}
	r.Settle(6)
	if bal := b.Balance(); bal != 6 {
		t.Fatalf("balance = %v, want 6", bal)
	}
	if avail := b.Available(); avail != 4 {
		t.Fatalf("available = %v, want 4", avail)
	}
}

// TestSettleMassiveOverage (BETA-05) verifies that overage much larger than
// capacity creates proportional debt, not capped at capacity.
func TestSettleMassiveOverage(t *testing.T) {
	b := NewTokenBucket(100, 0, 0, nil)
	r := b.Reserve(10)
	if r == nil {
		t.Fatal("reserve failed")
	}
	r.Settle(1000)
	// Reserved 10, actual 1000 → balance = 10 + 990 = 1000.
	if bal := b.Balance(); bal != 1000 {
		t.Fatalf("balance after massive overage = %v, want 1000", bal)
	}
	if avail := b.Available(); avail != 0 {
		t.Fatalf("available = %v, want 0", avail)
	}
}

// TestEstimateZeroActualPositive (P0.12) verifies the estimate=0 / actual>0
// edge case. A zero estimate creates a zero-amount reservation so that
// Settle(actual) can create debt. This is essential because provider estimators
// often cannot predict output tokens/cost before execution.
func TestEstimateZeroActualPositive(t *testing.T) {
	b := NewTokenBucket(10, 0, 0, nil)
	// P0.12: Reserve(0) now returns a non-nil zero-amount reservation.
	r := b.Reserve(0)
	if r == nil {
		t.Fatal("Reserve(0) should return a non-nil zero-amount reservation")
	}
	// Settle(5) should charge 5 units of debt (0 reserved + 5 overage).
	r.Settle(5)
	// Balance should reflect the debt.
	if bal := b.Balance(); bal != 5 {
		t.Fatalf("balance = %v, want 5 (debt from zero estimate)", bal)
	}
	// Available: capacity 10 - balance 5 = 5 (not in debt yet, just reduced)
	if avail := b.Available(); avail != 5 {
		t.Fatalf("available = %v, want 5", avail)
	}
}

// TestReserveZeroDebtBypass (P0.12 fix) verifies that Reserve(0) is denied
// when the bucket is already exhausted/debted.
func TestReserveZeroDebtBypass(t *testing.T) {
	// capacity 10, balance 5 (available = 5)
	b := NewTokenBucket(10, 0, 0, nil)
	b.Take(5)
	if r := b.Reserve(0); r == nil {
		t.Fatal("Reserve(0) should succeed when bucket has positive allowance")
	}
	// capacity 10, balance 10 (available = 0)
	b2 := NewTokenBucket(10, 0, 0, nil)
	b2.Take(10)
	if r := b2.Reserve(0); r != nil {
		t.Fatal("Reserve(0) should be denied when bucket is exhausted")
	}
	// capacity 10, balance 15 (in debt, available = -5)
	b3 := NewTokenBucket(10, 0, 0, nil)
	b3.Take(15)
	if r := b3.Reserve(0); r != nil {
		t.Fatal("Reserve(0) should be denied when bucket is in debt")
	}
}

// TestDebtRecoveryThroughRefill (BETA-05) verifies that a bucket in debt
// recovers as refills reduce the balance over time.
func TestDebtRecoveryThroughRefill(t *testing.T) {
	base := time.Now()
	now := base
	b := NewTokenBucket(100, 100, time.Hour, func() time.Time { return now })

	r := b.Reserve(50)
	r.Settle(200) // 50 consumed + 150 debt → balance = 200
	if bal := b.Balance(); bal != 200 {
		t.Fatalf("balance after overage = %v, want 200", bal)
	}

	// Advance time: 0.5 hours → 50 tokens refilled → balance = 150.
	now = base.Add(30 * time.Minute)
	if bal := b.Balance(); bal != 150 {
		t.Fatalf("balance after 0.5h refill = %v, want 150", bal)
	}
	// Still in debt (balance 150 > capacity 100).
	if avail := b.Available(); avail != 0 {
		t.Fatalf("available = %v, want 0", avail)
	}

	// Advance another 0.5 hours (total 1h) → 50 more tokens → balance = 100.
	now = base.Add(time.Hour)
	if bal := b.Balance(); bal != 100 {
		t.Fatalf("balance after 1h total = %v, want 100", bal)
	}
	// Exactly at capacity (not in debt).
	if avail := b.Available(); avail != 0 {
		t.Fatalf("available = %v, want 0", avail)
	}

	// Advance another 0.5 hours (total 1.5h) → 50 more → balance = 50.
	now = base.Add(90 * time.Minute)
	if bal := b.Balance(); bal != 50 {
		t.Fatalf("balance after 1.5h total = %v, want 50", bal)
	}
	// Out of debt.
	if avail := b.Available(); avail != 50 {
		t.Fatalf("available = %v, want 50", avail)
	}
}

// TestConcurrentSettleAndRelease (BETA-05) verifies that concurrent Settle
// and Cancel calls are race-free.
func TestConcurrentSettleAndRelease(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		b := NewTokenBucket(1000, 0, 0, nil)
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := b.Reserve(10)
				if r == nil {
					return
				}
				r.Settle(15) // overage
			}()
		}
		wg.Wait()
	}
}
