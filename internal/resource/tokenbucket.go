package resource

import (
	"math"
	"sync"
	"time"
)

// TokenBucket models one resource gauge (requests, tokens, cost per scope)
// with capacity, refill rate, and an atomic Take/Return API (§47). It
// implements a token-bucket with continuous refill. Balance reflects
// unavailable-tokens (what's been spent); Take decrements, Return
// increments, never below 0.
//
// Hard authorization MUST use Reserve (all-or-nothing, P0.11 hardening), not
// partial-Take semantics: a reservation either secures the full amount or
// fails. Reserve returns a handle that settles or cancels exactly its own
// reservation — settlement is ownership-safe and idempotent.
type TokenBucket struct {
	mu         sync.Mutex
	now        func() time.Time
	capacity   float64
	refillPer  float64 // per refill interval
	refillIn   time.Duration
	balance    float64 // spent/unavailable amount (0..capacity)
	lastRefill time.Time
	revision   int
}

// NewTokenBucket creates a bucket with the given capacity and rate.
// refillPer tokens every refillIn. Non-finite (NaN/±Inf) or negative
// parameters are refused: NaN bypasses `< 0` checks and would corrupt
// security-sensitive accounting.
func NewTokenBucket(capacity float64, refillPer float64, refillIn time.Duration, now func() time.Time) *TokenBucket {
	if now == nil {
		now = time.Now
	}
	if capacity < 0 || math.IsNaN(capacity) || math.IsInf(capacity, 0) {
		capacity = 0
	}
	if refillPer < 0 || math.IsNaN(refillPer) || math.IsInf(refillPer, 0) {
		refillPer = 0
	}
	return &TokenBucket{
		capacity: capacity, refillPer: refillPer, refillIn: refillIn,
		balance: 0, lastRefill: now(), now: now,
	}
}

// Capacity returns the configured bucket capacity.
func (b *TokenBucket) Capacity() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capacity
}

// Available returns the currently usable (unspent) tokens. Returns 0 when
// the bucket is in debt (balance > capacity) — debt must be repaid through
// future refills before new reservations can be granted.
func (b *TokenBucket) Available() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	avail := b.capacity - b.balance
	if avail < 0 {
		return 0
	}
	return avail
}

// RetryAfter returns the lower-bound time until amt tokens could be available
// under the current refill configuration. It is advisory telemetry only: a
// concurrent reservation may consume the allowance before the caller retries.
func (b *TokenBucket) RetryAfter(amt float64) time.Duration {
	if b == nil || amt <= 0 {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	avail := b.capacity - b.balance
	if avail >= amt || b.refillPer <= 0 || b.refillIn <= 0 {
		return 0
	}
	deficit := amt - avail
	seconds := deficit / b.refillPer * b.refillIn.Seconds()
	if seconds <= 0 {
		return time.Second
	}
	return time.Duration(seconds*float64(time.Second)) + time.Nanosecond
}

// Take consumes up to `amt` tokens; returns the number actually consumed
// (limits to what is currently available after refill). Atomic.
func (b *TokenBucket) Take(amt float64) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	if amt <= 0 {
		return 0
	}
	avail := b.capacity - b.balance
	if avail <= 0 {
		// In debt — no allowance available until debt is repaid.
		// P0.11 fix: don't let negative avail reduce the debt.
		return 0
	}
	if amt > avail {
		amt = avail
	}
	b.balance += amt
	b.revision++
	return amt
}

// Return refunds tokens, never going below 0 (INV-15). Returns the amount
// actually refunded.
func (b *TokenBucket) Return(amt float64) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if amt <= 0 {
		return 0
	}
	if b.balance >= amt {
		b.balance -= amt
	} else {
		amt = b.balance
		b.balance = 0
	}
	b.revision++
	return amt
}

// Revision returns the mutation counter.
func (b *TokenBucket) Revision() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.revision
}

// Balance returns the spent amount.
func (b *TokenBucket) Balance() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	return b.balance
}

// Evictable reports whether this bucket has no outstanding reservation/debt
// and is fully replenished. It is deliberately stricter than merely being
// idle: evicting a partially spent bucket would reset an attacker's allowance.
func (b *TokenBucket) Evictable() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	return b.balance == 0
}

// Reconfigure swaps a bucket's policy parameters (capacity, refill rate) in
// place (P0.2). A scope's bucket is created on first use; without this, the
// burst/rate in effect at creation time would be frozen forever — a constrained
// credential would keep its original allowance and a restored one would never
// regain it. Refill is applied first so elapsed time is credited under the OLD
// rate (the time already passed), then the new parameters apply to future
// elapsed time. The spent balance is preserved and clamped into the new
// capacity: tightening never mints allowance, loosening never resets accounting.
func (b *TokenBucket) Reconfigure(capacity float64, refillPer float64, refillIn time.Duration) {
	if capacity < 0 || math.IsNaN(capacity) || math.IsInf(capacity, 0) {
		capacity = 0
	}
	if refillPer < 0 || math.IsNaN(refillPer) || math.IsInf(refillPer, 0) {
		refillPer = 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	// refillLocked skips lastRefill advancement entirely when refillIn <= 0;
	// advance it unconditionally here so elapsed time under a zero OLD rate is
	// not re-credited at the NEW rate (a tightening must not mint allowance).
	b.lastRefill = b.now()
	b.capacity = capacity
	b.refillPer = refillPer
	b.refillIn = refillIn
	// P0.11 fix: Do NOT clamp balance to capacity when in debt.
	// Debt must be repaid through future refills, not destroyed by reconfiguration.
	// Clamping balance=1000 to capacity=100 would silently erase 900 units of debt.
	b.revision++
}

// refillLocked adds elapsed refill units, capped at capacity. It is the only
// place time advances the bucket.
func (b *TokenBucket) refillLocked() {
	if b.refillIn <= 0 {
		// no refill configured; balance never shrinks over time
		return
	}
	elapsed := b.now().Sub(b.lastRefill)
	if elapsed <= 0 {
		return
	}
	units := float64(elapsed) / float64(b.refillIn) * b.refillPer
	if units <= 0 {
		return
	}
	if b.balance > 0 {
		b.balance -= units
		if b.balance < 0 {
			b.balance = 0
		}
		b.revision++
	}
	b.lastRefill = b.now()
}

// Reservation is an all-or-nothing hold on bucket capacity (§47 hard
// authorization). Settle and Cancel are each idempotent, and only the
// reservation's own amount is ever released — one request cannot return
// capacity consumed by another (INV-15 settlement). Copies of the handle
// share one settlement state, mirroring LeaseHandle.
type Reservation struct {
	st *reservationState
}

type reservationState struct {
	mu        *sync.Mutex
	b         *TokenBucket
	amount    float64
	done      bool // settled or cancelled exactly once
	cancelled bool
}

// Reserve attempts to secure amt tokens atomically. All-or-nothing: the full
// amount is held or nil is returned (never a partial hold — partial takes are
// too easy to misuse for hard authorization).
func (b *TokenBucket) Reserve(amt float64) *Reservation {
	if amt < 0 || math.IsNaN(amt) || math.IsInf(amt, 0) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	// P0.12 fix: Zero-amount reservations are allowed so Settle(actual) can
	// create debt from zero, but only while the bucket still has positive
	// allowance. If the bucket is already exhausted/debted, deny even a
	// zero-amount reservation.
	avail := b.capacity - b.balance
	if avail <= 0 {
		return nil
	}
	if amt > avail {
		return nil
	}
	b.balance += amt
	b.revision++
	return &Reservation{st: &reservationState{mu: &b.mu, b: b, amount: amt}}
}

// Amount returns the reserved amount.
func (r *Reservation) Amount() float64 {
	if r == nil || r.st == nil {
		return 0
	}
	return r.st.amount
}

// Settle commits the reservation against the ACTUAL usage (P0.36): the
// reserved-but-unused remainder (reserved − actual, never below 0) is
// refunded to THIS reservation's bucket and nothing else. When actual
// exceeds the reserved amount, the overage is charged against the bucket as
// debt — the bucket's balance may exceed its capacity, representing an
// obligation that must be repaid through future refills before new
// reservations can be granted. Ownership-complete: no generic Return sits
// on the settlement path, so one request cannot release capacity another
// consumed, and a settlement can never refund more than its own hold.
// Idempotent; a second Settle (or Settle after Cancel) is a no-op.
func (r *Reservation) Settle(actual float64) {
	if r == nil || r.st == nil {
		return
	}
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	if r.st.done {
		return
	}
	r.st.done = true
	if actual < 0 {
		actual = 0
	}
	if actual <= r.st.amount {
		// Actual <= reserved: refund the unused portion.
		refund := r.st.amount - actual
		if refund <= 0 {
			return
		}
		b := r.st.b
		b.balance -= refund
		if b.balance < 0 {
			b.balance = 0
		}
		b.revision++
		return
	}
	// Actual > reserved: consume the full reservation and charge the overage
	// as debt against the bucket. The bucket's balance may now exceed its
	// capacity — this is intentional debt that must be repaid through future
	// refills before new reservations can be granted.
	overage := actual - r.st.amount
	b := r.st.b
	b.balance += overage
	b.revision++
}

// Cancel releases the full held amount back to the bucket. Idempotent, and a
// no-op after Settle — exactly one of the two outcomes ever fires, so
// settlement can never mint allowance (INV-15).
func (r *Reservation) Cancel() {
	if r == nil || r.st == nil {
		return
	}
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	if r.st.done {
		return
	}
	r.st.done = true
	r.st.cancelled = true
	b := r.st.b
	b.balance -= r.st.amount
	if b.balance < 0 {
		b.balance = 0
	}
	b.revision++
}

// Done reports whether the reservation has been settled or cancelled.
func (r *Reservation) Done() bool {
	if r == nil || r.st == nil {
		return true
	}
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	return r.st.done
}
