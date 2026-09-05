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

// Available returns the currently usable (unspent) tokens.
func (b *TokenBucket) Available() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	return b.capacity - b.balance
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
	if amt <= 0 || math.IsNaN(amt) || math.IsInf(amt, 0) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refillLocked()
	if b.capacity-b.balance < amt {
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

// Settle commits the reservation: the held amount is consumed (the refund of
// the unspent remainder is a policy decision made by the caller via a second
// Return on actual usage — settlement itself finalizes the hold). Idempotent.
func (r *Reservation) Settle() {
	if r == nil || r.st == nil {
		return
	}
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	if r.st.done {
		return
	}
	r.st.done = true // amount stays spent: reservation consumed
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
