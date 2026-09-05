package resource

import (
	"sync"
	"time"
)

// TokenBucket models one resource gauge (requests, tokens, cost per scope)
// with capacity, refill rate, and an atomic Take/Return API (§47). It
// implements a token-bucket with continuous refill. Balance reflects
// unavailable-tokens (what's been spent); Take decrements, Return
// increments, never below 0.
type TokenBucket struct {
	mu        sync.Mutex
	now       func() time.Time
	capacity  float64
	refillPer float64 // per refill interval
	refillIn  time.Duration
	balance   float64 // spent/unavailable amount (0..capacity)
	lastRefill time.Time
	revision  int
}

// NewTokenBucket creates a bucket with the given capacity and rate.
// refillPer tokens every refillIn.
func NewTokenBucket(capacity float64, refillPer float64, refillIn time.Duration, now func() time.Time) *TokenBucket {
	if now == nil {
		now = time.Now
	}
	if capacity < 0 {
		capacity = 0
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