// Package resource enforces hard resource authorization independently of
// anomaly scoring (spec §46-51, INV-9, INV-15). Concurrency is represented as
// atomic leases; accounting never becomes negative because a lease owns an
// exact number of slots and releases at most once.
package resource

import "sync"

// LeaseHandle is an acquired concurrency slot (or N slots from AcquireN).
// Release is idempotent: releasing more than once never returns more
// concurrency than was acquired (INV-15 — accounting cannot go negative;
// settlement cannot mint allowance).
type LeaseHandle struct {
	mu       *sync.Mutex
	balance  *int
	released bool
	slots    int // how many slots this lease owns
}

// Release returns exactly the leased slots to the pool. Idempotent.
func (h *LeaseHandle) Release() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released {
		return
	}
	*h.balance += h.slots
	h.released = true
}

// Released reports whether the lease has already been released.
func (h *LeaseHandle) Released() bool {
	if h == nil {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.released
}

// ConcurrencyPool is an atomic, capacity-bounded lease pool for one resource
// scope (e.g. a credential or lane). Safe for concurrent use.
//
// In production the pool is backed by a shared store where leases carry a TTL
// ≥ expected request duration or are renewed while an active request lives
// (§48-49); orphaned leases expire and the store replenishes. This in-memory
// pool models exactly the atomic accounting invariant that must hold under any
// backing store — balance never goes negative.
type ConcurrencyPool struct {
	mu       sync.Mutex
	capacity int
	balance  int // currently free slots
}

// NewConcurrencyPool creates a pool with `capacity` concurrent slots.
// Capacity 0 means deny-all for that scope.
func NewConcurrencyPool(capacity int) *ConcurrencyPool {
	if capacity < 0 {
		capacity = 0
	}
	return &ConcurrencyPool{capacity: capacity, balance: capacity}
}

// Capacity returns the configured maximum concurrency.
func (p *ConcurrencyPool) Capacity() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.capacity
}

// Balance returns the currently free slots.
func (p *ConcurrencyPool) Balance() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.balance
}

// InUse returns capacity - balance, clamped at 0 so it never reports negative.
func (p *ConcurrencyPool) InUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	u := p.capacity - p.balance
	if u < 0 {
		u = 0
	}
	return u
}

// Acquire reserves one slot and returns a lease; nil if at capacity.
func (p *ConcurrencyPool) Acquire() *LeaseHandle {
	return p.AcquireN(1)
}

// AcquireN reserves n slots atomically if all are free, else nil. The returned
// lease owns exactly n slots and Release returns exactly n.
func (p *ConcurrencyPool) AcquireN(n int) *LeaseHandle {
	if n < 0 {
		n = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if n == 0 {
		return &LeaseHandle{mu: &p.mu, balance: &p.balance, released: true, slots: 0}
	}
	if p.balance < n {
		return nil
	}
	p.balance -= n
	return &LeaseHandle{mu: &p.mu, balance: &p.balance, released: false, slots: n}
}