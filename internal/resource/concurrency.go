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
//
// The idempotency state lives in a shared *leaseState, NOT in the struct
// itself: Go structs are freely copyable, and a `copy := *lease` with inline
// state would carry its own `released` flag while pointing at the same pool —
// enabling a double refund through the copy. With shared state, every copy of
// the handle releases the same lease exactly once.
type LeaseHandle struct {
	st *leaseState
}

// leaseState is the release-once record shared by all copies of a handle.
type leaseState struct {
	mu       *sync.Mutex
	balance  *int
	released bool
	slots    int // how many slots this lease owns
}

// Release returns exactly the leased slots to the pool. Idempotent — across
// every copy of the handle.
func (h *LeaseHandle) Release() {
	if h == nil || h.st == nil {
		return
	}
	h.st.mu.Lock()
	defer h.st.mu.Unlock()
	if h.st.released {
		return
	}
	*h.st.balance += h.st.slots
	h.st.released = true
}

// Released reports whether the lease has already been released (through any
// copy of the handle).
func (h *LeaseHandle) Released() bool {
	if h == nil || h.st == nil {
		return true
	}
	h.st.mu.Lock()
	defer h.st.mu.Unlock()
	return h.st.released
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
// lease owns exactly n slots and Release returns exactly n (once, across all
// copies of the handle).
func (p *ConcurrencyPool) AcquireN(n int) *LeaseHandle {
	if n < 0 {
		n = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if n == 0 {
		return &LeaseHandle{st: &leaseState{mu: &p.mu, balance: &p.balance, released: true, slots: 0}}
	}
	if p.balance < n {
		return nil
	}
	p.balance -= n
	return &LeaseHandle{st: &leaseState{mu: &p.mu, balance: &p.balance, released: false, slots: n}}
}
