package resource

import (
	"errors"
	"sync"
	"time"
)

// Scope identifies the resource-authorization scope dimension (§04-4). The
// ordering matters: a denial at a higher-priority scope dominates, per the
// policy precedence (§58 of the design docs). Lower index = higher priority.
type Scope int

const (
	ScopeSource     Scope = iota // source / network origin
	ScopeLane                    // classified lane
	ScopeCredential              // credential
	ScopeAccount                 // account (tenant)
	ScopeGlobal                  // global fleet
)

func (s Scope) String() string {
	switch s {
	case ScopeSource:
		return "SOURCE"
	case ScopeLane:
		return "LANE"
	case ScopeCredential:
		return "CREDENTIAL"
	case ScopeAccount:
		return "ACCOUNT"
	case ScopeGlobal:
		return "GLOBAL"
	default:
		return "UNKNOWN_SCOPE"
	}
}

// ScopeError is returned when a hard resource limit is exceeded at a specific
// scope. The scope identifies which dimension in the precedence chain denied,
// so the caller can map it to the correct external reason (CredentialLimit vs
// LaneLimit vs AccountLimit, P0.25) instead of collapsing everything into one
// "rate limited" bucket.
var ErrScopeLimit = errors.New("resource: scope hard limit exceeded")

// ScopeLimitError carries the scope that denied.
type ScopeLimitError struct {
	Scope Scope
}

func (e *ScopeLimitError) Error() string {
	return "resource: " + e.Scope.String() + " hard limit exceeded"
}

// Dimension is one resource gauge to enforce per scope. A provision request
// declares which dimensions it consumes; only those are reserved.
type Dimension int

const (
	DimRequests Dimension = iota
	DimConcurrency
	DimInputTokens
	DimOutputTokens
	DimCombinedTokens
	DimCost
)

func (d Dimension) String() string {
	switch d {
	case DimRequests:
		return "requests"
	case DimConcurrency:
		return "concurrency"
	case DimInputTokens:
		return "input_tokens"
	case DimOutputTokens:
		return "output_tokens"
	case DimCombinedTokens:
		return "combined_tokens"
	case DimCost:
		return "cost"
	default:
		return "unknown_dimension"
	}
}

// BucketSpec describes how to build a scope's gauges. A zero RefillIn means
// burst-only (no continuous refill) for that dimension.
type BucketSpec struct {
	ConcurrencyCap int     // max concurrent slots; 0 = deny-all concurrency
	BurstCapacity  float64 // token-bucket capacity for gauge dimensions
	RefillPer      float64
	RefillIn       time.Duration
}

// Governor is a bounded, per-scope resource governor enforcing the policy
// precedence across SOURCE/LANE/CREDENTIAL/ACCOUNT/GLOBAL (§04). It composes
// the atomic ConcurrencyPool (lease accounting, INV-15) and TokenBucket
// (reservation accounting, INV-15) into a single all-or-nothing admission
// surface, so a request either clears EVERY scope's hard limits or holds
// nothing.
//
// All-or-nothing is the security property that matters here (P0.23-P0.27):
// if a request clears SOURCE and LANE but trips CREDENTIAL, the governor must
// not leave SOURCE/LANE leases taken — a partial hold would both reject the
// request AND permanently consume capacity (a leak you can never refund
// because the caller never learned an admission succeeded).
type Governor struct {
	mu     sync.Mutex
	now    func() time.Time
	pools  map[string]*ConcurrencyPool // scopeKey <Scope>:<id> -> pool
	buckets map[Dimension]map[string]*TokenBucket
}

// NewGovernor builds a Governor. now may be nil (defaults to time.Now).
func NewGovernor(now func() time.Time) *Governor {
	if now == nil {
		now = time.Now
	}
	g := &Governor{
		now:     now,
		pools:   make(map[string]*ConcurrencyPool),
		buckets: make(map[Dimension]map[string]*TokenBucket),
	}
	for i := 0; i < int(DimCost)+1; i++ {
		g.buckets[Dimension(i)] = make(map[string]*TokenBucket)
	}
	return g
}

func scopeKey(s Scope, id string) string {
	return s.String() + ":" + id
}

// pool retrieves-or-creates the concurrency pool for a scope key. The
// construction capacity is only the pool's high-water bound — the CURRENT
// policy cap is supplied per acquisition via AcquireNCap (P0.2), so later
// NORMAL→CONSTRAINED (or reverse) transitions take effect immediately without
// recreating the pool or resetting its accounting. Caller holds g.mu.
func (g *Governor) pool(key string, cap int) *ConcurrencyPool {
	if p, ok := g.pools[key]; ok {
		return p
	}
	p := NewConcurrencyPool(cap)
	g.pools[key] = p
	return p
}

// bucket retrieves-or-creates a token bucket for a dimension+scope. On every
// call the bucket is reconfigured to the CURRENT spec (P0.2): the parameters in
// effect at first creation are not frozen — a constrained scope's tightened
// burst/rate applies to the next reservation, and a restored scope's allowance
// returns without resetting accounting. Caller holds g.mu.
func (g *Governor) bucket(dim Dimension, key string, spec BucketSpec) *TokenBucket {
	m := g.buckets[dim]
	if b, ok := m[key]; ok {
		b.Reconfigure(spec.BurstCapacity, spec.RefillPer, spec.RefillIn)
		return b
	}
	b := NewTokenBucket(spec.BurstCapacity, spec.RefillPer, spec.RefillIn, g.now)
	m[key] = b
	return b
}

// ScopeSpec declares the enforced gauges for one scope.
type ScopeSpec struct {
	Scope   Scope
	ID      string
	Buckets BucketSpec
}

// Provision reserves availability across every scope in ss in policy order.
// It is all-or-nothing: on success a MultiReservation is returned holding
// capacity at every scope; on failure (any scope over its hard limit) every
// partial hold is released and a *ScopeLimitError naming the denying scope is
// returned. dims declares which token-bucket dimensions to charge (requests,
// tokens, cost). Concurrency is charged when amt.Concurrency > 0.
//
// The cost amt is per-request consumed amount for each declared dimension. Only
// dimension gauges listed in dims are touched: a call that only cares about
// concurrency (PureAdmission) charges nothing else.
type ProvisionAmt struct {
	Concurrency int
	Tokens      float64 // charged to each token dimension in dims
}

func (g *Governor) Provision(scopes []ScopeSpec, dims []Dimension, amt ProvisionAmt) (*MultiReservation, error) {
	if len(scopes) == 0 {
		return nil, errors.New("resource: no scopes to provision")
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	var acquired []*singleAcquired
	// Rollback on any failure: releases every lease + reservation taken so far.
	defer func() {
		if acquired != nil {
			for i := len(acquired) - 1; i >= 0; i-- {
				acquired[i].release()
			}
		}
	}()

	// Round 1 — concurrency: every scope in precedence order. A failure here
	// names the denying scope directly. Each acquisition supplies the scope's
	// CURRENT policy cap (P0.2): admission is capped at
	// min(pool construction capacity, current cap), so a NORMAL→CONSTRAINED
	// transition throttles the very next request, and a return to NORMAL
	// expands capacity without recreating the pool or resetting accounting.
	for _, sp := range scopes {
		key := scopeKey(sp.Scope, sp.ID)
		p := g.pool(key, sp.Buckets.ConcurrencyCap)
		lease := p.AcquireNCap(amt.Concurrency, sp.Buckets.ConcurrencyCap)
		if lease == nil {
			return nil, &ScopeLimitError{Scope: sp.Scope}
		}
		acquired = append(acquired, &singleAcquired{kind: acquPool, pool: p, lease: lease})
	}

	// Round 2 — token buckets for declared dimensions, per scope precedence.
	for _, dim := range dims {
		for _, sp := range scopes {
			key := scopeKey(sp.Scope, sp.ID)
			b := g.bucket(dim, key, sp.Buckets)
			res := b.Reserve(amt.Tokens)
			if res == nil {
				return nil, &ScopeLimitError{Scope: sp.Scope}
			}
			acquired = append(acquired, &singleAcquired{kind: acquBucket, bucket: b, res: res})
		}
	}

	// Success: detach the rollback list (owned by the caller's reservation).
	hold := &MultiReservation{now: g.now}
	hold.acquired = acquired
	acquired = nil // deferred rollback becomes a no-op
	return hold, nil
}

type acquKind int

const (
	acquPool acquKind = iota
	acquBucket
)

// singleAcquired is one scope's held capacity: either a concurrency lease or a
// token reservation. It owns exactly its own hold and releases at most once
// (INV-15).
type singleAcquired struct {
	kind   acquKind
	pool   *ConcurrencyPool
	lease  *LeaseHandle
	bucket *TokenBucket
	res    *Reservation
}

func (a *singleAcquired) release() {
	switch a.kind {
	case acquPool:
		a.lease.Release()
	case acquBucket:
		a.res.Cancel()
	}
}

// MultiReservation is the all-or-nothing grip across every scope of one
// admitted request. Settle commits all holds (concurrency remains leased until
// the caller Release()s the shared lease; token reservations are consumed).
// Release returns all concurrency to their pools (idempotent across copies).
type MultiReservation struct {
	now      func() time.Time
	acquired []*singleAcquired
	settled  bool
}

// Settle commits all token reservations. Concurrency leases are NOT released
// here — they stay held for the request's lifetime and are returned by Release.
func (r *MultiReservation) Settle() {
	if r == nil {
		return
	}
	for _, a := range r.acquired {
		switch a.kind {
		case acquBucket:
			a.res.Settle()
		}
	}
	r.settled = true
}

// Release returns all held concurrency to their pools (idempotent). It also
// cancels any not-yet-settled token reservations so an abandoned admission
// refunds its token holds (never mints allowance — each cancel is its own
// amount and can only release what was reserved).
func (r *MultiReservation) Release() {
	if r == nil {
		return
	}
	for _, a := range r.acquired {
		a.release()
	}
}

// Leases returns the concurrency leases held, for callers that want to attach
// the lease lifetime to the proxy's request lifecycle separately from tokens.
func (r *MultiReservation) Leases() []*LeaseHandle {
	if r == nil {
		return nil
	}
	var out []*LeaseHandle
	for _, a := range r.acquired {
		if a.kind == acquPool && a.lease != nil {
			out = append(out, a.lease)
		}
	}
	return out
}
// InUseAll reports the total concurrency currently held across every scope
// pool (diagnostics/leak-detection in tests).
func (g *Governor) InUseAll() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	total := 0
	for _, p := range g.pools {
		total += p.InUse()
	}
	return total
}
