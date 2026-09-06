package resource

import (
	"errors"
	"sync"
	"time"
)

// Scope identifies the resource-authorization scope dimension (§04-4). The
// ordering IS the policy precedence (§58, P0.33): after revoked/emergency,
// hard-limit denials resolve SOURCE → ACCOUNT → CREDENTIAL → LANE. Lower
// index = higher priority. This enum is the ONE statement of that order; the
// governor iterates specs in slice order but denial naming, terminator reason
// mapping, and any future scope tables must derive from this constant block —
// never from a second hand-restated list in another package.
type Scope int

const (
	ScopeSource     Scope = iota // source / network origin
	ScopeAccount                 // account (tenant)
	ScopeCredential              // credential
	ScopeLane                    // classified lane
	ScopeGlobal                  // global fleet (P0.34: whole-plane gauge)
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
//
// P0.35: the three token gauges are DIFFERENT resources and get different
// buckets. RequestsBurst bounds request velocity; TokensBurst bounds token
// velocity (input+output+combined share the token policy multiplier today but
// are distinct gauges); CostBurst bounds spend. A zero BurstCapacity on a
// dimension means that dimension is NOT enforced at this scope (no bucket);
// concurrency is governed separately by ConcurrencyCap.
type BucketSpec struct {
	ConcurrencyCap int // max concurrent slots; 0 = deny-all concurrency
	// RequestsBurst bounds REQUESTS per window (P0.35).
	RequestsBurst BucketConfig
	// TokensBurst bounds INPUT/OUTPUT/COMBINED token gauges (P0.35).
	TokensBurst BucketConfig
	// CostBurst bounds spend in microunits per window (P0.35).
	CostBurst BucketConfig
}

// BucketConfig is one gauge's burst/rate policy (P0.35). A zero Capacity
// disables the gauge at this scope.
type BucketConfig struct {
	Capacity float64
	RefillPer float64
	RefillIn  time.Duration
}

// specFor selects the per-dimension gauge config (P0.35): requests, tokens,
// and cost each get their OWN bucket parameters instead of one shared spec.
func (bs BucketSpec) specFor(dim Dimension) BucketConfig {
	switch dim {
	case DimRequests:
		return bs.RequestsBurst
	case DimInputTokens, DimOutputTokens, DimCombinedTokens:
		return bs.TokensBurst
	case DimCost:
		return bs.CostBurst
	default:
		return BucketConfig{}
	}
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
// call the bucket is reconfigured to the CURRENT config (P0.2): the parameters
// in effect at first creation are not frozen — a constrained scope's tightened
// burst/rate applies to the next reservation, and a restored scope's allowance
// returns without resetting accounting. Caller holds g.mu.
func (g *Governor) bucket(dim Dimension, key string, cfg BucketConfig) *TokenBucket {
	m := g.buckets[dim]
	if b, ok := m[key]; ok {
		b.Reconfigure(cfg.Capacity, cfg.RefillPer, cfg.RefillIn)
		return b
	}
	b := NewTokenBucket(cfg.Capacity, cfg.RefillPer, cfg.RefillIn, g.now)
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

// UsageEstimate is the typed, per-dimension usage of one request (P0.3).
// Integers everywhere: tokens are integers by nature and float accounting on
// cost invites drift. Cost is integer MICROUNITS (1e-6 of a currency unit) so
// tiny per-request costs still accumulate exactly.
//
// The provider adapter supplies what is knowable before execution (request
// body size → input-token estimate; requested max_tokens → output estimate);
// admission reserves the ESTIMATE across every scope, and the reservation is
// SETTLED with the actual usage after execution — refunding only reserved-
// but-unused amounts (P0.36: ownership-complete settlement).
type UsageEstimate struct {
	Requests       int64
	InputTokens    int64
	OutputTokens   int64
	CombinedTokens int64
	CostMicrounits int64
}

// amountFor returns the reserved amount for one gauge dimension.
func (u UsageEstimate) amountFor(dim Dimension) int64 {
	switch dim {
	case DimRequests:
		return u.Requests
	case DimInputTokens:
		return u.InputTokens
	case DimOutputTokens:
		return u.OutputTokens
	case DimCombinedTokens:
		return u.CombinedTokens
	case DimCost:
		return u.CostMicrounits
	default:
		return 0
	}
}

// ProvisionUsage is the P0.3 admission path: an atomic estimate-based reserve
// across every scope for EVERY dimension the estimate carries, with a
// settlement handle that accepts the ACTUAL usage. Concurrency is always
// charged (1 slot) when amt > 0. Token dimensions with a zero estimate are
// not reserved (nothing to refund later); the policy may still bound them at
// settle-time through the same buckets.
func (g *Governor) ProvisionUsage(scopes []ScopeSpec, est UsageEstimate) (*MultiReservation, error) {
	if len(scopes) == 0 {
		return nil, errors.New("resource: no scopes to provision")
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	var acquired []*singleAcquired
	defer func() {
		if acquired != nil {
			for i := len(acquired) - 1; i >= 0; i-- {
				acquired[i].release()
			}
		}
	}()

	// Round 1 — concurrency, in precedence order, each scope at its CURRENT
	// policy cap (P0.2).
	for _, sp := range scopes {
		p := g.pool(scopeKey(sp.Scope, sp.ID), sp.Buckets.ConcurrencyCap)
		lease := p.AcquireNCap(1, sp.Buckets.ConcurrencyCap)
		if lease == nil {
			return nil, &ScopeLimitError{Scope: sp.Scope}
		}
		acquired = append(acquired, &singleAcquired{kind: acquPool, pool: p, lease: lease})
	}

	// Round 2 — one bucket reservation per dimension the estimate carries,
	// per scope, in precedence order. A dimension whose scope config has zero
	// capacity is NOT enforced at that scope (P0.35) and is skipped — reserving
	// against a capacity-0 bucket would deny every request. The reservation
	// remembers ITS amount so Settle(actual) can refund reserved−actual
	// against the same bucket (P0.36 ownership: only the reservation refunds
	// its own unused amount).
	for _, dim := range []Dimension{DimRequests, DimInputTokens, DimOutputTokens, DimCombinedTokens, DimCost} {
		amount := est.amountFor(dim)
		if amount <= 0 {
			continue
		}
		for _, sp := range scopes {
			cfg := sp.Buckets.specFor(dim)
			if cfg.Capacity <= 0 {
				continue // gauge not enforced at this scope
			}
			key := scopeKey(sp.Scope, sp.ID)
			b := g.bucket(dim, key, cfg)
			res := b.Reserve(float64(amount))
			if res == nil {
				return nil, &ScopeLimitError{Scope: sp.Scope}
			}
			acquired = append(acquired, &singleAcquired{kind: acquBucket, bucket: b, res: res, dim: dim})
		}
	}

	hold := &MultiReservation{now: g.now}
	hold.acquired = acquired
	acquired = nil
	return hold, nil
}

type acquKind int

const (
	acquPool acquKind = iota
	acquBucket
)

// singleAcquired is one scope's held capacity: either a concurrency lease or a
// token reservation. It owns exactly its own hold and releases at most once
// (INV-15). dim records which gauge the reservation is against so settlement
// can attribute actual usage per dimension (P0.36).
type singleAcquired struct {
	kind   acquKind
	pool   *ConcurrencyPool
	lease  *LeaseHandle
	bucket *TokenBucket
	res    *Reservation
	dim    Dimension
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

// Settle commits every dimension reservation against the ACTUAL usage (P0.3/
// P0.36): each hold refunds only its own reserved−actual remainder, to its own
// bucket. An actual above the estimate consumes the full hold (overage is
// charged against future capacity through the buckets' refill, never negative
// refunded). Concurrency leases are NOT released here — they stay held for the
// request's lifetime and are returned by Release. Idempotent.
func (r *MultiReservation) Settle(actual UsageEstimate) {
	if r == nil {
		return
	}
	for _, a := range r.acquired {
		switch a.kind {
		case acquBucket:
			a.res.Settle(float64(actual.amountFor(a.dim)))
		}
	}
	r.settled = true
}

// Settled reports whether Settle has run (diagnostics; the proxy uses it to
// guarantee settle-then-release ordering).
func (r *MultiReservation) Settled() bool {
	if r == nil {
		return false
	}
	return r.settled
}

// Release returns all held concurrency to their pools (idempotent). Any
// not-yet-settled token reservation is CANCELLED so an abandoned admission
// refunds its full token hold (never mints allowance — each cancel is its own
// amount and can only release what was reserved). Settle-then-Release is the
// normal completion order: settled dimensions are already done, so Release
// only returns concurrency.
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

// AvailableFor reports a gauge's current availability for one scope+dimension
// (diagnostics/observability). Returns (0, false) when no bucket exists —
// i.e. the gauge was never enforced for this scope.
func (g *Governor) AvailableFor(dim Dimension, scope Scope, id string) (float64, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := g.buckets[dim]
	if m == nil {
		return 0, false
	}
	b, ok := m[scopeKey(scope, id)]
	if !ok {
		return 0, false
	}
	return b.Available(), true
}
