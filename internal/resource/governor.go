package resource

import (
	"context"
	"errors"
	"hash/fnv"
	"strconv"
	"strings"
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

// ErrSourceScopeSaturated means a new attacker-controlled source scope could
// not be admitted because every bounded-table entry still carries active or
// recently spent state. The caller should treat this as resource unavailability
// rather than silently growing memory.
var ErrSourceScopeSaturated = errors.New("resource: source scope table saturated")

// ScopeLimitError carries the scope and gauge dimension that denied. Both are
// internal diagnostic data; callers should not expose the exact scope to an
// untrusted client.
type ScopeLimitError struct {
	Scope     Scope
	Dimension Dimension
	// Cause carries an operational saturation reason when the scope table, not
	// the gauge allowance, prevented admission.
	Cause error
	// RetryAfter is a best-effort lower bound for bucket-backed limits. A zero
	// value means the denial was concurrency-only, burst-only, or otherwise has
	// no meaningful automatic retry time.
	RetryAfter time.Duration
}

func (e *ScopeLimitError) Error() string {
	return "resource: " + e.Scope.String() + " hard limit exceeded"
}

// Unwrap preserves the sentinel classification for callers that do not need
// the scope detail. The concrete error remains available through errors.As.
func (e *ScopeLimitError) Unwrap() []error {
	if e == nil || e.Cause == nil {
		return []error{ErrScopeLimit}
	}
	return []error{ErrScopeLimit, e.Cause}
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
	ConcurrencyCap int // max concurrent slots
	// RequestsBurst bounds REQUESTS per window (P0.35).
	RequestsBurst BucketConfig
	// TokensBurst bounds INPUT/OUTPUT/COMBINED token gauges (P0.35).
	TokensBurst BucketConfig
	// CostBurst bounds spend in microunits per window (P0.35).
	CostBurst BucketConfig
}

func (bs BucketSpec) hasNonConcurrencyGauge() bool {
	return bs.RequestsBurst.Capacity > 0 || bs.TokensBurst.Capacity > 0 || bs.CostBurst.Capacity > 0
}

// BucketConfig is one gauge's burst/rate policy (P0.35). A zero Capacity
// disables the gauge at this scope.
type BucketConfig struct {
	Capacity  float64
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
	// metaMu protects scope metadata and the maps that resolve a scope to its
	// independently locked resource objects. It is not held while acquiring or
	// settling a pool/bucket, so unrelated credentials do not serialize behind a
	// process-wide admission mutex (P1-10).
	metaMu  sync.Mutex
	now     func() time.Time
	pools   map[string]*ConcurrencyPool // scopeKey <Scope>:<id> -> pool
	buckets map[Dimension]map[string]*TokenBucket
	// sourceScopes is the bounded metadata table for attacker-controlled SOURCE
	// keys. Entries are removed only after an idle horizon and when every owned
	// gauge is fully idle/replenished.
	sourceScopes      map[string]sourceScopeMeta
	maxSourceScopes   int
	sourceIdle        time.Duration
	sourceEvictions   uint64
	sourceSaturations uint64
	sourceOverflows   uint64
}

type sourceScopeMeta struct{ lastUsed time.Time }

const (
	defaultMaxSourceScopes       = 4096
	defaultSourceScopeIdle       = 10 * time.Minute
	defaultSourceOverflowBuckets = 64
)

// DefaultMaxSourceScopes is the conservative process-local bound used when a
// deployment leaves the source-table limit at zero. Zero in configuration means
// "use this default", never unlimited (P1-11).
const DefaultMaxSourceScopes = defaultMaxSourceScopes

// NewGovernor builds a Governor. now may be nil (defaults to time.Now).
func NewGovernor(now func() time.Time) *Governor {
	if now == nil {
		now = time.Now
	}
	g := &Governor{
		now:             now,
		pools:           make(map[string]*ConcurrencyPool),
		buckets:         make(map[Dimension]map[string]*TokenBucket),
		sourceScopes:    make(map[string]sourceScopeMeta),
		maxSourceScopes: defaultMaxSourceScopes,
		sourceIdle:      defaultSourceScopeIdle,
	}
	for i := 0; i < int(DimCost)+1; i++ {
		g.buckets[Dimension(i)] = make(map[string]*TokenBucket)
	}
	return g
}

// SetSourceScopeLimits configures the bounded table for attacker-controlled
// source pseudonyms. A zero max selects the conservative default; an idle
// horizon of zero retains the conservative default. There is no unlimited
// source-table mode in the production governor (P1-11).
func (g *Governor) SetSourceScopeLimits(max int, idle time.Duration) {
	g.metaMu.Lock()
	defer g.metaMu.Unlock()
	if max > 0 {
		g.maxSourceScopes = max
	} else if max == 0 {
		g.maxSourceScopes = defaultMaxSourceScopes
	}
	if idle > 0 {
		g.sourceIdle = idle
	}
}

// GovernorStats exposes bounded-state utilization without exposing scope IDs.
type GovernorStats struct {
	SourceScopes      int
	MaxSourceScopes   int
	SourceEvictions   uint64
	SourceSaturations uint64
	SourceOverflows   uint64
}

func (g *Governor) Stats() GovernorStats {
	g.metaMu.Lock()
	defer g.metaMu.Unlock()
	return GovernorStats{SourceScopes: len(g.sourceScopes), MaxSourceScopes: g.maxSourceScopes,
		SourceEvictions: g.sourceEvictions, SourceSaturations: g.sourceSaturations,
		SourceOverflows: g.sourceOverflows}
}

// StatsContext is the cancellable diagnostics form used by clustered
// observability. The local governor cannot fail remotely, but it still honors
// cancellation so callers can use one bounded contract for every authority.
func (g *Governor) StatsContext(ctx context.Context) (ResourceStats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ResourceStats{}, err
	}
	g.metaMu.Lock()
	defer g.metaMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ResourceStats{}, err
	}
	stats := ResourceStats{SourceScopes: len(g.sourceScopes)}
	for key, pool := range g.pools {
		stats.ActiveConcurrency += pool.InUse()
		if strings.HasPrefix(key, "SOURCE:") && strings.HasPrefix(strings.TrimPrefix(key, "SOURCE:"), "__source_overflow_") {
			stats.SourceOverflows++
		}
	}
	return stats, nil
}

func (g *Governor) ensureSourceScopeLocked(sp ScopeSpec) (ScopeSpec, error) {
	if sp.Scope != ScopeSource || sp.ID == "" {
		return sp, nil
	}
	key := scopeKey(sp.Scope, sp.ID)
	now := g.now()
	if meta, ok := g.sourceScopes[key]; ok {
		meta.lastUsed = now
		g.sourceScopes[key] = meta
		return sp, nil
	}
	if g.maxSourceScopes > 0 && len(g.sourceScopes) >= g.maxSourceScopes {
		if !g.evictSourceScopeLocked(now) {
			// A saturated global table must not become a denial oracle for every
			// unrelated new source. Fold excess identities into a fixed set of
			// hashed overflow scopes. Their shared allowance is conservative, but
			// one attacker cannot exhaust all future source identities (P1-12).
			g.sourceSaturations++
			g.sourceOverflows++
			sp.ID = sourceOverflowID(sp.ID)
			return sp, nil
		}
	}
	g.sourceScopes[key] = sourceScopeMeta{lastUsed: now}
	return sp, nil
}

func (g *Governor) evictSourceScopeLocked(now time.Time) bool {
	for key, meta := range g.sourceScopes {
		if now.Sub(meta.lastUsed) < g.sourceIdle {
			continue
		}
		if p := g.pools[key]; p != nil && p.InUse() != 0 {
			continue
		}
		for _, byScope := range g.buckets {
			if b := byScope[key]; b != nil && !b.Evictable() {
				goto next
			}
		}
		delete(g.pools, key)
		for _, byScope := range g.buckets {
			delete(byScope, key)
		}
		delete(g.sourceScopes, key)
		g.sourceEvictions++
		return true
	next:
	}
	return false
}

func scopeKey(s Scope, id string) string {
	return s.String() + ":" + id
}

func sourceOverflowID(id string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return "__source_overflow_" + strconv.Itoa(int(h.Sum32()%defaultSourceOverflowBuckets))
}

// pool retrieves-or-creates the concurrency pool for a scope key. The
// construction capacity is only the pool's high-water bound — the CURRENT
// policy cap is supplied per acquisition via AcquireNCap (P0.2), so later
// NORMAL→CONSTRAINED (or reverse) transitions take effect immediately without
// recreating the pool or resetting its accounting. Caller holds g.metaMu.
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
// returns without resetting accounting. Caller holds g.metaMu.
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
	Requests                   int64
	InputTokens                int64
	OutputTokens               int64
	CombinedTokens             int64
	CacheReadInputTokens       int64
	CacheCreationInputTokens   int64
	CacheCreation5mInputTokens int64
	CacheCreation1hInputTokens int64
	CostConservative           bool
	CostMicrounits             int64
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
	return g.ProvisionUsageContext(context.Background(), scopes, est)
}

// Reserve implements the backend-neutral resource authority. The resident
// governor has no durable request replay state, so it delegates to its local
// cancellable reservation path.
func (g *Governor) Reserve(ctx context.Context, req ReserveRequest) (UsageReservation, error) {
	return g.ProvisionUsageContext(ctx, req.Scopes, req.Estimate)
}

// ProvisionUsageContext is the cancellable resource-authority entry point.
// The in-process governor completes quickly, while a clustered implementation
// can use the same contract to abort a remote lease transaction at the
// request boundary.
func (g *Governor) ProvisionUsageContext(ctx context.Context, scopes []ScopeSpec, est UsageEstimate) (*MultiReservation, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if len(scopes) == 0 {
		return nil, errors.New("resource: no scopes to provision")
	}

	// Resolve metadata and resource objects under the metadata lock, then
	// release it before doing any admission work. Each pool and bucket has its
	// own lock, so requests for unrelated scopes do not serialize behind one
	// process-wide admission mutex (P1-10).
	type scopeRuntime struct {
		spec ScopeSpec
		pool *ConcurrencyPool
	}
	runtimes := make([]scopeRuntime, len(scopes))
	bucketRefs := make(map[Dimension][]*TokenBucket)
	g.metaMu.Lock()
	for i, sp := range scopes {
		resolved, err := g.ensureSourceScopeLocked(sp)
		if err != nil {
			g.metaMu.Unlock()
			return nil, &ScopeLimitError{Scope: sp.Scope, Dimension: DimConcurrency, Cause: err}
		}
		runtimes[i].spec = resolved
		key := scopeKey(resolved.Scope, resolved.ID)
		if resolved.Buckets.ConcurrencyCap > 0 || !resolved.Buckets.hasNonConcurrencyGauge() {
			runtimes[i].pool = g.pool(key, resolved.Buckets.ConcurrencyCap)
		}
	}
	for _, dim := range []Dimension{DimRequests, DimInputTokens, DimOutputTokens, DimCombinedTokens, DimCost} {
		refs := make([]*TokenBucket, len(runtimes))
		for i, rt := range runtimes {
			cfg := rt.spec.Buckets.specFor(dim)
			if cfg.Capacity > 0 {
				refs[i] = g.bucket(dim, scopeKey(rt.spec.Scope, rt.spec.ID), cfg)
			}
		}
		bucketRefs[dim] = refs
	}
	g.metaMu.Unlock()

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
	for _, rt := range runtimes {
		sp := rt.spec
		// A zero concurrency cap is disabled when another gauge is authored;
		// otherwise a concurrency-only zero spec retains the historical
		// deny-all behavior for direct resource callers.
		if sp.Buckets.ConcurrencyCap > 0 || !sp.Buckets.hasNonConcurrencyGauge() {
			lease := rt.pool.AcquireNCap(1, sp.Buckets.ConcurrencyCap)
			if lease == nil {
				return nil, &ScopeLimitError{Scope: sp.Scope, Dimension: DimConcurrency}
			}
			acquired = append(acquired, &singleAcquired{kind: acquPool, pool: rt.pool, lease: lease})
		}
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
		for i, rt := range runtimes {
			sp := rt.spec
			cfg := sp.Buckets.specFor(dim)
			if cfg.Capacity <= 0 {
				continue // gauge not enforced at this scope
			}
			// P0.12 fix: Create a reservation even for zero-amount estimates
			// so Settle(actual) can create debt from zero.
			if amount < 0 {
				continue
			}
			b := bucketRefs[dim][i]
			res := b.Reserve(float64(amount))
			if res == nil {
				return nil, &ScopeLimitError{Scope: sp.Scope, Dimension: dim, RetryAfter: b.RetryAfter(float64(amount))}
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
	a.releaseForwarded(false)
}

func (a *singleAcquired) releaseForwarded(forwarded bool) {
	switch a.kind {
	case acquPool:
		a.lease.Release()
	case acquBucket:
		if forwarded {
			// Once the request was handed to the backend, a lost response cannot
			// prove that the provider did not execute it. Consume the estimate
			// conservatively instead of refunding capacity that may already have
			// been spent upstream.
			a.res.Settle(a.res.Amount())
		} else {
			a.res.Cancel()
		}
	}
}

// MultiReservation is the all-or-nothing grip across every scope of one
// admitted request. Settle commits all holds (concurrency remains leased until
// the caller Release()s the shared lease; token reservations are consumed).
// Release returns all concurrency to their pools (idempotent across copies).
type MultiReservation struct {
	now       func() time.Time
	mu        sync.Mutex
	acquired  []*singleAcquired
	settled   bool
	forwarded bool
	released  bool
}

// Settle commits every dimension reservation against the ACTUAL usage.
// P0.13 fix: synchronized with mutex for concurrent safety.
func (r *MultiReservation) Settle(actual UsageEstimate) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.settled {
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

// MarkForwarded records the point after which a transport error is ambiguous:
// the backend may have accepted the request even if no response reaches the
// gateway. Release therefore consumes unsettled estimates after this point.
func (r *MultiReservation) MarkForwarded(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return errors.New("resource: reservation already released")
	}
	r.forwarded = true
	return nil
}

// Renew satisfies the distributed reservation contract. Local holds do not
// expire while owned by the process, so renewal only checks cancellation.
func (r *MultiReservation) Renew(ctx context.Context) error {
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

// SettleContext is the cancellable form used by a backend-neutral proxy.
func (r *MultiReservation) SettleContext(ctx context.Context, actual UsageEstimate) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	r.Settle(actual)
	return nil
}

// ExpiresAt is zero for resident reservations because their lifetime is
// bounded by the owning request and explicit Release.
func (r *MultiReservation) ExpiresAt() time.Time { return time.Time{} }

// Settled reports whether Settle has run.
func (r *MultiReservation) Settled() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.settled
}

// Release returns all held concurrency to their pools (idempotent).
// P0.13 fix: synchronized with mutex for concurrent safety.
func (r *MultiReservation) Release() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return
	}
	r.released = true
	for _, a := range r.acquired {
		a.releaseForwarded(r.forwarded && !r.settled)
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
	g.metaMu.Lock()
	pools := make([]*ConcurrencyPool, 0, len(g.pools))
	for _, p := range g.pools {
		pools = append(pools, p)
	}
	g.metaMu.Unlock()
	total := 0
	for _, p := range pools {
		total += p.InUse()
	}
	return total
}

// InUseFor reports the current concurrency held for a specific scope+id
// (P0.4B: live concurrency value for the ResourceVelocityProducer).
// Returns 0 when the scope has no pool yet (no admissions against it).
func (g *Governor) InUseFor(scope Scope, id string) int {
	g.metaMu.Lock()
	p := g.pools[scopeKey(scope, id)]
	g.metaMu.Unlock()
	if p != nil {
		return p.InUse()
	}
	return 0
}

// AvailableFor reports a gauge's current availability for one scope+dimension
// (diagnostics/observability). Returns (0, false) when no bucket exists —
// i.e. the gauge was never enforced for this scope.
func (g *Governor) AvailableFor(dim Dimension, scope Scope, id string) (float64, bool) {
	g.metaMu.Lock()
	m := g.buckets[dim]
	if m == nil {
		g.metaMu.Unlock()
		return 0, false
	}
	b := m[scopeKey(scope, id)]
	g.metaMu.Unlock()
	if b == nil {
		return 0, false
	}
	return b.Available(), true
}

// RemoveScope removes an idle scope's resource state. It is used when a
// dynamic scope (currently a classified lane) disappears from the durable
// classification set. Active leases, outstanding reservations, or bucket
// debt make the scope non-evictable; returning false preserves that state for
// later cleanup rather than discarding accounting (P1-13).
func (g *Governor) RemoveScope(scope Scope, id string) bool {
	key := scopeKey(scope, id)
	g.metaMu.Lock()
	defer g.metaMu.Unlock()
	if p := g.pools[key]; p != nil && p.InUse() != 0 {
		return false
	}
	for _, byScope := range g.buckets {
		if b := byScope[key]; b != nil && !b.Evictable() {
			return false
		}
	}
	delete(g.pools, key)
	for _, byScope := range g.buckets {
		delete(byScope, key)
	}
	delete(g.sourceScopes, key)
	return true
}
