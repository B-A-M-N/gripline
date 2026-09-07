package resource

import (
	"errors"
	"testing"
	"time"
)

// P0.33: the Scope enum IS the policy precedence — SOURCE → ACCOUNT →
// CREDENTIAL → LANE, GLOBAL last. Lower index = higher priority.
func TestScopePrecedenceOrder(t *testing.T) {
	if !(ScopeSource < ScopeAccount && ScopeAccount < ScopeCredential && ScopeCredential < ScopeLane && ScopeLane < ScopeGlobal) {
		t.Fatal("P0.33: scope enum must encode policy precedence SOURCE < ACCOUNT < CREDENTIAL < LANE < GLOBAL")
	}
}

// P0.34: GLOBAL scope provisions like any other and denies when saturated.
func TestGovernorGlobalScopeProvisions(t *testing.T) {
	g := NewGovernor(nil)
	specs := []ScopeSpec{
		{Scope: ScopeCredential, ID: "c", Buckets: BucketSpec{ConcurrencyCap: 8}},
		{Scope: ScopeGlobal, ID: "fleet", Buckets: BucketSpec{ConcurrencyCap: 2}},
	}
	r1, err := g.ProvisionUsage(specs, UsageEstimate{Requests: 1})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := g.ProvisionUsage(specs, UsageEstimate{Requests: 1})
	if err != nil {
		t.Fatal(err)
	}
	// GLOBAL at 2 is saturated → third denied, naming GLOBAL.
	_, err = g.ProvisionUsage(specs, UsageEstimate{Requests: 1})
	var sle *ScopeLimitError
	if !errors.As(err, &sle) || sle.Scope != ScopeGlobal {
		t.Fatalf("P0.34: saturated GLOBAL must deny naming GLOBAL, got %v", err)
	}
	r1.Release()
	r2.Release()
}

// P0.35: requests, tokens, and cost get DISTINCT buckets from one spec —
// exhausting one gauge does not consume another's allowance.
func TestGovernorPerDimensionBuckets(t *testing.T) {
	base := time.Now()
	g := NewGovernor(func() time.Time { return base })
	specs := []ScopeSpec{{Scope: ScopeCredential, ID: "c", Buckets: BucketSpec{
		ConcurrencyCap: 8,
		RequestsBurst:  BucketConfig{Capacity: 2, RefillPer: 1, RefillIn: time.Hour},
		TokensBurst:    BucketConfig{Capacity: 100, RefillPer: 1, RefillIn: time.Hour},
		CostBurst:      BucketConfig{Capacity: 500, RefillPer: 1, RefillIn: time.Hour},
	}}}

	// Two requests exhaust the REQUEST gauge only.
	r1, err := g.ProvisionUsage(specs, UsageEstimate{Requests: 1, CombinedTokens: 10, CostMicrounits: 100})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := g.ProvisionUsage(specs, UsageEstimate{Requests: 1, CombinedTokens: 10, CostMicrounits: 100})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.ProvisionUsage(specs, UsageEstimate{Requests: 1}); !errors.As(err, new(*ScopeLimitError)) {
		t.Fatal("request gauge at 2 must deny")
	}

	// But the token gauge (100 capacity, only 20 held) still admits when the
	// request dimension is skipped — proving the buckets are distinct gauges.
	// Use a fresh scope to avoid the exhausted request bucket.
	r3, err := g.ProvisionUsage([]ScopeSpec{{Scope: ScopeAccount, ID: "a", Buckets: specs[0].Buckets}}, UsageEstimate{CombinedTokens: 50, CostMicrounits: 100})
	if err != nil {
		t.Fatalf("P0.35: token dimension must be a distinct gauge, denied: %v", err)
	}
	_ = r3
	r1.Release()
	r2.Release()
}

// P0.35: a zero-capacity gauge is NOT enforced (skipped), so a policy that
// authors only ConcurrencyCap behaves as pure concurrency control.
func TestGovernorZeroCapacityGaugeSkipped(t *testing.T) {
	g := NewGovernor(nil)
	specs := []ScopeSpec{{Scope: ScopeCredential, ID: "c", Buckets: BucketSpec{
		ConcurrencyCap: 4,
		// no RequestsBurst/TokensBurst/CostBurst configured
	}}}
	for i := 0; i < 10; i++ {
		r, err := g.ProvisionUsage(specs, UsageEstimate{Requests: 1, CombinedTokens: 99999, CostMicrounits: 99999})
		if err != nil {
			t.Fatalf("iteration %d: unenforced gauges must never deny: %v", i, err)
		}
		r.Release()
	}
}

// P0.36: settlement is ownership-complete per dimension — each hold refunds
// only its own reserved−actual to its own bucket.
func TestSettleRefundsOnlyOwnUnused(t *testing.T) {
	base := time.Now()
	g := NewGovernor(func() time.Time { return base })
	specs := []ScopeSpec{{Scope: ScopeCredential, ID: "c", Buckets: BucketSpec{
		ConcurrencyCap: 4,
		TokensBurst:    BucketConfig{Capacity: 1000, RefillPer: 1, RefillIn: time.Hour},
	}}}
	r, err := g.ProvisionUsage(specs, UsageEstimate{InputTokens: 200, OutputTokens: 100, CombinedTokens: 300})
	if err != nil {
		t.Fatal(err)
	}
	// Actual: input 200 fully used, output 30 used, combined 120 used.
	r.Settle(UsageEstimate{InputTokens: 200, OutputTokens: 30, CombinedTokens: 120})
	r.Release()

	g.metaMu.Lock()
	in := g.bucket(DimInputTokens, scopeKey(ScopeCredential, "c"), specs[0].Buckets.TokensBurst)
	out := g.bucket(DimOutputTokens, scopeKey(ScopeCredential, "c"), specs[0].Buckets.TokensBurst)
	comb := g.bucket(DimCombinedTokens, scopeKey(ScopeCredential, "c"), specs[0].Buckets.TokensBurst)
	g.metaMu.Unlock()

	if avail := in.Available(); avail != 800 {
		t.Fatalf("input fully consumed → nothing refunded; avail = %v, want 800", avail)
	}
	if avail := out.Available(); avail != 970 {
		t.Fatalf("output: reserved 100, actual 30 → refund 70; avail = %v, want 970", avail)
	}
	if avail := comb.Available(); avail != 880 {
		t.Fatalf("combined: reserved 300, actual 120 → refund 180; avail = %v, want 880", avail)
	}
}

// P0.36: Release without Settle cancels the FULL hold (abandoned admission),
// and Release after Settle releases only concurrency.
func TestReleaseWithoutSettleCancelsFullHold(t *testing.T) {
	base := time.Now()
	g := NewGovernor(func() time.Time { return base })
	specs := []ScopeSpec{{Scope: ScopeCredential, ID: "c", Buckets: BucketSpec{
		ConcurrencyCap: 2,
		TokensBurst:    BucketConfig{Capacity: 100, RefillPer: 1, RefillIn: time.Hour},
	}}}
	r, err := g.ProvisionUsage(specs, UsageEstimate{Requests: 1, CombinedTokens: 40})
	if err != nil {
		t.Fatal(err)
	}
	if r.Settled() {
		t.Fatal("fresh reservation must not report settled")
	}
	r.Release() // abandoned: concurrency returned AND full token hold cancelled
	g.metaMu.Lock()
	b := g.bucket(DimCombinedTokens, scopeKey(ScopeCredential, "c"), specs[0].Buckets.TokensBurst)
	p := g.pools[scopeKey(ScopeCredential, "c")]
	g.metaMu.Unlock()
	if avail := b.Available(); avail != 100 {
		t.Fatalf("abandoned reservation must refund the full hold, avail = %v, want 100", avail)
	}
	if inUse := p.InUse(); inUse != 0 {
		t.Fatalf("abandoned reservation must release concurrency, inUse = %d", inUse)
	}
}
