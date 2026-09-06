package resource

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// securityScopes builds a typical SOURCE → LANE → CREDENTIAL → ACCOUNT chain
// with distinct concurrency caps so precedence and denial are observable.
func securityScopes() []ScopeSpec {
	return []ScopeSpec{
		{Scope: ScopeSource, ID: "src-1", Buckets: BucketSpec{ConcurrencyCap: 4}},
		{Scope: ScopeLane, ID: "lane-1", Buckets: BucketSpec{ConcurrencyCap: 3}},
		{Scope: ScopeCredential, ID: "cred-1", Buckets: BucketSpec{ConcurrencyCap: 2}},
		{Scope: ScopeAccount, ID: "acct-1", Buckets: BucketSpec{ConcurrencyCap: 8}},
	}
}

// TestGovernorAllOrNothingAcrossScopes proves P0.23-P0.27: when a downstream
// scope (CREDENTIAL) is at its hard cap, the upstream scopes (SOURCE/LANE) that
// were already leased MUST be rolled back. A partial hold is a leaked lease.
func TestGovernorAllOrNothingAcrossScopes(t *testing.T) {
	g := NewGovernor(nil)
	scopes := securityScopes()

	// Fill CREDENTIAL (cap 2) to saturation first, through two full admissions.
	for i := 0; i < 2; i++ {
		res, err := g.ProvisionUsage(scopes, UsageEstimate{Requests: 1})
		if err != nil {
			t.Fatalf("provision %d: %v", i, err)
		}
		defer res.Release() // hold both until test end
	}

	// Next admission: SOURCE/LANE have room, CREDENTIAL is full → deny, and the
	// SOURCE/LANE partial holds MUST be returned (rollback).
	_, err := g.ProvisionUsage(scopes, UsageEstimate{Requests: 1})
	if err == nil {
		t.Fatal("P0.23: admission must fail when CREDENTIAL is at cap")
	}
	var sle *ScopeLimitError
	if !errors.As(err, &sle) {
		t.Fatalf("P0.24: want ScopeLimitError, got %T", err)
	}
	if sle.Scope != ScopeCredential {
		t.Fatalf("P0.25: denying scope = %v, want CREDENTIAL", sle.Scope)
	}

	// Rollback proof: the SOURCE and LANE pools must have their FULL capacity
	// back (the failed admission's partial holds were released).
	g.mu.Lock()
	src := g.pools[scopeKey(ScopeSource, "src-1")]
	lane := g.pools[scopeKey(ScopeLane, "lane-1")]
	g.mu.Unlock()
	if got := src.Balance(); got != 4-2 {
		t.Fatalf("P0.23: SOURCE balance = %d, want %d (2 held by live admissions, failed one rolled back)", got, 4-2)
	}
	if got := lane.Balance(); got != 3-2 {
		t.Fatalf("P0.23: LANE balance = %d, want %d (failed partial hold must be returned)", got, 3-2)
	}
}

// TestGovernorHighestPriorityOpensAfterRelease proves capacity returns on
// Release and a previously-denied scope authorizes again (correct lifetime).
func TestGovernorHighestPriorityOpensAfterRelease(t *testing.T) {
	g := NewGovernor(nil)
	scopes := securityScopes()

	var res []*MultiReservation
	for i := 0; i < 2; i++ {
		r, err := g.ProvisionUsage(scopes, UsageEstimate{Requests: 1})
		if err != nil {
			t.Fatal(err)
		}
		res = append(res, r)
	}
	// Full credential → third denied.
	if _, err := g.ProvisionUsage(scopes, UsageEstimate{Requests: 1}); err == nil {
		t.Fatal("expected deny at capacity")
	}
	// Release one admission → credential capacity freed → next succeeds.
	res[0].Release()
	if _, err := g.ProvisionUsage(scopes, UsageEstimate{Requests: 1}); err != nil {
		t.Fatalf("P0.25: after release the credential scope must authorize, got %v", err)
	}
}

// TestGovernorDenyAllScope proves a cap-0 scope refuses every admission without
// leaking upstream capacity (P0.24: capacity 0 means deny-all, and rollback
// still applies).
func TestGovernorDenyAllScope(t *testing.T) {
	g := NewGovernor(nil)
	scopes := []ScopeSpec{
		{Scope: ScopeSource, ID: "s", Buckets: BucketSpec{ConcurrencyCap: 4}},
		{Scope: ScopeLane, ID: "l", Buckets: BucketSpec{ConcurrencyCap: 0}}, // deny-all lane
	}
	_, err := g.ProvisionUsage(scopes, UsageEstimate{Requests: 1})
	if err == nil {
		t.Fatal("cap-0 scope must deny")
	}
	var sle *ScopeLimitError
	errors.As(err, &sle)
	if sle == nil || sle.Scope != ScopeLane {
		t.Fatalf("want LANE denial, got %+v", err)
	}
	g.mu.Lock()
	src := g.pools[scopeKey(ScopeSource, "s")]
	g.mu.Unlock()
	if got := src.Balance(); got != 4 {
		t.Fatalf("SOURCE must be fully rolled back after LANE deny-all, balance=%d", got)
	}
}

// TestGovernorTokenSettleConsumesCancelRefunds proves reservation semantics:
// Settle consumes the tokens, Cancel (via Release-before-settle) refunds them,
// and accounting can never go negative across either path (INV-15).
func TestGovernorTokenSettleConsumesCancelRefunds(t *testing.T) {
	base := time.Now()
	g := NewGovernor(func() time.Time { return base })
	scopes := []ScopeSpec{
		{Scope: ScopeCredential, ID: "c", Buckets: BucketSpec{
			ConcurrencyCap: 4, TokensBurst: BucketConfig{Capacity: 100, RefillPer: 10, RefillIn: time.Second},
		}},
	}
	// First admission reserves 30 tokens; settle with ACTUAL 10 → only the
	// unused 20 is refunded, 10 is consumed (P0.36 ownership-complete settle).
	r1, err := g.ProvisionUsage(scopes, UsageEstimate{CombinedTokens: 30})
	if err != nil {
		t.Fatal(err)
	}
	r1.Settle(UsageEstimate{CombinedTokens: 10})
	r1.Release() // concurrency returns, tokens stay settled

	g.mu.Lock()
	b := g.bucket(DimCombinedTokens, scopeKey(ScopeCredential, "c"), scopes[0].Buckets.TokensBurst)
	g.mu.Unlock()
	afterSettle := b.Available()
	if afterSettle != 90 {
		t.Fatalf("settle(actual 10) must consume 10 and refund 20; available = %v, want 90", afterSettle)
	}

	// Second admission reserves 40 but the request aborts → Release (not Settle)
	// refunds the reservation.
	r2, err := g.ProvisionUsage(scopes, UsageEstimate{CombinedTokens: 40})
	if err != nil {
		t.Fatal(err)
	}
	// While held, availability drops by 40.
	if held := b.Available(); held != 50 {
		t.Fatalf("reservation must temporarily hold tokens; available = %v, want 50", held)
	}
	// Abandon → release → the full 40 is refunded back to the pre-hold level.
	r2.Release()
	if avail := b.Available(); avail != afterSettle {
		t.Fatalf("P0.27: abandoned reservation must refund its 40 tokens; available = %v, want %v", avail, afterSettle)
	}

	// P0.36: an actual ABOVE the estimate consumes the whole hold — never a
	// negative refund, never minted allowance.
	r3, err := g.ProvisionUsage(scopes, UsageEstimate{CombinedTokens: 10})
	if err != nil {
		t.Fatal(err)
	}
	r3.Settle(UsageEstimate{CombinedTokens: 999})
	if avail := b.Available(); avail != 80 {
		t.Fatalf("over-estimate actual must consume the full hold; available = %v, want 80", avail)
	}
	r3.Release()
}

// TestGovernorBalanceNeverNegative is a concurrent stress: many goroutines
// provision/release, and total balance across the pool never drops below 0 and
// never exceeds capacity (settlement never mints).
func TestGovernorBalanceNeverNegative(t *testing.T) {
	g := NewGovernor(nil)
	scopes := []ScopeSpec{{Scope: ScopeCredential, ID: "c", Buckets: BucketSpec{ConcurrencyCap: 8}}}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				r, err := g.ProvisionUsage(scopes, UsageEstimate{Requests: 1})
				if err != nil {
					// A denial is legal under concurrency; just don't double-release.
					continue
				}
				r.Settle(UsageEstimate{Requests: 1})
				r.Release()
			}
		}()
	}
	wg.Wait()

	g.mu.Lock()
	p := g.pools[scopeKey(ScopeCredential, "c")]
	g.mu.Unlock()
	if bal := p.Balance(); bal != 8 {
		t.Fatalf("P0.27/INV-15: final balance = %d, want 8 (must return to full, never negative)", bal)
	}
}