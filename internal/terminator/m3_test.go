package terminator

import (
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
)

// m3Terminator builds a TERMINATE-mode terminator with a MULTI-SCOPE resource
// governor configured (P0.23-P0.27). The governor replaces the legacy
// per-credential concurrency seam at the hard gate.
func m3Terminator(t *testing.T, reg *credential.MemoryRegistry, id string) (*Terminator, *resource.Governor, string) {
	t.Helper()
	// buildCredential seals under its own internal pepper; use the same pep it
	// returns so the ring and the stored verifier agree (matches m1Terminator's
	// contract).
	pep, raw := buildCredential(t, reg, id, credential.StatusNormal, 1)
	signer, _ := GenerateSigner()
	gov := resource.NewGovernor(nil)
	dep := Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: "fi-inference",
		Evidence: evidence.NewMemoryStore(),
		Resource: gov,
	}
	term, err := New(dep)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return term, gov, raw
}

// TestM3MultiscopeHoldCoversPriorityScopes proves the terminator's multi-scope
// gate provisions exactly SOURCE/LANE/CREDENTIAL/ACCOUNT (4 holds) for an
// authorized request, proving P0.23's premise that a single admission is
// bounded across the whole precedence chain, not just one reservoir.
func TestM3MultiscopeHoldCoversPriorityScopes(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	term, _, raw := m3Terminator(t, reg, "cred_m3")

	feat := lane.Features{NetworkASN: "AS1", RegionClass: "us"}
	// P0.4: the source identity rides the request, not the Terminator.
	out := term.AdmitSource(bearerHeaders(raw), feat, TrustedSource{Pseudonym: "src-3"})
	if !out.Authorized {
		t.Fatalf("request should authorize: %s", out.Reason)
	}
	if out.ResourceRes == nil {
		t.Fatal("P0.23: authorized request must carry a multi-scope resource hold")
	}
	if n := len(out.ResourceRes.Leases()); n != 5 {
		t.Fatalf("P0.23/P0.34: hold must carry SOURCE+ACCOUNT+CREDENTIAL+LANE+GLOBAL leases, got %d", n)
	}
	// Release so the test doesn't leak capacity for the rest of the suite.
	out.ResourceRes.Release()
}

// TestM3MultiscopeDeniesWhenScopeSaturated proves the multi-scope gate actually
// denies a real admission when the credential scope is full while keeping the
// public reason scope-agnostic (P0.24/P0.25/P0.8).
func TestM3MultiscopeDeniesWhenScopeSaturated(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	term, gov, raw := m3Terminator(t, reg, "cred_m3")

	feat := lane.Features{NetworkASN: "AS2", RegionClass: "eu"}

	// Saturate the CREDENTIAL scope (cap 1) directly through the governor, as a
	// long-running prior request would. The lane/source/account pools stay open.
	fillSpecs := []resource.ScopeSpec{
		{Scope: resource.ScopeCredential, ID: "cred_m3", Buckets: resource.BucketSpec{ConcurrencyCap: 1}},
	}
	fill, err := gov.ProvisionUsage(fillSpecs, resource.UsageEstimate{Requests: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer fill.Release()

	// Next admission: lane/source/account have room but CREDENTIAL is full → deny
	// while keeping the exact scope in the internal decision trace rather than
	// exposing it to the caller.
	out := term.Admit(bearerHeaders(raw), feat)
	if out.Authorized {
		t.Fatal("P0.23: admission must deny when the credential scope is saturated")
	}
	if out.Reason != "rate_limit" {
		t.Fatalf("P0.8: denial reason = %q, want scope-agnostic rate_limit", out.Reason)
	}
	if out.DenialErr == nil {
		t.Fatal("denial must carry a typed error")
	}
	_ = term
}

func TestM3GlobalRequestTokenAndCostGauges(t *testing.T) {
	tests := []struct {
		name string
		set  func(*policy.Limits)
		est  resource.UsageEstimate
	}{
		{name: "requests", set: func(l *policy.Limits) { l.Requests = policy.BucketConfig{Capacity: 1} }, est: resource.UsageEstimate{Requests: 1}},
		{name: "tokens", set: func(l *policy.Limits) { l.Tokens = policy.BucketConfig{Capacity: 10} }, est: resource.UsageEstimate{CombinedTokens: 10}},
		{name: "cost", set: func(l *policy.Limits) { l.Cost = policy.BucketConfig{Capacity: 10} }, est: resource.UsageEstimate{CostMicrounits: 10}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := credential.NewMemoryRegistry()
			term, _, raw := m3Terminator(t, reg, "cred_global_"+tc.name)
			term.pol.Global = policy.Limits{}
			tc.set(&term.pol.Global)
			first := term.AdmitUsage(bearerHeaders(raw), lane.Features{NetworkASN: "AS-global"}, TrustedSource{}, tc.est)
			if !first.Authorized {
				t.Fatalf("first admission: %s", first.Reason)
			}
			second := term.AdmitUsage(bearerHeaders(raw), lane.Features{NetworkASN: "AS-global"}, TrustedSource{}, tc.est)
			if second.Authorized || second.Reason != "rate_limit" {
				t.Fatalf("second admission=%+v, want scope-agnostic rate_limit", second)
			}
			if second.Trace.ReservationScope != "GLOBAL" || second.Trace.ReservationDimension == "" {
				t.Fatalf("global denial trace=%+v", second.Trace)
			}
			first.Reservation().Release()
		})
	}
}

func TestM3GlobalAllGaugesZeroSkipsScope(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	term, _, raw := m3Terminator(t, reg, "cred_global_zero")
	term.pol.Global = policy.Limits{}
	out := term.AdmitUsage(bearerHeaders(raw), lane.Features{NetworkASN: "AS-global-zero"}, TrustedSource{}, resource.UsageEstimate{Requests: 1})
	if !out.Authorized {
		t.Fatalf("zero global gauges must not create a deny-all scope: %s", out.Reason)
	}
	if out.Trace.ReservationScope == "GLOBAL" {
		t.Fatal("all-zero global profile must not be provisioned")
	}
	out.Reservation().Release()
}
