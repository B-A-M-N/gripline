package policy

import (
	"errors"
	"testing"
)

func TestDefaultPolicyValid(t *testing.T) {
	p := Default()
	if !p.IsValid() {
		t.Fatal("default policy should be valid")
	}
	if p.Identity.MaxTTLSeconds != 30 {
		t.Fatalf("default identity TTL = %d, want 30 (INV-10)", p.Identity.MaxTTLSeconds)
	}
	if p.MaxIdentityTTLSeconds() > 60 {
		t.Fatal("identity TTL must never exceed 60s upper bound")
	}
}

func TestInvalidPolicy(t *testing.T) {
	bad := &Policy{ID: ""}
	if bad.IsValid() {
		t.Fatal("empty-ID policy must be invalid")
	}
	bad2 := &Policy{ID: "x", Revision: 0, Identity: Identity{MaxTTLSeconds: 0}}
	if bad2.IsValid() {
		t.Fatal("revision 0 / TTL 0 policy must be invalid")
	}
}

// TestEnforcementPrecedence verifies §58: more severe denial wins.
func TestEnforcementPrecedence(t *testing.T) {
	p := Default()

	cases := []struct {
		name string
		in   EvalInput
		want error
	}{
		{"revoked wins over everything", EvalInput{CredentialRevoked: true, RiskDenied: true, LaneOverLimit: true}, ErrRevoked},
		{"emergency over source/risk", EvalInput{Emergency: true, SourceBlocked: true, RiskDenied: true}, ErrEmergencyBlock},
		{"source block over hard limits", EvalInput{SourceBlocked: true, AccountOverLimit: true, CredentialOverLimit: true}, ErrSourceBlock},
		{"account over credential", EvalInput{AccountOverLimit: true, CredentialOverLimit: true}, ErrAccountLimit},
		{"credential over lane", EvalInput{CredentialOverLimit: true, LaneOverLimit: true}, ErrCredentialLimit},
		{"lane over risk", EvalInput{LaneOverLimit: true, RiskDenied: true}, ErrLaneLimit},
		{"risk denial alone", EvalInput{RiskDenied: true}, ErrRiskDenial},
		{"no denial", EvalInput{}, nil},
	}
	for _, c := range cases {
		got := p.Evaluate(c.in)
		if !errors.Is(got, c.want) {
			t.Errorf("%s: Evaluate()=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestMorePermissiveLowerPolicyCannotOverride(t *testing.T) {
	// Even if risk is low, a revoked credential must deny (§58).
	p := Default()
	if err := p.Evaluate(EvalInput{CredentialRevoked: true}); err != ErrRevoked {
		t.Fatal("revoked must deny regardless of other state")
	}
}
