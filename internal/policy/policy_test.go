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

// Regression (§57): an inverted risk ladder must be rejected at load time —
// otherwise the state machine would enforce thresholds in the wrong order.
func TestInvertedRiskThresholdsInvalid(t *testing.T) {
	p := Default()
	p.Risk = RiskThresholds{Watch: 90, Constrained: 40, Quarantine: 80}
	if p.IsValid() {
		t.Fatal("inverted threshold ladder must be invalid")
	}
	p2 := Default()
	p2.Risk = RiskThresholds{Watch: 0, Constrained: 55, Quarantine: 80}
	if p2.IsValid() {
		t.Fatal("zero Watch threshold must be invalid")
	}
	p3 := Default()
	p3.Risk = RiskThresholds{Watch: 30, Constrained: 55, Quarantine: 101}
	if p3.IsValid() {
		t.Fatal("quarantine above 100 must be invalid")
	}
	// Equal boundaries are also invalid — each step must strictly increase.
	p4 := Default()
	p4.Risk = RiskThresholds{Watch: 30, Constrained: 30, Quarantine: 80}
	if p4.IsValid() {
		t.Fatal("equal adjacent thresholds must be invalid")
	}
}
