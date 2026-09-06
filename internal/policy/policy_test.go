package policy

import (
	"errors"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
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

	// Down-thresholds must be below escalation thresholds.
	p5 := Default()
	p5.Risk.WatchDownThresh = 40 // above Watch=30
	if p5.IsValid() {
		t.Fatal("WatchDownThresh must be below Watch")
	}
	p6 := Default()
	p6.Risk.ConstrainedDownThresh = 60 // above Constrained=55
	if p6.IsValid() {
		t.Fatal("ConstrainedDownThresh must be below Constrained")
	}

	// Dwell times must be positive.
	p7 := Default()
	p7.Risk.WatchDwell = 0
	if p7.IsValid() {
		t.Fatal("zero WatchDwell must be invalid")
	}
	p8 := Default()
	p8.Risk.ConstrainedDwell = -time.Minute
	if p8.IsValid() {
		t.Fatal("negative ConstrainedDwell must be invalid")
	}

	// WatchObs must be at least 1.
	p9 := Default()
	p9.Risk.WatchObs = 0
	if p9.IsValid() {
		t.Fatal("WatchObs=0 must be invalid")
	}

	// Promotion criteria validation.
	p10 := Default()
	p10.Learning.MaxEstablishmentRisk = 101
	if p10.IsValid() {
		t.Fatal("MaxEstablishmentRisk above 100 must be invalid")
	}
	p11 := Default()
	p11.Learning.MaxEstablishmentRisk = -1
	if p11.IsValid() {
		t.Fatal("negative MaxEstablishmentRisk must be invalid")
	}
}

// P0.11: the compiled policy revision must carry BOTH the evidence rule table
// and the lane-classification cutoffs, so the data plane classifies lanes and
// mints evidence against the versioned artifact — not package globals. A policy
// missing these (empty evidence table / degenerate classification) must FAIL
// CLOSED at validation.
func TestPolicyCarriesEvidenceRulesAndClassification(t *testing.T) {
	p := Default()
	if len(p.EvidenceRules) == 0 {
		t.Fatal("compiled policy must carry an evidence rule table (P0.11)")
	}
	if p.Classification.Match <= p.Classification.Related {
		t.Fatal("compiled policy classification must have Match > Related (P0.11)")
	}
	if p.Classification.MinComparableWeight <= 0 {
		t.Fatal("compiled policy anti-laundering floor must be non-zero (P0.9/P0.11)")
	}
	// The compiled default must agree with the spec baseline so behavior is
	// unchanged for a default policy.
	if p.Classification.MinComparableWeight != lane.DefaultThresholds().MinComparableWeight {
		t.Fatal("compiled default floor diverges from lane.DefaultThresholds baseline")
	}
	// NEW_LANE + the core risk codes must be mintable from the compiled table.
	if _, err := evidence.Mint(p.EvidenceRules, "NEW_LANE", "subject", time.Now(), p.Revision); err != nil {
		t.Fatalf("compiled evidence table must mint NEW_LANE: %v", err)
	}
}

// P0.11 fail-closed: a policy carrying NO evidence rules (or degenerate lane
// classification) is rejected by IsValid — the data plane must not silently
// fall back to global defaults.
func TestPolicyFailsClosedWithoutEvidenceRules(t *testing.T) {
	noRules := Default()
	noRules.EvidenceRules = nil
	if noRules.IsValid() {
		t.Fatal("policy with nil evidence table must be invalid (P0.11 fail-closed)")
	}
	emptyRules := Default()
	emptyRules.EvidenceRules = map[string]evidence.Rule{}
	if emptyRules.IsValid() {
		t.Fatal("policy with empty evidence table must be invalid (P0.11 fail-closed)")
	}
	degenerate := Default()
	degenerate.Classification.Match = degenerate.Classification.Related
	if degenerate.IsValid() {
		t.Fatal("policy with Match <= Related classification must be invalid (P0.11)")
	}
}
