package protocollimits

import "testing"

func TestSignerRetirementHorizonCoversAssertionAcceptanceWindow(t *testing.T) {
	if SignerRetirementHorizon < MaxAssertionTTL+AssertionClockSkew {
		t.Fatalf("signer retirement horizon=%s is shorter than assertion acceptance window=%s", SignerRetirementHorizon, MaxAssertionTTL+AssertionClockSkew)
	}
}
