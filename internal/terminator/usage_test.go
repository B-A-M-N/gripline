package terminator

import (
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// usageTerminator builds a governor-backed terminator whose CREDENTIAL scope
// enforces a token gauge, returning the governor for balance inspection.
func usageTerminator(t *testing.T, cp *control.ControlPlane) (*Terminator, *resource.Governor, string) {
	t.Helper()
	pol := policy.Default()
	// Burst-only token gauge (no continuous refill) so float comparisons are exact.
	pol.Limits.Normal.Tokens = policy.BucketConfig{Capacity: 100}

	pep := &credential.PepperKey{Version: 1, Key: []byte("usage-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('u' + i%26)
	}
	raw := "sk-usage-" + string(rawBytes)
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_usage", AccountID: "acct_u",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	gov := resource.NewGovernor(nil)
	signer, _ := GenerateSigner()
	term, err := New(Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: pol, Signer: signer,
		Audience: "fi-inference", Evidence: evidence.NewMemoryStore(),
		Resource: gov, Control: cp,
	})
	if err != nil {
		t.Fatal(err)
	}
	return term, gov, raw
}

// P0.3 end-to-end at the terminator: the typed estimate is RESERVED at
// admission and the proxy-side settle charges only the ACTUAL — the unused
// remainder returns to the credential's token gauge.
func TestAdmitUsageReservesAndSettlesActual(t *testing.T) {
	term, gov, raw := usageTerminator(t, nil)

	feat := lane.Features{NetworkASN: "AS1"}
	out := term.AdmitUsage(bearerHeaders(raw), feat, TrustedSource{}, resource.UsageEstimate{
		Requests: 1, CombinedTokens: 30,
	})
	if !out.Authorized {
		t.Fatalf("should authorize: %s", out.Reason)
	}
	if out.ResourceRes == nil {
		t.Fatal("governor-backed admission must carry the multi-scope reservation")
	}

	// While held: 30 of 100 tokens reserved.
	availOf := func() float64 {
		v, ok := gov.AvailableFor(resource.DimCombinedTokens, resource.ScopeCredential, "cred_usage")
		if !ok {
			t.Fatal("credential token gauge must exist after an estimated admission")
		}
		return v
	}
	if avail := availOf(); avail != 70 {
		t.Fatalf("estimate must reserve 30 tokens; avail = %v, want 70", avail)
	}

	// Backend done: actual usage 10 → refund 20.
	out.ResourceRes.Settle(resource.UsageEstimate{Requests: 1, CombinedTokens: 10})
	out.ResourceRes.Release()
	if avail := availOf(); avail != 90 {
		t.Fatalf("settle(actual 10) must consume 10, refund 20; avail = %v, want 90", avail)
	}

	// Abandoned admission (never settled): Release refunds the FULL hold.
	out2 := term.AdmitUsage(bearerHeaders(raw), feat, TrustedSource{}, resource.UsageEstimate{CombinedTokens: 40})
	if !out2.Authorized {
		t.Fatalf("second admission: %s", out2.Reason)
	}
	out2.ResourceRes.Release()
	if avail := availOf(); avail != 90 {
		t.Fatalf("abandoned hold must refund in full; avail = %v, want 90", avail)
	}
}

// P0.48: EMERGENCY_LOCKDOWN throttles ESTABLISHED traffic with the policy's
// Emergency limit set — here cap 1, so a second concurrent admission is denied
// even though the Normal cap (8) would allow it.
func TestEmergencyLimitsThrottleEstablishedTraffic(t *testing.T) {
	cp := control.New(64)
	pol := policy.Default()
	pol.Limits.Normal.ConcurrencyCap = 8
	pol.Limits.Emergency.ConcurrencyCap = 1

	pep := &credential.PepperKey{Version: 1, Key: []byte("emg-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('e' + i%26)
	}
	raw := "sk-emg-" + string(rawBytes)
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_emg", AccountID: "acct_e",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := GenerateSigner()
	term, err := New(Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: pol, Signer: signer,
		Audience: "fi-inference", Evidence: evidence.NewMemoryStore(),
		Resource: resource.NewGovernor(nil), Control: cp,
	})
	if err != nil {
		t.Fatal(err)
	}

	feat := lane.Features{NetworkASN: "AS-EMG"}
	// Normal posture: two concurrent admissions fit under cap 8.
	o1 := term.Admit(bearerHeaders(raw), feat)
	if !o1.Authorized {
		t.Fatalf("normal admission 1: %s", o1.Reason)
	}
	o2 := term.Admit(bearerHeaders(raw), feat)
	if !o2.Authorized {
		t.Fatalf("normal admission 2 should fit cap 8: %s", o2.Reason)
	}
	o1.Reservation().Release()
	o2.Reservation().Release()

	// Lockdown: Emergency cap 1 — first admission takes the only slot, second
	// is denied. Same established lane: this is throttle, not lane denial.
	cp.SetEmergency(true, "ops", "incident")
	e1 := term.Admit(bearerHeaders(raw), feat)
	if !e1.Authorized {
		t.Fatalf("first established admission under lockdown: %s", e1.Reason)
	}
	e2 := term.Admit(bearerHeaders(raw), feat)
	if e2.Authorized {
		t.Fatal("P0.48: emergency cap 1 must deny the second concurrent admission")
	}
	if e2.Reason != "rate_limit" {
		t.Fatalf("P0.48: emergency throttle denial = %q (ACCOUNT scope denial), want rate_limit", e2.Reason)
	}
	e1.Reservation().Release()

	// A zero-authored Emergency set falls back to Constrained (never grants
	// more headroom than the posture it overrides).
	pol2 := policy.Default()
	pol2.Limits.Normal.ConcurrencyCap = 8
	pol2.Limits.Emergency = policy.Limits{} // unset
	term2, err := New(Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: pol2, Signer: signer,
		Audience: "fi-inference", Evidence: evidence.NewMemoryStore(),
		Resource: resource.NewGovernor(nil), Control: cp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := term2.emergencyLimits(); got.ConcurrencyCap != pol2.Limits.Constrained.ConcurrencyCap {
		t.Fatalf("unset Emergency must fall back to Constrained cap, got %d want %d",
			got.ConcurrencyCap, pol2.Limits.Constrained.ConcurrencyCap)
	}
}
