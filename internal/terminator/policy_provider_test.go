package terminator

import (
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
)

func TestPolicyProviderActivationChangesNewRequestsOnly(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("policy-provider-test-pepper")}
	tc := makeCredentialWithStatus("cred_policy_provider", "acct_policy_provider", credential.StatusNormal, pep)
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	initial := policy.Default()
	manager, err := policy.NewManager(initial, policy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	term, err := New(Dependencies{
		Registry: tc.reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: initial, Policies: manager,
		Signer: signer, Audience: "fi-inference",
	})
	if err != nil {
		t.Fatal(err)
	}
	first := term.Admit(bearerHeaders(tc.raw), lane.Features{})
	if !first.Authorized || first.Assertion.Claims().PolicyRev != initial.Revision {
		t.Fatalf("initial request did not use active policy revision %d: %+v", initial.Revision, first)
	}

	candidate := *initial
	candidate.Revision++
	if _, err := manager.Prepare(&candidate); err != nil {
		t.Fatal(err)
	}
	stillInitial := term.Admit(bearerHeaders(tc.raw), lane.Features{NetworkASN: "AS-before-activation"})
	if !stillInitial.Authorized || stillInitial.Assertion.Claims().PolicyRev != initial.Revision {
		t.Fatalf("prepared candidate leaked before activation: %+v", stillInitial)
	}
	if err := manager.Activate("provider test"); err != nil {
		t.Fatal(err)
	}
	activated := term.Admit(bearerHeaders(tc.raw), lane.Features{NetworkASN: "AS-after-activation"})
	if !activated.Authorized || activated.Assertion.Claims().PolicyRev != candidate.Revision {
		t.Fatalf("activated policy was not used by a new request: %+v", activated)
	}
}
