package terminator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
)

type blockingPolicyLanes struct {
	*lane.Store
	started chan lane.PolicyContext
	release chan struct{}
}

func (s *blockingPolicyLanes) BorrowOrCreateWithPolicy(ctx context.Context, credID, candidateID string, features lane.Features, policy lane.PolicyContext) (*lane.LaneRecord, bool, error) {
	s.started <- policy
	<-s.release
	return s.Store.BorrowOrCreateWithPolicy(ctx, credID, candidateID, features, policy)
}

func TestAdmissionCapturesOneLanePolicyAcrossActivation(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("policy-overlap-test-pepper")}
	tc := makeCredentialWithStatus("cred_policy_overlap", "acct_policy_overlap", credential.StatusNormal, pep)
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	initial := policy.Default()
	manager, err := policy.NewManager(initial, policy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	lanes := &blockingPolicyLanes{
		Store:   lane.NewStore(nil, time.Now),
		started: make(chan lane.PolicyContext, 1),
		release: make(chan struct{}),
	}
	term, err := New(Dependencies{
		Registry: tc.reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lanes, Policy: initial, Policies: manager,
		Signer: signer, Audience: "fi-inference",
	})
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan *Outcome, 1)
	go func() {
		result <- term.AdmitUsageContext(context.Background(), "req-policy-overlap", bearerHeaders(tc.raw), lane.Features{NetworkASN: "AS-overlap"}, TrustedSource{}, resource.UsageEstimate{Requests: 1})
	}()

	var captured lane.PolicyContext
	select {
	case captured = <-lanes.started:
	case <-time.After(time.Second):
		t.Fatal("admission did not reach policy-bound lane mutation")
	}
	candidate := *initial
	candidate.Revision++
	if _, err := manager.Prepare(&candidate); err != nil {
		t.Fatal(err)
	}
	if err := manager.Activate("overlap test"); err != nil {
		t.Fatal(err)
	}
	close(lanes.release)

	select {
	case out := <-result:
		if !out.Authorized {
			t.Fatalf("overlap admission denied: %s (%v)", out.Reason, out.DenialErr)
		}
	case <-time.After(time.Second):
		t.Fatal("overlap admission did not complete")
	}
	compiledInitial, err := policy.Compile(initial)
	if err != nil {
		t.Fatal(err)
	}
	expected := lanePolicyContext(compiledInitial)
	if captured.PolicyRevision != expected.PolicyRevision || captured.Classification.Revision != expected.Classification.Revision || captured.Limits != expected.Limits || captured.Security != expected.Security {
		t.Fatalf("lane mutation observed mixed policy: captured=%+v expected=%+v", captured, expected)
	}
}

func TestAdmissionPropagatesCanceledContextToVerifierAuthority(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("policy-context-cancel-test-pepper")}
	tc := makeCredentialWithStatus("cred_policy_cancel", "acct_policy_cancel", credential.StatusNormal, pep)
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	term, err := New(Dependencies{
		Registry: tc.reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: policy.Default(),
		Signer: signer, Audience: "fi-inference",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := term.AdmitUsageContext(ctx, "req-policy-canceled", bearerHeaders(tc.raw), lane.Features{}, TrustedSource{}, resource.UsageEstimate{Requests: 1})
	if out.Authorized || !errors.Is(out.DenialErr, credential.ErrLookupTimeout) {
		t.Fatalf("canceled admission did not fail through verifier authority: %+v", out)
	}
}

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
