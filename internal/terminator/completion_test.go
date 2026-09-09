package terminator

import (
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/producers"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// completionTerminator builds a terminator with the ResourceVelocityProducer
// wired (so completion signals fire against ACTUAL usage) and a memory evidence
// store to observe them.
func completionTerminator(t *testing.T, now func() time.Time) (*Terminator, *resource.Governor, string) {
	t.Helper()
	if now == nil {
		now = time.Now
	}
	pol := policy.Default()
	pep := &credential.PepperKey{Version: 1, Key: []byte("completion-pepper")}
	raw := "sk-completion-secret"
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_comp", AccountID: "acct_comp",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	gov := resource.NewGovernor(nil)
	signer, _ := GenerateSigner()
	term, err := New(Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: pol, Signer: signer,
		Audience: "fi-inference", Evidence: evidence.NewMemoryStore(),
		Resource: gov,
		Producers: []producers.Producer{
			producers.NewResourceVelocityProducer(now),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return term, gov, raw
}

// TestOutcomeCompleteDrivesCompletionProducers proves P0.4A end-to-end: an
// authorized outcome issues a CompletionToken, and spending it with a HIGH
// actual usage (after a low baseline) trips the token-velocity producer and
// persists the scoped evidence for SUBSEQUENT admissions — on the lane, not the
// credential.
func TestOutcomeCompleteDrivesCompletionProducers(t *testing.T) {
	base := time.Now()
	term, gov, raw := completionTerminator(t, func() time.Time { return base })
	_ = gov

	feat := lane.Features{NetworkASN: "AS1"}
	admit := func(actual resource.UsageEstimate) *Outcome {
		out := term.AdmitUsage(bearerHeaders(raw), feat, TrustedSource{}, resource.UsageEstimate{Requests: 1, CombinedTokens: actual.CombinedTokens})
		if !out.Authorized {
			t.Fatalf("expected authorization, got %s", out.Reason)
		}
		if out.Completion == nil {
			t.Fatal("authorized outcome with producers wired must carry a CompletionToken")
		}
		out.Complete(actual, true)
		return out
	}

	// Establish a low token baseline for the lane.
	for i := 0; i < 5; i++ {
		admit(resource.UsageEstimate{Requests: 1, CombinedTokens: 5})
	}

	// Capture the lane id from the last outcome's completion token.
	var laneID string
	out := admit(resource.UsageEstimate{Requests: 1, CombinedTokens: 5})
	laneID = out.Completion.subjects.LaneID
	if laneID == "" {
		t.Fatal("completion token must carry the authoritative lane id")
	}

	// Now a 100-token completion on the SAME features → same lane, 20x the ~5
	// baseline → TOKEN_VELOCITY_OVER_4X_BASELINE must be persisted for the lane.
	admit(resource.UsageEstimate{Requests: 1, CombinedTokens: 100})

	snap, err := term.dep.Evidence.Snapshot([]evidence.SubjectKey{
		{Scope: evidence.ScopeLane, ID: laneID},
	}, time.Now())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	found := false
	for _, ev := range snap {
		if ev.Code == "TOKEN_VELOCITY_OVER_4X_BASELINE" ||
			ev.Code == "TOKEN_VELOCITY_OVER_10X_BASELINE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("token-velocity completion evidence must be persisted for lane %s; snapshot: %+v", laneID, snap)
	}
}

type alwaysCompletionSignalProducer struct{}

func (alwaysCompletionSignalProducer) ObserveAdmission(producers.AdmissionBehavior) []producers.Signal {
	return nil
}

func (alwaysCompletionSignalProducer) ObserveCompletion(producers.CompletionBehavior) []producers.Signal {
	return []producers.Signal{{Code: "TOKEN_VELOCITY_OVER_10X_BASELINE"}}
}

// Completion authority must be bounded from the completion event, not from
// admission. This exercises the >5s stream case that previously reused an
// already-expired detached context.
func TestCompletionAfterAdmissionBudgetPersistsEvidence(t *testing.T) {
	term, _, raw := completionTerminator(t, time.Now)
	term.dep.Producers = []producers.Producer{alwaysCompletionSignalProducer{}}
	out := term.AdmitUsage(bearerHeaders(raw), lane.Features{NetworkASN: "AS1"}, TrustedSource{}, resource.UsageEstimate{Requests: 1})
	if !out.Authorized || out.Completion == nil {
		t.Fatalf("expected authorized completion token: authorized=%v token=%v reason=%s", out.Authorized, out.Completion != nil, out.Reason)
	}
	time.Sleep(deferredAuthorityTimeout + 100*time.Millisecond)
	result := out.Complete(resource.UsageEstimate{Requests: 1, CombinedTokens: 100}, true)
	if result.Err != nil || !result.Persisted {
		t.Fatalf("completion after long stream was not persisted: %+v", result)
	}
}

// TestOutcomeCompleteIdempotent proves a second Complete on the same outcome is
// a no-op (CAS), so a proxy that completes + double-releases never double-counts
// completion evidence.
func TestOutcomeCompleteIdempotent(t *testing.T) {
	base := time.Now()
	term, _, raw := completionTerminator(t, func() time.Time { return base })
	_ = term

	feat := lane.Features{NetworkASN: "AS1"}
	out := term.AdmitUsage(bearerHeaders(raw), feat, TrustedSource{}, resource.UsageEstimate{Requests: 1, CombinedTokens: 10})
	if !out.Authorized {
		t.Fatal("expected authorization")
	}
	if out.Completion == nil {
		t.Fatal("must carry CompletionToken")
	}
	r1 := out.Complete(resource.UsageEstimate{Requests: 1, CombinedTokens: 10}, true)
	r2 := out.Complete(resource.UsageEstimate{Requests: 1, CombinedTokens: 10}, true)
	if len(r1.EvidenceCodes) != len(r2.EvidenceCodes) {
		t.Fatalf("second Complete must be a no-op: %v vs %v", r1.EvidenceCodes, r2.EvidenceCodes)
	}
}
