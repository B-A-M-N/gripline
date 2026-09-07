package observability

import (
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/principal"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// TestDecisionRecordNeverContainsRawCredential proves Gate A / INV-2 for the
// observability surface: neither the DecisionRecord nor its JSON serialization
// can ever contain the raw external credential or its prefix. This is the
// shipped audit/trace path — a raw secret here would be a release-blocking leak.
func TestDecisionRecordNeverContainsRawCredential(t *testing.T) {
	raw := "sk-decision-" + strings.Repeat("x", 24)
	out := &terminator.Outcome{
		RequestID:  "req_1",
		Authorized: true,
		Reason:     "authorized",
		Principal:  principal.Principal{CredentialID: "cred_1", AccountID: "acct_1", PolicyID: "p1"},
		Context:    principal.AuthorizedContext{AuthorizationScope: principal.ScopeLane, LaneState: "ESTABLISHED"},
		RiskAfter:  42,
		Evidence:   []string{"NEW_ASN"},
	}
	dr := New(out)
	b, err := dr.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), raw) || strings.Contains(string(b), "sk-decision") {
		t.Fatalf("decision record leaked raw credential: %s", b)
	}
	if strings.Contains(dr.Principal.CredentialID, "sk-decision") {
		t.Fatal("credential id must be the internal ID, never the raw secret")
	}
}

// TestDecisionRecordProjectsOutcome proves §97 explainability: the record
// compactly answers what happened, why, under which policy revision, and at
// what scope, for both an authorized and a denied admission.
func TestDecisionRecordProjectsOutcome(t *testing.T) {
	// Authorized case.
	auth := New(&terminator.Outcome{
		RequestID:  "req_a",
		Authorized: true,
		Reason:     "authorized",
		Principal:  principal.Principal{CredentialID: "cred_a", AccountID: "acct_a", PolicyID: "p1"},
		Context:    principal.AuthorizedContext{AuthorizationScope: principal.ScopeLane, LaneState: "ESTABLISHED", RiskState: 12},
		RiskAfter:  12,
		Evidence:   []string{"NEW_LANE"},
		Adaptive:   terminator.AdaptiveAvailable,
	})
	if auth.Action != "AUTHORIZE" || !auth.Authorized || auth.Scope != "LANE" {
		t.Fatalf("authorized projection wrong: %+v", auth)
	}

	// Denied case must carry the safe reason.
	den := New(&terminator.Outcome{
		RequestID:  "req_d",
		Authorized: false,
		Reason:     "lane_restricted",
		Principal:  principal.Principal{CredentialID: "cred_d"},
		Context:    principal.AuthorizedContext{AuthorizationScope: principal.ScopeLane},
		RiskAfter:  90,
		Evidence:   []string{"CONCURRENCY_OVER_10X_BASELINE"},
	})
	if den.Action != "DENY" || den.Authorized || den.Reason != "lane_restricted" {
		t.Fatalf("denied projection wrong: %+v", den)
	}

	// Degraded case.
	deg := New(&terminator.Outcome{
		RequestID:  "req_g",
		Authorized: true,
		Reason:     "authorized",
		Degraded:   true,
		Context:    principal.AuthorizedContext{AuthorizationScope: principal.ScopeLane},
		Adaptive:   terminator.AdaptiveDegraded,
	})
	if deg.Action != "AUTHORIZE_DEGRADED" {
		t.Fatalf("degraded projection wrong: %s", deg.Action)
	}
}

// TestDecisionRecordEndToEndWired proves observability is wired to a REAL
// admission: the terminator's Outcome for an authorized request carries a
// policy revision via the issued assertion, which the record must project.
func TestDecisionRecordEndToEndWired(t *testing.T) {
	rawBytes := make([]byte, 24)
	for i := range rawBytes {
		rawBytes[i] = byte('z' + i%26)
	}
	raw := "sk-e2e-" + string(rawBytes)
	pep := &credential.PepperKey{Version: 1, Key: []byte("obs-pepper")}
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_obs", AccountID: "acct", PolicyID: "fi-default-v1", PlanID: "plan-a",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := terminator.GenerateSigner()
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: policy.Default(),
		Signer: signer, Audience: "fi-inference",
		Evidence: evidence.NewMemoryStore(), Resource: resource.NewGovernor(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	out := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, lane.Features{NetworkASN: "AS-1", NetworkType: "residential"})
	if !out.Authorized {
		t.Fatalf("admission should authorize: %s", out.Reason)
	}
	dr := New(out)
	if dr.PolicyRevision != 1 {
		t.Fatalf("record policy revision = %d, want 1 (from issued assertion)", dr.PolicyRevision)
	}
	if dr.Scope == "" || dr.RiskAfter < 0 {
		t.Fatalf("record missing scope/risk: %+v", dr)
	}
}

// P0.50/P0.51: a DENIED decision must be as explainable as an authorized one.
// The internal DecisionTrace supplies the principal, lane identity, and —
// critically — the policy revision (stamped from the compiled policy, since
// denied requests never receive an assertion). Revision 0 on a denied record
// was the old bug: the most security-critical decisions reported no policy.
func TestDeniedDecisionCarriesTraceAndPolicyRevision(t *testing.T) {
	raw := "sk-denied-" + strings.Repeat("y", 24)
	pep := &credential.PepperKey{Version: 1, Key: []byte("obs-pepper")}
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_deny", AccountID: "acct_d", PolicyID: "fi-default-v1", PlanID: "plan-a",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusRevoked, CreatedAt: time.Now().Add(-time.Hour), Revision: 7,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := terminator.GenerateSigner()
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: policy.Default(),
		Signer: signer, Audience: "fi-inference",
		Evidence: evidence.NewMemoryStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	out := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, lane.Features{})
	if out.Authorized {
		t.Fatal("revoked credential must be denied")
	}
	if out.Trace == nil {
		t.Fatal("P0.50: every outcome must carry a decision trace, denials included")
	}
	dr := New(out)
	if dr.Action != "DENY" {
		t.Fatalf("action = %q, want DENY", dr.Action)
	}
	if dr.PolicyRevision == 0 {
		t.Fatal("P0.51: denied decision must carry the compiled policy revision, not 0")
	}
	if dr.Principal.CredentialID != "cred_deny" || dr.Principal.AccountID != "acct_d" {
		t.Fatalf("P0.50: denied record lost principal: %+v", dr.Principal)
	}
	b, err := dr.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), raw) {
		t.Fatalf("denied record leaked raw credential: %s", b)
	}
	if !strings.Contains(string(b), `"policy_revision":`) {
		t.Fatalf("denied record JSON missing policy_revision: %s", b)
	}
}

// P0.50: the trace captures credential state transitions (before → after) and
// the evidence that contributed, so audit/replay can reconstruct the decision.
func TestTraceRecordsStateTransitionsAndEvidence(t *testing.T) {
	raw := "sk-trace-" + strings.Repeat("z", 24)
	pep := &credential.PepperKey{Version: 1, Key: []byte("obs-pepper")}
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_tr", AccountID: "acct_t", PolicyID: "fi-default-v1", PlanID: "plan-a",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, CreatedAt: time.Now().Add(-time.Hour), Revision: 3,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := terminator.GenerateSigner()
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: policy.Default(),
		Signer: signer, Audience: "fi-inference",
		Evidence: evidence.NewMemoryStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	feat := lane.Features{NetworkASN: "AS-trace", NetworkType: "residential", RegionClass: "us", ClientFamily: "web", SDKFamily: "sdk", HTTPVersion: "h2", Streaming: "no", ModelFamily: "m", ConcurrencyPattern: "solo", EndpointFamily: "chat"}
	out := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, feat)
	if !out.Authorized {
		t.Fatalf("admission should authorize: %s", out.Reason)
	}
	tr := out.Trace
	if tr.CredentialStatusBefore != "NORMAL" || tr.CredentialStatusAfter != "NORMAL" {
		t.Fatalf("credential status transition not traced: %q → %q", tr.CredentialStatusBefore, tr.CredentialStatusAfter)
	}
	if tr.CredentialRevBefore != 3 || tr.CredentialRevAfter != 3 {
		t.Fatalf("credential revisions not traced: %d → %d", tr.CredentialRevBefore, tr.CredentialRevAfter)
	}
	if !tr.LaneNew {
		t.Fatal("first request should create a new lane, traced")
	}
	if tr.LaneID == "" || tr.LaneTrustBefore == "" || tr.LaneSecAfter == "" {
		t.Fatalf("lane state not traced: %+v", tr)
	}
	if tr.PolicyRevision != 1 || tr.PolicyID != policy.DefaultPolicyID {
		t.Fatalf("policy identity not traced: %q@%d", tr.PolicyID, tr.PolicyRevision)
	}
	if tr.LimitsClass != "normal" {
		t.Fatalf("limits class not traced: %q", tr.LimitsClass)
	}
}
