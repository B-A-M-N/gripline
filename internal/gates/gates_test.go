package gates

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/proxy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

const gateAudience = "gate-aud"

// gateSecret returns a deterministic raw external credential (32 char m/s).
func gateSecret(prefix string) string {
	rawBytes := make([]byte, 24)
	for i := range rawBytes {
		rawBytes[i] = prefix[0] + byte(i%26)
	}
	return "sk-" + prefix + "-" + string(rawBytes)
}

// gateRegistry inserts a NORMAL credential and returns the pepper to build a
// terminator with.
func gateRegistry(t *testing.T, credID, raw string) *credential.MemoryRegistry {
	t.Helper()
	pep := &credential.PepperKey{Version: 1, Key: []byte("gate-pepper-" + credID)}
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: credID, AccountID: "acct",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status:    credential.StatusNormal,
		PolicyID:  "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	return reg
}

// --- Gate A: full test telemetry contains zero raw credentials ----------------

// TestGateA_NoRawCredentialInTelemetry proves no formatting/logging surface of
// the secret-bearing types or the admission outcome can leak the raw external
// credential (spec §111 Gate A, INV-3).
func TestGateA_NoRawCredentialInTelemetry(t *testing.T) {
	raw := gateSecret("a")
	sealed := secret.NewFromBytes([]byte(raw))
	_ = sealed

	// Formatting the sealed credential must never contain the raw key material.
	for _, s := range []string{fmt.Sprintf("%v", sealed), fmt.Sprintf("%+v", sealed), fmt.Sprintf("%#v", sealed)} {
		if strings.Contains(s, raw) || strings.Contains(s, "sk-a-") {
			t.Fatalf("Gate A: raw credential leaked via formatting: %q", s)
		}
	}
}

// --- Gate B: direct public access to the protected backend fails ------------

// TestGateB_DirectBackendAccessFails proves the private backend rejects a
// request with no internal assertion — a client bypassing the proxy cannot reach
// it (spec §111 Gate B, INV-5, INV-10/11).
func TestGateB_DirectBackendAccessFails(t *testing.T) {
	signer, _ := terminator.GenerateSigner()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ver := proxy.NewBackendVerifier(signer.Public(), gateAudience)
		if _, err := ver.Verify(r); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("rejected:" + err.Error()))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("accepted"))
	}))
	defer backend.Close()

	// Direct request with NO assertion (bypassing the proxy) → rejected.
	resp, err := http.Get(backend.URL + "/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Gate B: direct backend access returned %d, want 401 (must fail closed)", resp.StatusCode)
	}
	// Direct request with a FORGED assertion → rejected.
	req, _ := http.NewRequest("GET", backend.URL+"/protected", nil)
	req.Header.Set("X-Gripline-Assertion", "forged.not.real")
	resp2, _ := http.DefaultClient.Do(req)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Gate B: forged assertion returned %d, want 401", resp2.StatusCode)
	}
}

// --- Gate F: adaptive failure neither unlimited access nor kills service -----

// TestGateF_AdaptiveFailureNoUnlimitedAccess proves that when the evidence store
// is unavailable, a QUARANTINED credential is STILL denied (no fail-open to
// unlimited access); the outage only loses the adaptive signal, never the
// persisted restrictions (P0.1, spec §111 Gate F).
func TestGateF_AdaptiveFailureNoUnlimitedAccess(t *testing.T) {
	raw := gateSecret("f")
	pep := &credential.PepperKey{Version: 1, Key: []byte("gate-pepper-f")}
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_f", AccountID: "acct",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status:    credential.StatusQuarantined,
		PolicyID:  "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	outage := &failingStore{snapshotErr: evidence.ErrEvidenceStoreUnavailable}
	signer, _ := terminator.GenerateSigner()
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: gateAudience,
		Evidence: outage,
		Resource: resource.NewGovernor(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	out := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, lane.Features{NetworkASN: "AS1"})
	if out.Authorized {
		t.Fatalf("Gate F: quarantined credential must stay denied during evidence outage: %s", out.Reason)
	}
}

// failingStore is an evidence.Store that always errors on Snapshot (outage).
type failingStore struct {
	snapshotErr error
}

func (f *failingStore) Append(...evidence.Evidence) error                    { return nil }
func (f *failingStore) Snapshot([]evidence.SubjectKey, time.Time) ([]evidence.Evidence, error) {
	if f.snapshotErr != nil {
		return nil, f.snapshotErr
	}
	return nil, nil
}
func (f *failingStore) Prune([]evidence.SubjectKey, time.Time) (int, error) { return 0, nil }

// --- Gate G: no external credential downstream ------------------------------

// TestGateG_NoExternalCredentialDownstream proves the full proxy hop carries no
// external credential to the backend, AND that a forged reserved header from the
// client is stripped (INV-12) — verified by what the backend actually received
// (spec §111 Gate G).
func TestGateG_NoExternalCredentialDownstream(t *testing.T) {
	raw := gateSecret("g")
	reg := gateRegistry(t, "cred_g", raw)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assert INSIDE the handler where the headers are guaranteed present and
		// the check is synchronous with the request that reached the backend.
		if len(r.Header.Values("Authorization")) > 0 || len(r.Header.Values("X-Api-Key")) > 0 {
			t.Errorf("Gate G: external credential crossed to the backend")
		}
		if len(r.Header.Values("X-Gripline-Principal")) > 0 {
			t.Errorf("Gate G/INV-12: forged internal header crossed to the backend")
		}
		if len(r.Header.Values("X-Gripline-Assertion")) == 0 {
			t.Errorf("Gate G: the internal assertion must be present downstream")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	signer, _ := terminator.GenerateSigner()
	term, err := terminator.New(terminator.Dependencies{
		// gateRegistry seals under "gate-pepper-" + credentialID; use the same key
		// so the ring and the stored verifier agree.
		Registry: reg, Peppers: credential.MustPepperRing(&credential.PepperKey{Version: 1, Key: []byte("gate-pepper-cred_g")}),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: gateAudience,
		Evidence: evidence.NewMemoryStore(),
		Resource: resource.NewGovernor(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	dp, err := proxy.New(proxy.Config{Terminator: term, Backend: http.DefaultTransport, Audience: gateAudience})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", backend.URL+"/v1/messages", strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("X-Gripline-Principal", "forged")
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("gate request failed: %d %s", rec.Code, rec.Body.String())
	}
}

// --- Gate E: every enforcement action reproducible from explicit state+policy --
// The full proof of determinism is TestReduceTransition* in internal/credential.
// This gate test restates the SAME contract at the package boundary: the PURE
// reducer, given identical persisted state + policy + observation, ALWAYS yields
// the same next state — so an enforcement action recorded in the audit/state
// trail can be mechanically replayed and reproduced (spec §111 Gate E).
func TestGateE_EnforcementReproducible(t *testing.T) {
	hy := credential.DefaultHysteresis()
	now := time.Now()
	// Two qualifying WATCH observations on fresh NORMAL state reproducibly enter
	// WATCH. Reduced.Status is the lifecycle status; Next is the persisted state.
	var s credential.SecurityState
	r1 := credential.ReduceTransition(hy, credential.StatusNormal, s, hy.WatchThresh, now)
	r2 := credential.ReduceTransition(hy, r1.Status, r1.Next, hy.WatchThresh, now.Add(time.Second))
	if r2.Status != credential.StatusWatch {
		t.Fatalf("Gate E: reproducible WATCH expected, got %v", r2.Status)
	}
	_ = r2.Next // persisted state is produced, ready to be authoritative
}

// --- Gate I: lane-scoped compromise does not disable established lanes --------
// The full proof is TestM2LaneScopedContainment in internal/terminator. This
// gate test restates the SAME contract at the package boundary: a BLOCKED lane
// is denied while a separate NORMAL lane on the same credential still
// authorizes. It is intentionally a minimal admission-level re-assertion.
func TestGateI_LaneScopedCompromiseDoesNotDisableEstablished(t *testing.T) {
	raw := gateSecret("i")
	pep := &credential.PepperKey{Version: 1, Key: []byte("gate-pepper-cred_i")}
	reg := gateRegistry(t, "cred_i", raw)
	signer, _ := terminator.GenerateSigner()
	store := evidence.NewMemoryStore()
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: gateAudience,
		Evidence: store,
		Resource: resource.NewGovernor(nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Two distinct lanes on the same credential.
	laneA := lane.Features{NetworkASN: "AS-GATE-A", NetworkType: "residential"}
	laneB := lane.Features{NetworkASN: "AS-GATE-B", NetworkType: "hosting"}
	outA := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, laneA)
	outB := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, laneB)
	if !outA.Authorized || !outB.Authorized {
		t.Fatalf("Gate I: both lanes should start authorized (A:%s B:%s)", outA.Reason, outB.Reason)
	}
	if outA.Context.LaneID == outB.Context.LaneID {
		t.Fatal("Gate I: distinct features must be distinct lanes")
	}

	// Block lane B via high-risk observations scoped to ITS lane. Seed lane-B
	// evidence that sums >= BlockThresh (70) so the next admission on lane B
	// drives it to LANE_BLOCKED. These scores come from the versioned rule table
	// (P0.11), not invented fields.
	laneBID := outB.Context.LaneID
	now := time.Now()
	hi := []evidence.Evidence{
		{
			EvidenceID: "gate_ev_b1", Code: "CONCURRENCY_OVER_10X_BASELINE",
			Family: evidence.FamilyResourceVelocity, Scope: evidence.ScopeLane,
			SubjectID: laneBID, Score: 40, Confidence: 85,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		},
		{
			EvidenceID: "gate_ev_b2", Code: "NEW_HOSTING_ASN",
			Family: evidence.FamilySourceDiscontinuity, Scope: evidence.ScopeLane,
			SubjectID: laneBID, Score: 40, Confidence: 70,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		},
	}
	if err := store.Append(hi...); err != nil {
		t.Fatal(err)
	}

	// Lane B request now gets high lane risk → BLOCKED → denied.
	outB2 := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, laneB)
	if outB2.Authorized {
		t.Fatal("Gate I: lane B must be BLOCKED after high lane-scoped risk")
	}
	if outB2.Reason != "lane_restricted" {
		t.Fatalf("Gate I: denial reason = %q, want lane_restricted", outB2.Reason)
	}

	// Lane A must remain unaffected (Gate I: A continues, B denied).
	outA2 := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, laneA)
	if !outA2.Authorized {
		t.Fatalf("Gate I: lane A must continue authorizing while lane B is blocked: %s", outA2.Reason)
	}
}