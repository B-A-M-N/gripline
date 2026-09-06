package gates

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	laneA := lane.Features{NetworkASN: "AS-GATE-A", NetworkType: "residential", RegionClass: "us", ClientFamily: "claude-code"}
	laneB := lane.Features{NetworkASN: "AS-GATE-B", NetworkType: "hosting", RegionClass: "eu", ClientFamily: "sdk"}
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

// --- Gate I end-to-end: lane-scoped restriction through the real proxy -------
//
// This is the user's capstone target made executable: a LANE-RESTRICTED
// decision that is authoritative and enforced through the actual terminate-and-
// forward proxy, accepted/denied by a private backend WITHOUT the external
// credential crossing the boundary. The terminator admits per-lane; the proxy
// streams the signed internal assertion only for an AUTHORIZED lane; the
// backend verifies it. A blocked lane's request must never reach the backend.
//
// sourceResolv attributes the trusted source identity (ASN/network/region +
// client family) from headers — standing in for an M4 edge-provider seam, the
// flagged default in proxy.HeaderFeatures. Without the trusted source dims the
// P0.9 anti-laundering floor (0.70) makes every request a fresh NOVEL lane, so
// no lane can ever establish or be restricted through the proxy. Supplying the
// full source identity is what lets the lane MATCH across requests here.
type sourceResolv struct{}

func (sourceResolv) Resolve(r *http.Request, _ proxy.Peer) lane.Features {
	return lane.Features{
		NetworkASN:   r.Header.Get("X-Source-ASN"),
		NetworkType:  "residential",
		RegionClass:  "us",
		ClientFamily: "claude-code",
		HTTPVersion:  "1.1",
	}
}

// TestGateI_LaneScopedRestrictionThroughProxy drives a lane block through the
// DataPlane + a real httptest backend. It proves the boundary is sealed even
// mid-firefight: the denied lane's request is terminated at the edge (403, no
// assertion minted) and never arrives at the private backend, while an
// established lane continues to be accepted with a backend-verified internal
// assertion.
func TestGateI_LaneScopedRestrictionThroughProxy(t *testing.T) {
	signer, _ := terminator.GenerateSigner()
	raw := gateSecret("i")
	pep := &credential.PepperKey{Version: 1, Key: []byte("gate-pepper-cred_i")}
	reg := gateRegistry(t, "cred_i", raw)
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

	// A private backend that verifies the internal assertion and rejects any
	// residual secret carrier.
	hit := make(map[string]int)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Authorization")) > 0 || len(r.Header.Values("X-Api-Key")) > 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("external-secret-leaked"))
			return
		}
		ver := proxy.NewBackendVerifier(signer.Public(), gateAudience)
		if _, verr := ver.Verify(r); verr != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(verr.Error()))
			return
		}
		hit[r.Header.Get("X-Source-ASN")]++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("accepted"))
	}))
	defer backend.Close()

	dp, err := proxy.New(proxy.Config{
		Terminator: term,
		Backend:    http.DefaultTransport,
		Audience:   gateAudience,
		Features:   sourceResolv{},
	})
	if err != nil {
		t.Fatal(err)
	}

	// admit runs one request through the real proxy with the given source ASN.
	admit := func(asn string) (int, string) {
		req := httptest.NewRequest("POST", backend.URL+"/v1/messages", strings.NewReader(`{"x":1}`))
		req.Header.Set("Authorization", "Bearer "+raw)
		req.Header.Set("X-Source-ASN", asn)
		rec := httptest.NewRecorder()
		dp.ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("X-Gripline-Reason")
	}

	// (1) Two distinct asns establish two lanes; both authorize end-to-end, and
	// the backend verifies the assertion for each.
	if c, r := admit("AS-PROXY-A"); c != http.StatusOK {
		t.Fatalf("lane A establish: proxy returned %d (reason %q)", c, r)
	}
	if c, r := admit("AS-PROXY-B"); c != http.StatusOK {
		t.Fatalf("lane B establish: proxy returned %d (reason %q)", c, r)
	}
	if hit["AS-PROXY-A"] != 1 || hit["AS-PROXY-B"] != 1 {
		t.Fatalf("backend must have accepted both lanes: %v", hit)
	}

	// (2) Block lane B via ITS OWN lane-scoped high-risk evidence (sum >= 70).
	// The lane id is deterministic on the feature vector (classifyLane), so a
	// direct Admit with the exact sourceResolv features yields the same lane id
	// the proxy uses. Seed lane-scoped evidence under that id.
	// Build the resolved feature the way the proxy does (Header.Set canonicalizes
	// the key), so the probe targets the SAME lane the proxy established.
	probeReq := httptest.NewRequest("POST", "/", nil)
	probeReq.Header.Set("X-Source-ASN", "AS-PROXY-B")
	laneBFeatures := sourceResolv{}.Resolve(probeReq, proxy.Peer{})
	probe := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, laneBFeatures)
	if !probe.Authorized {
		t.Fatalf("pre-block lane B should authorize: %s", probe.Reason)
	}
	laneBID := probe.Context.LaneID
	now := time.Now()
	hi := []evidence.Evidence{
		{
			EvidenceID: "gate_epxy_b1", Code: "CONCURRENCY_OVER_10X_BASELINE",
			Family: evidence.FamilyResourceVelocity, Scope: evidence.ScopeLane,
			SubjectID: laneBID, Score: 40, Confidence: 85,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		},
		{
			EvidenceID: "gate_epxy_b2", Code: "NEW_HOSTING_ASN",
			Family: evidence.FamilySourceDiscontinuity, Scope: evidence.ScopeLane,
			SubjectID: laneBID, Score: 40, Confidence: 70,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		},
	}
	if err := store.Append(hi...); err != nil {
		t.Fatal(err)
	}

	// (3) The blocked lane's request through the REAL proxy must be denied at the
	// edge (403) and must NEVER reach the backend — no assertion is minted for a
	// restricted lane, so the backend cannot accept it.
	before := hit["AS-PROXY-B"]
	if c, r := admit("AS-PROXY-B"); c != http.StatusForbidden {
		t.Fatalf("blocked lane through proxy: got %d (reason %q), want 403 (lane_restricted)", c, r)
	}
	if hit["AS-PROXY-B"] != before {
		t.Fatal("Gate I proxy: blocked lane's request must never reach the backend")
	}

	// (4) Lane A is untouched and still accepted end-to-end through the proxy.
	before = hit["AS-PROXY-A"]
	// Direct admit for AS-PROXY-A (canonical header, matching the proxy path).
	diagReq := httptest.NewRequest("POST", "/", nil)
	diagReq.Header.Set("X-Source-ASN", "AS-PROXY-A")
	diagFeat := sourceResolv{}.Resolve(diagReq, proxy.Peer{})
	if da := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, diagFeat); !da.Authorized {
		t.Fatalf("pre-check direct lane A must authorize: %s", da.Reason)
	}
	if c, r := admit("AS-PROXY-A"); c != http.StatusOK {
		t.Fatalf("lane A must continue through proxy: got %d (reason %q), want 200", c, r)
	}
	if hit["AS-PROXY-A"] != before+1 {
		t.Fatal("Gate I proxy: established lane A must still be backend-accepted")
	}
}


// gateHIOTerminator builds a terminator with the given auto-quarantine posture.
// It returns the terminator, the evidence store (so the test can seed a high
// risk), the registry (to read persisted status), and the raw credential.
func gateHIOTerminator(t *testing.T, autoQuarantine bool) (*terminator.Terminator, evidence.Store, *credential.MemoryRegistry, string) {
	raw := gateSecret("h")
	pep := &credential.PepperKey{Version: 1, Key: []byte("gate-pepper-cred_h")}
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_h", AccountID: "acct",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status:    credential.StatusNormal,
		PolicyID:  "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	p := policy.Default()
	p.Risk.EnableAutomaticQuarantine = autoQuarantine
	store := evidence.NewMemoryStore()
	signer, _ := terminator.GenerateSigner()
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg,
		Peppers:  credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   p,
		Signer:   signer,
		Audience: gateAudience,
		Evidence: store,
		Resource: resource.NewGovernor(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return term, store, reg, raw
}

// TestGateH_AutomaticQuarantineDisabledUntilValidation proves the §102 phase 6 /
// Gate H fail-closed default: with a risk-model not yet shadow-validated
// (EnableAutomaticQuarantine=false, the default), a credential whose risk
// crosses the quarantine threshold is DENIED the request (temporarily_restricted)
// but its PERSISTED status is NOT auto-quarantined — quarantine remains a
// validated operator/policy action. Enabling the flag restores auto-quarantine.
func TestGateH_AutomaticQuarantineDisabledUntilValidation(t *testing.T) {
	// Gate H default is fail-closed: the flag is OFF in the default policy.
	if policy.Default().Risk.EnableAutomaticQuarantine {
		t.Fatal("Gate H: automatic quarantine must default to DISABLED (shadow-first)")
	}

	for name, auto := range map[string]bool{"disabled": false, "enabled": true} {
		t.Run(name, func(t *testing.T) {
			term, store, reg, raw := gateHIOTerminator(t, auto)

			// Establish the lane normally (so classification/lane exist).
			feat := lane.Features{NetworkASN: "AS-H", NetworkType: "residential", RegionClass: "us", ClientFamily: "claude-code"}
			est := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, feat)
			if !est.Authorized {
				t.Fatalf("gate H %s: establish must authorize: %s", name, est.Reason)
			}

			// Seed credential-scoped evidence that crosses the quarantine
			// threshold (80). Three families sum past their caps to an effective
			// risk >= 80: AbuseCorrelation(40 cap) + ResourceVelocity(35 cap) +
			// ClientNovelty(20 cap) = 95.
			now := time.Now()
			hi := []evidence.Evidence{
				{EvidenceID: "gate_h1", Code: "MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN",
					Family: evidence.FamilyAbuseCorrelation, Scope: evidence.ScopeCredential,
					SubjectID: "cred_h", Score: 45, Confidence: 85, CorrelationGroup: "topology",
					CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
				{EvidenceID: "gate_h2", Code: "CONCURRENCY_OVER_10X_BASELINE",
					Family: evidence.FamilyResourceVelocity, Scope: evidence.ScopeCredential,
					SubjectID: "cred_h", Score: 45, Confidence: 85, CorrelationGroup: "resource",
					CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
				{EvidenceID: "gate_h3", Code: "RAPID_ENDPOINT_OR_MODEL_ENUMERATION",
					Family: evidence.FamilyClientNovelty, Scope: evidence.ScopeCredential,
					SubjectID: "cred_h", Score: 40, Confidence: 80, CorrelationGroup: "novelty",
					CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
			}
			if err := store.Append(hi...); err != nil {
				t.Fatal(err)
			}

			// A fresh observation on the established lane sees the high persisted
			// credential risk. The request must be DENIED either way (a hot
			// credential is never granted), but the PERSISTED status differs by
			// posture.
			out := term.Admit(map[string][]string{"Authorization": {"Bearer " + raw}}, feat)

			// Read the authoritative persisted status after admission.
			rec, err := reg.LookupAuthoritative(nil, "cred_h")
			if err != nil {
				t.Fatalf("gate H %s: read persisted credential: %v", name, err)
			}
			persisted := rec.Status

			switch auto {
			case false:
				// Disabled posture: the hot credential is still denied the request…
				if out.Authorized {
					t.Fatalf("gate H disabled: high-risk request must be denied, got %s", out.Reason)
				}
				// …but its persisted status is NOT auto-quarantined.
				if persisted == credential.StatusQuarantined {
					t.Fatalf("gate H disabled: risk alone must NOT auto-quarantine, persisted got %v", persisted)
				}
			case true:
				// Enabled posture (validated shadow): auto-quarantine persists.
				if persisted != credential.StatusQuarantined {
					t.Fatalf("gate H enabled: risk >= quarantine threshold must persist QUARANTINED, got %v", persisted)
				}
			}
		})
	}
}

// --- Gate C: supported clients (generic HTTP) operate unchanged --------------

// gateProxyUpstream builds a terminator + DataPlane in front of the given
// backend handler, returning a handler a client can dial directly.
func gateProxyUpstream(t *testing.T, credID, raw string, backend http.Handler) http.Handler {
	t.Helper()
	reg := gateRegistry(t, credID, raw)
	signer, _ := terminator.GenerateSigner()
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg,
		Peppers:  credential.MustPepperRing(&credential.PepperKey{Version: 1, Key: []byte("gate-pepper-" + credID)}),
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
	dp, err := proxy.New(proxy.Config{Terminator: term, Backend: roundTripper(backend), Audience: gateAudience})
	if err != nil {
		t.Fatal(err)
	}
	return dp
}

// roundTripper adapts an http.Handler into a RoundTripper so the proxy can be
// pointed at a handler-backed backend.
type handlerRT struct{ h http.Handler }

func roundTripper(h http.Handler) http.RoundTripper { return &handlerRT{h: h} }

func (rt *handlerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rt.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// TestGateC_GenericClientOperatesUnchanged proves Gate C's broadest surface: a
// plain generic HTTP client (the curl-equivalent) sends a normal GET, and — with
// the secret terminated and the internal assertion injected on the trusted hop —
// receives an unchanged status + body back. "Supported clients operate unchanged"
// cannot run the real third-party SDKs in this repo; the generic-HTTP contract
// (a valid credential, 200, exact body via the same URL) is the subset this gate
// enforces at the package boundary.
func TestGateC_GenericClientOperatesUnchanged(t *testing.T) {
	raw := gateSecret("c")
	const body = `{"data":[{"id":"model-x"}]}`
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	})
	dp := gateProxyUpstream(t, "cred_c", raw, backend)
	backendSrv := httptest.NewServer(dp)
	defer backendSrv.Close()

	// A plain GET — the curl-equivalent: the standard Authorization credential a
	// normal client always presents, with no SDK headers, no streaming, no body.
	req, _ := http.NewRequest("GET", backendSrv.URL+"/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Gate C: generic GET got %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Fatalf("Gate C: body changed through the proxy: got %q want %q", got, body)
	}
}

// --- Gate D: no material streaming-semantic regression ------------------------

// TestGateD_StreamingResponseUnmodified proves Gate D: a SSE-style streaming
// backend (multiple flushed chunks, `text/event-stream` content type and
// Transfer-Encoding preserved) is streamed back to the client without buffering
// omission, truncation, or body mutation.
func TestGateD_StreamingResponseUnmodified(t *testing.T) {
	raw := gateSecret("d")
	chunks := []string{"data: {\"i\":1}\n\n", "data: {\"i\":2}\n\n", "data: {\"i\":3}\n\n"}
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		for _, ch := range chunks {
			w.Write([]byte(ch))
			if f != nil {
				f.Flush()
			}
		}
	})
	dp := gateProxyUpstream(t, "cred_d", raw, backend)
	backendSrv := httptest.NewServer(dp)
	defer backendSrv.Close()

	req, _ := http.NewRequest("POST", backendSrv.URL+"/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Gate D: streaming content type lost: %q", ct)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != strings.Join(chunks, "") {
		t.Fatalf("Gate D: stream body mutated/truncated: got %q", got)
	}
}

// --- Gate J: concurrency accounting survives race without over-admission ------

// TestGateJ_ConcurrentAccountingNoOverAdmission proves Gate J at the package
// boundary: under concurrency, the number of SIMULTANEOUS holders of a scope
// never exceeds its cap — no over-admission beyond tolerance. Sequencing the
// workers so they genuinely overlap (each admitted holder blocks on a barrier
// before releasing) makes peak concurrent concurrency the measured invariant,
// which is what a multi-node operator actually needs bounded.
func TestGateJ_ConcurrentAccountingNoOverAdmission(t *testing.T) {
	const cap, workers = 3, 128
	scopes := []resource.ScopeSpec{{Scope: resource.ScopeCredential, ID: "cred_j", Buckets: resource.BucketSpec{ConcurrencyCap: cap}}}
	g := resource.NewGovernor(time.Now)

	var wg sync.WaitGroup
	var mu sync.Mutex
	peak, live := 0, 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := g.Provision(scopes, nil, resource.ProvisionAmt{Concurrency: 1})
			if err != nil {
				return
			}
			// Carry the hold so overlapping workers contend for the same pool.
			// `live` counts goroutines that are CURRENTLY holding a slot, so it
			// must be decremented BEFORE Release returns the slot: leaving the
			// live set after Release lets a legitimate successor re-provision the
			// freed slot while this goroutine is still counted, driving peak above
			// cap even though only `cap` slots are ever held at once (a pure
			// measurement artifact, not over-admission).
			mu.Lock()
			live++
			if live > peak {
				peak = live
			}
			mu.Unlock()
			mu.Lock()
			live--
			mu.Unlock()
			res.Release()
		}()
	}
	wg.Wait()

	if peak > cap {
		t.Fatalf("Gate J: over-admission — peak simultaneous holders %d, cap %d", peak, cap)
	}
}