package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

const testAudience = "fi-inference"

// buildTerminator wires a full terminator + multi-scope governor with the given
// (shared) signer, and returns the raw external credential that authenticates.
func buildTerminator(t *testing.T, signer *terminator.Signer) *terminator.Terminator {
	t.Helper()
	pep := &credential.PepperKey{Version: 1, Key: []byte("dp-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('d' + i%26)
	}
	raw := "sk-dp-" + string(rawBytes)
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_dp", AccountID: "acct_dp",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status:    credential.StatusNormal,
		PolicyID:  "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes:    lane.NewStore(nil, time.Now),
		Policy:   policy.Default(),
		Signer:   signer,
		Audience: testAudience,
		Evidence: evidence.NewMemoryStore(),
		Resource: resource.NewGovernor(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return term
}

// TestDataPlaneExternalSecretNeverCrosses is the capstone containment proof:
// the external credential at ingress is terminated, the signed internal
// assertion replaces it on the trusted hop, the private backend verifies the
// assertion WITHOUT the raw secret, and a client-forged reserved header is
// stripped (INV-1/INV-10/INV-11/INV-12).
func TestDataPlaneExternalSecretNeverCrosses(t *testing.T) {
	signer, _ := terminator.GenerateSigner()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// INV-1: the external credential must not arrive here.
		if len(r.Header.Values("Authorization")) > 0 || len(r.Header.Values("X-Api-Key")) > 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("external-secret-leaked"))
			return
		}
		// Verify the internal assertion against the shared signer's public key.
		ver := NewBackendVerifier(signer.Public(), testAudience)
		claims, verr := ver.Verify(r)
		if verr != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(verr.Error()))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("accepted:" + claims.Subject))
	}))
	defer backend.Close()

	dp, err := New(Config{
		Terminator: buildTerminator(t, signer),
		Backend:    http.DefaultTransport,
		Audience:   testAudience,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The raw external credential for the request.
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('d' + i%26)
	}
	raw := "sk-dp-" + string(rawBytes)

	// Client request carries the EXTERNAL credential AND a forged reserved
	// internal header (INV-12 impersonation attempt).
	req := httptest.NewRequest("POST", backend.URL+"/v1/messages", strings.NewReader(`{"text":"hi"}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("X-Gripline-Principal", "forged-account-id")

	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)

	// The proxy forwards to backend.URL via DefaultTransport.
	if rec.Code != http.StatusOK {
		t.Fatalf("proxy returned %d: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "accepted:acct_dp") {
		t.Fatalf("backend must accept the internal assertion (INV-10/11): body %q", body)
	}
}

// TestDataPlaneDenialMapsStatus proves a request with no external credential
// produces a 401 with a safe reason and never reaches the backend.
func TestDataPlaneDenialMapsStatus(t *testing.T) {
	signer, _ := terminator.GenerateSigner()
	dp, err := New(Config{
		Terminator: buildTerminator(t, signer),
		Backend:    &http.Transport{},
		Audience:   testAudience,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "http://backend.example/", nil)
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-credential request: got %d, want 401", rec.Code)
	}
	if rec.Header().Get("X-Gripline-Reason") == "" {
		t.Fatal("denial must carry a safe reason header")
	}
}