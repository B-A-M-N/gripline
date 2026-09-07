package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

// dpRaw returns the raw external credential the test terminator embeds.
func dpRaw() string {
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('d' + i%26)
	}
	return "sk-dp-" + string(rawBytes)
}

// buildTerminatorWithSigner wires a full terminator + multi-scope governor with
// the given (shared) signer. signer is the AssertionSigner interface so either a
// *terminator.Signer (fixed key) or a *terminator.Keyring (rotation, P0.59) can
// be supplied.
func buildTerminatorWithSigner(t *testing.T, signer terminator.AssertionSigner) *terminator.Terminator {
	t.Helper()
	pep := &credential.PepperKey{Version: 1, Key: []byte("dp-pepper")}
	raw := dpRaw()
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_dp", AccountID: "acct_dp",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status:   credential.StatusNormal,
		PolicyID: "fi-default-v1", PlanID: "plan-a",
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

// buildTerminator is the fixed-key convenience wrapper.
func buildTerminator(t *testing.T, signer *terminator.Signer) *terminator.Terminator {
	return buildTerminatorWithSigner(t, signer)
}

// buildTerminatorWithGovernor wires a terminator around a shared governor so
// leak tests can inspect held capacity.
func buildTerminatorWithGovernor(t *testing.T, signer terminator.AssertionSigner, gov *resource.Governor) *terminator.Terminator {
	t.Helper()
	pep := &credential.PepperKey{Version: 1, Key: []byte("dp-pepper")}
	raw := dpRaw()
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_dp", AccountID: "acct_dp",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status:   credential.StatusNormal,
		PolicyID: "fi-default-v1", PlanID: "plan-a",
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
		Resource: gov,
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

	bu, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	dp, err := New(Config{
		Terminator: buildTerminator(t, signer),
		BackendURL: bu,
		Audience:   testAudience,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The raw external credential for the request.
	raw := dpRaw()

	// Client request carries the EXTERNAL credential AND a forged reserved
	// internal header (INV-12 impersonation attempt). P0.7: the client targets
	// the PROXY with a relative-style origin (the proxy's own address is
	// irrelevant to routing); the upstream is chosen by config, not the client.
	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{"text":"hi"}`))
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

// TestDataPlaneBackendFollowsSignerRotation proves P0.59 end-to-end: the
// proxy signs under a Keyring, the keyring ROTATES mid-flight, and the private
// backend (verifying via the same Keyring's retained public keys) still
// accepts a request signed under the rotated generation. Old and new
// generations coexist during the overlap.
func TestDataPlaneBackendFollowsSignerRotation(t *testing.T) {
	keyring, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	// Rotate once BEFORE the backend starts, so the backend has both pubs.
	if _, err := keyring.Rotate(); err != nil {
		t.Fatal(err)
	}

	// Private backend verifies via a PUBLISHED verifier keyring (P0.59 +
	// P0.17): the backend holds public keys only, connected by publication.
	vk := keyring.PublishVerifier()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Authorization")) > 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("external-secret-leaked"))
			return
		}
		ver := NewBackendVerifierKeyring(vk, testAudience)
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

	bu, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	dp, err := New(Config{
		Terminator: buildTerminatorWithSigner(t, keyring),
		BackendURL: bu,
		Audience:   testAudience,
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := dpRaw()

	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("rotated-signature request rejected by backend: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "accepted:acct_dp") {
		t.Fatalf("backend must accept assertion signed by the rotated keyring: %q", rec.Body.String())
	}
}

// TestDataPlaneDenialMapsStatus proves a request with no external credential
// produces a 401 with a safe reason and never reaches the backend.
func TestDataPlaneDenialMapsStatus(t *testing.T) {
	signer, _ := terminator.GenerateSigner()
	dp, err := New(Config{
		Terminator: buildTerminator(t, signer),
		BackendURL: &url.URL{Scheme: "http", Host: "backend.internal"},
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
	if rec.Header().Get("X-Gripline-Request-ID") == "" {
		t.Fatal("denial must carry a request id")
	}
}

func TestDataPlaneRejectsBackendURLComponents(t *testing.T) {
	signer, _ := terminator.GenerateSigner()
	base := &url.URL{Scheme: "http", Host: "backend.internal", User: url.User("bad"), RawQuery: "token=secret", Fragment: "bad"}
	if _, err := New(Config{Terminator: buildTerminator(t, signer), BackendURL: base, Audience: testAudience}); err == nil {
		t.Fatal("backend URL userinfo/query/fragment must be rejected")
	}
}

// P0.7 regression: the client cannot select the upstream host. A request
// addressed at ANY origin is forwarded to the CONFIGURED backend only — the
// client-supplied scheme/host are discarded and the path is safely joined.
func TestDataPlaneClientCannotSelectUpstreamHost(t *testing.T) {
	signer, _ := terminator.GenerateSigner()

	var gotPath, gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.Path
		ver := NewBackendVerifier(signer.Public(), testAudience)
		if _, verr := ver.Verify(r); verr != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bu, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	dp, err := New(Config{
		Terminator: buildTerminator(t, signer),
		BackendURL: bu,
		Audience:   testAudience,
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := dpRaw()
	// The attacker addresses the proxy at an "upstream-looking" origin and a
	// traversal-flavored path; neither may influence where the request lands.
	req := httptest.NewRequest("POST", "http://evil.example/../../v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("request should succeed: %d %s", rec.Code, rec.Body.String())
	}
	if gotHost != bu.Host {
		t.Fatalf("upstream host = %q, want configured backend %q (client host must be discarded)", gotHost, bu.Host)
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("upstream path = %q, want cleaned /v1/messages (no traversal)", gotPath)
	}
}

// P0.8/P0.9 regression: the reservation is released exactly once through the
// unified lifecycle, on a successful stream AND on a backend transport error.
func TestDataPlaneReservationReleasedOnSuccessAndTransportError(t *testing.T) {
	signer, _ := terminator.GenerateSigner()

	// Successful backend: request completes, release must happen (governor
	// balance returns to full).
	gov := resource.NewGovernor(nil)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bu, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	term := buildTerminatorWithGovernor(t, signer, gov)
	dp, err := New(Config{Terminator: term, BackendURL: bu, Audience: testAudience})
	if err != nil {
		t.Fatal(err)
	}
	raw := dpRaw()

	run := func() int {
		req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+raw)
		rec := httptest.NewRecorder()
		dp.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := run(); c != http.StatusOK {
		t.Fatalf("success run: %d", c)
	}
	if inUse := gov.InUseAll(); inUse != 0 {
		t.Fatalf("P0.9: reservation leaked after successful stream: %d slots in use", inUse)
	}

	// Transport error path: unreachable backend port; the reservation must
	// still release (P0.8: one lifecycle, no leak on error branches).
	bad, err := url.Parse("http://127.0.0.1:1") // nothing listens here
	if err != nil {
		t.Fatal(err)
	}
	dpBad, err := New(Config{Terminator: buildTerminatorWithGovernor(t, signer, gov), BackendURL: bad, Audience: testAudience})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	dpBad.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("transport error should map to 502, got %d", rec.Code)
	}
	if inUse := gov.InUseAll(); inUse != 0 {
		t.Fatalf("P0.8: reservation leaked on transport error: %d slots in use", inUse)
	}
}

// TestDataPlaneCredentialLeakIntoResolvers (BETA-01) verifies that resolvers
// (FeatureResolver, SourceResolver, UsageEstimator) never receive secret
// carriers or the reserved Gripline-* namespace. Each resolver is hostile:
// it fails the test if it sees a carrier in the Observation.Header.
func TestDataPlaneCredentialLeakIntoResolvers(t *testing.T) {
	signer, _ := terminator.GenerateSigner()

	dp, err := New(Config{
		Terminator: buildTerminator(t, signer),
		BackendURL: &url.URL{Scheme: "http", Host: "127.0.0.1:0"},
		Audience:   testAudience,
		Features:   hostileFeatures{t: t},
		Sources:    hostileSource{t: t},
		Usage:      hostileUsage{t: t},
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+dpRaw())
	req.Header.Set("X-Api-Key", "secondary-secret")
	req.Header.Set("X-Gripline-Principal", "forged")
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)
}

// hostileFeatures is a FeatureResolver that fails the test if it sees secret carriers.
type hostileFeatures struct {
	t *testing.T
}

func (h hostileFeatures) Resolve(obs Observation) lane.Features {
	assertSanitized(h.t, obs.Header, "FeatureResolver")
	return HeaderFeatures{}.Resolve(obs)
}

// hostileSource is a SourceResolver that fails the test if it sees secret carriers.
type hostileSource struct {
	t *testing.T
}

func (h hostileSource) ResolveSource(obs Observation) (terminator.TrustedSource, error) {
	assertSanitized(h.t, obs.Header, "SourceResolver")
	return terminator.TrustedSource{}, nil
}

// hostileUsage is a UsageProvider that fails the test if it sees secret carriers.
type hostileUsage struct {
	t *testing.T
}

func (h hostileUsage) Estimate(obs Observation) resource.UsageEstimate {
	assertSanitized(h.t, obs.Header, "UsageProvider.Estimate")
	return resource.UsageEstimate{Requests: 1}
}

func (h hostileUsage) Begin(obs Observation, _ *http.Response) UsageSession {
	assertSanitized(h.t, obs.Header, "UsageProvider.Begin")
	return hostileSession(h)
}

type hostileSession struct {
	t *testing.T
}

func (h hostileSession) ObserveChunk([]byte) {}
func (h hostileSession) Finish(error) resource.UsageEstimate {
	return resource.UsageEstimate{Requests: 1}
}

// assertSanitized verifies that the given header map carries no secret carriers
// and no reserved Gripline-* headers.
func assertSanitized(t *testing.T, h http.Header, name string) {
	for _, k := range []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key"} {
		if len(h.Values(k)) > 0 {
			t.Fatalf("BETA-01: %s saw secret carrier %s=%v", name, k, h.Values(k))
		}
	}
	for kk := range h {
		lk := strings.ToLower(kk)
		if strings.HasPrefix(lk, "gripline-") || strings.HasPrefix(lk, "x-gripline-") {
			t.Fatalf("BETA-01: %s saw reserved header %s", name, kk)
		}
	}
}

// TestMaxBodyBytesEnforced (BETA-08) verifies that oversized request bodies
// are rejected with 413 before admission.
func TestMaxBodyBytesEnforced(t *testing.T) {
	signer, _ := terminator.GenerateSigner()
	term := buildTerminatorWithSigner(t, signer)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("accepted:" + r.Header.Get("X-Gripline-Principal")))
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	// Proxy with a 100-byte body limit.
	dp, err := New(Config{
		Terminator:   term,
		BackendURL:   bu,
		Audience:     testAudience,
		MaxBodyBytes: 100,
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := dpRaw()

	// Oversized body (200 bytes) — Content-Length exceeds limit.
	bigBody := strings.Repeat("x", 200)
	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(bigBody))
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d: %s", rec.Code, rec.Body.String())
	}

	// Small body should succeed.
	smallBody := `{"text":"hi"}`
	req2 := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(smallBody))
	req2.Header.Set("Authorization", "Bearer "+raw)
	rec2 := httptest.NewRecorder()
	dp.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 for small body, got %d: %s", rec2.Code, rec2.Body.String())
	}
}
