package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// backendVerifier is a test backend that verifies the internal assertion
// like a real private backend would (P0.17).
type backendVerifier struct {
	verifier   *terminator.VerifierKeyring
	audience   string
	hits       atomic.Int64
	authorized atomic.Int64
	rejected   atomic.Int64
	lastClaims atomic.Value
}

func newBackendVerifierFromKeyring(kr *terminator.Keyring, audience string) *backendVerifier {
	return &backendVerifier{
		verifier: kr.PublishVerifier(),
		audience: audience,
	}
}

func (b *backendVerifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.hits.Add(1)
	if r.Header.Get("Authorization") != "" {
		b.rejected.Add(1)
		http.Error(w, "raw_credential_rejected", http.StatusForbidden)
		return
	}
	assertion := r.Header.Get("X-Gripline-Assertion")
	if assertion == "" {
		b.rejected.Add(1)
		http.Error(w, "missing_assertion", http.StatusUnauthorized)
		return
	}
	claims, err := b.verifier.Verify(assertion, b.audience, time.Now())
	if err != nil {
		b.rejected.Add(1)
		http.Error(w, "invalid_assertion", http.StatusUnauthorized)
		return
	}
	b.authorized.Add(1)
	b.lastClaims.Store(claims)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "ok",
		"sub":       claims.Subject,
		"cid":       claims.CredID,
		"lane":      claims.LaneID,
		"policyRev": fmt.Sprintf("%d", claims.PolicyRev),
	})
}

func TestAcceptanceEndToEnd(t *testing.T) {
	dir := t.TempDir()
	rawCred := make([]byte, 32)
	rand.Read(rawCred)
	externalSecret := "sk-live-" + fmt.Sprintf("%x", rawCred)
	setBootstrapCredential(t, "cred_e2e", "acct_e2e", externalSecret)
	os.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	defer func() {
		os.Unsetenv("GRIPLINE_PEPPER_V1")
	}()
	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	be := newBackendVerifierFromKeyring(kr, "test-audience")
	backend := httptest.NewServer(be)
	defer backend.Close()
	keyringPath := filepath.Join(dir, "keyring.json")
	if err := kr.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := fmt.Sprintf(`{"listen":"127.0.0.1:0","backend":{"url":"%s","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"tls":{"terminate_tls_upstream":true},"paths":{"evidence":"%s","signer_keyring":"%s"}}`, backend.URL, filepath.Join(dir, "evidence.gob"), keyringPath)
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	defer func() { _ = rt.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: rt.DataPlane}
	go srv.Serve(ln)
	defer srv.Close()
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())
	req, _ := http.NewRequest("POST", baseURL+"/v1/messages", strings.NewReader(`{"text":"hi"}`))
	req.Header.Set("Authorization", "Bearer "+externalSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("valid credential: expected 200, got %d: %s", resp.StatusCode, body)
	}
	if be.hits.Load() != 1 {
		t.Fatalf("backend hits = %d, want 1", be.hits.Load())
	}
	if be.authorized.Load() != 1 {
		t.Fatalf("backend authorized = %d, want 1", be.authorized.Load())
	}
	// The provisioned credential id must be honored end-to-end: the claimed
	// credential id delivered to the protected backend must match the record.
	claimsVal := be.lastClaims.Load()
	if claimsVal == nil {
		t.Fatal("backend did not record claims")
	}
	if c := claimsVal.(*terminator.Claims); c.CredID != "cred_e2e" {
		t.Fatalf("expected claimed CredID cred_e2e (from the provisioned record), got %s", c.CredID)
	}
	req2, _ := http.NewRequest("POST", baseURL+"/v1/messages", strings.NewReader(`{"text":"x"}`))
	req2.Header.Set("Authorization", "Bearer sk-invalid-credential")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("invalid credential: expected 401, got %d: %s", resp2.StatusCode, body)
	}
	if be.hits.Load() != 1 {
		t.Fatalf("backend should not be reached on invalid credential, hits = %d", be.hits.Load())
	}
	req3, _ := http.NewRequest("POST", baseURL+"/v1/messages", strings.NewReader(`{"text":"x"}`))
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	if resp3.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp3.Body)
		t.Fatalf("no credential: expected 401, got %d: %s", resp3.StatusCode, body)
	}
	if be.hits.Load() != 1 {
		t.Fatalf("backend should not be reached without credential, hits = %d", be.hits.Load())
	}
	t.Log("PASS: end-to-end data-plane flow verified")
}

func TestAcceptanceOversizedBody(t *testing.T) {
	dir := t.TempDir()
	rawCred := make([]byte, 32)
	rand.Read(rawCred)
	externalSecret := "sk-live-" + fmt.Sprintf("%x", rawCred)
	setBootstrapCredential(t, "cred_size", "acct_size", externalSecret)
	os.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	defer func() {
		os.Unsetenv("GRIPLINE_PEPPER_V1")
	}()
	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	be := newBackendVerifierFromKeyring(kr, "test-audience")
	backend := httptest.NewServer(be)
	defer backend.Close()
	keyringPath := filepath.Join(dir, "keyring.json")
	if err := kr.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := fmt.Sprintf(`{"listen":"127.0.0.1:0","backend":{"url":"%s","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s","max_body_bytes":1024},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"tls":{"terminate_tls_upstream":true},"paths":{"signer_keyring":"%s"}}`, backend.URL, keyringPath)
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	defer func() { _ = rt.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: rt.DataPlane}
	go srv.Serve(ln)
	defer srv.Close()
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())
	bigBody := strings.Repeat("x", 2048)
	req, _ := http.NewRequest("POST", baseURL+"/v1/messages", strings.NewReader(bigBody))
	req.Header.Set("Authorization", "Bearer "+externalSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("oversized body: expected 413, got %d: %s", resp.StatusCode, body)
	}
	if be.hits.Load() != 0 {
		t.Fatalf("backend should not be reached on oversized body, hits = %d", be.hits.Load())
	}
	t.Log("PASS: oversized body rejected before admission")
}

func TestAcceptanceSharedAuthorities(t *testing.T) {
	dir := t.TempDir()
	setBootstrapCredential(t, "cred_shared", "acct_shared", "sk-test-shared-auth-1234567890")
	os.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	defer func() {
		os.Unsetenv("GRIPLINE_PEPPER_V1")
	}()
	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	be := newBackendVerifierFromKeyring(kr, "test-audience")
	backend := httptest.NewServer(be)
	defer backend.Close()
	keyringPath := filepath.Join(dir, "keyring.json")
	if err := kr.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := fmt.Sprintf(`{"listen":"127.0.0.1:0","backend":{"url":"%s","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"tls":{"terminate_tls_upstream":true},"paths":{"evidence":"%s","signer_keyring":"%s"}}`, backend.URL, filepath.Join(dir, "evidence.gob"), keyringPath)
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	defer func() { _ = rt.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: rt.DataPlane}
	go srv.Serve(ln)
	defer srv.Close()
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())
	req, _ := http.NewRequest("POST", baseURL+"/v1/messages", strings.NewReader(`{"text":"hi"}`))
	req.Header.Set("Authorization", "Bearer sk-test-shared-auth-1234567890")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	claimsVal := be.lastClaims.Load()
	if claimsVal == nil {
		t.Fatal("backend did not record claims")
	}
	claims := claimsVal.(*terminator.Claims)
	if claims.CredID != "cred_shared" {
		t.Fatalf("expected credID cred_shared, got %s", claims.CredID)
	}
	rec, ok := rt.Lanes.Get(claims.CredID, claims.LaneID)
	if !ok {
		t.Fatalf("lane %s not found in shared lane store after admission", claims.LaneID)
	}
	if rec.State.String() == "" {
		t.Fatal("lane record has no state")
	}
	t.Log("PASS: shared authorities identity verified behaviorally")
}

// mustInsertCred wires an additional credential into the shared registry at
// runtime (mirroring the env-bootstrap derivation in bootstrapCredentials).
// Each distinct credential resolves to a distinct lane, so probing it exercises
// the NEW-lane admission path deterministically.
func mustInsertCred(t *testing.T, reg *credential.MemoryRegistry, id, secretStr string) {
	t.Helper()
	sealed := secret.NewFromBytes([]byte(secretStr))
	ver := credential.Verifier(sealed, &credential.PepperKey{Version: 1, Key: testPepperKey()})
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID:  id,
		AccountID:     "acct_behavior",
		Verifier:      ver,
		PepperVersion: 1,
		Status:        credential.StatusNormal,
		PolicyID:      "fi-default-v1",
		PlanID:        "plan-a",
		CreatedAt:     time.Now().Add(-time.Hour),
		Revision:      1,
	}); err != nil {
		t.Fatalf("insert credential %s: %v", id, err)
	}
}

// doProbe POSTs to the data plane and returns (status, body). The response is
// drained even on error so the proxy can be reused.
func doProbe(t *testing.T, baseURL, secretStr string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", baseURL+"/v1/messages", strings.NewReader(`{"text":"hi"}`))
	req.Header.Set("Authorization", "Bearer "+secretStr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", baseURL+"/v1/messages", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestAcceptanceSharedControlBehavioral proves the shared in-memory ControlPlane
// (emergency posture) is the SAME object the data plane consults — by behavior,
// not just by non-nil fields (P0.1). Flipping the plane's posture through
// rt.Control must change what rt.DataPlane does on the next admission, and
// backing it out must restore normal behavior.
func TestAcceptanceSharedControlBehavioral(t *testing.T) {
	dir := t.TempDir()
	setBootstrapCredential(t, "cred_behavioral", "acct_behavioral", "sk-behavioral-base-123456789012345678")
	os.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	defer func() {
		os.Unsetenv("GRIPLINE_PEPPER_V1")
	}()
	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	be := newBackendVerifierFromKeyring(kr, "test-audience")
	backend := httptest.NewServer(be)
	defer backend.Close()
	keyringPath := filepath.Join(dir, "keyring.json")
	if err := kr.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := fmt.Sprintf(`{"listen":"127.0.0.1:0","backend":{"url":"%s","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"tls":{"terminate_tls_upstream":true},"paths":{"evidence":"%s","signer_keyring":"%s"}}`, backend.URL, filepath.Join(dir, "evidence.gob"), keyringPath)
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	defer func() { _ = rt.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: rt.DataPlane}
	go srv.Serve(ln)
	defer srv.Close()
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())

	// NORMAL posture: probe an untouched credential → its new lane is admitted.
	mustInsertCred(t, rt.Registry.(*credential.MemoryRegistry), "beh_normal", "sk-behavioral-normal-000000000000000001")
	if code, _ := doProbe(t, baseURL, "sk-behavioral-normal-000000000000000001"); code != http.StatusOK {
		t.Fatalf("normal posture: expected 200, got %d", code)
	}
	if rt.Control.InEmergency() {
		t.Fatal("expected normal posture (not emergency) after boot")
	}

	// Flip the SHARED control plane into EMERGENCY_LOCKDOWN via the runtime field.
	rt.Control.SetEmergency(true, "operator-acceptance", "behavioral lockdown")
	if !rt.Control.InEmergency() {
		t.Fatalf("SetEmergency(true) did not enter lockdown (posture %s)", rt.Control.Posture())
	}

	// EMERGENCY posture: a NEW lane must be denied by the shared control plane,
	// proving the data plane consults the exact plane we just mutated.
	mustInsertCred(t, rt.Registry.(*credential.MemoryRegistry), "beh_lock", "sk-behavioral-lock-0000000000000000001")
	codeLock, bodyLock := doProbe(t, baseURL, "sk-behavioral-lock-0000000000000000001")
	if codeLock != http.StatusForbidden {
		t.Fatalf("emergency posture: expected 403 denying new lane, got %d (body %q)", codeLock, bodyLock)
	}
	if !strings.Contains(bodyLock, "emergency_lockdown") {
		t.Fatalf("emergency posture: expected reason emergency_lockdown, got body %q", bodyLock)
	}

	// Emergence ON->OFF->ON must be invertible (SetEmergency toggles the same object).
	rt.Control.SetEmergency(false, "operator-acceptance", "behavioral recovery")
	if rt.Control.InEmergency() {
		t.Fatal("SetEmergency(false) did not exit lockdown")
	}

	// NORMAL restored: a fresh credential is admitted again.
	mustInsertCred(t, rt.Registry.(*credential.MemoryRegistry), "beh_restore", "sk-behavioral-restore-000000000000000001")
	if code, _ := doProbe(t, baseURL, "sk-behavioral-restore-000000000000000001"); code != http.StatusOK {
		t.Fatalf("post-recovery posture: expected 200, got %d", code)
	}

	t.Log("PASS: shared ControlPlane identity proven behaviorally through rt.Control")
}

// TestAcceptanceAdminPostureLockdown drives the REAL admin HTTP endpoint
// (/admin/posture) through the actual listener with bearer-token auth. It
// proves emergency lockdown is operator-triggerable over the wire and that the
// admin surface rejects unauthenticated requests.
func TestAcceptanceAdminPostureLockdown(t *testing.T) {
	dir := t.TempDir()
	setBootstrapCredential(t, "cred_admin", "acct_admin", "sk-admin-base-12345678901234567890")
	os.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	defer func() {
		os.Unsetenv("GRIPLINE_PEPPER_V1")
	}()
	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	be := newBackendVerifierFromKeyring(kr, "test-audience")
	backend := httptest.NewServer(be)
	defer backend.Close()
	keyringPath := filepath.Join(dir, "keyring.json")
	if err := kr.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	opToken := "op-token-acceptance-0123456789abcdef0123456789abcdef"
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := fmt.Sprintf(`{"listen":"127.0.0.1:0","backend":{"url":"%s","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"admin":{"listen":"127.0.0.1:0","operator_tokens":{"%s":"operator:posture.control"}},"tls":{"terminate_tls_upstream":true},"paths":{"evidence":"%s","signer_keyring":"%s","audit_log":"%s"}}`, backend.URL, opToken, filepath.Join(dir, "evidence.gob"), keyringPath, filepath.Join(dir, "audit.jsonl"))
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	defer func() { _ = rt.Close() }()

	// Data plane listener.
	dpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dpLn.Close()
	dpSrv := &http.Server{Handler: rt.DataPlane}
	go dpSrv.Serve(dpLn)
	defer dpSrv.Close()
	baseURL := fmt.Sprintf("http://%s", dpLn.Addr().String())

	// Admin listener uses the real rt.Admin server (its mux + handler).
	admLn, err := net.Listen("tcp", cfg.Admin.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer admLn.Close()
	go rt.Admin.Serve(admLn)
	defer func() { _ = rt.Admin.Close() }()
	admURL := fmt.Sprintf("http://%s", admLn.Addr().String())

	// Normal posture: bootstrap credential admitted.
	if code, _ := doProbe(t, baseURL, "sk-admin-base-12345678901234567890"); code != http.StatusOK {
		t.Fatalf("normal posture: expected 200, got %d", code)
	}
	if rt.Control.InEmergency() {
		t.Fatal("expected normal posture after boot")
	}

	// Unauthenticated admin POST must be rejected (401) — proves admin auth.
	unauth, err := http.NewRequest("POST", admURL+"/admin/posture", strings.NewReader(`{"on":true,"reason":"acceptance"}`))
	if err != nil {
		t.Fatal(err)
	}
	unauth.Header.Set("Content-Type", "application/json")
	uresp, err := http.DefaultClient.Do(unauth)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, uresp.Body)
	uresp.Body.Close()
	if uresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin without bearer token: expected 401, got %d", uresp.StatusCode)
	}
	// A WRONG token is equally rejected.
	wrong, _ := http.NewRequest("POST", admURL+"/admin/posture", strings.NewReader(`{"on":true,"reason":"acceptance"}`))
	wrong.Header.Set("Authorization", "Bearer wrong-token")
	wresp, err := http.DefaultClient.Do(wrong)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, wresp.Body)
	wresp.Body.Close()
	if wresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin with wrong token: expected 401, got %d", wresp.StatusCode)
	}

	// Authorized OP turns EMERGENCY ON via the real endpoint.
	onReq, _ := http.NewRequest("POST", admURL+"/admin/posture", strings.NewReader(`{"on":true,"reason":"acceptance"}`))
	onReq.Header.Set("Authorization", "Bearer "+opToken)
	onReq.Header.Set("Content-Type", "application/json")
	onResp, err := http.DefaultClient.Do(onReq)
	if err != nil {
		t.Fatal(err)
	}
	onBody, _ := io.ReadAll(onResp.Body)
	onResp.Body.Close()
	if onResp.StatusCode != http.StatusOK {
		t.Fatalf("admin posture ON: expected 200, got %d body %q", onResp.StatusCode, onBody)
	}
	if !strings.Contains(string(onBody), "EMERGENCY_LOCKDOWN") {
		t.Fatalf("admin posture ON body should report EMERGENCY_LOCKDOWN, got %q", onBody)
	}
	if !rt.Control.InEmergency() {
		t.Fatal("admin posture ON did not flip the shared control plane to emergency")
	}

	// Data plane must now deny a NEW lane.
	mustInsertCred(t, rt.Registry.(*credential.MemoryRegistry), "admin_lock", "sk-admin-lock-00000000000000000001")
	if code, body := doProbe(t, baseURL, "sk-admin-lock-00000000000000000001"); code != http.StatusForbidden {
		t.Fatalf("emergency posture via admin: expected 403, got %d body %q", code, body)
	}

	// Authorized OP restores NORMAL.
	offReq, _ := http.NewRequest("POST", admURL+"/admin/posture", strings.NewReader(`{"on":false,"reason":"acceptance"}`))
	offReq.Header.Set("Authorization", "Bearer "+opToken)
	offReq.Header.Set("Content-Type", "application/json")
	offResp, err := http.DefaultClient.Do(offReq)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, offResp.Body)
	offResp.Body.Close()
	if offResp.StatusCode != http.StatusOK {
		t.Fatalf("admin posture OFF: expected 200, got %d", offResp.StatusCode)
	}
	if rt.Control.InEmergency() {
		t.Fatal("admin posture OFF did not exit emergency")
	}
	mustInsertCred(t, rt.Registry.(*credential.MemoryRegistry), "admin_restore", "sk-admin-restore-0000000000000000001")
	if code, _ := doProbe(t, baseURL, "sk-admin-restore-0000000000000000001"); code != http.StatusOK {
		t.Fatalf("post-recovery via admin: expected 200, got %d", code)
	}

	t.Log("PASS: real admin HTTP endpoint drives emergency lockdown over the wire with auth")
}

// TestAcceptanceBackendContainment drives a REAL protected backend (the
// verifier-backed backendVerifier) and proves it rejects assertions that are
// missing, forged, or bound to the wrong audience — the containment the proxy
// relies on (INV-10/11, P0.17).
func TestAcceptanceBackendContainment(t *testing.T) {
	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	be := newBackendVerifierFromKeyring(kr, "test-audience")
	backend := httptest.NewServer(be)
	defer backend.Close()

	validClaims := terminator.Claims{
		Subject:   "acct_containment",
		CredID:    "cred_containment",
		Audience:  "test-audience",
		JTI:       "req-containment-1",
		Scope:     []string{"inference"},
		PolicyRev: 1,
		CredRev:   1,
	}
	valid, err := kr.Issue(validClaims, 30*time.Second)
	if err != nil {
		t.Fatalf("issue valid assertion: %v", err)
	}
	validEnc := valid.Encode()

	// POST helper against the raw protected backend.
	post := func(assertion string) (int, string) {
		req, _ := http.NewRequest("POST", backend.URL+"/v1/messages", strings.NewReader(`{"text":"hi"}`))
		if assertion != "" {
			req.Header.Set("X-Gripline-Assertion", assertion)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("backend POST: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// 1. Valid assertion → authorized.
	if code, _ := post(validEnc); code != http.StatusOK {
		t.Fatalf("valid assertion: expected 200, got %d", code)
	}
	if be.authorized.Load() != 1 {
		t.Fatalf("valid assertion: backend authorized = %d, want 1", be.authorized.Load())
	}

	// 2. No assertion → rejected 401 (missing_assertion).
	if code, body := post(""); code != http.StatusUnauthorized {
		t.Fatalf("no assertion: expected 401, got %d body %q", code, body)
	}

	// 3. Forged assertion (tampered payload) → rejected 401 (invalid_assertion).
	dot := strings.IndexByte(validEnc, '.')
	if dot < 0 {
		t.Fatal("encoded assertion missing '.'")
	}
	payloadPart, sigPart := validEnc[:dot], validEnc[dot+1:]
	forged := flipFirstChar(payloadPart)
	tampered := forged + "." + sigPart
	if code, body := post(tampered); code != http.StatusUnauthorized {
		t.Fatalf("forged assertion: expected 401, got %d body %q", code, body)
	}

	// 4. Wrong-audience assertion (correctly signed, wrong aud) → rejected 401.
	wrongAud := validClaims
	wrongAud.Audience = "some-other-audience"
	wrongAud.JTI = "req-containment-2"
	wa, err := kr.Issue(wrongAud, 30*time.Second)
	if err != nil {
		t.Fatalf("issue wrong-audience assertion: %v", err)
	}
	if code, body := post(wa.Encode()); code != http.StatusUnauthorized {
		t.Fatalf("wrong-audience assertion: expected 401, got %d body %q", code, body)
	}

	// Only the single valid assertion was authorized.
	if be.authorized.Load() != 1 {
		t.Fatalf("authorized count = %d, want exactly 1 (only the valid assertion)", be.authorized.Load())
	}
	t.Log("PASS: protected backend rejects missing/forged/wrong-audience assertions")
}

// flipFirstChar returns s with its first byte altered (for signature-tamper tests).
func flipFirstChar(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	b[0] = b[0] ^ 0xff
	return string(b)
}
