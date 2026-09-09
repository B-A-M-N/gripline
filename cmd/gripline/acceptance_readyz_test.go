package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/B-A-M-N/gripline/internal/config"
)

// TestAcceptanceReadyzIsReal (P1-24): /readyz must consult the runtime's
// actual readiness (a live probe read of the state authority), not echo a
// static flag. Healthy store → 200; a runtime whose state store is closed →
// 503.
func TestAcceptanceReadyzIsReal(t *testing.T) {
	os.Unsetenv("GRIPLINE_BOOTSTRAP_CREDENTIAL")
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	dir := t.TempDir()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfgJSON := `{"listen":"127.0.0.1:0","backend":{"url":"` + backend.URL + `","trust_mode":"private_network","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"tls":{"terminate_tls_upstream":true},"paths":{"state":"` + filepath.Join(dir, "state.db") + `","signer_keyring":"` + filepath.Join(dir, "keyring.json") + `"}}`
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}

	// Healthy: Ready() is nil, and a handler wired like main.go's /readyz
	// returns 200.
	if err := rt.Ready(); err != nil {
		t.Fatalf("fresh runtime must be ready: %v", err)
	}
	if code := probeReadyz(t, rt); code != http.StatusOK {
		t.Fatalf("healthy runtime /readyz must be 200, got %d", code)
	}

	// Closed store: Ready() must fail, /readyz must report 503.
	if err := rt.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := rt.Ready(); err == nil {
		t.Fatal("Ready must fail after the state store is closed")
	}
	if code := probeReadyz(t, rt); code != http.StatusServiceUnavailable {
		t.Fatalf("closed-store /readyz must be 503, got %d", code)
	}
}

// probeReadyz runs a request through a /readyz handler wired exactly like
// main.go's (same checks, same statuses).
func probeReadyz(t *testing.T, rt *Runtime) int {
	t.Helper()
	root := http.NewServeMux()
	var readyOK bool = true // main.go's atomic.Bool equivalent (not draining)
	root.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !readyOK {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err := rt.Ready(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/readyz", nil)
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec.Code
}
