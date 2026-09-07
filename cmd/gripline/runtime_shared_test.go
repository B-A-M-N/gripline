package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/B-A-M-N/gripline/internal/config"
)

// TestRuntimeSharedAuthorities (P0.1) verifies that BuildRuntime creates
// a single set of shared authorities used by both the data plane and admin.
func TestRuntimeSharedAuthorities(t *testing.T) {
	dir := t.TempDir()

	os.Setenv("GRIPLINE_CREDENTIAL_SECRET", "sk-runtime-test-123456789012345678")
	os.Setenv("GRIPLINE_CREDENTIAL_ID", "cred_runtime_test")
	os.Setenv("GRIPLINE_PEPPER_V1", "test-pepper-123456789012345678")
	defer func() {
		os.Unsetenv("GRIPLINE_CREDENTIAL_SECRET")
		os.Unsetenv("GRIPLINE_CREDENTIAL_ID")
		os.Unsetenv("GRIPLINE_PEPPER_V1")
	}()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer backend.Close()

	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := `{
		"listen": "127.0.0.1:0",
		"backend": {"url": "` + backend.URL + `", "timeout": "5s"},
		"server": {
			"read_timeout": "5s",
			"write_timeout": "5s",
			"idle_timeout": "5s",
			"read_header_timeout": "5s"
		},
		"identity": {"audience": "test-audience"},
		"tls": {"terminate_tls_upstream": true},
		"paths": {
			"evidence": "` + filepath.Join(dir, "evidence.gob") + `"
		}
	}`
	os.WriteFile(cfgPath, []byte(cfgJSON), 0o640)

	cfgLoaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	rt, err := BuildRuntime(cfgLoaded)
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	defer rt.Close()

	if rt.Registry == nil {
		t.Fatal("Runtime.Registry is nil")
	}
	if rt.Lanes == nil {
		t.Fatal("Runtime.Lanes is nil")
	}
	if rt.Resource == nil {
		t.Fatal("Runtime.Resource is nil")
	}
	if rt.Control == nil {
		t.Fatal("Runtime.Control is nil")
	}
	if rt.Spray == nil {
		t.Fatal("Runtime.Spray is nil")
	}
	if rt.Signer == nil {
		t.Fatal("Runtime.Signer is nil")
	}
	if rt.Evidence == nil {
		t.Fatal("Runtime.Evidence is nil")
	}

	t.Log("PASS: Runtime exposes all shared authorities")
}
