package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B-A-M-N/gripline/internal/config"
)

// TestAcceptanceBuildRuntime (P0.17) verifies that the actual application
// composition root works end-to-end.
func TestAcceptanceBuildRuntime(t *testing.T) {
	dir := t.TempDir()

	rawCred := make([]byte, 32)
	rand.Read(rawCred)
	externalSecret := "sk-live-" + fmt.Sprintf("%x", rawCred)

	setBootstrapCredential(t, "cred_test", "acct_test", externalSecret)
	os.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	defer func() {
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
		"backend": {"url": "` + backend.URL + `", "trust_mode": "private_network", "timeout": "5s"},
		"server": {
			"read_timeout": "5s",
			"write_timeout": "5s",
			"idle_timeout": "5s",
			"read_header_timeout": "5s"
		},
		"identity": {"audience": "test-audience"},
		"deployment": {"allow_ephemeral_state": true},
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
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	t.Log("PASS: valid credential authorized via BuildRuntime")
}
