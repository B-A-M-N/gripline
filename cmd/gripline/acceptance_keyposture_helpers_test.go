package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/B-A-M-N/gripline/internal/config"
)

// cfgPathFromString writes a config JSON body to a temp file and returns its
// path for config.Load.
func cfgPathFromString(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ephemeralConfigForPepperTest builds a minimal allow_ephemeral_state config
// for key-posture boot tests.
func ephemeralConfigForPepperTest(t *testing.T) *config.Config {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	cfgJSON := `{"listen":"127.0.0.1:0","backend":{"url":"` + backend.URL + `","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"tls":{"terminate_tls_upstream":true},"paths":{"signer_keyring":"` + t.TempDir() + `/keyring.json"}}`
	cfg, err := config.Load(cfgPathFromString(t, cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// ingressConfig returns an IngressSection with the given base64 pseudonym key.
func ingressConfig(t *testing.T, pseudonymKey string) *config.IngressSection {
	t.Helper()
	return &config.IngressSection{PseudonymKey: pseudonymKey}
}
