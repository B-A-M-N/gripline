package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// testPepperEnv is the base64 pepper the acceptance tests set in
// GRIPLINE_PEPPER_V1; testPepperKey is the DECODED key material, for test
// sites that build verifier keys directly (the runtime decodes the env value
// before deriving verifiers).
const testPepperEnv = "Z3JpcGxpbmUtdGVzdC1wZXBwZXItdjEtMDEyMzQ1Njc4OWFiY2RlZg=="

func testPepperKey() []byte {
	key, err := base64.StdEncoding.DecodeString(testPepperEnv)
	if err != nil {
		panic(err)
	}
	return key
}

func TestBootstrapCredentialUsesDerivedVerifierContract(t *testing.T) {
	reg := credential.NewMemoryRegistry()
	setBootstrapCredential(t, "cred_bootstrap", "acct_bootstrap", "sk-bootstrap-12345678901234567890")
	if err := bootstrapCredentials(reg); err != nil {
		t.Fatalf("derived verifier bootstrap must succeed: %v", err)
	}
	// A raw credential environment variable is not a bootstrap input. It is
	// intentionally ignored by the production composition root.
	t.Setenv("GRIPLINE_CREDENTIAL_SECRET", "sk-raw-secret-must-not-bootstrap")
	t.Setenv("GRIPLINE_BOOTSTRAP_CREDENTIAL", "")
	if err := bootstrapCredentials(credential.NewMemoryRegistry()); err != nil {
		t.Fatalf("raw secret must not affect bootstrap: %v", err)
	}
}

func setBootstrapCredential(t *testing.T, id, account, raw string) {
	t.Helper()
	sealed := secret.NewFromBytes([]byte(raw))
	verifier := credential.Verifier(sealed, &credential.PepperKey{Version: 1, Key: testPepperKey()})
	sealed.Zero()
	rec := credential.CredentialRecord{
		CredentialID: id, AccountID: account, Verifier: verifier, VerifierVersion: 1,
		PepperVersion: 1, Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal bootstrap verifier: %v", err)
	}
	for i := range verifier {
		verifier[i] = 0
	}
	t.Setenv("GRIPLINE_BOOTSTRAP_CREDENTIAL", string(b))
}

func TestLoadVersionedPepperRing(t *testing.T) {
	second := base64.StdEncoding.EncodeToString([]byte("gripline-test-pepper-v2-material-32!!"))
	cfg := &config.Config{Secrets: config.SecretsSection{PepperVersions: map[string]string{
		"1": testPepperEnv, "2": second,
	}}}
	ring, err := loadPepperRing(cfg)
	if err != nil {
		t.Fatalf("load versioned pepper ring: %v", err)
	}
	if ring.Latest() != 2 {
		t.Fatalf("latest pepper version=%d, want 2", ring.Latest())
	}
	if got := ring.Versions(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("pepper versions=%v, want [1 2]", got)
	}
}

// TestRuntimeSharedAuthorities (P0.1) verifies that BuildRuntime creates
// a single set of shared authorities used by both the data plane and admin.
func TestRuntimeSharedAuthorities(t *testing.T) {
	dir := t.TempDir()

	setBootstrapCredential(t, "cred_runtime_test", "acct_runtime_test", "sk-runtime-test-123456789012345678")
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
		"backend": {"url": "` + backend.URL + `", "timeout": "5s"},
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
