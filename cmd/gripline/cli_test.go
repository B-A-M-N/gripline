package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/secret"
)

// cliStatefulConfig writes a state-backed config with an admin section and
// returns its path (and the dir).
func cliStatefulConfig(t *testing.T, dir, backendURL string) string {
	t.Helper()
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	cfgJSON := `{"listen":"127.0.0.1:0","backend":{"url":"` + backendURL + `","trust_mode":"private_network","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"admin":{"listen":"127.0.0.1:0","operator_tokens":{"op-tok-cli-0123456789abcdef0123456789abcdef":"cli:credential.lifecycle,lane.lifecycle"}},"tls":{"terminate_tls_upstream":true},"paths":{"state":"` + filepath.Join(dir, "state.db") + `","signer_keyring":"` + filepath.Join(dir, "keyring.json") + `"}}`
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCLIStatusCommand (P1-27) proves the capability-status output names the
// durability of every authority honestly.
func TestCLIStatusCommand(t *testing.T) {
	os.Unsetenv("GRIPLINE_BOOTSTRAP_CREDENTIAL")
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer backend.Close()
	cfgPath := cliStatefulConfig(t, dir, backend.URL)

	out := captureStdout(t, func() {
		if err := runStatusCLI(cfgPath); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{
		"credential authority",
		"lane authority",
		"evidence authority",
		"signer identity",
	} {
		if !strings.Contains(out, want) || !strings.Contains(out, "durable") {
			t.Fatalf("status output missing %q as durable:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "source blocking") || !strings.Contains(out, "off") {
		t.Fatalf("status output must report source blocking shadow-only:\n%s", out)
	}
}

func TestCLIStatusCommandRecognizesPostgresAuthority(t *testing.T) {
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer backend.Close()
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := `{"listen":"127.0.0.1:8080","backend":{"url":"` + backend.URL + `","trust_mode":"private_network","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"tls":{"terminate_tls_upstream":true},"authority":{"backend":"postgres","dsn_env":"GRIPLINE_STATUS_DSN","node_id":"status-node","lease_ttl":"10s","renew_every":"2s"}}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runStatusCLI(cfgPath); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{
		"authority backend",
		"postgres",
		"PostgreSQL shared authority",
		"resource persistence",
		"shared-durable",
		"node identity",
		"configured",
		"active policy",
		"shared-authority",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("cluster status missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "process-lifetime") {
		t.Fatalf("PostgreSQL status incorrectly reports process-lifetime resources:\n%s", out)
	}
}

// TestCLILifecycleUsesLiveAdmin proves the normal lifecycle commands talk to
// the running private admin listener. The raw-state helpers remain available
// only behind the explicit --offline flag.
func TestCLILifecycleUsesLiveAdmin(t *testing.T) {
	const token = "op-live-cli-0123456789abcdef0123456789abcdef"
	var revoked bool
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/credentials":
			_ = json.NewEncoder(w).Encode([]credential.Summary{{
				CredentialID: "cred_live", AccountID: "acct_live", Status: "NORMAL",
				PolicyID: "fi-default-v1", CreatedAt: time.Unix(1, 0).UTC(), Revision: 3,
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/admin/credentials/revoke":
			revoked = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"REVOKED"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/lanes":
			_ = json.NewEncoder(w).Encode([]adminLaneSummary{{LaneID: "lane_live", CredentialID: "cred_live", State: "NEW"}})
		case r.Method == http.MethodGet && r.URL.Path == "/admin/security-events":
			_, _ = w.Write([]byte(`[{"sequence":7,"at":"2026-09-07T00:00:00Z","kind":"lane_security","credential_id":"cred_live","lane_id":"lane_live","before":"NORMAL","after":"BLOCKED","risk_score":50,"revision":4,"policy_revision":3,"request_id":"req_live","evidence_codes":["CONCURRENCY_OVER_10X_BASELINE"]}]`))
		case r.Method == http.MethodGet && (r.URL.Path == "/admin/cluster" || r.URL.Path == "/admin/crypto"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"node_id": "node-a", "local_ready": true,
				"nodes":  []map[string]any{{"node_id": "node-a", "state": "ready", "live": true}},
				"crypto": map[string]any{"initialized": true, "generation_epoch": 3},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer admin.Close()

	dir := t.TempDir()
	adminAddr := strings.TrimPrefix(admin.URL, "http://")
	cfgJSON := `{"listen":"127.0.0.1:8080","backend":{"url":"http://backend.invalid:80","trust_mode":"private_network","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"admin":{"listen":"` + adminAddr + `","operator_tokens":{"` + token + `":"ops:credential.lifecycle,lane.lifecycle,cluster.read"}},"tls":{"terminate_tls_upstream":true},"paths":{"audit_log":"` + filepath.Join(dir, "audit.jsonl") + `"}}`
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runCredentialCLI([]string{"list", "--config", cfgPath, "--token", token}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "cred_live") {
		t.Fatalf("live credential list did not use admin response: %s", out)
	}
	if err := runCredentialCLI([]string{"revoke", "--config", cfgPath, "--id", "cred_live", "--reason", "live test", "--token", token}); err != nil {
		t.Fatalf("live credential revoke: %v", err)
	}
	if !revoked {
		t.Fatal("credential revoke did not reach the live admin listener")
	}
	out = captureStdout(t, func() {
		if err := runLaneCLI([]string{"list", "--config", cfgPath, "--credential", "cred_live", "--token", token}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "lane_live") {
		t.Fatalf("live lane list did not use admin response: %s", out)
	}
	out = captureStdout(t, func() {
		if err := runAuditCLI([]string{"security", "list", "--config", cfgPath, "--token", token}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "CONCURRENCY_OVER_10X_BASELINE") || !strings.Contains(out, "req_live") {
		t.Fatalf("security audit list did not use live admin response: %s", out)
	}
	out = captureStdout(t, func() {
		if err := runClusterCLI([]string{"status", "--config", cfgPath, "--token", token}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"local_ready": true`) || !strings.Contains(out, `"generation_epoch": 3`) {
		t.Fatalf("cluster status did not use live admin response: %s", out)
	}
	out = captureStdout(t, func() {
		if err := runCryptoCLI([]string{"status", "--config", cfgPath, "--token", token}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"initialized": true`) {
		t.Fatalf("crypto status did not use live admin response: %s", out)
	}
}

func TestCLICredentialAddUsesSharedExternalContract(t *testing.T) {
	const token = "op-add-cli-0123456789abcdef0123456789abcdef"
	const rawCredential = "sk-cli-add-credential-0123456789"
	var received map[string]any
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/credentials/add" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("credential add authorization header missing")
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode credential add: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer admin.Close()

	dir := t.TempDir()
	adminAddr := strings.TrimPrefix(admin.URL, "http://")
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := `{"listen":"127.0.0.1:8080","backend":{"url":"http://backend.invalid:80","trust_mode":"private_network","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"tls":{"terminate_tls_upstream":true},"admin":{"listen":"` + adminAddr + `","operator_tokens":{"` + token + `":"ops:credential.lifecycle"}},"paths":{"state":"/server-only/state.db"}}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)

	stdin, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = stdin.Close()
	})
	if _, err := writer.WriteString(rawCredential); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if err := runCredentialAddLive(cfgPath, "cred_added", "acct_added", "fi-default-v1", "plan-default", "cli contract test", token); err != nil {
		t.Fatal(err)
	}
	if stringValue, _ := received["verifier_b64"].(string); stringValue == "" {
		t.Fatal("live credential add did not send a derived verifier")
	}
	encoded, _ := json.Marshal(received)
	if strings.Contains(string(encoded), rawCredential) {
		t.Fatal("raw credential must not cross the live admin request")
	}

	// The live client only requires the configured state path; it must not
	// require the CLI process to see or open the server-owned file.
	if _, err := os.Stat(filepath.Join(dir, "state.db")); !os.IsNotExist(err) {
		t.Fatalf("test unexpectedly created a client-side state file: %v", err)
	}
}

func TestCLICredentialAddRejectsOversizedExternalCredential(t *testing.T) {
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	cfgPath := cliStatefulConfig(t, dir, backend.URL)
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	stdin, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = stdin.Close()
	})
	if _, err := writer.WriteString(strings.Repeat("x", 1025)); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if err := runCredentialAddLive(cfgPath, "cred_too_long", "acct", "fi-default-v1", "plan-default", "contract test", "op-tok-cli-0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("1025-byte external credential must be rejected")
	}
}

// TestCLICredentialLifecycle (P1-26) proves the CLI lists credentials and
// revokes through the authorization + atomic mutation path — and refuses to
// run mutations without a reason/token.
func TestCLICredentialLifecycle(t *testing.T) {
	os.Unsetenv("GRIPLINE_BOOTSTRAP_CREDENTIAL")
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer backend.Close()
	cfgPath := cliStatefulConfig(t, dir, backend.URL)

	// Seed one credential directly into the store.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	prov, ok := rt.Registry.(credential.Provisioner)
	if !ok {
		t.Fatal("durable registry must support provisioning")
	}
	pepperKey := testPepperKey()
	sealed := secret.NewFromBytes([]byte("sk-cli-cred-000000000000000000"))
	if _, err := prov.InsertIfAbsent(&credential.CredentialRecord{
		CredentialID: "cred_cli", AccountID: "acct_cli",
		Verifier:      credential.Verifier(sealed, &credential.PepperKey{Version: 1, Key: pepperKey}),
		PepperVersion: 1, Status: credential.StatusNormal,
		PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}

	// list shows it.
	out := captureStdout(t, func() {
		if err := runCredentialList(cfgPath); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "cred_cli") || !strings.Contains(out, "NORMAL") {
		t.Fatalf("credential list must show cred_cli NORMAL:\n%s", out)
	}

	// revoke requires a reason.
	if err := runCredentialRevoke(cfgPath, "cred_cli", "", "op-tok-cli-0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("revoke without a reason must fail")
	}
	// revoke requires a token.
	if err := runCredentialRevoke(cfgPath, "cred_cli", "testing", ""); err == nil {
		t.Fatal("revoke without a token must fail")
	}
	// revoke with a bad token fails closed.
	if err := runCredentialRevoke(cfgPath, "cred_cli", "testing", "wrong-token"); err == nil {
		t.Fatal("revoke with an invalid operator token must fail")
	}
	// revoke succeeds.
	if err := runCredentialRevoke(cfgPath, "cred_cli", "cli acceptance revoke", "op-tok-cli-0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The revocation is durable: the list shows REVOKED.
	out = captureStdout(t, func() {
		if err := runCredentialList(cfgPath); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "REVOKED") {
		t.Fatalf("credential list must show REVOKED after revoke:\n%s", out)
	}
}

// TestCLILaneList proves the lane list path against the durable repository.
func TestCLILaneList(t *testing.T) {
	os.Unsetenv("GRIPLINE_BOOTSTRAP_CREDENTIAL")
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer backend.Close()
	cfgPath := cliStatefulConfig(t, dir, backend.URL)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rt.Lanes.BorrowOrCreate("cred_cli_lanes", "lane_1", laneFeaturesForCLI(), laneContextForCLI()); err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := runLaneList(cfgPath, "cred_cli_lanes"); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "lane_1") || !strings.Contains(out, "NEW") {
		t.Fatalf("lane list must show lane_1 NEW:\n%s", out)
	}

	// Unknown credential: clean empty answer.
	out = captureStdout(t, func() {
		if err := runLaneList(cfgPath, "cred_absent"); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "no lanes") {
		t.Fatalf("absent credential must print 'no lanes':\n%s", out)
	}
}

// captureStdout runs fn and returns what it wrote to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 8192)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	_ = w.Close()
	os.Stdout = old
	out := <-done
	_ = r.Close()
	return out
}

func laneFeaturesForCLI() lane.Features {
	return lane.Features{NetworkASN: "AS1", HTTPVersion: "1.1"}
}

func laneContextForCLI() lane.ClassificationContext {
	return lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()}
}

// TestOpenStateRequiresPersistentDeployment proves the CLI refuses ephemeral
// deployments: there is no lifecycle state to operate on.
func TestOpenStateRequiresPersistentDeployment(t *testing.T) {
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer backend.Close()
	cfgJSON := `{"listen":"127.0.0.1:0","backend":{"url":"` + backend.URL + `","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"tls":{"terminate_tls_upstream":true},"paths":{"signer_keyring":"` + filepath.Join(dir, "kr.json") + `"}}`
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	_, _, err := openStateForCLI(p)
	if err == nil || !strings.Contains(err.Error(), "persistent deployment") {
		t.Fatalf("ephemeral deployment must be refused, got %v", err)
	}
	_ = errors.Is
}
