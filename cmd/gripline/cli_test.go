package main

import (
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
	cfgJSON := `{"listen":"127.0.0.1:0","backend":{"url":"` + backendURL + `","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"admin":{"listen":"127.0.0.1:0","operator_tokens":{"op-tok-cli-123456789012345":"cli:credential.lifecycle,lane.lifecycle"}},"tls":{"terminate_tls_upstream":true},"paths":{"state":"` + filepath.Join(dir, "state.db") + `","signer_keyring":"` + filepath.Join(dir, "keyring.json") + `"}}`
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
	if err := runCredentialRevoke(cfgPath, "cred_cli", "", "op-tok-cli-123456789012345"); err == nil {
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
	if err := runCredentialRevoke(cfgPath, "cred_cli", "cli acceptance revoke", "op-tok-cli-123456789012345"); err != nil {
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
