package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/statepg"
)

type fakeCryptoStatusReader struct {
	status statepg.ClusterStatus
	err    error
}

func (f fakeCryptoStatusReader) ClusterStatus(context.Context) (statepg.ClusterStatus, error) {
	return f.status, f.err
}

func TestActiveCredentialPepperUsesSharedActiveGeneration(t *testing.T) {
	ring, err := credential.NewPepperRing(
		&credential.PepperKey{Version: 1, Key: []byte("pepper-generation-one")},
		&credential.PepperKey{Version: 2, Key: []byte("pepper-generation-two")},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.SetActiveVersion(2); err != nil {
		t.Fatal(err)
	}
	shared := fakeCryptoStatusReader{status: statepg.ClusterStatus{Crypto: statepg.ClusterCryptoStatus{
		Initialized: true, PepperActiveVersion: 1,
	}}}
	version, err := activeCredentialPepperVersion(context.Background(), ring, shared)
	if err != nil {
		t.Fatalf("resolve shared pepper: %v", err)
	}
	if version != 1 {
		t.Fatalf("resolved pepper version=%d, want shared active version 1", version)
	}
}

func TestActiveCredentialPepperRejectsMissingSharedGeneration(t *testing.T) {
	ring, err := credential.NewPepperRing(&credential.PepperKey{Version: 1, Key: []byte("pepper-generation-one")})
	if err != nil {
		t.Fatal(err)
	}
	shared := fakeCryptoStatusReader{status: statepg.ClusterStatus{Crypto: statepg.ClusterCryptoStatus{
		Initialized: true, PepperActiveVersion: 2,
	}}}
	if _, err := activeCredentialPepperVersion(context.Background(), ring, shared); err == nil {
		t.Fatal("missing locally loaded shared pepper generation must fail closed")
	}
}

func TestActiveCredentialPolicyBindsAndRejectsStaleRequest(t *testing.T) {
	manager, err := policy.NewManager(policy.Default(), policy.Options{})
	if err != nil {
		t.Fatal(err)
	}
	active, err := activeCredentialPolicy(context.Background(), manager, "")
	if err != nil {
		t.Fatalf("resolve active policy: %v", err)
	}
	if active != policy.DefaultPolicyID {
		t.Fatalf("active policy=%q, want %q", active, policy.DefaultPolicyID)
	}
	if _, err := activeCredentialPolicy(context.Background(), manager, "stale-policy"); !errors.Is(err, errCredentialPolicyInactive) {
		t.Fatalf("stale policy error=%v, want errCredentialPolicyInactive", err)
	}
}

func TestCLICredentialAddReadsClusterPolicyAndPepper(t *testing.T) {
	const token = "op-cluster-add-0123456789abcdef0123456789abcdef"
	var received map[string]any
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("cluster credential add authorization header missing")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/admin/policy":
			_, _ = w.Write([]byte(`{"active":{"id":"policy-cluster-b"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/admin/crypto":
			_, _ = w.Write([]byte(`{"crypto":{"initialized":true,"pepper_active_version":1}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/admin/credentials/add":
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Fatalf("decode clustered credential add: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer admin.Close()

	secondPepper := base64.StdEncoding.EncodeToString([]byte("gripline-test-pepper-v2-material-32!!"))
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := fmt.Sprintf(`{"listen":"127.0.0.1:8080","backend":{"url":"http://backend.invalid:80","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"tls":{"terminate_tls_upstream":true},"authority":{"backend":"postgres","dsn_env":"GRIPLINE_DSN","node_id":"cli-node","lease_ttl":"30s","renew_every":"5s"},"secrets":{"pepper_versions":{"1":%q,"2":%q}},"admin":{"listen":%q,"operator_tokens":{%q:"ops:credential.lifecycle,cluster.read,policy.install"}},"paths":{"signer_keyring":"%s"}}`, testPepperEnv, secondPepper, strings.TrimPrefix(admin.URL, "http://"), token, filepath.Join(dir, "keyring.json"))
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}

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
	if _, err := writer.WriteString("sk-cluster-add-credential-0123456789"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if err := runCredentialAddLive(cfgPath, "cred_cluster", "acct_cluster", "", "plan-default", "cluster test", token); err != nil {
		t.Fatalf("cluster credential add: %v", err)
	}
	if received["policy_id"] != "policy-cluster-b" {
		t.Fatalf("credential policy=%v, want live policy-cluster-b", received["policy_id"])
	}
	if pepper, ok := received["pepper_version"].(float64); !ok || pepper != 1 {
		t.Fatalf("credential pepper=%v, want shared active generation 1", received["pepper_version"])
	}
}
