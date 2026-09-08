package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B-A-M-N/gripline/internal/policy"
)

func TestAcceptanceAdminPolicyLifecycleUsesSignedDurableAuthority(t *testing.T) {
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	t.Setenv("GRIPLINE_BOOTSTRAP_CREDENTIAL", "")
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifierPath := filepath.Join(dir, "policy-verifier.key")
	if err := os.WriteFile(verifierPath, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeStatefulConfig(t, dir, "http://127.0.0.1:1", true)
	cfg.Policy.VerifierKeyFile = verifierPath
	const token = "op-tok-restart-0123456789abcdef0123456789abcdef"
	cfg.Admin.OperatorTokens[token] = "operator:policy.install"

	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	defer rt.Admin.Close()
	ln, err := net.Listen("tcp", cfg.Admin.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = rt.Admin.Serve(ln) }()
	base := "http://" + ln.Addr().String()

	status, body := adminHTTP(t, base, http.MethodGet, "/admin/policy", token, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"revision":1`) {
		t.Fatalf("initial policy status=%d body=%s", status, body)
	}

	candidate := *policy.Default()
	candidate.Revision = 2
	candidateBytes, err := json.Marshal(&candidate)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, candidateBytes)
	envelope, err := json.Marshal(policy.SignedArtifact{
		Version: 1, Policy: candidateBytes, Signature: base64.RawURLEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.LoadAuthenticated(envelope, pub); err != nil {
		t.Fatalf("locally verify signed candidate: %v", err)
	}
	prepareBody, err := json.Marshal(map[string]any{"artifact": json.RawMessage(envelope), "reason": "policy lifecycle acceptance"})
	if err != nil {
		t.Fatal(err)
	}
	status, body = adminHTTP(t, base, http.MethodPost, "/admin/policy/prepare", token, prepareBody)
	if status != http.StatusOK || !strings.Contains(string(body), `"revision":2`) {
		t.Fatalf("prepare status=%d body=%s", status, body)
	}
	status, _ = adminHTTP(t, base, http.MethodPost, "/admin/policy/activate", token, []byte(`{"reason":"policy lifecycle acceptance"}`))
	if status != http.StatusOK || rt.PolicyManager.Current().Revision != 2 {
		t.Fatalf("activate status=%d active=%d", status, rt.PolicyManager.Current().Revision)
	}
	if events, err := rt.State.ListPolicyAudit(0, 10); err != nil || len(events) != 2 || events[0].Actor != "operator" || events[1].Action != "activate" {
		t.Fatalf("durable policy audit=%v err=%v", events, err)
	}

	status, _ = adminHTTP(t, base, http.MethodPost, "/admin/policy/rollback", token, []byte(`{"revision":1,"reason":"rollback acceptance"}`))
	if status != http.StatusOK || rt.PolicyManager.Current().Revision != 1 {
		t.Fatalf("rollback status=%d active=%d", status, rt.PolicyManager.Current().Revision)
	}
}
