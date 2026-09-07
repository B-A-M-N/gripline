package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/lane"
)

// TestAcceptanceAdminLifecycleRoutes proves the authenticated admin surface
// reads and mutates the same durable credential/lane/audit authority used by
// admission. Responses contain summaries only; verifier material is never
// exposed.
func TestAcceptanceAdminLifecycleRoutes(t *testing.T) {
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	t.Setenv("GRIPLINE_BOOTSTRAP_CREDENTIAL", "")
	dir := t.TempDir()
	cfg := writeStatefulConfig(t, dir, "http://127.0.0.1:1", true)

	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rt.Close() }()
	defer func() { _ = rt.Admin.Close() }()
	if err := mustInsertCredInto(rt.Registry, "cred_admin_routes", "sk-admin-routes-secret-000000000000"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rt.Lanes.BorrowOrCreate(
		"cred_admin_routes", "lane_admin_routes",
		lane.Features{NetworkASN: "AS1", HTTPVersion: "1.1"},
		lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()},
	); err != nil {
		t.Fatal(err)
	}
	hy := lane.DefaultSecurityHysteresis()
	hy.EnableAutomaticBlock = true
	rt.State.SetSecurityHysteresis(hy)
	if _, err := rt.Lanes.ObserveRisk("cred_admin_routes", "lane_admin_routes", 90, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Lanes.ObserveRisk("cred_admin_routes", "lane_admin_routes", 90, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", cfg.Admin.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = rt.Admin.Serve(ln) }()
	base := "http://" + ln.Addr().String()
	token := "op-tok-restart-0123456789abcdef0123456789abcdef"

	status, body := adminHTTP(t, base, http.MethodGet, "/admin/credentials", token, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("cred_admin_routes")) || bytes.Contains(body, []byte("sk-admin-routes-secret")) {
		t.Fatalf("credential summary status=%d body=%s", status, body)
	}
	status, body = adminHTTP(t, base, http.MethodGet, "/admin/lanes?credential=cred_admin_routes", token, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("lane_admin_routes")) || !bytes.Contains(body, []byte("BLOCKED")) {
		t.Fatalf("lane summary status=%d body=%s", status, body)
	}
	status, _ = adminHTTP(t, base, http.MethodPost, "/admin/credentials/revoke", token, []byte(`{"credential_id":"cred_admin_routes","reason":"acceptance revoke"}`))
	if status != http.StatusOK {
		t.Fatalf("credential revoke status=%d", status)
	}
	status, _ = adminHTTP(t, base, http.MethodPost, "/admin/lanes/unblock", token, []byte(`{"credential_id":"cred_admin_routes","lane_id":"lane_admin_routes","reason":"acceptance unblock"}`))
	if status != http.StatusOK {
		t.Fatalf("lane unblock status=%d", status)
	}
	status, body = adminHTTP(t, base, http.MethodGet, "/admin/audit?limit=100", token, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("credential.revoke")) || !bytes.Contains(body, []byte("lane.unblock")) {
		t.Fatalf("audit status=%d body=%s", status, body)
	}
	status, body = adminHTTP(t, base, http.MethodGet, "/admin/security-events?limit=100", token, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte("lane_security")) {
		t.Fatalf("security audit status=%d body=%s", status, body)
	}
	status, _ = adminHTTP(t, base, http.MethodPost, "/admin/identity/keys/rotate", token, []byte(`{"reason":"rotation is out of beta"}`))
	if status != http.StatusNotFound {
		t.Fatalf("live key rotation must be absent, status=%d", status)
	}
	status, _ = adminHTTP(t, base, http.MethodGet, "/admin/credentials", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("missing admin token status=%d, want %d", status, http.StatusUnauthorized)
	}
}

func adminHTTP(t *testing.T, base, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}
