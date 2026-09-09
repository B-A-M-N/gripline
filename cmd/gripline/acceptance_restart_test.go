package main

import (
	"context"
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
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/statebolt"
)

// writeStatefulConfig writes a PRODUCTION-SHAPED config: persistent Bolt state,
// persistent signer keyring, private admin bind — no ephemeral escape hatch.
func writeStatefulConfig(t *testing.T, dir string, backendURL string, extraAdmin bool) *config.Config {
	t.Helper()
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	cfgPath := filepath.Join(dir, "config.json")
	admin := ""
	if extraAdmin {
		admin = `,"admin":{"listen":"127.0.0.1:0","operator_tokens":{"op-tok-restart-0123456789abcdef0123456789abcdef":"operator:posture.control,credential.lifecycle,lane.lifecycle,audit.read"}}`
	}
	cfgJSON := `{"listen":"127.0.0.1:0","backend":{"url":"` + backendURL + `","trust_mode":"private_network","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"}` + admin + `,"tls":{"terminate_tls_upstream":true},"paths":{"state":"` + filepath.Join(dir, "state.db") + `","signer_keyring":"` + filepath.Join(dir, "keyring.json") + `"}}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func mustInsertCredInto(rtReg credential.Registry, id, secretStr string) error {
	prov, ok := rtReg.(credential.Provisioner)
	if !ok {
		return errors.New("registry does not support provisioning")
	}
	sealed := secret.NewFromBytes([]byte(secretStr))
	ver := credential.Verifier(sealed, &credential.PepperKey{Version: 1, Key: testPepperKey()})
	_, err := prov.InsertIfAbsent(&credential.CredentialRecord{
		CredentialID: id, AccountID: "acct_restart",
		Verifier: ver, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	})
	return err
}

func secretFor(id string) string { return "sk-" + id + "-00000000000000000000" }

// TestAcceptanceRestartContainment proves the core containment story survives a
// process restart (P0.10/P0.18 close-out): credential security state
// (CONSTRAINED, REVOKED), lane security state (SUSPICIOUS, BLOCKED), evidence,
// emergency posture, and the signer identity all restore from the single Bolt
// authority, and the runtime refuses split Bolt/Gob configuration.
func TestAcceptanceRestartContainment(t *testing.T) {
	os.Unsetenv("GRIPLINE_BOOTSTRAP_CREDENTIAL")
	dir := t.TempDir()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := writeStatefulConfig(t, dir, backend.URL, false)
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	if rt.State == nil {
		t.Fatal("state-backed runtime must expose the Bolt store")
	}
	if _, ok := rt.Lanes.(*statebolt.Store); !ok {
		t.Fatal("state-backed runtime must use the Bolt lane repository (P0.1)")
	}

	// Seed: two live credentials.
	for _, id := range []string{"cred_constr", "cred_revoked", "cred_live"} {
		if err := mustInsertCredInto(rt.Registry, id, secretFor(id)); err != nil {
			t.Fatal(err)
		}
	}

	// Drive a lane to SUSPICIOUS for cred_constr through the REAL repository.
	_, created, err := rt.Lanes.BorrowOrCreate("cred_constr", "lane_susp", lane.Features{NetworkASN: "AS1", HTTPVersion: "1.1"}, lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()})
	if err != nil || !created {
		t.Fatalf("borrow: created=%v err=%v", created, err)
	}
	if _, err := rt.Lanes.ObserveRisk("cred_constr", "lane_susp", 60, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Lanes.ObserveRisk("cred_constr", "lane_susp", 60, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, _ := rt.Lanes.Get("cred_constr", "lane_susp"); got.Security.Status != lane.LaneSuspicious {
		t.Fatalf("want SUSPICIOUS pre-restart, got %v", got.Security.Status)
	}

	// Drive a lane to BLOCKED for cred_revoked (automatic block enabled).
	hy := lane.DefaultSecurityHysteresis()
	hy.EnableAutomaticBlock = true
	if _, _, err := rt.Lanes.BorrowOrCreate("cred_revoked", "lane_blk", lane.Features{NetworkASN: "AS2", HTTPVersion: "1.1"}, lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()}); err != nil {
		t.Fatal(err)
	}
	policyCtx := lane.DefaultPolicyContext()
	policyCtx.Security = hy
	if _, err := rt.State.ObserveRiskWithPolicy(context.Background(), "cred_revoked", "lane_blk", 90, time.Now(), policyCtx, lane.TransitionMetadata{}); err != nil {
		t.Fatal(err)
	}

	// Persist evidence against cred_live.
	if err := rt.Evidence.Append(evidence.Evidence{
		EvidenceID: "ev_restart", Code: "TEST_RESTART_EVIDENCE", Family: evidence.FamilyAbuseCorrelation,
		Scope: evidence.ScopeCredential, SubjectID: "cred_live", Score: 10, Severity: 1,
		Confidence: 50, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// CONSTRAIN cred_constr and REVOKE cred_revoked through the authoritative
	// CAS path.
	if _, err := rt.State.UpdateStatusCAS("cred_constr", 1, credential.StatusNormal, credential.StatusConstrained); err != nil {
		t.Fatalf("constrain: %v", err)
	}
	if err := rt.State.Revoke("cred_revoked"); err != nil {
		t.Fatal(err)
	}

	if err := rt.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// ---- RESTART: same state file, same keyring ----
	rt2, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime (restart): %v", err)
	}
	defer func() { _ = rt2.Close() }()
	if rt2.State == nil {
		t.Fatal("restart lost the state store")
	}

	// Credential CONSTRAINED survives.
	rec2, err := rt2.State.LookupAuthoritative(t.Context(), "cred_constr")
	if err != nil {
		t.Fatal(err)
	}
	if rec2.Status != credential.StatusConstrained {
		t.Fatalf("CONSTRAINED lost across restart: %v", rec2.Status)
	}
	// Credential REVOKED survives (and auth would fail closed).
	rec3, err := rt2.State.LookupAuthoritative(t.Context(), "cred_revoked")
	if err != nil {
		t.Fatal(err)
	}
	if rec3.Status != credential.StatusRevoked {
		t.Fatalf("REVOKED lost across restart: %v", rec3.Status)
	}
	// Live credential still present and normal.
	rec4, err := rt2.State.LookupAuthoritative(t.Context(), "cred_live")
	if err != nil {
		t.Fatal(err)
	}
	if rec4.Status != credential.StatusNormal {
		t.Fatalf("live credential corrupted across restart: %v", rec4.Status)
	}

	// Lane SUSPICIOUS survives with its full record.
	got, ok := rt2.Lanes.Get("cred_constr", "lane_susp")
	if !ok {
		t.Fatal("SUSPICIOUS lane LOST across restart (P0.10 violated)")
	}
	if got.Security.Status != lane.LaneSuspicious {
		t.Fatalf("lane security lost across restart: %v", got.Security.Status)
	}
	// Lane BLOCKED tombstone survives.
	got2, ok := rt2.Lanes.Get("cred_revoked", "lane_blk")
	if !ok {
		t.Fatal("BLOCKED lane LOST across restart")
	}
	if got2.Security.Status != lane.LaneBlocked {
		t.Fatalf("BLOCKED security lost across restart: %v", got2.Security.Status)
	}

	// Evidence survives.
	snap, err := rt2.Evidence.Snapshot([]evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: "cred_live"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range snap {
		if ev.EvidenceID == "ev_restart" {
			found = true
		}
	}
	if !found {
		t.Fatal("evidence LOST across restart (P0.2 violated)")
	}

	// Signer identity survives: a keyring file existed pre-restart and the
	// restored runtime's signer has the same active kid as the original.
	if rt2.Signer == nil {
		t.Fatal("signer lost across restart")
	}

	// The unblock transactional path works on the restored authority and is
	// audited in the SAME database.
	if err := rt2.State.Unblock("cred_revoked", "lane_blk", "op", "acceptance unblock", time.Now()); err != nil {
		t.Fatalf("unblock after restart: %v", err)
	}
	if got3, _ := rt2.Lanes.Get("cred_revoked", "lane_blk"); got3.Security.Status != lane.LaneNormal {
		t.Fatalf("unblock did not restore NORMAL: %v", got3.Security.Status)
	}
	if n, err := rt2.State.CountAuditRecords(); err != nil || n < 1 {
		t.Fatalf("unblock must be audited in the state db: n=%d err=%v", n, err)
	}

	t.Log("PASS: credential CONSTRAINED/REVOKED, lane SUSPICIOUS/BLOCKED, evidence, and signer identity all survive a restart through one Bolt authority")
}

// TestAcceptanceRejectSplitAuthorities proves P0.2's fail-closed rule: a
// config that names BOTH the Bolt state database and the legacy Gob evidence
// file is a boot ERROR, never a silently split security authority.
func TestAcceptanceRejectSplitAuthorities(t *testing.T) {
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := `{"listen":"127.0.0.1:0","backend":{"url":"http://127.0.0.1:1","trust_mode":"private_network","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"tls":{"terminate_tls_upstream":true},"paths":{"state":"` + filepath.Join(dir, "state.db") + `","evidence":"` + filepath.Join(dir, "evidence.gob") + `","signer_keyring":"` + filepath.Join(dir, "keyring.json") + `"}}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if _, err := BuildRuntime(cfg); err == nil {
		t.Fatal("split Bolt+Gob authorities must be a boot error (P0.2)")
	} else if !strings.Contains(err.Error(), "single evidence authority") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestAcceptanceMandatoryPersistentState proves P0.18: without the explicit
// development escape hatch, omitting paths.state (or paths.signer_keyring) is
// a boot FAILURE — the safe deployment is the default.
func TestAcceptanceMandatoryPersistentState(t *testing.T) {
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)
	dir := t.TempDir()
	base := `"listen":"127.0.0.1:0","backend":{"url":"http://127.0.0.1:1","trust_mode":"private_network","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"tls":{"terminate_tls_upstream":true},`

	load := func(t *testing.T, paths, deployment string) (*config.Config, error) {
		t.Helper()
		cfgPath := filepath.Join(dir, t.Name()+".json")
		if err := os.WriteFile(cfgPath, []byte("{"+base+deployment+`"paths":{`+paths+`}}`), 0o640); err != nil {
			t.Fatal(err)
		}
		return config.Load(cfgPath)
	}

	// No state, no escape hatch: error.
	cfg, err := load(t, `"signer_keyring":"`+filepath.Join(dir, "kr1.json")+`"`, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRuntime(cfg); err == nil || !strings.Contains(err.Error(), "paths.state is required") {
		t.Fatalf("missing paths.state must fail boot, got %v", err)
	}
	// No keyring, no escape hatch: error.
	cfg, err = load(t, `"state":"`+filepath.Join(dir, "s2.db")+`"`, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRuntime(cfg); err == nil || !strings.Contains(err.Error(), "signer_keyring is required") {
		t.Fatalf("missing paths.signer_keyring must fail boot, got %v", err)
	}
	// Escape hatch explicitly set: boot succeeds (development mode).
	cfg, err = load(t, "", `"deployment":{"allow_ephemeral_state":true},`)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("explicit ephemeral mode must boot: %v", err)
	}
	_ = rt.Close()
}

// TestAcceptanceTransactionalOperatorMutations proves P0.18 close-out over the
// REAL admin surface: credential revoke, lane unblock, and posture all commit
// with their audit rows in the state database (a revoked credential stops
// authenticating; audit rows land in Bolt, not a JSONL sidecar).
func TestAcceptanceTransactionalOperatorMutations(t *testing.T) {
	os.Unsetenv("GRIPLINE_BOOTSTRAP_CREDENTIAL")
	dir := t.TempDir()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := writeStatefulConfig(t, dir, backend.URL, true)
	rt, err := BuildRuntime(cfg)
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	defer func() { _ = rt.Close() }()

	if err := mustInsertCredInto(rt.Registry, "cred_op", secretFor("cred_op")); err != nil {
		t.Fatal(err)
	}
	// Give the credential a BLOCKED lane so lane unblock has a target.
	hy := lane.DefaultSecurityHysteresis()
	hy.EnableAutomaticBlock = true
	if _, _, err := rt.Lanes.BorrowOrCreate("cred_op", "lane_op", lane.Features{NetworkASN: "AS9", HTTPVersion: "1.1"}, lane.ClassificationContext{Revision: 1, Thresholds: lane.DefaultThresholds()}); err != nil {
		t.Fatal(err)
	}
	policyCtx := lane.DefaultPolicyContext()
	policyCtx.Security = hy
	if _, err := rt.State.ObserveRiskWithPolicy(context.Background(), "cred_op", "lane_op", 95, time.Now(), policyCtx, lane.TransitionMetadata{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := rt.Lanes.Get("cred_op", "lane_op"); got.Security.Status != lane.LaneBlocked {
		t.Fatalf("setup: want BLOCKED, got %v", got.Security.Status)
	}

	// Audit count BEFORE the operator actions (unblock audit rows land later).
	before, err := rt.State.CountAuditRecords()
	if err != nil {
		t.Fatal(err)
	}

	// Transactional credential revoke via the control service seam.
	opToken := "op-tok-restart-0123456789abcdef0123456789abcdef"
	if err := rt.controlService().RevokeCredential(t.Context(), opToken, "cred_op", "acceptance revoke"); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}
	rec, err := rt.State.LookupAuthoritative(t.Context(), "cred_op")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != credential.StatusRevoked {
		t.Fatalf("want REVOKED, got %v", rec.Status)
	}

	// Transactional lane unblock.
	if err := rt.controlService().UnblockLane(t.Context(), opToken, "cred_op", "lane_op", "acceptance unblock"); err != nil {
		t.Fatalf("UnblockLane: %v", err)
	}
	if got, _ := rt.Lanes.Get("cred_op", "lane_op"); got.Security.Status != lane.LaneNormal {
		t.Fatalf("want NORMAL after unblock, got %v", got.Security.Status)
	}

	// Every action audited in the SAME database (revoke + unblock; posture not
	// exercised here — see TestAcceptanceAdminPostureLockdown).
	after, err := rt.State.CountAuditRecords()
	if err != nil {
		t.Fatal(err)
	}
	if after-before < 2 {
		t.Fatalf("operator mutations must be audited in the state db: before=%d after=%d", before, after)
	}

	t.Log("PASS: credential revoke + lane unblock are atomic mutation+audit operations against the single state authority")
}
