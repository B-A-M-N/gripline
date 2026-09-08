package statepg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/adaptive"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
)

func TestPostgresAuthorityIntegration(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prefix := fmt.Sprintf("pg-it-%d", time.Now().UnixNano())
	a := openIntegrationStore(t, ctx, dsn, prefix+"-a")
	b := openIntegrationStore(t, ctx, dsn, prefix+"-b")
	defer a.Close()
	defer b.Close()

	identity := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "integration-signer",
		PepperActiveVersion: 1, PepperFingerprint: "integration-pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if _, err := a.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize node A crypto: %v", err)
	}
	if _, err := b.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize node B crypto: %v", err)
	}
	if err := a.Ready(ctx); err != nil {
		t.Fatalf("node A readiness: %v", err)
	}
	if err := b.Ready(ctx); err != nil {
		t.Fatalf("node B readiness: %v", err)
	}

	now := time.Now().UTC()
	credentialID := prefix + "-credential"
	record := &credential.CredentialRecord{
		CredentialID: credentialID, AccountID: prefix + "-account",
		Verifier: []byte("integration-verifier"), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "integration-policy", PlanID: "integration-plan",
		CreatedAt: now, Revision: 1,
	}
	if created, err := a.InsertIfAbsent(record); err != nil || !created {
		t.Fatalf("insert credential: created=%v err=%v", created, err)
	}
	got, err := b.LookupAuthoritative(ctx, credentialID)
	if err != nil || got.AccountID != record.AccountID {
		t.Fatalf("cross-node credential lookup: record=%+v err=%v", got, err)
	}
	duplicate := *record
	duplicate.CredentialID = prefix + "-duplicate"
	if err := b.Insert(&duplicate); err == nil {
		t.Fatal("verifier uniqueness must be enforced by PostgreSQL")
	}
	if err := a.Revoke(credentialID); err != nil {
		t.Fatalf("revoke credential: %v", err)
	}
	got, err = b.LookupAuthoritative(ctx, credentialID)
	if err != nil || got.Status != credential.StatusRevoked || got.Revision != 2 {
		t.Fatalf("cross-node revoke: record=%+v err=%v", got, err)
	}

	policyContext := lane.DefaultPolicyContext()
	policyContext.PolicyRevision = 1
	laneID := prefix + "-lane"
	if _, created, err := a.BorrowOrCreateWithPolicy(ctx, credentialID, laneID, lane.Features{NetworkASN: "AS-INTEGRATION"}, policyContext); err != nil || !created {
		t.Fatalf("create lane: created=%v err=%v", created, err)
	}
	if got, ok, err := b.LookupLane(ctx, credentialID, laneID); err != nil || !ok || got.LaneID != laneID {
		t.Fatalf("cross-node lane lookup: lane=%+v ok=%v err=%v", got, ok, err)
	}

	evidenceID := prefix + "-evidence"
	item := evidence.Evidence{
		EvidenceID: evidenceID, Code: "INTEGRATION_SIGNAL", Family: evidence.FamilyClientNovelty,
		Scope: evidence.ScopeCredential, SubjectID: credentialID, Score: 10, Confidence: 80,
		CreatedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), PolicyRevision: 1,
	}
	if err := a.AppendContext(ctx, item); err != nil {
		t.Fatalf("append evidence: %v", err)
	}
	evidenceRows, err := b.SnapshotContext(ctx, []evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: credentialID}}, time.Now().UTC())
	if err != nil || len(evidenceRows) != 1 || evidenceRows[0].EvidenceID != evidenceID {
		t.Fatalf("cross-node evidence snapshot: rows=%+v err=%v", evidenceRows, err)
	}

	if err := a.SavePosture(control.EmergencyLockdown); err != nil {
		t.Fatalf("save posture: %v", err)
	}
	if posture, err := b.LoadPostureContext(ctx); err != nil || posture != control.EmergencyLockdown {
		t.Fatalf("cross-node posture: posture=%v err=%v", posture, err)
	}
	if err := a.SavePosture(control.Normal); err != nil {
		t.Fatalf("restore posture: %v", err)
	}

	compiled, err := policy.Compile(policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := policy.Digest(&compiled.Policy)
	if err != nil {
		t.Fatal(err)
	}
	ref := policy.PolicyRef{ID: compiled.ID, Revision: compiled.Revision, Digest: digest}
	if err := a.PersistPolicyArtifact(compiled); err != nil {
		t.Fatalf("persist policy artifact: %v", err)
	}
	if err := a.InitializePolicyManifest(policy.Manifest{SchemaVersion: 1, ActivationEpoch: 1, Active: ref}); err != nil {
		t.Fatalf("initialize policy manifest: %v", err)
	}
	if manifest, err := b.LoadPolicyManifest(); err != nil || manifest.Active != ref {
		t.Fatalf("cross-node policy manifest: manifest=%+v err=%v", manifest, err)
	}
	if loaded, err := b.LoadPolicyArtifact(ref); err != nil || loaded.ID != compiled.ID {
		t.Fatalf("cross-node policy artifact: policy=%+v err=%v", loaded, err)
	}

	window := adaptive.WindowObservation{Detector: "integration-window", Subject: prefix, Threshold: 1, Window: time.Minute, MaxKeys: 8}
	window.Key = "node-a"
	if emitted, err := a.ObserveWindow(ctx, window); err != nil || emitted {
		t.Fatalf("first adaptive window observation: emitted=%v err=%v", emitted, err)
	}
	window.Key = "node-b"
	if emitted, err := b.ObserveWindow(ctx, window); err != nil || !emitted {
		t.Fatalf("cross-node adaptive window aggregation: emitted=%v err=%v", emitted, err)
	}
	baseline := adaptive.BaselineObservation{
		Detector: "integration-baseline", Subject: prefix, Metric: "latency",
		Value: 1, Alpha: 0.5, Threshold4: 4, Code4: "LATENCY_SPIKE",
	}
	for i := 0; i < 3; i++ {
		if _, err := a.ObserveBaseline(ctx, baseline); err != nil {
			t.Fatalf("baseline warmup %d: %v", i, err)
		}
	}
	baseline.Value = 10
	if signal, err := b.ObserveBaseline(ctx, baseline); err != nil || signal != "LATENCY_SPIKE" {
		t.Fatalf("cross-node baseline aggregation: signal=%q err=%v", signal, err)
	}

	scope := resource.ScopeSpec{
		Scope: resource.ScopeCredential, ID: credentialID,
		Buckets: resource.BucketSpec{ConcurrencyCap: 1},
	}
	reserve := resource.ReserveRequest{RequestID: prefix + "-request", Scopes: []resource.ScopeSpec{scope}}
	first, err := a.Reserve(ctx, reserve)
	if err != nil {
		t.Fatalf("reserve on node A: %v", err)
	}
	replay, err := a.Reserve(ctx, reserve)
	if err != nil {
		t.Fatalf("same-node reservation replay: %v", err)
	}
	if firstID, replayID := first.(interface{ ID() string }), replay.(interface{ ID() string }); firstID.ID() != replayID.ID() {
		t.Fatalf("reservation replay minted a new lease: %s != %s", firstID.ID(), replayID.ID())
	}
	if _, err := b.Reserve(ctx, resource.ReserveRequest{RequestID: prefix + "-other", Scopes: []resource.ScopeSpec{scope}}); err == nil {
		t.Fatal("cross-node concurrency cap must reject the second lease")
	}
	first.Release()
	replay.Release()
	afterRelease, err := b.Reserve(ctx, resource.ReserveRequest{RequestID: prefix + "-after-release", Scopes: []resource.ScopeSpec{scope}})
	if err != nil {
		t.Fatalf("cross-node reservation after release: %v", err)
	}
	afterRelease.Release()

	badID := prefix + "-malformed"
	if _, err := a.pool.Exec(ctx, `INSERT INTO gripline_credentials
		(credential_id, account_id, verifier, verifier_version, pepper_version, status, security, policy_id, plan_id, created_at, revision)
		VALUES ($1,$2,$3,99,1,0,'{}',$4,$5,CURRENT_TIMESTAMP,1)`, badID, prefix, []byte("bad"), "policy", "plan"); err != nil {
		t.Fatalf("insert malformed credential fixture: %v", err)
	}
	if _, err := b.LookupAuthoritative(ctx, badID); !errors.Is(err, credential.ErrLookupCorrupt) {
		t.Fatalf("malformed credential lookup error=%v, want ErrLookupCorrupt", err)
	}

	if err := b.MarkDraining(ctx, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("mark node B draining: %v", err)
	}
	if err := b.Ready(ctx); err == nil {
		t.Fatal("draining node must not be ready")
	}
}

func openIntegrationStore(t *testing.T, ctx context.Context, dsn, nodeID string) *Store {
	t.Helper()
	store, err := Open(ctx, Options{DSN: dsn, NodeID: nodeID, LeaseTTL: 10 * time.Second, RenewEvery: 2 * time.Second, MaxSourceScopes: 64})
	if err != nil {
		t.Fatalf("open PostgreSQL node %s: %v", nodeID, err)
	}
	return store
}
