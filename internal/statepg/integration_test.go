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
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresAuthorityIntegration(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)
	prefix := fmt.Sprintf("pg-it-%d", time.Now().UnixNano())
	a := openIntegrationStore(t, ctx, dsn, prefix+"-a")
	b := openIntegrationStore(t, ctx, dsn, prefix+"-b")
	c := openIntegrationStore(t, ctx, dsn, prefix+"-c")
	defer a.Close()
	defer b.Close()
	defer c.Close()

	identity := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "integration-signer",
		PepperActiveVersion: 1, PepperFingerprint: "integration-pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if _, err := a.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize node A crypto: %v", err)
	}
	stagedIdentity := identity
	stagedIdentity.Loaded = []CryptoGeneration{
		{Kind: CryptoKindSigner, Generation: 1, Fingerprint: identity.SignerFingerprint},
		{Kind: CryptoKindSigner, Generation: 2, Fingerprint: "integration-signer-2"},
		{Kind: CryptoKindPepper, Generation: 1, Fingerprint: identity.PepperFingerprint},
		{Kind: CryptoKindPepper, Generation: 2, Fingerprint: "integration-pepper-2"},
	}
	if _, err := b.SynchronizeCrypto(ctx, stagedIdentity); err != nil {
		t.Fatalf("synchronize node B crypto: %v", err)
	}
	if _, err := c.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize node C crypto: %v", err)
	}
	var activeGenerations, stagedAcks int
	if err := a.pool.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_cluster_crypto_generations WHERE state='active'`).Scan(&activeGenerations); err != nil {
		t.Fatalf("count active crypto generations: %v", err)
	}
	if activeGenerations != 2 {
		t.Fatalf("active crypto generations=%d, want signer and pepper", activeGenerations)
	}
	if err := a.pool.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_cluster_crypto_acks WHERE node_id=$1 AND node_epoch=$2 AND generation=2`, b.nodeID, b.nodeEpoch).Scan(&stagedAcks); err != nil {
		t.Fatalf("count staged crypto acknowledgements: %v", err)
	}
	if stagedAcks != 2 {
		t.Fatalf("staged crypto acknowledgements=%d, want signer and pepper", stagedAcks)
	}
	if err := a.Ready(ctx); err != nil {
		t.Fatalf("node A readiness: %v", err)
	}
	if err := b.Ready(ctx); err != nil {
		t.Fatalf("node B readiness: %v", err)
	}
	if err := c.Ready(ctx); err != nil {
		t.Fatalf("node C readiness: %v", err)
	}
	clusterStatus, err := b.ClusterStatus(ctx)
	if err != nil {
		t.Fatalf("cluster status: %v", err)
	}
	if !clusterStatus.LocalReady || len(clusterStatus.Nodes) != 3 {
		t.Fatalf("cluster status local_ready=%v nodes=%d, want ready and three nodes: %+v", clusterStatus.LocalReady, len(clusterStatus.Nodes), clusterStatus)
	}
	if !clusterStatus.Crypto.Initialized || clusterStatus.Crypto.GenerationEpoch < 1 {
		t.Fatalf("cluster crypto status is not initialized: %+v", clusterStatus.Crypto)
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
	if got, err := c.LookupAuthoritative(ctx, credentialID); err != nil || got.AccountID != record.AccountID {
		t.Fatalf("third-node credential lookup: record=%+v err=%v", got, err)
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
	if got, err := c.LookupAuthoritative(ctx, credentialID); err != nil || got.Status != credential.StatusRevoked || got.Revision != 2 {
		t.Fatalf("third-node revoke: record=%+v err=%v", got, err)
	}

	// Control mutations use a durable operation claim so a retry after an
	// ambiguous commit does not repeat the state change or its audit row.
	operatorCredentialID := prefix + "-operator-credential"
	operatorRecord := *record
	operatorRecord.CredentialID = operatorCredentialID
	operatorRecord.Verifier = []byte("operator-verifier")
	if created, err := a.InsertIfAbsent(&operatorRecord); err != nil || !created {
		t.Fatalf("insert operator credential: created=%v err=%v", created, err)
	}
	auditBefore, err := a.CountAuditRecords()
	if err != nil {
		t.Fatalf("count operator audit before replay test: %v", err)
	}
	operatorAudit := control.OperatorRecord{
		At: time.Now().UTC(), Actor: "integration-operator", Action: "credential.revoke",
		Target: operatorCredentialID, Reason: "integration revoke", Posture: control.Normal.String(), Committed: true,
	}
	const revokeOperationID = "integration-revoke-operation"
	if err := a.RevokeCredentialWithAuditOperation(ctx, operatorCredentialID, operatorAudit, revokeOperationID); err != nil {
		t.Fatalf("operator revoke: %v", err)
	}
	if err := b.RevokeCredentialWithAuditOperation(ctx, operatorCredentialID, operatorAudit, revokeOperationID); err != nil {
		t.Fatalf("operator revoke replay on second node: %v", err)
	}
	auditAfter, err := a.CountAuditRecords()
	if err != nil {
		t.Fatalf("count operator audit after replay test: %v", err)
	}
	if auditAfter != auditBefore+1 {
		t.Fatalf("operation replay must append one audit row, before=%d after=%d", auditBefore, auditAfter)
	}
	operatorGot, err := c.LookupAuthoritative(ctx, operatorCredentialID)
	if err != nil || operatorGot.Status != credential.StatusRevoked || operatorGot.Revision != 2 {
		t.Fatalf("operator revoke replay state: record=%+v err=%v", operatorGot, err)
	}
	conflictingAudit := operatorAudit
	conflictingAudit.Reason = "different payload"
	if err := c.RevokeCredentialWithAuditOperation(ctx, operatorCredentialID, conflictingAudit, revokeOperationID); !errors.Is(err, control.ErrOperationConflict) {
		t.Fatalf("reused operation id with changed payload error=%v, want conflict", err)
	}
	repeatAudit := operatorAudit
	repeatAudit.Reason = "independent repeat"
	if err := c.RevokeCredentialWithAuditOperation(ctx, operatorCredentialID, repeatAudit, "integration-revoke-repeat"); err != nil {
		t.Fatalf("independent repeat revoke: %v", err)
	}
	operatorGot, err = a.LookupAuthoritative(ctx, operatorCredentialID)
	if err != nil || operatorGot.Revision != 2 {
		t.Fatalf("independent repeat revoke must not bump revision: record=%+v err=%v", operatorGot, err)
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
	if posture, err := c.LoadPostureContext(ctx); err != nil || posture != control.EmergencyLockdown {
		t.Fatalf("third-node posture: posture=%v err=%v", posture, err)
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
	initialManifest := policy.Manifest{SchemaVersion: 1, ActivationEpoch: 1, Active: ref}
	// Resource admission is not allowed to run on a node whose local policy
	// observation has not caught up with the shared manifest. Acknowledge the
	// initial epoch for every node before exercising shared resource limits.
	for name, store := range map[string]*Store{"a": a, "b": b, "c": c} {
		if err := store.AcknowledgePolicyContext(ctx, initialManifest); err != nil {
			t.Fatalf("acknowledge initial policy on node %s: %v", name, err)
		}
	}
	if manifest, err := b.LoadPolicyManifest(); err != nil || manifest.Active != ref {
		t.Fatalf("cross-node policy manifest: manifest=%+v err=%v", manifest, err)
	}
	if manifest, err := c.LoadPolicyManifest(); err != nil || manifest.Active != ref {
		t.Fatalf("third-node policy manifest: manifest=%+v err=%v", manifest, err)
	}
	if loaded, err := b.LoadPolicyArtifact(ref); err != nil || loaded.ID != compiled.ID {
		t.Fatalf("cross-node policy artifact: policy=%+v err=%v", loaded, err)
	}

	window := adaptive.WindowObservation{Detector: "integration-window", Subject: prefix, Threshold: 1, Window: time.Minute, Cooldown: time.Hour, MaxKeys: 8}
	window.Key = "node-a"
	if emitted, err := a.ObserveWindow(ctx, window); err != nil || emitted {
		t.Fatalf("first adaptive window observation: emitted=%v err=%v", emitted, err)
	}
	window.Key = "node-b"
	if emitted, err := b.ObserveWindow(ctx, window); err != nil || !emitted {
		t.Fatalf("cross-node adaptive window aggregation: emitted=%v err=%v", emitted, err)
	}
	window.Key = "node-c"
	if emitted, err := c.ObserveWindow(ctx, window); err != nil || emitted {
		t.Fatalf("third-node adaptive cooldown: emitted=%v err=%v", emitted, err)
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
	if _, err := c.Reserve(ctx, resource.ReserveRequest{RequestID: prefix + "-third", Scopes: []resource.ScopeSpec{scope}}); err == nil {
		t.Fatal("third-node concurrency cap must reject the second lease")
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
	if err := c.MarkDraining(ctx, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("mark node C draining: %v", err)
	}
	if err := c.Ready(ctx); err == nil {
		t.Fatal("third draining node must not be ready")
	}
}

func TestPostgresServingOpenRequiresExplicitMigration(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect migration test authority: %v", err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE gripline_schema`); err != nil {
		pool.Close()
		t.Fatalf("remove schema marker: %v", err)
	}
	pool.Close()

	if status, err := InspectSchema(ctx, Options{DSN: dsn}); err != nil {
		t.Fatalf("inspect uninitialized schema: %v", err)
	} else if status.Present {
		t.Fatalf("schema inspection reported marker after removal: %+v", status)
	}
	if _, err := Open(ctx, Options{DSN: dsn}); !errors.Is(err, ErrMigrationRequired) {
		t.Fatalf("serving Open on uninitialized schema = %v, want ErrMigrationRequired", err)
	}

	migrated, err := Open(ctx, Options{DSN: dsn, Migrate: true})
	if err != nil {
		t.Fatalf("explicit migration Open: %v", err)
	}
	migrated.Close()
	if status, err := InspectSchema(ctx, Options{DSN: dsn}); err != nil {
		t.Fatalf("inspect migrated schema: %v", err)
	} else if !status.Present || status.Version != SupportedSchemaVersion() {
		t.Fatalf("migrated schema status=%+v, want current version", status)
	}
}

func TestPostgresPolicyActivationRequiresLiveNodeAcknowledgements(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)
	a := openIntegrationStore(t, ctx, dsn, "policy-barrier-a")
	b := openIntegrationStore(t, ctx, dsn, "policy-barrier-b")
	defer a.Close()
	defer b.Close()
	identity := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "policy-signer",
		PepperActiveVersion: 1, PepperFingerprint: "policy-pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if _, err := a.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize policy node A: %v", err)
	}
	if _, err := b.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize policy node B: %v", err)
	}

	first := policy.Default()
	compiledFirst, err := policy.Compile(first)
	if err != nil {
		t.Fatalf("compile initial policy: %v", err)
	}
	firstDigest, err := policy.Digest(&compiledFirst.Policy)
	if err != nil {
		t.Fatalf("digest initial policy: %v", err)
	}
	firstRef := policy.PolicyRef{ID: compiledFirst.ID, Revision: compiledFirst.Revision, Digest: firstDigest}
	candidate := *policy.Default()
	candidate.Revision = 2
	compiledCandidate, err := policy.Compile(&candidate)
	if err != nil {
		t.Fatalf("compile candidate policy: %v", err)
	}
	candidateDigest, err := policy.Digest(&compiledCandidate.Policy)
	if err != nil {
		t.Fatalf("digest candidate policy: %v", err)
	}
	candidateRef := policy.PolicyRef{ID: compiledCandidate.ID, Revision: compiledCandidate.Revision, Digest: candidateDigest}
	if err := a.PersistPolicyArtifact(compiledFirst); err != nil {
		t.Fatalf("persist initial policy artifact: %v", err)
	}
	if err := a.PersistPolicyArtifact(compiledCandidate); err != nil {
		t.Fatalf("persist candidate policy artifact: %v", err)
	}
	if err := a.InitializePolicyManifest(policy.Manifest{SchemaVersion: 1, ActivationEpoch: 1, Active: firstRef}); err != nil {
		t.Fatalf("initialize policy manifest: %v", err)
	}
	now := time.Now().UTC()
	prepared := policy.Manifest{SchemaVersion: 1, ActivationEpoch: 1, Active: firstRef, Candidate: &candidateRef, UpdatedAt: now}
	if err := a.PersistPolicyTransition(prepared, policy.Event{
		Action: "prepare", FromRevision: 1, ToRevision: 2, FromEpoch: 1, ToEpoch: 1,
		PolicyID: candidateRef.ID, Reason: "barrier test", At: now,
	}); err != nil {
		t.Fatalf("persist policy prepare: %v", err)
	}
	if err := a.AcknowledgePolicyContext(ctx, prepared); err != nil {
		t.Fatalf("acknowledge candidate on node A: %v", err)
	}
	activated := policy.Manifest{SchemaVersion: 1, ActivationEpoch: 2, Active: candidateRef, Previous: &firstRef, UpdatedAt: now.Add(time.Second)}
	activation := policy.Event{
		Action: "activate", FromRevision: 1, ToRevision: 2, FromEpoch: 1, ToEpoch: 2,
		PolicyID: candidateRef.ID, Reason: "barrier test", At: activated.UpdatedAt,
	}
	if err := a.PersistPolicyTransition(activated, activation); !errors.Is(err, ErrPolicyActivationBarrier) {
		t.Fatalf("activation without node B acknowledgement error=%v, want barrier", err)
	}
	if err := b.AcknowledgePolicyContext(ctx, prepared); err != nil {
		t.Fatalf("acknowledge candidate on node B: %v", err)
	}
	if err := a.PersistPolicyTransition(activated, activation); err != nil {
		t.Fatalf("activation after all live nodes acknowledged: %v", err)
	}
	manifest, err := b.LoadPolicyManifestContext(ctx)
	if err != nil {
		t.Fatalf("load activated manifest: %v", err)
	}
	if manifest.Active != candidateRef || manifest.ActivationEpoch != 2 {
		t.Fatalf("activated manifest=%+v, want candidate epoch 2", manifest)
	}
}

func TestPostgresResourceAdmissionRejectsStalePolicyObservation(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)
	a := openIntegrationStore(t, ctx, dsn, "policy-resource-a")
	b := openIntegrationStore(t, ctx, dsn, "policy-resource-b")
	defer a.Close()
	defer b.Close()
	identity := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "policy-resource-signer",
		PepperActiveVersion: 1, PepperFingerprint: "policy-resource-pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if _, err := a.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize node A: %v", err)
	}
	if _, err := b.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize node B: %v", err)
	}

	first, err := policy.Compile(policy.Default())
	if err != nil {
		t.Fatalf("compile initial policy: %v", err)
	}
	firstDigest, err := policy.Digest(&first.Policy)
	if err != nil {
		t.Fatalf("digest initial policy: %v", err)
	}
	firstRef := policy.PolicyRef{ID: first.ID, Revision: first.Revision, Digest: firstDigest}
	secondPolicy := *policy.Default()
	secondPolicy.Revision = first.Revision + 1
	second, err := policy.Compile(&secondPolicy)
	if err != nil {
		t.Fatalf("compile candidate policy: %v", err)
	}
	secondDigest, err := policy.Digest(&second.Policy)
	if err != nil {
		t.Fatalf("digest candidate policy: %v", err)
	}
	secondRef := policy.PolicyRef{ID: second.ID, Revision: second.Revision, Digest: secondDigest}
	if err := a.PersistPolicyArtifact(first); err != nil {
		t.Fatalf("persist initial artifact: %v", err)
	}
	if err := a.PersistPolicyArtifact(second); err != nil {
		t.Fatalf("persist candidate artifact: %v", err)
	}
	initial := policy.Manifest{SchemaVersion: 1, ActivationEpoch: 1, Active: firstRef}
	if err := a.InitializePolicyManifest(initial); err != nil {
		t.Fatalf("initialize policy: %v", err)
	}
	if err := a.AcknowledgePolicyContext(ctx, initial); err != nil {
		t.Fatalf("acknowledge initial policy on A: %v", err)
	}
	if err := b.AcknowledgePolicyContext(ctx, initial); err != nil {
		t.Fatalf("acknowledge initial policy on B: %v", err)
	}

	reserve := func(node *Store, requestID string) error {
		reservation, err := node.Reserve(ctx, resource.ReserveRequest{
			RequestID: requestID,
			Scopes:    []resource.ScopeSpec{{Scope: resource.ScopeCredential, ID: "policy-resource-credential", Buckets: resource.BucketSpec{ConcurrencyCap: 1}}},
		})
		if err == nil {
			reservation.Release()
		}
		return err
	}
	if err := reserve(b, "policy-resource-initial"); err != nil {
		t.Fatalf("initial policy should permit resource admission: %v", err)
	}

	prepared := policy.Manifest{SchemaVersion: 1, ActivationEpoch: 1, Active: firstRef, Candidate: &secondRef, UpdatedAt: time.Now().UTC()}
	if err := a.PersistPolicyTransition(prepared, policy.Event{
		Action: "prepare", FromRevision: first.Revision, ToRevision: second.Revision,
		FromEpoch: 1, ToEpoch: 1, PolicyID: second.ID, Reason: "strict rollout test", At: prepared.UpdatedAt,
	}); err != nil {
		t.Fatalf("prepare policy: %v", err)
	}
	if err := b.AcknowledgePolicyContext(ctx, prepared); err != nil {
		t.Fatalf("acknowledge candidate on B: %v", err)
	}
	activated := policy.Manifest{SchemaVersion: 1, ActivationEpoch: 2, Active: secondRef, Previous: &firstRef, UpdatedAt: time.Now().UTC()}
	if err := a.PersistPolicyTransition(activated, policy.Event{
		Action: "activate", FromRevision: first.Revision, ToRevision: second.Revision,
		FromEpoch: 1, ToEpoch: 2, PolicyID: second.ID, Reason: "strict rollout test", At: activated.UpdatedAt,
	}); err != nil {
		t.Fatalf("activate policy: %v", err)
	}

	if err := reserve(b, "policy-resource-stale"); !errors.Is(err, ErrPolicyObservationStale) {
		t.Fatalf("stale node resource admission error=%v, want ErrPolicyObservationStale", err)
	}
	if err := reserve(a, "policy-resource-current"); err != nil {
		t.Fatalf("activating node should remain able to admit: %v", err)
	}
	if err := b.AcknowledgePolicyContext(ctx, activated); err != nil {
		t.Fatalf("acknowledge active policy on B: %v", err)
	}
	if err := reserve(b, "policy-resource-reconciled"); err != nil {
		t.Fatalf("reconciled node should admit: %v", err)
	}
}

func TestPostgresCryptoActivationRequiresLiveNodeAcknowledgements(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)
	a := openIntegrationStore(t, ctx, dsn, "crypto-activation-a")
	b := openIntegrationStore(t, ctx, dsn, "crypto-activation-b")
	defer a.Close()
	defer b.Close()
	base := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "crypto-activation-signer",
		PepperActiveVersion: 1, PepperFingerprint: "crypto-activation-pepper",
		PseudonymVersion: 1, PseudonymFingerprint: "crypto-activation-pseudonym",
	}
	if _, err := a.SynchronizeCrypto(ctx, base); err != nil {
		t.Fatalf("synchronize crypto node A: %v", err)
	}
	if _, err := b.SynchronizeCrypto(ctx, base); err != nil {
		t.Fatalf("synchronize crypto node B: %v", err)
	}
	staged := base
	staged.Loaded = []CryptoGeneration{
		{Kind: CryptoKindSigner, Generation: 1, Fingerprint: base.SignerFingerprint},
		{Kind: CryptoKindPepper, Generation: 1, Fingerprint: base.PepperFingerprint},
		{Kind: CryptoKindPepper, Generation: 2, Fingerprint: "crypto-activation-pepper-2"},
		{Kind: CryptoKindPseudonym, Generation: 1, Fingerprint: base.PseudonymFingerprint},
		{Kind: CryptoKindPseudonym, Generation: 2, Fingerprint: "crypto-activation-pseudonym-2"},
	}
	if _, err := a.SynchronizeCrypto(ctx, staged); err != nil {
		t.Fatalf("stage pepper on node A: %v", err)
	}
	request := CryptoActivationRequest{
		Kind: CryptoKindPepper, Generation: 2, Fingerprint: "crypto-activation-pepper-2",
		OperationID: "crypto-activation-operation", Actor: "integration-operator", Reason: "rotate pepper",
	}
	if _, err := a.ActivateCryptoGeneration(ctx, request); !errors.Is(err, ErrCryptoActivationBarrier) {
		t.Fatalf("activation before node B acknowledgement error=%v, want barrier", err)
	}
	diverged := staged
	diverged.PepperActiveVersion = 2
	diverged.PepperActiveFingerprint = "crypto-activation-pepper-2"
	diverged.PseudonymVersion = 2
	diverged.PseudonymActiveFingerprint = "crypto-activation-pseudonym-2"
	sharedBeforeActivation, err := b.SynchronizeCrypto(ctx, diverged)
	if err != nil {
		t.Fatalf("a node with a locally selected future pepper should synchronize before cluster activation: %v", err)
	}
	if sharedBeforeActivation.PepperActiveVersion != base.PepperActiveVersion {
		t.Fatalf("pre-activation synchronization selected pepper %d, want shared %d", sharedBeforeActivation.PepperActiveVersion, base.PepperActiveVersion)
	}
	if sharedBeforeActivation.PseudonymVersion != base.PseudonymVersion {
		t.Fatalf("pre-activation synchronization selected pseudonym %d, want shared %d", sharedBeforeActivation.PseudonymVersion, base.PseudonymVersion)
	}
	active, err := a.ActivateCryptoGeneration(ctx, request)
	if err != nil {
		t.Fatalf("activation after all nodes acknowledged: %v", err)
	}
	if active.PepperActiveVersion != 2 || active.PepperActiveFingerprint != request.Fingerprint || active.GenerationEpoch != 2 {
		t.Fatalf("activated crypto identity=%+v, want pepper 2 at epoch 2", active)
	}
	var state string
	if err := a.pool.QueryRow(ctx, `SELECT state FROM gripline_cluster_crypto_generations
		WHERE kind=$1 AND generation=$2`, CryptoKindPepper, 2).Scan(&state); err != nil {
		t.Fatalf("load activated generation state: %v", err)
	}
	if state != "active" {
		t.Fatalf("activated pepper state=%q, want active", state)
	}
	if err := a.pool.QueryRow(ctx, `SELECT state FROM gripline_cluster_crypto_generations
		WHERE kind=$1 AND generation=$2`, CryptoKindPepper, 1).Scan(&state); err != nil {
		t.Fatalf("load previous generation state: %v", err)
	}
	if state != "loaded" {
		t.Fatalf("previous pepper state=%q, want loaded", state)
	}
	replayed, err := b.ActivateCryptoGeneration(ctx, request)
	if err != nil {
		t.Fatalf("exact activation retry on node B: %v", err)
	}
	if replayed.GenerationEpoch != active.GenerationEpoch || replayed.PepperActiveVersion != active.PepperActiveVersion {
		t.Fatalf("activation retry identity=%+v differs from committed identity=%+v", replayed, active)
	}
	conflict := request
	conflict.Reason = "different reason"
	if _, err := b.ActivateCryptoGeneration(ctx, conflict); !errors.Is(err, control.ErrOperationConflict) {
		t.Fatalf("reused activation operation error=%v, want conflict", err)
	}
}

func TestPostgresCryptoReadinessRejectsUnreconciledActivation(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)
	store := openIntegrationStore(t, ctx, dsn, "crypto-readiness-node")
	defer store.Close()
	base := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "crypto-readiness-signer",
		PepperActiveVersion: 1, PepperFingerprint: "crypto-readiness-pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if _, err := store.SynchronizeCrypto(ctx, base); err != nil {
		t.Fatalf("synchronize base crypto identity: %v", err)
	}
	staged := base
	staged.Loaded = []CryptoGeneration{
		{Kind: CryptoKindSigner, Generation: 1, Fingerprint: base.SignerFingerprint},
		{Kind: CryptoKindPepper, Generation: 1, Fingerprint: base.PepperFingerprint},
		{Kind: CryptoKindPepper, Generation: 2, Fingerprint: "crypto-readiness-pepper-2"},
	}
	if _, err := store.SynchronizeCrypto(ctx, staged); err != nil {
		t.Fatalf("synchronize staged crypto identity: %v", err)
	}
	if _, err := store.ActivateCryptoGeneration(ctx, CryptoActivationRequest{
		Kind: CryptoKindPepper, Generation: 2, Fingerprint: "crypto-readiness-pepper-2",
		OperationID: "crypto-readiness-activation", Actor: "integration-operator", Reason: "readiness test",
	}); err != nil {
		t.Fatalf("activate staged crypto identity: %v", err)
	}
	if err := store.CryptoReady(ctx); !errors.Is(err, ErrCryptoIdentityStale) {
		t.Fatalf("CryptoReady after shared activation = %v, want ErrCryptoIdentityStale", err)
	}
	if _, err := store.SynchronizeCrypto(ctx, staged); err != nil {
		t.Fatalf("reconcile active crypto identity: %v", err)
	}
	if err := store.CryptoReady(ctx); err != nil {
		t.Fatalf("CryptoReady after reconciliation: %v", err)
	}
}

func TestPostgresFencedNodeCannotMutateAuthority(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)

	const nodeID = "pg-fencing-node"
	old := openIntegrationStore(t, ctx, dsn, nodeID)
	defer old.Close()
	identity := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "fencing-signer",
		PepperActiveVersion: 1, PepperFingerprint: "fencing-pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if _, err := old.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize old node crypto: %v", err)
	}

	now := time.Now().UTC()
	credentialID := "fencing-credential"
	record := &credential.CredentialRecord{
		CredentialID: credentialID, AccountID: "fencing-account",
		Verifier: []byte("fencing-verifier"), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fencing-policy", PlanID: "fencing-plan",
		CreatedAt: now, Revision: 1,
	}
	if created, err := old.InsertIfAbsent(record); err != nil || !created {
		t.Fatalf("seed credential: created=%v err=%v", created, err)
	}
	policyContext := lane.DefaultPolicyContext()
	if _, created, err := old.BorrowOrCreateWithPolicy(ctx, credentialID, "fencing-lane", lane.Features{NetworkASN: "AS-FENCE"}, policyContext); err != nil || !created {
		t.Fatalf("seed lane: created=%v err=%v", created, err)
	}
	if err := old.AppendContext(ctx, evidence.Evidence{
		EvidenceID: "fencing-evidence", Code: "FENCING_SIGNAL", Family: evidence.FamilyClientNovelty,
		Scope: evidence.ScopeCredential, SubjectID: credentialID, Score: 1, Confidence: 50,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1,
	}); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
	compiled, err := policy.Compile(policy.Default())
	if err != nil {
		t.Fatalf("compile fencing policy: %v", err)
	}
	digest, err := policy.Digest(&compiled.Policy)
	if err != nil {
		t.Fatalf("digest fencing policy: %v", err)
	}
	ref := policy.PolicyRef{ID: compiled.ID, Revision: compiled.Revision, Digest: digest}
	if err := old.PersistPolicyArtifact(compiled); err != nil {
		t.Fatalf("seed policy artifact: %v", err)
	}
	manifest := policy.Manifest{SchemaVersion: 1, ActivationEpoch: 1, Active: ref, UpdatedAt: now}
	if err := old.InitializePolicyManifest(manifest); err != nil {
		t.Fatalf("seed policy manifest: %v", err)
	}

	// Stop only the old membership heartbeat. Keeping its pool open lets the
	// test issue mutations after a replacement has acquired the same node ID.
	close(old.membershipStop)
	<-old.membershipDone
	if _, err := old.pool.Exec(ctx, `UPDATE gripline_membership SET last_seen_at=CURRENT_TIMESTAMP - INTERVAL '1 hour' WHERE node_id=$1`, nodeID); err != nil {
		t.Fatalf("expire old membership lease: %v", err)
	}
	replacement := openIntegrationStore(t, ctx, dsn, nodeID)
	defer replacement.Close()
	if _, err := replacement.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize replacement crypto: %v", err)
	}
	if replacement.nodeEpoch <= old.nodeEpoch {
		t.Fatalf("replacement epoch=%d did not advance old epoch=%d", replacement.nodeEpoch, old.nodeEpoch)
	}

	assertFenced := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrNodeFenced) {
			t.Errorf("%s error=%v, want ErrNodeFenced", name, err)
		}
	}
	assertFenced("credential insert", func() error {
		candidate := *record
		candidate.CredentialID = "fencing-after-takeover"
		candidate.Verifier = []byte("fencing-after-takeover-verifier")
		_, err := old.InsertIfAbsent(&candidate)
		return err
	}())
	_, err = old.RotateVerifierCASContext(ctx, credentialID, 1, 1, []byte("fencing-rotated-verifier"))
	assertFenced("credential verifier rotation", err)
	_, err = old.ObserveAndCommit(ctx, credentialID, 90, credential.Hysteresis{}, now)
	assertFenced("credential observation", err)
	err = old.TouchLastSeenContext(ctx, credentialID, now.Add(time.Minute))
	assertFenced("credential last-seen telemetry", err)
	_, _, err = old.BorrowOrCreateWithPolicy(ctx, credentialID, "fencing-after-takeover-lane", lane.Features{NetworkASN: "AS-FENCE-2"}, policyContext)
	assertFenced("lane creation", err)
	_, err = old.ObserveRiskWithPolicy(ctx, credentialID, "fencing-lane", 90, now, policyContext, lane.TransitionMetadata{})
	assertFenced("lane risk observation", err)
	assertFenced("evidence append", old.AppendContext(ctx, evidence.Evidence{
		EvidenceID: "fencing-after-takeover-evidence", Code: "FENCING_SIGNAL_2", Family: evidence.FamilyClientNovelty,
		Scope: evidence.ScopeCredential, SubjectID: credentialID, Score: 1, Confidence: 50,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1,
	}))
	assertFenced("posture mutation", old.SavePosture(control.EmergencyLockdown))
	assertFenced("admission audit", old.AppendAdmission(ctx, control.Event{At: now, RequestID: "fencing-request", CredentialID: credentialID}))
	assertFenced("operator audit", old.AppendOperator(ctx, control.OperatorRecord{At: now, Actor: "fencing-test", Action: "fencing.test", Target: credentialID, Reason: "test"}))
	assertFenced("policy artifact mutation", old.PersistPolicyArtifact(compiled))
	assertFenced("policy manifest mutation", old.PersistPolicyManifest(manifest))
	assertFenced("policy transition mutation", old.PersistPolicyTransition(manifest, policy.Event{
		Action: "rollback", Actor: "fencing-test", FromRevision: compiled.Revision, ToRevision: compiled.Revision,
		PolicyID: compiled.ID, Reason: "test", At: now,
	}))
	assertFenced("operator credential mutation", old.RevokeCredentialWithAuditOperation(ctx, credentialID, control.OperatorRecord{
		At: now, Actor: "fencing-test", Action: "credential.revoke", Target: credentialID, Reason: "test", Committed: true,
	}, "fencing-operation"))
}

func TestPostgresEvidenceConcurrentFirstWrites(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)
	a := openIntegrationStore(t, ctx, dsn, "evidence-contention-a")
	b := openIntegrationStore(t, ctx, dsn, "evidence-contention-b")
	defer a.Close()
	defer b.Close()
	identity := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "evidence-signer",
		PepperActiveVersion: 1, PepperFingerprint: "evidence-pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if _, err := a.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize evidence node A: %v", err)
	}
	if _, err := b.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize evidence node B: %v", err)
	}

	now := time.Now().UTC()
	item := func(id, subject string) evidence.Evidence {
		return evidence.Evidence{
			EvidenceID: id, Code: "CONTENTION_SIGNAL", Family: evidence.FamilyClientNovelty,
			Scope: evidence.ScopeCredential, SubjectID: subject, Score: 1, Confidence: 50,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour), PolicyRevision: 1,
		}
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- a.AppendContext(ctx, item("a-one", "subject-a"), item("b-one", "subject-b"))
	}()
	go func() {
		<-start
		results <- b.AppendContext(ctx, item("b-two", "subject-b"), item("a-two", "subject-a"))
	}()
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent evidence append %d: %v", i, err)
		}
	}
	for _, subject := range []string{"subject-a", "subject-b"} {
		rows, err := a.SnapshotContext(ctx, []evidence.SubjectKey{{Scope: evidence.ScopeCredential, ID: subject}}, now)
		if err != nil {
			t.Fatalf("snapshot %s: %v", subject, err)
		}
		if len(rows) != 2 {
			t.Fatalf("subject %s lost a concurrent first-write item: rows=%+v", subject, rows)
		}
	}
}

func TestPostgresForwardedLeaseConservativelyConsumesEstimate(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)
	a := openIntegrationStore(t, ctx, dsn, "resource-forwarded-a")
	b := openIntegrationStore(t, ctx, dsn, "resource-forwarded-b")
	defer a.Close()
	defer b.Close()
	identity := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "resource-signer",
		PepperActiveVersion: 1, PepperFingerprint: "resource-pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if _, err := a.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize resource node A: %v", err)
	}
	if _, err := b.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize resource node B: %v", err)
	}

	estimate := resource.UsageEstimate{CostMicrounits: 60}
	scope := func(id string) resource.ScopeSpec {
		return resource.ScopeSpec{
			Scope: resource.ScopeCredential, ID: id,
			Buckets: resource.BucketSpec{CostBurst: resource.BucketConfig{Capacity: 100}},
		}
	}
	request := func(requestID, scopeID string) resource.ReserveRequest {
		return resource.ReserveRequest{
			RequestID: requestID, Scopes: []resource.ScopeSpec{scope(scopeID)}, Estimate: estimate,
		}
	}
	expireAndReap := func(name string, reservation resource.UsageReservation) {
		t.Helper()
		lease, ok := reservation.(interface{ ID() string })
		if !ok {
			t.Fatalf("%s reservation does not expose a durable lease id", name)
		}
		if _, err := a.pool.Exec(ctx, `UPDATE gripline_resource_leases
			SET expires_at=CURRENT_TIMESTAMP - INTERVAL '1 minute' WHERE lease_id=$1`, lease.ID()); err != nil {
			t.Fatalf("expire %s lease: %v", name, err)
		}
		if err := a.reapExpired(ctx); err != nil {
			t.Fatalf("reap %s lease: %v", name, err)
		}
	}

	forwarded, err := a.Reserve(ctx, request("forwarded-initial", "forwarded-scope"))
	if err != nil {
		t.Fatalf("reserve forwarded lease: %v", err)
	}
	if err := forwarded.MarkForwarded(ctx); err != nil {
		t.Fatalf("mark lease forwarded: %v", err)
	}
	expireAndReap("forwarded", forwarded)
	forwarded.Release()
	if _, err := b.Reserve(ctx, request("forwarded-retry", "forwarded-scope")); err == nil {
		t.Fatal("forwarded lease expiration must consume its reserved estimate")
	}

	reserved, err := a.Reserve(ctx, request("reserved-initial", "reserved-scope"))
	if err != nil {
		t.Fatalf("reserve never-forwarded lease: %v", err)
	}
	expireAndReap("reserved", reserved)
	reserved.Release()
	refunded, err := b.Reserve(ctx, request("reserved-retry", "reserved-scope"))
	if err != nil {
		t.Fatalf("never-forwarded lease expiration must refund its estimate: %v", err)
	}
	refunded.Release()
}

func TestPostgresSourceScopeEvictsOnlySafeIdleScopes(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GRIPLINE_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resetIntegrationAuthority(t, ctx, dsn)
	store, err := Open(ctx, Options{
		DSN: dsn, NodeID: "source-scope-eviction", LeaseTTL: 10 * time.Second,
		RenewEvery: 2 * time.Second, MaxSourceScopes: 1, SourceScopeIdle: time.Second,
	})
	if err != nil {
		t.Fatalf("open source-scope authority: %v", err)
	}
	defer store.Close()
	identity := CryptoIdentity{
		SignerActiveKID: 1, SignerFingerprint: "source-scope-signer",
		PepperActiveVersion: 1, PepperFingerprint: "source-scope-pepper",
		PseudonymVersion: 0, PseudonymFingerprint: "disabled",
	}
	if _, err := store.SynchronizeCrypto(ctx, identity); err != nil {
		t.Fatalf("synchronize source-scope authority: %v", err)
	}
	scope := func(id string) resource.ScopeSpec {
		return resource.ScopeSpec{Scope: resource.ScopeSource, ID: id, Buckets: resource.BucketSpec{
			RequestsBurst: resource.BucketConfig{Capacity: 1},
		}}
	}
	first, err := store.Reserve(ctx, resource.ReserveRequest{
		RequestID: "source-scope-first", Scopes: []resource.ScopeSpec{scope("source-one")},
		Estimate: resource.UsageEstimate{Requests: 1},
	})
	if err != nil {
		t.Fatalf("reserve first source: %v", err)
	}
	first.Release()
	if _, err := store.pool.Exec(ctx, `UPDATE gripline_resource_source_scopes
		SET last_used_at=CURRENT_TIMESTAMP - INTERVAL '1 hour' WHERE scope_id='source-one'`); err != nil {
		t.Fatalf("age first source scope: %v", err)
	}
	second, err := store.Reserve(ctx, resource.ReserveRequest{
		RequestID: "source-scope-second", Scopes: []resource.ScopeSpec{scope("source-two")},
		Estimate: resource.UsageEstimate{Requests: 1},
	})
	if err != nil {
		t.Fatalf("reserve second source after safe eviction: %v", err)
	}
	second.Release()
	var oldCount, newCount, bucketCount int
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_resource_source_scopes WHERE scope_id='source-one'`).Scan(&oldCount); err != nil {
		t.Fatalf("count evicted source: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_resource_source_scopes WHERE scope_id='source-two'`).Scan(&newCount); err != nil {
		t.Fatalf("count current source: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_resource_buckets WHERE scope=$1 AND scope_id='source-one'`, resource.ScopeSource).Scan(&bucketCount); err != nil {
		t.Fatalf("count evicted source buckets: %v", err)
	}
	if oldCount != 0 || newCount != 1 || bucketCount != 0 {
		t.Fatalf("source eviction old=%d new=%d old_buckets=%d, want 0/1/0", oldCount, newCount, bucketCount)
	}

	active, err := store.Reserve(ctx, resource.ReserveRequest{
		RequestID: "source-scope-active", Scopes: []resource.ScopeSpec{scope("source-two")},
		Estimate: resource.UsageEstimate{Requests: 1},
	})
	if err != nil {
		t.Fatalf("reserve active source: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE gripline_resource_source_scopes
		SET last_used_at=CURRENT_TIMESTAMP - INTERVAL '1 hour' WHERE scope_id='source-two'`); err != nil {
		active.Release()
		t.Fatalf("age active source scope: %v", err)
	}
	overflow, err := store.Reserve(ctx, resource.ReserveRequest{
		RequestID: "source-scope-blocked", Scopes: []resource.ScopeSpec{scope("source-three")},
		Estimate: resource.UsageEstimate{Requests: 1},
	})
	if err != nil {
		t.Fatalf("reserve overflow source: %v", err)
	}
	overflow.Release()
	active.Release()
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_resource_source_scopes WHERE scope_id='source-three'`).Scan(&newCount); err != nil {
		t.Fatalf("count overflow source row: %v", err)
	}
	if newCount != 0 {
		t.Fatal("overflow source must not consume a bounded source-scope row")
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

// resetIntegrationAuthority is intentionally an exact Gripline table list.
// This test is opt-in and mutates its supplied database, but it must never
// truncate unrelated application data when a developer points it at a shared
// PostgreSQL service.
func resetIntegrationAuthority(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	bootstrap, err := Open(ctx, Options{DSN: dsn, Migrate: true})
	if err != nil {
		t.Fatalf("bootstrap integration authority schema: %v", err)
	}
	bootstrap.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect integration reset authority: %v", err)
	}
	defer pool.Close()
	const tables = `
		gripline_resource_leases,
		gripline_resource_holds,
		gripline_resource_buckets,
		gripline_resource_source_scopes,
		gripline_credential_receipts,
		gripline_security_transitions,
		gripline_admission_audit,
		gripline_lane_operator_audit,
		gripline_operator_audit,
		gripline_control_operations,
		gripline_operator_posture,
		gripline_evidence,
		gripline_evidence_guards,
		gripline_lanes,
		gripline_lane_guards,
		gripline_credentials,
		gripline_policy_audit,
		gripline_policy_artifacts,
		gripline_policy_manifest,
		gripline_adaptive_window_keys,
		gripline_adaptive_window_subjects,
		gripline_adaptive_baselines,
		gripline_adaptive_state,
		gripline_cluster_crypto,
		gripline_cluster_crypto_generations,
		gripline_cluster_crypto_acks,
		gripline_policy_node_state,
		gripline_membership`
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+tables+" RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("reset integration authority: %v", err)
	}
}
