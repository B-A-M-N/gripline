// Command gripline-test-cluster-setup creates disposable, shared fixtures for
// the multi-process PostgreSQL acceptance harness. It emits no private
// material except into the explicitly named keyring path.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/pseudonym"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	keyringPath := flag.String("keyring", "", "shared signer keyring path")
	policyPath := flag.String("policy", "", "signed policy artifact path")
	candidatePath := flag.String("candidate", "", "optional signed revision-2 policy artifact path")
	verifierPath := flag.String("verifier", "", "policy verifier public key path")
	dsn := flag.String("reset-dsn", "", "disposable authority DSN to reset before setup")
	pepperOne := flag.String("pepper-one", "", "optional base64 pepper generation 1 for seeded crypto state")
	pepperTwo := flag.String("pepper-two", "", "optional base64 pepper generation 2 for seeded crypto state")
	pseudonymOne := flag.String("pseudonym-one", "", "optional base64 pseudonym generation 1 for seeded crypto state")
	pseudonymTwo := flag.String("pseudonym-two", "", "optional base64 pseudonym generation 2 for seeded crypto state")
	seedReferenceState := flag.Bool("seed-reference-state", false, "seed valid policy and representative non-secret authority state")
	seedMaintenanceFixture := flag.Bool("seed-maintenance-fixture", false, "seed one expired disposable row for the runtime maintenance qualification")
	capacityMode := flag.Bool("capacity-mode", false, "use high test-only resource ceilings for persistent capacity load")
	flag.Parse()
	if *keyringPath == "" || *policyPath == "" || *verifierPath == "" {
		fatal("-keyring, -policy, and -verifier are required")
	}
	if *candidatePath != "" {
		if err := os.MkdirAll(filepath.Dir(*candidatePath), 0o700); err != nil {
			fatal("create candidate directory: %v", err)
		}
	}
	if *dsn != "" {
		ensureAuthority(*dsn)
		resetAuthority(*dsn)
	}
	for _, path := range []*string{keyringPath, policyPath, verifierPath} {
		if err := os.MkdirAll(filepath.Dir(*path), 0o700); err != nil {
			fatal("create fixture directory: %v", err)
		}
	}
	keyring, err := terminator.NewKeyring()
	if err != nil {
		fatal("create signer: %v", err)
	}
	if err := keyring.Save(*keyringPath); err != nil {
		fatal("save signer: %v", err)
	}
	if *dsn != "" && (*pepperOne != "" || *pepperTwo != "" || *pseudonymOne != "" || *pseudonymTwo != "") {
		if *pepperOne == "" || *pepperTwo == "" || *pseudonymOne == "" || *pseudonymTwo == "" {
			fatal("seeded crypto requires both pepper and pseudonym generations")
		}
		seedCrypto(*dsn, keyring, *pepperOne, *pepperTwo, *pseudonymOne, *pseudonymTwo)
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("create policy verifier: %v", err)
	}
	if err := os.WriteFile(*verifierPath, public, 0o600); err != nil {
		fatal("save policy verifier: %v", err)
	}

	configured := policy.Default()
	if *capacityMode {
		configured.Learning.AllowNewLanes = true
		// Capacity qualification measures concurrency headroom. Disable the
		// request-rate gauges in this disposable fixture rather than turning a
		// deliberately enormous shared source/global token bucket into the
		// benchmark's serialization point; production policies still exercise
		// those gauges normally.
		configured.Limits.Normal.ConcurrencyCap = 1024
		configured.Limits.Normal.Requests = policy.BucketConfig{}
		configured.Limits.Constrained.ConcurrencyCap = 1024
		configured.Limits.Constrained.Requests = policy.BucketConfig{}
		configured.Limits.Emergency.ConcurrencyCap = 1024
		configured.Limits.Emergency.Requests = policy.BucketConfig{}
		configured.Global.ConcurrencyCap = 4096
		configured.LaneLimits.MaxActiveLanesPerCredential = 1024
		configured.LaneLimits.MaxProvisionalLanes = 1024
		configured.LaneLimits.Security.EnableAutomaticBlock = false
	} else {
		configured.Limits.Normal.ConcurrencyCap = 5
		configured.Limits.Constrained.ConcurrencyCap = 5
		configured.Global.ConcurrencyCap = 5
	}
	writePolicy(*policyPath, configured, private)
	if *candidatePath != "" {
		candidate := *configured
		candidate.Revision = 2
		writePolicy(*candidatePath, &candidate, private)
	}
	if *dsn != "" && *seedReferenceState {
		seedReferenceAuthority(*dsn, configured, *pepperOne)
	}
	if *dsn != "" && *seedMaintenanceFixture {
		seedMaintenanceFixtureRows(*dsn)
	}
}

func seedMaintenanceFixtureRows(dsn string) {
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		fatal("connect maintenance fixture authority: %v", err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cutoff := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := pool.Exec(ctx, `INSERT INTO gripline_resource_leases
		(lease_id, request_id, request_fingerprint, node_id, node_epoch, state, expires_at, created_at, released_at)
		VALUES ('qualification-maintenance-lease','qualification-maintenance-request','qualification-maintenance-fingerprint','qualification-maintenance-node',1,'released',$1,$1,$1)
		ON CONFLICT (lease_id) DO NOTHING`, cutoff); err != nil {
		fatal("seed maintenance fixture lease: %v", err)
	}
}

// seedReferenceAuthority creates the state that the HA/PITR labs must carry
// across a boundary. It intentionally contains only disposable identifiers,
// verifier bytes, and fingerprints; no raw credential or key material is
// persisted. The rows use the same JSON/domain types as the live stores so a
// lab exercises real decoding and readiness paths rather than count-only SQL.
func seedReferenceAuthority(dsn string, configured *policy.Policy, pepperEncoded string) {
	digest, err := policy.Digest(configured)
	if err != nil {
		fatal("digest reference policy: %v", err)
	}
	policyRaw, err := json.Marshal(configured)
	if err != nil {
		fatal("encode reference policy: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	securityRaw, err := json.Marshal(credential.SecurityState{LastObservedAt: now, LastStateChangeAt: now})
	if err != nil {
		fatal("encode reference credential security: %v", err)
	}
	pepper, err := base64.StdEncoding.DecodeString(pepperEncoded)
	if err != nil || len(pepper) < 32 {
		fatal("reference state requires a base64 pepper generation 1")
	}
	activeSecret := secret.NewFromBytes([]byte("reference-active-secret"))
	defer activeSecret.Zero()
	revokedSecret := secret.NewFromBytes([]byte("reference-revoked-secret"))
	defer revokedSecret.Zero()
	activeVerifier := credential.Verifier(activeSecret, &credential.PepperKey{Version: 1, Key: pepper})
	revokedVerifier := credential.Verifier(revokedSecret, &credential.PepperKey{Version: 1, Key: pepper})
	laneRaw, err := json.Marshal(lane.LaneRecord{
		LaneID: "qualification-lane", CredentialID: "qualification-active",
		State: lane.StateEstablished, FirstSeenAt: now.Add(-24 * time.Hour), LastSeenAt: now,
		Features:   lane.Features{NetworkASN: "AS64500", NetworkType: "residential", RegionClass: "reference", ClientFamily: "qualification", SDKFamily: "local", HTTPVersion: "2", Streaming: "non-streaming", ModelFamily: "local", ConcurrencyPattern: "interactive", EndpointFamily: "messages"},
		FeatSchema: 1, ClassificationRevision: 1, RequestCount: 12, ActiveDays: 1,
		LastActiveDay: now.Format("2006-01-02"), EstablishmentScore: 100,
		Security: lane.SecurityState{LastObservedAt: now}, AuthorizedCleanRequests: 12,
		CleanActiveDays: 1, LastCleanActiveDay: now.Format("2006-01-02"), CleanSince: now.Add(-24 * time.Hour), Revision: 3,
	})
	if err != nil {
		fatal("encode reference lane: %v", err)
	}
	evidenceRaw, err := json.Marshal(evidence.Evidence{
		EvidenceID: "qualification-evidence", Code: "REFERENCE_SIGNAL", Family: evidence.FamilyClientNovelty,
		Scope: evidence.ScopeCredential, SubjectID: "qualification-active", Score: 1, Severity: 1,
		Confidence: 90, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), PolicyRevision: configured.Revision,
	})
	if err != nil {
		fatal("encode reference evidence: %v", err)
	}
	beforeRaw, _ := json.Marshal(map[string]any{"status": "NORMAL", "revision": 1})
	afterRaw, _ := json.Marshal(map[string]any{"status": "WATCH", "revision": 2})
	manifestRaw, err := json.Marshal(policy.Manifest{
		SchemaVersion: 1, ActivationEpoch: 1,
		Active: policy.PolicyRef{ID: configured.ID, Revision: configured.Revision, Digest: digest}, UpdatedAt: now,
	})
	if err != nil {
		fatal("encode reference manifest: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		fatal("connect reference authority: %v", err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO gripline_policy_artifacts (policy_id, revision, digest, artifact) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, []any{configured.ID, configured.Revision, digest, policyRaw}},
		{`INSERT INTO gripline_policy_manifest (singleton, manifest, updated_at) VALUES (TRUE,$1,$2) ON CONFLICT (singleton) DO UPDATE SET manifest=EXCLUDED.manifest, updated_at=EXCLUDED.updated_at`, []any{manifestRaw, now}},
		{`INSERT INTO gripline_operator_posture (singleton, posture, updated_at) VALUES (TRUE,$1,$2) ON CONFLICT (singleton) DO UPDATE SET posture=EXCLUDED.posture, updated_at=EXCLUDED.updated_at`, []any{control.Normal, now}},
		{`INSERT INTO gripline_credentials (credential_id, account_id, verifier, verifier_version, pepper_version, status, security, policy_id, plan_id, created_at, revision) VALUES ('qualification-active','qualification-account',$1,1,1,$2,$3,$4,'qualification-plan',$5,1), ('qualification-revoked','qualification-account',$6,1,1,$7,$3,$4,'qualification-plan',$5,4) ON CONFLICT (credential_id) DO UPDATE SET verifier=EXCLUDED.verifier, status=EXCLUDED.status, security=EXCLUDED.security, policy_id=EXCLUDED.policy_id, plan_id=EXCLUDED.plan_id, revision=EXCLUDED.revision`, []any{activeVerifier, credential.StatusNormal, securityRaw, configured.ID, now, revokedVerifier, credential.StatusRevoked}},
		{`INSERT INTO gripline_lanes (credential_id, lane_id, record) VALUES ('qualification-active','qualification-lane',$1) ON CONFLICT (credential_id,lane_id) DO UPDATE SET record=EXCLUDED.record`, []any{laneRaw}},
		{`INSERT INTO gripline_lane_guards (credential_id, created_at) VALUES ('qualification-active',$1) ON CONFLICT DO NOTHING`, []any{now}},
		{`INSERT INTO gripline_evidence (scope, subject_id, evidence_id, item) VALUES ($1,$2,$3,$4) ON CONFLICT (scope,subject_id,evidence_id) DO UPDATE SET item=EXCLUDED.item`, []any{evidence.ScopeCredential.String(), "qualification-active", "qualification-evidence", evidenceRaw}},
		{`INSERT INTO gripline_evidence_guards (scope, subject_id, created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, []any{evidence.ScopeCredential.String(), "qualification-active", now}},
		{`INSERT INTO gripline_control_operations (operation_id, action, payload_fingerprint, created_at) VALUES ('qualification-seed-operation','credential.reference-seed','reference-payload-fingerprint',$1) ON CONFLICT DO NOTHING`, []any{now}},
		{`INSERT INTO gripline_credential_receipts (request_id, credential_id, changed, before_record, after_record, created_at) VALUES ('qualification-seed-request','qualification-active',TRUE,$1,$2,$3) ON CONFLICT DO NOTHING`, []any{beforeRaw, afterRaw, now}},
		{`INSERT INTO gripline_resource_buckets (scope, scope_id, dimension, capacity, refill_per, refill_in_ns, available, concurrency_used, updated_at) VALUES ($1,'qualification-active',$2,5,0,0,5,1,$3) ON CONFLICT (scope,scope_id,dimension) DO UPDATE SET capacity=EXCLUDED.capacity, available=EXCLUDED.available, concurrency_used=EXCLUDED.concurrency_used, updated_at=EXCLUDED.updated_at`, []any{resource.ScopeCredential, resource.DimConcurrency, now}},
		{`INSERT INTO gripline_resource_leases (lease_id, request_id, request_fingerprint, node_id, node_epoch, state, expires_at, created_at) VALUES ('qualification-seed-lease','qualification-seed-request','reference-request-fingerprint','qualification-reference-node',1,'reserved',$1,$2) ON CONFLICT (lease_id) DO UPDATE SET state=EXCLUDED.state, expires_at=EXCLUDED.expires_at`, []any{now.Add(time.Hour), now}},
		{`INSERT INTO gripline_resource_holds (lease_id, scope, scope_id, dimension, amount, settled) VALUES ('qualification-seed-lease',$1,'qualification-active',$2,1,FALSE) ON CONFLICT DO NOTHING`, []any{resource.ScopeCredential, resource.DimConcurrency}},
		{`INSERT INTO gripline_operator_audit (at, actor, action, target, reason, posture, committed, detail) VALUES ($1,'qualification-fixture','reference.seed','qualification-active','repository-owned reference fixture','NORMAL',TRUE,'non-secret state seed')`, []any{now}},
		{`INSERT INTO gripline_admission_audit (at, request_id, credential_id, account_id, lane_id, posture, authorized, reason) VALUES ($1,'qualification-seed-request','qualification-active','qualification-account','qualification-lane','NORMAL',TRUE,'reference fixture')`, []any{now}},
	}
	for _, item := range queries {
		if _, err := pool.Exec(ctx, item.query, item.args...); err != nil {
			fatal("seed reference authority: %v", err)
		}
	}
}

func seedCrypto(dsn string, keyring *terminator.Keyring, pepperOne, pepperTwo, pseudonymOne, pseudonymTwo string) {
	decode := func(label, encoded string) []byte {
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(value) < 32 {
			fatal("decode %s: expected base64 material of at least 32 bytes", label)
		}
		return value
	}
	pepperKeys := [][]byte{decode("pepper generation 1", pepperOne), decode("pepper generation 2", pepperTwo)}
	pepperRing, err := credential.NewPepperRing(
		&credential.PepperKey{Version: 1, Key: pepperKeys[0]},
		&credential.PepperKey{Version: 2, Key: pepperKeys[1]},
	)
	if err != nil {
		fatal("build seeded pepper ring: %v", err)
	}
	pseudonymKeys := [][]byte{decode("pseudonym generation 1", pseudonymOne), decode("pseudonym generation 2", pseudonymTwo)}
	pseudonymRing, err := pseudonym.NewRing(
		&pseudonym.Key{Version: 1, Secret: pseudonymKeys[0]},
		&pseudonym.Key{Version: 2, Secret: pseudonymKeys[1]},
	)
	if err != nil {
		fatal("build seeded pseudonym ring: %v", err)
	}
	if err := pseudonymRing.SetActiveVersion(1); err != nil {
		fatal("select seeded pseudonym generation: %v", err)
	}
	signerActiveFingerprint, ok := keyring.PublicKeyFingerprint(keyring.ActiveKid())
	if !ok {
		fatal("read seeded signer fingerprint")
	}
	pepperActiveFingerprint, ok := pepperRing.VersionFingerprint(1)
	if !ok {
		fatal("read seeded pepper fingerprint")
	}
	pseudonymActiveFingerprint, ok := pseudonymRing.VersionFingerprint(1)
	if !ok {
		fatal("read seeded pseudonym fingerprint")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		fatal("connect seeded authority: %v", err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		fatal("ping seeded authority: %v", err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO gripline_cluster_crypto
		(singleton, signer_active_kid, signer_fingerprint, signer_active_fingerprint,
		 pepper_active_version, pepper_fingerprint, pepper_active_fingerprint,
		 pseudonym_version, pseudonym_fingerprint, pseudonym_active_fingerprint,
		 generation_epoch, updated_at)
		VALUES (TRUE,$1,$2,$3,1,$4,$5,1,$6,$7,1,CURRENT_TIMESTAMP)`,
		keyring.ActiveKid(), keyring.PublicKeysetFingerprint(), signerActiveFingerprint,
		pepperRing.Fingerprint(), pepperActiveFingerprint, pseudonymRing.Fingerprint(), pseudonymActiveFingerprint)
	if err != nil {
		fatal("seed cluster crypto identity: %v", err)
	}
	loaded := []struct {
		kind, fingerprint, state string
		generation               int
	}{
		{statepg.CryptoKindSigner, signerActiveFingerprint, "active", keyring.ActiveKid()},
		{statepg.CryptoKindPepper, pepperActiveFingerprint, "active", 1},
		{statepg.CryptoKindPepper, mustFingerprint(pepperRing.VersionFingerprint(2)), "loaded", 2},
		{statepg.CryptoKindPseudonym, pseudonymActiveFingerprint, "active", 1},
		{statepg.CryptoKindPseudonym, mustFingerprint(pseudonymRing.VersionFingerprint(2)), "loaded", 2},
	}
	for _, generation := range loaded {
		if _, err := pool.Exec(ctx, `INSERT INTO gripline_cluster_crypto_generations
			(kind, generation, fingerprint, state, updated_at) VALUES ($1,$2,$3,$4,CURRENT_TIMESTAMP)`,
			generation.kind, generation.generation, generation.fingerprint, generation.state); err != nil {
			fatal("seed cluster crypto generation %s/%d: %v", generation.kind, generation.generation, err)
		}
	}
}

func mustFingerprint(fingerprint string, ok bool) string {
	if !ok {
		fatal("read seeded generation fingerprint")
	}
	return fingerprint
}

func ensureAuthority(dsn string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := statepg.Open(ctx, statepg.Options{DSN: dsn, ConnectTimeout: 10 * time.Second, Migrate: true})
	if err != nil {
		fatal("initialize authority schema: %v", err)
	}
	store.Close()
}

func writePolicy(path string, configured *policy.Policy, private ed25519.PrivateKey) {
	policyBytes, err := json.Marshal(configured)
	if err != nil {
		fatal("encode policy: %v", err)
	}
	envelope, err := json.Marshal(policy.SignedArtifact{
		Version:   1,
		Policy:    policyBytes,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, policyBytes)),
	})
	if err != nil {
		fatal("encode policy artifact: %v", err)
	}
	if err := os.WriteFile(path, envelope, 0o600); err != nil {
		fatal("save policy artifact: %v", err)
	}
}

func resetAuthority(dsn string) {
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		fatal("connect reset authority: %v", err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		fatal("ping reset authority: %v", err)
	}
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
		fatal("reset authority: %v", err)
	}
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "cluster setup: "+format+"\n", args...)
	os.Exit(1)
}
