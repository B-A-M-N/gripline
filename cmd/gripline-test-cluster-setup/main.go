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

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/pseudonym"
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
	configured.Limits.Normal.ConcurrencyCap = 5
	configured.Limits.Constrained.ConcurrencyCap = 5
	configured.Global.ConcurrencyCap = 5
	writePolicy(*policyPath, configured, private)
	if *candidatePath != "" {
		candidate := *configured
		candidate.Revision = 2
		writePolicy(*candidatePath, &candidate, private)
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
		gripline_membership`
	if _, err := pool.Exec(ctx, "TRUNCATE TABLE "+tables+" RESTART IDENTITY CASCADE"); err != nil {
		fatal("reset authority: %v", err)
	}
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "cluster setup: "+format+"\n", args...)
	os.Exit(1)
}
