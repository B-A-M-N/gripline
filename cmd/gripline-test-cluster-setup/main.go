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

	"github.com/B-A-M-N/gripline/internal/policy"
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

func ensureAuthority(dsn string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := statepg.Open(ctx, statepg.Options{DSN: dsn, ConnectTimeout: 10 * time.Second})
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
