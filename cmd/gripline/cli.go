package main

// CLI operator lifecycle subcommands (P1-26): credential list/revoke and lane
// list/unblock against the running deployment's private admin listener. The
// explicit --offline flag is the only path that opens a stopped state database.
// The CLI operates THROUGH the same control-plane service seams the admin HTTP
// surface uses (authorization + transactional mutation + audit), and it NEVER
// prints or accepts raw credential secrets — verifiers are internal material.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// runMigrateCLI is deliberately separate from the serving runtime. The
// migration role may create/alter the authority schema; serving nodes only
// perform the read-only compatibility check in statepg.Open.
func runMigrateCLI(args []string) error {
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply") {
		return fmt.Errorf("migrate: expected plan or apply")
	}
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	migrationTimeout := fs.Duration("timeout", 5*time.Minute, "maximum time for schema inspection or migration")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *migrationTimeout <= 0 {
		return fmt.Errorf("migrate: --timeout must be positive")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(cfg.Authority.Backend)) != "postgres" {
		return fmt.Errorf("migrate: authority.backend must be postgres")
	}
	dsn := os.Getenv(cfg.Authority.DSNEnv)
	if dsn == "" {
		return fmt.Errorf("migrate: authority DSN environment variable %q is empty", cfg.Authority.DSNEnv)
	}
	connectTimeout := cfg.Authority.ConnectTimeout.D()
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}
	operationTimeout := cfg.Authority.OperationTimeout.D()
	if operationTimeout <= 0 {
		operationTimeout = 2 * time.Second
	}
	opts := statepg.Options{
		DSN: dsn, MaxConns: cfg.Authority.MaxConns, MinConns: cfg.Authority.MinConns,
		ConnectTimeout: connectTimeout, OperationTimeout: operationTimeout,
	}
	switch args[0] {
	case "plan":
		ctx, cancel := context.WithTimeout(context.Background(), *migrationTimeout)
		defer cancel()
		status, err := statepg.InspectSchema(ctx, opts)
		if err != nil {
			return fmt.Errorf("migrate plan: %w", err)
		}
		if !status.Present {
			fmt.Printf("schema uninitialized: migration required (supported %d)\n", status.SupportedVersion)
		} else if status.Version != status.SupportedVersion {
			fmt.Printf("schema version %d (supported %d): migration required\n", status.Version, status.SupportedVersion)
		} else {
			fmt.Printf("schema version %d: current\n", status.Version)
		}
		return errSubcommand
	case "apply":
		ctx, cancel := context.WithTimeout(context.Background(), *migrationTimeout)
		defer cancel()
		opts.Migrate = true
		store, err := statepg.Open(ctx, opts)
		if err != nil {
			return fmt.Errorf("migrate apply: %w", err)
		}
		store.Close()
		fmt.Printf("schema migration applied: version %d\n", statepg.SupportedSchemaVersion())
		return errSubcommand
	}
	return nil
}

// runPolicyCLI dispatches policy verification and the authenticated lifecycle
// commands used by the running control plane.
func runPolicyCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy: expected verify, status, prepare, activate, or rollback")
	}
	if args[0] == "verify" {
		fs := flag.NewFlagSet("policy verify", flag.ContinueOnError)
		cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return fmt.Errorf("policy verify: %w", err)
		}
		pol, err := policyFor(cfg)
		if err != nil {
			return fmt.Errorf("policy verify: %w", err)
		}
		digest, err := policy.Digest(pol)
		if err != nil {
			return fmt.Errorf("policy verify: %w", err)
		}
		fmt.Printf("policy verified: %s revision=%d digest=%s\n", pol.ID, pol.Revision, digest)
		return errSubcommand
	}
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	filePath := fs.String("file", "", "signed policy envelope (prepare)")
	reason := fs.String("reason", "", "operator reason")
	revision := fs.Int("revision", 0, "known-good revision (rollback)")
	operationID := fs.String("operation-id", "", "stable Idempotency-Key for retrying the lifecycle mutation")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	tok, err := operatorTokenFromFile(*token, *tokenFile)
	if err != nil {
		return err
	}
	if tok == "" {
		return fmt.Errorf("policy %s: --token (or GRIPLINE_OPERATOR_TOKEN) is required", args[0])
	}
	client, err := newAdminClient(*cfgPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		var status map[string]any
		if err := client.request(http.MethodGet, "/admin/policy", tok, nil, &status); err != nil {
			return fmt.Errorf("policy status: %w", err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(status); err != nil {
			return err
		}
	case "prepare":
		if *filePath == "" || strings.TrimSpace(*reason) == "" {
			return fmt.Errorf("policy prepare: --file and --reason are required")
		}
		artifact, err := os.ReadFile(*filePath)
		if err != nil {
			return fmt.Errorf("policy prepare: read artifact: %w", err)
		}
		if len(artifact) > 4<<20 {
			return fmt.Errorf("policy prepare: artifact exceeds 4194304 bytes")
		}
		var result map[string]any
		if err := client.requestWithOperationID(http.MethodPost, "/admin/policy/prepare", tok, *operationID, map[string]any{
			"artifact": json.RawMessage(artifact), "reason": *reason,
		}, &result); err != nil {
			return fmt.Errorf("policy prepare: %w", err)
		}
		fmt.Printf("policy candidate prepared\n")
	case "activate":
		if strings.TrimSpace(*reason) == "" {
			return fmt.Errorf("policy activate: --reason is required")
		}
		if err := client.requestWithOperationID(http.MethodPost, "/admin/policy/activate", tok, *operationID, map[string]string{"reason": *reason}, nil); err != nil {
			return fmt.Errorf("policy activate: %w", err)
		}
		fmt.Println("policy candidate activated")
	case "rollback":
		if *revision < 1 || strings.TrimSpace(*reason) == "" {
			return fmt.Errorf("policy rollback: --revision and --reason are required")
		}
		if err := client.requestWithOperationID(http.MethodPost, "/admin/policy/rollback", tok, *operationID, map[string]any{"revision": *revision, "reason": *reason}, nil); err != nil {
			return fmt.Errorf("policy rollback: %w", err)
		}
		fmt.Printf("policy rolled back to revision %d\n", *revision)
	default:
		return fmt.Errorf("policy: unknown action %q", args[0])
	}
	return nil
}

// runClusterCLI exposes shared authority diagnostics through the authenticated
// admin listener. It never opens or mutates the database locally, which keeps
// status accurate when the CLI runs on a different operator workstation.
func runClusterCLI(args []string) error {
	if len(args) == 0 || args[0] != "status" {
		return fmt.Errorf("cluster: expected status")
	}
	return runRemoteStatusCLI("cluster status", "/admin/cluster", args[1:])
}

// runCryptoCLI is the focused view and activation surface for shared crypto
// generations. Status is read-only; activation is authenticated, audited, and
// replay-safe through the live admin authority.
func runCryptoCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("crypto: expected status, activate, retire, or signer-prepare")
	}
	if args[0] == "status" {
		return runRemoteStatusCLI("crypto status", "/admin/crypto", args[1:])
	}
	if args[0] == "signer-prepare" {
		return runCryptoSignerPrepareCLI(args[1:])
	}
	if args[0] != "activate" && args[0] != "retire" {
		return fmt.Errorf("crypto: unknown action %q (expected status, activate, retire, or signer-prepare)", args[0])
	}
	action := args[0]
	fs := flag.NewFlagSet("crypto "+action, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	kind := fs.String("kind", "", "generation kind: signer, pepper, or pseudonym")
	generation := fs.Int("generation", 0, "loaded generation to activate")
	fingerprint := fs.String("fingerprint", "", "exact loaded-generation fingerprint from crypto status")
	reason := fs.String("reason", "", "operator reason")
	notBefore := fs.String("not-before", "", "RFC3339 overlap horizon (retire only)")
	operationID := fs.String("operation-id", "", "stable Idempotency-Key for retrying the activation")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	tok, err := operatorTokenFromFile(*token, *tokenFile)
	if err != nil {
		return err
	}
	if tok == "" || strings.TrimSpace(*kind) == "" || *generation < 1 || strings.TrimSpace(*fingerprint) == "" || strings.TrimSpace(*reason) == "" || strings.TrimSpace(*operationID) == "" {
		return fmt.Errorf("crypto %s: --kind, --generation, --fingerprint, --reason, --operation-id, and --token (or --token-file/GRIPLINE_OPERATOR_TOKEN) are required", action)
	}
	body := map[string]any{"kind": *kind, "generation": *generation, "fingerprint": *fingerprint, "reason": *reason}
	endpoint := "/admin/crypto/activate"
	if action == "retire" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*notBefore))
		if err != nil {
			return fmt.Errorf("crypto retire: --not-before must be RFC3339: %w", err)
		}
		body["not_before"] = parsed.UTC()
		endpoint = "/admin/crypto/retire"
	}
	client, err := newAdminClient(*cfgPath)
	if err != nil {
		return err
	}
	var result map[string]any
	if err := client.requestWithOperationID(http.MethodPost, endpoint, tok, *operationID, body, &result); err != nil {
		return fmt.Errorf("crypto %s: %w", action, err)
	}
	fmt.Printf("%s %s generation %d\n", action, *kind, *generation)
	return nil
}

// runCryptoSignerPrepareCLI creates one durable local candidate. In a cluster
// this is a stopped-node/key-material operation: the resulting sealed keyring
// must be distributed identically to every node before the live activation
// command can pass the authority acknowledgement barrier.
func runCryptoSignerPrepareCLI(args []string) error {
	fs := flag.NewFlagSet("crypto signer-prepare", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	offline := fs.Bool("offline", false, "confirm the serving deployment is stopped")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*offline {
		return fmt.Errorf("crypto signer-prepare: --offline is required; prepare and distribute keyrings while the cluster is stopped")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("crypto signer-prepare: %w", err)
	}
	if cfg.Paths.SignerKeyring == "" {
		return fmt.Errorf("crypto signer-prepare: paths.signer_keyring is required")
	}
	keyring, err := terminator.LoadExistingKeyring(cfg.Paths.SignerKeyring)
	if err != nil {
		return fmt.Errorf("crypto signer-prepare: load keyring: %w", err)
	}
	candidate, err := keyring.PrepareRotation(cfg.Paths.SignerKeyring)
	if err != nil {
		return fmt.Errorf("crypto signer-prepare: %w", err)
	}
	fingerprint, ok := keyring.PublicKeyFingerprint(candidate.KID)
	if !ok {
		return fmt.Errorf("crypto signer-prepare: candidate fingerprint unavailable")
	}
	fmt.Printf("prepared signer generation %d fingerprint=%s; distribute this sealed keyring to every node before activation\n", candidate.KID, fingerprint)
	return errSubcommand
}

func runRemoteStatusCLI(command, endpoint string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tok, err := operatorTokenFromFile(*token, *tokenFile)
	if err != nil {
		return err
	}
	if tok == "" {
		return fmt.Errorf("%s: --token (or GRIPLINE_OPERATOR_TOKEN) is required", command)
	}
	client, err := newAdminClient(*cfgPath)
	if err != nil {
		return err
	}
	var status map[string]any
	if err := client.request(http.MethodGet, endpoint, tok, nil, &status); err != nil {
		return fmt.Errorf("%s: %w", command, err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(status); err != nil {
		return err
	}
	return nil
}

// runCredentialCLI dispatches `gripline credential <list|revoke>`.
func runCredentialCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("credential: expected 'list', 'add', or 'revoke' (use --token-file; add --offline only for stopped maintenance)")
	}
	fs := flag.NewFlagSet("credential", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	credID := fs.String("id", "", "credential id (revoke)")
	reason := fs.String("reason", "", "audit reason (revoke, required)")
	operationID := fs.String("operation-id", "", "stable Idempotency-Key for retrying a mutation")
	account := fs.String("account", "", "account id (add, required)")
	policyID := fs.String("policy", "", "policy id (add; defaults to the active policy)")
	planID := fs.String("plan", "plan-default", "plan id (add)")
	secretStdin := fs.Bool("secret-stdin", false, "read the raw credential from stdin (add, required)")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	offline := fs.Bool("offline", false, "operate directly on a stopped state database")
	switch args[0] {
	case "list":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		if *offline {
			return runCredentialList(*cfgPath)
		}
		return runCredentialListLive(*cfgPath, tok)
	case "pepper-status":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		if *offline {
			return fmt.Errorf("credential pepper-status: offline mode is not supported; use the authenticated live authority")
		}
		return runCredentialPepperStatusLive(*cfgPath, tok)
	case "revoke":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		if *offline {
			return runCredentialRevoke(*cfgPath, *credID, *reason, tok)
		}
		return runCredentialRevokeLiveWithOperationID(*cfgPath, *credID, *reason, tok, *operationID)
	case "add":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if !*secretStdin {
			return fmt.Errorf("credential add: --secret-stdin is required; raw secrets are never accepted as flags")
		}
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		return runCredentialAddLiveWithOperationID(*cfgPath, *credID, *account, *policyID, *planID, *reason, tok, *operationID)
	default:
		return fmt.Errorf("credential: unknown action %q (expected list|pepper-status|add|revoke)", args[0])
	}
}

// runLaneCLI dispatches `gripline lane <list|unblock>`.
func runLaneCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("lane: expected 'list' or 'unblock' (use --token-file; add --offline only for stopped maintenance)")
	}
	fs := flag.NewFlagSet("lane", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	credID := fs.String("credential", "", "credential id (required)")
	laneID := fs.String("id", "", "lane id (unblock)")
	reason := fs.String("reason", "", "audit reason (unblock, required)")
	operationID := fs.String("operation-id", "", "stable Idempotency-Key for retrying a mutation")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	offline := fs.Bool("offline", false, "operate directly on a stopped state database")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		if *credID == "" {
			return fmt.Errorf("lane list: --credential is required")
		}
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		if *offline {
			return runLaneList(*cfgPath, *credID)
		}
		return runLaneListLive(*cfgPath, *credID, tok)
	case "unblock":
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		if *offline {
			return runLaneUnblock(*cfgPath, *credID, *laneID, *reason, tok)
		}
		return runLaneUnblockLiveWithOperationID(*cfgPath, *credID, *laneID, *reason, tok, *operationID)
	default:
		return fmt.Errorf("lane: unknown action %q (expected list|unblock)", args[0])
	}
}

func operatorTokenFromFile(flagValue, path string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read operator token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv("GRIPLINE_OPERATOR_TOKEN"), nil
}

type adminClient struct {
	base   string
	client *http.Client
}

func newAdminClient(cfgPath string) (*adminClient, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	if cfg.Admin == nil || cfg.Admin.Listen == "" {
		return nil, fmt.Errorf("deployment has no private admin listener configured")
	}
	return &adminClient{
		base:   "http://" + cfg.Admin.Listen,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (c *adminClient) request(method, path, token string, body any, out any) error {
	return c.requestWithOperationID(method, path, token, "", body, out)
}

func (c *adminClient) requestWithOperationID(method, path, token, operationID string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if operationID != "" {
		req.Header.Set("Idempotency-Key", operationID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("admin request: %w", err)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return fmt.Errorf("admin response: %w", readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("admin request %s %s: %s", method, path, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("admin response: decode: %w", err)
		}
	}
	return nil
}

func runCredentialListLive(cfgPath, token string) error {
	if token == "" {
		return fmt.Errorf("credential list: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	c, err := newAdminClient(cfgPath)
	if err != nil {
		return err
	}
	var rows []credential.Summary
	if err := c.request(http.MethodGet, "/admin/credentials", token, nil, &rows); err != nil {
		return fmt.Errorf("credential list: %w", err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CREDENTIAL\tACCOUNT\tSTATUS\tPOLICY\tCREATED\tREV")
	for _, s := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n", s.CredentialID, s.AccountID, s.Status, s.PolicyID, s.CreatedAt.UTC().Format(time.RFC3339), s.Revision)
	}
	return w.Flush()
}

func runCredentialPepperStatusLive(cfgPath, token string) error {
	if token == "" {
		return fmt.Errorf("credential pepper-status: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	c, err := newAdminClient(cfgPath)
	if err != nil {
		return err
	}
	var counts map[string]int
	if err := c.request(http.MethodGet, "/admin/credentials/pepper-status", token, nil, &counts); err != nil {
		return fmt.Errorf("credential pepper-status: %w", err)
	}
	versions := make([]int, 0, len(counts))
	for raw := range counts {
		version, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("credential pepper-status: invalid server version %q", raw)
		}
		versions = append(versions, version)
	}
	sort.Ints(versions)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tCREDENTIALS")
	for _, version := range versions {
		fmt.Fprintf(w, "%d\t%d\n", version, counts[strconv.Itoa(version)])
	}
	return w.Flush()
}

func runCredentialRevokeLiveWithOperationID(cfgPath, credID, reason, token, operationID string) error {
	if credID == "" || reason == "" || token == "" {
		return fmt.Errorf("credential revoke: --id, --reason, and --token (or GRIPLINE_OPERATOR_TOKEN) are required")
	}
	c, err := newAdminClient(cfgPath)
	if err != nil {
		return err
	}
	if err := c.requestWithOperationID(http.MethodPost, "/admin/credentials/revoke", token, operationID, map[string]string{
		"credential_id": credID, "reason": reason,
	}, nil); err != nil {
		return fmt.Errorf("credential revoke: %w", err)
	}
	fmt.Printf("revoked %s (mutation + audit committed atomically)\n", credID)
	return nil
}

func runCredentialAddLive(cfgPath, credID, accountID, policyID, planID, reason, token string) error {
	return runCredentialAddLiveWithOperationID(cfgPath, credID, accountID, policyID, planID, reason, token, "")
}

func runCredentialAddLiveWithOperationID(cfgPath, credID, accountID, policyID, planID, reason, token, operationID string) error {
	if credID == "" || accountID == "" || planID == "" || reason == "" || token == "" {
		return fmt.Errorf("credential add: --id, --account, --reason, and --token (or --token-file/GRIPLINE_OPERATOR_TOKEN) are required")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	client, err := newAdminClient(cfgPath)
	if err != nil {
		return err
	}
	clustered := strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres")
	if policyID == "" {
		if clustered {
			var status struct {
				Active *struct {
					ID string `json:"id"`
				} `json:"active"`
			}
			if err := client.request(http.MethodGet, "/admin/policy", token, nil, &status); err != nil {
				return fmt.Errorf("credential add: read active policy: %w", err)
			}
			if status.Active == nil || status.Active.ID == "" {
				return fmt.Errorf("credential add: live authority returned no active policy")
			}
			policyID = status.Active.ID
		} else {
			pol, err := policyFor(cfg)
			if err != nil {
				return fmt.Errorf("credential add: active policy: %w", err)
			}
			policyID = pol.ID
		}
	}
	if cfg.Paths.State == "" && strings.ToLower(strings.TrimSpace(cfg.Authority.Backend)) != "postgres" {
		return fmt.Errorf("credential add: live mode requires a configured persistent authority")
	}
	peppers, err := loadPepperRing(cfg)
	if err != nil {
		return err
	}
	pepperVersion := peppers.ActiveVersion()
	if clustered {
		var status struct {
			Crypto struct {
				Initialized         bool `json:"initialized"`
				PepperActiveVersion int  `json:"pepper_active_version"`
			} `json:"crypto"`
		}
		if err := client.request(http.MethodGet, "/admin/crypto", token, nil, &status); err != nil {
			return fmt.Errorf("credential add: read active pepper: %w", err)
		}
		if !status.Crypto.Initialized || status.Crypto.PepperActiveVersion < 1 {
			return fmt.Errorf("credential add: live authority returned no active pepper")
		}
		pepperVersion = status.Crypto.PepperActiveVersion
	}
	if _, ok := peppers.VersionFingerprint(pepperVersion); !ok {
		return fmt.Errorf("credential add: active pepper generation %d is not loaded locally", pepperVersion)
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, terminator.MaxExternalCredentialBytes+1))
	if err != nil {
		return fmt.Errorf("credential add: read --secret-stdin: %w", err)
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if len(raw) == terminator.MaxExternalCredentialBytes+1 {
		return fmt.Errorf("credential add: secret exceeds %d bytes", terminator.MaxExternalCredentialBytes)
	}
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		raw = raw[:len(raw)-1]
		if len(raw) > 0 && raw[len(raw)-1] == '\r' {
			raw = raw[:len(raw)-1]
		}
	}
	if err := terminator.ValidateExternalCredential(raw); err != nil {
		return fmt.Errorf("credential add: invalid external credential: %w", err)
	}
	sealed := secret.NewFromBytes(raw)
	verifier := peppers.DeriveVerifier(sealed, pepperVersion)
	defer func() {
		for i := range verifier {
			verifier[i] = 0
		}
	}()
	sealed.Zero()
	if err := client.requestWithOperationID(http.MethodPost, "/admin/credentials/add", token, operationID, map[string]any{
		"credential_id": credID, "account_id": accountID, "policy_id": policyID, "plan_id": planID,
		"verifier_b64": base64.StdEncoding.EncodeToString(verifier), "verifier_version": 1,
		"pepper_version": pepperVersion, "reason": reason,
	}, nil); err != nil {
		return fmt.Errorf("credential add: %w", err)
	}
	fmt.Printf("added %s (verifier derived locally; raw secret not sent)\n", credID)
	return nil
}

type adminLaneSummary struct {
	LaneID       string    `json:"lane_id"`
	CredentialID string    `json:"credential_id"`
	State        string    `json:"state"`
	Security     string    `json:"security_state"`
	RiskScore    int       `json:"risk_score"`
	RequestCount int64     `json:"request_count"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	Revision     int       `json:"revision"`
}

func runLaneListLive(cfgPath, credID, token string) error {
	if credID == "" || token == "" {
		return fmt.Errorf("lane list: --credential and --token (or GRIPLINE_OPERATOR_TOKEN) are required")
	}
	c, err := newAdminClient(cfgPath)
	if err != nil {
		return err
	}
	var rows []adminLaneSummary
	if err := c.request(http.MethodGet, "/admin/lanes?credential="+url.QueryEscape(credID), token, nil, &rows); err != nil {
		return fmt.Errorf("lane list: %w", err)
	}
	if len(rows) == 0 {
		fmt.Printf("no lanes for credential %s\n", credID)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "LANE\tSTATE\tSECURITY\tRISK\tREQUESTS\tLAST_SEEN")
	for _, row := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n", row.LaneID, row.State, row.Security, row.RiskScore, row.RequestCount, row.LastSeenAt.UTC().Format(time.RFC3339))
	}
	return w.Flush()
}

func runLaneUnblockLiveWithOperationID(cfgPath, credID, laneID, reason, token, operationID string) error {
	if credID == "" || laneID == "" || reason == "" || token == "" {
		return fmt.Errorf("lane unblock: --credential, --id, --reason, and --token (or GRIPLINE_OPERATOR_TOKEN) are required")
	}
	c, err := newAdminClient(cfgPath)
	if err != nil {
		return err
	}
	if err := c.requestWithOperationID(http.MethodPost, "/admin/lanes/unblock", token, operationID, map[string]string{
		"credential_id": credID, "lane_id": laneID, "reason": reason,
	}, nil); err != nil {
		return fmt.Errorf("lane unblock: %w", err)
	}
	fmt.Printf("unblocked %s/%s (mutation + audit committed atomically)\n", credID, laneID)
	return nil
}

func runAuditCLI(args []string) error {
	if len(args) > 0 && args[0] == "security" {
		return runSecurityAuditCLI(args[1:])
	}
	if len(args) == 0 || (args[0] != "list" && args[0] != "export") {
		return fmt.Errorf("audit: expected list, export, or security list|export")
	}
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to deployment configuration")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	tok, err := operatorTokenFromFile(*token, *tokenFile)
	if err != nil {
		return err
	}
	if tok == "" {
		return fmt.Errorf("audit: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	c, err := newAdminClient(*cfgPath)
	if err != nil {
		return err
	}
	rows, err := fetchOperatorAudit(c, tok)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if args[0] == "export" {
		enc := json.NewEncoder(os.Stdout)
		for _, row := range rows {
			if err := enc.Encode(row); err != nil {
				return err
			}
		}
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "AT\tACTOR\tACTION\tTARGET\tREASON\tCOMMITTED")
	for _, row := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%t\n", row.At.UTC().Format(time.RFC3339), row.Actor, row.Action, row.Target, row.Reason, row.Committed)
	}
	return w.Flush()
}

func runSecurityAuditCLI(args []string) error {
	if len(args) == 0 || (args[0] != "list" && args[0] != "export") {
		return fmt.Errorf("audit security: expected list or export")
	}
	fs := flag.NewFlagSet("audit security", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to deployment configuration")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	tok, err := operatorTokenFromFile(*token, *tokenFile)
	if err != nil {
		return err
	}
	if tok == "" {
		return fmt.Errorf("audit security: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	c, err := newAdminClient(*cfgPath)
	if err != nil {
		return err
	}
	rows, err := fetchSecurityAudit(c, tok)
	if err != nil {
		return fmt.Errorf("audit security: %w", err)
	}
	if args[0] == "export" {
		enc := json.NewEncoder(os.Stdout)
		for _, row := range rows {
			if err := enc.Encode(row); err != nil {
				return err
			}
		}
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SEQ\tAT\tKIND\tCREDENTIAL\tLANE\tBEFORE\tAFTER\tRISK\tREV\tPOLICY_REV\tREQUEST_ID\tEVIDENCE")
	for _, row := range rows {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n",
			row.Sequence, row.At.UTC().Format(time.RFC3339), row.Kind, row.CredentialID, row.LaneID,
			row.Before, row.After, row.RiskScore, row.Revision, row.PolicyRevision, row.RequestID,
			strings.Join(row.EvidenceCodes, ","))
	}
	return w.Flush()
}

// runStateCLI provides stopped-deployment maintenance without constructing
// the data plane or loading runtime secrets.
func runStateCLI(args []string) error {
	if len(args) == 0 || (args[0] != "check" && args[0] != "backup" && args[0] != "restore" && args[0] != "compact") {
		return fmt.Errorf("state: expected check, backup, restore, or compact")
	}
	fs := flag.NewFlagSet("state", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to deployment configuration")
	outPath := fs.String("out", "", "backup output path")
	fromPath := fs.String("from", "", "backup input path")
	manifestPath := fs.String("manifest", "", "backup recovery manifest path (default: <out>.manifest.json)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Paths.State == "" {
		return fmt.Errorf("state: paths.state is required")
	}
	switch args[0] {
	case "check":
		if err := statebolt.CheckFile(cfg.Paths.State); err != nil {
			return err
		}
		fmt.Printf("state healthy: %s\n", cfg.Paths.State)
		return nil
	case "backup":
		if *outPath == "" {
			return fmt.Errorf("state backup: --out is required")
		}
		state, err := statebolt.Open(cfg.Paths.State, statebolt.Options{})
		if err != nil {
			return err
		}
		defer state.Close()
		metadata, err := recoveryMetadata(cfg, state)
		if err != nil {
			return err
		}
		if err := state.BackupWithRecoveryManifest(*outPath, *manifestPath, metadata); err != nil {
			return err
		}
		manifest := *manifestPath
		if manifest == "" {
			manifest = *outPath + ".manifest.json"
		}
		fmt.Printf("state backup verified: %s (manifest %s)\n", *outPath, manifest)
		return nil
	case "restore":
		if *fromPath == "" {
			return fmt.Errorf("state restore: --from is required")
		}
		manifest := *manifestPath
		if manifest == "" {
			manifest = *fromPath + ".manifest.json"
		}
		if err := statebolt.ValidateRecoveryManifest(*fromPath, manifest); err != nil {
			return err
		}
		sourceState, err := statebolt.OpenReadOnly(*fromPath, statebolt.Options{})
		if err != nil {
			return fmt.Errorf("state restore: inspect source authority: %w", err)
		}
		metadata, metadataErr := recoveryMetadata(cfg, sourceState)
		closeErr := sourceState.Close()
		if metadataErr != nil {
			return metadataErr
		}
		if closeErr != nil {
			return fmt.Errorf("state restore: close source authority: %w", closeErr)
		}
		manifestData, err := os.ReadFile(manifest)
		if err != nil {
			return err
		}
		recoveryManifest, err := statebolt.ParseRecoveryManifest(manifestData)
		if err != nil {
			return err
		}
		if err := statebolt.ValidateRecoveryEnvironment(recoveryManifest, metadata); err != nil {
			return fmt.Errorf("state restore: external authority validation: %w", err)
		}
		err = statebolt.RestoreBackupWithManifest(*fromPath, manifest, cfg.Paths.State)
		if err != nil {
			return err
		}
		fmt.Printf("state restored and verified: %s\n", cfg.Paths.State)
		return nil
	case "compact":
		if err := statebolt.CompactFile(cfg.Paths.State); err != nil {
			return err
		}
		fmt.Printf("state compacted and verified: %s\n", cfg.Paths.State)
		return nil
	}
	return nil
}

// recoveryMetadata collects only the public and versioned inputs an operator
// must restore with the state database. Secret values are read only to detect
// the legacy version-1 environment fallback and are never placed in the
// manifest.
func recoveryMetadata(cfg *config.Config, durableState *statebolt.Store) (statebolt.RecoveryMetadata, error) {
	if cfg == nil {
		return statebolt.RecoveryMetadata{}, fmt.Errorf("recovery metadata: config required")
	}
	var pol *policy.Policy
	if durableState != nil {
		manifest, err := durableState.LoadPolicyManifest()
		if err != nil {
			return statebolt.RecoveryMetadata{}, fmt.Errorf("recovery metadata: durable policy manifest: %w", err)
		}
		if manifest.Active.Revision > 0 {
			active, err := durableState.LoadPolicyArtifact(manifest.Active)
			if err != nil {
				return statebolt.RecoveryMetadata{}, fmt.Errorf("recovery metadata: durable policy artifact: %w", err)
			}
			pol = &active.Policy
		}
	}
	if pol == nil {
		var err error
		pol, err = policyFor(cfg)
		if err != nil {
			return statebolt.RecoveryMetadata{}, err
		}
	}
	policyDigest, err := policy.Digest(pol)
	if err != nil {
		return statebolt.RecoveryMetadata{}, err
	}
	metadata := statebolt.RecoveryMetadata{PolicyID: pol.ID, PolicyRevision: pol.Revision, PolicyDigest: policyDigest}
	if cfg.Paths.SignerKeyring != "" {
		keyring, err := terminator.LoadExistingKeyring(cfg.Paths.SignerKeyring)
		if err != nil {
			return statebolt.RecoveryMetadata{}, fmt.Errorf("recovery metadata: signer keyring: %w", err)
		}
		keyringData, err := os.ReadFile(cfg.Paths.SignerKeyring)
		if err != nil {
			return statebolt.RecoveryMetadata{}, fmt.Errorf("recovery metadata: read signer keyring: %w", err)
		}
		sum := sha256.Sum256(keyringData)
		metadata.SignerKeyringSHA256 = hex.EncodeToString(sum[:])
		metadata.SignerKeyringBytes = int64(len(keyringData))
		for kid, pub := range keyring.PublicKeys() {
			sum := sha256.Sum256(pub)
			metadata.SignerPublicFingerprints = append(metadata.SignerPublicFingerprints, fmt.Sprintf("%d:%s", kid, hex.EncodeToString(sum[:8])))
		}
		sort.Strings(metadata.SignerPublicFingerprints)
	}
	for rawVersion := range cfg.Secrets.PepperVersions {
		if version, err := strconv.Atoi(rawVersion); err == nil && version > 0 {
			metadata.RequiredPepperVersions = append(metadata.RequiredPepperVersions, version)
		}
	}
	if len(metadata.RequiredPepperVersions) == 0 && (os.Getenv("GRIPLINE_PEPPER_V1") != "" || os.Getenv("GRILINE_PEPPER_V1") != "") {
		metadata.RequiredPepperVersions = []int{1}
	}
	if cfg.Ingress != nil {
		if cfg.Ingress.PseudonymKey != "" {
			metadata.RequiredPseudonymVersions = append(metadata.RequiredPseudonymVersions, 1)
		}
		for rawVersion := range cfg.Ingress.PseudonymKeys {
			if version, err := strconv.Atoi(rawVersion); err == nil && version > 0 {
				metadata.RequiredPseudonymVersions = append(metadata.RequiredPseudonymVersions, version)
			}
		}
	}
	sort.Ints(metadata.RequiredPepperVersions)
	sort.Ints(metadata.RequiredPseudonymVersions)
	return metadata, nil
}

func fetchOperatorAudit(c *adminClient, token string) ([]control.OperatorRecord, error) {
	var all []control.OperatorRecord
	after := uint64(0)
	for {
		var page []control.OperatorRecord
		if err := c.request(http.MethodGet, fmt.Sprintf("/admin/audit?after=%d&limit=1000", after), token, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < 1000 {
			return all, nil
		}
		next := page[len(page)-1].Sequence
		if next <= after {
			return nil, fmt.Errorf("audit cursor did not advance")
		}
		after = next
	}
}

func fetchSecurityAudit(c *adminClient, token string) ([]control.SecurityTransitionRecord, error) {
	var all []control.SecurityTransitionRecord
	after := uint64(0)
	for {
		var page []control.SecurityTransitionRecord
		if err := c.request(http.MethodGet, fmt.Sprintf("/admin/security-events?after=%d&limit=1000", after), token, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < 1000 {
			return all, nil
		}
		next := page[len(page)-1].Sequence
		if next <= after {
			return nil, fmt.Errorf("security audit cursor did not advance")
		}
		after = next
	}
}

// openStateForCLI is the explicit offline maintenance seam. Normal lifecycle
// commands use the running admin HTTP service and never open the state DB.
// It returns the durable state store plus the control service it backs (or nil
// when no admin section is configured — list works either way, mutations
// require the operator surface).
func openStateForCLI(cfgPath string) (*config.Config, *runtimeCLI, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Paths.State == "" {
		return nil, nil, fmt.Errorf("this command requires a persistent deployment (paths.state); ephemeral mode has no lifecycle state to inspect")
	}
	state, err := statebolt.Open(cfg.Paths.State, statebolt.Options{})
	if err != nil {
		return nil, nil, err
	}
	return cfg, &runtimeCLI{state: state}, nil
}

type runtimeCLI struct {
	state   *statebolt.Store
	service *control.Service
}

func (c *runtimeCLI) close() error {
	if c == nil || c.state == nil {
		return nil
	}
	return c.state.Close()
}

// offlineService builds only the minimum authenticated mutation surface. It
// intentionally does not load pepper material, construct a signer, start the
// data plane, or process bootstrap credentials.
func (c *runtimeCLI) offlineService(cfg *config.Config) (*control.Service, error) {
	if c.service != nil {
		return c.service, nil
	}
	if cfg.Admin == nil {
		return nil, fmt.Errorf("deployment configures no admin section; offline mutation has no operator identity")
	}
	tokens := make(map[string]*control.Identity, len(cfg.Admin.OperatorTokens))
	for rawToken, spec := range cfg.Admin.OperatorTokens {
		name, rawCaps, err := parseSpec(spec)
		if err != nil {
			return nil, err
		}
		caps := make([]control.Capability, 0, len(rawCaps))
		for _, rawCap := range rawCaps {
			capability, err := control.ParseCapability(rawCap)
			if err != nil {
				return nil, err
			}
			caps = append(caps, capability)
		}
		tokens[rawToken] = &control.Identity{Name: name, Capabilities: caps}
	}
	auth, err := control.NewTokenAuthenticator(tokens)
	if err != nil {
		return nil, err
	}
	service, err := control.NewService(control.New(0), auth, c.state, control.WithMutationStore(c.state))
	if err != nil {
		return nil, err
	}
	c.service = service
	return service, nil
}

func runCredentialList(cfgPath string) error {
	_, h, err := openStateForCLI(cfgPath)
	if err != nil {
		return err
	}
	defer h.close()
	sums, err := h.state.ListCredentials()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CREDENTIAL\tACCOUNT\tSTATUS\tPOLICY\tCREATED\tREV")
	for _, s := range sums {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n", s.CredentialID, s.AccountID, s.Status, s.PolicyID, s.CreatedAt.UTC().Format(time.RFC3339), s.Revision)
	}
	return w.Flush()
}

func runCredentialRevoke(cfgPath, credID, reason, token string) error {
	if credID == "" {
		return fmt.Errorf("credential revoke: --id is required")
	}
	if reason == "" {
		return fmt.Errorf("credential revoke: --reason is required (every operator mutation is audited)")
	}
	if token == "" {
		return fmt.Errorf("credential revoke: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	cfg, h, err := openStateForCLI(cfgPath)
	if err != nil {
		return err
	}
	defer h.close()
	svc, err := h.offlineService(cfg)
	if err != nil {
		return fmt.Errorf("credential revoke: %w", err)
	}
	// NOTE: the CLI holds the runtime exclusively (the data plane is not
	// serving here), so the mutation is safe without runtime coordination.
	if err := svc.RevokeCredential(context.Background(), token, credID, reason); err != nil {
		return fmt.Errorf("credential revoke: %w", err)
	}
	fmt.Printf("revoked %s (mutation + audit committed atomically)\n", credID)
	return nil
}

func runLaneList(cfgPath, credID string) error {
	_, h, err := openStateForCLI(cfgPath)
	if err != nil {
		return err
	}
	defer h.close()
	rows, err := h.state.ListLaneRecords(credID)
	if err != nil {
		return fmt.Errorf("lane list: %w", err)
	}
	if len(rows) == 0 {
		fmt.Printf("no lanes for credential %s\n", credID)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "LANE\tSTATE\tSECURITY\tRISK\tREQUESTS\tLAST_SEEN")
	for _, rec := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n",
			rec.LaneID, rec.State.String(), rec.Security.Status.String(),
			rec.RiskScore, rec.RequestCount,
			rec.LastSeenAt.UTC().Format(time.RFC3339))
	}
	return w.Flush()
}

func runLaneUnblock(cfgPath, credID, laneID, reason, token string) error {
	if credID == "" || laneID == "" {
		return fmt.Errorf("lane unblock: --credential and --id are required")
	}
	if reason == "" {
		return fmt.Errorf("lane unblock: --reason is required (every operator mutation is audited)")
	}
	if token == "" {
		return fmt.Errorf("lane unblock: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	cfg, h, err := openStateForCLI(cfgPath)
	if err != nil {
		return err
	}
	defer h.close()
	svc, err := h.offlineService(cfg)
	if err != nil {
		return fmt.Errorf("lane unblock: %w", err)
	}
	if err := svc.UnblockLane(context.Background(), token, credID, laneID, reason); err != nil {
		return fmt.Errorf("lane unblock: %w", err)
	}
	fmt.Printf("unblocked %s/%s (mutation + audit committed atomically)\n", credID, laneID)
	return nil
}

// runStatusCLI prints startup capability status (P1-27): which authorities are
// durable, which are shadow-only, and which are disabled — the honest
// deployment picture an operator needs before trusting the gateway.
func runStatusCLI(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	pol, err := statusPolicyFor(cfg)
	if err != nil {
		return err
	}
	clustered := strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres")
	stateBacked := cfg.Paths.State != "" || clustered
	providerSource := cfg.Ingress != nil && (cfg.Ingress.PseudonymKey != "" || len(cfg.Ingress.PseudonymKeys) > 0)
	networkMetadata := cfg.Ingress != nil && len(cfg.Ingress.Networks) > 0
	policyDigest, _ := policy.Digest(pol)
	policyState := "configured"
	if cfg.Paths.State != "" {
		if lifecycle, lifecycleErr := statebolt.OpenReadOnly(cfg.Paths.State, statebolt.Options{}); lifecycleErr == nil {
			if manifest, manifestErr := lifecycle.LoadPolicyManifest(); manifestErr == nil && manifest.Active.Revision > 0 {
				policyState = "durable"
			}
			_ = lifecycle.Close()
		}
	} else if clustered {
		// This command is static configuration inspection. Live PostgreSQL
		// membership, policy epoch, and fencing state belong to `cluster
		// status`, which uses the authenticated admin plane.
		policyState = "shared-authority"
	}
	usageConfigured := cfg.Usage.Mode == "openai" || cfg.Usage.Mode == "anthropic"
	activeKID := "unknown"
	signerState := "ephemeral"
	if cfg.Paths.SignerKeyring != "" {
		if keyring, loadErr := terminator.LoadExistingKeyring(cfg.Paths.SignerKeyring); loadErr == nil {
			activeKID = fmt.Sprintf("%d", keyring.ActiveKid())
			signerState = "durable"
		} else {
			activeKID = "unavailable"
			signerState = "unavailable"
		}
	}
	pepperVersions := "none"
	if len(cfg.Secrets.PepperVersions) > 0 {
		versions := make([]int, 0, len(cfg.Secrets.PepperVersions))
		for raw := range cfg.Secrets.PepperVersions {
			if n, parseErr := strconv.Atoi(raw); parseErr == nil {
				versions = append(versions, n)
			}
		}
		sort.Ints(versions)
		parts := make([]string, 0, len(versions))
		for _, version := range versions {
			parts = append(parts, strconv.Itoa(version))
		}
		pepperVersions = strings.Join(parts, ",")
	}
	pseudonymVersions := "none"
	if cfg.Ingress != nil {
		versions := make([]int, 0, len(cfg.Ingress.PseudonymKeys))
		for raw := range cfg.Ingress.PseudonymKeys {
			if n, parseErr := strconv.Atoi(raw); parseErr == nil {
				versions = append(versions, n)
			}
		}
		if len(versions) == 0 && cfg.Ingress.PseudonymKey != "" {
			versions = []int{1}
		}
		sort.Ints(versions)
		parts := make([]string, 0, len(versions))
		for _, version := range versions {
			parts = append(parts, strconv.Itoa(version))
		}
		if len(parts) > 0 {
			pseudonymVersions = strings.Join(parts, ",")
		}
	}
	type row struct {
		capability string
		state      string
		note       string
	}
	maxSourceScopes := cfg.Server.MaxSourceScopes
	if maxSourceScopes == 0 {
		maxSourceScopes = resource.DefaultMaxSourceScopes
	}
	spoolBytes, spoolFiles := cfg.Server.SpoolMaxBytes, cfg.Server.SpoolMaxFiles
	if !cfg.Deployment.AllowEphemeralState {
		if spoolBytes == 0 {
			spoolBytes = 64 << 20
		}
		if spoolFiles == 0 {
			spoolFiles = 64
		}
	}
	rows := []row{
		{"authority backend", authorityBackendState(cfg), authorityNote(cfg)},
		{"credential authority", durab(stateBacked), authorityNote(cfg)},
		{"lane authority", durab(stateBacked), authorityNote(cfg)},
		{"evidence authority", durab(stateBacked), authorityNote(cfg)},
		{"signer identity", signerState, signerNote(cfg)},
		{"operator audit", durab(stateBacked || cfg.Paths.AuditLog != ""), auditNote(cfg)},
		{"operator control plane", onoff(cfg.Admin != nil), adminNote(cfg)},
		{"node identity", nodeIdentityState(cfg), nodeIdentityNote(cfg)},
		{"source attribution", onoff(providerSource), sourceNote(cfg)},
		{"network metadata", onoff(networkMetadata), networkNote(cfg)},
		{"source blocking", onoff(pol.Risk.SourceMode == policy.SourceEnforce), sourceBlockingNote(pol)},
		{"automatic credential quarantine", onoff(pol.Risk.EnableAutomaticQuarantine), "policy-controlled; operator-set only while disabled"},
		{"automatic lane block", onoff(pol.LaneSecurity.EnableAutomaticBlock), "policy-controlled (INV hysteresis)"},
		{"request accounting", on(), "NoUsage provider counts one admitted request"},
		{"token accounting", onoff(usageConfigured), usageNote(cfg, "tokens")},
		{"cost accounting", onoff(usageConfigured && (cfg.Usage.InputMicrounitsPerToken > 0 || cfg.Usage.OutputMicrounitsPerToken > 0)), usageNote(cfg, "cost")},
		{"active policy", policyState, fmt.Sprintf("%s revision=%d digest=%s", pol.ID, pol.Revision, policyDigest)},
		{"resource persistence", resourcePersistenceState(clustered), resourcePersistenceNote(clustered)},
		{"source-table bound", fmt.Sprintf("%d", maxSourceScopes), "zero resolves to the conservative runtime default; overflow identities are hashed into bounded shared scopes"},
		{"spool bounds", fmt.Sprintf("%d bytes/%d files", spoolBytes, spoolFiles), "aggregate unknown-length request budget"},
		{"active signer KID", activeKID, "public key generations are exported separately"},
		{"pepper versions", pepperVersions, "version identifiers only; key material is never displayed"},
		{"pseudonym versions", pseudonymVersions, "active and overlap versions; key material is never displayed"},
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CAPABILITY\tSTATE\tNOTE")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.capability, r.state, r.note)
	}
	return w.Flush()
}

func statusPolicyFor(cfg *config.Config) (*policy.Policy, error) {
	pol, err := policyFor(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Paths.State == "" {
		return pol, nil
	}
	store, err := statebolt.OpenReadOnly(cfg.Paths.State, statebolt.Options{})
	if errors.Is(err, os.ErrNotExist) {
		return pol, nil
	}
	if err != nil {
		return nil, fmt.Errorf("policy lifecycle status: %w", err)
	}
	defer store.Close()
	manifest, err := store.LoadPolicyManifest()
	if err != nil {
		return nil, fmt.Errorf("policy lifecycle status: %w", err)
	}
	if manifest.Active.Revision == 0 {
		return pol, nil
	}
	active, err := store.LoadPolicyArtifact(manifest.Active)
	if err != nil {
		return nil, fmt.Errorf("policy lifecycle status artifact: %w", err)
	}
	return &active.Policy, nil
}

func durab(yes bool) string {
	if yes {
		return "durable"
	}
	return "ephemeral"
}
func onoff(yes bool) string {
	if yes {
		return "on"
	}
	return "off"
}
func on() string { return "on" }

func sourceBlockingNote(pol *policy.Policy) string {
	if pol != nil && pol.Risk.SourceMode == policy.SourceEnforce {
		return "enforcing source risk threshold; validate shared-NAT impact before rollout"
	}
	return "shadow-only default: sourceWouldBlock recorded, never denies (P0.7)"
}

func authorityBackendState(cfg *config.Config) string {
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres") {
		return "postgres"
	}
	if cfg != nil && cfg.Paths.State != "" {
		return "bbolt"
	}
	return "memory"
}

func authorityNote(cfg *config.Config) string {
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres") {
		return "PostgreSQL shared authority; use cluster status for live state"
	}
	if cfg != nil && cfg.Paths.State != "" {
		return "Bolt transactional store"
	}
	return "memory store (ephemeral; not for production)"
}

func nodeIdentityState(cfg *config.Config) string {
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres") {
		return "configured"
	}
	return "none"
}

func nodeIdentityNote(cfg *config.Config) string {
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres") {
		return fmt.Sprintf("node_id=%s; live instance/epoch are reported by cluster status", cfg.Authority.NodeID)
	}
	return "standalone process has no shared membership identity"
}

func resourcePersistenceState(clustered bool) string {
	if clustered {
		return "shared-durable"
	}
	return "process-lifetime"
}

func resourcePersistenceNote(clustered bool) string {
	if clustered {
		return "PostgreSQL leases and token/cost buckets are shared across nodes"
	}
	return "governor windows are volatile; restart-safe credential/lane/evidence state remains durable"
}

func signerNote(cfg *config.Config) string {
	if cfg.Paths.SignerKeyring != "" {
		return "persistent keyring"
	}
	return "in-memory keyring (identity changes on restart)"
}

func auditNote(cfg *config.Config) string {
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres") {
		return "PostgreSQL shared audit authority"
	}
	if cfg.Paths.State != "" {
		return "bolt state database (authoritative)"
	}
	if cfg.Paths.AuditLog != "" {
		return "JSONL file (ephemeral state mode)"
	}
	return "none"
}

func sourceNote(cfg *config.Config) string {
	if cfg.Ingress == nil || (cfg.Ingress.PseudonymKey == "" && len(cfg.Ingress.PseudonymKeys) == 0) {
		return "no trusted ingress source resolver configured"
	}
	if len(cfg.Ingress.Networks) > 0 {
		return fmt.Sprintf("trusted ingress pseudonym adapter + %d-entry network metadata adapter", len(cfg.Ingress.Networks))
	}
	return "trusted ingress pseudonym adapter; network metadata unavailable"
}

func networkNote(cfg *config.Config) string {
	if cfg.Ingress == nil || len(cfg.Ingress.Networks) == 0 {
		return "no provider-authored CIDR map configured; ASN/region are unknown"
	}
	return fmt.Sprintf("provider-authored CIDR map (%d entries); trusted canonical source only", len(cfg.Ingress.Networks))
}

func usageNote(cfg *config.Config, dimension string) string {
	if cfg.Usage.Mode == "" || cfg.Usage.Mode == "none" {
		return "disabled; configure usage.mode for a bounded provider adapter"
	}
	if dimension == "cost" && cfg.Usage.InputMicrounitsPerToken == 0 && cfg.Usage.OutputMicrounitsPerToken == 0 {
		return "provider usage parsed; pricing is zero, so cost remains inert"
	}
	return fmt.Sprintf("%s-compatible bounded usage adapter", cfg.Usage.Mode)
}

func adminNote(cfg *config.Config) string {
	if cfg.Admin == nil {
		return "no admin listener configured"
	}
	return "admin listener at " + cfg.Admin.Listen
}

// interface assertions keep the CLI seams honest: the durable store must
// implement the credential lister (it does, via internal/statebolt).
var _ = credential.Lister(nil)
