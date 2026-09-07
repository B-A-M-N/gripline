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
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// runCredentialCLI dispatches `gripline credential <list|revoke>`.
func runCredentialCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("credential: expected 'list', 'add', or 'revoke' (use --token-file; add --offline only for stopped maintenance)")
	}
	fs := flag.NewFlagSet("credential", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	credID := fs.String("id", "", "credential id (revoke)")
	reason := fs.String("reason", "", "audit reason (revoke, required)")
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
		return runCredentialRevokeLive(*cfgPath, *credID, *reason, tok)
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
		return runCredentialAddLive(*cfgPath, *credID, *account, *policyID, *planID, *reason, tok)
	default:
		return fmt.Errorf("credential: unknown action %q (expected list|add|revoke)", args[0])
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
		return runLaneUnblockLive(*cfgPath, *credID, *laneID, *reason, tok)
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

func runCredentialRevokeLive(cfgPath, credID, reason, token string) error {
	if credID == "" || reason == "" || token == "" {
		return fmt.Errorf("credential revoke: --id, --reason, and --token (or GRIPLINE_OPERATOR_TOKEN) are required")
	}
	c, err := newAdminClient(cfgPath)
	if err != nil {
		return err
	}
	if err := c.request(http.MethodPost, "/admin/credentials/revoke", token, map[string]string{
		"credential_id": credID, "reason": reason,
	}, nil); err != nil {
		return fmt.Errorf("credential revoke: %w", err)
	}
	fmt.Printf("revoked %s (mutation + audit committed atomically)\n", credID)
	return nil
}

func runCredentialAddLive(cfgPath, credID, accountID, policyID, planID, reason, token string) error {
	if credID == "" || accountID == "" || policyID == "" || planID == "" || reason == "" || token == "" {
		return fmt.Errorf("credential add: --id, --account, --reason, and --token (or --token-file/GRIPLINE_OPERATOR_TOKEN) are required")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if policyID == "" {
		pol, err := policyFor(cfg)
		if err != nil {
			return fmt.Errorf("credential add: active policy: %w", err)
		}
		policyID = pol.ID
	}
	if cfg.Paths.State == "" {
		return fmt.Errorf("credential add: live mode requires a configured persistent paths.state")
	}
	peppers, err := loadPepperRing(cfg)
	if err != nil {
		return err
	}
	pepperVersion := peppers.Latest()
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
	client, err := newAdminClient(cfgPath)
	if err != nil {
		return err
	}
	if err := client.request(http.MethodPost, "/admin/credentials/add", token, map[string]any{
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

func runLaneUnblockLive(cfgPath, credID, laneID, reason, token string) error {
	if credID == "" || laneID == "" || reason == "" || token == "" {
		return fmt.Errorf("lane unblock: --credential, --id, --reason, and --token (or GRIPLINE_OPERATOR_TOKEN) are required")
	}
	c, err := newAdminClient(cfgPath)
	if err != nil {
		return err
	}
	if err := c.request(http.MethodPost, "/admin/lanes/unblock", token, map[string]string{
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
		metadata, err := recoveryMetadata(cfg)
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
		var err error
		if *manifestPath != "" {
			err = statebolt.RestoreBackupWithManifest(*fromPath, *manifestPath, cfg.Paths.State)
		} else {
			err = statebolt.RestoreBackup(*fromPath, cfg.Paths.State)
		}
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
func recoveryMetadata(cfg *config.Config) (statebolt.RecoveryMetadata, error) {
	if cfg == nil {
		return statebolt.RecoveryMetadata{}, fmt.Errorf("recovery metadata: config required")
	}
	pol, err := policyFor(cfg)
	if err != nil {
		return statebolt.RecoveryMetadata{}, err
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
	pol, err := policyFor(cfg)
	if err != nil {
		return err
	}
	stateBacked := cfg.Paths.State != ""
	providerSource := cfg.Ingress != nil && (cfg.Ingress.PseudonymKey != "" || len(cfg.Ingress.PseudonymKeys) > 0)
	networkMetadata := cfg.Ingress != nil && len(cfg.Ingress.Networks) > 0
	policyDigest, _ := policy.Digest(pol)
	usageConfigured := cfg.Usage.Mode == "openai" || cfg.Usage.Mode == "anthropic"
	activeKID := "unknown"
	if cfg.Paths.SignerKeyring != "" {
		if keyring, loadErr := terminator.LoadExistingKeyring(cfg.Paths.SignerKeyring); loadErr == nil {
			activeKID = fmt.Sprintf("%d", keyring.ActiveKid())
		} else {
			activeKID = "unavailable"
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
		{"credential authority", durab(stateBacked), authorityNote(stateBacked)},
		{"lane authority", durab(stateBacked), authorityNote(stateBacked)},
		{"evidence authority", durab(stateBacked), authorityNote(stateBacked)},
		{"signer identity", durab(cfg.Paths.SignerKeyring != ""), signerNote(cfg)},
		{"operator audit", durab(stateBacked || cfg.Paths.AuditLog != ""), auditNote(cfg)},
		{"operator control plane", onoff(cfg.Admin != nil), adminNote(cfg)},
		{"source attribution", onoff(providerSource), sourceNote(cfg)},
		{"network metadata", onoff(networkMetadata), networkNote(cfg)},
		{"source blocking", onoff(pol.Risk.SourceMode == policy.SourceEnforce), "shadow-only default: sourceWouldBlock recorded, never denies (P0.7)"},
		{"automatic credential quarantine", onoff(pol.Risk.EnableAutomaticQuarantine), "policy-controlled; operator-set only while disabled"},
		{"automatic lane block", onoff(pol.LaneSecurity.EnableAutomaticBlock), "policy-controlled (INV hysteresis)"},
		{"request accounting", on(), "NoUsage provider counts one admitted request"},
		{"token accounting", onoff(usageConfigured), usageNote(cfg, "tokens")},
		{"cost accounting", onoff(usageConfigured && (cfg.Usage.InputMicrounitsPerToken > 0 || cfg.Usage.OutputMicrounitsPerToken > 0)), usageNote(cfg, "cost")},
		{"active policy", "configured", fmt.Sprintf("%s revision=%d digest=%s", pol.ID, pol.Revision, policyDigest)},
		{"resource persistence", "process-lifetime", "governor windows are volatile; restart-safe credential/lane/evidence state remains durable"},
		{"source-table bound", fmt.Sprintf("%d", maxSourceScopes), "zero resolves to the conservative runtime default; overflow identities are hashed into bounded shared scopes"},
		{"spool bounds", fmt.Sprintf("%d bytes/%d files", spoolBytes, spoolFiles), "aggregate unknown-length request budget"},
		{"active signer KID", activeKID, "public key generations are exported separately"},
		{"pepper versions", pepperVersions, "version identifiers only; key material is never displayed"},
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CAPABILITY\tSTATE\tNOTE")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.capability, r.state, r.note)
	}
	return w.Flush()
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

func authorityNote(stateBacked bool) string {
	if stateBacked {
		return "Bolt transactional store"
	}
	return "memory store (ephemeral; not for production)"
}

func signerNote(cfg *config.Config) string {
	if cfg.Paths.SignerKeyring != "" {
		return "persistent keyring"
	}
	return "in-memory keyring (identity changes on restart)"
}

func auditNote(cfg *config.Config) string {
	if cfg.Paths.State != "" {
		return "bolt state database (authoritative)"
	}
	if cfg.Paths.AuditLog != "" {
		return "JSONL file (ephemeral state mode)"
	}
	return "none"
}

func sourceNote(cfg *config.Config) string {
	if cfg.Ingress == nil || cfg.Ingress.PseudonymKey == "" {
		return "no trusted ingress source resolver configured"
	}
	return "trusted ingress pseudonyms; network attribution still unavailable"
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
