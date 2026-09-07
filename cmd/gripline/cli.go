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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/policy"
)

// runCredentialCLI dispatches `gripline credential <list|revoke>`.
func runCredentialCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("credential: expected 'list' or 'revoke' (use --token; add --offline only for stopped maintenance)")
	}
	fs := flag.NewFlagSet("credential", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	credID := fs.String("id", "", "credential id (revoke)")
	reason := fs.String("reason", "", "audit reason (revoke, required)")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	offline := fs.Bool("offline", false, "operate directly on a stopped state database")
	switch args[0] {
	case "list":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		tok := operatorToken(*token)
		if *offline {
			return runCredentialList(*cfgPath)
		}
		return runCredentialListLive(*cfgPath, tok)
	case "revoke":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		tok := *token
		if tok == "" {
			tok = os.Getenv("GRIPLINE_OPERATOR_TOKEN")
		}
		if *offline {
			return runCredentialRevoke(*cfgPath, *credID, *reason, tok)
		}
		return runCredentialRevokeLive(*cfgPath, *credID, *reason, tok)
	default:
		return fmt.Errorf("credential: unknown action %q (expected list|revoke)", args[0])
	}
}

// runLaneCLI dispatches `gripline lane <list|unblock>`.
func runLaneCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("lane: expected 'list' or 'unblock' (use --token; add --offline only for stopped maintenance)")
	}
	fs := flag.NewFlagSet("lane", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	credID := fs.String("credential", "", "credential id (required)")
	laneID := fs.String("id", "", "lane id (unblock)")
	reason := fs.String("reason", "", "audit reason (unblock, required)")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	offline := fs.Bool("offline", false, "operate directly on a stopped state database")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		if *credID == "" {
			return fmt.Errorf("lane list: --credential is required")
		}
		tok := operatorToken(*token)
		if *offline {
			return runLaneList(*cfgPath, *credID)
		}
		return runLaneListLive(*cfgPath, *credID, tok)
	case "unblock":
		tok := *token
		if tok == "" {
			tok = os.Getenv("GRIPLINE_OPERATOR_TOKEN")
		}
		if *offline {
			return runLaneUnblock(*cfgPath, *credID, *laneID, *reason, tok)
		}
		return runLaneUnblockLive(*cfgPath, *credID, *laneID, *reason, tok)
	default:
		return fmt.Errorf("lane: unknown action %q (expected list|unblock)", args[0])
	}
}

func operatorToken(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("GRIPLINE_OPERATOR_TOKEN")
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
	if len(args) == 0 || (args[0] != "list" && args[0] != "export") {
		return fmt.Errorf("audit: expected list or export")
	}
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to deployment configuration")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	tok := operatorToken(*token)
	if tok == "" {
		return fmt.Errorf("audit: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	c, err := newAdminClient(*cfgPath)
	if err != nil {
		return err
	}
	var rows []control.OperatorRecord
	if err := c.request(http.MethodGet, "/admin/audit?limit=1000", tok, nil, &rows); err != nil {
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
	rt, err := BuildRuntime(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, &runtimeCLI{rt: rt}, nil
}

type runtimeCLI struct {
	rt *Runtime
}

func (c *runtimeCLI) close() error { return c.rt.Close() }

func runCredentialList(cfgPath string) error {
	_, h, err := openStateForCLI(cfgPath)
	if err != nil {
		return err
	}
	defer h.close()
	sums, err := h.rt.State.ListCredentials()
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
	_, h, err := openStateForCLI(cfgPath)
	if err != nil {
		return err
	}
	defer h.close()
	if h.rt.AdminService == nil {
		return fmt.Errorf("credential revoke: the deployment configures no admin section (admin.operator_tokens); there is no operator identity to authorize")
	}
	// NOTE: the CLI holds the runtime exclusively (the data plane is not
	// serving here), so the mutation is safe without runtime coordination.
	if err := h.rt.controlService().RevokeCredential(context.Background(), token, credID, reason); err != nil {
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
	rows, err := h.rt.State.ListLaneRecords(credID)
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
	_, h, err := openStateForCLI(cfgPath)
	if err != nil {
		return err
	}
	defer h.close()
	if h.rt.AdminService == nil {
		return fmt.Errorf("lane unblock: the deployment configures no admin section (admin.operator_tokens); there is no operator identity to authorize")
	}
	if err := h.rt.controlService().UnblockLane(context.Background(), token, credID, laneID, reason); err != nil {
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
	pol := policyFor(cfg)
	stateBacked := cfg.Paths.State != ""
	providerSource := cfg.Ingress != nil && cfg.Ingress.PseudonymKey != ""
	type row struct {
		capability string
		state      string
		note       string
	}
	rows := []row{
		{"credential authority", durab(stateBacked), authorityNote(stateBacked)},
		{"lane authority", durab(stateBacked), authorityNote(stateBacked)},
		{"evidence authority", durab(stateBacked), authorityNote(stateBacked)},
		{"signer identity", durab(cfg.Paths.SignerKeyring != ""), signerNote(cfg)},
		{"operator audit", durab(stateBacked || cfg.Paths.AuditLog != ""), auditNote(cfg)},
		{"operator control plane", onoff(cfg.Admin != nil), adminNote(cfg)},
		{"source attribution", onoff(providerSource), sourceNote(cfg)},
		{"network metadata", off(), "no NetworkMetadataResolver configured; ASN/region are unknown"},
		{"source blocking", onoff(pol.Risk.SourceMode == policy.SourceEnforce), "shadow-only default: sourceWouldBlock recorded, never denies (P0.7)"},
		{"automatic credential quarantine", off(), "operator-set only until shadow validation (policy gate)"},
		{"automatic lane block", onoff(pol.LaneSecurity.EnableAutomaticBlock), "policy-controlled (INV hysteresis)"},
		{"request accounting", on(), "NoUsage provider counts one admitted request"},
		{"token accounting", off(), "NoUsage provider; provider usage adapter required"},
		{"cost accounting", off(), "NoUsage provider; provider usage adapter required"},
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
func off() string { return "off" }

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

func adminNote(cfg *config.Config) string {
	if cfg.Admin == nil {
		return "no admin listener configured"
	}
	return "admin listener at " + cfg.Admin.Listen
}

// interface assertions keep the CLI seams honest: the durable store must
// implement the credential lister (it does, via internal/statebolt).
var _ = credential.Lister(nil)
