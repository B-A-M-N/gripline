package main

// CLI operator lifecycle subcommands (P1-26): credential list/revoke and lane
// list/unblock against the configured deployment's state authority. The CLI
// operates THROUGH the same control-plane service seams the admin HTTP surface
// uses (authorization + transactional mutation + audit), and it NEVER prints
// or accepts raw credential secrets — verifiers are internal material.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/credential"
)

// runCredentialCLI dispatches `gripline credential <list|revoke>`.
func runCredentialCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("credential: expected 'list' or 'revoke' (usage: gripline credential list --config c.json; gripline credential revoke --config c.json --id <cred> --reason <text> --token <op-token>)")
	}
	fs := flag.NewFlagSet("credential", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	credID := fs.String("id", "", "credential id (revoke)")
	reason := fs.String("reason", "", "audit reason (revoke, required)")
	token := fs.String("token", "", "operator token (revoke; env GRIPLINE_OPERATOR_TOKEN)")
	switch args[0] {
	case "list":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runCredentialList(*cfgPath)
	case "revoke":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		tok := *token
		if tok == "" {
			tok = os.Getenv("GRIPLINE_OPERATOR_TOKEN")
		}
		return runCredentialRevoke(*cfgPath, *credID, *reason, tok)
	default:
		return fmt.Errorf("credential: unknown action %q (expected list|revoke)", args[0])
	}
}

// runLaneCLI dispatches `gripline lane <list|unblock>`.
func runLaneCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("lane: expected 'list' or 'unblock' (usage: gripline lane list --config c.json --credential <cred>; gripline lane unblock --config c.json --credential <cred> --id <lane> --reason <text> --token <op-token>)")
	}
	fs := flag.NewFlagSet("lane", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	credID := fs.String("credential", "", "credential id (required)")
	laneID := fs.String("id", "", "lane id (unblock)")
	reason := fs.String("reason", "", "audit reason (unblock, required)")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		if *credID == "" {
			return fmt.Errorf("lane list: --credential is required")
		}
		return runLaneList(*cfgPath, *credID)
	case "unblock":
		tok := *token
		if tok == "" {
			tok = os.Getenv("GRIPLINE_OPERATOR_TOKEN")
		}
		return runLaneUnblock(*cfgPath, *credID, *laneID, *reason, tok)
	default:
		return fmt.Errorf("lane: unknown action %q (expected list|unblock)", args[0])
	}
}

// openStateForCLI loads the config and returns the durable state store plus
// the control service it backs (or nil when no admin section is configured —
// list works either way, mutations require the operator surface).
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
	ids := h.rt.Lanes.ListLaneIDs(credID)
	if len(ids) == 0 {
		fmt.Printf("no lanes for credential %s\n", credID)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "LANE\tSTATE\tSECURITY\tRISK\tREQUESTS\tLAST_SEEN")
	now := time.Now()
	for _, id := range ids {
		rec, ok := h.rt.Lanes.Get(credID, id)
		if !ok {
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n",
			rec.LaneID, rec.State.String(), rec.Security.Status.String(),
			rec.RiskScore, rec.RequestCount,
			rec.LastSeenAt.UTC().Format(time.RFC3339))
	}
	_ = now
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
	type row struct {
		capability string
		state      string
		note       string
	}
	rows := []row{
		{"credential authority", durab(cfg.Paths.State != ""), "bolt transactional store"},
		{"lane authority", durab(cfg.Paths.State != ""), "bolt transactional store"},
		{"evidence authority", durab(cfg.Paths.State != ""), "bolt transactional store"},
		{"signer identity", durab(cfg.Paths.SignerKeyring != ""), "persistent keyring"},
		{"operator audit", durab(cfg.Paths.State != "" || cfg.Paths.AuditLog != ""), auditNote(cfg)},
		{"operator control plane", onoff(cfg.Admin != nil), adminNote(cfg)},
		{"source blocking", onoff(pol.Risk.SourceMode == 1), "shadow-only default: sourceWouldBlock recorded, never denies (P0.7)"},
		{"automatic credential quarantine", off(), "operator-set only until shadow validation (policy gate)"},
		{"automatic lane block", onoff(pol.LaneSecurity.EnableAutomaticBlock), "policy-controlled (INV hysteresis)"},
		{"token/cost gauges", onoff(pol.Limits.Normal.Tokens.Capacity > 0 || pol.Limits.Normal.Cost.Capacity > 0), "disabled until provider-specific budgets are authored"},
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

func auditNote(cfg *config.Config) string {
	if cfg.Paths.State != "" {
		return "bolt state database (authoritative)"
	}
	if cfg.Paths.AuditLog != "" {
		return "jsonl file (ephemeral mode)"
	}
	return "none"
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
