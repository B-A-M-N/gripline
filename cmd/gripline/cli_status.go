package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// runStatusCLI prints startup capability status (P1-27): which authorities are
// durable, which are shadow-only, and which are disabled — the honest
// deployment picture an operator needs before trusting the gateway.
func runStatusCLI(cfgPath string) error {
	return runStatusCLIWithOutput(cfgPath, outputTable)
}

func runStatusCLIWithOutput(cfgPath string, format outputFormat) error {
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
		Capability string `json:"capability"`
		State      string `json:"state"`
		Note       string `json:"note"`
	}
	maxSourceScopes := cfg.Server.MaxSourceScopes
	if maxSourceScopes == 0 {
		maxSourceScopes = resource.DefaultMaxSourceScopes
	}
	maxSourceAliasIdentities := cfg.Authority.MaxSourceAliasIdentities
	if maxSourceAliasIdentities == 0 {
		maxSourceAliasIdentities = 4096
	}
	clusterBehaviorState, clusterBehaviorNote := "not-applicable", "standalone deployment"
	if clustered {
		clusterBehaviorState = "configured"
		behaviorDigest, digestErr := clusterBehaviorFromConfig(cfg).Digest()
		if digestErr != nil {
			return fmt.Errorf("cluster behavior digest: %w", digestErr)
		}
		clusterBehaviorNote = fmt.Sprintf("local digest=%s; authority mismatch is reported by cluster status", behaviorDigest)
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
		{"cluster behavior", clusterBehaviorState, clusterBehaviorNote},
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
		{"resource source-scope bound", fmt.Sprintf("%d", maxSourceScopes), "backend-neutral resource scope cardinality; overflow identities are hashed into bounded shared scopes"},
		{"source alias identity bound", fmt.Sprintf("%d", maxSourceAliasIdentities), "shared alias capacity; live identity and row counts are shown by cluster status/metrics"},
		{"source alias registration", "authenticated-only", "durable source aliases are bound only after credential match"},
		{"spool bounds", fmt.Sprintf("%d bytes/%d files", spoolBytes, spoolFiles), "aggregate unknown-length request budget"},
		{"active signer KID", activeKID, "public key generations are exported separately"},
		{"pepper versions", pepperVersions, "version identifiers only; key material is never displayed"},
		{"pseudonym versions", pseudonymVersions, "active and overlap versions; key material is never displayed"},
	}
	if clustered {
		controlRetention := cfg.Authority.Maintenance.ControlOperationRetention.D()
		credentialRetention := cfg.Authority.Maintenance.CredentialReceiptRetention.D()
		if controlRetention <= 0 {
			controlRetention = 24 * time.Hour
		}
		if credentialRetention <= 0 {
			credentialRetention = 24 * time.Hour
		}
		rows = append(rows,
			row{"control operation retention", formatRetention(controlRetention), "operation IDs replay only within this authority retention window"},
			row{"credential receipt retention", formatRetention(credentialRetention), "credential retry receipts are retained for this window"},
		)
		sourceAliasRetention := cfg.Authority.Maintenance.SourceAliasRetention.D()
		if sourceAliasRetention <= 0 {
			sourceAliasRetention = 7 * 24 * time.Hour
		}
		rows = append(rows, row{"source alias retention", formatRetention(sourceAliasRetention), "stale unreferenced aliases are reclaimed only after this window"})
	}
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutputRows(format, rows)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CAPABILITY\tSTATE\tNOTE")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.Capability, r.State, r.Note)
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

func formatRetention(retention time.Duration) string {
	if retention%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(retention/time.Hour))
	}
	return retention.String()
}

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
