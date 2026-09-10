package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

func runStateCLI(args []string) error {
	if len(args) == 0 || (args[0] != "check" && args[0] != "backup" && args[0] != "restore" && args[0] != "compact") {
		return fmt.Errorf("state: expected check, backup, restore, or compact")
	}
	fs := newCLIFlagSet("state")
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to deployment configuration")
	outPath := fs.String("out", "", "backup output path")
	fromPath := fs.String("from", "", "backup input path")
	manifestPath := fs.String("manifest", "", "backup recovery manifest path (default: <out>.manifest.json)")
	output := fs.String("output", "table", "output format: table, json, or jsonl")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	format, err := parseCLIOutput(*output)
	if err != nil {
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
		if format == outputJSON || format == outputJSONL {
			return encodeCLIOutput(format, map[string]string{"result": "healthy", "state": cfg.Paths.State})
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
		if format == outputJSON || format == outputJSONL {
			return encodeCLIOutput(format, map[string]string{"result": "backup verified", "path": *outPath, "manifest": manifest})
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
		manifestData, err := os.ReadFile(manifest) // #nosec G304 -- manifest path is an explicit operator input.
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
		if format == outputJSON || format == outputJSONL {
			return encodeCLIOutput(format, map[string]string{"result": "restored and verified", "state": cfg.Paths.State})
		}
		fmt.Printf("state restored and verified: %s\n", cfg.Paths.State)
		return nil
	case "compact":
		if err := statebolt.CompactFile(cfg.Paths.State); err != nil {
			return err
		}
		if format == outputJSON || format == outputJSONL {
			return encodeCLIOutput(format, map[string]string{"result": "compacted and verified", "state": cfg.Paths.State})
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

func runCredentialList(cfgPath string, formats ...outputFormat) error {
	format := firstCLIOutputFormat(formats)
	_, h, err := openStateForCLI(cfgPath)
	if err != nil {
		return err
	}
	defer h.close()
	sums, err := h.state.ListCredentials()
	if err != nil {
		return err
	}
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutputRows(format, sums)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CREDENTIAL\tACCOUNT\tSTATUS\tPOLICY\tCREATED\tREV")
	for _, s := range sums {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n", s.CredentialID, s.AccountID, s.Status, s.PolicyID, s.CreatedAt.UTC().Format(time.RFC3339), s.Revision)
	}
	return w.Flush()
}

func runCredentialRevoke(cfgPath, credID, reason, token string, formats ...outputFormat) error {
	format := firstCLIOutputFormat(formats)
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
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutput(format, map[string]string{"result": "revoked", "credential_id": credID})
	}
	fmt.Printf("revoked %s (mutation + audit committed atomically)\n", credID)
	return nil
}

func runLaneList(cfgPath, credID string, formats ...outputFormat) error {
	format := firstCLIOutputFormat(formats)
	_, h, err := openStateForCLI(cfgPath)
	if err != nil {
		return err
	}
	defer h.close()
	rows, err := h.state.ListLaneRecords(credID)
	if err != nil {
		return fmt.Errorf("lane list: %w", err)
	}
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutputRows(format, rows)
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

func runLaneUnblock(cfgPath, credID, laneID, reason, token string, formats ...outputFormat) error {
	format := firstCLIOutputFormat(formats)
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
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutput(format, map[string]string{"result": "unblocked", "credential_id": credID, "lane_id": laneID})
	}
	fmt.Printf("unblocked %s/%s (mutation + audit committed atomically)\n", credID, laneID)
	return nil
}
