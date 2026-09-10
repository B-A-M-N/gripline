package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// runCryptoCLI is the focused view and activation surface for shared crypto
// generations. Status is read-only; activation is authenticated, audited, and
// replay-safe through the live admin authority.
func runCryptoCLI(args []string) error {
	return runCryptoCLIWithContext(&cliContext{Timeout: 30 * time.Second}, args)
}

func runCryptoCLIWithContext(cliCtx *cliContext, args []string) error {
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
	fs := newCLIFlagSet("crypto " + action)
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	kind := fs.String("kind", "", "generation kind: signer, pepper, or pseudonym")
	generation := fs.Int("generation", 0, "loaded generation to activate")
	fingerprint := fs.String("fingerprint", "", "exact loaded-generation fingerprint from crypto status")
	reason := fs.String("reason", "", "operator reason")
	notBefore := fs.String("not-before", "", "RFC3339 overlap horizon (retire only)")
	operationID := fs.String("operation-id", "", "idempotent retry key within the authority retention window")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	output := fs.String("output", "table", "output format: table, json, or jsonl")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	format, err := parseCLIOutput(*output)
	if err != nil {
		return fmt.Errorf("crypto %s: %w", action, err)
	}
	tok, err := operatorTokenFromFile(*token, *tokenFile)
	if err != nil {
		return err
	}
	if tok == "" {
		return fmt.Errorf("crypto %s: no operator credential found; set GRIPLINE_OPERATOR_TOKEN, GRIPLINE_OPERATOR_TOKEN_FILE, or pass --token-file", action)
	}
	if strings.TrimSpace(*kind) == "" || *generation < 1 || strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("crypto %s: usage is `gripline crypto %s <kind> <generation> -r <reason>`", action, action)
	}
	operation, err := newOperationID(*operationID)
	if err != nil {
		return err
	}
	client, err := newAdminClientWithTimeout(*cfgPath, cliRequestTimeout(fs))
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(context.Background(), cliRequestTimeout(fs))
	defer cancel()
	resolved, err := resolveCryptoGeneration(requestCtx, client, tok, *kind, *generation)
	if err != nil {
		return fmt.Errorf("crypto %s: %w", action, err)
	}
	if strings.TrimSpace(*fingerprint) != "" && *fingerprint != resolved.Fingerprint {
		return fmt.Errorf("crypto %s: explicit fingerprint does not match authoritative %s/%d fingerprint", action, *kind, *generation)
	}
	*fingerprint = resolved.Fingerprint
	body := map[string]any{"kind": *kind, "generation": *generation, "fingerprint": *fingerprint, "reason": *reason}
	endpoint := "/admin/crypto/activate"
	if action == "retire" {
		if strings.TrimSpace(*notBefore) != "" {
			parsed, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(*notBefore))
			if parseErr != nil {
				return fmt.Errorf("crypto retire: --not-before must be RFC3339: %w", parseErr)
			}
			body["not_before"] = parsed.UTC()
		}
		endpoint = "/admin/crypto/retire"
	}
	var result map[string]any
	if err := client.requestWithOperationIDContext(requestCtx, http.MethodPost, endpoint, tok, operation, body, &result); err != nil {
		return fmt.Errorf("crypto %s: %w", action, err)
	}
	if format == outputJSON || format == outputJSONL {
		if err := encodeCLIOutput(format, result); err != nil {
			return err
		}
	} else {
		fmt.Printf("%s %s generation %d\n", action, *kind, *generation)
	}
	return nil
}

func resolveCryptoGeneration(ctx context.Context, client *adminClient, token, kind string, generation int) (statepg.ClusterCryptoGenerationStatus, error) {
	if client == nil {
		return statepg.ClusterCryptoGenerationStatus{}, errors.New("crypto authority client unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var status struct {
		Crypto statepg.ClusterCryptoStatus `json:"crypto"`
	}
	if err := client.requestContext(ctx, http.MethodGet, "/admin/crypto", token, nil, &status); err != nil {
		return statepg.ClusterCryptoGenerationStatus{}, err
	}
	for _, candidate := range status.Crypto.Generations {
		if candidate.Kind == kind && candidate.Generation == generation {
			if strings.TrimSpace(candidate.Fingerprint) == "" {
				return statepg.ClusterCryptoGenerationStatus{}, fmt.Errorf("generation %s/%d has no authoritative fingerprint", kind, generation)
			}
			return candidate, nil
		}
	}
	return statepg.ClusterCryptoGenerationStatus{}, fmt.Errorf("generation %s/%d is not present in the authoritative crypto status", kind, generation)
}

// runCryptoSignerPrepareCLI creates one durable local candidate. In a cluster
// this is a stopped-node/key-material operation: the resulting sealed keyring
// must be distributed identically to every node before the live activation
// command can pass the authority acknowledgement barrier.
func runCryptoSignerPrepareCLI(args []string) error {
	fs := newCLIFlagSet("crypto signer-prepare")
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	offline := fs.Bool("offline", false, "confirm the serving deployment is stopped")
	output := fs.String("output", "", "output format: table, json, or jsonl")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := parseCLIOutput(*output); err != nil {
		return fmt.Errorf("crypto signer-prepare: %w", err)
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
	format, err := parseCLIOutput(*output)
	if err != nil {
		return fmt.Errorf("crypto signer-prepare: %w", err)
	}
	if format == outputJSON || format == outputJSONL {
		if err := encodeCLIOutput(format, map[string]any{"generation": candidate.KID, "fingerprint": fingerprint, "status": "prepared"}); err != nil {
			return err
		}
	} else {
		fmt.Printf("prepared signer generation %d fingerprint=%s; distribute this sealed keyring to every node before activation\n", candidate.KID, fingerprint)
	}
	return errSubcommand
}
