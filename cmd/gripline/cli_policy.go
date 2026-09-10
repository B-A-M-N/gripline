package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/policy"
)

// runPolicyCLI dispatches policy verification and the authenticated lifecycle
// commands used by the running control plane.
func runPolicyCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy: expected verify, status, prepare, activate, or rollback")
	}
	if args[0] == "verify" {
		fs := newCLIFlagSet("policy verify")
		cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
		output := fs.String("output", "table", "output format: table, json, or jsonl")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		format, err := parseCLIOutput(*output)
		if err != nil {
			return fmt.Errorf("policy verify: %w", err)
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
		if format == outputTable {
			fmt.Printf("policy verified: %s revision=%d digest=%s\n", pol.ID, pol.Revision, digest)
		} else {
			if err := encodeCLIOutput(format, map[string]any{"id": pol.ID, "revision": pol.Revision, "digest": digest}); err != nil {
				return err
			}
		}
		return errSubcommand
	}
	fs := newCLIFlagSet("policy")
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	filePath := fs.String("file", "", "signed policy envelope (prepare)")
	reason := fs.String("reason", "", "operator reason")
	revision := fs.Int("revision", 0, "known-good revision (rollback)")
	operationID := fs.String("operation-id", "", "idempotent retry key within the authority retention window")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	output := fs.String("output", "", "output format: table, json, or jsonl")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	format, err := parseCLIOutput(*output)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	tok, err := operatorTokenFromFile(*token, *tokenFile)
	if err != nil {
		return err
	}
	if tok == "" {
		return fmt.Errorf("policy %s: --token (or GRIPLINE_OPERATOR_TOKEN) is required", args[0])
	}
	client, err := newAdminClientWithTimeout(*cfgPath, cliRequestTimeout(fs))
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		var status map[string]any
		if err := client.request(http.MethodGet, "/admin/policy", tok, nil, &status); err != nil {
			return fmt.Errorf("policy status: %w", err)
		}
		if format == outputTable || format == "" {
			return printPolicyStatusTable(status)
		}
		if err := encodeCLIOutput(format, status); err != nil {
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
		if format == outputJSON || format == outputJSONL {
			return encodeCLIOutput(format, result)
		}
		fmt.Printf("policy candidate prepared\n")
	case "activate":
		if strings.TrimSpace(*reason) == "" {
			return fmt.Errorf("policy activate: --reason is required")
		}
		if err := client.requestWithOperationID(http.MethodPost, "/admin/policy/activate", tok, *operationID, map[string]string{"reason": *reason}, nil); err != nil {
			return fmt.Errorf("policy activate: %w", err)
		}
		if format == outputJSON || format == outputJSONL {
			return encodeCLIOutput(format, map[string]string{"result": "policy candidate activated"})
		}
		fmt.Println("policy candidate activated")
	case "rollback":
		if *revision < 1 || strings.TrimSpace(*reason) == "" {
			return fmt.Errorf("policy rollback: --revision and --reason are required")
		}
		if err := client.requestWithOperationID(http.MethodPost, "/admin/policy/rollback", tok, *operationID, map[string]any{"revision": *revision, "reason": *reason}, nil); err != nil {
			return fmt.Errorf("policy rollback: %w", err)
		}
		if format == outputJSON || format == outputJSONL {
			return encodeCLIOutput(format, map[string]any{"result": "policy rolled back", "revision": *revision})
		}
		fmt.Printf("policy rolled back to revision %d\n", *revision)
	default:
		return fmt.Errorf("policy: unknown action %q", args[0])
	}
	return nil
}
