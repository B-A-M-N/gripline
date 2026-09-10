package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/terminator"
	"golang.org/x/term"
)

// runCredentialCLI dispatches `gripline credential <list|revoke>`.
func runCredentialCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("credential: expected 'list', 'add', or 'revoke' (use --token-file; add --offline only for stopped maintenance)")
	}
	fs := newCLIFlagSet("credential")
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	credID := fs.String("id", "", "credential id (revoke)")
	reason := fs.String("reason", "", "audit reason (revoke, required)")
	operationID := fs.String("operation-id", "", "idempotent retry key within the authority retention window")
	account := fs.String("account", "", "account id (add, required)")
	policyID := fs.String("policy", "", "policy id (add; defaults to the active policy)")
	planID := fs.String("plan", "plan-default", "plan id (add)")
	secretStdin := fs.Bool("secret-stdin", false, "deprecated compatibility flag; stdin is detected automatically")
	secretFile := fs.String("secret-file", "", "read the raw credential from this file (add)")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	offline := fs.Bool("offline", false, "operate directly on a stopped state database")
	output := fs.String("output", "table", "output format: table, json, or jsonl")
	switch args[0] {
	case "list":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		format, err := parseCLIOutput(*output)
		if err != nil {
			return err
		}
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		if *offline {
			return runCredentialList(*cfgPath, format)
		}
		return runCredentialListLiveWithOutput(*cfgPath, tok, format, cliRequestTimeout(fs))
	case "pepper-status":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		format, err := parseCLIOutput(*output)
		if err != nil {
			return err
		}
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		if *offline {
			return fmt.Errorf("credential pepper-status: offline mode is not supported; use the authenticated live authority")
		}
		return runCredentialPepperStatusLiveWithOutput(*cfgPath, tok, format, cliRequestTimeout(fs))
	case "revoke":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		format, err := parseCLIOutput(*output)
		if err != nil {
			return err
		}
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		if *offline {
			return runCredentialRevoke(*cfgPath, *credID, *reason, tok, format)
		}
		return runCredentialRevokeLiveWithOperationIDAndOutput(*cfgPath, *credID, *reason, tok, *operationID, format, cliRequestTimeout(fs))
	case "add":
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		format, err := parseCLIOutput(*output)
		if err != nil {
			return err
		}
		_ = *secretStdin
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		return runCredentialAddLiveWithOperationIDAndSecretFileAndOutput(*cfgPath, *credID, *account, *policyID, *planID, *reason, tok, *operationID, *secretFile, format, cliRequestTimeout(fs))
	default:
		return fmt.Errorf("credential: unknown action %q (expected list|pepper-status|add|revoke)", args[0])
	}
}

// runLaneCLI dispatches `gripline lane <list|unblock>`.

func runCredentialListLiveWithOutput(cfgPath, token string, format outputFormat, timeouts ...time.Duration) error {
	if token == "" {
		return fmt.Errorf("credential list: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	c, err := newAdminClientWithTimeout(cfgPath, firstCLITimeout(timeouts))
	if err != nil {
		return err
	}
	var rows []credential.Summary
	if err := c.request(http.MethodGet, "/admin/credentials", token, nil, &rows); err != nil {
		return fmt.Errorf("credential list: %w", err)
	}
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutputRows(format, rows)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CREDENTIAL\tACCOUNT\tSTATUS\tPOLICY\tCREATED\tREV")
	for _, s := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n", s.CredentialID, s.AccountID, s.Status, s.PolicyID, s.CreatedAt.UTC().Format(time.RFC3339), s.Revision)
	}
	return w.Flush()
}

func runCredentialPepperStatusLiveWithOutput(cfgPath, token string, format outputFormat, timeouts ...time.Duration) error {
	if token == "" {
		return fmt.Errorf("credential pepper-status: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	c, err := newAdminClientWithTimeout(cfgPath, firstCLITimeout(timeouts))
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
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutput(format, counts)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tCREDENTIALS")
	for _, version := range versions {
		fmt.Fprintf(w, "%d\t%d\n", version, counts[strconv.Itoa(version)])
	}
	return w.Flush()
}

func runCredentialRevokeLiveWithOperationIDAndOutput(cfgPath, credID, reason, token, operationID string, format outputFormat, timeouts ...time.Duration) error {
	if credID == "" || reason == "" || token == "" {
		return fmt.Errorf("credential revoke: --id, --reason, and --token (or GRIPLINE_OPERATOR_TOKEN) are required")
	}
	c, err := newAdminClientWithTimeout(cfgPath, firstCLITimeout(timeouts))
	if err != nil {
		return err
	}
	if err := c.requestWithOperationID(http.MethodPost, "/admin/credentials/revoke", token, operationID, map[string]string{
		"credential_id": credID, "reason": reason,
	}, nil); err != nil {
		return fmt.Errorf("credential revoke: %w", err)
	}
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutput(format, map[string]string{"result": "revoked", "credential_id": credID})
	}
	fmt.Printf("revoked %s (mutation + audit committed atomically)\n", credID)
	return nil
}

func runCredentialAddLive(cfgPath, credID, accountID, policyID, planID, reason, token string) error {
	return runCredentialAddLiveWithOperationID(cfgPath, credID, accountID, policyID, planID, reason, token, "")
}

func readCredentialInput(secretFile string) ([]byte, error) {
	if strings.TrimSpace(secretFile) != "" {
		file, err := os.Open(secretFile) // #nosec G304 -- the operator explicitly supplied the secret file.
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return io.ReadAll(io.LimitReader(file, terminator.MaxExternalCredentialBytes+1))
	}
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "External credential: ")
		secret, readErr := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return secret, readErr
	}
	return io.ReadAll(io.LimitReader(os.Stdin, terminator.MaxExternalCredentialBytes+1))
}

func runCredentialAddLiveWithOperationID(cfgPath, credID, accountID, policyID, planID, reason, token, operationID string) error {
	return runCredentialAddLiveWithOperationIDAndSecretFileAndOutput(cfgPath, credID, accountID, policyID, planID, reason, token, operationID, "", outputTable)
}

func runCredentialAddLiveWithOperationIDAndSecretFileAndOutput(cfgPath, credID, accountID, policyID, planID, reason, token, operationID, secretFile string, format outputFormat, timeouts ...time.Duration) error {
	if credID == "" || accountID == "" || planID == "" || reason == "" || token == "" {
		return fmt.Errorf("credential add: --id, --account, --reason, and --token (or --token-file/GRIPLINE_OPERATOR_TOKEN) are required")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	client, err := newAdminClientWithTimeout(cfgPath, firstCLITimeout(timeouts))
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
	raw, err := readCredentialInput(secretFile)
	if err != nil {
		return fmt.Errorf("credential add: read external credential: %w", err)
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
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutput(format, map[string]string{"result": "added", "credential_id": credID})
	}
	fmt.Printf("added %s (verifier derived locally; raw secret not sent)\n", credID)
	return nil
}
