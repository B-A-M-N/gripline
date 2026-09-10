package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
)

func runAuditCLI(args []string) error {
	if len(args) > 0 && args[0] == "security" {
		return runSecurityAuditCLI(args[1:])
	}
	if len(args) == 0 || (args[0] != "list" && args[0] != "export") {
		return fmt.Errorf("audit: expected list, export, or security list|export")
	}
	fs := newCLIFlagSet("audit")
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to deployment configuration")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	output := fs.String("output", "table", "output format: table, json, or jsonl")
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
	if tok == "" {
		return fmt.Errorf("audit: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	c, err := newAdminClientWithTimeout(*cfgPath, cliRequestTimeout(fs))
	if err != nil {
		return err
	}
	rows, err := fetchOperatorAudit(c, tok)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if args[0] == "export" || format == outputJSONL {
		return encodeCLIOutputRows(formatOrJSONL(format), rows)
	}
	if format == outputJSON {
		return encodeCLIOutput(outputJSON, rows)
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
	fs := newCLIFlagSet("audit security")
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to deployment configuration")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	output := fs.String("output", "table", "output format: table, json, or jsonl")
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
	if tok == "" {
		return fmt.Errorf("audit security: --token (or GRIPLINE_OPERATOR_TOKEN) is required")
	}
	c, err := newAdminClientWithTimeout(*cfgPath, cliRequestTimeout(fs))
	if err != nil {
		return err
	}
	rows, err := fetchSecurityAudit(c, tok)
	if err != nil {
		return fmt.Errorf("audit security: %w", err)
	}
	if args[0] == "export" || format == outputJSONL {
		return encodeCLIOutputRows(formatOrJSONL(format), rows)
	}
	if format == outputJSON {
		return encodeCLIOutput(outputJSON, rows)
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
