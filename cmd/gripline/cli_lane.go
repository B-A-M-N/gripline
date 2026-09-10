package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"text/tabwriter"
	"time"
)

func runLaneCLI(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("lane: expected 'list' or 'unblock' (use --token-file; add --offline only for stopped maintenance)")
	}
	fs := newCLIFlagSet("lane")
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	credID := fs.String("credential", "", "credential id (required)")
	laneID := fs.String("id", "", "lane id (unblock)")
	reason := fs.String("reason", "", "audit reason (unblock, required)")
	operationID := fs.String("operation-id", "", "idempotent retry key within the authority retention window")
	token := fs.String("token", "", "operator token (env GRIPLINE_OPERATOR_TOKEN)")
	tokenFile := fs.String("token-file", "", "read the operator token from this file")
	offline := fs.Bool("offline", false, "operate directly on a stopped state database")
	output := fs.String("output", "table", "output format: table, json, or jsonl")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	format, err := parseCLIOutput(*output)
	if err != nil {
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
			return runLaneList(*cfgPath, *credID, format)
		}
		return runLaneListLiveWithOutput(*cfgPath, *credID, tok, format, cliRequestTimeout(fs))
	case "unblock":
		format, err := parseCLIOutput(*output)
		if err != nil {
			return err
		}
		tok, err := operatorTokenFromFile(*token, *tokenFile)
		if err != nil {
			return err
		}
		if *offline {
			return runLaneUnblock(*cfgPath, *credID, *laneID, *reason, tok, format)
		}
		return runLaneUnblockLiveWithOperationIDAndOutput(*cfgPath, *credID, *laneID, *reason, tok, *operationID, format, cliRequestTimeout(fs))
	default:
		return fmt.Errorf("lane: unknown action %q (expected list|unblock)", args[0])
	}
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

func runLaneListLiveWithOutput(cfgPath, credID, token string, format outputFormat, timeouts ...time.Duration) error {
	if credID == "" || token == "" {
		return fmt.Errorf("lane list: --credential and --token (or GRIPLINE_OPERATOR_TOKEN) are required")
	}
	c, err := newAdminClientWithTimeout(cfgPath, firstCLITimeout(timeouts))
	if err != nil {
		return err
	}
	var rows []adminLaneSummary
	if err := c.request(http.MethodGet, "/admin/lanes?credential="+url.QueryEscape(credID), token, nil, &rows); err != nil {
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
	for _, row := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n", row.LaneID, row.State, row.Security, row.RiskScore, row.RequestCount, row.LastSeenAt.UTC().Format(time.RFC3339))
	}
	return w.Flush()
}

func runLaneUnblockLiveWithOperationIDAndOutput(cfgPath, credID, laneID, reason, token, operationID string, format outputFormat, timeouts ...time.Duration) error {
	if credID == "" || laneID == "" || reason == "" || token == "" {
		return fmt.Errorf("lane unblock: --credential, --id, --reason, and --token (or GRIPLINE_OPERATOR_TOKEN) are required")
	}
	c, err := newAdminClientWithTimeout(cfgPath, firstCLITimeout(timeouts))
	if err != nil {
		return err
	}
	if err := c.requestWithOperationID(http.MethodPost, "/admin/lanes/unblock", token, operationID, map[string]string{
		"credential_id": credID, "lane_id": laneID, "reason": reason,
	}, nil); err != nil {
		return fmt.Errorf("lane unblock: %w", err)
	}
	if format == outputJSON || format == outputJSONL {
		return encodeCLIOutput(format, map[string]string{"result": "unblocked", "credential_id": credID, "lane_id": laneID})
	}
	fmt.Printf("unblocked %s/%s (mutation + audit committed atomically)\n", credID, laneID)
	return nil
}
