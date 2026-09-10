package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"text/tabwriter"
	"time"
)

func encodeCLIOutput(format outputFormat, value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if format == outputJSON {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(value)
}

func parseCLIOutput(raw string) (outputFormat, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "", nil // compatibility calls historically emitted JSON
	}
	format := outputFormat(raw)
	if format != outputTable && format != outputJSON && format != outputJSONL {
		return "", fmt.Errorf("invalid output format %q (expected table, json, or jsonl)", raw)
	}
	return format, nil
}

func encodeRemoteStatus(format outputFormat, command string, status map[string]any) error {
	if format == "" || format == outputJSON || format == outputJSONL {
		return encodeCLIOutput(formatOrJSON(format), status)
	}
	if command == "crypto status" {
		return printCryptoStatusTable(status)
	}
	if command == "cluster status" {
		return printClusterStatusTable(status)
	}
	return encodeCLIOutput(outputJSON, status)
}

func formatOrJSON(format outputFormat) outputFormat {
	if format == "" {
		return outputJSON
	}
	return format
}

func formatOrJSONL(format outputFormat) outputFormat {
	if format == outputJSON {
		return outputJSON
	}
	return outputJSONL
}

func encodeCLIOutputRows(format outputFormat, rows any) error {
	if format == outputJSON {
		return encodeCLIOutput(outputJSON, rows)
	}
	value := reflect.ValueOf(rows)
	if value.Kind() != reflect.Slice && value.Kind() != reflect.Array {
		return encodeCLIOutput(outputJSONL, rows)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	for i := 0; i < value.Len(); i++ {
		if err := enc.Encode(value.Index(i).Interface()); err != nil {
			return err
		}
	}
	return nil
}

func printCryptoStatusTable(status map[string]any) error {
	crypto, _ := status["crypto"].(map[string]any)
	active := func(kind string) int {
		key := kind + "_active_version"
		if kind == "signer" {
			key = "signer_active_kid"
		}
		if value, ok := crypto[key].(float64); ok {
			return int(value)
		}
		return 0
	}
	generations, _ := crypto["generations"].([]any)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tGENERATION\tSTATE\tACKS\tACTIVE\tRETIRE_AFTER\tUPDATED")
	for _, raw := range generations {
		generation, _ := raw.(map[string]any)
		kind, _ := generation["kind"].(string)
		gen, _ := generation["generation"].(float64)
		state, _ := generation["state"].(string)
		acks, _ := generation["acknowledged_nodes"].(float64)
		updated, _ := generation["updated_at"].(string)
		retireAfter, _ := generation["retire_after"].(string)
		activeText := "no"
		if int(gen) == active(kind) {
			activeText = "yes"
		}
		if len(updated) > 16 {
			updated = updated[11:16]
		}
		retireText := "-"
		if activeText == "yes" {
			retireText = "active"
		} else if retireAfter != "" {
			if safeAfter, parseErr := time.Parse(time.RFC3339, retireAfter); parseErr == nil {
				if !time.Now().Before(safeAfter) {
					retireText = "ready"
				} else {
					retireText = safeAfter.UTC().Format("15:04:05Z")
				}
			} else {
				retireText = retireAfter
			}
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%s\t%s\t%s\n", kind, int(gen), state, int(acks), activeText, retireText, updated)
	}
	return w.Flush()
}

func printClusterStatusTable(status map[string]any) error {
	behavior, _ := status["behavior"].(map[string]any)
	authoritative, _ := behavior["authoritative_digest"].(string)
	local, _ := behavior["local_digest"].(string)
	match, _ := behavior["match"].(bool)
	fmt.Printf("CLUSTER_BEHAVIOR\tMATCH=%t\tLOCAL=%s\tAUTHORITATIVE=%s\n", match, local, authoritative)
	aliases, _ := status["source_aliases"].(map[string]any)
	capacity, _ := aliases["capacity"].(float64)
	identities, _ := aliases["canonical_identities"].(float64)
	rowsCount, _ := aliases["rows"].(float64)
	fmt.Printf("SOURCE_ALIASES\tCAPACITY=%d\tIDENTITIES=%d\tROWS=%d\n", int(capacity), int(identities), int(rowsCount))
	nodes, _ := status["nodes"].([]any)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTATE\tLIVE\tLOCAL\tLAST_SEEN")
	for _, raw := range nodes {
		node, _ := raw.(map[string]any)
		id, _ := node["node_id"].(string)
		state, _ := node["state"].(string)
		live, _ := node["live"].(bool)
		local, _ := node["local"].(bool)
		seen, _ := node["last_seen_at"].(string)
		fmt.Fprintf(w, "%s\t%s\t%t\t%t\t%s\n", id, state, live, local, seen)
	}
	return w.Flush()
}

func printPolicyStatusTable(status map[string]any) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SLOT\tID\tREVISION\tDIGEST\tACTIVATION_EPOCH")
	for _, slot := range []string{"active", "candidate"} {
		value, ok := status[slot].(map[string]any)
		if !ok || value == nil {
			fmt.Fprintf(w, "%s\t-\t-\t-\t-\n", slot)
			continue
		}
		id, _ := value["id"].(string)
		revision, _ := value["revision"].(float64)
		digest, _ := value["digest"].(string)
		epoch, _ := value["activation_epoch"].(float64)
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%d\n", slot, id, int(revision), digest, int(epoch))
	}
	return w.Flush()
}
