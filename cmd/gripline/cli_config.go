package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/B-A-M-N/gripline/internal/config"
)

// runConfigCommandCLI owns the deployment-config inspection surface. It is
// intentionally local and read-only: policy artifacts and live crypto state
// have separate lifecycle commands and are not folded into this output.
func runConfigCommandCLI(_ *cliContext, args []string) error {
	return runConfigCLI(args)
}

func runConfigCLI(args []string) error {
	if len(args) == 0 || (args[0] != "validate" && args[0] != "effective") {
		return fmt.Errorf("config: expected validate or effective")
	}
	action := args[0]
	fs := newCLIFlagSet("config")
	cfgPath := fs.String("config", "/etc/gripline/config.json", "path to deployment configuration")
	_ = fs.Bool("redact", false, "redact all secret values (always enforced)")
	output := fs.String("output", "table", "table, json, or jsonl")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("config: unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	format, err := parseCLIOutput(*output)
	if err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("config %s: %w", action, err)
	}
	if action == "validate" {
		if format == outputJSON || format == outputJSONL {
			return encodeCLIOutput(format, map[string]any{"valid": true, "config": *cfgPath})
		}
		fmt.Printf("configuration valid: %s\n", *cfgPath)
		return nil
	}

	// Redaction is unconditional, even when --redact is omitted. There is no
	// supported unredacted effective-config mode because this command's output
	// is routinely copied into tickets and automation logs.
	return writeRedactedEffectiveConfig(cfg)
}

func writeRedactedEffectiveConfig(cfg *config.Config) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config effective: marshal: %w", err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("config effective: normalize: %w", err)
	}
	value = redactConfigValue(value, "")
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("config effective: write: %w", err)
	}
	return nil
}

func redactConfigValue(value any, parentKey string) any {
	switch typed := value.(type) {
	case map[string]any:
		if parentKey == "operator_tokens" {
			if len(typed) == 0 {
				return typed
			}
			return map[string]any{"<redacted>": "<redacted>"}
		}
		if parentKey == "pepper_versions" || parentKey == "pseudonym_keys" {
			out := make(map[string]any, len(typed))
			for key := range typed {
				out[key] = "<redacted>"
			}
			return out
		}
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			out[key] = redactConfigValue(child, key)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = redactConfigValue(child, parentKey)
		}
		return out
	case string:
		if parentKey == "token" || parentKey == "pseudonym_key" {
			return "<redacted>"
		}
		if parentKey == "pepper_versions" || parentKey == "pseudonym_keys" {
			return "<redacted>"
		}
		return typed
	default:
		return value
	}
}

// parseCLIGeneration enforces the same signed-32-bit generation domain as the
// config loader and the runtime rings. CLI output must not reintroduce a
// wider or platform-dependent integer interpretation.
func parseCLIGeneration(raw string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 32)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("generation must be a positive signed-32-bit decimal")
	}
	return int(n), nil
}
