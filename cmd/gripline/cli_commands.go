package main

// The operator CLI has one small, declarative front door. The existing
// run*CLI functions remain the compatibility implementation behind it while
// this file owns the human-facing grammar, persistent options, help, and
// normalization. Keeping that boundary explicit lets old automation continue
// to work while new invocations describe intent instead of HTTP/storage
// protocol details.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
)

type cliExitError struct{ Code int }

func (e *cliExitError) Error() string { return fmt.Sprintf("cli exited with status %d", e.Code) }

type cliUserError struct{ Message string }

func (e *cliUserError) Error() string { return e.Message }

type outputFormat string

const (
	outputTable outputFormat = "table"
	outputJSON  outputFormat = "json"
	outputJSONL outputFormat = "jsonl"
)

type cliContext struct {
	ConfigPath string
	Token      string
	TokenFile  string
	Output     outputFormat
	Timeout    time.Duration

	configExplicit bool
	tokenExplicit  bool
	fileExplicit   bool
}

type cliCommand struct {
	Name     string
	Summary  string
	Usage    string
	Examples []string
	Default  string
	Options  []cliOption
	Children []*cliCommand
	Run      func(*cliContext, []string) error
}

type cliOption struct {
	Name     string
	Value    string
	Summary  string
	Advanced bool
}

var cliRoot = &cliCommand{
	Name:    "gripline",
	Summary: "credential containment gateway",
	Usage:   "gripline [global options] <command> [arguments]",
	Children: []*cliCommand{
		{Name: "serve", Summary: "run the gateway", Usage: "gripline serve", Run: runServeCLI},
		{Name: "config", Summary: "validate or inspect deployment configuration", Usage: "gripline config <validate|effective>", Default: "validate", Run: runConfigCommandCLI, Children: []*cliCommand{
			{Name: "validate", Summary: "validate deployment configuration", Options: []cliOption{{Name: "--config PATH", Summary: "deployment configuration to validate"}}},
			{Name: "effective", Summary: "print normalized configuration with secrets redacted", Options: []cliOption{{Name: "--config PATH", Summary: "deployment configuration to inspect"}, {Name: "--redact", Summary: "replace every secret value with <redacted> (default and only supported mode)"}}},
		}},
		{Name: "status", Summary: "show configured capability and persistence posture", Usage: "gripline status", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}}, Run: runStatusCommandCLI},
		{Name: "credential", Summary: "manage credentials", Usage: "gripline credential <list|add|revoke|pepper-status>", Default: "list", Run: runCredentialCommandCLI, Children: []*cliCommand{
			{Name: "list", Summary: "list credentials", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--offline", Summary: "read stopped standalone state without the admin listener"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			{Name: "add", Summary: "add a credential from stdin, a file, or a secure prompt", Usage: "gripline credential add <id> --account <account> -r <reason>", Options: []cliOption{
				{Name: "--account ACCOUNT", Summary: "account identifier (required)"},
				{Name: "--secret-file PATH", Summary: "read the credential from a file; stdin and secure terminal input are also supported"},
				{Name: "--policy ID", Summary: "policy override; defaults to the active policy"},
				{Name: "--plan ID", Summary: "plan identifier"},
				{Name: "-r, --reason TEXT", Summary: "audited operator reason (required)"},
				{Name: "--offline", Summary: "use stopped standalone maintenance mode"},
				{Name: "--token-file PATH", Summary: "read the operator token from this file"},
				{Name: "--operation-id ID", Summary: "idempotent retry key within the authority retention window", Advanced: true},
				{Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true},
			}},
			{Name: "revoke", Summary: "revoke a credential", Usage: "gripline credential revoke <id> -r <reason>", Options: []cliOption{
				{Name: "-r, --reason TEXT", Summary: "audited operator reason (required)"},
				{Name: "--offline", Summary: "use stopped standalone maintenance mode"},
				{Name: "--token-file PATH", Summary: "read the operator token from this file"},
				{Name: "--operation-id ID", Summary: "idempotent retry key within the authority retention window", Advanced: true},
				{Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true},
			}},
			{Name: "pepper-status", Summary: "show credential counts by pepper generation", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
		}},
		{Name: "lane", Summary: "inspect and manage lanes", Usage: "gripline lane <list|unblock>", Run: runLaneCommandCLI, Children: []*cliCommand{
			{Name: "list", Summary: "list lanes for a credential", Usage: "gripline lane list <credential>", Options: []cliOption{{Name: "--credential ID", Summary: "credential identifier (required)"}, {Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			{Name: "unblock", Summary: "unblock a lane", Usage: "gripline lane unblock <credential> <lane> -r <reason>", Options: []cliOption{{Name: "--credential ID", Summary: "credential identifier (required)"}, {Name: "--id LANE", Summary: "lane identifier (required)"}, {Name: "-r, --reason TEXT", Summary: "audited operator reason (required)"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--operation-id ID", Summary: "idempotent retry key within the authority retention window", Advanced: true}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
		}},
		{Name: "policy", Summary: "manage policy lifecycle", Usage: "gripline policy [status|verify|prepare|activate|rollback]", Default: "status", Run: runPolicyCommandCLI, Children: []*cliCommand{
			{Name: "status", Summary: "show the active and candidate policy", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			{Name: "verify", Summary: "verify the configured policy", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
			{Name: "prepare", Summary: "prepare a signed policy artifact", Options: []cliOption{{Name: "--file PATH", Summary: "signed policy envelope"}, {Name: "-r, --reason TEXT", Summary: "audited operator reason (required)"}, {Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--operation-id ID", Summary: "idempotent retry key within the authority retention window", Advanced: true}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			{Name: "activate", Summary: "activate the prepared policy", Options: []cliOption{{Name: "-r, --reason TEXT", Summary: "audited operator reason (required)"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--operation-id ID", Summary: "idempotent retry key within the authority retention window", Advanced: true}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			{Name: "rollback", Summary: "roll back to a known-good revision", Usage: "gripline policy rollback <revision> -r <reason>", Options: []cliOption{{Name: "--revision N", Summary: "known-good policy revision"}, {Name: "-r, --reason TEXT", Summary: "audited operator reason (required)"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--operation-id ID", Summary: "idempotent retry key within the authority retention window", Advanced: true}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
		}},
		{Name: "crypto", Summary: "manage cryptographic generations", Usage: "gripline crypto [status|prepare|activate|retire]", Examples: []string{"gripline crypto prepare signer --offline", "gripline crypto activate signer 4 -r \"quarterly rotation\"", "gripline crypto retire signer 3 -r \"overlap complete\""}, Default: "status", Run: runCryptoCommandCLI, Children: []*cliCommand{
			{Name: "status", Summary: "show synchronized generations", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			{Name: "prepare", Summary: "prepare a signer generation while offline", Usage: "gripline crypto prepare signer --offline", Options: []cliOption{{Name: "--offline", Summary: "confirm serving is stopped"}, {Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
			{Name: "activate", Summary: "activate a loaded generation", Usage: "gripline crypto activate <signer|pepper|pseudonym> <generation> -r <reason>", Options: []cliOption{
				{Name: "-r, --reason TEXT", Summary: "audited operator reason (required)"},
				{Name: "--token-file PATH", Summary: "read the operator token from this file"},
				{Name: "--operation-id ID", Summary: "idempotent retry key within the authority retention window", Advanced: true},
				{Name: "--fingerprint FP", Summary: "optional; resolved from authoritative status"},
			}},
			{Name: "retire", Summary: "retire a safe generation", Usage: "gripline crypto retire <signer|pepper|pseudonym> <generation> -r <reason>", Options: []cliOption{
				{Name: "-r, --reason TEXT", Summary: "audited operator reason (required)"},
				{Name: "--token-file PATH", Summary: "read the operator token from this file"},
				{Name: "--operation-id ID", Summary: "idempotent retry key within the authority retention window", Advanced: true},
				{Name: "--not-before RFC3339", Summary: "additional lower bound; authority horizon still wins", Advanced: true},
			}},
		}},
		{Name: "audit", Summary: "view security and operator history", Usage: "gripline audit [list|export|security]", Default: "list", Run: runAuditCommandCLI, Children: []*cliCommand{
			{Name: "list", Summary: "list operator history", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			{Name: "export", Summary: "export operator history as JSONL", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			{Name: "security", Summary: "view security transitions", Usage: "gripline audit security [list|export]", Default: "list", Children: []*cliCommand{
				{Name: "list", Summary: "list security transitions", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
				{Name: "export", Summary: "export security transitions as JSONL", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			}},
		}},
		{Name: "state", Summary: "maintain stopped standalone state", Usage: "gripline state [check|backup|restore|compact]", Default: "check", Run: runStateCommandCLI, Children: []*cliCommand{
			{Name: "check", Summary: "check the local state file", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
			{Name: "backup", Summary: "create a backup of a stopped standalone authority", Options: []cliOption{{Name: "--out PATH", Summary: "backup output path"}, {Name: "--manifest PATH", Summary: "recovery manifest path"}, {Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
			{Name: "restore", Summary: "restore into a stopped standalone authority", Options: []cliOption{{Name: "--from PATH", Summary: "backup input path"}, {Name: "--manifest PATH", Summary: "recovery manifest path"}, {Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
			{Name: "compact", Summary: "compact a stopped standalone authority", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
		}},
		{Name: "migrate", Summary: "inspect or migrate PostgreSQL schema", Usage: "gripline migrate [plan|apply]", Default: "plan", Run: runMigrateCommandCLI, Children: []*cliCommand{
			{Name: "plan", Summary: "inspect schema compatibility", Options: []cliOption{{Name: "--timeout DURATION", Summary: "maximum schema inspection time"}, {Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
			{Name: "apply", Summary: "migrate PostgreSQL while serving nodes are stopped", Options: []cliOption{{Name: "--timeout DURATION", Summary: "maximum migration time"}, {Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
		}},
		{Name: "cluster", Summary: "show status or manage shared behavior", Usage: "gripline cluster [status|behavior]", Default: "status", Run: runClusterCommandCLI, Children: []*cliCommand{
			{Name: "status", Summary: "show nodes and shared authority state", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}, {Name: "--token TOKEN", Summary: "legacy bearer token; visible in shell history", Advanced: true}}},
			{Name: "behavior", Summary: "plan or apply an explicit shared behavior transition", Usage: "gripline cluster behavior <plan|apply>", Default: "plan", Children: []*cliCommand{
				{Name: "plan", Summary: "compare configured behavior with the authority", Options: []cliOption{{Name: "--timeout DURATION", Summary: "maximum database operation time"}, {Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
				{Name: "apply", Summary: "apply a quiescent compare-and-swap behavior update", Options: []cliOption{{Name: "--expected-current-digest DIGEST", Summary: "authority digest required for compare-and-swap (or none)"}, {Name: "-r, --reason TEXT", Summary: "audited operator reason (required)"}, {Name: "--actor ID", Summary: "operator identity for the audit record"}, {Name: "--timeout DURATION", Summary: "maximum database operation time"}, {Name: "--output FORMAT", Summary: "table, json, or jsonl"}}},
			}},
		}},
		{Name: "keys", Summary: "export backend verification keys", Usage: "gripline keys [export]", Default: "export", Run: runKeysCommandCLI, Children: []*cliCommand{
			{Name: "export", Summary: "export public verification material (JSON only)", Options: []cliOption{{Name: "output", Summary: "fixed JSON artifact; global output formats do not apply"}}},
		}},
		{Name: "doctor", Summary: "check deployment health", Usage: "gripline doctor", Options: []cliOption{{Name: "--output FORMAT", Summary: "table, json, or jsonl"}, {Name: "--token-file PATH", Summary: "read the operator token from this file"}}, Run: runDoctorCommandCLI},
		{Name: "version", Summary: "show build information", Usage: "gripline version", Run: runVersionCommandCLI},
	},
}

func defaultCLIContext() cliContext {
	configPath := strings.TrimSpace(os.Getenv("GRIPLINE_CONFIG"))
	if configPath == "" {
		configPath = "/etc/gripline/config.json"
	}
	return cliContext{
		ConfigPath: configPath,
		Token:      os.Getenv("GRIPLINE_OPERATOR_TOKEN"),
		TokenFile:  os.Getenv("GRIPLINE_OPERATOR_TOKEN_FILE"),
		Output:     outputTable,
		Timeout:    30 * time.Second,
	}
}

// parseGlobalCLI accepts persistent options before or after the command. It
// intentionally does not use flag.FlagSet: Go's standard parser stops at the
// first positional token, which makes conventional `gripline -c x status`
// and `gripline status -c x` disagree.
func parseGlobalCLI(args []string) (cliContext, []string, bool, error) {
	ctx := defaultCLIContext()
	var rest []string
	help := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		if arg == "-h" || arg == "--help" {
			help = true
			continue
		}
		name, value, hasValue := strings.Cut(arg, "=")
		consume := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", name)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "-c", "--config", "-config":
			v, err := consume()
			if err != nil {
				return ctx, nil, false, err
			}
			ctx.ConfigPath, ctx.configExplicit = v, true
		case "--token":
			v, err := consume()
			if err != nil {
				return ctx, nil, false, err
			}
			ctx.Token, ctx.tokenExplicit = v, true
		case "--token-file":
			v, err := consume()
			if err != nil {
				return ctx, nil, false, err
			}
			ctx.TokenFile, ctx.fileExplicit = v, true
		case "-o", "--output":
			v, err := consume()
			if err != nil {
				return ctx, nil, false, err
			}
			ctx.Output = outputFormat(strings.ToLower(strings.TrimSpace(v)))
			if ctx.Output != outputTable && ctx.Output != outputJSON && ctx.Output != outputJSONL {
				return ctx, nil, false, fmt.Errorf("invalid output format %q (expected table, json, or jsonl)", v)
			}
		case "--request-timeout":
			v, err := consume()
			if err != nil {
				return ctx, nil, false, err
			}
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return ctx, nil, false, fmt.Errorf("--request-timeout must be a positive duration: %q", v)
			}
			ctx.Timeout = d
		case "--version", "-version":
			fmt.Println(versionString())
			return ctx, nil, true, errSubcommand
		default:
			rest = append(rest, arg)
		}
	}
	return ctx, rest, help, nil
}

func runCLIInvocation(args []string) (bool, string, error) {
	ctx, rest, help, err := parseGlobalCLI(args)
	if errors.Is(err, errSubcommand) {
		return false, ctx.ConfigPath, nil
	}
	if err != nil {
		return false, ctx.ConfigPath, &cliUserError{Message: err.Error()}
	}
	if len(rest) == 0 {
		if help {
			printCLIHelp(nil)
			return false, ctx.ConfigPath, nil
		}
		return true, ctx.ConfigPath, nil
	}

	rootName := rest[0]
	if rootName == "serve" {
		if help {
			printCLIHelp([]string{"serve"})
			return false, ctx.ConfigPath, nil
		}
		if len(rest) != 1 {
			return false, ctx.ConfigPath, fmt.Errorf("serve does not accept command arguments; use `gripline serve --help`")
		}
		return true, ctx.ConfigPath, nil
	}
	command := findCLICommand([]string{rootName})
	if command == nil {
		return false, ctx.ConfigPath, &cliUserError{Message: unknownCLICommand(rootName).Error()}
	}
	if help {
		path, helpErr := resolveCLIHelpPath(rest)
		printCLIHelp(path)
		if helpErr != nil {
			return false, ctx.ConfigPath, &cliUserError{Message: helpErr.Error()}
		}
		return false, ctx.ConfigPath, nil
	}
	commandArgs, err := normalizeCLIArgs(rootName, rest[1:], ctx.ConfigPath)
	if err != nil {
		return false, ctx.ConfigPath, err
	}
	if rootName == "status" {
		if len(commandArgs) != 0 {
			return false, ctx.ConfigPath, fmt.Errorf("status does not accept positional arguments")
		}
		if command.Run == nil {
			return false, ctx.ConfigPath, errors.New("status command is not configured")
		}
		return false, ctx.ConfigPath, command.Run(&ctx, nil)
	}
	if rootName == "doctor" {
		return false, ctx.ConfigPath, command.Run(&ctx, nil)
	}
	if rootName == "version" {
		return false, ctx.ConfigPath, command.Run(&ctx, commandArgs)
	}
	if rootName == "keys" {
		err := command.Run(&ctx, commandArgs)
		if errors.Is(err, errSubcommand) {
			return false, ctx.ConfigPath, nil
		}
		return false, ctx.ConfigPath, err
	}
	commandArgs = appendCLIContextArgs(ctx, commandArgs)
	if command.Run == nil {
		return false, ctx.ConfigPath, fmt.Errorf("%s command is not configured", rootName)
	}
	err = command.Run(&ctx, commandArgs)
	if errors.Is(err, errSubcommand) {
		return false, ctx.ConfigPath, nil
	}
	if isCLIFlagParseError(err) {
		path, _ := resolveCLIHelpPath(rest)
		usage := "gripline " + strings.Join(path, " ")
		if command.Usage != "" {
			usage = command.Usage
		}
		return false, ctx.ConfigPath, &cliUserError{Message: fmt.Sprintf("%s\nUsage:\n  %s", err, usage)}
	}
	return false, ctx.ConfigPath, err
}

func isCLIFlagParseError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "flag provided but not defined") ||
		strings.Contains(message, "flag needs an argument") ||
		strings.Contains(message, "invalid value")
}

func appendCLIContextArgs(ctx cliContext, args []string) []string {
	out := append([]string(nil), args...)
	if !hasCLIFlag(out, "config") {
		out = append(out, "--config", ctx.ConfigPath)
	}
	if ctx.tokenExplicit && !hasCLIFlag(out, "token") {
		out = append(out, "--token", ctx.Token)
	} else if ctx.fileExplicit && !hasCLIFlag(out, "token-file") {
		out = append(out, "--token-file", ctx.TokenFile)
	}
	// Every compatibility handler accepts this option. Supplying the default
	// explicitly lets the new front door have a stable default without changing
	// direct calls used by older integrations and tests.
	out = append(out, "--output", string(ctx.Output))
	out = append(out, "--request-timeout", ctx.Timeout.String())
	return out
}

func normalizeCLIArgs(root string, args []string, configPaths ...string) ([]string, error) {
	out := append([]string(nil), args...)
	if len(out) == 0 || strings.HasPrefix(out[0], "-") {
		if command := findCLICommand([]string{root}); command != nil && command.Default != "" {
			out = append([]string{command.Default}, out...)
		}
	}
	if root == "audit" && len(out) == 1 && out[0] == "security" {
		out = append(out, "list")
	}
	if root == "crypto" {
		if len(out) >= 2 && out[0] == "prepare" && out[1] == "signer" {
			out = append([]string{"signer-prepare"}, out[2:]...)
		} else if len(out) >= 2 && out[0] == "signer" && out[1] == "prepare" {
			out = append([]string{"signer-prepare"}, out[2:]...)
		}
	}
	out = normalizeReasonFlag(out)
	switch root {
	case "credential":
		if len(out) > 1 && (out[0] == "add" || out[0] == "revoke") && !strings.HasPrefix(out[1], "-") && !hasCLIFlag(out[1:], "id") {
			out = append([]string{out[0], "--id", out[1]}, out[2:]...)
		}
	case "lane":
		if len(out) > 1 && out[0] == "list" && !strings.HasPrefix(out[1], "-") && !hasCLIFlag(out[1:], "credential") {
			out = append([]string{out[0], "--credential", out[1]}, out[2:]...)
		}
		if len(out) > 2 && out[0] == "unblock" && !strings.HasPrefix(out[1], "-") && !strings.HasPrefix(out[2], "-") && !hasCLIFlag(out[1:], "credential") && !hasCLIFlag(out[2:], "id") {
			out = append([]string{out[0], "--credential", out[1], "--id", out[2]}, out[3:]...)
		}
	case "policy":
		if len(out) > 1 && out[0] == "rollback" && !strings.HasPrefix(out[1], "-") && !hasCLIFlag(out[1:], "revision") {
			out = append([]string{out[0], "--revision", out[1]}, out[2:]...)
		}
		if len(out) > 1 && out[0] == "prepare" && !strings.HasPrefix(out[1], "-") && !hasCLIFlag(out[1:], "file") {
			out = append([]string{out[0], "--file", out[1]}, out[2:]...)
		}
	case "crypto":
		if len(out) > 2 && (out[0] == "activate" || out[0] == "retire") && !strings.HasPrefix(out[1], "-") && !strings.HasPrefix(out[2], "-") && !hasCLIFlag(out[1:], "kind") && !hasCLIFlag(out[2:], "generation") {
			out = append([]string{out[0], "--kind", out[1], "--generation", out[2]}, out[3:]...)
		}
	case "state":
		if len(out) > 1 && out[0] == "backup" && !strings.HasPrefix(out[1], "-") && !hasCLIFlag(out[1:], "out") {
			out = append([]string{out[0], "--out", out[1]}, out[2:]...)
		}
		if len(out) > 1 && out[0] == "restore" && !strings.HasPrefix(out[1], "-") && !hasCLIFlag(out[1:], "from") {
			out = append([]string{out[0], "--from", out[1]}, out[2:]...)
		}
	}
	autoOperationID := len(configPaths) == 0
	if len(configPaths) > 0 {
		if cfg, configErr := config.Load(configPaths[0]); configErr == nil {
			autoOperationID = strings.EqualFold(strings.TrimSpace(cfg.Authority.Backend), "postgres")
		}
	}
	if autoOperationID && isCLIMutation(root, out) && !hasCLIFlag(out, "operation-id") && !hasCLIFlag(out, "offline") {
		op, err := newOperationID("")
		if err != nil {
			return nil, err
		}
		out = append(out, "--operation-id", op)
	}
	return out, nil
}

func normalizeReasonFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "-r" {
			out = append(out, "--reason")
		} else if strings.HasPrefix(arg, "-r=") {
			out = append(out, "--reason="+strings.TrimPrefix(arg, "-r="))
		} else {
			out = append(out, arg)
		}
	}
	return out
}

func isCLIMutation(root string, args []string) bool {
	if len(args) == 0 {
		return false
	}
	action := args[0]
	switch root {
	case "credential":
		return action == "add" || action == "revoke"
	case "lane":
		return action == "unblock"
	case "policy":
		return action == "prepare" || action == "activate" || action == "rollback"
	case "crypto":
		return action == "activate" || action == "retire"
	default:
		return false
	}
}

func hasCLIFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == "--"+name || strings.HasPrefix(arg, "--"+name+"=") {
			return true
		}
	}
	return false
}

func newOperationID(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), nil
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate operation ID: %w", err)
	}
	return "op_" + hex.EncodeToString(raw[:]), nil
}

func findCLICommand(path []string) *cliCommand {
	current := cliRoot
	for _, name := range path {
		var found *cliCommand
		for _, child := range current.Children {
			if child.Name == name {
				found = child
				break
			}
		}
		if found == nil {
			return nil
		}
		current = found
	}
	return current
}

func resolveCLIHelpPath(args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, nil
	}
	// These spellings are normalized to the signer-prepare implementation for
	// execution. Resolve them to the canonical metadata node for help too, so
	// a compatibility alias never becomes a dead end for operators.
	if len(args) >= 3 && args[0] == "crypto" &&
		((args[1] == "prepare" && args[2] == "signer") || (args[1] == "signer" && args[2] == "prepare")) {
		return []string{"crypto", "prepare"}, nil
	}
	path := []string{args[0]}
	current := findCLICommand(path)
	if current == nil {
		return path, unknownCLICommand(args[0])
	}
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, "-") {
			break
		}
		var child *cliCommand
		for _, candidate := range current.Children {
			if candidate.Name == arg {
				child = candidate
				break
			}
		}
		if child == nil {
			return path, fmt.Errorf("unknown subcommand %q under %s", arg, strings.Join(path, " "))
		}
		path = append(path, arg)
		current = child
	}
	return path, nil
}

func unknownCLICommand(name string) error {
	valid := make([]string, 0, len(cliRoot.Children))
	for _, command := range cliRoot.Children {
		valid = append(valid, command.Name)
	}
	return fmt.Errorf("unknown command %q (expected one of: %s); run `gripline --help`", name, strings.Join(valid, ", "))
}

func printCLIHelp(path []string) {
	command := cliRoot
	if len(path) > 0 {
		if found := findCLICommand(path); found != nil {
			command = found
		}
	}
	if len(path) == 0 {
		fmt.Printf("Gripline — %s\n\nUsage:\n  %s\n\nCommands:\n", cliRoot.Summary, cliRoot.Usage)
		for _, child := range cliRoot.Children {
			fmt.Printf("  %-12s %s\n", child.Name, child.Summary)
		}
		fmt.Print("\nGlobal options:\n  -c, --config PATH       deployment configuration (env GRIPLINE_CONFIG)\n      --token-file PATH   operator token file (env GRIPLINE_OPERATOR_TOKEN_FILE)\n  -o, --output FORMAT     table, json, or jsonl (default table)\n      --request-timeout DURATION\n                           admin request timeout (default 30s)\n\nAdvanced global options:\n      --token TOKEN       legacy bearer token; visible in shell history\n\nRun 'gripline <command> --help' for details.\n")
		return
	}
	usage := command.Usage
	if usage == "" {
		usage = "gripline " + strings.Join(path, " ")
	}
	fmt.Printf("%s — %s\n\nUsage:\n  %s\n", strings.Join(path, " "), command.Summary, usage)
	if len(command.Children) > 0 {
		fmt.Print("\nCommands:\n")
		for _, child := range command.Children {
			fmt.Printf("  %-14s %s\n", child.Name, child.Summary)
		}
	}
	if len(command.Examples) > 0 {
		fmt.Print("\nExamples:\n")
		for _, example := range command.Examples {
			fmt.Printf("  %s\n", example)
		}
	}
	if len(command.Options) > 0 {
		fmt.Print("\nOptions:\n")
		for _, option := range command.Options {
			if !option.Advanced {
				fmt.Printf("  %-24s %s\n", option.Name, option.Summary)
			}
		}
		advanced := false
		for _, option := range command.Options {
			if option.Advanced {
				if !advanced {
					fmt.Print("\nAdvanced options:\n")
					advanced = true
				}
				fmt.Printf("  %-24s %s\n", option.Name, option.Summary)
			}
		}
	}
	if command.Default != "" {
		fmt.Printf("\nWith no subcommand, runs: %s\n", command.Default)
	}
}

func runServeCLI(_ *cliContext, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("serve does not accept positional arguments")
	}
	return nil
}

func runStatusCommandCLI(ctx *cliContext, _ []string) error {
	return runStatusCLIWithOutput(ctx.ConfigPath, ctx.Output)
}

func runCredentialCommandCLI(_ *cliContext, args []string) error { return runCredentialCLI(args) }
func runLaneCommandCLI(_ *cliContext, args []string) error       { return runLaneCLI(args) }
func runPolicyCommandCLI(_ *cliContext, args []string) error     { return runPolicyCLI(args) }
func runCryptoCommandCLI(ctx *cliContext, args []string) error {
	return runCryptoCLIWithContext(ctx, args)
}
func runAuditCommandCLI(_ *cliContext, args []string) error   { return runAuditCLI(args) }
func runStateCommandCLI(_ *cliContext, args []string) error   { return runStateCLI(args) }
func runMigrateCommandCLI(_ *cliContext, args []string) error { return runMigrateCLI(args) }
func runClusterCommandCLI(_ *cliContext, args []string) error { return runClusterCLI(args) }

func runKeysCommandCLI(ctx *cliContext, args []string) error {
	if len(args) != 0 && (len(args) != 1 || args[0] != "export") {
		return fmt.Errorf("keys: expected export")
	}
	return runKeysExport(ctx.ConfigPath)
}

func runVersionCommandCLI(_ *cliContext, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("version does not accept arguments")
	}
	fmt.Println(versionString())
	return nil
}
