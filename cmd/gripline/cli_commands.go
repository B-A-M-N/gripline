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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
)

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
	Children []*cliCommand
	Run      func(*cliContext, []string) error
}

var cliRoot = &cliCommand{
	Name:    "gripline",
	Summary: "credential containment gateway",
	Usage:   "gripline [global options] <command> [arguments]",
	Children: []*cliCommand{
		{Name: "serve", Summary: "run the gateway", Usage: "gripline serve", Run: runServeCLI},
		{Name: "status", Summary: "show deployment and runtime status", Usage: "gripline status", Run: runStatusCommandCLI},
		{Name: "credential", Summary: "manage credentials", Usage: "gripline credential <list|add|revoke|pepper-status>", Default: "list", Run: runCredentialCommandCLI, Children: []*cliCommand{
			{Name: "list", Summary: "list credentials"},
			{Name: "add", Summary: "add a credential from stdin, a file, or a secure prompt", Usage: "gripline credential add <id> --account <account> -r <reason>"},
			{Name: "revoke", Summary: "revoke a credential", Usage: "gripline credential revoke <id> -r <reason>"},
			{Name: "pepper-status", Summary: "show credential counts by pepper generation"},
		}},
		{Name: "lane", Summary: "inspect and manage lanes", Usage: "gripline lane <list|unblock>", Run: runLaneCommandCLI, Children: []*cliCommand{
			{Name: "list", Summary: "list lanes for a credential", Usage: "gripline lane list <credential>"},
			{Name: "unblock", Summary: "unblock a lane", Usage: "gripline lane unblock <credential> <lane> -r <reason>"},
		}},
		{Name: "policy", Summary: "manage policy lifecycle", Usage: "gripline policy [status|verify|prepare|activate|rollback]", Default: "status", Run: runPolicyCommandCLI, Children: []*cliCommand{
			{Name: "status", Summary: "show the active and candidate policy"},
			{Name: "verify", Summary: "verify the configured policy"},
			{Name: "prepare", Summary: "prepare a signed policy artifact"},
			{Name: "activate", Summary: "activate the prepared policy"},
			{Name: "rollback", Summary: "roll back to a known-good revision", Usage: "gripline policy rollback <revision> -r <reason>"},
		}},
		{Name: "crypto", Summary: "manage cryptographic generations", Usage: "gripline crypto [status|prepare|activate|retire]", Examples: []string{"gripline crypto prepare signer --offline", "gripline crypto activate signer 4 -r \"quarterly rotation\"", "gripline crypto retire signer 3 -r \"overlap complete\""}, Default: "status", Run: runCryptoCommandCLI, Children: []*cliCommand{
			{Name: "status", Summary: "show synchronized generations"},
			{Name: "prepare", Summary: "prepare a signer generation while offline", Usage: "gripline crypto prepare signer --offline"},
			{Name: "activate", Summary: "activate a loaded generation", Usage: "gripline crypto activate <signer|pepper|pseudonym> <generation> -r <reason>"},
			{Name: "retire", Summary: "retire a safe generation", Usage: "gripline crypto retire <signer|pepper|pseudonym> <generation> -r <reason>"},
		}},
		{Name: "audit", Summary: "view security and operator history", Usage: "gripline audit [list|export|security]", Default: "list", Run: runAuditCommandCLI, Children: []*cliCommand{
			{Name: "list", Summary: "list operator history"},
			{Name: "export", Summary: "export operator history as JSONL"},
			{Name: "security", Summary: "view security transitions", Default: "list"},
		}},
		{Name: "state", Summary: "maintain standalone state", Usage: "gripline state [check|backup|restore|compact]", Default: "check", Run: runStateCommandCLI, Children: []*cliCommand{
			{Name: "check", Summary: "check the local state file"},
			{Name: "backup", Summary: "create a verified state backup"},
			{Name: "restore", Summary: "restore a verified state backup"},
			{Name: "compact", Summary: "compact and verify the state file"},
		}},
		{Name: "migrate", Summary: "inspect or migrate PostgreSQL schema", Usage: "gripline migrate [plan|apply]", Default: "plan", Run: runMigrateCommandCLI, Children: []*cliCommand{
			{Name: "plan", Summary: "inspect schema compatibility"},
			{Name: "apply", Summary: "apply the schema migration"},
		}},
		{Name: "cluster", Summary: "show shared membership status", Usage: "gripline cluster [status]", Default: "status", Run: runClusterCommandCLI, Children: []*cliCommand{
			{Name: "status", Summary: "show nodes and shared authority state"},
		}},
		{Name: "keys", Summary: "export backend verification keys", Usage: "gripline keys [export]", Default: "export", Run: runKeysCommandCLI, Children: []*cliCommand{
			{Name: "export", Summary: "export public verification material"},
		}},
		{Name: "doctor", Summary: "check deployment health", Usage: "gripline doctor", Run: runDoctorCommandCLI},
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
		case "-c", "--config":
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
		case "--timeout":
			v, err := consume()
			if err != nil {
				return ctx, nil, false, err
			}
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return ctx, nil, false, fmt.Errorf("--timeout must be a positive duration: %q", v)
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
		return false, ctx.ConfigPath, err
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
		return false, ctx.ConfigPath, unknownCLICommand(rootName)
	}
	if help {
		path := []string{rootName}
		if command.Children != nil && len(rest) > 1 && !strings.HasPrefix(rest[1], "-") {
			path = append(path, rest[1])
		}
		printCLIHelp(path)
		return false, ctx.ConfigPath, nil
	}
	commandArgs, err := normalizeCLIArgs(rootName, rest[1:])
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
		return false, ctx.ConfigPath, command.Run(&ctx, commandArgs)
	}
	commandArgs = appendCLIContextArgs(ctx, commandArgs)
	if command.Run == nil {
		return false, ctx.ConfigPath, fmt.Errorf("%s command is not configured", rootName)
	}
	oldTimeout, hadTimeout := os.LookupEnv("GRIPLINE_CLI_TIMEOUT")
	_ = os.Setenv("GRIPLINE_CLI_TIMEOUT", ctx.Timeout.String())
	defer func() {
		if hadTimeout {
			_ = os.Setenv("GRIPLINE_CLI_TIMEOUT", oldTimeout)
		} else {
			_ = os.Unsetenv("GRIPLINE_CLI_TIMEOUT")
		}
	}()
	err = command.Run(&ctx, commandArgs)
	if errors.Is(err, errSubcommand) {
		return false, ctx.ConfigPath, nil
	}
	return false, ctx.ConfigPath, err
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
	return out
}

func normalizeCLIArgs(root string, args []string) ([]string, error) {
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
	if isCLIMutation(root, out) && !hasCLIFlag(out, "operation-id") && !hasCLIFlag(out, "offline") {
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
		fmt.Print("\nGlobal options:\n  -c, --config PATH       deployment configuration (env GRIPLINE_CONFIG)\n      --token TOKEN       operator token (env GRIPLINE_OPERATOR_TOKEN)\n      --token-file PATH   operator token file (env GRIPLINE_OPERATOR_TOKEN_FILE)\n  -o, --output FORMAT     table, json, or jsonl (default table)\n      --timeout DURATION  admin request timeout (default 30s)\n\nRun 'gripline <command> --help' for details.\n")
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
func runCryptoCommandCLI(_ *cliContext, args []string) error     { return runCryptoCLI(args) }
func runAuditCommandCLI(_ *cliContext, args []string) error      { return runAuditCLI(args) }
func runStateCommandCLI(_ *cliContext, args []string) error      { return runStateCLI(args) }
func runMigrateCommandCLI(_ *cliContext, args []string) error    { return runMigrateCLI(args) }
func runClusterCommandCLI(_ *cliContext, args []string) error    { return runClusterCLI(args) }

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

func runDoctorCommandCLI(ctx *cliContext, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("doctor does not accept arguments")
	}
	return runDoctorCLI(ctx)
}

type doctorCheck struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Blocking bool   `json:"blocking"`
	Detail   string `json:"detail"`
}

func runDoctorCLI(ctx *cliContext) error {
	checks := make([]doctorCheck, 0, 8)
	add := func(name string, ok, blocking bool, detail string) {
		checks = append(checks, doctorCheck{Name: name, OK: ok, Blocking: blocking, Detail: detail})
	}
	cfg, err := config.Load(ctx.ConfigPath)
	if err != nil {
		add("configuration", false, true, err.Error())
		return printDoctor(ctx.Output, checks)
	}
	if err := cfg.ValidateCertificates(); err != nil {
		add("TLS configuration", false, true, err.Error())
	} else {
		add("TLS configuration", true, true, "valid")
	}
	trustMode := "unconfigured"
	trustMode = string(cfg.Backend.TrustMode)
	trustOK := trustMode == "mtls" || trustMode == "private_network" || trustMode == "development"
	add("backend trust mode", trustOK, true, trustMode)
	token, tokenErr := operatorTokenFromFile(ctx.Token, ctx.TokenFile)
	if tokenErr != nil {
		add("operator credentials", false, true, tokenErr.Error())
	} else if token == "" {
		add("operator credentials", false, true, "set GRIPLINE_OPERATOR_TOKEN, GRIPLINE_OPERATOR_TOKEN_FILE, or pass --token-file")
	} else {
		add("operator credentials", true, true, "configured")
	}
	if token != "" && tokenErr == nil {
		client, clientErr := newAdminClient(ctx.ConfigPath)
		if clientErr != nil {
			add("admin endpoint", false, true, clientErr.Error())
		} else {
			var cluster map[string]any
			if err := client.request(http.MethodGet, "/admin/cluster", token, nil, &cluster); err != nil {
				add("admin endpoint", false, true, err.Error())
			} else {
				add("admin endpoint", true, true, "reachable and authenticated")
				add("state authority", true, true, "cluster status returned")
			}
			var policyStatus map[string]any
			if err := client.request(http.MethodGet, "/admin/policy", token, nil, &policyStatus); err != nil {
				add("active policy", false, true, err.Error())
			} else {
				add("active policy", true, true, "policy endpoint reachable")
			}
			var cryptoStatus map[string]any
			if err := client.request(http.MethodGet, "/admin/crypto", token, nil, &cryptoStatus); err != nil {
				add("crypto synchronization", false, true, err.Error())
			} else {
				add("crypto synchronization", true, true, "crypto endpoint reachable")
			}
		}
	}
	return printDoctor(ctx.Output, checks)
}

func printDoctor(format outputFormat, checks []doctorCheck) error {
	if format == outputJSON {
		return encodeCLIOutput(format, checks)
	}
	if format == outputJSONL {
		return encodeCLIOutputRows(format, checks)
	}
	blocking := 0
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tCHECK\tDETAIL")
	for _, check := range checks {
		status := "✓"
		if !check.OK {
			status = "!"
			if check.Blocking {
				blocking++
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", status, check.Name, check.Detail)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if blocking == 0 {
		fmt.Fprintln(os.Stdout, "READY       no blocking issues")
	} else {
		fmt.Fprintf(os.Stdout, "NOT READY   %d blocking issue(s)\n", blocking)
	}
	return nil
}

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
	fmt.Fprintln(w, "KIND\tGENERATION\tSTATE\tACKS\tACTIVE\tUPDATED")
	for _, raw := range generations {
		generation, _ := raw.(map[string]any)
		kind, _ := generation["kind"].(string)
		gen, _ := generation["generation"].(float64)
		state, _ := generation["state"].(string)
		acks, _ := generation["acknowledged_nodes"].(float64)
		updated, _ := generation["updated_at"].(string)
		activeText := "no"
		if int(gen) == active(kind) {
			activeText = "yes"
		}
		if len(updated) > 16 {
			updated = updated[11:16]
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%s\t%s\n", kind, int(gen), state, int(acks), activeText, updated)
	}
	return w.Flush()
}

func printClusterStatusTable(status map[string]any) error {
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
