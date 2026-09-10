package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLIUXHierarchicalHelp(t *testing.T) {
	root := captureStdout(t, func() { printCLIHelp(nil) })
	for _, want := range []string{"credential", "crypto", "config", "doctor", "-c, --config", "-o, --output"} {
		if !strings.Contains(root, want) {
			t.Fatalf("root help missing %q:\n%s", want, root)
		}
	}
	crypto := captureStdout(t, func() { printCLIHelp([]string{"crypto"}) })
	for _, want := range []string{"status", "prepare", "activate", "retire", "gripline crypto activate"} {
		if !strings.Contains(crypto, want) {
			t.Fatalf("crypto help missing %q:\n%s", want, crypto)
		}
	}
	_, _, err := runCLIInvocation([]string{"crypto", "prepare", "signer", "--help"})
	if err != nil {
		t.Fatalf("legacy crypto preparation help failed: %v", err)
	}
	credentialAdd := captureStdout(t, func() { printCLIHelp([]string{"credential", "add"}) })
	for _, want := range []string{"--secret-file PATH", "secure prompt", "--operation-id ID", "--policy ID"} {
		if !strings.Contains(credentialAdd, want) {
			t.Fatalf("credential add help missing %q:\n%s", want, credentialAdd)
		}
	}
	security := captureStdout(t, func() { printCLIHelp([]string{"audit", "security"}) })
	for _, want := range []string{"list", "export"} {
		if !strings.Contains(security, want) {
			t.Fatalf("audit security help missing %q:\n%s", want, security)
		}
	}
}

func TestCLIConfigEffectiveRedactsSecretsAndShowsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://provider.internal","trust_mode":"private_network","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test"},"admin":{"listen":"127.0.0.1:9090","operator_tokens":{"operator-secret-0123456789abcdef0123456789abcdef":"ops:posture.control"}},"secrets":{"pepper_versions":{"1":"pepper-secret"}},"ingress":{"pseudonym_key":"pseudonym-secret"},"paths":{"audit_log":"audit.jsonl"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout := captureStdout(t, func() {
		if _, _, err := runCLIInvocation([]string{"config", "effective", "--config", path, "--redact"}); err != nil {
			t.Fatal(err)
		}
	})
	for _, secret := range []string{"operator-secret-0123456789abcdef0123456789abcdef", "pepper-secret", "pseudonym-secret"} {
		if strings.Contains(stdout, secret) {
			t.Fatalf("effective config leaked %q: %s", secret, stdout)
		}
	}
	for _, want := range []string{"<redacted>", `"spool_memory_threshold": 262144`, `"shutdown_timeout": "30s"`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("effective config missing %q: %s", want, stdout)
		}
	}
}

func TestCLIUXEveryRegisteredLeafHasHelpAndDispatchOwner(t *testing.T) {
	var visit func([]string, *cliCommand)
	visit = func(path []string, command *cliCommand) {
		if len(command.Children) == 0 {
			help := captureStdout(t, func() { printCLIHelp(path) })
			if !strings.Contains(help, "Usage:") {
				t.Fatalf("leaf %s has no usage block:\n%s", strings.Join(path, " "), help)
			}
			if command.Summary == "" || !strings.Contains(help, command.Summary) {
				t.Fatalf("leaf %s help is missing its summary:\n%s", strings.Join(path, " "), help)
			}
			return
		}
		for _, child := range command.Children {
			childPath := append(append([]string(nil), path...), child.Name)
			visit(childPath, child)
		}
	}
	for _, command := range cliRoot.Children {
		if command.Run == nil {
			t.Fatalf("root command %q has no dispatch handler", command.Name)
		}
		visit([]string{command.Name}, command)
	}
}

func TestCLIUXMachineFormatsContainOnlyJSONRecords(t *testing.T) {
	value := []map[string]any{{"result": "ok", "count": 2}}
	for _, format := range []outputFormat{outputJSON, outputJSONL} {
		t.Run(string(format), func(t *testing.T) {
			stdout := captureStdout(t, func() {
				if err := encodeCLIOutputRows(format, value); err != nil {
					t.Fatal(err)
				}
			})
			if strings.Contains(stdout, "result:") || strings.Contains(stdout, "completed") {
				t.Fatalf("machine output contains human prose: %q", stdout)
			}
			if format == outputJSON {
				var decoded []map[string]any
				if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
					t.Fatalf("JSON output=%q: %v", stdout, err)
				}
			} else {
				for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
					var decoded map[string]any
					if err := json.Unmarshal([]byte(line), &decoded); err != nil {
						t.Fatalf("JSONL record=%q: %v", line, err)
					}
				}
			}
		})
	}
}

func TestCLIUXInvalidNestedHelpUsesNearestParent(t *testing.T) {
	stdout := captureStdout(t, func() {
		_, _, err := runCLIInvocation([]string{"credential", "nope", "--help"})
		if err == nil || !strings.Contains(err.Error(), `unknown subcommand "nope"`) {
			t.Fatalf("invalid nested help error=%v", err)
		}
	})
	if !strings.Contains(stdout, "gripline credential") || !strings.Contains(stdout, "add") {
		t.Fatalf("invalid nested help did not show credential help:\n%s", stdout)
	}
}

func TestCLIUXFlagParseErrorsDoNotExposeCompatibilityFlags(t *testing.T) {
	_, _, err := runCLIInvocation([]string{"credential", "list", "--unknown-option"})
	if err == nil || !strings.Contains(err.Error(), "Usage:") || strings.Contains(err.Error(), "secret-stdin") {
		t.Fatalf("parse error=%v, want canonical usage without legacy flag dump", err)
	}
}

func TestCLIUXDoctorEnvelopeAndExitStatusAgree(t *testing.T) {
	var err error
	stdout := captureStdout(t, func() {
		err = printDoctor(outputJSON, []doctorCheck{{Name: "state", OK: false, Blocking: true, Detail: "broken"}})
	})
	var report doctorReport
	if decodeErr := json.Unmarshal([]byte(stdout), &report); decodeErr != nil {
		t.Fatalf("doctor JSON=%q: %v", stdout, decodeErr)
	}
	if report.Ready || report.BlockingIssues != 1 || len(report.Checks) != 1 {
		t.Fatalf("doctor report=%+v, want not ready with one blocking issue", report)
	}
	var exitErr *cliExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 1 {
		t.Fatalf("doctor error=%v, want exit code 1", err)
	}
}

func TestCLIUXGlobalOptionsWorkBeforeAndAfterCommand(t *testing.T) {
	t.Setenv("GRIPLINE_CONFIG", "/env/config.json")
	t.Setenv("GRIPLINE_OPERATOR_TOKEN_FILE", "/env/token")
	ctx, rest, help, err := parseGlobalCLI([]string{"--config", "/explicit/config.json", "status", "-o", "json", "--token-file", "/explicit/token"})
	if err != nil {
		t.Fatal(err)
	}
	if help || len(rest) != 1 || rest[0] != "status" {
		t.Fatalf("unexpected parsed command: rest=%v help=%t", rest, help)
	}
	if ctx.ConfigPath != "/explicit/config.json" || ctx.TokenFile != "/explicit/token" || ctx.Output != outputJSON {
		t.Fatalf("global precedence not applied: %+v", ctx)
	}
	ctx, rest, _, err = parseGlobalCLI([]string{"credential", "list"})
	if err != nil {
		t.Fatal(err)
	}
	if ctx.ConfigPath != "/env/config.json" || ctx.TokenFile != "/env/token" || len(rest) != 2 {
		t.Fatalf("environment defaults not applied: ctx=%+v rest=%v", ctx, rest)
	}
}

func TestCLIUXConfigAliasesResolveIdentically(t *testing.T) {
	for _, args := range [][]string{
		{"-config", "/one/config.json", "status"},
		{"-c", "/one/config.json", "status"},
		{"--config", "/one/config.json", "status"},
		{"-config=/one/config.json", "status"},
	} {
		ctx, rest, help, err := parseGlobalCLI(args)
		if err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		if help || len(rest) != 1 || rest[0] != "status" || ctx.ConfigPath != "/one/config.json" || !ctx.configExplicit {
			t.Fatalf("alias %v parsed as ctx=%+v rest=%v help=%t", args, ctx, rest, help)
		}
	}
}

func TestCLIUXMigrationTimeoutBelongsToMigrationCommand(t *testing.T) {
	ctx, rest, _, err := parseGlobalCLI([]string{"migrate", "apply", "--timeout", "10m"})
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Timeout != 30*time.Second || strings.Join(rest, " ") != "migrate apply --timeout 10m" {
		t.Fatalf("migration timeout was claimed globally: timeout=%s rest=%v", ctx.Timeout, rest)
	}
	ctx, rest, _, err = parseGlobalCLI([]string{"doctor", "--request-timeout", "2s"})
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Timeout != 2*time.Second || strings.Join(rest, " ") != "doctor" {
		t.Fatalf("request timeout was not global: timeout=%s rest=%v", ctx.Timeout, rest)
	}
}

func TestCLIUXPositionalNormalizationAndGeneratedOperationID(t *testing.T) {
	args, err := normalizeCLIArgs("credential", []string{"revoke", "cred-1", "-r", "compromised"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"revoke", "--id cred-1", "--reason compromised", "--operation-id op_"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("normalized args missing %q: %v", want, args)
		}
	}
	crypto, err := normalizeCLIArgs("crypto", []string{"activate", "signer", "4", "-r", "rotation"})
	if err != nil {
		t.Fatal(err)
	}
	cryptoText := strings.Join(crypto, " ")
	for _, want := range []string{"--kind signer", "--generation 4", "--reason rotation", "--operation-id op_"} {
		if !strings.Contains(cryptoText, want) {
			t.Fatalf("crypto normalized args missing %q: %v", want, crypto)
		}
	}
	prepared, err := normalizeCLIArgs("crypto", []string{"prepare", "signer", "--offline"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(prepared, " ") != "signer-prepare --offline" {
		t.Fatalf("unexpected canonical prepare form: %v", prepared)
	}
}

func TestCLIUXIdempotentTransportRetryReusesOperationID(t *testing.T) {
	var calls int
	var operationIDs []string
	client := &adminClient{base: "http://admin.invalid", client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		operationIDs = append(operationIDs, req.Header.Get("Idempotency-Key"))
		if calls == 1 {
			return nil, errors.New("connection reset")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: make(http.Header)}, nil
	})}}
	if err := client.requestWithOperationID(http.MethodPost, "/admin/mutate", "token", "op_test", map[string]string{"reason": "test"}, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(operationIDs) != 2 || operationIDs[0] != "op_test" || operationIDs[1] != "op_test" {
		t.Fatalf("operation ID was not reused across bounded retry: calls=%d ids=%v", calls, operationIDs)
	}
}

func TestCLIUXIdempotentTransportRetryAfterResponseBodyFailure(t *testing.T) {
	var calls int
	var operationIDs []string
	client := &adminClient{base: "http://admin.invalid", client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		operationIDs = append(operationIDs, req.Header.Get("Idempotency-Key"))
		if calls == 1 {
			return &http.Response{StatusCode: http.StatusOK, Body: failingReadCloser{}, Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"replayed":true}`)), Header: make(http.Header)}, nil
	})}}
	var result map[string]bool
	if err := client.requestWithOperationID(http.MethodPost, "/admin/mutate", "token", "op_body", map[string]string{"reason": "test"}, &result); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !result["replayed"] || len(operationIDs) != 2 || operationIDs[0] != "op_body" || operationIDs[1] != "op_body" {
		t.Fatalf("body retry did not replay safely: calls=%d ids=%v result=%v", calls, operationIDs, result)
	}
}

func TestCLIUXAmbiguousResponseBodyFailureIncludesOperationID(t *testing.T) {
	client := &adminClient{base: "http://admin.invalid", client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingReadCloser{}, Header: make(http.Header)}, nil
	})}}
	err := client.requestWithOperationID(http.MethodPost, "/admin/mutate", "token", "op_uncertain", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "operation ID: op_uncertain") {
		t.Fatalf("ambiguous body failure error=%v, want operation ID", err)
	}
}

func TestCLIUXCryptoRetirementTooEarlyIsActionable(t *testing.T) {
	safeAfter := time.Now().Add(18 * time.Second).UTC()
	err := cryptoRetirementTooEarlyCLIError{Kind: "signer", Generation: 3, SafeAfter: safeAfter}
	message := err.Error()
	for _, want := range []string{"signer generation 3 is not safe to retire yet", "Safe after:", "Remaining:"} {
		if !strings.Contains(message, want) {
			t.Fatalf("retirement message=%q, missing %q", message, want)
		}
	}
}

func TestCLIUXSuccessfulResponseIgnoresBodyCloseError(t *testing.T) {
	client := &adminClient{base: "http://admin.invalid", client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: closeErrorReadCloser{Reader: strings.NewReader(`{"ok":true}`)}, Header: make(http.Header)}, nil
	})}}
	if err := client.requestWithOperationID(http.MethodPost, "/admin/mutate", "token", "op_close", nil, nil); err != nil {
		t.Fatalf("close error should not fail successful response: %v", err)
	}
}

func TestCLIUXCryptoRetirementBlockerIsTyped(t *testing.T) {
	client := &adminClient{base: "http://admin.invalid", client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusConflict,
			Body:       io.NopCloser(strings.NewReader(`{"kind":"pepper","generation":2,"references":3,"detail":"credentials"}`)),
			Header:     make(http.Header),
		}, nil
	})}}
	err := client.requestWithOperationID(http.MethodPost, "/admin/crypto/retire", "token", "op_blocked", nil, nil)
	var blocked cryptoRetirementBlockedCLIError
	if !errors.As(err, &blocked) || blocked.Kind != "pepper" || blocked.Generation != 2 || blocked.References != 3 {
		t.Fatalf("retirement error=%v, parsed=%+v", err, blocked)
	}
}

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (failingReadCloser) Close() error             { return nil }

type closeErrorReadCloser struct{ *strings.Reader }

func (c closeErrorReadCloser) Close() error { return errors.New("synthetic close failure") }

func TestCLIUXSecretFileNeverBecomesArgument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "provider-key")
	if err := os.WriteFile(path, []byte("secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readCredentialInput(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("secret file read mismatch: %q", got)
	}
	if strings.Contains(strings.Join([]string{"credential", "add", "id", "--secret-file", path}, " "), "secret-value") {
		t.Fatal("raw secret appeared in the command arguments")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
