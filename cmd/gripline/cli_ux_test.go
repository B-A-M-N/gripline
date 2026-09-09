package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIUXHierarchicalHelp(t *testing.T) {
	root := captureStdout(t, func() { printCLIHelp(nil) })
	for _, want := range []string{"credential", "crypto", "doctor", "-c, --config", "-o, --output"} {
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
