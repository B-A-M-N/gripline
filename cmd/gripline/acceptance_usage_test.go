package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/proxy"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// TestAcceptanceBuiltInUsageAdapters proves that the production composition
// root wires both built-in provider-compatible meters into the real data
// plane. The assertion is behavioral: the stream's final usage envelope must
// reach the adapter and appear in low-cardinality runtime counters.
func TestAcceptanceBuiltInUsageAdapters(t *testing.T) {
	for _, tt := range []struct {
		name, mode, method, path, stream string
		input, output, combined, cost    uint64
	}{
		{
			name: "openai", mode: "openai", method: http.MethodPost, path: "/v1/chat/completions",
			stream: "data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5,\"total_tokens\":8}}\n\n",
			input:  3, output: 5, combined: 8, cost: 21,
		},
		{
			name: "anthropic", mode: "anthropic", method: http.MethodPost, path: "/v1/messages",
			stream: "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3}}}\n\n" +
				"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n" +
				"data: {\"type\":\"message_stop\"}\n\n",
			input: 3, output: 5, combined: 8, cost: 21,
		},
		{
			name: "openai-responses", mode: "openai", method: http.MethodPost, path: "/v1/responses",
			stream: "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":4,\"output_tokens\":6,\"total_tokens\":10}}}\n\n",
			input:  4, output: 6, combined: 10, cost: 26,
		},
		{
			name: "openai-embeddings", mode: "openai", method: http.MethodPost, path: "/v1/embeddings",
			stream: `{"usage":{"prompt_tokens":4,"total_tokens":4}}`,
			input:  4, output: 0, combined: 4, cost: 8,
		},
		{
			name: "openai-models", mode: "openai", method: http.MethodGet, path: "/v1/models",
			stream: `{"data":[{"id":"model"}]}`,
			input:  0, output: 0, combined: 0, cost: 0,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			externalSecret := "sk-usage-" + tt.name + "-012345678901234567890123456789"
			setBootstrapCredential(t, "cred_usage", "acct_usage", externalSecret)
			t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)

			kr, err := terminator.NewKeyring()
			if err != nil {
				t.Fatal(err)
			}
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, tt.stream)
			}))
			defer backend.Close()

			keyringPath := filepath.Join(dir, "keyring.json")
			if err := kr.Save(keyringPath); err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(dir, "config.json")
			cfgJSON := fmt.Sprintf(`{"listen":"127.0.0.1:0","backend":{"url":"%s","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"tls":{"terminate_tls_upstream":true},"paths":{"evidence":"%s","signer_keyring":"%s"},"usage":{"mode":"%s","input_microunits_per_token":2,"output_microunits_per_token":3,"max_output_tokens":8}}`, backend.URL, filepath.Join(dir, "evidence.gob"), keyringPath, tt.mode)
			if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o640); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}
			rt, err := BuildRuntime(cfg)
			if err != nil {
				t.Fatalf("BuildRuntime: %v", err)
			}
			defer rt.Close()

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			srv := &http.Server{Handler: rt.DataPlane}
			go srv.Serve(ln)
			defer srv.Close()

			body := io.Reader(strings.NewReader(`{"prompt":"usage"}`))
			if tt.method == http.MethodGet {
				body = nil
			}
			req, err := http.NewRequest(tt.method, "http://"+ln.Addr().String()+tt.path, body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+externalSecret)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("usage request status=%d body=%s", resp.StatusCode, body)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}

			dp, ok := rt.DataPlane.(*proxy.DataPlane)
			if !ok {
				t.Fatalf("runtime data plane type=%T, want *proxy.DataPlane", rt.DataPlane)
			}
			var metrics proxy.MetricsSnapshot
			deadline := time.Now().Add(time.Second)
			for {
				metrics = dp.Metrics()
				if metrics.UsageSessions == 1 || time.Now().After(deadline) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if metrics.UsageSessions != 1 || metrics.UsageInputTokens != tt.input || metrics.UsageOutputTokens != tt.output || metrics.UsageCombinedTokens != tt.combined || metrics.UsageCostMicrounits != tt.cost {
				t.Fatalf("%s usage metrics=%+v, want one session input=%d output=%d combined=%d cost=%d", tt.mode, metrics, tt.input, tt.output, tt.combined, tt.cost)
			}
		})
	}
}
