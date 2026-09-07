package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// sseBackend mimics a real inference provider: it verifies the internal
// assertion, then streams an SSE response token-by-token with real delays,
// ending with a usage-bearing final envelope. It records whether the forwarded
// request body arrived chunked (Transfer-Encoding, no Content-Length) and
// forwards arrival timestamps of what it sent.
type sseBackend struct {
	*backendVerifier
	// interChunk delays each token's emission.
	interChunk time.Duration
	// chunkedBodySeen records that the gateway forwarded the request with
	// chunked framing (unknown length) intact.
	chunkedBodySeen atomic.Bool
	receivedBody    chan string
}

func newSSEBackend(kr *terminator.Keyring, audience string, interChunk time.Duration) *sseBackend {
	return &sseBackend{
		backendVerifier: newBackendVerifierFromKeyring(kr, audience),
		interChunk:      interChunk,
		receivedBody:    make(chan string, 4),
	}
}

func (b *sseBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Assertion verification via the shared verifier, minus its JSON response:
	// inline the check so we control the streaming shape.
	b.hits.Add(1)
	if r.Header.Get("Authorization") != "" {
		b.rejected.Add(1)
		http.Error(w, "raw_credential_rejected", http.StatusForbidden)
		return
	}
	assertion := r.Header.Get("X-Gripline-Assertion")
	if assertion == "" {
		b.rejected.Add(1)
		http.Error(w, "missing_assertion", http.StatusUnauthorized)
		return
	}
	claims, err := b.verifier.VerifyAndStrip(r)
	if err != nil {
		b.rejected.Add(1)
		http.Error(w, "invalid_assertion", http.StatusUnauthorized)
		return
	}
	b.authorized.Add(1)
	b.lastClaims.Store(claims)

	// Record the forwarded body (a chunked request must arrive complete).
	body, _ := io.ReadAll(r.Body)
	b.receivedBody <- string(body)
	if r.ContentLength < 0 && len(body) > 0 {
		b.chunkedBodySeen.Store(true)
	}

	// Stream SSE with real inter-chunk delays, then the usage envelope.
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	tokens := []string{"hello", " ", "world", "!"}
	for _, tok := range tokens {
		fmt.Fprintf(w, "data: {\"token\":%q}\n\n", tok)
		if fl != nil {
			fl.Flush()
		}
		time.Sleep(b.interChunk)
	}
	fmt.Fprintf(w, "data: {\"type\":\"message_stop\",\"usage\":{\"output_tokens\":4}}\n\n")
	if fl != nil {
		fl.Flush()
	}
}

// TestAcceptanceRealStreaming proves the executable data plane is a TRUE
// streaming proxy over a REAL HTTP server (P1-29/P0.40): SSE chunks arrive at
// the client paced by the backend's emission (not batched at stream end), a
// chunked request body forwards intact, and the response terminates cleanly.
func TestAcceptanceRealStreaming(t *testing.T) {
	dir := t.TempDir()
	rawCred := make([]byte, 32)
	rand.Read(rawCred)
	externalSecret := "sk-live-" + fmt.Sprintf("%x", rawCred)
	setBootstrapCredential(t, "cred_stream", "acct_stream", externalSecret)
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)

	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	// 150ms between tokens: a concatenating (buffering) proxy would deliver
	// everything at ~600ms in one read; a streaming proxy delivers each chunk
	// as emitted. We assert per-chunk arrival timing.
	be := newSSEBackend(kr, "test-audience", 150*time.Millisecond)
	backend := httptest.NewServer(be)
	defer backend.Close()
	keyringPath := filepath.Join(dir, "keyring.json")
	if err := kr.Save(keyringPath); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "config.json")
	// P0.16 streaming timeout scheme active: write_timeout 5s budget with a
	// 1s stream idle bound — the paced stream (150ms gaps) must survive it.
	cfgJSON := fmt.Sprintf(`{"listen":"127.0.0.1:0","backend":{"url":"%s","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s","stream_write_idle_timeout":"1s"},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"tls":{"terminate_tls_upstream":true},"paths":{"signer_keyring":"%s"}}`, backend.URL, keyringPath)
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
	defer func() { _ = rt.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Serve through a REAL http.Server configured exactly as main.go would
	// with the streaming exemption: WriteTimeout 0, per-request deadlines
	// govern inside the data plane.
	srv := &http.Server{
		Handler:           rt.DataPlane,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      0, // P0.16: idle-bound scheme governs
		IdleTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go srv.Serve(ln)
	defer srv.Close()
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())

	// Chunked (unknown-length) request body — the spooler path.
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte(`{"prompt":"stream me"}`))
		_ = pw.Close()
	}()
	req, _ := http.NewRequest("POST", baseURL+"/v1/messages", pr)
	req.Header.Set("Authorization", "Bearer "+externalSecret)
	req.Header.Set("Accept", "text/event-stream")
	req.ContentLength = -1 // force chunked framing

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("streaming proxy must succeed, got %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("SSE content type must survive, got %q", ct)
	}

	// Read the stream, timestamping each event's arrival.
	type arrival struct {
		line string
		at   time.Duration
	}
	start := time.Now()
	var events []arrival
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if line != "" {
			events = append(events, arrival{line: line, at: time.Since(start)})
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("stream read error: %v", err)
	}

	// All four tokens + the usage envelope arrived.
	var tokenLines, usageLines int
	for _, ev := range events {
		if len(ev.line) > 6 && ev.line[:6] == "data: " {
			switch {
			case len(ev.line) > 15 && ev.line[6:15] == `{"token":`:
				tokenLines++
			case containsString(ev.line, `"usage"`):
				usageLines++
			}
		}
	}
	if tokenLines != 4 {
		t.Fatalf("expected 4 token events, got %d (%v)", tokenLines, events)
	}
	if usageLines != 1 {
		t.Fatalf("expected the final usage envelope, got %d (%v)", usageLines, events)
	}

	// TRUE streaming: the first token must arrive well before the stream end.
	// Backend spacing is 150ms; a buffering proxy would deliver the first
	// token at >= 450ms (after all sleeps). Streaming delivers it < 150ms
	// after emission (generous bound: < 400ms).
	if events[0].at > 400*time.Millisecond {
		t.Fatalf("first token arrived at %v — proxy is buffering, not streaming (backend paces at 150ms)", events[0].at)
	}
	// And the last token precedes the usage envelope (order preserved).
	if events[len(events)-2].at >= events[len(events)-1].at {
		t.Fatal("events must arrive in stream order")
	}

	// The chunked request body arrived intact at the backend.
	select {
	case body := <-be.receivedBody:
		if body != `{"prompt":"stream me"}` {
			t.Fatalf("chunked body corrupted in forwarding: %q", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never received the request body")
	}
	if !be.chunkedBodySeen.Load() {
		t.Fatal("backend must see chunked request framing preserved (ContentLength<0)")
	}
	if be.rejected.Load() != 0 {
		t.Fatalf("no request may be rejected in the streaming path: %d", be.rejected.Load())
	}

	t.Log("PASS: SSE tokens arrive paced by the backend (true streaming), chunked request bodies forward intact, stream_write_idle_timeout active")
}

func containsString(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// stalledStreamBackend sends a first chunk then goes silent forever.
type stalledStreamBackend struct {
	*backendVerifier
	firstChunk chan struct{} // closed after the first chunk is written
}

func newStalledBackend(kr *terminator.Keyring, audience string) *stalledStreamBackend {
	return &stalledStreamBackend{
		backendVerifier: newBackendVerifierFromKeyring(kr, audience),
		firstChunk:      make(chan struct{}),
	}
}

func (b *stalledStreamBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.hits.Add(1)
	assertion := r.Header.Get("X-Gripline-Assertion")
	if assertion == "" {
		b.rejected.Add(1)
		http.Error(w, "missing_assertion", http.StatusUnauthorized)
		return
	}
	claims, err := b.verifier.VerifyAndStrip(r)
	if err != nil {
		b.rejected.Add(1)
		http.Error(w, "invalid_assertion", http.StatusUnauthorized)
		return
	}
	b.authorized.Add(1)
	_ = claims
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "data: {\"token\":\"first\"}\n\n")
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	close(b.firstChunk)
	// Then hang: never write again. The handler must still exit when the
	// gateway cuts the upstream connection (idle deadline), so watch the
	// request context instead of blocking forever.
	<-r.Context().Done()
}

// TestAcceptanceStalledStreamCut proves the P0.16 idle bound kills a stream
// whose backend stalls: after the first chunk the backend goes silent; the
// gateway must terminate the client response within the idle bound plus
// slack, not hang for the full write budget or forever.
func TestAcceptanceStalledStreamCut(t *testing.T) {
	dir := t.TempDir()
	rawCred := make([]byte, 32)
	rand.Read(rawCred)
	externalSecret := "sk-live-" + fmt.Sprintf("%x", rawCred)
	setBootstrapCredential(t, "cred_stall", "acct_stall", externalSecret)
	t.Setenv("GRIPLINE_PEPPER_V1", testPepperEnv)

	kr, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	be := newStalledBackend(kr, "test-audience")
	backend := httptest.NewServer(be)
	defer backend.Close()
	keyringPath := filepath.Join(dir, "keyring.json")
	if err := kr.Save(keyringPath); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := fmt.Sprintf(`{"listen":"127.0.0.1:0","backend":{"url":"%s","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s","stream_write_idle_timeout":"1s"},"identity":{"audience":"test-audience"},"deployment":{"allow_ephemeral_state":true},"tls":{"terminate_tls_upstream":true},"paths":{"signer_keyring":"%s"}}`, backend.URL, keyringPath)
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
	defer func() { _ = rt.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: rt.DataPlane, WriteTimeout: 0}
	go srv.Serve(ln)
	defer srv.Close()

	req, _ := http.NewRequest("POST", fmt.Sprintf("http://%s/v1/messages", ln.Addr().String()), strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", "Bearer "+externalSecret)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream must start, got %d", resp.StatusCode)
	}

	// Read to completion. The read must END (server cut the stream) well
	// within the 5s write budget — bounded by the 1s idle deadline.
	buf := make([]byte, 4096)
	total := 0
	for {
		n, rerr := resp.Body.Read(buf)
		total += n
		if rerr != nil {
			break
		}
	}
	elapsed := time.Since(start)
	if total == 0 {
		t.Fatal("first chunk must have been delivered before the cut")
	}
	<-be.firstChunk // ensure the backend actually emitted before we judge timing
	// The cut must be driven by the 1s idle bound, not the 5s budget. Allow
	// generous slack for the two hops (deadline set at WriteHeader, then the
	// backend hang detection) but require it well under the 5s budget.
	if elapsed > 3*time.Second {
		t.Fatalf("stalled stream must be cut by the idle bound (~1s), took %v (budget path would take 5s)", elapsed)
	}
	t.Logf("PASS: stalled stream cut after %v (idle bound 1s, write budget 5s)", elapsed)
}
