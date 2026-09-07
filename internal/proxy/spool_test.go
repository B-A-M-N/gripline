package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B-A-M-N/gripline/internal/terminator"
)

type countingBody struct {
	read  bool
	inner io.Reader
}

func (b *countingBody) Read(p []byte) (int, error) {
	b.read = true
	return b.inner.Read(p)
}
func (b *countingBody) Close() error { return nil }

// readAllSpooled drains a spooled body fully and returns its content.
func readAllSpooled(t *testing.T, b *spooledBody) string {
	t.Helper()
	data, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("read spooled body: %v", err)
	}
	return string(data)
}

// buildDataPlaneForBodyTest wires a DataPlane with a 100-byte body limit and a
// working terminator, with optional config mutation.
func buildDataPlaneForBodyTest(t *testing.T, bu *url.URL, maxBytes int64, mutate ...func(*Config)) *DataPlane {
	t.Helper()
	signer, _ := terminator.GenerateSigner()
	cfg := Config{
		Terminator:   buildTerminatorWithSigner(t, signer),
		BackendURL:   bu,
		Audience:     testAudience,
		MaxBodyBytes: maxBytes,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	dp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return dp
}

// TestSpoolBodyLimitBoundaries proves the spooler's maxBytes parameter is the
// ACTUAL limit (P0-6): a body of exactly maxBytes forwards, one byte over is
// flagged tooLarge, and a massively oversized body is flagged rather than
// silently truncated. Both the in-memory path and the temp-file spool path are
// exercised (memThreshold forces the file path for large bodies).
func TestSpoolBodyLimitBoundaries(t *testing.T) {
	const maxBytes = 1024

	cases := []struct {
		name     string
		size     int
		tooLarge bool
	}{
		{"max-1", maxBytes - 1, false},
		{"exactly-max", maxBytes, false},
		{"max+1", maxBytes + 1, true},
		{"10x-max", 10 * maxBytes, true},
	}

	for _, tc := range cases {
		for _, memThreshold := range []int64{spoolMemoryThreshold, 64} {
			body := strings.Repeat("x", tc.size)
			spooled, err := spoolBody(io.NopCloser(strings.NewReader(body)), maxBytes, memThreshold)
			if err != nil {
				t.Fatalf("%s (mem=%d): %v", tc.name, memThreshold, err)
			}
			if spooled.tooLarge != tc.tooLarge {
				t.Fatalf("%s (mem=%d): tooLarge=%v, want %v (len=%d)", tc.name, memThreshold, spooled.tooLarge, tc.tooLarge, spooled.length)
			}
			if !tc.tooLarge && spooled.length != maxBytes && spooled.length != int64(tc.size) {
				t.Fatalf("%s (mem=%d): length=%d, want %d", tc.name, memThreshold, spooled.length, tc.size)
			}
			_ = spooled.Close()
		}
	}
}

// TestSpoolBodyTooLargeNotForwardable proves a tooLarge spooled body is never
// handed back as a valid forwardable body: the caller rejects it, and Close
// cleans up. The truncated content must not survive as a usable body.
func TestSpoolBodyTooLargeNotForwardable(t *testing.T) {
	const maxBytes = 128
	spooled, err := spoolBody(io.NopCloser(strings.NewReader(strings.Repeat("y", 4096))), maxBytes, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !spooled.tooLarge {
		t.Fatal("4096-byte body against a 128-byte cap must be tooLarge")
	}
	fileName := spooled.fileName
	_ = spooled.Close()
	if fileName != "" {
		if _, err := os.Stat(fileName); !os.IsNotExist(err) {
			t.Fatalf("temp file %q must be removed on Close", fileName)
		}
	}
}

// TestSpoolBodyTempFileCleanedOnNormalClose proves the temp file is removed by
// the ordinary Close lifecycle (P0-7), not only on the tooLarge error path.
func TestSpoolBodyTempFileCleanedOnNormalClose(t *testing.T) {
	body := strings.Repeat("z", 4096) // > 64-byte threshold → spools to file
	spooled, err := spoolBody(io.NopCloser(strings.NewReader(body)), 8192, 64)
	if err != nil {
		t.Fatal(err)
	}
	if spooled.fileName == "" {
		t.Fatal("expected a temp-file-backed spool")
	}
	if spooled.tooLarge {
		t.Fatal("body within limit must not be tooLarge")
	}
	fileName := spooled.fileName

	// Simulate the transport: read fully, then Close once.
	if got := readAllSpooled(t, spooled); got != body {
		t.Fatalf("spooled content mismatch: %d vs %d bytes", len(got), len(body))
	}
	if err := spooled.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(fileName); !os.IsNotExist(err) {
		t.Fatalf("temp file %q must not survive a normal Close", fileName)
	}

	// Idempotent: a second Close must not error or resurrect anything.
	if err := spooled.Close(); err != nil {
		t.Fatalf("second close must be a no-op, got %v", err)
	}
}

// TestSpoolBodyChunkedEndToEnd drives the full DataPlane with a chunked
// (unknown-length) body for every boundary case: max-1/exactly-max forward,
// max+1/10x-max reject 413 with the backend never reached.
func TestSpoolBodyChunkedEndToEnd(t *testing.T) {
	const maxBytes = 256

	backendHits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	dp := buildDataPlaneForBodyTest(t, bu, maxBytes)

	send := func(size int) *httptest.ResponseRecorder {
		// httptest.NewRequest with an io.Reader of unknown length sets
		// ContentLength=-1 (chunked) when the reader is not a *bytes.Reader /
		// *strings.Reader — use a plain pipe-backed reader.
		pr, pw := io.Pipe()
		go func() {
			_, werr := pw.Write([]byte(strings.Repeat("q", size)))
			_ = pw.CloseWithError(werr)
		}()
		req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", pr)
		req.Header.Set("Authorization", "Bearer "+dpRaw())
		req.ContentLength = -1
		req.Header.Set("Transfer-Encoding", "chunked")
		rec := httptest.NewRecorder()
		dp.ServeHTTP(rec, req)
		return rec
	}

	cases := []struct {
		name string
		size int
		code int
	}{
		{"max-1", maxBytes - 1, http.StatusOK},
		{"exactly-max", maxBytes, http.StatusOK},
		{"max+1", maxBytes + 1, http.StatusRequestEntityTooLarge},
		{"10x-max", 10 * maxBytes, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		hitsBefore := backendHits
		rec := send(tc.size)
		if rec.Code != tc.code {
			t.Fatalf("%s: got %d, want %d (%s)", tc.name, rec.Code, tc.code, rec.Body.String())
		}
		if tc.code == http.StatusOK && backendHits == hitsBefore {
			t.Fatalf("%s: expected the backend to be reached", tc.name)
		}
		if tc.code == http.StatusRequestEntityTooLarge && backendHits != hitsBefore {
			t.Fatalf("%s: backend must NOT be reached for an oversized body", tc.name)
		}
	}
}

func TestChunkedInvalidCredentialPreflightDoesNotReadBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("invalid credential must not reach backend")
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	dp := buildDataPlaneForBodyTest(t, bu, 1<<20)
	body := &countingBody{inner: strings.NewReader(strings.Repeat("x", 1<<20))}
	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", body)
	req.Body = body
	req.ContentLength = -1
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Authorization", "Bearer definitely-not-a-valid-key")
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid preflight status=%d body=%s", rec.Code, rec.Body.String())
	}
	if body.read {
		t.Fatal("invalid credential preflight must reject before reading/spooling the body")
	}
	if rec.Header().Get("X-Gripline-Request-ID") == "" {
		t.Fatal("early denial must carry request id")
	}
}

// TestSpoolTempFilesDoNotLeakEndToEnd proves no gripline-body temp files
// survive completed requests (P0-7): spool, forward, transport-closes-body —
// the file must be gone.
func TestSpoolTempFilesDoNotLeakEndToEnd(t *testing.T) {
	const maxBytes = 1 << 20
	tmpDir := t.TempDir()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	dp := buildDataPlaneForBodyTest(t, bu, maxBytes, func(cfg *Config) {
		// Route temp files into the test dir so the leak assertion is scoped.
		orig := spoolTempDir
		spoolTempDir = tmpDir
		t.Cleanup(func() { spoolTempDir = orig })
	})

	// Several sequential large chunked requests: any leak accumulates.
	for i := 0; i < 5; i++ {
		pr, pw := io.Pipe()
		go func() {
			_, werr := pw.Write(bytes.Repeat([]byte("b"), 2*spoolMemoryThreshold))
			_ = pw.CloseWithError(werr)
		}()
		req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", pr)
		req.Header.Set("Authorization", "Bearer "+dpRaw())
		req.ContentLength = -1
		rec := httptest.NewRecorder()
		dp.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200 (%s)", i, rec.Code, rec.Body.String())
		}
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file leaked: %s", filepath.Join(tmpDir, e.Name()))
		}
	}
}
