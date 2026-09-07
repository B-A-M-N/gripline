package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestStreamWriteIdleTimeout exercises the P0.16 deadline scheme at the
// httptest boundary: with WriteTimeout + StreamWriteIdleTimeout configured the
// data plane sets a per-request write deadline that it re-arms after every
// forwarded chunk. httptest's ResponseRecorder supports deadline control, so we
// verify the deadline is (a) set before WriteHeader with the full budget and
// (b) re-armed after chunks flow.
func TestStreamWriteIdleTimeoutDeadlineScheme(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 3; i++ {
			_, _ = w.Write([]byte("chunk\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	defer backend.Close()
	bu, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	var seen []time.Time // snapshots of the recorder's write deadline
	dp := buildDataPlaneForBodyTest(t, bu, 1024, func(cfg *Config) {
		cfg.WriteTimeout = 30 * time.Second
		cfg.StreamWriteIdleTimeout = 2 * time.Second
	})
	// Wrap the recorder so we can snapshot its deadline after writes.
	rec := newDeadlineRecorder()
	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", "Bearer "+dpRaw())
	dp.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("proxy must stream successfully, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "chunk\nchunk\nchunk\n") {
		t.Fatalf("full streamed body expected, got %q", rec.Body.String())
	}
	seen = rec.deadlines()
	if len(seen) == 0 || seen[0].IsZero() {
		t.Fatal("initial write deadline must be set before the first body write")
	}
	// The backend sends 3 chunks; even when the transport coalesces reads, the
	// deadline must have been set initially AND re-armed after the final
	// forwarded chunk (>= 2 SetWriteDeadline calls total).
	if got := rec.setCallsCount(); got < 2 {
		t.Fatalf("write deadline must be re-armed after chunks: %d SetWriteDeadline calls", got)
	}
	// The FINAL SetWriteDeadline must use the idle bound, not the full budget.
	// (Chunk reads may coalesce — a single Write can carry every chunk and the
	// re-arm then happens after the last write — so write snapshots alone
	// cannot prove the re-arm value; the set-call log can.)
	lastSet := rec.lastSet()
	if until := time.Until(lastSet); until > 2*time.Second+time.Second {
		t.Fatalf("final write deadline must use the idle bound (2s), got %v from now", until)
	}
	// The FIRST set must be the full budget (proportional, not flaky on slow
	// machines: it must exceed the idle bound).
	firstSet := seen[0]
	if until := time.Until(firstSet); until < 10*time.Second {
		t.Fatalf("initial write deadline must be the full budget (30s), got %v from now", until)
	}
}

// deadlineRecorder wraps ResponseRecorder and snapshots the write deadline
// after every Write, proving re-arm behavior.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	mu        sync.Mutex
	deadline  time.Time
	setCalls  int
	sets      []time.Time
	snapshots []time.Time
}

func newDeadlineRecorder() *deadlineRecorder {
	return &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.deadline = t
	d.setCalls++
	d.sets = append(d.sets, t)
	d.mu.Unlock()
	return nil
}

// lastSet returns the most recent deadline passed to SetWriteDeadline.
func (d *deadlineRecorder) lastSet() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.sets) == 0 {
		return time.Time{}
	}
	return d.sets[len(d.sets)-1]
}

func (d *deadlineRecorder) Write(p []byte) (int, error) {
	d.mu.Lock()
	d.snapshots = append(d.snapshots, d.deadline)
	d.mu.Unlock()
	return d.ResponseRecorder.Write(p)
}

func (d *deadlineRecorder) deadlines() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.snapshots...)
}

func (d *deadlineRecorder) setCallsCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.setCalls
}
