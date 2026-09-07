package proxy

import (
	"errors"
	"io"
	"sync"
	"time"
)

// ErrStreamIdle is returned by idleTimeoutReader when no bytes arrived within
// the idle bound. It surfaces to the client as a truncated stream (the
// response is already committed), so the cut must be observable in gateway
// telemetry, not recoverable.
var ErrStreamIdle = errors.New("proxy: upstream stream exceeded the write-idle bound")

// idleTimeoutReader bounds how long Read may block without returning bytes
// (P0.16). http.ResponseController write deadlines only fire when bytes are
// written; a backend that stalls mid-stream produces none, so without this
// wrapper the proxy's read loop blocks on the silent upstream forever while
// the client connection hangs open.
//
// Each Read launches (or reuses) a watchdog: if no byte arrives within the
// idle bound, the underlying body is Close()d, which unblocks the in-flight
// Read with an error. This is safe under net/http's contract — the response
// body's Close is valid concurrently with a pending Read (it aborts the
// read).
type idleTimeoutReader struct {
	mu     sync.Mutex
	body   io.ReadCloser
	idle   time.Duration
	timer  *time.Timer
	closed bool
}

func newIdleTimeoutReader(body io.ReadCloser, idle time.Duration) *idleTimeoutReader {
	return &idleTimeoutReader{body: body, idle: idle}
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	r.armWatchdog()
	n, err := r.body.Read(p)
	if n > 0 {
		// Bytes are flowing: disarm until the next gap.
		r.disarmWatchdog()
	}
	if err == io.EOF {
		// Stream finished cleanly before the bound: stop the watchdog.
		r.stopWatchdog()
	}
	return n, err
}

func (r *idleTimeoutReader) armWatchdog() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.timer != nil {
		return
	}
	r.timer = time.AfterFunc(r.idle, func() {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return
		}
		r.closed = true
		body := r.body
		r.mu.Unlock()
		// Closing the body unblocks any in-flight Read with an error.
		_ = body.Close()
	})
}

func (r *idleTimeoutReader) disarmWatchdog() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil && !r.closed {
		r.timer.Stop()
		r.timer = nil
	}
}

func (r *idleTimeoutReader) stopWatchdog() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
}

// Close releases the watchdog and the underlying body (idempotent; the proxy
// also defers resp.Body.Close()).
func (r *idleTimeoutReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	if r.closed {
		return nil
	}
	r.closed = true
	return r.body.Close()
}
