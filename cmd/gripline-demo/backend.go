package main

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/proxy"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

type demoBarrier struct {
	mu      sync.Mutex
	want    int
	reached int
	changed chan struct{}
	release chan struct{}
}

func newDemoBarrier() *demoBarrier { return &demoBarrier{} }

func (b *demoBarrier) begin(want int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.want, b.reached = want, 0
	b.changed = make(chan struct{})
	b.release = make(chan struct{})
}

func (b *demoBarrier) holds(r *http.Request) bool {
	b.mu.Lock()
	if b.release == nil || !strings.Contains(strings.ToLower(r.Header.Get("User-Agent")), "stealer") || b.reached >= b.want {
		b.mu.Unlock()
		return false
	}
	b.reached++
	changed, release := b.changed, b.release
	close(changed)
	b.changed = make(chan struct{})
	b.mu.Unlock()
	<-release
	return true
}

func (b *demoBarrier) waitFor(want int, timeout time.Duration) bool {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		b.mu.Lock()
		if b.reached >= want {
			b.mu.Unlock()
			return true
		}
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-changed:
		case <-deadline.C:
			return false
		}
	}
}

func (b *demoBarrier) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reached
}

func (b *demoBarrier) releaseAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.release != nil {
		close(b.release)
		b.release = nil
	}
}

type backendStats struct {
	mu                sync.Mutex
	RawAuthorization  int `json:"raw_authorization"`
	RawAPIKey         int `json:"raw_api_key"`
	ValidAssertions   int `json:"valid_assertions"`
	InvalidOrForged   int `json:"invalid_or_forged_assertions"`
	DirectRawRejected int `json:"direct_raw_rejected"`
}

func newProtectedBackend(verifier *terminator.VerifierKeyring, audience string, stats *backendStats, barrier *demoBarrier) http.Handler {
	bv := proxy.NewBackendVerifierKeyring(verifier, audience)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats.mu.Lock()
		// RawAuthorization/RawAPIKey measure raw credentials arriving on the
		// assertion-bearing proxy hop. Direct raw attempts are counted separately
		// below, so the boundary counter remains a proof that forwarding never
		// carried the external credential.
		if r.Header.Get("Authorization") != "" && r.Header.Get("X-Gripline-Assertion") != "" {
			stats.RawAuthorization++
		}
		if r.Header.Get("X-API-Key") != "" && r.Header.Get("X-Gripline-Assertion") != "" {
			stats.RawAPIKey++
		}
		stats.mu.Unlock()
		claims, err := bv.Verify(r)
		if err != nil {
			stats.mu.Lock()
			stats.InvalidOrForged++
			if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
				stats.DirectRawRejected++
			}
			stats.mu.Unlock()
			http.Error(w, "assertion required", http.StatusUnauthorized)
			return
		}
		stats.mu.Lock()
		stats.ValidAssertions++
		stats.mu.Unlock()
		if barrier != nil {
			barrier.holds(r)
		}
		// Keep admitted requests overlapping so the stock resource-velocity
		// producer observes real in-flight lane concurrency.
		time.Sleep(500 * time.Millisecond)
		bv.StripAssertion(r)
		w.Header().Set("X-Demo-Assertion-Verified", "true")
		w.Header().Set("X-Demo-Principal", claims.CredID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"backend":"protected","identity":"assertion"}`))
	})
}
