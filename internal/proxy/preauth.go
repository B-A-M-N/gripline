package proxy

import (
	"net"
	"strings"
	"sync"
	"time"
)

// preAuthGuard bounds work that happens before a credential is known to be
// valid. It is intentionally separate from authorization policy: an invalid
// credential must not be able to spend unbounded HMAC/database/telemetry work.
type preAuthGuard struct {
	mu                sync.Mutex
	maxConcurrent     int
	requestsPerSecond int
	sourceRequestsPS  int
	maxSources        int
	sourceIdle        time.Duration
	active            int
	windowStart       time.Time
	windowCount       int
	sources           map[string]*preAuthSource
}

type preAuthSource struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time
}

func newPreAuthGuard(maxConcurrent, requestsPerSecond, sourceRequestsPerSecond, maxSources int, sourceIdle time.Duration) *preAuthGuard {
	if maxConcurrent <= 0 {
		maxConcurrent = 1024
	}
	if requestsPerSecond <= 0 {
		requestsPerSecond = 2000
	}
	if sourceRequestsPerSecond <= 0 {
		sourceRequestsPerSecond = 100
	}
	if maxSources <= 0 {
		maxSources = 10000
	}
	if sourceIdle <= 0 {
		sourceIdle = 10 * time.Minute
	}
	return &preAuthGuard{
		maxConcurrent: maxConcurrent, requestsPerSecond: requestsPerSecond,
		sourceRequestsPS: sourceRequestsPerSecond, maxSources: maxSources,
		sourceIdle: sourceIdle, windowStart: time.Now(), sources: make(map[string]*preAuthSource),
	}
}

func (g *preAuthGuard) acquire(remote string, now time.Time) (func(), bool) {
	return g.acquireKey(canonicalPeer(remote), now)
}

func (g *preAuthGuard) acquireKey(key string, now time.Time) (func(), bool) {
	if g == nil {
		return func() {}, true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.IsZero() {
		now = time.Now()
	}
	if now.Sub(g.windowStart) >= time.Second {
		g.windowStart, g.windowCount = now, 0
	}
	if g.active >= g.maxConcurrent || g.windowCount >= g.requestsPerSecond {
		return nil, false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "__unknown__"
	}
	for source, state := range g.sources {
		if now.Sub(state.lastSeen) >= g.sourceIdle {
			delete(g.sources, source)
		}
	}
	state, ok := g.sources[key]
	if !ok {
		if len(g.sources) >= g.maxSources {
			key = "__overflow__"
			state = g.sources[key]
		}
		if state == nil {
			state = &preAuthSource{windowStart: now}
			g.sources[key] = state
		}
	}
	if now.Sub(state.windowStart) >= time.Second {
		state.windowStart, state.count = now, 0
	}
	if state.count >= g.sourceRequestsPS {
		return nil, false
	}
	state.count++
	state.lastSeen = now
	g.active++
	g.windowCount++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			if g.active > 0 {
				g.active--
			}
			g.mu.Unlock()
		})
	}, true
}

func canonicalPeer(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "__unknown__"
	}
	return remote
}
