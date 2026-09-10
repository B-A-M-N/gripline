package proxy

import (
	"hash/maphash"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const preAuthOverflowShards = 64

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
	overflowSeed      maphash.Seed
	sourceTableFull   atomic.Uint64
	overflowAssigned  atomic.Uint64
	overflowDenied    atomic.Uint64
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
		sourceIdle: sourceIdle, windowStart: time.Now(), sources: make(map[string]*preAuthSource), overflowSeed: maphash.MakeSeed(),
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
	overflow := false
	if !ok {
		if len(g.sources) >= g.maxSources {
			g.sourceTableFull.Add(1)
			key = g.overflowKey(key)
			overflow = true
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
		if overflow || strings.HasPrefix(key, "__overflow_") {
			g.overflowDenied.Add(1)
		}
		return nil, false
	}
	if overflow {
		g.overflowAssigned.Add(1)
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

func (g *preAuthGuard) overflowKey(source string) string {
	var hash maphash.Hash
	hash.SetSeed(g.overflowSeed)
	_, _ = hash.WriteString(source)
	return "__overflow_" + strconv.FormatUint(hash.Sum64()%preAuthOverflowShards, 10)
}

type preAuthMetricsSnapshot struct {
	SourceTableSaturated uint64
	OverflowAssignments  uint64
	OverflowDenials      uint64
	SourceTableEntries   int
}

func (g *preAuthGuard) metricsSnapshot() preAuthMetricsSnapshot {
	if g == nil {
		return preAuthMetricsSnapshot{}
	}
	g.mu.Lock()
	entries := len(g.sources)
	g.mu.Unlock()
	return preAuthMetricsSnapshot{
		SourceTableSaturated: g.sourceTableFull.Load(),
		OverflowAssignments:  g.overflowAssigned.Load(),
		OverflowDenials:      g.overflowDenied.Load(),
		SourceTableEntries:   entries,
	}
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
