package proxy

import (
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/ingress"
)

func TestPreAuthGuardBoundsConcurrencyAndSourceRate(t *testing.T) {
	now := time.Now()
	guard := newPreAuthGuard(1, 100, 1, 8, time.Minute)

	release, ok := guard.acquire("198.51.100.10:1234", now)
	if !ok {
		t.Fatal("first pre-auth request should be admitted")
	}
	if _, ok := guard.acquire("198.51.100.11:1234", now); ok {
		t.Fatal("concurrency bound must reject a second in-flight request")
	}
	release()

	// Releasing the first request makes the slot available to another source.
	release, ok = guard.acquire("198.51.100.11:1234", now)
	if !ok {
		t.Fatal("a separate source should be admitted after the concurrency slot is released")
	}
	release()

	// The source budget is a request-rate budget, so it remains enforced after
	// the first request releases its concurrency slot.
	if _, ok := guard.acquire("198.51.100.10:5678", now); ok {
		t.Fatal("one source must not exceed its pre-auth request budget")
	}

	if release, ok := guard.acquire("198.51.100.10:1234", now.Add(time.Second)); !ok {
		t.Fatal("source budget should replenish in the next window")
	} else {
		release()
	}
}

func TestPreAuthSourceUsesTrustedForwardingIdentity(t *testing.T) {
	resolver := NewIngressSourceResolver(&ingress.Resolver{
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	for _, tc := range []struct {
		name string
		xff  string
		want string
	}{
		{name: "client-a", xff: "198.51.100.10, 10.0.0.2", want: "198.51.100.10"},
		{name: "client-b", xff: "198.51.100.11, 10.0.0.2", want: "198.51.100.11"},
		{name: "multi-proxy", xff: "198.51.100.12, 10.0.0.2, 10.0.0.3", want: "198.51.100.12"},
		{name: "malformed-fallback", xff: "198.51.100.12, not-an-ip, 10.0.0.3", want: "10.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("X-Forwarded-For", tc.xff)
			got, err := resolver.ResolvePreAuthSource(Observation{RemoteAddr: "10.0.0.1:443", Header: h})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("pre-auth source=%q, want %q", got, tc.want)
			}
		})
	}

	h := http.Header{}
	h.Set("X-Forwarded-For", "203.0.113.99")
	got, err := resolver.ResolvePreAuthSource(Observation{RemoteAddr: "198.51.100.1:443", Header: h})
	if err != nil {
		t.Fatal(err)
	}
	if got != "198.51.100.1" {
		t.Fatalf("untrusted peer accepted spoofed XFF: %q", got)
	}
}

func TestPreAuthOverflowUsesBoundedShards(t *testing.T) {
	guard := newPreAuthGuard(256, 1000, 1, 1, time.Minute)
	accepted := 0
	for i := 0; i < 128; i++ {
		release, ok := guard.acquireKey("source-"+string(rune('a'+i)), time.Unix(100, 0))
		if ok {
			accepted++
			release()
		}
	}
	if accepted < 2 {
		t.Fatalf("bounded overflow shards admitted %d sources, want at least 2", accepted)
	}
	metrics := guard.metricsSnapshot()
	if metrics.SourceTableSaturated == 0 || metrics.OverflowAssignments == 0 {
		t.Fatalf("overflow metrics = %+v, want saturation and assignments", metrics)
	}
}
