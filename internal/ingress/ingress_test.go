package ingress

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/B-A-M-N/gripline/internal/pseudonym"
)

// testRingAdapter adapts a *pseudonym.Ring to the ingress.PseudonymRing seam,
// mirroring the production adapter in cmd/gripline/runtime.go.
type testRingAdapter struct {
	ring *pseudonym.Ring
}

func (a *testRingAdapter) Derive(family []byte, raw []byte) (string, error) {
	return a.ring.Derive(pseudonym.Family(family), raw)
}

func mustRing(t *testing.T, keys ...*pseudonym.Key) *pseudonym.Ring {
	t.Helper()
	r, err := pseudonym.NewRing(keys...)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	return r
}

func testPseudonyms(t *testing.T) PseudonymRing {
	t.Helper()
	return &testRingAdapter{ring: mustRing(t, &pseudonym.Key{Version: 1, Secret: []byte("ingress-test-key")})}
}

func testProxyPrefix(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var prefixes []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("parse prefix %q: %v", c, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}

func hdr(k, v string) http.Header {
	h := make(http.Header)
	h.Set(k, v)
	return h
}

func resolve(t *testing.T, r *Resolver, remoteAddr string, headers http.Header) TrustedSource {
	t.Helper()
	src, err := r.Resolve(remoteAddr, headers)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", remoteAddr, err)
	}
	return src
}

// Scenario 1 — A spoofed X-Forwarded-For must be ignored entirely when the
// direct peer is NOT a trusted proxy: the canonical source is the direct peer
// IP, never the forged value.
func TestDirectPeerIgnoresSpoofedForwardedFor(t *testing.T) {
	r := &Resolver{
		Pseudonyms:     testPseudonyms(t),
		TrustedProxies: []netip.Prefix{}, // trust nothing
	}
	spoofed := hdr("X-Forwarded-For", "203.0.113.66")
	direct := resolve(t, r, "198.51.100.10:443", spoofed)

	// The pseudonym must derive from the direct peer IP (198.51.100.10), not
	// the forged XFF value (203.0.113.66).
	noHeader := resolve(t, r, "198.51.100.10:443", http.Header{})
	forged := resolve(t, r, "203.0.113.66:443", http.Header{})
	if direct.Pseudonym != noHeader.Pseudonym {
		t.Fatalf("spoofed XFF changed identity: direct=%q want %q", direct.Pseudonym, noHeader.Pseudonym)
	}
	if direct.Pseudonym == forged.Pseudonym {
		t.Fatalf("spoofed XFF was honored: direct=%q equals forged=%q", direct.Pseudonym, forged.Pseudonym)
	}
}

// Scenario 2 — When the direct peer IS a trusted proxy, the X-Forwarded-For
// header is consumed and drives the resolved client.
func TestTrustedProxyAcceptsForwardedFor(t *testing.T) {
	r := &Resolver{
		Pseudonyms:     testPseudonyms(t),
		TrustedProxies: testProxyPrefix(t, "10.0.0.0/8"),
	}

	// Direct peer is a trusted proxy; XFF names the real client.
	client := resolve(t, r, "10.0.0.5:443", hdr("X-Forwarded-For", "198.51.100.7"))
	want := resolve(t, r, "198.51.100.7:0", http.Header{})
	if client.Pseudonym != want.Pseudonym {
		t.Fatalf("trusted proxy XFF not honored: got %q want %q", client.Pseudonym, want.Pseudonym)
	}
}

// Scenario 3 — XFF is walked right-to-left, and only past trusted proxies. The
// first hop that is NOT a trusted proxy is the true client; entries to its left
// (already behind untrusted hops... but in practice the client is never a
// trusted proxy) are not consulted.
func TestRightToLeftTrustedProxyWalk(t *testing.T) {
	// Trusted edge: 10.1.0.1; intermediate trusted proxy 10.1.0.2; client
	// 198.51.100.20 on the far left, with a forged leftmost entry.
	r := &Resolver{
		Pseudonyms:     testPseudonyms(t),
		TrustedProxies: testProxyPrefix(t, "10.0.0.0/8"),
	}
	// XFF reads left-to-right as client->edge; rightmost "10.1.0.1" is trusted,
	// next "10.1.0.2" is trusted, then "198.51.100.20" is NOT trusted => client.
	headers := hdr("X-Forwarded-For", "203.0.113.9, 198.51.100.20, 10.1.0.2, 10.1.0.1")
	got := resolve(t, r, "10.1.0.1:443", headers)
	want := resolve(t, r, "198.51.100.20:0", http.Header{})
	if got.Pseudonym != want.Pseudonym {
		t.Fatalf("right-to-left walk: got %q want client %q", got.Pseudonym, want.Pseudonym)
	}

	// The forged leftmost entry (203.0.113.9) must never be selected when an
	// earlier untrusted hop is present to its right.
	if got.Pseudonym == resolve(t, r, "203.0.113.9:0", http.Header{}).Pseudonym {
		t.Fatal("rightmost-untrusted selection picked a left, untrusted hop")
	}
}

// Scenario 8 — If EVERY hop in the chain is a trusted proxy, there is no
// untrusted hop; the leftmost (original) entry is taken as the client.
func TestAllTrustedProxyChainUsesLeftmost(t *testing.T) {
	r := &Resolver{
		Pseudonyms:     testPseudonyms(t),
		TrustedProxies: testProxyPrefix(t, "10.0.0.0/8"),
	}
	// All hops trusted (client itself never appended its IP as a trusted hop,
	// so the leftmost edge proxy is the best available answer).
	headers := hdr("X-Forwarded-For", "10.0.0.9, 10.1.0.2, 10.1.0.1")
	got := resolve(t, r, "10.1.0.1:443", headers)
	want := resolve(t, r, "10.0.0.9:0", http.Header{})
	if got.Pseudonym != want.Pseudonym {
		t.Fatalf("all-proxy chain: got %q want leftmost %q", got.Pseudonym, want.Pseudonym)
	}
}

// Scenario 4 — IPv4 remote addresses resolve.
func TestResolveIPv4(t *testing.T) {
	r := &Resolver{Pseudonyms: testPseudonyms(t)}
	src, err := r.Resolve("198.51.100.42:5555", http.Header{})
	if err != nil {
		t.Fatalf("IPv4 resolve: %v", err)
	}
	if src.Pseudonym == "" {
		t.Fatal("IPv4 resolve produced empty pseudonym")
	}
}

// Scenario 5 — IPv6 remote addresses parse and resolve.
func TestResolveIPv6(t *testing.T) {
	r := &Resolver{Pseudonyms: testPseudonyms(t)}
	// Bracket form is required for a v6 literal with a port.
	src, err := r.Resolve("[2001:db8::7]:8080", http.Header{})
	if err != nil {
		t.Fatalf("IPv6 resolve: %v", err)
	}
	if src.Pseudonym == "" {
		t.Fatal("IPv6 resolve produced empty pseudonym")
	}
}

// Scenario 6 — IPv6 zone identifiers. A zone is transient link-local routing
// metadata, not part of network identity; the pseudonym must be stable across
// zones for the same address.
func TestIPv6ZoneHandling(t *testing.T) {
	r := &Resolver{Pseudonyms: testPseudonyms(t)}

	a, err := r.Resolve("[fe80::1%eth0]:65000", http.Header{})
	if err != nil {
		t.Fatalf("zone resolve: %v", err)
	}
	b, err := r.Resolve("[fe80::1%eth1]:65001", http.Header{})
	if err != nil {
		t.Fatalf("zone resolve 2: %v", err)
	}

	// P0.6 stable source identity: the zone must be stripped from the canonical
	// address before pseudonymization, so a re-link on %eth0 vs %eth1 does not
	// change the source identity.
	if a.Pseudonym != b.Pseudonym {
		t.Fatalf("zoned IPv6 pseudonym not stable across zones: %q vs %q", a.Pseudonym, b.Pseudonym)
	}
	// Also: the zoned and unzoned forms of the SAME interface must agree.
	plain, err := r.Resolve("[fe80::1]:65002", http.Header{})
	if err != nil {
		t.Fatalf("plain zone resolve: %v", err)
	}
	if plain.Pseudonym != a.Pseudonym {
		t.Fatalf("zoned vs unzoned fe80::1 diverged: %q vs %q", a.Pseudonym, plain.Pseudonym)
	}
}

// Scenario 7 — Malformed forwarding entries (garbage, empty, unspecified)
// must not panic and must be rejected by the strict authoritative resolver.
func TestMalformedForwardingEntriesDegradeSafely(t *testing.T) {
	cases := []struct {
		name string
		xff  string
	}{
		{name: "garbage-single", xff: "not-an-ip"},
		{name: "garbage-mixed", xff: "203.0.113.2,..garbage, 10.0.0.1"},
		{name: "empty-entry", xff: "198.51.100.3, , 10.0.0.1"},
		{name: "trailing-comma", xff: "10.0.0.1,"},
		{name: "only-garbage", xff: "%%%%%%"},
	}
	r := &Resolver{
		Pseudonyms:     testPseudonyms(t),
		TrustedProxies: testProxyPrefix(t, "10.0.0.0/8"),
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Direct peer is a trusted proxy, so the (malformed) chain is parsed.
			if _, err := r.Resolve("10.0.0.1:443", hdr("X-Forwarded-For", tc.xff)); err == nil {
				t.Fatalf("Resolve with malformed XFF %q must fail closed", tc.xff)
			}
		})
	}
}

// Scenario 9 — The same IP with different source ports must map to the same
// pseudonym: port is ephemeral transport detail, not source identity.
func TestSameIPDifferentPortsSamePseudonym(t *testing.T) {
	r := &Resolver{Pseudonyms: testPseudonyms(t)}
	a := resolve(t, r, "198.51.100.10:1000", http.Header{})
	b := resolve(t, r, "198.51.100.10:9999", http.Header{})
	// Also a no-port bare form, if the resolver can parse it.
	// ExtractPeer falls back to the whole string when SplitHostPort fails, so
	// "198.51.100.10" parses as a bare IP.
	c := resolve(t, r, "198.51.100.10", http.Header{})
	if a.Pseudonym != b.Pseudonym || a.Pseudonym != c.Pseudonym {
		t.Fatalf("same IP different ports diverged: %q %q %q", a.Pseudonym, b.Pseudonym, c.Pseudonym)
	}
}

// Scenario 10 — Distinct IPs must produce distinct pseudonyms.
func TestDifferentIPDifferentPseudonym(t *testing.T) {
	r := &Resolver{Pseudonyms: testPseudonyms(t)}
	a := resolve(t, r, "198.51.100.10:443", http.Header{})
	b := resolve(t, r, "198.51.100.11:443", http.Header{})
	if a.Pseudonym == b.Pseudonym {
		t.Fatalf("distinct IPs produced same pseudonym %q", a.Pseudonym)
	}
}

// Scenario 11 — Pseudonym key rotation. The ingress seam never rotates keys
// itself, but the injected *pseudonym.Ring supports it: a value minted under an
// older key version is still accepted by Verify after a ring carries both keys,
// and new derivations use the newest version. This is the rotation contract the
// ingress Resolver relies on for source identity.
func TestPseudonymKeyRotationSupportedByRing(t *testing.T) {
	v1 := mustRing(t, &pseudonym.Key{Version: 1, Secret: []byte("old-secret")})
	rotated := mustRing(t,
		&pseudonym.Key{Version: 1, Secret: []byte("old-secret")},
		&pseudonym.Key{Version: 2, Secret: []byte("new-secret")},
	)
	v2 := mustRing(t, &pseudonym.Key{Version: 2, Secret: []byte("new-secret")})

	adapter1 := &testRingAdapter{ring: v1}
	adapterR := &testRingAdapter{ring: rotated}

	oldVal, err := adapter1.Derive([]byte("source"), []byte("198.51.100.88"))
	if err != nil {
		t.Fatal(err)
	}
	// After rotation, the SAME raw + family mints a NEW-version pseudonym.
	newVal, err := adapterR.Derive([]byte("source"), []byte("198.51.100.88"))
	if err != nil {
		t.Fatal(err)
	}
	if newVal == oldVal {
		t.Fatal("rotated ring must mint a new-version pseudonym")
	}
	// The old value is still verifiable under the rotated ring (backward compat).
	if !rotated.Verify(pseudonym.FamilySource, []byte("198.51.100.88"), oldVal) {
		t.Fatal("rotated ring must still Verify the old-version pseudonym")
	}
	// A maturer ring that has dropped v1 errors out (no cross-version trust).
	if v2.Verify(pseudonym.FamilySource, []byte("198.51.100.88"), oldVal) {
		t.Fatal("v2-only ring must not Verify an old-version pseudonym")
	}

	// End-to-end through the ingress Resolver: same raw peer, different key
	// generations => different pseudonyms (no continuity leak).
	r1 := &Resolver{Pseudonyms: adapter1}
	rR := &Resolver{Pseudonyms: adapterR}
	if resolve(t, r1, "198.51.100.88:1", http.Header{}).Pseudonym == resolve(t, rR, "198.51.100.88:1", http.Header{}).Pseudonym {
		t.Fatal("resolver across key generations must mint different pseudonyms")
	}
}

// Scenario 6 companion — the PeerIP helper (used for source-key derivation in
// consumers) ALSO strips the zone, matching the Resolver's normalization so both
// identity paths are consistent.
func TestPeerIPStripsIPv6Zone(t *testing.T) {
	req := &http.Request{RemoteAddr: "[fe80::1%eth0]:80"}
	got := PeerIP(req)
	if got != "fe80::1" {
		t.Fatalf("PeerIP(%q) = %q, want fe80::1", req.RemoteAddr, got)
	}
}
