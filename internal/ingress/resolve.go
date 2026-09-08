// Package ingress provides trusted source identity resolution (P0.6).
// It derives canonical source identity from the TCP peer, with optional
// trusted-proxy forwarding-header support.
package ingress

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// Resolver derives trusted source identity from the transport peer and
// forwarding headers (P0.6). It is the trusted-ingress seam: a production
// deployment supplies one backed by its RealIP configuration and an ASN
// database; the default trusts nothing and returns the zero TrustedSource
// (source-scoped features inert for that request).
type Resolver struct {
	// Pseudonyms is the keyed transform for source identity. Required.
	Pseudonyms PseudonymRing
	// TrustedProxies is the set of CIDR prefixes that may supply forwarding
	// headers. Empty means no trusted proxies (direct peer is canonical).
	TrustedProxies []netip.Prefix
	// Networks resolves ASN/network/region metadata for a source IP.
	// Optional; nil means source metadata is unknown.
	Networks NetworkMetadataResolver
}

// PseudonymRing is the keyed-transform seam for source pseudonymization.
type PseudonymRing interface {
	Derive(family []byte, raw []byte) (string, error)
}

// ContextPseudonymRing is the request-aware extension used when source
// pseudonyms need a shared alias lookup during key rotation. Legacy rings may
// implement only Derive; ResolveContext falls back to that method.
type ContextPseudonymRing interface {
	DeriveContext(context.Context, []byte, []byte) (string, error)
}

// NetworkMetadataResolver resolves ASN/network/region metadata for a source IP.
type NetworkMetadataResolver interface {
	Resolve(ip netip.Addr) (asn string, networkType string, region string, ok bool)
}

// TrustedSource is the authoritative source identity for one request (P0.4).
type TrustedSource struct {
	Pseudonym   string
	ASN         string
	NetworkType string
	Region      string
}

// Resolve derives the trusted source identity from the transport peer and
// forwarding headers. The algorithm:
//
//  1. Parse the direct peer IP from RemoteAddr.
//  2. If the direct peer is a trusted proxy, parse the forwarding chain
//     (X-Forwarded-For) to find the rightmost untrusted IP.
//  3. If the direct peer is NOT a trusted proxy, the direct peer IS the
//     canonical source (forwarding headers from untrusted peers are ignored).
//  4. HMAC-pseudonymize the canonical peer IP.
//  5. Enrich with ASN/network/region metadata if a resolver is configured.
func (r *Resolver) Resolve(remoteAddr string, headers http.Header) (TrustedSource, error) {
	return r.ResolveContext(context.Background(), remoteAddr, headers)
}

// ResolveContext is Resolve with a bounded request context. A clustered
// pseudonym adapter may use it to resolve a pre-rotation source alias from
// shared authority state; cancellation must stop that lookup before admission
// continues.
func (r *Resolver) ResolveContext(ctx context.Context, remoteAddr string, headers http.Header) (TrustedSource, error) {
	if r.Pseudonyms == nil {
		return TrustedSource{}, nil
	}

	canonical, err := CanonicalClientIP(remoteAddr, headers, r.TrustedProxies)
	if err != nil {
		return TrustedSource{}, fmt.Errorf("ingress: canonical client IP: %w", err)
	}

	// Normalize a link-local zone off the canonical address (netip keeps it in
	// String()): a zone is transient routing metadata, not part of network
	// identity, so including it would make the pseudonym unstable as the same
	// interface re-links on %eth0 vs %eth1. WithZone("") is a no-op for IPv4 and
	// zoned IPv6 alike.
	canonical = canonical.WithZone("")

	// HMAC-pseudonymize the canonical peer IP.
	var pseudonym string
	if contextRing, ok := r.Pseudonyms.(ContextPseudonymRing); ok {
		pseudonym, err = contextRing.DeriveContext(ctx, []byte("source"), []byte(canonical.String()))
	} else {
		pseudonym, err = r.Pseudonyms.Derive([]byte("source"), []byte(canonical.String()))
	}
	if err != nil {
		return TrustedSource{}, fmt.Errorf("ingress: pseudonymize: %w", err)
	}

	src := TrustedSource{
		Pseudonym: pseudonym,
	}

	// Enrich with ASN/network/region metadata.
	if r.Networks != nil {
		if asn, netType, region, ok := r.Networks.Resolve(canonical); ok {
			src.ASN = asn
			src.NetworkType = netType
			src.Region = region
		}
	}

	return src, nil
}

// CanonicalClientIP derives the cheap, raw source key used before credential
// authentication. It deliberately performs no pseudonym, database, or ASN
// work. Forwarding headers are considered only when the direct TCP peer is in
// trusted; malformed trusted-proxy chains fall back to that direct peer.
func CanonicalClientIP(remoteAddr string, headers http.Header, trusted []netip.Prefix) (netip.Addr, error) {
	peer, err := ExtractPeer(remoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("extract peer: %w", err)
	}
	canonical := peer.IP
	if !prefixContains(trusted, peer.IP) {
		return canonical.WithZone(""), nil
	}
	hops := forwardingHops(headers)
	if len(hops) == 0 {
		return canonical.WithZone(""), nil
	}
	for _, hop := range hops {
		if hop == "" {
			return canonical.WithZone(""), nil
		}
	}
	parsed := make([]netip.Addr, 0, len(hops))
	for _, raw := range hops {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.IsUnspecified() {
			return canonical.WithZone(""), nil
		}
		parsed = append(parsed, ip)
	}
	for i := len(parsed) - 1; i >= 0; i-- {
		if !prefixContains(trusted, parsed[i]) {
			return parsed[i].WithZone(""), nil
		}
	}
	return parsed[0].WithZone(""), nil
}

func prefixContains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func forwardingHops(headers http.Header) []string {
	values := headers.Values("X-Forwarded-For")
	if len(values) == 0 {
		return nil
	}
	var hops []string
	for _, value := range values {
		for _, raw := range strings.Split(value, ",") {
			hops = append(hops, strings.TrimSpace(raw))
		}
	}
	return hops
}
