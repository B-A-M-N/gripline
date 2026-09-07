// Package ingress provides trusted source identity resolution (P0.6).
// It derives canonical source identity from the TCP peer, with optional
// trusted-proxy forwarding-header support.
package ingress

import (
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
	if r.Pseudonyms == nil {
		return TrustedSource{}, nil
	}

	peer, err := ExtractPeer(remoteAddr)
	if err != nil {
		return TrustedSource{}, fmt.Errorf("ingress: extract peer: %w", err)
	}

	canonical := peer.IP

	// If the direct peer is a trusted proxy, parse the forwarding chain.
	if r.isTrustedProxy(peer.IP) {
		if clientIP := r.parseForwardingChain(headers); clientIP.IsValid() && !clientIP.IsUnspecified() {
			canonical = clientIP
		}
	}

	// Normalize a link-local zone off the canonical address (netip keeps it in
	// String()): a zone is transient routing metadata, not part of network
	// identity, so including it would make the pseudonym unstable as the same
	// interface re-links on %eth0 vs %eth1. WithZone("") is a no-op for IPv4 and
	// zoned IPv6 alike.
	canonical = canonical.WithZone("")

	// HMAC-pseudonymize the canonical peer IP.
	pseudonym, err := r.Pseudonyms.Derive([]byte("source"), []byte(canonical.String()))
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

// isTrustedProxy reports whether the given IP is within a trusted-proxy CIDR.
func (r *Resolver) isTrustedProxy(ip netip.Addr) bool {
	for _, prefix := range r.TrustedProxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// parseForwardingChain extracts the client IP from forwarding headers.
// It walks X-Forwarded-For right-to-left, stopping at the first IP that
// is NOT a trusted proxy — that is the client IP as seen by the trusted edge.
// If every hop is a trusted proxy, the leftmost (original) is used.
func (r *Resolver) parseForwardingChain(headers http.Header) netip.Addr {
	// X-Forwarded-For: client, proxy1, proxy2
	xff := headers.Get("X-Forwarded-For")
	if xff == "" {
		return netip.Addr{}
	}

	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(hops[i])
		ip, err := netip.ParseAddr(ipStr)
		if err != nil || ip.IsUnspecified() {
			continue
		}
		// If this hop is not a trusted proxy, it's the client.
		if !r.isTrustedProxy(ip) {
			return ip
		}
	}
	// All hops are trusted proxies — use the leftmost (original client).
	for _, hop := range hops {
		ipStr := strings.TrimSpace(hop)
		if ip, err := netip.ParseAddr(ipStr); err == nil && !ip.IsUnspecified() {
			return ip
		}
	}
	return netip.Addr{}
}
