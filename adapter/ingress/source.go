// Package ingress contains the provider-facing trusted-source contract. It is
// deliberately independent of Gripline's internal lane and credential types.
package ingress

import (
	"net/http"
	"net/netip"
)

// Observation is the sanitized request view supplied to a source adapter.
type Observation struct {
	Header     http.Header
	RemoteAddr string
}

// Source is the non-secret source identity and optional trusted enrichment.
type Source struct {
	SourceID    string
	ASN         string
	NetworkType string
	Region      string
}

// Resolver derives a source from a sanitized observation. Implementations must
// only trust forwarding metadata from an authenticated/configured edge.
type Resolver interface {
	ResolveSource(Observation) (Source, error)
}

// NetworkMetadataResolver resolves provider-controlled metadata for a canonical
// source IP. It is never called with an address selected from an untrusted
// forwarding header.
type NetworkMetadataResolver interface {
	Resolve(netip.Addr) (asn, networkType, region string, ok bool)
}

// NetworkMapping is a bounded, provider-authored CIDR-to-metadata mapping.
type NetworkMapping struct {
	Prefix      netip.Prefix
	ASN         string
	NetworkType string
	Region      string
}

// StaticNetworks is a deterministic local metadata adapter. Longest-prefix
// match wins, and no network lookup is performed outside the configured map.
type StaticNetworks []NetworkMapping

func (s StaticNetworks) Resolve(ip netip.Addr) (string, string, string, bool) {
	var best NetworkMapping
	matched := false
	for _, m := range s {
		if m.Prefix.Contains(ip) && (!matched || m.Prefix.Bits() > best.Prefix.Bits()) {
			best, matched = m, true
		}
	}
	if !matched {
		return "", "", "", false
	}
	return best.ASN, best.NetworkType, best.Region, true
}
