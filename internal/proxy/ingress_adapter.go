package proxy

import (
	"context"

	"github.com/B-A-M-N/gripline/internal/ingress"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// IngressSourceResolver adapts an ingress.Resolver to the proxy.SourceResolver
// interface (P0.6/P0.6B). It derives trusted source identity from the
// sanitized Observation (transport peer + forwarding headers), then merges the
// trusted network provenance into the lane features so spoofable HTTP metadata
// can never compete with trusted ingress metadata.
type IngressSourceResolver struct {
	inner *ingress.Resolver
}

// NewIngressSourceResolver wraps an ingress.Resolver as a proxy.SourceResolver.
func NewIngressSourceResolver(r *ingress.Resolver) *IngressSourceResolver {
	return &IngressSourceResolver{inner: r}
}

// ResolveSource implements proxy.SourceResolver. It returns the trusted source
// identity from the ingress resolver, or the zero TrustedSource when no
// pseudonym ring is configured (nil error). A resolution failure (malformed
// peer, pseudonymization error) is returned as an error so the proxy can fail
// closed instead of silently dropping source protection (P0.11).
func (s *IngressSourceResolver) ResolveSource(obs Observation) (terminator.TrustedSource, error) {
	return s.ResolveSourceContext(context.Background(), obs)
}

// ResolveSourceContext is the request-aware source path. It preserves the
// legacy ResolveSource method for embedders while allowing a clustered ingress
// pseudonym ring to consult shared source aliases without losing cancellation.
func (s *IngressSourceResolver) ResolveSourceContext(ctx context.Context, obs Observation) (terminator.TrustedSource, error) {
	src, err := s.inner.ResolveContext(ctx, obs.RemoteAddr, obs.Header)
	if err != nil {
		return terminator.TrustedSource{}, err
	}
	return terminator.TrustedSource{
		Pseudonym:   src.Pseudonym,
		ASN:         src.ASN,
		NetworkType: src.NetworkType,
		Region:      src.Region,
	}, nil
}

// MergeSourceIntoFeatures overrides the feature resolver's network provenance
// with the trusted source's values (P0.6B). Trusted ingress metadata is the
// authority; the generic feature resolver's values are spoofable HTTP headers
// and must not compete.
func MergeSourceIntoFeatures(feat *lane.Features, src terminator.TrustedSource) {
	if src.ASN != "" {
		feat.NetworkASN = src.ASN
	}
	if src.NetworkType != "" {
		feat.NetworkType = src.NetworkType
	}
	if src.Region != "" {
		feat.RegionClass = src.Region
	}
}
