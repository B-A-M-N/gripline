package proxy

import (
	"net/http"

	publicingress "github.com/B-A-M-N/gripline/adapter/ingress"
	publicusage "github.com/B-A-M-N/gripline/adapter/usage"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// AdaptUsageProvider bridges the public provider-facing contract into the
// internal resource accounting types. Provider integrations only implement
// adapter/usage and never import an internal package.
func AdaptUsageProvider(p publicusage.Provider) UsageProvider {
	if p == nil {
		return NoUsage{}
	}
	return publicUsageProvider{provider: p}
}

type publicUsageProvider struct{ provider publicusage.Provider }

func (p publicUsageProvider) Estimate(obs Observation) resource.UsageEstimate {
	e := p.provider.Estimate(publicusage.Observation{
		Header: obs.Header, RemoteAddr: obs.RemoteAddr, ProtoMajor: obs.ProtoMajor,
		Method: obs.Method, URLPath: obs.URLPath, UsageProfile: publicusage.UsageProfile(obs.UsageProfile),
		BodySize: obs.BodySize, MaxBodyBytes: obs.MaxBodyBytes,
	})
	return resource.UsageEstimate{
		Requests: e.Requests, InputTokens: e.InputTokens, OutputTokens: e.OutputTokens,
		CombinedTokens: e.CombinedTokens, CacheReadInputTokens: e.CacheReadInputTokens,
		CacheCreationInputTokens: e.CacheCreationInputTokens, CacheCreation5mInputTokens: e.CacheCreation5mInputTokens,
		CacheCreation1hInputTokens: e.CacheCreation1hInputTokens, CostConservative: e.CostConservative,
		CostMicrounits: e.CostMicrounits,
	}
}

func (p publicUsageProvider) Begin(obs Observation, resp *http.Response) UsageSession {
	return publicUsageSession{session: p.provider.Begin(publicusage.Observation{
		Header: obs.Header, RemoteAddr: obs.RemoteAddr, ProtoMajor: obs.ProtoMajor,
		Method: obs.Method, URLPath: obs.URLPath, UsageProfile: publicusage.UsageProfile(obs.UsageProfile),
		BodySize: obs.BodySize, MaxBodyBytes: obs.MaxBodyBytes,
	}, resp)}
}

type publicUsageSession struct{ session publicusage.Session }

func (s publicUsageSession) ObserveChunk(chunk []byte) { s.session.ObserveChunk(chunk) }

func (s publicUsageSession) Finish(err error) resource.UsageEstimate {
	e := s.session.Finish(err)
	return resource.UsageEstimate{
		Requests: e.Requests, InputTokens: e.InputTokens, OutputTokens: e.OutputTokens,
		CombinedTokens: e.CombinedTokens, CacheReadInputTokens: e.CacheReadInputTokens,
		CacheCreationInputTokens: e.CacheCreationInputTokens, CacheCreation5mInputTokens: e.CacheCreation5mInputTokens,
		CacheCreation1hInputTokens: e.CacheCreation1hInputTokens, CostConservative: e.CostConservative,
		CostMicrounits: e.CostMicrounits,
	}
}

// AdaptSourceResolver bridges the public trusted-source contract into the
// internal identity used by admission. The public adapter receives only the
// already sanitized observation.
func AdaptSourceResolver(r publicingress.Resolver) SourceResolver {
	if r == nil {
		return NoSource{}
	}
	return publicSourceResolver{resolver: r}
}

type publicSourceResolver struct{ resolver publicingress.Resolver }

func (r publicSourceResolver) ResolveSource(obs Observation) (terminator.TrustedSource, error) {
	s, err := r.resolver.ResolveSource(publicingress.Observation{Header: obs.Header, RemoteAddr: obs.RemoteAddr})
	if err != nil {
		return terminator.TrustedSource{}, err
	}
	return terminator.TrustedSource{Pseudonym: s.SourceID, ASN: s.ASN, NetworkType: s.NetworkType, Region: s.Region}, nil
}
