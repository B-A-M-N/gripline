package adapter_test

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/B-A-M-N/gripline/adapter/ingress"
	"github.com/B-A-M-N/gripline/adapter/usage"
)

// These assertions intentionally live outside the adapter packages. They
// prove an external provider can implement the published contracts without
// importing any internal Gripline package.
var (
	_ usage.Provider   = externalUsage{}
	_ ingress.Resolver = externalIngress{}
)

type externalUsage struct{}

func (externalUsage) Estimate(usage.Observation) usage.Estimate { return usage.Estimate{Requests: 1} }
func (externalUsage) Begin(usage.Observation, *http.Response) usage.Session {
	return externalUsageSession{}
}

type externalUsageSession struct{}

func (externalUsageSession) ObserveChunk([]byte)         {}
func (externalUsageSession) Finish(error) usage.Estimate { return usage.Estimate{Requests: 1} }

type externalIngress struct{}

func (externalIngress) ResolveSource(obs ingress.Observation) (ingress.Source, error) {
	return ingress.Source{SourceID: obs.RemoteAddr}, nil
}

func TestExternalAdapterSurface(t *testing.T) {
	_ = ingress.StaticNetworks{{
		Prefix: netip.MustParsePrefix("192.0.2.0/24"), ASN: "AS64500",
		NetworkType: "hosting", Region: "test",
	}}
}
