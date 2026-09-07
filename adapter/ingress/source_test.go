package ingress

import (
	"net/netip"
	"testing"
)

func TestStaticNetworksLongestPrefix(t *testing.T) {
	s := StaticNetworks{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), ASN: "AS1", Region: "NA"},
		{Prefix: netip.MustParsePrefix("192.0.2.8/32"), ASN: "AS2", NetworkType: "hosting", Region: "EU"},
	}
	asn, typ, region, ok := s.Resolve(netip.MustParseAddr("192.0.2.8"))
	if !ok || asn != "AS2" || typ != "hosting" || region != "EU" {
		t.Fatalf("metadata=%q/%q/%q/%v", asn, typ, region, ok)
	}
}
