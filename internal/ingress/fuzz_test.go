package ingress

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/B-A-M-N/gripline/internal/pseudonym"
)

func FuzzTrustedProxyForwardedFor(f *testing.F) {
	ring, err := pseudonym.NewRing(&pseudonym.Key{Version: 1, Secret: []byte("ingress-fuzz-key")})
	if err != nil {
		f.Fatal(err)
	}
	r := &Resolver{Pseudonyms: &fuzzPseudonymRing{ring: ring}, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	f.Add("10.0.0.5:443", "198.51.100.7, 10.0.0.8")
	f.Fuzz(func(t *testing.T, remote, forwarded string) {
		h := make(http.Header)
		h.Set("X-Forwarded-For", forwarded)
		_, _ = r.Resolve(remote, h)
	})
}

type fuzzPseudonymRing struct{ ring *pseudonym.Ring }

func (r *fuzzPseudonymRing) Derive(family []byte, raw []byte) (string, error) {
	return r.ring.Derive(pseudonym.Family(family), raw)
}
