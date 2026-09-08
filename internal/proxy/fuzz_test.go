package proxy

import "testing"

func FuzzPathAndEncodingNormalization(f *testing.F) {
	f.Add("/v1", "/messages", "identity")
	f.Fuzz(func(t *testing.T, base, request, encoding string) {
		_ = joinPath(base, request)
		_ = unsupportedContentEncoding([]string{encoding})
		d := &DataPlane{cfg: Config{EndpointRules: defaultEndpointRules()}}
		_, _ = d.routeStatus("POST", request)
	})
}
