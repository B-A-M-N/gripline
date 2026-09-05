// Package proxy is the deployable data plane (§0x): it terminates the external
// credential at the edge, runs the terminator's admission pipeline, and streams
// the request to a private backend carrying only the short-lived internal
// assertion — the raw external secret never crosses the boundary (INV-1,
// INV-10, INV-11).
//
// The proxy enforces INV-12 two ways: it STRIPS the external-secret carriers and
// the reserved Gripline-* namespace from anything arriving from the public side,
// and it only ever re-injects an authoritatively-signed assertion after a
// successful admission, on the trusted internal hop to the backend.
package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// assertionHeader is where the internal assertion crosses the boundary on the
// trusted hop to the backend. It lives in the reserved namespace that
// StripSecretHeaders refuses from external ingress, so only the proxy can
// present it post-admission.
const assertionHeader = "X-Gripline-Assertion"

// FeatureResolver derives the normalized lane feature vector from a request
// (peer origin, client family, transport). Real ASN/region attribution is a
// provider adapter; the default resolver covers what is unambiguous from the
// HTTP surface and treats the rest as unknown (zeros are not scored by
// lane.Similarity, so unknown features never cause a false match).
type FeatureResolver interface {
	Resolve(r *http.Request, peer Peer) lane.Features
}

// Peer is the resolved transport-origin view of the request sender.
type Peer struct {
	// IP is the remote address (after any trusted proxy). Empty resolves no
	// SOURCE scope features (unknown).
	IP string
}

// HeaderFeatures implements FeatureResolver from request headers + transport.
// It is the default: deterministic, no external provider.
type HeaderFeatures struct{}

// Resolve derives features present in the request without a provider:
// client family (User-Agent keywords), HTTP version, streaming (Accept /
// X-Stream) — the classification-critical ones the caller can't spoof easily
// are the source-identity dims, which default to unknown here (flagged default:
// real ASN/region attribution is an M4 provider-adapter seam).
func (HeaderFeatures) Resolve(r *http.Request, _ Peer) lane.Features {
	f := lane.Features{
		HTTPVersion: "1.1",
	}
	if r.ProtoMajor == 2 {
		f.HTTPVersion = "2"
	} else if r.ProtoMajor == 3 {
		f.HTTPVersion = "3"
	}
	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "claude-code"):
		f.ClientFamily = "claude-code"
	case strings.Contains(ua, "anthropic") || strings.Contains(ua, "python"):
		f.ClientFamily = "sdk"
	case strings.Contains(ua, "curl"):
		f.ClientFamily = "curl"
	default:
		f.ClientFamily = ""
	}
	// Streaming preference from Accept or the SDK advertisement header.
	if v := r.Header.Get("Accept"); strings.Contains(strings.ToLower(v), "text/event-stream") {
		f.Streaming = "streaming"
	} else if v := r.Header.Get("X-Stream"); v == "true" || v == "1" {
		f.Streaming = "streaming"
	} else {
		f.Streaming = "non-streaming"
	}
	return f
}

// Config wires the data plane. Backend is REQUIRED; Terminator is REQUIRED.
type Config struct {
	Terminator *terminator.Terminator
	Backend    http.RoundTripper // upstream transport (e.g. a *http.Transport to the private backend)
	Features   FeatureResolver   // defaults to HeaderFeatures
	// Audience must match the terminator's audience, so its assertions verify
	// at the backend (INV-11 binding).
	Audience string
}

// DataPlane is a single terminate-and-forward proxy hop. It is CONCURRENT-SAFE
// (stateless besides the terminator), so a single instance can serve the whole
// edge.
type DataPlane struct {
	cfg Config
	feat FeatureResolver
}

// New validates the required seams and returns a DataPlane. Fail-closed: a
// missing backend, terminator, or audience is a construction error, not a
// degraded runtime (matching the terminator's own P0.6 seam contract).
func New(cfg Config) (*DataPlane, error) {
	if cfg.Terminator == nil {
		return nil, fmt.Errorf("proxy: terminator required")
	}
	if cfg.Backend == nil {
		return nil, fmt.Errorf("proxy: backend round tripper required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("proxy: audience required (INV-11)")
	}
	if cfg.Features == nil {
		cfg.Features = HeaderFeatures{}
	}
	return &DataPlane{cfg: cfg, feat: cfg.Features}, nil
}

// ServeHTTP implements the data-plane admission. It is safe to use as an
// http.Handler.
//
// Flow: extract credential → strip secret + reserved headers → terminate
// (admit) → on denial respond with a safe status → on success re-inject the
// signed assertion on the trusted hop → forward → stream back. The resource
// hold is released when the upstream response body finishes.
func (d *DataPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Copy headers so stripping never mutates the caller's request, and so we
	// keep a normalized map for extraction + a pristine one for the backend.
	headers := copyHeaders(r.Header)
	peer := Peer{IP: remoteIP(r)}

	// 2. Terminate. Admit derives the feature vector, but the terminator needs
	// the normalized headers map (it strips internally). We strip here AND let
	// the terminator's own Admit do the authoritative terminal strip.
	feat := d.feat.Resolve(r, peer)
	out := d.cfg.Terminator.Admit(headers, feat)

	if !out.Authorized {
		d.writeDenial(w, out)
		return
	}

	// 3. Resolve the (now stripped + re-injected) upstream headers: every secret
	// carrier and any forged Gripline-* header is gone; the signed assertion is
	// freshly minted.
	upstreamHeaders := copyHeaders(r.Header)
	terminator.StripSecretHeaders(upstreamHeaders)
	upstreamHeaders["X-Gripline-Assertion"] = []string{out.Assertion.Encode()}

	// 4. Build and forward the upstream request, streaming the body.
	upr := r.Clone(r.Context())
	upr.Header = upstreamHeaders
	upr.RequestURI = "" // illegal for client requests after Server round-trip

	resp, err := d.cfg.Backend.RoundTrip(upr)
	if err != nil {
		// Release the multi-scope hold on transport failure — capacity must not
		// leak for a request that never reached the backend.
		if out.ResourceRes != nil {
			out.ResourceRes.Release()
		}
		http.Error(w, "backend_error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 5. Copy the backend response headers + status, stream the body back.
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	// 6. Release the multi-scope hold at end-of-stream once the response has been
	// fully streamed back. Release is idempotent, so the transport-error well is
	// double-released safely. A hosting server that wants the concurrency to span
	// its own response handling must call out.ResourceRes.Release() itself; for
	// the minimal in-process path the default keeps the hold for exactly the
	// request lifecycle.
	if out.ResourceRes != nil {
		out.ResourceRes.Release()
	}
}

// writeDenial maps an admission denial to an HTTP status + safe reason. Internal
// error details never leak the secret or internal state.
func (d *DataPlane) writeDenial(w http.ResponseWriter, out *terminator.Outcome) {
	code := http.StatusForbidden
	switch out.Reason {
	case "concurrency_limit", "rate_limit", "temporarily_restricted":
		code = http.StatusTooManyRequests
	case "invalid_credential", "credential_expired", "bad", "invalid_authentication":
		code = http.StatusUnauthorized
	case "backend_error", "internal_identity_failure", "resource_unavailable":
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("X-Gripline-Reason", out.Reason)
	http.Error(w, out.Reason, code)
}

// copyHeaders clones a header map.
func copyHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		vals := make([]string, len(v))
		copy(vals, v)
		out[k] = vals
	}
	return out
}

// copyResponseHeaders copies backend response headers onto w.
func copyResponseHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// remoteIP is a coarse peer-address resolver. It returns the direct remote
// address; a trusted proxy in front is expected to override Peer.IP (RealIP
// resolution is a provider adapter, flagged M4 default).
func remoteIP(r *http.Request) string {
	return r.RemoteAddr
}