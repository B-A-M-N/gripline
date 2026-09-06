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
//
// Termination ordering (P0.6): the credential is extracted and stripped BEFORE
// any pluggable adapter (FeatureResolver / SourceResolver) runs, and those
// adapters receive a bounded Observation — never the original *http.Request,
// whose Header still carries Authorization / x-api-key. An adapter cannot log,
// copy, or forward what it is never handed.
package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// assertionHeader is where the internal assertion crosses the boundary on the
// trusted hop to the backend. It lives in the reserved namespace that
// StripSecretHeaders refuses from external ingress, so only the proxy can
// present it post-admission.
const assertionHeader = "X-Gripline-Assertion"

// Observation is the bounded, credential-free view of a request that feature
// and source resolvers may inspect (P0.6). It carries only non-secret
// metadata: transport identity and headers the secret carriers have already
// been stripped from. There is no path from an Observation to the presented
// credential.
type Observation struct {
	// Header is a COPY of the request headers with every secret carrier and
	// reserved Gripline-* header already stripped. Resolvers may read it freely;
	// mutating it affects nothing outside this request's classification.
	Header http.Header
	// RemoteAddr is the transport peer (host:port), after any trusted-proxy
	// resolution the deployment configures.
	RemoteAddr string
	// ProtoMajor is the HTTP major version of the inbound request.
	ProtoMajor int
	// URLPath is the request path (no query), for endpoint-family features.
	URLPath string
}

// FeatureResolver derives the normalized lane feature vector from a sanitized
// Observation (P0.6 — previously the raw *http.Request, exposing the
// credential to every adapter). Real ASN/region attribution is a provider
// adapter; the default resolver covers what is unambiguous from the HTTP
// surface and treats the rest as unknown (zeros are not scored by
// lane.Similarity, so unknown features never cause a false match).
type FeatureResolver interface {
	Resolve(obs Observation) lane.Features
}

// SourceResolver derives the per-request trusted source identity (P0.4) from
// a sanitized Observation. It is the trusted-ingress seam: a production
// deployment supplies one backed by its RealIP configuration and an ASN
// database; the default trusts nothing and returns the zero TrustedSource
// (source-scoped features inert for that request).
type SourceResolver interface {
	ResolveSource(obs Observation) terminator.TrustedSource
}

// Peer is retained for adapter compatibility; resolvers should prefer the
// Observation.RemoteAddr field.
type Peer struct {
	// IP is the remote address (after any trusted proxy). Empty resolves no
	// SOURCE scope features (unknown).
	IP string
}

// HeaderFeatures implements FeatureResolver from sanitized request metadata.
// It is the default: deterministic, no external provider.
type HeaderFeatures struct{}

// Resolve derives features present in the request without a provider:
// client family (User-Agent keywords), HTTP version, streaming (Accept /
// X-Stream) — the classification-critical ones the caller can't spoof easily
// are the source-identity dims, which default to unknown here (flagged default:
// real ASN/region attribution is an M4 provider-adapter seam).
func (HeaderFeatures) Resolve(obs Observation) lane.Features {
	f := lane.Features{
		HTTPVersion: "1.1",
	}
	switch obs.ProtoMajor {
	case 2:
		f.HTTPVersion = "2"
	case 3:
		f.HTTPVersion = "3"
	}
	ua := strings.ToLower(obs.Header.Get("User-Agent"))
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
	if v := obs.Header.Get("Accept"); strings.Contains(strings.ToLower(v), "text/event-stream") {
		f.Streaming = "streaming"
	} else if v := obs.Header.Get("X-Stream"); v == "true" || v == "1" {
		f.Streaming = "streaming"
	} else {
		f.Streaming = "non-streaming"
	}
	return f
}

// NoSource is the default SourceResolver: it derives no trusted source
// identity, so source-scoped features stay inert per request (P0.4 fail-closed
// default — an unknown source is not attributed to any bucket).
type NoSource struct{}

// ResolveSource returns the zero TrustedSource.
func (NoSource) ResolveSource(Observation) terminator.TrustedSource { return terminator.TrustedSource{} }

// Config wires the data plane. Terminator, BackendURL, and Audience are
// REQUIRED (P0.7); Transport is the upstream round tripper (defaults to
// http.DefaultTransport).
type Config struct {
	Terminator *terminator.Terminator
	// BackendURL is the FIXED upstream origin (scheme + host). The client
	// cannot select the upstream host: the forwarded request's scheme/host are
	// always the configured backend's, with only the path safely joined and
	// the query preserved (P0.7).
	BackendURL *url.URL
	// Transport forwards to the backend. Nil defaults to http.DefaultTransport.
	Transport http.RoundTripper
	Features  FeatureResolver // defaults to HeaderFeatures
	// Sources derives per-request trusted source identity (P0.4/P0.6). Nil
	// defaults to NoSource (source-scoped features inert).
	Sources SourceResolver
	// Audience must match the terminator's audience, so its assertions verify
	// at the backend (INV-11 binding).
	Audience string
	// Usage (P0.3) supplies the typed per-dimension usage knowledge: the
	// ESTIMATE admission reserves before execution, and the ACTUAL usage the
	// reservation settles against after the backend responds. Nil uses the
	// minimal {Requests: 1} both ways — correct for pure-request accounting;
	// token/cost dimension enforcement requires a real provider adapter.
	Usage UsageEstimator
}

// UsageEstimator is the provider-adapter seam for resource accounting (P0.3).
// Estimate is what admission reserves (what is knowable before execution);
// Actual is what settlement charges (collected from the backend's response —
// usage headers or a metering API). Actual receives the response so a
// provider adapter can read provider-specific usage headers.
type UsageEstimator interface {
	Estimate(obs Observation) resource.UsageEstimate
	Actual(obs Observation, resp *http.Response) resource.UsageEstimate
}

// NoUsage is the default UsageEstimator: one request per admission, settled
// at one request. Token/cost gauges stay inert (a zero estimate reserves
// nothing, and the governor skips unenforced dimensions).
type NoUsage struct{}

func (NoUsage) Estimate(Observation) resource.UsageEstimate { return resource.UsageEstimate{Requests: 1} }
func (NoUsage) Actual(Observation, *http.Response) resource.UsageEstimate {
	return resource.UsageEstimate{Requests: 1}
}

// DataPlane is a single terminate-and-forward proxy hop. It is CONCURRENT-SAFE
// (stateless besides the terminator), so a single instance can serve the whole
// edge.
type DataPlane struct {
	cfg    Config
	feat   FeatureResolver
	srcs   SourceResolver
	backend *url.URL
}

// New validates the required seams and returns a DataPlane. Fail-closed: a
// missing backend URL, terminator, or audience is a construction error, not a
// degraded runtime (matching the terminator's own P0.6 seam contract).
func New(cfg Config) (*DataPlane, error) {
	if cfg.Terminator == nil {
		return nil, fmt.Errorf("proxy: terminator required")
	}
	if cfg.BackendURL == nil || cfg.BackendURL.Host == "" {
		return nil, fmt.Errorf("proxy: fixed backend URL required (P0.7)")
	}
	if cfg.BackendURL.Scheme != "http" && cfg.BackendURL.Scheme != "https" {
		return nil, fmt.Errorf("proxy: backend URL scheme must be http/https, got %q", cfg.BackendURL.Scheme)
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("proxy: audience required (INV-11)")
	}
	if cfg.Transport == nil {
		cfg.Transport = http.DefaultTransport
	}
	if cfg.Features == nil {
		cfg.Features = HeaderFeatures{}
	}
	if cfg.Sources == nil {
		cfg.Sources = NoSource{}
	}
	if cfg.Usage == nil {
		cfg.Usage = NoUsage{}
	}
	bu := *cfg.BackendURL
	bu.User = nil
	bu.RawQuery = ""
	bu.Fragment = ""
	bu.Path = strings.TrimSuffix(bu.Path, "/") // joined per-request below
	return &DataPlane{cfg: cfg, feat: cfg.Features, srcs: cfg.Sources, backend: &bu}, nil
}

// ServeHTTP implements the data-plane admission. It is safe to use as an
// http.Handler.
//
// Flow: extract credential → strip secret + reserved headers → build the
// sanitized Observation → resolve features/source from sanitized metadata only
// (P0.6) → terminate (admit) → on denial respond with a safe status → on
// success defer the reservation release (P0.8/P0.9: panic-safe, idempotent) →
// re-inject the signed assertion on the trusted hop → forward to the FIXED
// backend (P0.7) → stream back.
func (d *DataPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Copy headers so stripping never mutates the caller's request, and so we
	// keep a normalized map for extraction + a pristine one for the backend.
	headers := copyHeaders(r.Header)

	// 2. Terminate the credential BEFORE any adapter sees the request (P0.6):
	// the extraction strips the secret carriers from our copy, and only that
	// sanitized copy is handed to resolvers.
	presented, _, err := terminator.ExtractExternalCredential(headers)
	if err != nil {
		// Even on extraction failure the terminator's safe-reason mapping is
		// reused so no header detail leaks into the response.
		out := &terminator.Outcome{Authorized: false, Reason: "invalid_credential", DenialErr: err}
		d.writeDenial(w, out)
		return
	}
	presented.Zero() // the proxy never needs the raw secret again

	obs := Observation{
		Header:     headers,
		RemoteAddr: remoteIP(r),
		ProtoMajor: r.ProtoMajor,
		URLPath:    r.URL.Path,
	}
	feat := d.feat.Resolve(obs)
	src := d.srcs.ResolveSource(obs)
	est := d.cfg.Usage.Estimate(obs)

	out := d.cfg.Terminator.AdmitUsage(headers, feat, src, est)

	if !out.Authorized {
		d.writeDenial(w, out)
		return
	}

	// 3. Panic-safe reservation lifecycle (P0.8/P0.9): one abstraction for every
	// reservation shape, released exactly once via defer before ANY subsequent
	// code can leak it. Release is idempotent; for the multi-scope governor
	// reservation it cancels any NOT-yet-settled token hold, so the settle below
	// must run first (P0.3 settle-with-actuals, then release).
	reservation := out.Reservation()
	defer reservation.Release()

	// 4. Resolve the (now stripped + re-injected) upstream headers: every secret
	// carrier and any forged Gripline-* header is gone; the signed assertion is
	// freshly minted.
	upstreamHeaders := copyHeaders(r.Header)
	terminator.StripSecretHeaders(upstreamHeaders)
	upstreamHeaders[assertionHeader] = []string{out.Assertion.Encode()}

	// 5. Build and forward the upstream request, streaming the body. The
	// upstream origin is the CONFIGURED backend (P0.7): scheme and host come
	// from BackendURL, the path is safely joined, and the client's query is
	// preserved. The client cannot redirect the proxy at another host.
	upr := r.Clone(r.Context())
	upr.Header = upstreamHeaders
	upr.URL = &url.URL{
		Scheme:   d.backend.Scheme,
		Host:     d.backend.Host,
		Path:     joinPath(d.backend.Path, r.URL.Path),
		RawQuery: r.URL.RawQuery,
	}
	// The Host HEADER must also be the backend's (not the client's chosen
	// origin) — Transport routes by URL.Host but writes req.Host as the Host
	// header, so leaving the client's value here would leak a wrong (or
	// attacker-chosen) Host to the backend. The backend URL's own Host header
	// override (its URL.Host) is what a plain reverse proxy would send.
	upr.Host = d.backend.Host
	upr.RequestURI = "" // illegal for client requests after Server round-trip

	resp, err := d.cfg.Transport.RoundTrip(upr)
	if err != nil {
		// Upstream never accepted the request: no baseline credit (P0.27 — an
		// admitted request that fails before any useful workload is not clean
		// trust-building activity). The deferred Release cancels the unsettled
		// reservation, refunding the full estimate hold (P0.36).
		http.Error(w, "backend_error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// The backend ACCEPTED the request (transport + response head received):
	// this is the "upstream accepted" lifecycle event (P0.27). Finalize the
	// deferred baseline credit exactly once — a request that was admitted but
	// never reached the backend earns no trust.
	out.FinalizeBaseline()

	// Settle the resource reservation against ACTUAL usage (P0.3/P0.36): only
	// the reserved-but-unused remainder is refunded, and only to this
	// reservation's own buckets. Runs BEFORE the deferred Release so unsettled
	// holds are never cancelled-and-refunded in full. Concurrency is released
	// by the deferred Release.
	if mr, ok := reservation.(*resource.MultiReservation); ok && !mr.Settled() {
		mr.Settle(d.cfg.Usage.Actual(obs, resp))
	}

	// 6. Copy the backend response headers + status, stream the body back.
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// joinPath joins a configured backend base path with the request path without
// allowing traversal out of the base (P0.7). The result is always rooted and
// cleaned.
func joinPath(base, req string) string {
	if base == "" {
		return path.Clean("/" + req)
	}
	return path.Clean(base + "/" + req)
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