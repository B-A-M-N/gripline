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
	"time"

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
// with a nil error (source-scoped features inert for that request).
//
// A NON-NIL error means the configured source identity could not be
// established (malformed peer, pseudonymization failure, ...). The proxy fails
// closed (503, backend never reached) rather than silently degrading to "no
// source" — an explicitly configured source boundary must not disable itself
// on resolver errors. Optional enrichment that is merely absent (no ASN
// metadata configured) is not an error: it returns the identity it could
// establish with a nil error.
type SourceResolver interface {
	ResolveSource(obs Observation) (terminator.TrustedSource, error)
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
	// P0.4C: Derive endpoint family from the request path for enumeration detection.
	f.EndpointFamily = endpointFamily(obs.URLPath)
	return f
}

// endpointFamily classifies the request path into a bounded set of categories
// for endpoint enumeration detection. P0.4C: Do not use raw arbitrary paths
// as unbounded producer keys.
func endpointFamily(path string) string {
	switch path {
	case "/v1/messages":
		return "messages"
	case "/v1/chat/completions":
		return "chat-completions"
	case "/v1/completions":
		return "completions"
	case "/v1/embeddings":
		return "embeddings"
	case "/v1/models":
		return "models"
	default:
		return "other"
	}
}

// NoSource is the default SourceResolver: it derives no trusted source
// identity, so source-scoped features stay inert per request (P0.4 fail-closed
// default — an unknown source is not attributed to any bucket). No error: an
// unconfigured source boundary is a deliberate posture, not a resolution
// failure.
type NoSource struct{}

// ResolveSource returns the zero TrustedSource and a nil error.
func (NoSource) ResolveSource(Observation) (terminator.TrustedSource, error) {
	return terminator.TrustedSource{}, nil
}

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
	// ESTIMATE admission reserves before execution, and the streaming METERING
	// session whose Finish() is what settlement charges. Nil uses the minimal
	// {Requests: 1} both ways — correct for pure-request accounting; token/cost
	// dimension enforcement requires a real provider adapter.
	Usage UsageProvider

	// Observer, when set, receives non-secret operational completion events
	// (P0.9): whether completion evidence persisted, and stream outcomes. It
	// never receives request/response content. Nil means no observation.
	Observer DecisionObserver

	// MaxBodyBytes caps the request body (BETA-08). Inference prompts can be
	// large but are not unbounded. Oversized bodies are rejected with 413
	// BEFORE admission. Zero disables the limit (not recommended).
	MaxBodyBytes int64

	// WriteTimeout is the initial response budget, from WriteHeader until the
	// first deadline expiry. Zero = no server-managed write deadline change
	// (the http.Server's WriteTimeout applies as-is).
	WriteTimeout time.Duration
	// StreamWriteIdleTimeout re-arms the write deadline after EVERY forwarded
	// chunk (P0.16): a streaming response may run arbitrarily long while
	// tokens are flowing, but a stalled stream is cut after this much
	// silence. Requires WriteTimeout > 0 to take effect (the server must run
	// with WriteTimeout 0 so the per-request deadlines govern).
	StreamWriteIdleTimeout time.Duration
}

// UsageProvider is the provider-adapter seam for resource accounting (P0.3,
// P0.8): Estimate is what admission reserves (what is knowable before
// execution); Begin opens the per-request METERING SESSION the moment the
// backend response headers arrive. A session sees every streamed body chunk as
// it is forwarded (ObserveChunk) and produces the settled usage at
// end-of-stream (Finish) — so token/cost enforcement can read the final JSON/SSE
// usage envelope without buffering the stream or retaining prompt/completion
// content. A provider must parse only bounded usage metadata.
type UsageProvider interface {
	Estimate(obs Observation) resource.UsageEstimate
	Begin(obs Observation, resp *http.Response) UsageSession
}

// UsageSession meters ONE in-flight streamed response. ObserveChunk receives
// each body chunk exactly once, in stream order, immediately before the same
// bytes are forwarded to the client. Finish is called exactly once at stream
// end; streamErr is nil for a clean EOF and non-nil when the stream failed
// (upstream read error or client disconnect). The returned estimate is what
// settlement charges. Implementations must not retain chunk contents beyond the
// call.
type UsageSession interface {
	ObserveChunk(chunk []byte)
	Finish(streamErr error) resource.UsageEstimate
}

// NoUsage is the default UsageProvider: one request per admission, settled at
// one request. Token/cost gauges stay inert (a zero estimate reserves nothing,
// and the governor skips unenforced dimensions).
type NoUsage struct{}

func (NoUsage) Estimate(Observation) resource.UsageEstimate {
	return resource.UsageEstimate{Requests: 1}
}

func (NoUsage) Begin(Observation, *http.Response) UsageSession { return noUsageSession{} }

type noUsageSession struct{}

func (noUsageSession) ObserveChunk([]byte) {}
func (noUsageSession) Finish(error) resource.UsageEstimate {
	return resource.UsageEstimate{Requests: 1}
}

// DecisionObserver receives non-secret operational completion events (P0.9).
// The API surface of Outcome.Complete reports persistence failure, but only an
// observer makes that visible in a shipping binary: the client response is
// already delivered and must not change. Implementations receive metadata only
// — never prompts, completions, or credentials.
type DecisionObserver interface {
	// ObserveCompletion is invoked once per completed request. persisted
	// reports whether completion evidence (when any was produced) reached the
	// durable store; err is the persistence/stream error, nil on full success.
	ObserveCompletion(event CompletionEvent)
}

// CompletionEvent is the non-secret completion telemetry record.
type CompletionEvent struct {
	// EvidenceCodes lists completion-signal codes minted for this request.
	EvidenceCodes []string
	// Persisted reports whether minted evidence reached the store.
	Persisted bool
	// StreamOK reports whether the upstream stream ended cleanly.
	StreamOK bool
	// Err is the completion-persistence error, when persistence was attempted
	// and failed.
	Err error
}

// DataPlane is a single terminate-and-forward proxy hop. It is CONCURRENT-SAFE
// (stateless besides the terminator), so a single instance can serve the whole
// edge.
type DataPlane struct {
	cfg     Config
	feat    FeatureResolver
	srcs    SourceResolver
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
	// BETA-08: Enforce MaxBodyBytes BEFORE admission. Reject oversized
	// bodies with 413 before any credential extraction or forwarding.
	if d.cfg.MaxBodyBytes > 0 {
		if r.ContentLength > d.cfg.MaxBodyBytes {
			http.Error(w, "payload_too_large", http.StatusRequestEntityTooLarge)
			return
		}
		// P0.16/P0.6-fix: Bounded spooling for chunked/unknown-length bodies.
		// Read the body with an absolute cap, spooling to a temp file if it
		// exceeds a memory threshold. This prevents an unauthenticated
		// attacker from causing large per-connection allocations (32
		// simultaneous 32MB requests = ~1GB). maxBytes is the actual limit:
		// the spooler sets tooLarge when input remains past it, so an
		// oversized chunked body is rejected 413, never truncated-and-forwarded.
		if r.ContentLength < 0 {
			body, err := spoolBody(r.Body, d.cfg.MaxBodyBytes, spoolMemoryThreshold)
			if err != nil {
				http.Error(w, "bad_request", http.StatusBadRequest)
				return
			}
			r.Body.Close()
			if body.tooLarge {
				_ = body.Close() // closes + removes any temp file
				http.Error(w, "payload_too_large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = body // body.Close() removes the temp file when the transport closes it
			r.ContentLength = body.length
		} else {
			// Known Content-Length within limit: use MaxBytesReader for safety.
			r.Body = http.MaxBytesReader(w, r.Body, d.cfg.MaxBodyBytes)
		}
	}

	// 1. Copy headers so stripping never mutates the caller's request, and so we
	// keep a normalized map for extraction + a pristine one for the backend.
	authHeaders := copyHeaders(r.Header)

	// 2. Terminate the credential BEFORE any adapter sees the request (P0.6):
	// the extraction strips the secret carriers from our copy, and only that
	// sanitized copy is handed to resolvers.
	presented, _, err := terminator.ExtractExternalCredential(authHeaders)
	if err != nil {
		// Even on extraction failure the terminator's safe-reason mapping is
		// reused so no header detail leaks into the response.
		out := &terminator.Outcome{Authorized: false, Reason: "invalid_credential", DenialErr: err}
		d.writeDenial(w, out)
		return
	}
	presented.Zero() // the proxy never needs the raw secret again

	// BETA-01: Build a SANITIZED header view for resolvers. The Observation must
	// never carry secret carriers — resolvers (FeatureResolver, SourceResolver,
	// UsageEstimator) are pluggable adapters that must not see Authorization /
	// x-api-key. We strip a COPY so authHeaders remains intact for
	// Terminator.AdmitUsage, which re-extracts and strips internally.
	obsHeaders := copyHeaders(authHeaders)
	terminator.StripSecretHeaders(obsHeaders)

	obs := Observation{
		Header:     obsHeaders,
		RemoteAddr: remoteIP(r),
		ProtoMajor: r.ProtoMajor,
		URLPath:    r.URL.Path,
	}
	// P0.11-fix: a configured source resolver that FAILS must fail the request
	// closed, not silently degrade to "no source" (which would disable the
	// source boundary exactly when resolution is broken). NoSource and healthy
	// resolvers return a nil error; optional metadata (ASN/region) being absent
	// is not an error.
	src, srcErr := d.srcs.ResolveSource(obs)
	if srcErr != nil {
		w.Header().Set("X-Gripline-Reason", "source_resolution_failed")
		http.Error(w, "source_resolution_failed", http.StatusServiceUnavailable)
		return
	}
	feat := d.feat.Resolve(obs)
	// P0.6B: Merge trusted source network provenance into features. Trusted
	// ingress metadata is the authority; the generic feature resolver's values
	// are spoofable HTTP headers and must not compete with trusted metadata.
	MergeSourceIntoFeatures(&feat, src)
	est := d.cfg.Usage.Estimate(obs)

	out := d.cfg.Terminator.AdmitUsage(authHeaders, feat, src, est)

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
	// freshly minted. Hop-by-hop headers and untrusted provenance headers are
	// also removed from the request path — the proxy must not forward the
	// client's Connection-named or provenance headers to the backend (P0.17/P0.7).
	upstreamHeaders := copyHeaders(r.Header)
	terminator.StripSecretHeaders(upstreamHeaders)
	stripHopByHopHeaders(upstreamHeaders)
	stripUntrustedProvenanceHeaders(upstreamHeaders)
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

	// 6. Copy the backend response headers + status, stream the body back.
	copyResponseHeaders(w.Header(), resp.Header)
	// P0.16 streaming timeouts: when stream_write_idle_timeout is configured,
	// the initial write deadline carries the full write budget; every
	// forwarded chunk then re-arms it to the idle bound. A live SSE stream
	// runs arbitrarily long; a stalled one is cut after the idle silence.
	var rc *http.ResponseController
	streamIdle := time.Duration(0)
	if d.cfg.WriteTimeout > 0 && d.cfg.StreamWriteIdleTimeout > 0 {
		rc = http.NewResponseController(w)
		streamIdle = d.cfg.StreamWriteIdleTimeout
		_ = rc.SetWriteDeadline(time.Now().Add(d.cfg.WriteTimeout))
	}
	w.WriteHeader(resp.StatusCode)
	// P0.8: open the streaming metering session NOW — before any body byte
	// moves — so the meter sees every chunk of the final response, including
	// the SSE/JSON usage envelope that only exists at end-of-stream. The
	// session sees bounded usage metadata only; chunk contents are never
	// retained by the proxy's own flow.
	meter := d.cfg.Usage.Begin(obs, resp)
	// Stream the body, flushing eagerly so SSE/chunked semantics survive the
	// hop (P0.40): a buffering proxy would still produce a correct final body,
	// which is exactly the failure mode a final-concatenation check cannot
	// distinguish from true streaming. Per-chunk Flush keeps chunk arrival
	// times bounded by the backend's, not the response's end.
	flusher, _ := w.(http.Flusher)
	// P0.16: the write deadline alone cannot cut a STALLED stream — a write
	// deadline only fires at write time, and a dead backend produces no
	// writes. The body reader wraps the upstream body with the idle bound so
	// a silent upstream unblocks the loop too.
	var body io.Reader = resp.Body
	if streamIdle > 0 && rc != nil {
		body = newIdleTimeoutReader(resp.Body, streamIdle)
	}
	buf := make([]byte, 32<<10)
	var streamErr error
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			// Meter the chunk first, then forward the SAME bytes unchanged —
			// the meter is a read-only observer of the stream.
			meter.ObserveChunk(buf[:n])
			if _, werr := w.Write(buf[:n]); werr != nil {
				// Client went away; the deferred release runs.
				streamErr = werr
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
			if streamIdle > 0 {
				// P0.16: tokens are flowing — re-arm the idle bound.
				_ = rc.SetWriteDeadline(time.Now().Add(streamIdle))
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				// P0.17: Differentiate real upstream errors from clean EOF.
				streamErr = rerr
			}
			break
		}
	}

	// 7. Settle + complete at ACTUAL end-of-stream (P0.3/P0.36/P0.8/P0.4A).
	// Resource settlement was deliberately NOT done on response headers: for
	// LLM APIs the real usage (token/cost) is reported in the final JSON/SSE
	// envelope, which the metering session has now observed chunk-by-chunk.
	// Finish produces the settled usage from that final surface; a header-only
	// provider implementation still settles correctly here.
	actual := meter.Finish(streamErr)
	// P0.36: only the reserved-but-unused remainder is refunded, and only to this
	// reservation's own buckets. Runs BEFORE the deferred Release so unsettled
	// holds are never cancelled-and-refunded in full. Concurrency is released by
	// the deferred Release.
	if mr, ok := reservation.(*resource.MultiReservation); ok && !mr.Settled() {
		mr.Settle(actual)
	}
	// P0.4A: drive the completion producers with the ACTUAL usage. `success`
	// is false when the upstream stream failed, so a corrupt/failed stream is
	// not credited as clean velocity. This affects SUBSEQUENT admissions.
	completion := out.Complete(actual, streamErr == nil)
	// P0.9: surface completion-persistence failure through the observer seam —
	// the client response is already delivered and must not change, but a
	// shipping binary must not silently discard the Complete() result.
	if d.cfg.Observer != nil {
		d.cfg.Observer.ObserveCompletion(CompletionEvent{
			EvidenceCodes: completion.EvidenceCodes,
			Persisted:     completion.Persisted,
			StreamOK:      streamErr == nil,
			Err:           completion.Err,
		})
	}
	// P0.27/P0.17: Finalize baseline trust ONLY after successful stream
	// completion. A request whose backend stream corrupts/fails earns no clean
	// trust.
	if streamErr == nil {
		out.FinalizeBaseline()
	}
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

// copyResponseHeaders copies backend response headers onto w, stripping
// hop-by-hop headers (including any named by the backend's Connection header)
// and the reserved Gripline-* namespace (P0.17).
func copyResponseHeaders(dst, src http.Header) {
	// Copy everything, then strip hop-by-hop + the internal namespace. Doing it
	// this way keeps one implementation of the Connection-named hop-by-hop rule
	// instead of re-deriving it in the per-key loop.
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	stripHopByHopHeaders(dst)
	for k := range dst {
		// P0.17: Don't forward backend Gripline-* headers to public clients.
		if strings.HasPrefix(strings.ToLower(k), "x-gripline-") ||
			strings.HasPrefix(strings.ToLower(k), "gripline-") {
			dst.Del(k)
		}
	}
}

// fixedHopByHopHeaders is the standard end-to-end hop-by-hop set (RFC 7230
// §6.1). Headers ADDITIONALLY named by Connection are also hop-by-hop.
var fixedHopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

// stripHopByHopHeaders removes hop-by-hop headers from h in place: first every
// header named by the h's own Connection value, then the fixed RFC 7230 set.
// It is used on BOTH the request path (before forwarding upstream) and the
// response path (before relaying to the client), so a header a hop marks
// Connection-requested never leaks to the next hop.
func stripHopByHopHeaders(h http.Header) {
	for _, conn := range h.Values("Connection") {
		for _, name := range strings.Split(conn, ",") {
			if n := strings.TrimSpace(name); n != "" {
				h.Del(n)
			}
		}
	}
	for name := range fixedHopByHopHeaders {
		h.Del(name)
	}
}

// stripUntrustedProvenanceHeaders removes client-supplied provenance headers
// before forwarding to the backend (P0.7). The ingress resolver inspects them
// ONLY when the direct peer is trusted; handing them blindly upstream lets a
// client inventory/convince arbitrary backends of a spoofed source. The proxy
// does not forward any of them — a trusted reverse proxy upstream may re-add
// an authoritative X-Forwarded-For if it terminates the client directly.
func stripUntrustedProvenanceHeaders(h http.Header) {
	for _, name := range []string{
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Real-IP",
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Original-URL",
	} {
		h.Del(name)
	}
}

// remoteIP is a coarse peer-address resolver. It returns the direct remote
// address; a trusted proxy in front is expected to override Peer.IP (RealIP
// resolution is a provider adapter, flagged M4 default).
func remoteIP(r *http.Request) string {
	return r.RemoteAddr
}
