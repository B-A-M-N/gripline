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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/observability"
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
	// Method is the normalized HTTP method used for route/profile selection.
	Method string
	// URLPath is the request path (no query), for endpoint-family features.
	URLPath string
	// UsageProfile binds metering to an explicit route schema when configured.
	UsageProfile string
	// BodySize is the declared request size, or -1 when unknown. It lets a
	// provider adapter make a bounded pre-execution estimate without receiving
	// the body itself.
	BodySize int64
	// MaxBodyBytes is the configured hard request ceiling. It lets a usage
	// adapter reserve conservatively for chunked requests whose ContentLength is
	// unknown.
	MaxBodyBytes int64
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

// ContextSourceResolver is the request-aware extension of SourceResolver.
// Implementations that consult shared authority state use this path so a
// canceled request cannot leave a database lookup running into admission.
type ContextSourceResolver interface {
	ResolveSourceContext(context.Context, Observation) (terminator.TrustedSource, error)
}

// PreAuthSourceResolver derives only a cheap, raw source key for the
// pre-authentication limiter. It must not perform pseudonym, database, ASN, or
// other expensive enrichment work. A failure falls back to the direct peer;
// the full SourceResolver still fails closed later if configured.
type PreAuthSourceResolver interface {
	ResolvePreAuthSource(obs Observation) (string, error)
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
	case "/v1/responses":
		return "responses"
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
	// PreAuthSource derives the trusted-proxy-aware raw source bucket before
	// credential authentication. Nil uses the direct TCP peer.
	PreAuthSource PreAuthSourceResolver
	// Audience must match the terminator's audience, so its assertions verify
	// at the backend (INV-11 binding).
	Audience string
	// EndpointRules is the exact public method/path allowlist. Nil selects the
	// built-in inference-only contract; a non-nil empty slice denies all paths.
	EndpointRules []EndpointRule
	// ForbiddenPath reserves the configured verifier-control path from the
	// public data plane, even if an operator accidentally includes it in a
	// custom endpoint contract.
	ForbiddenPath string
	// Pre-authentication limits protect HMAC/authority work from invalid-key
	// floods. They are not authorization policy and are released immediately
	// after admission returns.
	PreAuthMaxConcurrent           int
	PreAuthRequestsPerSecond       int
	PreAuthSourceRequestsPerSecond int
	PreAuthMaxSources              int
	PreAuthSourceIdle              time.Duration
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
	// Admission receives the authoritative decision immediately after the
	// terminator returns, including early denials. It is separate from the
	// completion observer because the response may stream for an arbitrary time.
	Admission AdmissionObserver
	// RequestIDGenerator creates the ingress correlation id before any request
	// work. Production defaults to terminator.NewRequestID; the error return is
	// surfaced as a controlled 503 when the CSPRNG is unavailable.
	RequestIDGenerator func() (string, error)

	// MaxBodyBytes caps the request body (BETA-08). Inference prompts can be
	// large but are not unbounded. Oversized bodies are rejected with 413
	// BEFORE admission. Zero disables the limit (not recommended).
	MaxBodyBytes int64
	// SpoolDir is the optional dedicated writable directory for unknown-length
	// request bodies. Empty uses the process temp directory.
	SpoolDir string
	// SpoolMaxBytes and SpoolMaxFiles bound aggregate unknown-length request
	// body work. A reservation is held from admission until the body is closed;
	// zero disables that particular aggregate bound.
	SpoolMaxBytes int64
	SpoolMaxFiles int
	// ReservationRenewEvery is the heartbeat for distributed usage leases.
	// Zero leaves renewal to the authority's own lifecycle.
	ReservationRenewEvery time.Duration

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

// AdmissionObserver receives exactly one credential-safe decision projection
// per request, immediately after admission. Implementations should make the
// callback non-blocking or bounded so telemetry cannot become an authorization
// dependency.
type AdmissionObserver interface {
	ObserveAdmission(record *observability.DecisionRecord)
}

// CompletionEvent is the non-secret completion telemetry record.
type CompletionEvent struct {
	// RequestID correlates completion telemetry with its admission decision.
	RequestID string `json:"request_id"`
	// CredentialID and LaneID are bounded internal identifiers used for
	// investigation, never raw credentials or prompt content.
	CredentialID string `json:"credential_id,omitempty"`
	LaneID       string `json:"lane_id,omitempty"`
	// EvidenceCodes lists completion-signal codes minted for this request.
	EvidenceCodes []string `json:"evidence_codes"`
	// Persisted reports whether minted evidence reached the store.
	Persisted bool `json:"persisted"`
	// StreamOK reports whether the upstream stream ended cleanly.
	StreamOK bool `json:"stream_ok"`
	// ErrorCode and ErrorMessage are the bounded JSON contract. ErrorMessage is
	// intentionally a fixed safe phrase; implementation errors stay in process
	// memory and are never serialized into telemetry.
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	// Err remains available to in-process observers for compatibility but is
	// never serialized as Go's error interface commonly becomes `{}`.
	Err error `json:"-"`
}

// EndpointRule is an exact public data-plane authorization rule. Endpoint
// family classification remains telemetry only; a method/path must be
// explicitly present here before authentication work or backend forwarding.
type EndpointRule struct {
	Method        string
	Path          string
	RequiredScope string
	UsageProfile  string
}

func defaultEndpointRules() []EndpointRule {
	return []EndpointRule{
		{Method: http.MethodPost, Path: "/v1/messages", RequiredScope: "inference"},
		{Method: http.MethodPost, Path: "/v1/responses", RequiredScope: "inference"},
		{Method: http.MethodPost, Path: "/v1/chat/completions", RequiredScope: "inference"},
		{Method: http.MethodPost, Path: "/v1/completions", RequiredScope: "inference"},
		{Method: http.MethodPost, Path: "/v1/embeddings", RequiredScope: "inference"},
		{Method: http.MethodGet, Path: "/v1/models", RequiredScope: "inference"},
	}
}

// DataPlane is a single terminate-and-forward proxy hop. It is CONCURRENT-SAFE
// (stateless besides the terminator), so a single instance can serve the whole
// edge.
type DataPlane struct {
	cfg     Config
	feat    FeatureResolver
	srcs    SourceResolver
	backend *url.URL
	spool   *SpoolBudget
	preAuth *preAuthGuard
	routes  map[routeKey]EndpointRule
	metrics proxyMetrics
}

type routeKey struct {
	method string
	path   string
}

// MetricsSnapshot is a low-cardinality operational view of the data plane.
// It intentionally contains counts and outcome classes only; request IDs,
// credentials, paths, and provider content do not belong in a metrics label.
type MetricsSnapshot struct {
	Admissions                   uint64
	Authorizations               uint64
	Denials                      uint64
	AuthenticationFail           uint64
	Degraded                     uint64
	ResourceDenials              uint64
	PolicyDenials                uint64
	PayloadTooLarge              uint64
	SpoolRejects                 uint64
	CompletionFailures           uint64
	BackendFailures              uint64
	Backend4xx                   uint64
	Backend5xx                   uint64
	EntropyFailures              uint64
	ActiveStreams                uint64
	EvidenceEvents               uint64
	UsageSessions                uint64
	UsageInputTokens             uint64
	UsageOutputTokens            uint64
	UsageCombinedTokens          uint64
	UsageCostMicrounits          uint64
	UsageConservativeSettlements uint64
	HTTP2Errors                  uint64
	PreAuthSourceTableSaturated  uint64
	PreAuthOverflowAssignments   uint64
	PreAuthOverflowDenials       uint64
	ResourceDenialsByScope       [5]uint64
	ResourceDenialsByDimension   [6]uint64
	Spool                        SpoolStats
}

type proxyMetrics struct {
	admissions, authorizations, denials, authenticationFail   atomic.Uint64
	degraded, resourceDenials, policyDenials, payloadTooLarge atomic.Uint64
	spoolRejects, completionFailures, backendFailures         atomic.Uint64
	backend4xx, backend5xx, activeStreams, evidenceEvents     atomic.Uint64
	entropyFailures                                           atomic.Uint64
	usageSessions, usageInputTokens, usageOutputTokens        atomic.Uint64
	usageCombinedTokens, usageCostMicrounits                  atomic.Uint64
	usageConservativeSettlements                              atomic.Uint64
	http2Errors                                               atomic.Uint64
	resourceByScope                                           [5]atomic.Uint64
	resourceByDim                                             [6]atomic.Uint64
}

func (d *DataPlane) Metrics() MetricsSnapshot {
	if d == nil {
		return MetricsSnapshot{}
	}
	snapshot := MetricsSnapshot{
		Admissions: d.metrics.admissions.Load(), Authorizations: d.metrics.authorizations.Load(),
		Denials: d.metrics.denials.Load(), AuthenticationFail: d.metrics.authenticationFail.Load(),
		Degraded: d.metrics.degraded.Load(), ResourceDenials: d.metrics.resourceDenials.Load(),
		PolicyDenials: d.metrics.policyDenials.Load(), PayloadTooLarge: d.metrics.payloadTooLarge.Load(),
		SpoolRejects: d.metrics.spoolRejects.Load(), CompletionFailures: d.metrics.completionFailures.Load(),
		BackendFailures: d.metrics.backendFailures.Load(), Backend4xx: d.metrics.backend4xx.Load(),
		Backend5xx: d.metrics.backend5xx.Load(), ActiveStreams: d.metrics.activeStreams.Load(),
		EntropyFailures: d.metrics.entropyFailures.Load(),
		EvidenceEvents:  d.metrics.evidenceEvents.Load(),
		UsageSessions:   d.metrics.usageSessions.Load(), UsageInputTokens: d.metrics.usageInputTokens.Load(),
		UsageOutputTokens: d.metrics.usageOutputTokens.Load(), UsageCombinedTokens: d.metrics.usageCombinedTokens.Load(),
		UsageCostMicrounits:          d.metrics.usageCostMicrounits.Load(),
		UsageConservativeSettlements: d.metrics.usageConservativeSettlements.Load(),
		HTTP2Errors:                  d.metrics.http2Errors.Load(),
		Spool:                        d.spool.Stats(),
	}
	preAuth := d.preAuth.metricsSnapshot()
	snapshot.PreAuthSourceTableSaturated = preAuth.SourceTableSaturated
	snapshot.PreAuthOverflowAssignments = preAuth.OverflowAssignments
	snapshot.PreAuthOverflowDenials = preAuth.OverflowDenials
	for i := range snapshot.ResourceDenialsByScope {
		snapshot.ResourceDenialsByScope[i] = d.metrics.resourceByScope[i].Load()
	}
	for i := range snapshot.ResourceDenialsByDimension {
		snapshot.ResourceDenialsByDimension[i] = d.metrics.resourceByDim[i].Load()
	}
	return snapshot
}

// RecordHTTP2Error receives the low-cardinality protocol error callback from
// x/net/http2. The detailed library error string is intentionally not stored
// as a metric label; only the bounded total is exposed.
func (d *DataPlane) RecordHTTP2Error(_ string) {
	if d != nil {
		d.metrics.http2Errors.Add(1)
	}
}

func (d *DataPlane) recordUsage(actual resource.UsageEstimate) {
	d.metrics.usageSessions.Add(1)
	if actual.CostConservative {
		d.metrics.usageConservativeSettlements.Add(1)
	}
	if actual.InputTokens > 0 {
		d.metrics.usageInputTokens.Add(uint64(actual.InputTokens))
	}
	if actual.OutputTokens > 0 {
		d.metrics.usageOutputTokens.Add(uint64(actual.OutputTokens))
	}
	if actual.CombinedTokens > 0 {
		d.metrics.usageCombinedTokens.Add(uint64(actual.CombinedTokens))
	}
	if actual.CostMicrounits > 0 {
		d.metrics.usageCostMicrounits.Add(uint64(actual.CostMicrounits))
	}
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
	if cfg.BackendURL.User != nil || cfg.BackendURL.RawQuery != "" || cfg.BackendURL.Fragment != "" {
		return nil, fmt.Errorf("proxy: backend URL must not contain userinfo, query, or fragment")
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
	if cfg.EndpointRules == nil {
		cfg.EndpointRules = defaultEndpointRules()
	}
	routes := make(map[routeKey]EndpointRule, len(cfg.EndpointRules))
	for i := range cfg.EndpointRules {
		rule, err := normalizeEndpointRule(cfg.EndpointRules[i])
		if err != nil {
			return nil, fmt.Errorf("proxy: endpoint rule %d: %w", i, err)
		}
		key := routeKey{method: rule.Method, path: rule.Path}
		if _, exists := routes[key]; exists {
			return nil, fmt.Errorf("proxy: duplicate endpoint rule %s %s", rule.Method, rule.Path)
		}
		cfg.EndpointRules[i] = rule
		routes[key] = rule
	}
	bu := *cfg.BackendURL
	bu.User = nil
	bu.RawQuery = ""
	bu.Fragment = ""
	bu.Path = strings.TrimSuffix(bu.Path, "/") // joined per-request below
	return &DataPlane{cfg: cfg, feat: cfg.Features, srcs: cfg.Sources, backend: &bu, routes: routes,
		spool: NewSpoolBudget(cfg.SpoolMaxBytes, cfg.SpoolMaxFiles),
		preAuth: newPreAuthGuard(cfg.PreAuthMaxConcurrent, cfg.PreAuthRequestsPerSecond,
			cfg.PreAuthSourceRequestsPerSecond, cfg.PreAuthMaxSources, cfg.PreAuthSourceIdle)}, nil
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
	requestIDGenerator := d.cfg.RequestIDGenerator
	if requestIDGenerator == nil {
		requestIDGenerator = terminator.NewRequestID
	}
	requestID, requestIDErr := requestIDGenerator()
	if requestIDErr != nil {
		d.metrics.entropyFailures.Add(1)
		d.metrics.admissions.Add(1)
		d.metrics.denials.Add(1)
		w.Header().Set("X-Gripline-Reason", "entropy_unavailable")
		http.Error(w, "internal security unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("X-Gripline-Request-ID", requestID)
	var observed bool
	observeAdmission := func(out *terminator.Outcome) {
		if observed {
			return
		}
		observed = true
		d.metrics.admissions.Add(1)
		if out != nil && out.Authorized {
			d.metrics.authorizations.Add(1)
		} else {
			d.metrics.denials.Add(1)
			if out != nil {
				var limitErr *resource.ScopeLimitError
				if errors.As(out.DenialErr, &limitErr) {
					if int(limitErr.Scope) >= 0 && int(limitErr.Scope) < len(d.metrics.resourceByScope) {
						d.metrics.resourceByScope[limitErr.Scope].Add(1)
					}
					if int(limitErr.Dimension) >= 0 && int(limitErr.Dimension) < len(d.metrics.resourceByDim) {
						d.metrics.resourceByDim[limitErr.Dimension].Add(1)
					}
				}
				switch out.Reason {
				case "invalid_authentication", "invalid_credential", "credential_revoked", "credential_restricted", "credential_expired":
					d.metrics.authenticationFail.Add(1)
				case "spool_capacity_exhausted":
					d.metrics.spoolRejects.Add(1)
				case "rate_limit", "resource_unavailable":
					d.metrics.resourceDenials.Add(1)
				case "temporarily_restricted", "policy_denied":
					d.metrics.policyDenials.Add(1)
				case "payload_too_large":
					d.metrics.payloadTooLarge.Add(1)
				}
			}
			if out != nil && out.Degraded {
				d.metrics.degraded.Add(1)
			}
		}
		if d.cfg.Admission != nil {
			d.cfg.Admission.ObserveAdmission(observability.New(out))
		}
	}
	// Any guard that returns before the normal admission call still produces
	// one correlated denial record.
	defer func() {
		if !observed {
			observeAdmission(&terminator.Outcome{RequestID: requestID, Reason: "internal_error"})
		}
	}()
	if unsupportedContentEncoding(r.Header.Values("Content-Encoding")) {
		observeAdmission(&terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "unsupported_content_encoding"})
		w.Header().Set("X-Gripline-Reason", "unsupported_content_encoding")
		http.Error(w, "unsupported content encoding", http.StatusUnsupportedMediaType)
		return
	}
	// Reject unknown methods/paths before credential authentication and full
	// admission. An endpoint that can never be forwarded must not spend HMAC,
	// authority, evidence, or resource-reservation work.
	requestPath := r.URL.EscapedPath()
	if requestPath == "" {
		requestPath = "/"
	}
	if d.cfg.ForbiddenPath != "" && requestPath == path.Clean(d.cfg.ForbiddenPath) {
		out := &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "forbidden_control_endpoint"}
		observeAdmission(out)
		w.Header().Set("X-Gripline-Reason", "forbidden_control_endpoint")
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if status, allow := d.routeStatus(r.Method, requestPath); status != 0 {
		reason := "unsupported_endpoint"
		if status == http.StatusMethodNotAllowed {
			reason = "unsupported_method"
		}
		out := &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: reason}
		observeAdmission(out)
		if allow != "" {
			w.Header().Set("Allow", allow)
		}
		w.Header().Set("X-Gripline-Reason", reason)
		http.Error(w, http.StatusText(status), status)
		return
	}

	// Copy headers before any body work. Credential parsing and the full
	// admission pipeline run before unknown-length request bodies can force disk
	// spooling.
	authHeaders := copyHeaders(r.Header)
	// Remove recognized credential carriers and the reserved internal namespace
	// from the original request immediately. The auth copy above is the only
	// place that may still carry the external credential, and it is consumed by
	// the terminator below. Keeping the raw header on r longer would enlarge the
	// accidental logging/panic/heap exposure window even though it is never sent
	// upstream (P1-16).
	terminator.StripSecretHeaders(r.Header)

	// BETA-08: Enforce MaxBodyBytes BEFORE admission. Reject oversized
	// bodies with 413 before credential extraction or forwarding when the
	// declared length already proves the request is too large. Unknown-length
	// bodies are checked after full admission, before forwarding.
	if d.cfg.MaxBodyBytes > 0 {
		if r.ContentLength > d.cfg.MaxBodyBytes {
			out := &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "payload_too_large"}
			observeAdmission(out)
			d.writeDenial(w, out)
			return
		}
	}
	preAuthKey := canonicalPeer(r.RemoteAddr)
	if d.cfg.PreAuthSource != nil {
		preAuthHeaders := copyHeaders(r.Header)
		terminator.StripSecretHeaders(preAuthHeaders)
		preAuthObs := Observation{
			Header: preAuthHeaders, RemoteAddr: r.RemoteAddr,
			ProtoMajor: r.ProtoMajor, Method: r.Method, URLPath: r.URL.Path,
			BodySize: r.ContentLength, MaxBodyBytes: d.cfg.MaxBodyBytes,
		}
		if key, err := d.cfg.PreAuthSource.ResolvePreAuthSource(preAuthObs); err == nil && strings.TrimSpace(key) != "" {
			preAuthKey = key
		}
	}
	preAuthRelease, allowed := d.preAuth.acquireKey(preAuthKey, time.Now())
	if !allowed {
		out := &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "authentication_rate_limited"}
		observeAdmission(out)
		d.writeDenial(w, out)
		return
	}
	defer preAuthRelease()

	// 1. Terminate the credential BEFORE any adapter sees the request (P0.6):
	// the extraction uses the private auth copy, and only the sanitized request
	// view is handed to resolvers.
	presented, _, err := terminator.ExtractExternalCredential(authHeaders)
	if err != nil {
		// Even on extraction failure the terminator's safe-reason mapping is
		// reused so no header detail leaks into the response.
		out := &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "invalid_authentication", DenialErr: err}
		observeAdmission(out)
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
		Header:       obsHeaders,
		RemoteAddr:   remoteIP(r),
		ProtoMajor:   r.ProtoMajor,
		Method:       r.Method,
		URLPath:      r.URL.Path,
		BodySize:     r.ContentLength,
		MaxBodyBytes: d.cfg.MaxBodyBytes,
	}
	if route, ok := d.routeRule(r.Method, r.URL.Path); ok {
		obs.UsageProfile = route.UsageProfile
	}
	// P0.11-fix: a configured source resolver that FAILS must fail the request
	// closed, not silently degrade to "no source" (which would disable the
	// source boundary exactly when resolution is broken). NoSource and healthy
	// resolvers return a nil error; optional metadata (ASN/region) being absent
	// is not an error.
	var src terminator.TrustedSource
	var srcErr error
	if contextResolver, ok := d.srcs.(ContextSourceResolver); ok {
		src, srcErr = contextResolver.ResolveSourceContext(r.Context(), obs)
	} else {
		src, srcErr = d.srcs.ResolveSource(obs)
	}
	if srcErr != nil {
		out := &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "source_resolution_failed", DenialErr: srcErr}
		observeAdmission(out)
		d.writeDenial(w, out)
		return
	}
	feat := d.feat.Resolve(obs)
	// P0.6B: Merge trusted source network provenance into features. Trusted
	// ingress metadata is the authority; the generic feature resolver's values
	// are spoofable HTTP headers and must not compete with trusted metadata.
	MergeSourceIntoFeatures(&feat, src)
	est := d.cfg.Usage.Estimate(obs)

	out := d.cfg.Terminator.AdmitUsageContext(r.Context(), requestID, authHeaders, feat, src, est)
	preAuthRelease()

	if !out.Authorized {
		observeAdmission(out)
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

	if rule, ok := d.routeRule(r.Method, requestPath); ok && rule.RequiredScope != "" && !assertionHasScope(out.Assertion, rule.RequiredScope) {
		out = &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "policy_denied"}
		observeAdmission(out)
		d.writeDenial(w, out)
		return
	}

	// P0-2: only an admitted request may incur body-spooling cost. This keeps
	// valid-but-contained credentials from consuming one full spool per
	// connection, while invalid credentials still reach AdmitUsage's spray
	// detector instead of taking an auth-only shortcut. A body rejected here is
	// a forward outcome, not a security authorization; emit one final decision
	// record below and do not finalize baseline trust.
	if d.cfg.MaxBodyBytes > 0 {
		if r.ContentLength < 0 {
			spoolReservation, err := d.spool.Acquire(d.cfg.MaxBodyBytes)
			if err != nil {
				out := &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "spool_capacity_exhausted", DenialErr: err}
				observeAdmission(out)
				d.writeDenial(w, out)
				return
			}
			tempDir := d.cfg.SpoolDir
			if tempDir == "" {
				tempDir = spoolTempDir
			}
			body, err := spoolBodyInDirWithReservation(r.Body, d.cfg.MaxBodyBytes, spoolMemoryThreshold, tempDir, spoolReservation)
			if err != nil {
				out := &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "bad_request", DenialErr: err}
				observeAdmission(out)
				d.writeDenial(w, out)
				return
			}
			_ = r.Body.Close()
			if body.tooLarge {
				_ = body.Close() // closes + removes any temp file
				out = &terminator.Outcome{RequestID: requestID, Authorized: false, Reason: "payload_too_large"}
				observeAdmission(out)
				d.writeDenial(w, out)
				return
			}
			r.Body = body // body.Close() removes the temp file when the transport closes it
			r.ContentLength = body.length
		} else {
			// Known Content-Length within limit: use MaxBytesReader for safety.
			r.Body = http.MaxBytesReader(w, r.Body, d.cfg.MaxBodyBytes)
		}
	}
	observeAdmission(out)

	// 4. Resolve the (now stripped + re-injected) upstream headers: every secret
	// carrier and any forged Gripline-* header is gone; the signed assertion is
	// freshly minted. Hop-by-hop headers and untrusted provenance headers are
	// also removed from the request path — the proxy must not forward the
	// client's Connection-named or provenance headers to the backend (P0.17/P0.7).
	upstreamHeaders := copyHeaders(r.Header)
	terminator.StripSecretHeaders(upstreamHeaders)
	stripHopByHopHeaders(upstreamHeaders)
	stripUntrustedProvenanceHeaders(upstreamHeaders)
	stripRequestTrailers(r.Trailer)
	upstreamHeaders[assertionHeader] = []string{out.Assertion.Encode()}
	forwardCtx, cancelForward := context.WithCancel(r.Context())
	defer cancelForward()
	if out.ResourceReservation != nil {
		if err := out.ResourceReservation.MarkForwarded(r.Context()); err != nil {
			http.Error(w, "resource_lease_error", http.StatusBadGateway)
			return
		}
		if d.cfg.ReservationRenewEvery > 0 {
			stopRenew := make(chan struct{})
			defer close(stopRenew)
			go renewReservation(forwardCtx, out.ResourceReservation, d.cfg.ReservationRenewEvery, cancelForward, stopRenew)
		}
	}

	// 5. Build and forward the upstream request, streaming the body. The
	// upstream origin is the CONFIGURED backend (P0.7): scheme and host come
	// from BackendURL, the path is safely joined, and the client's query is
	// preserved. The client cannot redirect the proxy at another host.
	upr := r.Clone(forwardCtx)
	upr.Header = upstreamHeaders
	upr.Trailer = copyHeaders(r.Trailer)
	stripRequestTrailers(upr.Trailer)
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
		d.metrics.backendFailures.Add(1)
		// No baseline credit: an admitted request that fails before a successful
		// response is not clean trust-building activity. MarkForwarded happened
		// before RoundTrip, so the deferred Release consumes any unsettled usage
		// estimate conservatively; a transport error cannot prove the backend did
		// not accept the request.
		http.Error(w, "backend_error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	d.metrics.activeStreams.Add(1)
	defer d.metrics.activeStreams.Add(^uint64(0))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		d.metrics.backend4xx.Add(1)
	} else if resp.StatusCode >= 500 {
		d.metrics.backend5xx.Add(1)
	}

	// 6. Copy the backend response headers + status, stream the body back.
	copyResponseHeaders(w.Header(), resp.Header)
	// The backend is not authoritative for the ingress correlation id; restore
	// it after reserved-header stripping so successful responses carry the same
	// id as denials.
	w.Header().Set("X-Gripline-Request-ID", requestID)
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
		defer func() {
			// A streamed response may leave the HTTP connection alive. Clear
			// the per-request deadline so it cannot poison the next request on
			// that keep-alive connection.
			_ = rc.SetWriteDeadline(time.Time{})
		}()
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
	d.recordUsage(actual)
	// P0.36: only the reserved-but-unused remainder is refunded, and only to this
	// reservation's own buckets. Runs BEFORE the deferred Release so unsettled
	// holds are never cancelled-and-refunded in full. Concurrency is released by
	// the deferred Release.
	if out.ResourceReservation != nil {
		settleCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		if err := out.ResourceReservation.SettleContext(settleCtx, actual); err != nil {
			d.metrics.completionFailures.Add(1)
		}
		cancel()
	}
	// P0.4A: drive the completion producers with the ACTUAL usage. `success`
	// is false when the upstream stream failed, so a corrupt/failed stream is
	// not credited as clean velocity. This affects SUBSEQUENT admissions.
	success := streamErr == nil && resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices
	completion := out.Complete(actual, success)
	if len(completion.EvidenceCodes) > 0 {
		d.metrics.evidenceEvents.Add(uint64(len(completion.EvidenceCodes)))
	}
	if completion.Err != nil {
		d.metrics.completionFailures.Add(1)
	}
	// P0.9: surface completion-persistence failure through the observer seam —
	// the client response is already delivered and must not change, but a
	// shipping binary must not silently discard the Complete() result.
	if d.cfg.Observer != nil {
		event := CompletionEvent{
			RequestID: out.RequestID, CredentialID: out.Principal.CredentialID,
			LaneID: out.Context.LaneID, EvidenceCodes: completion.EvidenceCodes,
			Persisted: completion.Persisted, StreamOK: streamErr == nil, Err: completion.Err,
		}
		if completion.Err != nil {
			event.ErrorCode = "completion_observation_failed"
			event.ErrorMessage = "completion observation failed"
		} else if streamErr != nil {
			event.ErrorCode = "stream_failed"
			event.ErrorMessage = "upstream stream failed"
		}
		d.cfg.Observer.ObserveCompletion(event)
	}
	// P0.27/P0.17: Finalize baseline trust ONLY after a clean, successful
	// backend response. A fully delivered 4xx/5xx is transport-clean but is not
	// trust-building provider activity; resource accounting still settled above.
	if streamErr == nil && resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		out.FinalizeBaseline()
	}
}

// routeStatus returns 0 for an allowed route, 404 for an unknown path, or
// 405 for a known path with an unsupported method.
func (d *DataPlane) routeStatus(method, requestPath string) (int, string) {
	if d.routes != nil {
		if _, ok := d.routes[routeKey{method: method, path: requestPath}]; ok {
			return 0, ""
		}
		var methods []string
		for key := range d.routes {
			if key.path == requestPath {
				methods = append(methods, key.method)
			}
		}
		if len(methods) == 0 {
			return http.StatusNotFound, ""
		}
		sort.Strings(methods)
		return http.StatusMethodNotAllowed, strings.Join(methods, ", ")
	}
	pathKnown := false
	allowed := false
	var methods []string
	for _, rule := range d.cfg.EndpointRules {
		if rule.Path != requestPath {
			continue
		}
		pathKnown = true
		if !containsString(methods, rule.Method) {
			methods = append(methods, rule.Method)
		}
		if rule.Method == method {
			allowed = true
		}
	}
	if allowed {
		return 0, ""
	}
	if !pathKnown {
		return http.StatusNotFound, ""
	}
	return http.StatusMethodNotAllowed, strings.Join(methods, ", ")
}

func (d *DataPlane) routeRule(method, requestPath string) (EndpointRule, bool) {
	if d.routes != nil {
		rule, ok := d.routes[routeKey{method: method, path: requestPath}]
		return rule, ok
	}
	for _, rule := range d.cfg.EndpointRules {
		if rule.Method == method && rule.Path == requestPath {
			return rule, true
		}
	}
	return EndpointRule{}, false
}

func normalizeEndpointRule(rule EndpointRule) (EndpointRule, error) {
	rule.Method = strings.ToUpper(strings.TrimSpace(rule.Method))
	rule.Path = strings.TrimSpace(rule.Path)
	rule.RequiredScope = strings.TrimSpace(rule.RequiredScope)
	rule.UsageProfile = strings.TrimSpace(rule.UsageProfile)
	if rule.Method == "" || strings.ContainsAny(rule.Method, " \t\r\n") || rule.Path == "" ||
		!strings.HasPrefix(rule.Path, "/v1/") || strings.ContainsAny(rule.Path, "?#*") {
		return EndpointRule{}, fmt.Errorf("must contain an exact method and /v1/ path")
	}
	if strings.Contains(rule.Path, "//") || path.Clean(rule.Path) != rule.Path || strings.Contains(rule.Path, "%") {
		return EndpointRule{}, fmt.Errorf("path %q is not canonical", rule.Path)
	}
	switch rule.RequiredScope {
	case "", "inference", "REQUEST", "LANE", "CREDENTIAL", "ACCOUNT":
	default:
		return EndpointRule{}, fmt.Errorf("unsupported required scope %q", rule.RequiredScope)
	}
	switch rule.UsageProfile {
	case "", "none", "openai-chat", "openai-responses", "openai-embeddings", "openai-models", "anthropic-messages":
	default:
		return EndpointRule{}, fmt.Errorf("unsupported usage profile %q", rule.UsageProfile)
	}
	if rule.UsageProfile == "openai-models" && rule.Method != http.MethodGet {
		return EndpointRule{}, fmt.Errorf("usage profile openai-models requires GET")
	}
	if rule.UsageProfile != "none" && rule.UsageProfile != "" && rule.UsageProfile != "openai-models" && rule.Method != http.MethodPost {
		return EndpointRule{}, fmt.Errorf("usage profile %q requires POST", rule.UsageProfile)
	}
	return rule, nil
}

func assertionHasScope(assertion *terminator.Assertion, required string) bool {
	if assertion == nil {
		return false
	}
	for _, scope := range assertion.Claims().Scope {
		if scope == required {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func unsupportedContentEncoding(values []string) bool {
	for _, value := range values {
		for _, encoding := range strings.Split(value, ",") {
			encoding = strings.ToLower(strings.TrimSpace(encoding))
			if encoding != "" && encoding != "identity" {
				return true
			}
		}
	}
	return false
}

func renewReservation(ctx context.Context, reservation resource.UsageReservation, every time.Duration, cancel context.CancelFunc, stop <-chan struct{}) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := reservation.Renew(ctx); err != nil {
				cancel()
				return
			}
		case <-stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

// joinPath joins a configured backend base path with the request path without
// allowing traversal out of the base (P0.7). The result is always rooted and
// cleaned.
func joinPath(base, req string) string {
	// Normalize the request as a rooted path first. This makes all traversal
	// components relative to the request root before they can interact with the
	// configured backend prefix; path.Clean(base + "/" + req) would let ../
	// escape that prefix.
	rel := path.Clean("/" + strings.TrimPrefix(req, "/"))
	rel = strings.TrimPrefix(rel, "/")
	if rel == "." {
		rel = ""
	}
	base = path.Clean("/" + strings.TrimPrefix(base, "/"))
	if base == "." {
		base = "/"
	}
	return path.Join(base, rel)
}

// writeDenial maps an admission denial to an HTTP status + safe reason. Internal
// error details never leak the secret or internal state.
func (d *DataPlane) writeDenial(w http.ResponseWriter, out *terminator.Outcome) {
	code := http.StatusForbidden
	var limitErr *resource.ScopeLimitError
	// The typed governor cause is authoritative. Scope-specific reason strings
	// are useful for internal telemetry, but must not turn a hard quota denial
	// into a security-state 403 or hide its retry metadata.
	if errors.As(out.DenialErr, &limitErr) {
		code = http.StatusTooManyRequests
	} else {
		switch out.Reason {
		case "concurrency_limit", "rate_limit", "temporarily_restricted", "authentication_rate_limited":
			code = http.StatusTooManyRequests
		case "invalid_credential", "credential_expired", "bad", "invalid_authentication":
			code = http.StatusUnauthorized
		case "backend_error", "internal_identity_failure", "resource_unavailable", "source_resolution_failed", "spool_capacity_exhausted", "internal_error", "entropy_unavailable":
			code = http.StatusServiceUnavailable
		case "bad_request":
			code = http.StatusBadRequest
		case "payload_too_large":
			code = http.StatusRequestEntityTooLarge
		}
	}
	if out.RequestID != "" {
		w.Header().Set("X-Gripline-Request-ID", out.RequestID)
	}
	w.Header().Set("X-Gripline-Reason", out.Reason)
	if limitErr != nil && limitErr.RetryAfter > 0 {
		seconds := int64((limitErr.RetryAfter + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	}
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
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"proxy-connection":    {},
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

// stripRequestTrailers removes secret, reserved, and hop-by-hop trailers.
// Trailer names are announced before the body is consumed but values arrive
// only afterward, so header-only sanitation is insufficient for chunked
// requests. The map is sanitized both before cloning and on the upstream copy.
func stripRequestTrailers(h http.Header) {
	if h == nil {
		return
	}
	terminator.StripSecretHeaders(h)
	stripHopByHopHeaders(h)
	for k := range h {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, "x-gripline-") || strings.HasPrefix(lower, "gripline-") {
			h.Del(k)
		}
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
