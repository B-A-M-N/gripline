// Package config loads and validates the Gripline gateway's deployment
// configuration (P0.54). An internal/proxy package is not a production
// gateway by itself: standing one up requires explicit, VALIDATED decisions
// about TLS, the fixed backend target, server timeouts, header/body limits,
// and the trusted-ingress secrets — a misconfigured default must be a boot
// FAILURE, never a silently degraded runtime.
//
// Configuration is file-based (JSON). Environment expansion (${VAR}) is
// applied to string values so secrets can be injected without touching disk;
// an unset referenced variable is a load ERROR, never an empty substitution
// (fail closed).
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
)

// Duration is a JSON-friendly time.Duration: it accepts string forms
// ("30s", "1m") in configuration files, which plain time.Duration does not.
type Duration time.Duration

const (
	credentialMaxLoadedGenerations = 4
	pseudonymMaxLoadedGenerations  = 4
	defaultAuthorityReconcile      = time.Second
	defaultSpoolMemoryThreshold    = 256 << 10
	defaultShutdownTimeout         = 30 * time.Second
	defaultAdminMaxConnections     = 256
	defaultAdminReadHeaderTimeout  = 10 * time.Second
	defaultAdminReadTimeout        = 30 * time.Second
	defaultAdminWriteTimeout       = 30 * time.Second
	defaultAdminIdleTimeout        = 120 * time.Second
)

func parseGenerationKey(raw string) (int, error) {
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("generation must be a positive signed-32-bit decimal")
	}
	return int(n), nil
}

// UnmarshalJSON parses either a Go-duration string or an integer nanosecond
// count. An unparseable value is a load error, never a zero.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" {
		*d = 0
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		*d = Duration(n)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("config: invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalJSON emits the same human-readable duration form accepted by the
// loader. This keeps `gripline config effective` useful to operators instead
// of exposing implementation-level nanosecond counts.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.D().String())
}

// Config is the complete deployment configuration. Every field with a
// security consequence is REQUIRED (no implicit defaults for TLS posture,
// backend target, or limits); Validate enforces the cross-field invariants.
type Config struct {
	// Listen is the public listener address, e.g. ":8585".
	Listen string `json:"listen"`

	// TLS is the public-side TLS configuration. TLS is REQUIRED for the
	// public listener (production inference credentials never cross plain
	// HTTP); a deployment that truly fronts a TLS-terminating load balancer
	// must say so explicitly via TerminateTLSUpstream.
	TLS TLSSection `json:"tls"`

	// Backend is the FIXED upstream origin (P0.7): scheme + host (+ optional
	// base path). The client cannot select the upstream host.
	Backend BackendSection `json:"backend"`

	// Server carries the HTTP server hardening (P0.54): bounded timeouts,
	// header size, and body size appropriate to inference workloads.
	Server ServerSection `json:"server"`

	// Admin carries the control-plane listener (P0.47). Optional: when unset,
	// no operator surface is exposed (the safest default for a pure data
	// plane).
	Admin *AdminSection `json:"admin,omitempty"`

	// Identity carries the internal assertion boundary (INV-10/11).
	Identity IdentitySection `json:"identity"`

	// Paths are the durable-state locations.
	Paths PathsSection `json:"paths"`

	// Secrets carries versioned verifier-pepper references. Values are expected
	// to come from environment expansion or a secret-injection layer; they are
	// never persisted in state.
	Secrets SecretsSection `json:"secrets,omitempty"`

	// Ingress configures trusted source identity resolution (P0.6).
	Ingress *IngressSection `json:"ingress,omitempty"`

	// Usage configures one of the bounded provider-compatible usage adapters.
	// Empty/none intentionally keeps token/cost accounting disabled.
	Usage UsageSection `json:"usage,omitempty"`

	// Deployment carries the deployment-posture switches (P0.18). The safe
	// production path is the DEFAULT: persistent state is required at boot.
	Deployment DeploymentSection `json:"deployment,omitempty"`

	// Policy optionally names the authenticated/versioned policy artifact. An
	// empty path retains the beta default; a supplied path is loaded and passed
	// through policy.Compile during runtime construction.
	Policy PolicySection `json:"policy,omitempty"`

	// Authority selects the authoritative state backend. The empty backend is
	// the explicit single-process mode; "postgres" is the clustered mode and
	// requires a shared DSN reference plus a stable node identity.
	Authority AuthoritySection `json:"authority,omitempty"`
}

// AuthoritySection configures the shared PostgreSQL authority. DSNEnv names an
// environment variable rather than storing database credentials in the config
// file. Lease timings are validated even before the first remote lease is
// requested so every node shares an explicit fencing/expiry contract.
type AuthoritySection struct {
	Backend    string   `json:"backend,omitempty"` // standalone | postgres
	DSNEnv     string   `json:"dsn_env,omitempty"`
	NodeID     string   `json:"node_id,omitempty"`
	LeaseTTL   Duration `json:"lease_ttl,omitempty"`
	RenewEvery Duration `json:"renew_every,omitempty"`
	// ConnectTimeout bounds pool creation and the initial authority probe.
	ConnectTimeout Duration `json:"connect_timeout,omitempty"`
	// OperationTimeout is the default bound for runtime-owned remote
	// reconciliation and other ordinary authority operations.
	OperationTimeout Duration `json:"operation_timeout,omitempty"`
	// ReconcileInterval controls policy and crypto convergence polling in a
	// clustered deployment. It is deliberately separate from operation
	// timeout: a slow operation must not silently change convergence cadence.
	ReconcileInterval Duration `json:"reconcile_interval,omitempty"`
	MaxConns          int32    `json:"max_conns,omitempty"`
	MinConns          int32    `json:"min_conns,omitempty"`
	// MaxSourceAliasIdentities bounds distinct canonical source identities in
	// the shared PostgreSQL alias authority. Zero uses its conservative default.
	MaxSourceAliasIdentities int                `json:"max_source_alias_identities,omitempty"`
	Maintenance              MaintenanceSection `json:"maintenance,omitempty"`
}

// MaintenanceSection exposes PostgreSQL historical-data retention to the
// deployment instead of hiding it in authority implementation defaults.
type MaintenanceSection struct {
	Interval                    Duration `json:"interval,omitempty"`
	BatchSize                   int      `json:"batch_size,omitempty"`
	MaxBatchesPerPass           int      `json:"max_batches_per_pass,omitempty"`
	MaxRowsPerPass              int      `json:"max_rows_per_pass,omitempty"`
	MaxRuntimePerPass           Duration `json:"max_runtime_per_pass,omitempty"`
	EvidenceGrace               Duration `json:"evidence_grace,omitempty"`
	ReleasedLeaseRetention      Duration `json:"released_lease_retention,omitempty"`
	CredentialReceiptRetention  Duration `json:"credential_receipt_retention,omitempty"`
	ControlOperationRetention   Duration `json:"control_operation_retention,omitempty"`
	AdmissionAuditRetention     Duration `json:"admission_audit_retention,omitempty"`
	SecurityTransitionRetention Duration `json:"security_transition_retention,omitempty"`
	OperatorAuditRetention      Duration `json:"operator_audit_retention,omitempty"`
	PolicyAuditRetention        Duration `json:"policy_audit_retention,omitempty"`
	MembershipRetention         Duration `json:"membership_retention,omitempty"`
	AdaptiveRetention           Duration `json:"adaptive_retention,omitempty"`
	EvidenceGuardRetention      Duration `json:"evidence_guard_retention,omitempty"`
	LaneOperatorAuditRetention  Duration `json:"lane_operator_audit_retention,omitempty"`
	PolicyNodeStateRetention    Duration `json:"policy_node_state_retention,omitempty"`
	ClusterCryptoAckRetention   Duration `json:"cluster_crypto_ack_retention,omitempty"`
	SourceAliasRetention        Duration `json:"source_alias_retention,omitempty"`
}

func (m MaintenanceSection) configured() bool {
	return m.Interval.D() != 0 || m.BatchSize != 0 || m.MaxBatchesPerPass != 0 || m.MaxRowsPerPass != 0 || m.MaxRuntimePerPass.D() != 0 || m.EvidenceGrace.D() != 0 ||
		m.ReleasedLeaseRetention.D() != 0 || m.CredentialReceiptRetention.D() != 0 ||
		m.ControlOperationRetention.D() != 0 || m.AdmissionAuditRetention.D() != 0 ||
		m.SecurityTransitionRetention.D() != 0 || m.OperatorAuditRetention.D() != 0 ||
		m.PolicyAuditRetention.D() != 0 || m.MembershipRetention.D() != 0 ||
		m.AdaptiveRetention.D() != 0 || m.EvidenceGuardRetention.D() != 0 ||
		m.LaneOperatorAuditRetention.D() != 0 || m.PolicyNodeStateRetention.D() != 0 ||
		m.ClusterCryptoAckRetention.D() != 0 || m.SourceAliasRetention.D() != 0
}

// PolicySection selects the versioned policy artifact for the deployment.
type PolicySection struct {
	File            string `json:"file,omitempty"`
	VerifierKeyFile string `json:"verifier_key_file,omitempty"`
}

// SecretsSection configures the active verifier pepper versions. The map key
// is a positive decimal version string and the value is base64 key material.
// Keeping more than one version live allows existing credentials to migrate
// without making the old verifier invalid before re-provisioning completes.
type SecretsSection struct {
	PepperVersions map[string]string `json:"pepper_versions,omitempty"`
}

// DeploymentSection carries the deployment-posture switches (P0.18).
type DeploymentSection struct {
	// AllowEphemeralState is the explicit development escape hatch. When
	// false (the default), boot REQUIRES paths.state and paths.signer_keyring
	// so an operator cannot accidentally run a security gateway that forgets
	// credentials, lanes, and posture on restart. Set true ONLY for
	// tests/development: every authority then degrades to its in-memory or
	// ephemeral form.
	AllowEphemeralState bool `json:"allow_ephemeral_state,omitempty"`
}

// IngressSection configures trusted source identity resolution (P0.6).
type IngressSection struct {
	// PseudonymKey is the HMAC key for source pseudonymization. Must be
	// distinct from the credential verifier pepper. Env-injected.
	PseudonymKey string `json:"pseudonym_key"`
	// PseudonymKeys is the versioned rotation window. The highest version is
	// used for new source identifiers; older versions remain accepted by the
	// resolver while stored identifiers migrate.
	PseudonymKeys map[string]string `json:"pseudonym_keys,omitempty"`
	// TrustedProxies is the set of CIDR prefixes that may supply forwarding
	// headers. Empty means no trusted proxies (direct peer is canonical).
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	// Networks is a provider-authored local CIDR map. It is consulted only
	// after trusted-proxy/source canonicalization.
	Networks []NetworkSection `json:"networks,omitempty"`
}

// NetworkSection maps a canonical source prefix to bounded metadata used by
// source novelty and lane classification.
type NetworkSection struct {
	CIDR        string `json:"cidr"`
	ASN         string `json:"asn,omitempty"`
	NetworkType string `json:"network_type,omitempty"`
	Region      string `json:"region,omitempty"`
}

// UsageSection selects the built-in provider-compatible usage adapter.
type UsageSection struct {
	// Mode is "none", "openai", or "anthropic". The empty value means none.
	Mode string `json:"mode,omitempty"`
	// CostMode is "none", "conservative", or "exact". Deployments should
	// choose explicitly; conservative is the safe posture when provider cache
	// pricing details are unavailable in a response.
	CostMode                          string `json:"cost_mode,omitempty"`
	InputMicrounitsPerToken           int64  `json:"input_microunits_per_token,omitempty"`
	OutputMicrounitsPerToken          int64  `json:"output_microunits_per_token,omitempty"`
	CacheReadMicrounitsPerToken       int64  `json:"cache_read_microunits_per_token,omitempty"`
	CacheCreationMicrounitsPerToken   int64  `json:"cache_creation_microunits_per_token,omitempty"`
	CacheCreation5mMicrounitsPerToken int64  `json:"cache_creation_5m_microunits_per_token,omitempty"`
	CacheCreation1hMicrounitsPerToken int64  `json:"cache_creation_1h_microunits_per_token,omitempty"`
	DefaultOutputTokens               int64  `json:"default_output_tokens,omitempty"`
	// MaxOutputTokens is the conservative pre-execution output reservation.
	// It must be explicit when token/cost enforcement is enabled; request
	// headers cannot lower this hard ceiling safely.
	MaxOutputTokens int64 `json:"max_output_tokens,omitempty"`
}

// TLSSection configures the public listener's TLS.
type TLSSection struct {
	// CertFile and KeyFile are the serving certificate and key (PEM).
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// TerminateTLSUpstream declares that a trusted fronting proxy terminates
	// TLS and forwards over a private network. This is the ONLY way to serve
	// plain HTTP on the public listener, and it must be deliberate.
	TerminateTLSUpstream bool `json:"terminate_tls_upstream"`
	// MinVersion is the minimum TLS version string: "1.2" (default) or "1.3".
	MinVersion string `json:"min_version,omitempty"`
}

// BackendTrustMode makes the upstream security boundary explicit.
type BackendTrustMode string

const (
	BackendTrustMTLS           BackendTrustMode = "mtls"
	BackendTrustPrivateNetwork BackendTrustMode = "private_network"
	BackendTrustDevelopment    BackendTrustMode = "development"
)

// BackendSection is the fixed upstream (P0.7).
type BackendSection struct {
	// URL is the upstream origin, e.g. "https://provider.internal:443".
	URL string `json:"url"`
	// TrustMode is the explicit trust boundary for the fixed backend. Persistent
	// deployments must declare either mTLS or a private-network boundary;
	// development mode is reserved for ephemeral loopback fixtures.
	TrustMode BackendTrustMode `json:"trust_mode,omitempty"`
	// VerifierControl is a separately authenticated backend control channel used
	// by the clustered signer-rotation handshake. It must not reuse the
	// data-plane transport identity.
	VerifierControl VerifierControlSection `json:"verifier_control,omitempty"`
	// Timeout is the default for the dial, TLS-handshake, and response-header
	// phases below. Streaming response bodies use the proxy's idle semantics;
	// this is not an absolute wall-clock cap on a live stream.
	Timeout Duration `json:"timeout"`
	// DialTimeout bounds establishing the TCP connection. Zero = Timeout.
	DialTimeout Duration `json:"dial_timeout,omitempty"`
	// TLSHandshakeTimeout bounds the upstream TLS handshake. Zero = Timeout.
	TLSHandshakeTimeout Duration `json:"tls_handshake_timeout,omitempty"`
	// ResponseHeaderTimeout bounds waiting for the upstream response HEADERS
	// (the slowest failure mode of a loaded inference backend). Zero = Timeout.
	ResponseHeaderTimeout Duration `json:"response_header_timeout,omitempty"`
	// MaxIdleConnsPerHost tunes connection pooling (0 = default).
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`
	// MaxResponseHeaderBytes bounds hostile or malfunctioning upstream response
	// headers before application proxy code receives control.
	MaxResponseHeaderBytes int `json:"max_response_header_bytes,omitempty"`
	// AllowedEndpoints is the exact public method/path contract. Omitted (nil)
	// retains the built-in provider-neutral inference surface; an explicit empty
	// array denies every public endpoint.
	AllowedEndpoints []EndpointRule `json:"allowed_endpoints,omitempty"`
	// TLS configures private-CA and optional client-certificate authentication
	// for an HTTPS backend. Cert and key must be supplied together.
	TLS BackendTLSSection `json:"tls,omitempty"`
}

// VerifierControlSection configures the signer-management transport. The
// control endpoint has its own URL and trust material, plus an optional
// separately injected bearer token for loopback fixtures or deployments that
// terminate mTLS in a dedicated control-plane sidecar. Production remote
// control endpoints should use ClientCertFile/ClientKeyFile with a private CA.
type VerifierControlSection struct {
	URL            string   `json:"url,omitempty"`
	CAFile         string   `json:"ca_file,omitempty"`
	ClientCertFile string   `json:"client_cert_file,omitempty"`
	ClientKeyFile  string   `json:"client_key_file,omitempty"`
	ServerName     string   `json:"server_name,omitempty"`
	MinVersion     string   `json:"min_version,omitempty"`
	Timeout        Duration `json:"timeout,omitempty"`
	Token          string   `json:"token,omitempty"`
}

// EndpointRule is an exact public data-plane authorization rule. Wildcards
// are intentionally not supported: every forwarded method/path must be
// present in the configured provider contract.
type EndpointRule struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	RequiredScope string `json:"required_scope,omitempty"`
	UsageProfile  string `json:"usage_profile,omitempty"`
}

// BackendTLSSection configures upstream TLS authentication.
type BackendTLSSection struct {
	CAFile         string `json:"ca_file,omitempty"`
	ClientCertFile string `json:"client_cert_file,omitempty"`
	ClientKeyFile  string `json:"client_key_file,omitempty"`
	ServerName     string `json:"server_name,omitempty"`
	MinVersion     string `json:"min_version,omitempty"`
}

// ServerSection hardens the HTTP server.
type ServerSection struct {
	// ReadTimeout bounds request-head+body reads; WriteTimeout bounds the
	// response; IdleTimeout reaps idle keep-alives. Zero values are REJECTED:
	// an unbounded server timeout is a slowloris resource exhaustion.
	ReadTimeout  Duration `json:"read_timeout"`
	WriteTimeout Duration `json:"write_timeout"`
	IdleTimeout  Duration `json:"idle_timeout"`
	// MaxConnections bounds accepted public/admin TCP connections before the
	// HTTP server allocates per-connection state. Zero uses a 4096 default.
	MaxConnections int `json:"max_connections,omitempty"`
	// HTTP2MaxConcurrentStreams and HTTP2HeaderTableBytes are explicit bounds
	// for direct TLS/HTTP2 listeners. Zero values use conservative defaults.
	HTTP2MaxConcurrentStreams         int `json:"http2_max_concurrent_streams,omitempty"`
	HTTP2HeaderTableBytes             int `json:"http2_header_table_bytes,omitempty"`
	HTTP2MaxReadFrameBytes            int `json:"http2_max_read_frame_bytes,omitempty"`
	HTTP2MaxUploadBufferPerConnection int `json:"http2_max_upload_buffer_per_connection,omitempty"`
	HTTP2MaxUploadBufferPerStream     int `json:"http2_max_upload_buffer_per_stream,omitempty"`
	// MaxHeaderBytes caps the request header block (net/http default 1MB is
	// generous; inference gateways should pin it lower). Zero = 64KB floor.
	MaxHeaderBytes int `json:"max_header_bytes,omitempty"`
	// MaxBodyBytes caps the request body (inference prompts can be large but
	// are not unbounded; 0 = 32MB default). Oversized bodies are rejected
	// with 413 by the data plane's LimitReader check.
	MaxBodyBytes int64 `json:"max_body_bytes,omitempty"`
	// ReadHeaderTimeout bounds header reads specifically (slowloris).
	ReadHeaderTimeout Duration `json:"read_header_timeout"`
	// StreamWriteIdleTimeout bounds how long a streaming response may stall
	// without forwarding any bytes to the client (P0.16). Long-lived SSE
	// inference streams are legitimate; a DEAD stream (backend hung, no
	// tokens flowing) is not — each idle stretch longer than this is cut.
	// Zero = server.write_timeout applies as-is (no streaming exemption).
	// Required to be positive when set; must be <= write_timeout is NOT
	// enforced (streams legitimately outlive short header-phase budgets).
	StreamWriteIdleTimeout Duration `json:"stream_write_idle_timeout,omitempty"`
	// SpoolDir is an optional dedicated directory for chunked request bodies.
	// In a read-only-root container, point this at a writable tmpfs mount.
	SpoolDir string `json:"spool_dir,omitempty"`
	// SpoolMaxBytes bounds aggregate unknown-length body reservations. Zero
	// resolves to a conservative production default.
	SpoolMaxBytes int64 `json:"spool_max_bytes,omitempty"`
	// SpoolMaxFiles bounds concurrent unknown-length body reservations. Zero
	// resolves to a conservative production default.
	SpoolMaxFiles int `json:"spool_max_files,omitempty"`
	// SpoolMemoryThreshold controls when an unknown-length body moves from
	// memory to the dedicated spool directory.
	SpoolMemoryThreshold int64 `json:"spool_memory_threshold,omitempty"`
	// ShutdownTimeout is the single graceful-drain budget for public/admin
	// HTTP shutdown and cluster drain publication.
	ShutdownTimeout Duration `json:"shutdown_timeout,omitempty"`
	// MaxSourceScopes is the backend-neutral resource source-scope cardinality
	// limit. Zero uses the conservative runtime default; source alias
	// registration state has its own authenticated-only lifecycle.
	MaxSourceScopes int `json:"max_source_scopes,omitempty"`
	// SourceScopeIdle is the minimum idle horizon before a fully replenished
	// source scope may be evicted.
	SourceScopeIdle Duration `json:"source_scope_idle,omitempty"`
	// PreAuthSourceIdle is the independent idle horizon for the bounded
	// pre-authentication source table. It must not inherit the post-auth source
	// scope retention horizon because the two tables have different threat and
	// lifecycle semantics.
	PreAuthSourceIdle Duration `json:"preauth_source_idle,omitempty"`
	// PreAuthMaxConcurrent bounds expensive credential/authority work before
	// authentication succeeds.
	PreAuthMaxConcurrent int `json:"preauth_max_concurrent,omitempty"`
	// PreAuthRequestsPerSecond is a process-wide syntactic/authentication work
	// budget, not an authorization policy.
	PreAuthRequestsPerSecond int `json:"preauth_requests_per_second,omitempty"`
	// PreAuthSourceRequestsPerSecond bounds one coarse peer source.
	PreAuthSourceRequestsPerSecond int `json:"preauth_source_requests_per_second,omitempty"`
	// PreAuthMaxSources bounds the guard's attacker-controlled source table.
	PreAuthMaxSources int `json:"preauth_max_sources,omitempty"`
}

// AdminSection configures the operator control-plane listener (P0.47).
type AdminSection struct {
	// Listen is the PRIVATE admin listener address (loopback or private
	// interface only — it is authenticated but must never be internet-facing).
	Listen string `json:"listen"`
	// OperatorTokens maps bearer tokens to operator names. Raw tokens live
	// only here (env-injected); the control plane stores digests. At least
	// one token with each needed capability must be configured.
	OperatorTokens map[string]string `json:"operator_tokens"` // token -> "name:cap1,cap2"
	// Admin listener resource limits are independent from the public data
	// plane. Zero values receive bounded defaults during validation.
	MaxConnections    int      `json:"max_connections,omitempty"`
	ReadHeaderTimeout Duration `json:"read_header_timeout,omitempty"`
	ReadTimeout       Duration `json:"read_timeout,omitempty"`
	WriteTimeout      Duration `json:"write_timeout,omitempty"`
	IdleTimeout       Duration `json:"idle_timeout,omitempty"`
}

// IdentitySection is the internal assertion boundary.
type IdentitySection struct {
	// Audience is the internal audience the proxy issues assertions to
	// (INV-11). The private backend must verify exactly this audience.
	Audience string `json:"audience"`
}

// PathsSection names durable-state locations.
type PathsSection struct {
	// AuditLog is the append-only operator audit JSONL used only by the
	// explicitly ephemeral administrative mode. It is rejected alongside
	// paths.state so there cannot be two audit authorities.
	AuditLog string `json:"audit_log"`
	// Evidence is the LEGACY gob-file evidence store path (BETA-09). It must
	// be empty when paths.state is configured (P0.2: the Bolt database is the
	// single evidence authority). Development-only otherwise: empty means
	// in-memory evidence.
	Evidence string `json:"evidence"`
	// SignerKeyring is the file path for the persistent signing keyring (BETA-10).
	// Required unless deployment.allow_ephemeral_state is true (P0.18).
	SignerKeyring string `json:"signer_keyring"`
	// State is the file path for the single transactional state database
	// (P0.10): credentials + verifier index + security state, lanes, evidence,
	// operator audit, and operator posture all in one bbolt file. Empty means
	// the ephemeral (in-memory) mode, which requires
	// deployment.allow_ephemeral_state=true (P0.18).
	State string `json:"state"`
}

// Load reads, expands, and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- configuration path is the explicit operator launch input.
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	expanded, err := expandEnv(string(raw))
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(expanded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("config: parse %s: trailing JSON value", path)
		}
		return nil, fmt.Errorf("config: parse %s: trailing data: %w", path, err)
	}
	if c.Policy.File != "" && !filepath.IsAbs(c.Policy.File) {
		c.Policy.File = filepath.Join(filepath.Dir(path), c.Policy.File)
	}
	if c.Policy.VerifierKeyFile != "" && !filepath.IsAbs(c.Policy.VerifierKeyFile) {
		c.Policy.VerifierKeyFile = filepath.Join(filepath.Dir(path), c.Policy.VerifierKeyFile)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: invalid: %w", err)
	}
	return &c, nil
}

// expandEnv substitutes ${VAR} references. An unset/empty referenced variable
// is an error (fail closed): an empty token or path substituted silently
// would produce a config that parses but cannot be safe.
func expandEnv(s string) (string, error) {
	var b strings.Builder
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			b.WriteString(s)
			return b.String(), nil
		}
		j := strings.Index(s[i:], "}")
		if j < 0 {
			return "", fmt.Errorf("config: unterminated ${ in configuration")
		}
		b.WriteString(s[:i])
		name := s[i+2 : i+j]
		val := os.Getenv(name)
		if val == "" {
			return "", fmt.Errorf("config: environment variable %q is not set (referenced in configuration)", name)
		}
		b.WriteString(val)
		s = s[i+j+1:]
	}
}

// Validate enforces the deployment invariants (P0.54): explicit TLS posture,
// fixed backend, bounded timeouts, bounded headers/bodies, identity audience.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address required")
	}
	// TLS posture: real TLS or an explicit upstream-termination declaration.
	hasCert, hasKey := c.TLS.CertFile != "", c.TLS.KeyFile != ""
	if hasCert != hasKey {
		return fmt.Errorf("tls.cert_file and tls.key_file must be supplied together")
	}
	if !hasCert {
		if !c.TLS.TerminateTLSUpstream {
			return fmt.Errorf("public listener must serve TLS (tls.cert_file/tls.key_file) or explicitly declare tls.terminate_tls_upstream")
		}
	} else if c.TLS.TerminateTLSUpstream {
		return fmt.Errorf("tls.terminate_tls_upstream and cert/key files are mutually exclusive")
	}
	switch c.TLS.MinVersion {
	case "", "1.2", "1.3":
	default:
		return fmt.Errorf("tls.min_version must be \"1.2\" or \"1.3\", got %q", c.TLS.MinVersion)
	}
	// P0-15: plain HTTP is only legitimate behind a trusted fronting proxy on
	// a PRIVATE network. A terminate_tls_upstream listener bound to a
	// wildcard or public interface would carry inference credentials in
	// cleartext over a network hop — fail the boot instead.
	if c.TLS.TerminateTLSUpstream && c.TLS.CertFile == "" {
		if err := requirePrivateBind(c.Listen, "listen"); err != nil {
			return err
		}
	}

	// Fixed backend (P0.7).
	if c.Backend.URL == "" {
		return fmt.Errorf("backend.url required (the fixed upstream origin)")
	}
	if c.Backend.Timeout.D() <= 0 {
		return fmt.Errorf("backend.timeout required (an unbounded upstream exchange is not deployable)")
	}
	backendURL, err := url.Parse(c.Backend.URL)
	if err != nil || backendURL.Scheme == "" || backendURL.Host == "" {
		return fmt.Errorf("backend.url must be an absolute http/https URL")
	}
	if backendURL.Scheme != "http" && backendURL.Scheme != "https" {
		return fmt.Errorf("backend.url scheme must be http or https")
	}
	if backendURL.User != nil || backendURL.RawQuery != "" || backendURL.Fragment != "" {
		return fmt.Errorf("backend.url must not contain userinfo, query, or fragment")
	}
	trustMode := strings.ToLower(strings.TrimSpace(string(c.Backend.TrustMode)))
	if trustMode == "" {
		if !c.Deployment.AllowEphemeralState {
			return fmt.Errorf("backend.trust_mode is required for persistent deployments (mtls or private_network)")
		}
		trustMode = "development"
	}
	switch trustMode {
	case "mtls":
		if backendURL.Scheme != "https" {
			return fmt.Errorf("backend.trust_mode mtls requires an https backend")
		}
		if c.Backend.TLS.CAFile == "" || c.Backend.TLS.ClientCertFile == "" || c.Backend.TLS.ClientKeyFile == "" || strings.TrimSpace(c.Backend.TLS.ServerName) == "" {
			return fmt.Errorf("backend.trust_mode mtls requires backend.tls.ca_file, client_cert_file, client_key_file, and server_name")
		}
		if c.Backend.TLS.MinVersion != "1.2" && c.Backend.TLS.MinVersion != "1.3" {
			return fmt.Errorf("backend.trust_mode mtls requires backend.tls.min_version 1.2 or 1.3")
		}
	case "private_network":
		// The operator is explicitly asserting that the backend hop is inside a
		// private network boundary. This mode permits local HTTP fixtures and
		// private HTTPS deployments whose network policy supplies the boundary.
	case "development":
		if !c.Deployment.AllowEphemeralState {
			return fmt.Errorf("backend.trust_mode development requires deployment.allow_ephemeral_state=true")
		}
		if !backendHostnameIsLoopback(backendURL.Hostname()) {
			return fmt.Errorf("backend.trust_mode development requires a loopback backend")
		}
	default:
		return fmt.Errorf("backend.trust_mode must be mtls, private_network, or development")
	}
	c.Backend.TrustMode = BackendTrustMode(trustMode)
	if backendURL.Scheme != "https" && (c.Backend.TLS.CAFile != "" || c.Backend.TLS.ClientCertFile != "" || c.Backend.TLS.ClientKeyFile != "" || c.Backend.TLS.ServerName != "" || c.Backend.TLS.MinVersion != "") {
		return fmt.Errorf("backend.tls requires an https backend")
	}
	if raw := strings.TrimSpace(c.Backend.VerifierControl.URL); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("backend.verifier_control.url must be an absolute http/https URL without userinfo, query, or fragment")
		}
		loopback := u.Hostname() == "localhost"
		if addr, parseErr := netip.ParseAddr(u.Hostname()); parseErr == nil {
			loopback = addr.IsLoopback()
		}
		if u.Scheme != "https" && (!loopback || strings.TrimSpace(c.Backend.VerifierControl.Token) == "") {
			return fmt.Errorf("backend.verifier_control.url must use https, except loopback fixtures with a dedicated control token")
		}
		verifierControl := c.Backend.VerifierControl
		if (verifierControl.ClientCertFile == "") != (verifierControl.ClientKeyFile == "") {
			return fmt.Errorf("backend.verifier_control client_cert_file and client_key_file must be supplied together")
		}
		if verifierControl.ClientCertFile == "" && strings.TrimSpace(verifierControl.Token) == "" {
			return fmt.Errorf("backend.verifier_control requires a dedicated client certificate or token")
		}
		if token := strings.TrimSpace(verifierControl.Token); token != "" && len([]byte(token)) < control.MinOperatorTokenBytes {
			return fmt.Errorf("backend.verifier_control.token must contain at least %d bytes", control.MinOperatorTokenBytes)
		}
		if !loopback && verifierControl.ClientCertFile == "" {
			return fmt.Errorf("backend.verifier_control non-loopback endpoints require client certificate authentication; token-only control is limited to loopback fixtures")
		}
		if verifierControl.MinVersion != "" && verifierControl.MinVersion != "1.2" && verifierControl.MinVersion != "1.3" {
			return fmt.Errorf("backend.verifier_control.min_version must be \"1.2\" or \"1.3\"")
		}
	} else if c.Backend.VerifierControl.CAFile != "" || c.Backend.VerifierControl.ClientCertFile != "" || c.Backend.VerifierControl.ClientKeyFile != "" || c.Backend.VerifierControl.ServerName != "" || c.Backend.VerifierControl.MinVersion != "" || c.Backend.VerifierControl.Timeout.D() != 0 || c.Backend.VerifierControl.Token != "" {
		return fmt.Errorf("backend.verifier_control settings require backend.verifier_control.url")
	}
	if c.Backend.MaxResponseHeaderBytes == 0 {
		c.Backend.MaxResponseHeaderBytes = 64 << 10
	}
	if c.Backend.MaxResponseHeaderBytes < 0 {
		return fmt.Errorf("backend.max_response_header_bytes must be positive")
	}
	seenRoutes := make(map[string]struct{}, len(c.Backend.AllowedEndpoints))
	for i, rule := range c.Backend.AllowedEndpoints {
		method := strings.ToUpper(strings.TrimSpace(rule.Method))
		endpointPath := strings.TrimSpace(rule.Path)
		if method == "" || strings.ContainsAny(method, " \t\r\n") || endpointPath == "" || !strings.HasPrefix(endpointPath, "/v1/") || strings.ContainsAny(endpointPath, "?#*") {
			return fmt.Errorf("backend.allowed_endpoints[%d] must contain an exact method and /v1/ path", i)
		}
		if strings.Contains(endpointPath, "//") || path.Clean(endpointPath) != endpointPath || strings.Contains(endpointPath, "%") {
			return fmt.Errorf("backend.allowed_endpoints[%d].path %q is not canonical", i, endpointPath)
		}
		if _, err := url.PathUnescape(endpointPath); err != nil {
			return fmt.Errorf("backend.allowed_endpoints[%d].path is not valid escaped syntax: %w", i, err)
		}
		switch rule.RequiredScope {
		case "", "inference", "REQUEST", "LANE", "CREDENTIAL", "ACCOUNT":
		default:
			return fmt.Errorf("backend.allowed_endpoints[%d].required_scope %q is unsupported", i, rule.RequiredScope)
		}
		key := method + "\x00" + endpointPath
		if _, exists := seenRoutes[key]; exists {
			return fmt.Errorf("backend.allowed_endpoints[%d] duplicates %s %s", i, method, endpointPath)
		}
		seenRoutes[key] = struct{}{}
		c.Backend.AllowedEndpoints[i].Method = method
		c.Backend.AllowedEndpoints[i].Path = endpointPath
		profile := strings.TrimSpace(rule.UsageProfile)
		meteringEnabled := c.Usage.Mode == "openai" || c.Usage.Mode == "anthropic"
		if profile == "" && meteringEnabled {
			switch endpointPath {
			case "/v1/responses":
				profile = "openai-responses"
			case "/v1/embeddings":
				profile = "openai-embeddings"
			case "/v1/models":
				profile = "openai-models"
			case "/v1/chat/completions", "/v1/completions":
				profile = "openai-chat"
			case "/v1/messages":
				profile = "anthropic-messages"
			default:
				if c.Usage.Mode == "openai" || c.Usage.Mode == "anthropic" {
					return fmt.Errorf("backend.allowed_endpoints[%d] requires usage_profile for custom path %q", i, endpointPath)
				}
			}
		}
		switch profile {
		case "", "none", "openai-chat", "openai-responses", "openai-embeddings", "openai-models", "anthropic-messages":
		default:
			return fmt.Errorf("backend.allowed_endpoints[%d].usage_profile %q is unsupported", i, profile)
		}
		if c.Usage.Mode == "openai" && strings.HasPrefix(profile, "anthropic-") {
			return fmt.Errorf("backend.allowed_endpoints[%d].usage_profile %q is incompatible with usage.mode openai", i, profile)
		}
		if c.Usage.Mode == "anthropic" && strings.HasPrefix(profile, "openai-") {
			return fmt.Errorf("backend.allowed_endpoints[%d].usage_profile %q is incompatible with usage.mode anthropic", i, profile)
		}
		if profile == "openai-models" && method != "GET" {
			return fmt.Errorf("backend.allowed_endpoints[%d].usage_profile openai-models requires GET", i)
		}
		if profile != "none" && profile != "openai-models" && profile != "" && method != "POST" {
			return fmt.Errorf("backend.allowed_endpoints[%d].usage_profile %q requires POST", i, profile)
		}
		c.Backend.AllowedEndpoints[i].UsageProfile = profile
	}
	if _, err := c.BackendTLSConfig(); err != nil {
		return err
	}
	if strings.TrimSpace(c.Backend.VerifierControl.URL) != "" {
		if _, err := c.VerifierControlTLSConfig(); err != nil {
			return err
		}
	}

	// Server hardening: unbounded timeouts are boot failures.
	if c.Server.ReadTimeout.D() <= 0 {
		return fmt.Errorf("server.read_timeout required")
	}
	if c.Server.WriteTimeout.D() <= 0 {
		return fmt.Errorf("server.write_timeout required")
	}
	if c.Server.IdleTimeout.D() <= 0 {
		return fmt.Errorf("server.idle_timeout required")
	}
	if c.Server.ReadHeaderTimeout.D() <= 0 {
		return fmt.Errorf("server.read_header_timeout required (slowloris bound)")
	}
	if c.Server.ReadTimeout.D() < c.Server.ReadHeaderTimeout.D() {
		return fmt.Errorf("server.read_timeout must be >= read_header_timeout")
	}
	if c.Server.MaxHeaderBytes == 0 {
		c.Server.MaxHeaderBytes = 64 << 10
	}
	if c.Server.MaxBodyBytes == 0 {
		c.Server.MaxBodyBytes = 32 << 20
	}
	if c.Server.MaxHeaderBytes < 0 || c.Server.MaxBodyBytes < 0 {
		return fmt.Errorf("server.max_header_bytes/max_body_bytes must be non-negative")
	}
	if c.Server.MaxConnections == 0 {
		c.Server.MaxConnections = 4096
	}
	if c.Server.MaxConnections < 0 {
		return fmt.Errorf("server.max_connections must be positive")
	}
	if c.Server.HTTP2MaxConcurrentStreams == 0 {
		c.Server.HTTP2MaxConcurrentStreams = 100
	}
	if c.Server.HTTP2HeaderTableBytes == 0 {
		c.Server.HTTP2HeaderTableBytes = 4096
	}
	if c.Server.HTTP2MaxReadFrameBytes == 0 {
		c.Server.HTTP2MaxReadFrameBytes = 1 << 20
	}
	if c.Server.HTTP2MaxUploadBufferPerConnection == 0 {
		c.Server.HTTP2MaxUploadBufferPerConnection = 1 << 20
	}
	if c.Server.HTTP2MaxUploadBufferPerStream == 0 {
		c.Server.HTTP2MaxUploadBufferPerStream = 64 << 10
	}
	if c.Server.HTTP2MaxConcurrentStreams < 1 || c.Server.HTTP2MaxConcurrentStreams > 10000 || c.Server.HTTP2HeaderTableBytes < 1 || c.Server.HTTP2HeaderTableBytes > 4<<20 || c.Server.HTTP2MaxReadFrameBytes < 16<<10 || c.Server.HTTP2MaxReadFrameBytes > 16<<20 || c.Server.HTTP2MaxUploadBufferPerConnection < 65535 || c.Server.HTTP2MaxUploadBufferPerConnection > 16<<20 || c.Server.HTTP2MaxUploadBufferPerStream < 4<<10 || c.Server.HTTP2MaxUploadBufferPerStream > 4<<20 {
		return fmt.Errorf("server HTTP/2 bounds are invalid")
	}
	if c.Server.SpoolMaxBytes < 0 || c.Server.SpoolMaxFiles < 0 {
		return fmt.Errorf("server.spool_max_bytes/spool_max_files must be non-negative")
	}
	if c.Server.SpoolMemoryThreshold == 0 {
		c.Server.SpoolMemoryThreshold = defaultSpoolMemoryThreshold
	}
	if c.Server.SpoolMemoryThreshold < 1 || c.Server.SpoolMemoryThreshold > 64<<20 {
		return fmt.Errorf("server.spool_memory_threshold must be between 1 and 67108864 bytes")
	}
	if c.Server.ShutdownTimeout.D() == 0 {
		c.Server.ShutdownTimeout = Duration(defaultShutdownTimeout)
	}
	if c.Server.ShutdownTimeout.D() < time.Second || c.Server.ShutdownTimeout.D() > 10*time.Minute {
		return fmt.Errorf("server.shutdown_timeout must be between 1s and 10m")
	}
	// Unknown-length request bodies consume process and filesystem resources
	// before the backend can help. Persistent deployments must never silently
	// opt into an unlimited aggregate spool budget. The values are intentionally
	// conservative and remain overridable for a known workload.
	if !c.Deployment.AllowEphemeralState {
		if c.Server.SpoolMaxBytes == 0 {
			c.Server.SpoolMaxBytes = 64 << 20
		}
		if c.Server.SpoolMaxFiles == 0 {
			c.Server.SpoolMaxFiles = 64
		}
	}
	if c.Server.MaxSourceScopes < 0 || c.Server.SourceScopeIdle.D() < 0 || c.Server.PreAuthMaxConcurrent < 0 || c.Server.PreAuthRequestsPerSecond < 0 || c.Server.PreAuthSourceRequestsPerSecond < 0 || c.Server.PreAuthMaxSources < 0 {
		return fmt.Errorf("server source and pre-auth bounds must be non-negative")
	}
	if c.Server.PreAuthSourceIdle.D() < 0 {
		return fmt.Errorf("server.preauth_source_idle must be non-negative")
	}
	if c.Server.PreAuthSourceIdle.D() == 0 {
		c.Server.PreAuthSourceIdle = Duration(10 * time.Minute)
	}
	if c.Server.StreamWriteIdleTimeout.D() < 0 {
		return fmt.Errorf("server.stream_write_idle_timeout must be non-negative")
	}
	if len(c.Secrets.PepperVersions) > credentialMaxLoadedGenerations {
		return fmt.Errorf("secrets.pepper_versions may contain at most %d loaded generations", credentialMaxLoadedGenerations)
	}
	for version, value := range c.Secrets.PepperVersions {
		if _, err := parseGenerationKey(version); err != nil {
			return fmt.Errorf("secrets.pepper_versions key %q must be a positive decimal version", version)
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("secrets.pepper_versions[%q] must not be empty", version)
		}
	}
	if c.Usage.Mode != "" && c.Usage.Mode != "none" && c.Usage.Mode != "openai" && c.Usage.Mode != "anthropic" {
		return fmt.Errorf("usage.mode must be none, openai, or anthropic, got %q", c.Usage.Mode)
	}
	if c.Usage.CostMode != "" && c.Usage.CostMode != "none" && c.Usage.CostMode != "conservative" && c.Usage.CostMode != "exact" {
		return fmt.Errorf("usage.cost_mode must be none, conservative, or exact, got %q", c.Usage.CostMode)
	}
	if c.Usage.InputMicrounitsPerToken < 0 || c.Usage.OutputMicrounitsPerToken < 0 || c.Usage.CacheReadMicrounitsPerToken < 0 || c.Usage.CacheCreationMicrounitsPerToken < 0 || c.Usage.CacheCreation5mMicrounitsPerToken < 0 || c.Usage.CacheCreation1hMicrounitsPerToken < 0 || c.Usage.DefaultOutputTokens < 0 || c.Usage.MaxOutputTokens < 0 {
		return fmt.Errorf("usage pricing and output-token bounds must be non-negative")
	}
	if (c.Usage.Mode == "openai" || c.Usage.Mode == "anthropic") && c.Usage.MaxOutputTokens == 0 {
		return fmt.Errorf("usage.max_output_tokens is required when usage.mode enables token metering")
	}
	if c.Usage.Mode == "" || c.Usage.Mode == "none" {
		if c.Usage.CostMode == "" {
			c.Usage.CostMode = "none"
		} else if c.Usage.CostMode != "none" {
			return fmt.Errorf("usage.cost_mode %q requires usage.mode openai or anthropic", c.Usage.CostMode)
		}
	} else if c.Usage.CostMode == "" {
		c.Usage.CostMode = "conservative"
	}
	if c.Usage.CostMode == "exact" {
		if c.Usage.InputMicrounitsPerToken <= 0 || c.Usage.OutputMicrounitsPerToken <= 0 {
			return fmt.Errorf("usage.cost_mode exact requires positive input and output pricing")
		}
		switch c.Usage.Mode {
		case "openai":
			// Chat and Responses can expose cached input independently of
			// ordinary input. An exact monetary posture must configure that
			// dimension rather than silently billing it at zero.
			if c.Usage.CacheReadMicrounitsPerToken <= 0 {
				return fmt.Errorf("usage.cost_mode exact with usage.mode openai requires positive cache_read_microunits_per_token")
			}
		case "anthropic":
			// Anthropic exposes separate 5-minute and 1-hour cache creation
			// prices. The legacy aggregate rate is insufficient for exact
			// billing when both TTL classes occur in one response.
			if c.Usage.CacheReadMicrounitsPerToken <= 0 || c.Usage.CacheCreation5mMicrounitsPerToken <= 0 || c.Usage.CacheCreation1hMicrounitsPerToken <= 0 {
				return fmt.Errorf("usage.cost_mode exact with usage.mode anthropic requires positive cache_read_microunits_per_token, cache_creation_5m_microunits_per_token, and cache_creation_1h_microunits_per_token")
			}
		}
	}
	if c.Ingress != nil {
		loadedPseudonymGenerations := len(c.Ingress.PseudonymKeys)
		if c.Ingress.PseudonymKey != "" {
			if _, explicitVersionOne := c.Ingress.PseudonymKeys["1"]; !explicitVersionOne {
				loadedPseudonymGenerations++
			}
		}
		if loadedPseudonymGenerations > pseudonymMaxLoadedGenerations {
			return fmt.Errorf("ingress.pseudonym_keys may contain at most %d loaded generations", pseudonymMaxLoadedGenerations)
		}
		for version, value := range c.Ingress.PseudonymKeys {
			if _, err := parseGenerationKey(version); err != nil {
				return fmt.Errorf("ingress.pseudonym_keys key %q must be a positive decimal version", version)
			}
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("ingress.pseudonym_keys[%q] must not be empty", version)
			}
		}
		for i, network := range c.Ingress.Networks {
			if _, err := netip.ParsePrefix(network.CIDR); err != nil {
				return fmt.Errorf("ingress.networks[%d].cidr %q: %w", i, network.CIDR, err)
			}
			if network.ASN == "" && network.NetworkType == "" && network.Region == "" {
				return fmt.Errorf("ingress.networks[%d] must provide metadata", i)
			}
			if network.NetworkType != "" && network.NetworkType != "residential" && network.NetworkType != "hosting" && network.NetworkType != "mobile" && network.NetworkType != "unknown" {
				return fmt.Errorf("ingress.networks[%d].network_type %q is unsupported", i, network.NetworkType)
			}
		}
	}

	// Identity boundary.
	if c.Identity.Audience == "" {
		return fmt.Errorf("identity.audience required (INV-11: assertions are audience-bound)")
	}
	// Authority posture is explicit. A PostgreSQL node cannot accidentally
	// combine a shared credential authority with a local Bolt/evidence/audit
	// authority, and lease timing is part of the cluster's safety contract.
	switch strings.ToLower(strings.TrimSpace(c.Authority.Backend)) {
	case "", "standalone":
		if c.Authority.DSNEnv != "" || c.Authority.NodeID != "" || c.Authority.LeaseTTL.D() != 0 || c.Authority.RenewEvery.D() != 0 || c.Authority.ConnectTimeout.D() != 0 || c.Authority.OperationTimeout.D() != 0 || c.Authority.ReconcileInterval.D() != 0 || c.Authority.MaxSourceAliasIdentities != 0 || c.Authority.Maintenance.configured() {
			return fmt.Errorf("authority.dsn_env, node_id, lease timings require authority.backend=postgres")
		}
	case "postgres":
		if c.Deployment.AllowEphemeralState {
			return fmt.Errorf("deployment.allow_ephemeral_state cannot be enabled with authority.backend=postgres")
		}
		if c.Authority.DSNEnv == "" {
			return fmt.Errorf("authority.dsn_env required for authority.backend=postgres")
		}
		if strings.TrimSpace(c.Authority.NodeID) == "" {
			return fmt.Errorf("authority.node_id required for authority.backend=postgres")
		}
		if c.Paths.State != "" {
			return fmt.Errorf("paths.state must be empty when authority.backend=postgres")
		}
		if c.Paths.Evidence != "" || c.Paths.AuditLog != "" {
			return fmt.Errorf("paths.evidence and paths.audit_log must be empty when authority.backend=postgres")
		}
		if c.Authority.LeaseTTL.D() < 5*time.Second {
			return fmt.Errorf("authority.lease_ttl must be at least 5s for authority.backend=postgres")
		}
		if c.Authority.RenewEvery.D() <= 0 || c.Authority.RenewEvery.D() >= c.Authority.LeaseTTL.D()/2 {
			return fmt.Errorf("authority.renew_every must be positive and less than half authority.lease_ttl")
		}
		if c.Authority.ConnectTimeout.D() < 0 || c.Authority.OperationTimeout.D() < 0 {
			return fmt.Errorf("authority connect/operation timeouts cannot be negative")
		}
		if c.Authority.ReconcileInterval.D() < 0 {
			return fmt.Errorf("authority.reconcile_interval must be positive")
		}
		if c.Authority.ReconcileInterval.D() == 0 {
			c.Authority.ReconcileInterval = Duration(defaultAuthorityReconcile)
		}
		if c.Authority.MaxConns < 0 || c.Authority.MinConns < 0 || c.Authority.MaxSourceAliasIdentities < 0 || (c.Authority.MaxConns > 0 && c.Authority.MinConns > c.Authority.MaxConns) {
			return fmt.Errorf("authority min/max connection bounds are invalid")
		}
		maxScopes := c.Server.MaxSourceScopes
		if maxScopes == 0 {
			maxScopes = 4096
		}
		maxAliases := c.Authority.MaxSourceAliasIdentities
		if maxAliases == 0 {
			maxAliases = 4096
		}
		if maxAliases < maxScopes {
			return fmt.Errorf("authority.max_source_alias_identities (%d) must be >= server.max_source_scopes (%d)", maxAliases, maxScopes)
		}
		if c.Authority.Maintenance.BatchSize < 0 || c.Authority.Maintenance.MaxBatchesPerPass < 0 || c.Authority.Maintenance.MaxRowsPerPass < 0 {
			return fmt.Errorf("authority.maintenance batch limits must be non-negative")
		}
		retentions := []struct {
			name  string
			value time.Duration
		}{
			{"interval", c.Authority.Maintenance.Interval.D()}, {"max_runtime_per_pass", c.Authority.Maintenance.MaxRuntimePerPass.D()}, {"evidence_grace", c.Authority.Maintenance.EvidenceGrace.D()},
			{"released_lease_retention", c.Authority.Maintenance.ReleasedLeaseRetention.D()}, {"credential_receipt_retention", c.Authority.Maintenance.CredentialReceiptRetention.D()},
			{"control_operation_retention", c.Authority.Maintenance.ControlOperationRetention.D()}, {"admission_audit_retention", c.Authority.Maintenance.AdmissionAuditRetention.D()},
			{"security_transition_retention", c.Authority.Maintenance.SecurityTransitionRetention.D()}, {"operator_audit_retention", c.Authority.Maintenance.OperatorAuditRetention.D()},
			{"policy_audit_retention", c.Authority.Maintenance.PolicyAuditRetention.D()}, {"membership_retention", c.Authority.Maintenance.MembershipRetention.D()},
			{"adaptive_retention", c.Authority.Maintenance.AdaptiveRetention.D()}, {"evidence_guard_retention", c.Authority.Maintenance.EvidenceGuardRetention.D()},
			{"lane_operator_audit_retention", c.Authority.Maintenance.LaneOperatorAuditRetention.D()}, {"policy_node_state_retention", c.Authority.Maintenance.PolicyNodeStateRetention.D()},
			{"cluster_crypto_ack_retention", c.Authority.Maintenance.ClusterCryptoAckRetention.D()}, {"source_alias_retention", c.Authority.Maintenance.SourceAliasRetention.D()},
		}
		for _, retention := range retentions {
			if retention.value < 0 {
				return fmt.Errorf("authority.maintenance.%s must be non-negative", retention.name)
			}
		}
	default:
		return fmt.Errorf("authority.backend must be standalone or postgres")
	}
	// P0.7: state-backed deployments use Bolt as the sole operator-audit
	// authority. Reject a second JSONL path even when the admin listener is
	// currently disabled, so enabling it later cannot introduce split history.
	if c.Paths.State != "" && c.Paths.AuditLog != "" {
		return fmt.Errorf("paths.audit_log must be empty when paths.state is configured: Bolt is the sole operator-audit authority")
	}
	if c.Policy.File != "" && c.Policy.VerifierKeyFile == "" {
		return fmt.Errorf("policy.verifier_key_file is required when policy.file is configured: unsigned policy artifacts are not accepted")
	}
	// A verifier key may be configured without a startup artifact so operators
	// can prepare signed candidates against the built-in default policy. The
	// key is still required whenever a file artifact is selected.

	// Admin: if exposed, it must be fully configured (P0.47).
	if c.Admin != nil {
		if c.Admin.Listen == "" {
			return fmt.Errorf("admin.listen required when the admin section is present")
		}
		if len(c.Admin.OperatorTokens) == 0 {
			return fmt.Errorf("admin.operator_tokens required when the admin section is present")
		}
		if c.Admin.MaxConnections == 0 {
			c.Admin.MaxConnections = defaultAdminMaxConnections
		}
		if c.Admin.ReadHeaderTimeout.D() == 0 {
			c.Admin.ReadHeaderTimeout = Duration(defaultAdminReadHeaderTimeout)
		}
		if c.Admin.ReadTimeout.D() == 0 {
			c.Admin.ReadTimeout = Duration(defaultAdminReadTimeout)
		}
		if c.Admin.WriteTimeout.D() == 0 {
			c.Admin.WriteTimeout = Duration(defaultAdminWriteTimeout)
		}
		if c.Admin.IdleTimeout.D() == 0 {
			c.Admin.IdleTimeout = Duration(defaultAdminIdleTimeout)
		}
		if c.Admin.MaxConnections < 1 || c.Admin.MaxConnections > 1_000_000 {
			return fmt.Errorf("admin.max_connections must be between 1 and 1000000")
		}
		if c.Admin.ReadHeaderTimeout.D() <= 0 || c.Admin.ReadTimeout.D() <= 0 || c.Admin.WriteTimeout.D() <= 0 || c.Admin.IdleTimeout.D() <= 0 {
			return fmt.Errorf("admin read/write/idle timeouts must be positive")
		}
		if c.Admin.ReadTimeout.D() < c.Admin.ReadHeaderTimeout.D() {
			return fmt.Errorf("admin.read_timeout must be >= admin.read_header_timeout")
		}
		for tok, spec := range c.Admin.OperatorTokens {
			if tok == "" {
				return fmt.Errorf("admin.operator_tokens contains an empty token")
			}
			if len([]byte(tok)) < control.MinOperatorTokenBytes {
				return fmt.Errorf("admin.operator_tokens token must contain at least %d bytes (generate with openssl rand -base64 32)", control.MinOperatorTokenBytes)
			}
			name, caps, err := parseOperatorSpec(spec)
			if err != nil {
				return fmt.Errorf("admin.operator_tokens: %w", err)
			}
			if name == "" || len(caps) == 0 {
				return fmt.Errorf("admin.operator_tokens: entry must be \"name:cap1,cap2\"")
			}
			for _, rawCap := range caps {
				if _, err := control.ParseCapability(rawCap); err != nil {
					return fmt.Errorf("admin.operator_tokens: %w", err)
				}
			}
		}
		if c.Paths.AuditLog == "" && c.Paths.State == "" && strings.ToLower(strings.TrimSpace(c.Authority.Backend)) != "postgres" {
			return fmt.Errorf("paths.audit_log required when the admin section is present without paths.state (P0.47: durable operator audit)")
		}
		// P0.7 hardening: reject a public/unspecified admin bind. The admin
		// listener is the operator control plane (posture + lifecycle
		// actions); binding it to a wildcard or public interface contradicts
		// the "private interface only" contract. There is NO override: an
		// internet-facing plaintext-token control plane is not a deployable
		// posture (P0-14 removal of admin.allow_public).
		if err := validateAdminBind(c.Admin); err != nil {
			return err
		}
	}
	return nil
}

func backendHostnameIsLoopback(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	return err == nil && addr.IsLoopback()
}

// requirePrivateBind enforces that a listener address binds loopback or a
// private (RFC1918 / unique-local / link-local) interface. It is used for the
// public listener when TLS is terminated upstream; the admin control plane is
// stricter and uses validateAdminBind below.
func requirePrivateBind(listen, what string) error {
	host := listen
	if h, _, err := net.SplitHostPort(listen); err == nil {
		host = h
	}
	if host == "" {
		return fmt.Errorf("%s %q: wildcard host is not allowed for this listener (bind 127.0.0.1 or a private interface)", what, listen)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%s %q: must be a numeric loopback or private address", what, listen)
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return nil
	}
	if addr.IsUnspecified() {
		return fmt.Errorf("%s %q: unspecified address is not allowed for this listener (bind 127.0.0.1 or a private interface)", what, listen)
	}
	return fmt.Errorf("%s %q: public address is not allowed for this listener (traffic is unencrypted on this bind; use 127.0.0.1 or a private interface)", what, listen)
}

// validateAdminBind enforces that the plaintext admin listener binds only to
// loopback. Private LAN addresses are intentionally rejected: a bearer token
// control plane must be reached through an explicit SSH/TLS tunnel.
func validateAdminBind(a *AdminSection) error {
	host := a.Listen
	if h, _, err := net.SplitHostPort(a.Listen); err == nil {
		host = h
	}
	if host == "" {
		return fmt.Errorf("admin.listen %q: wildcard host is not allowed (bind loopback and use an SSH/TLS tunnel)", a.Listen)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return fmt.Errorf("admin.listen %q: only a numeric loopback address is allowed; use an SSH/TLS tunnel for remote access", a.Listen)
	}
	return nil
}

// parseOperatorSpec parses "name:cap1,cap2".
func parseOperatorSpec(spec string) (string, []string, error) {
	name, caps, ok := strings.Cut(spec, ":")
	if !ok {
		return "", nil, fmt.Errorf("entry must be \"name:cap1,cap2\"")
	}
	var out []string
	for _, c := range strings.Split(caps, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			out = append(out, c)
		}
	}
	return strings.TrimSpace(name), out, nil
}

// TLSConfig computes the tls.Config for the public listener; nil means the
// listener is plain HTTP under an explicitly declared upstream terminator.
func (c *Config) TLSConfig() (minVersion uint16, enabled bool) {
	if c.TLS.CertFile == "" {
		return 0, false
	}
	switch c.TLS.MinVersion {
	case "1.3":
		return tlsVersion13, true
	default:
		return tlsVersion12, true
	}
}

// ValidateCertificates checks the TLS files exist and are readable at boot
// (fail fast, not first-request).
func (c *Config) ValidateCertificates() error {
	if c.TLS.CertFile != "" {
		for _, f := range []string{c.TLS.CertFile, c.TLS.KeyFile} {
			if fi, err := os.Stat(f); err != nil {
				return fmt.Errorf("config: tls file %s: %w", f, err)
			} else if fi.IsDir() {
				return fmt.Errorf("config: tls file %s is a directory", f)
			}
		}
		if _, err := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile); err != nil {
			return fmt.Errorf("config: tls certificate/key pair invalid: %w", err)
		}
	}
	control := c.Backend.VerifierControl
	if control.ClientCertFile != "" {
		if _, err := tls.LoadX509KeyPair(control.ClientCertFile, control.ClientKeyFile); err != nil {
			return fmt.Errorf("config: backend.verifier_control client certificate/key pair invalid: %w", err)
		}
	}
	return nil
}

// BackendTLSConfig loads and validates the upstream TLS material at boot.
// The returned config contains no mutable references to the decoded CA pool
// or client certificate slices owned by the caller.
func (c *Config) BackendTLSConfig() (*tls.Config, error) {
	return tlsConfigFor("backend.tls", c.Backend.TLS)
}

// VerifierControlTLSConfig loads the dedicated control-plane TLS material.
func (c *Config) VerifierControlTLSConfig() (*tls.Config, error) {
	return tlsConfigFor("backend.verifier_control", BackendTLSSection{
		CAFile: c.Backend.VerifierControl.CAFile, ClientCertFile: c.Backend.VerifierControl.ClientCertFile,
		ClientKeyFile: c.Backend.VerifierControl.ClientKeyFile, ServerName: c.Backend.VerifierControl.ServerName,
		MinVersion: c.Backend.VerifierControl.MinVersion,
	})
}

func tlsConfigFor(prefix string, t BackendTLSSection) (*tls.Config, error) {
	if t.ClientCertFile != "" || t.ClientKeyFile != "" {
		if t.ClientCertFile == "" || t.ClientKeyFile == "" {
			return nil, fmt.Errorf("%s client_cert_file and client_key_file must be supplied together", prefix)
		}
	}
	minVersion := uint16(tls.VersionTLS12)
	switch t.MinVersion {
	case "", "1.2":
	case "1.3":
		minVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("%s.min_version must be \"1.2\" or \"1.3\"", prefix)
	}
	tlsCfg := &tls.Config{MinVersion: minVersion, ServerName: t.ServerName} // #nosec G402 -- TLS 1.2 is the explicit compatibility floor; production examples use TLS 1.3.
	if t.CAFile != "" {
		data, err := os.ReadFile(filepath.Clean(t.CAFile))
		if err != nil {
			return nil, fmt.Errorf("config: %s.ca_file: %w", prefix, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("config: %s.ca_file contains no certificates", prefix)
		}
		tlsCfg.RootCAs = pool
	}
	if t.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(t.ClientCertFile, t.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("config: %s client certificate/key pair invalid: %w", prefix, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

const (
	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304
)
