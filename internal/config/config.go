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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
)

// Duration is a JSON-friendly time.Duration: it accepts string forms
// ("30s", "1m") in configuration files, which plain time.Duration does not.
type Duration time.Duration

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

// Config is the complete deployment configuration. Every field with a
// security consequence is REQUIRED (no implicit defaults for TLS posture,
// backend target, or limits); Validate enforces the cross-field invariants.
type Config struct {
	// Listen is the public listener address, e.g. ":8080".
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
	Mode                     string `json:"mode,omitempty"`
	InputMicrounitsPerToken  int64  `json:"input_microunits_per_token,omitempty"`
	OutputMicrounitsPerToken int64  `json:"output_microunits_per_token,omitempty"`
	DefaultOutputTokens      int64  `json:"default_output_tokens,omitempty"`
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

// BackendSection is the fixed upstream (P0.7).
type BackendSection struct {
	// URL is the upstream origin, e.g. "https://provider.internal:443".
	URL string `json:"url"`
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
	// TLS configures private-CA and optional client-certificate authentication
	// for an HTTPS backend. Cert and key must be supplied together.
	TLS BackendTLSSection `json:"tls,omitempty"`
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
	// MaxSourceScopes bounds source pseudonym state in the process-local
	// governor. Zero uses the conservative runtime default.
	MaxSourceScopes int `json:"max_source_scopes,omitempty"`
	// SourceScopeIdle is the minimum idle horizon before a fully replenished
	// source scope may be evicted.
	SourceScopeIdle Duration `json:"source_scope_idle,omitempty"`
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
	raw, err := os.ReadFile(path)
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
	if u, err := url.Parse(c.Backend.URL); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("backend.url must be an absolute http/https URL")
	} else if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("backend.url scheme must be http or https")
	} else if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("backend.url must not contain userinfo, query, or fragment")
	} else if u.Scheme != "https" && (c.Backend.TLS.CAFile != "" || c.Backend.TLS.ClientCertFile != "" || c.Backend.TLS.ClientKeyFile != "" || c.Backend.TLS.ServerName != "" || c.Backend.TLS.MinVersion != "") {
		return fmt.Errorf("backend.tls requires an https backend")
	}
	if _, err := c.BackendTLSConfig(); err != nil {
		return err
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
	if c.Server.SpoolMaxBytes < 0 || c.Server.SpoolMaxFiles < 0 {
		return fmt.Errorf("server.spool_max_bytes/spool_max_files must be non-negative")
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
	if c.Server.MaxSourceScopes < 0 || c.Server.SourceScopeIdle.D() < 0 {
		return fmt.Errorf("server.max_source_scopes/source_scope_idle must be non-negative")
	}
	if c.Server.StreamWriteIdleTimeout.D() < 0 {
		return fmt.Errorf("server.stream_write_idle_timeout must be non-negative")
	}
	for version, value := range c.Secrets.PepperVersions {
		n, err := strconv.Atoi(version)
		if err != nil || n < 1 {
			return fmt.Errorf("secrets.pepper_versions key %q must be a positive decimal version", version)
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("secrets.pepper_versions[%q] must not be empty", version)
		}
	}
	if c.Usage.Mode != "" && c.Usage.Mode != "none" && c.Usage.Mode != "openai" && c.Usage.Mode != "anthropic" {
		return fmt.Errorf("usage.mode must be none, openai, or anthropic, got %q", c.Usage.Mode)
	}
	if c.Usage.InputMicrounitsPerToken < 0 || c.Usage.OutputMicrounitsPerToken < 0 || c.Usage.DefaultOutputTokens < 0 || c.Usage.MaxOutputTokens < 0 {
		return fmt.Errorf("usage pricing and output-token bounds must be non-negative")
	}
	if (c.Usage.Mode == "openai" || c.Usage.Mode == "anthropic") && c.Usage.MaxOutputTokens == 0 {
		return fmt.Errorf("usage.max_output_tokens is required when usage.mode enables token metering")
	}
	if c.Ingress != nil {
		for version, value := range c.Ingress.PseudonymKeys {
			n, err := strconv.Atoi(version)
			if err != nil || n < 1 {
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
		if c.Paths.AuditLog == "" && c.Paths.State == "" {
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
	if c.TLS.CertFile == "" {
		return nil
	}
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
	return nil
}

// BackendTLSConfig loads and validates the upstream TLS material at boot.
// The returned config contains no mutable references to the decoded CA pool
// or client certificate slices owned by the caller.
func (c *Config) BackendTLSConfig() (*tls.Config, error) {
	t := c.Backend.TLS
	if t.ClientCertFile != "" || t.ClientKeyFile != "" {
		if t.ClientCertFile == "" || t.ClientKeyFile == "" {
			return nil, fmt.Errorf("backend.tls client_cert_file and client_key_file must be supplied together")
		}
	}
	minVersion := uint16(tls.VersionTLS12)
	switch t.MinVersion {
	case "", "1.2":
	case "1.3":
		minVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("backend.tls.min_version must be \"1.2\" or \"1.3\"")
	}
	tlsCfg := &tls.Config{MinVersion: minVersion, ServerName: t.ServerName}
	if t.CAFile != "" {
		data, err := os.ReadFile(filepath.Clean(t.CAFile))
		if err != nil {
			return nil, fmt.Errorf("config: backend.tls.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("config: backend.tls.ca_file contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	if t.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(t.ClientCertFile, t.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("config: backend.tls client certificate/key pair invalid: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

const (
	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304
)
