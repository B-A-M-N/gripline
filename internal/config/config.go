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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
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
	// URL is the upstream origin, e.g. "https://provider.internal:443/v1".
	URL string `json:"url"`
	// Timeout bounds the full upstream exchange (dial + headers + body).
	Timeout Duration `json:"timeout"`
	// MaxIdleConnsPerHost tunes connection pooling (0 = default).
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`
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
	// AuditLog is the append-only operator audit JSONL (P0.47). Required when
	// Admin is configured.
	AuditLog string `json:"audit_log"`
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
	if err := json.Unmarshal([]byte(expanded), &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
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
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
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

	// Fixed backend (P0.7).
	if c.Backend.URL == "" {
		return fmt.Errorf("backend.url required (the fixed upstream origin)")
	}
	if c.Backend.Timeout.D() <= 0 {
		return fmt.Errorf("backend.timeout required (an unbounded upstream exchange is not deployable)")
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

	// Identity boundary.
	if c.Identity.Audience == "" {
		return fmt.Errorf("identity.audience required (INV-11: assertions are audience-bound)")
	}

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
			name, caps, err := parseOperatorSpec(spec)
			if err != nil {
				return fmt.Errorf("admin.operator_tokens: %w", err)
			}
			if name == "" || len(caps) == 0 {
				return fmt.Errorf("admin.operator_tokens: entry must be \"name:cap1,cap2\"")
			}
		}
		if c.Paths.AuditLog == "" {
			return fmt.Errorf("paths.audit_log required when the admin section is present (P0.47: durable operator audit)")
		}
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
	return nil
}

const (
	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304
)
