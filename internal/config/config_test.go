package config

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// strictUnmarshal decodes data into v rejecting unknown fields (the check
// used to prove a config field no longer exists on the surface).
func strictUnmarshal(data string, v any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(data)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func validConfigJSON() string {
	return `{
		"listen": ":8080",
		"tls": {"cert_file": "/etc/gripline/tls/cert.pem", "key_file": "/etc/gripline/tls/key.pem", "min_version": "1.3"},
		"backend": {"url": "https://provider.internal:443/v1", "timeout": "30s"},
		"server": {"read_timeout": "30s", "write_timeout": "60s", "idle_timeout": "120s", "read_header_timeout": "10s", "max_header_bytes": 65536, "max_body_bytes": 33554432},
		"identity": {"audience": "fi-inference"},
		"paths": {"audit_log": "/var/lib/gripline/audit.jsonl"}
	}`
}

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A fully-specified config loads.
func TestLoadValid(t *testing.T) {
	c, err := Load(writeCfg(t, validConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Backend.Timeout.D() != 30*time.Second || c.Identity.Audience != "fi-inference" {
		t.Fatalf("fields not parsed: %+v", c)
	}
	if c.Server.MaxConnections != 4096 || c.Server.HTTP2MaxConcurrentStreams != 100 || c.Server.HTTP2HeaderTableBytes != 4096 || c.Server.HTTP2MaxReadFrameBytes != 1<<20 {
		t.Fatalf("HTTP listener defaults not applied: %+v", c.Server)
	}
	if v, enabled := c.TLSConfig(); !enabled || v != tlsVersion13 {
		t.Fatalf("TLS config wrong: %v %v", v, enabled)
	}
	if err := c.ValidateCertificates(); err == nil {
		t.Fatal("nonexistent cert files must fail certificate validation")
	}
}

func TestDeploymentExamplesValidate(t *testing.T) {
	for _, name := range []string{"GRIPLINE_OPERATOR_TOKEN", "GRIPLINE_PEPPER_V1", "GRIPLINE_PEPPER_V2", "GRIPLINE_PSEUDONYM_KEY", "GRIPLINE_PSEUDONYM_V1", "GRIPLINE_PSEUDONYM_V2"} {
		t.Setenv(name, "fixture-"+name+"-0123456789abcdef0123456789abcdef")
	}
	paths, err := filepath.Glob(filepath.Join("..", "..", "deploy", "config*.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no deployment examples found")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fixtureDir := t.TempDir()
			caCert, clientKey := writeCertificateMaterial(t, fixtureDir, "verifier-control")
			raw = bytes.ReplaceAll(raw, []byte("/etc/gripline/tls/verifier-control-ca.pem"), []byte(caCert))
			raw = bytes.ReplaceAll(raw, []byte("/etc/gripline/tls/verifier-control-client.pem"), []byte(caCert))
			raw = bytes.ReplaceAll(raw, []byte("/etc/gripline/tls/verifier-control-client-key.pem"), []byte(clientKey))
			fixtureConfig := filepath.Join(fixtureDir, filepath.Base(path))
			if err := os.WriteFile(fixtureConfig, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(fixtureConfig); err != nil {
				t.Fatalf("deployment example rejected: %v", err)
			}
		})
	}
}

func TestValidateClusterAuthorityContract(t *testing.T) {
	c := &Config{
		Listen:    "127.0.0.1:8080",
		TLS:       TLSSection{TerminateTLSUpstream: true},
		Backend:   BackendSection{URL: "https://provider.internal", Timeout: Duration(time.Second)},
		Server:    ServerSection{ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), IdleTimeout: Duration(time.Second), ReadHeaderTimeout: Duration(time.Second)},
		Identity:  IdentitySection{Audience: "a"},
		Authority: AuthoritySection{Backend: "postgres", DSNEnv: "GRIPLINE_DSN", NodeID: "node-a", LeaseTTL: Duration(30 * time.Second), RenewEvery: Duration(10 * time.Second)},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid postgres authority rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"missing DSN reference": func(v *Config) { v.Authority.DSNEnv = "" },
		"missing node id":       func(v *Config) { v.Authority.NodeID = "" },
		"renewal too slow":      func(v *Config) { v.Authority.RenewEvery = Duration(15 * time.Second) },
		"local state split":     func(v *Config) { v.Paths.State = "/tmp/state.db" },
	} {
		copy := *c
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestValidateVerifierControlUsesDedicatedAuthentication(t *testing.T) {
	c := &Config{
		Listen: "127.0.0.1:8080",
		TLS:    TLSSection{TerminateTLSUpstream: true},
		Backend: BackendSection{
			URL:     "https://provider.internal:443/v1",
			Timeout: Duration(time.Second),
			VerifierControl: VerifierControlSection{
				URL: "https://127.0.0.1:9443/private/verifier", Token: "control-token-0123456789abcdef0123456789abcdef",
			},
		},
		Server:   ServerSection{ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), IdleTimeout: Duration(time.Second), ReadHeaderTimeout: Duration(time.Second)},
		Identity: IdentitySection{Audience: "a"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("dedicated verifier control endpoint rejected: %v", err)
	}
	shortToken := *c
	shortToken.Backend.VerifierControl.Token = "short"
	if err := shortToken.Validate(); err == nil {
		t.Fatal("short verifier-control token must be rejected")
	}
	for name, endpoint := range map[string]string{
		"missing authentication": "https://other.internal/private/verifier",
		"remote token only":      "https://other.internal/private/verifier",
		"insecure remote":        "http://10.0.0.2:9443/private/verifier",
	} {
		t.Run(name, func(t *testing.T) {
			copy := *c
			copy.Backend.VerifierControl.URL = endpoint
			if name == "missing authentication" || name == "insecure remote" {
				copy.Backend.VerifierControl.Token = ""
			}
			if err := copy.Validate(); err == nil {
				t.Fatal("verifier control endpoint without dedicated authentication must be rejected")
			}
		})
	}
}

func TestValidateEndpointRulesCompilesCanonicalRoutes(t *testing.T) {
	base := &Config{
		Listen: "127.0.0.1:8080", TLS: TLSSection{TerminateTLSUpstream: true},
		Backend:  BackendSection{URL: "https://provider.internal", Timeout: Duration(time.Second)},
		Server:   ServerSection{ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), IdleTimeout: Duration(time.Second), ReadHeaderTimeout: Duration(time.Second)},
		Identity: IdentitySection{Audience: "a"},
	}
	for name, rules := range map[string][]EndpointRule{
		"duplicate":     {{Method: "POST", Path: "/v1/messages"}, {Method: "post", Path: "/v1/messages"}},
		"unknown scope": {{Method: "POST", Path: "/v1/messages", RequiredScope: "infernece"}},
		"outside v1":    {{Method: "POST", Path: "/admin"}},
		"dot segment":   {{Method: "POST", Path: "/v1/../admin"}},
		"double slash":  {{Method: "POST", Path: "/v1//messages"}},
		"encoded dot":   {{Method: "POST", Path: "/v1/%2e%2e/admin"}},
	} {
		t.Run(name, func(t *testing.T) {
			copy := *base
			copy.Backend.AllowedEndpoints = rules
			if err := copy.Validate(); err == nil {
				t.Fatal("invalid endpoint rule must be rejected")
			}
		})
	}
	valid := *base
	valid.Backend.AllowedEndpoints = []EndpointRule{{Method: "post", Path: "/v1/messages", RequiredScope: "inference"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("canonical endpoint rule rejected: %v", err)
	}
	if valid.Backend.AllowedEndpoints[0].Method != "POST" {
		t.Fatalf("method was not canonicalized: %q", valid.Backend.AllowedEndpoints[0].Method)
	}
}

func TestValidateUsageProfilesSeparateMeteredAndUnmeteredRoutes(t *testing.T) {
	base := func(mode string) Config {
		return Config{
			Listen:   "127.0.0.1:8080",
			TLS:      TLSSection{TerminateTLSUpstream: true},
			Backend:  BackendSection{URL: "https://provider.internal", Timeout: Duration(time.Second)},
			Server:   ServerSection{ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), IdleTimeout: Duration(time.Second), ReadHeaderTimeout: Duration(time.Second)},
			Identity: IdentitySection{Audience: "a"},
			Usage:    UsageSection{Mode: mode, InputMicrounitsPerToken: 1, OutputMicrounitsPerToken: 1, MaxOutputTokens: 8},
		}
	}

	none := base("none")
	none.Backend.AllowedEndpoints = []EndpointRule{{Method: "GET", Path: "/v1/messages"}}
	if err := none.Validate(); err != nil {
		t.Fatalf("unmetered GET /v1/messages rejected: %v", err)
	}
	if got := none.Backend.AllowedEndpoints[0].UsageProfile; got != "" {
		t.Fatalf("unmetered route inferred usage profile %q", got)
	}

	anthropic := base("anthropic")
	anthropic.Backend.AllowedEndpoints = []EndpointRule{{Method: "GET", Path: "/v1/messages"}}
	if err := anthropic.Validate(); err == nil {
		t.Fatal("metered Anthropic GET /v1/messages must be rejected")
	}

	explicitNone := base("anthropic")
	explicitNone.Backend.AllowedEndpoints = []EndpointRule{{Method: "GET", Path: "/v1/health", UsageProfile: "none"}}
	if err := explicitNone.Validate(); err != nil {
		t.Fatalf("explicit unmetered route rejected: %v", err)
	}

	mixed := base("openai")
	mixed.Backend.AllowedEndpoints = []EndpointRule{
		{Method: "GET", Path: "/v1/health", UsageProfile: "none"},
		{Method: "POST", Path: "/v1/chat/completions"},
	}
	if err := mixed.Validate(); err != nil {
		t.Fatalf("mixed metered/unmetered routes rejected: %v", err)
	}
	if got := mixed.Backend.AllowedEndpoints[1].UsageProfile; got != "openai-chat" {
		t.Fatalf("metered route profile=%q, want openai-chat", got)
	}
}

func TestValidateExactUsageRequiresProviderCachePricing(t *testing.T) {
	base := func(mode string) Config {
		return Config{
			Listen:   "127.0.0.1:8080",
			TLS:      TLSSection{TerminateTLSUpstream: true},
			Backend:  BackendSection{URL: "https://provider.internal", Timeout: Duration(time.Second)},
			Server:   ServerSection{ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), IdleTimeout: Duration(time.Second), ReadHeaderTimeout: Duration(time.Second)},
			Identity: IdentitySection{Audience: "a"},
			Usage:    UsageSection{Mode: mode, CostMode: "exact", InputMicrounitsPerToken: 3, OutputMicrounitsPerToken: 15, MaxOutputTokens: 8},
		}
	}
	openai := base("openai")
	if err := openai.Validate(); err == nil {
		t.Fatal("exact OpenAI cost posture must require cached-input pricing")
	}
	openai.Usage.CacheReadMicrounitsPerToken = 1
	if err := openai.Validate(); err != nil {
		t.Fatalf("exact OpenAI pricing rejected: %v", err)
	}
	anthropic := base("anthropic")
	anthropic.Usage.CacheReadMicrounitsPerToken = 1
	anthropic.Usage.CacheCreation5mMicrounitsPerToken = 4
	if err := anthropic.Validate(); err == nil {
		t.Fatal("exact Anthropic cost posture must require both cache creation TTL prices")
	}
	anthropic.Usage.CacheCreation1hMicrounitsPerToken = 8
	if err := anthropic.Validate(); err != nil {
		t.Fatalf("exact Anthropic pricing rejected: %v", err)
	}
}

func TestValidateUsageCostModeDefaultsAndRejectsUnusedPosture(t *testing.T) {
	c := Config{
		Listen:   "127.0.0.1:8080",
		TLS:      TLSSection{TerminateTLSUpstream: true},
		Backend:  BackendSection{URL: "https://provider.internal", Timeout: Duration(time.Second)},
		Server:   ServerSection{ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), IdleTimeout: Duration(time.Second), ReadHeaderTimeout: Duration(time.Second)},
		Identity: IdentitySection{Audience: "a"},
		Usage:    UsageSection{Mode: "openai", InputMicrounitsPerToken: 3, OutputMicrounitsPerToken: 15, MaxOutputTokens: 8},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("conservative usage default rejected: %v", err)
	}
	if c.Usage.CostMode != "conservative" {
		t.Fatalf("usage cost mode default=%q, want conservative", c.Usage.CostMode)
	}
	c = Config{
		Listen:   "127.0.0.1:8080",
		TLS:      TLSSection{TerminateTLSUpstream: true},
		Backend:  BackendSection{URL: "https://provider.internal", Timeout: Duration(time.Second)},
		Server:   ServerSection{ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), IdleTimeout: Duration(time.Second), ReadHeaderTimeout: Duration(time.Second)},
		Identity: IdentitySection{Audience: "a"},
		Usage:    UsageSection{Mode: "none", CostMode: "exact"},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("cost posture without a usage adapter must be rejected")
	}
}

func TestValidateClusterAdminUsesPostgresAuditAuthority(t *testing.T) {
	c := &Config{
		Listen:   "127.0.0.1:8080",
		TLS:      TLSSection{TerminateTLSUpstream: true},
		Backend:  BackendSection{URL: "https://provider.internal", Timeout: Duration(time.Second)},
		Server:   ServerSection{ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), IdleTimeout: Duration(time.Second), ReadHeaderTimeout: Duration(time.Second)},
		Identity: IdentitySection{Audience: "a"},
		Authority: AuthoritySection{
			Backend: "postgres", DSNEnv: "GRIPLINE_DSN", NodeID: "node-a",
			LeaseTTL: Duration(30 * time.Second), RenewEvery: Duration(10 * time.Second),
		},
		Admin: &AdminSection{
			Listen: "127.0.0.1:9090",
			OperatorTokens: map[string]string{
				"operator-token-0123456789abcdef0123456789abcdef": "operator:posture.control",
			},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("postgres authority must satisfy admin audit durability: %v", err)
	}

	withLocalAudit := *c
	withLocalAudit.Paths.AuditLog = "/tmp/gripline-audit.jsonl"
	if err := withLocalAudit.Validate(); err == nil {
		t.Fatal("postgres authority must reject a local audit path")
	}
}

func TestValidateStandaloneEphemeralAdminRequiresAuditPath(t *testing.T) {
	c := &Config{
		Listen:     "127.0.0.1:8080",
		TLS:        TLSSection{TerminateTLSUpstream: true},
		Backend:    BackendSection{URL: "https://provider.internal", Timeout: Duration(time.Second)},
		Server:     ServerSection{ReadTimeout: Duration(time.Second), WriteTimeout: Duration(time.Second), IdleTimeout: Duration(time.Second), ReadHeaderTimeout: Duration(time.Second)},
		Identity:   IdentitySection{Audience: "a"},
		Deployment: DeploymentSection{AllowEphemeralState: true},
		Admin: &AdminSection{
			Listen: "127.0.0.1:9090",
			OperatorTokens: map[string]string{
				"operator-token-0123456789abcdef0123456789abcdef": "operator:posture.control",
			},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("standalone ephemeral admin must require a durable JSONL audit path")
	}
	c.Paths.AuditLog = "/tmp/gripline-audit.jsonl"
	if err := c.Validate(); err != nil {
		t.Fatalf("standalone ephemeral admin with audit path rejected: %v", err)
	}
}

func writeCertificateMaterial(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IsCA:     true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestValidateCertificatesMaterial(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCertificateMaterial(t, dir, "listener")
	_, otherKey := writeCertificateMaterial(t, dir, "other")

	valid := &Config{TLS: TLSSection{CertFile: cert, KeyFile: key}}
	if err := valid.ValidateCertificates(); err != nil {
		t.Fatalf("valid certificate/key pair rejected: %v", err)
	}
	for name, cfg := range map[string]*Config{
		"malformed certificate": {TLS: TLSSection{CertFile: filepath.Join(dir, "bad.crt"), KeyFile: key}},
		"mismatched key":        {TLS: TLSSection{CertFile: cert, KeyFile: otherKey}},
	} {
		if name == "malformed certificate" {
			if err := os.WriteFile(cfg.TLS.CertFile, []byte("not a certificate"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := cfg.ValidateCertificates(); err == nil {
			t.Errorf("%s must fail certificate validation", name)
		}
	}

	if err := (&Config{TLS: TLSSection{CertFile: cert}}).ValidateCertificates(); err == nil {
		t.Fatal("one-sided certificate configuration must fail")
	}
}

func TestBackendTLSConfigMaterial(t *testing.T) {
	dir := t.TempDir()
	caCert, _ := writeCertificateMaterial(t, dir, "ca")
	clientCert, clientKey := writeCertificateMaterial(t, dir, "client")
	c := &Config{Backend: BackendSection{TLS: BackendTLSSection{
		CAFile: caCert, ClientCertFile: clientCert, ClientKeyFile: clientKey,
		ServerName: "backend.internal", MinVersion: "1.3",
	}}}
	tlsConfig, err := c.BackendTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.RootCAs == nil || len(tlsConfig.Certificates) != 1 {
		t.Fatalf("backend TLS material not loaded: %+v", tlsConfig)
	}
	bad := *c
	bad.Backend.TLS.ClientKeyFile = filepath.Join(dir, "missing.key")
	if _, err := bad.BackendTLSConfig(); err == nil {
		t.Fatal("missing client key must fail backend TLS validation")
	}
}

// Every security-consequential zero is a boot failure, not a degraded default.
func TestValidateRejectsMissingSecurityDecisions(t *testing.T) {
	cases := map[string]string{
		"no tls posture":         `{"listen":":8080","backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"no backend":             `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"no backend timeout":     `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"unbounded read":         `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"unbounded write":        `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"unbounded idle":         `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"no header bound":        `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s"},"identity":{"audience":"a"}}`,
		"no audience":            `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{}}`,
		"admin without audit":    `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":":9090","operator_tokens":{"t":"op:posture.control"}}}`,
		"admin without tokens":   `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":":9090"},"paths":{"audit_log":"a.jsonl"}}`,
		"state and audit mirror": `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"paths":{"state":"state.db","audit_log":"audit.jsonl"}}`,
		"unknown capability":     `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":"127.0.0.1:9090","operator_tokens":{"01234567890123456789012345678901":"op:posture.typo"}},"paths":{"audit_log":"audit.jsonl"}}`,
		"bad min version":        `{"listen":":8080","tls":{"terminate_tls_upstream":true,"min_version":"1.1"},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
	}
	for name, body := range cases {
		if _, err := Load(writeCfg(t, body)); err == nil {
			t.Errorf("%s: must fail validation", name)
		}
	}
}

// TLS-vs-upstream-termination is exclusive.
func TestTLSExclusivity(t *testing.T) {
	base := `{"listen":":8080","tls":{"cert_file":"c.pem","key_file":"k.pem","terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`
	if _, err := Load(writeCfg(t, base)); err == nil {
		t.Fatal("cert files + terminate_tls_upstream are mutually exclusive")
	}
}

// ${VAR} expansion: set variables substitute; unset variables are load errors.
func TestEnvExpansion(t *testing.T) {
	t.Setenv("GP_BACKEND", "https://real.internal/v1")
	t.Setenv("GP_TOKEN", "op-secret-0123456789abcdef0123456789abcdef")
	body := `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"${GP_BACKEND}","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":"127.0.0.1:9090","operator_tokens":{"${GP_TOKEN}":"op:posture.control"}},"paths":{"audit_log":"audit.jsonl"}}`
	c, err := Load(writeCfg(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if c.Backend.URL != "https://real.internal/v1" {
		t.Fatalf("expansion failed: %q", c.Backend.URL)
	}
	if _, ok := c.Admin.OperatorTokens["op-secret-0123456789abcdef0123456789abcdef"]; !ok {
		t.Fatal("token variable not expanded")
	}

	t.Setenv("GP_MISSING_UNSET", "")
	if os.Getenv("GP_MISSING_UNSET") != "" {
		t.Skip("variable unexpectedly set")
	}
	body2 := strings.Replace(validConfigJSON(), "${", "${NO_SUCH_VAR_", 1)
	if _, err := Load(writeCfg(t, body2)); err == nil {
		// validConfigJSON has no ${...} so also test directly:
		_ = body2
	}
	unsetBody := `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"${DEFINITELY_UNSET_VAR_XYZ}","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`
	if _, err := Load(writeCfg(t, unsetBody)); err == nil {
		t.Fatal("unset ${VAR} must be a load error (fail closed)")
	}
}

// Missing config file is an error naming the path.
func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing file must error")
	}
}

// Malformed JSON is an error.
func TestLoadBadJSON(t *testing.T) {
	if _, err := Load(writeCfg(t, "{not json")); err == nil {
		t.Fatal("bad JSON must error")
	}
}

func TestLoadRejectsUnknownFieldsAtEveryNesting(t *testing.T) {
	base := validConfigJSON()
	cases := map[string]string{
		"top":         strings.Replace(base, "{\n", "{\n\t\t\"unknown\": true,\n", 1),
		"tls":         strings.Replace(base, `"tls": {`, `"tls": {"unknown": true,`, 1),
		"backend":     strings.Replace(base, `"backend": {`, `"backend": {"unknown": true,`, 1),
		"backend_tls": strings.Replace(base, `"backend": {`, `"backend": {"tls":{"unknown":true},`, 1),
		"server":      strings.Replace(base, `"server": {`, `"server": {"unknown": true,`, 1),
		"identity":    strings.Replace(base, `"identity": {`, `"identity": {"unknown": true,`, 1),
		"paths":       strings.Replace(base, `"paths": {`, `"paths": {"unknown": true,`, 1),
		"deployment": strings.TrimSuffix(base, "\n}") + `,"deployment":{"unknown":true}
}`,
		"ingress": strings.TrimSuffix(base, "\n}") + `,"ingress":{"unknown":true}
}`,
		"admin": strings.TrimSuffix(base, "\n}") + `,"admin":{"listen":"127.0.0.1:9090","unknown":true,"operator_tokens":{"test-token-0123456789abcdef0123456789abcdef":"op:posture.control"}}
}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeCfg(t, body)); err == nil {
				t.Fatal("unknown config field must be rejected")
			}
		})
	}
}

func TestLoadRejectsTrailingJSONValue(t *testing.T) {
	if _, err := Load(writeCfg(t, validConfigJSON()+"{}")); err == nil {
		t.Fatal("trailing second JSON value must be rejected")
	}
}

// Operator token specs parse as name:caps.
func TestParseOperatorSpec(t *testing.T) {
	name, caps, err := parseOperatorSpec("alice:posture.control,credential.lifecycle")
	if err != nil || name != "alice" || len(caps) != 2 {
		t.Fatalf("parse failed: %q %v %v", name, caps, err)
	}
	if _, _, err := parseOperatorSpec("no-colon"); err == nil {
		t.Fatal("spec without colon must fail")
	}
}

// TestAdminBindValidation (P0.7) enforces loopback-only plaintext admin binds.
func TestAdminBindValidation(t *testing.T) {
	adminBody := func(listen string, allowPublic bool) string {
		ap := ""
		if allowPublic {
			ap = `,"allow_public":true`
		}
		return `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":"` + listen + `","operator_tokens":{"test-token-0123456789abcdef0123456789abcdef":"op:posture.control"}` + ap + `},"paths":{"audit_log":"a.jsonl"}}`
	}

	// Valid: IPv4 and IPv6 loopback only.
	for _, l := range []string{"127.0.0.1:9090", "127.0.0.2:9090", "[::1]:9090"} {
		if _, err := Load(writeCfg(t, adminBody(l, false))); err != nil {
			t.Errorf("admin listen %q must be valid, got %v", l, err)
		}
	}
	// Invalid: wildcard, unspecified, private LAN, link-local, and public.
	for _, l := range []string{":9090", "0.0.0.0:9090", "[::]:9090", "10.0.0.5:9090", "192.168.1.2:9090", "169.254.1.1:9090", "8.8.8.8:9090", "52.0.0.1:9090"} {
		if _, err := Load(writeCfg(t, adminBody(l, false))); err == nil {
			t.Errorf("admin listen %q must be rejected (private bind required)", l)
		}
	}
	// A hostname (non-numeric) is rejected (we require numeric loopback/private).
	if _, err := Load(writeCfg(t, adminBody("admin.internal:9090", false))); err == nil {
		t.Error("admin listen hostname must be rejected (numeric loopback/private required)")
	}
}

// TestNoPublicAdminOverride (P0-14) proves the plaintext public-admin escape
// hatch is GONE from the config surface: admin.allow_public must not exist as
// an accepted field that disables the private-bind requirement.
func TestNoPublicAdminOverride(t *testing.T) {
	body := `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":"8.8.8.8:9090","allow_public":true,"operator_tokens":{"t":"op:posture.control"}},"paths":{"audit_log":"a.jsonl"}}`
	if _, err := Load(writeCfg(t, body)); err == nil {
		t.Fatal("admin.allow_public must NOT permit a public admin bind (P0-14)")
	}
	var c Config
	if err := strictUnmarshal(`{"allow_public":true}`, &c); err == nil {
		t.Fatal("allow_public must not be a recognized config field (strict decode must reject it)")
	}
}

// TestTerminateUpstreamRequiresPrivateBind (P0-15): a plain-HTTP public
// listener is only legitimate on a private network behind a trusted proxy.
func TestTerminateUpstreamRequiresPrivateBind(t *testing.T) {
	base := func(listen string) string {
		return `{"listen":"` + listen + `","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`
	}
	for _, l := range []string{"127.0.0.1:8080", "10.0.0.5:8080", "192.168.1.2:8080", "[::1]:8080"} {
		if _, err := Load(writeCfg(t, base(l))); err != nil {
			t.Errorf("terminate_tls_upstream listen %q must be valid on a private bind, got %v", l, err)
		}
	}
	for _, l := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "8.8.8.8:8080"} {
		if _, err := Load(writeCfg(t, base(l))); err == nil {
			t.Errorf("terminate_tls_upstream listen %q must be rejected (cleartext credentials need a private bind)", l)
		}
	}
	// With REAL TLS the public bind is fine (encryption is end-to-end).
	tlsBody := `{"listen":"0.0.0.0:8443","tls":{"cert_file":"c.pem","key_file":"k.pem"},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`
	if _, err := Load(writeCfg(t, tlsBody)); err != nil {
		t.Errorf("real-TLS public bind must be accepted, got %v", err)
	}
}

// TestNegativeLimitsRejected (P0-13): negative header/body limits and a
// negative stream idle timeout are boot failures, not silently inert ones.
func TestNegativeLimitsRejected(t *testing.T) {
	cases := map[string]string{
		"negative header bytes": `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s","max_header_bytes":-1},"identity":{"audience":"a"}}`,
		"negative body bytes":   `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s","max_body_bytes":-100},"identity":{"audience":"a"}}`,
		"negative stream idle":  `{"listen":"127.0.0.1:8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s","stream_write_idle_timeout":"-5s"},"identity":{"audience":"a"}}`,
	}
	for name, body := range cases {
		if _, err := Load(writeCfg(t, body)); err == nil {
			t.Errorf("%s: negative limit must fail validation", name)
		}
	}
}
