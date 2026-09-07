package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	if v, enabled := c.TLSConfig(); !enabled || v != tlsVersion13 {
		t.Fatalf("TLS config wrong: %v %v", v, enabled)
	}
	if err := c.ValidateCertificates(); err == nil {
		t.Fatal("nonexistent cert files must fail certificate validation")
	}
}

// Every security-consequential zero is a boot failure, not a degraded default.
func TestValidateRejectsMissingSecurityDecisions(t *testing.T) {
	cases := map[string]string{
		"no tls posture":       `{"listen":":8080","backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"no backend":           `{"listen":":8080","tls":{"terminate_tls_upstream":true},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"no backend timeout":   `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"unbounded read":       `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"unbounded write":      `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"unbounded idle":       `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
		"no header bound":      `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s"},"identity":{"audience":"a"}}`,
		"no audience":          `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{}}`,
		"admin without audit":  `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":":9090","operator_tokens":{"t":"op:posture.control"}}}`,
		"admin without tokens": `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":":9090"},"paths":{"audit_log":"a.jsonl"}}`,
		"bad min version":      `{"listen":":8080","tls":{"terminate_tls_upstream":true,"min_version":"1.1"},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`,
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
	t.Setenv("GP_TOKEN", "op-secret")
	body := `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"${GP_BACKEND}","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":"127.0.0.1:9090","operator_tokens":{"${GP_TOKEN}":"op:posture.control"}},"paths":{"audit_log":"audit.jsonl"}}`
	c, err := Load(writeCfg(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if c.Backend.URL != "https://real.internal/v1" {
		t.Fatalf("expansion failed: %q", c.Backend.URL)
	}
	if _, ok := c.Admin.OperatorTokens["op-secret"]; !ok {
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
	unsetBody := `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"${DEFINITELY_UNSET_VAR_XYZ}","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"}}`
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

// TestAdminBindValidation (P0.7) enforces the "private interface only" contract
// for the admin control plane: loopback and private/unique-local addresses pass;
// wildcard/unspecified and public addresses are rejected unless allow_public.
func TestAdminBindValidation(t *testing.T) {
	adminBody := func(listen string, allowPublic bool) string {
		ap := ""
		if allowPublic {
			ap = `,"allow_public":true`
		}
		return `{"listen":":8080","tls":{"terminate_tls_upstream":true},"backend":{"url":"https://b","timeout":"5s"},"server":{"read_timeout":"5s","write_timeout":"5s","idle_timeout":"5s","read_header_timeout":"5s"},"identity":{"audience":"a"},"admin":{"listen":"` + listen + `","operator_tokens":{"t":"op:posture.control"}` + ap + `},"paths":{"audit_log":"a.jsonl"}}`
	}

	// Valid: loopback, RFC1918 private, IPv6 loopback.
	for _, l := range []string{"127.0.0.1:9090", "10.0.0.5:9090", "192.168.1.2:9090", "[::1]:9090", "172.16.0.1:9090", "169.254.1.1:9090"} {
		if _, err := Load(writeCfg(t, adminBody(l, false))); err != nil {
			t.Errorf("admin listen %q must be valid, got %v", l, err)
		}
	}
	// Invalid without override: wildcard (empty host), 0.0.0.0, [::], public.
	for _, l := range []string{":9090", "0.0.0.0:9090", "[::]:9090", "8.8.8.8:9090", "52.0.0.1:9090"} {
		if _, err := Load(writeCfg(t, adminBody(l, false))); err == nil {
			t.Errorf("admin listen %q must be rejected without allow_public", l)
		}
	}
	// A hostname (non-numeric) is rejected (we require numeric loopback/private).
	if _, err := Load(writeCfg(t, adminBody("admin.internal:9090", false))); err == nil {
		t.Error("admin listen hostname must be rejected (numeric loopback/private required)")
	}
	// allow_public opts out of the check.
	if _, err := Load(writeCfg(t, adminBody("8.8.8.8:9090", true))); err != nil {
		t.Errorf("allow_public=true must accept a public bind, got %v", err)
	}
}
