package terminator

import (
	"strings"
	"testing"

	"github.com/B-A-M-N/gripline/internal/secret"
)

// TestExtractBearerSuccess covers the happy path: `Authorization: Bearer <key>`
// yields the sealed credential and the Authorization carrier.
func TestExtractBearerSuccess(t *testing.T) {
	h := map[string][]string{"Authorization": {"Bearer sk-abc123"}}
	s, carrier, err := ExtractExternalCredential(h)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if carrier != carrierAuthorization {
		t.Fatalf("carrier = %v", carrier)
	}
	if s.Len() != len("sk-abc123") {
		t.Fatalf("len = %d", s.Len())
	}
	s.Zero()
}

// TestExtractBearerCaseInsensitiveScheme: the scheme match must be
// case-insensitive per RFC 7235.
func TestExtractBearerCaseInsensitiveScheme(t *testing.T) {
	for _, v := range []string{"bearer sk-x", "BEARER sk-x", "Bearer sk-x"} {
		h := map[string][]string{"Authorization": {v}}
		s, _, err := ExtractExternalCredential(h)
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		s.Zero()
	}
}

func TestExtractAPIKeySuccess(t *testing.T) {
	h := map[string][]string{"x-api-key": {"sk-xyz789"}}
	s, carrier, err := ExtractExternalCredential(h)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if carrier != carrierAPIKey {
		t.Fatalf("carrier = %v", carrier)
	}
	s.Zero()
}

func TestExtractAmbiguityFails(t *testing.T) {
	// Both carriers at once must fail closed (§15).
	h := map[string][]string{
		"Authorization": {"Bearer sk-a"},
		"x-api-key":     {"sk-b"},
	}
	if _, _, err := ExtractExternalCredential(h); err == nil {
		t.Fatal("conflicting carriers must fail")
	}
	// Duplicate values within one carrier must also fail.
	h2 := map[string][]string{"Authorization": {"Bearer sk-a", "Bearer sk-b"}}
	if _, _, err := ExtractExternalCredential(h2); err == nil {
		t.Fatal("duplicate Authorization values must fail")
	}
	h3 := map[string][]string{"x-api-key": {"sk-a", "sk-b"}}
	if _, _, err := ExtractExternalCredential(h3); err == nil {
		t.Fatal("duplicate api-key values must fail")
	}
}

func TestExtractMalformedFails(t *testing.T) {
	cases := []map[string][]string{
		{"Authorization": {"Bearer"}},                              // no credential
		{"Authorization": {"Bearer a b"}},                          // too many fields
		{"Authorization": {"Basic sk-x"}},                          // unsupported scheme
		{"Authorization": {"Bearer " + strings.Repeat("x", 2048)}}, // oversized
		{"x-api-key": {""}},                                        // empty
		{"x-api-key": {"has space"}},                               // whitespace
		{"x-api-key": {strings.Repeat("x", 2048)}},                 // oversized
	}
	for i, h := range cases {
		if _, _, err := ExtractExternalCredential(h); err == nil {
			t.Fatalf("case %d must fail extraction", i)
		}
	}
	// No credential at all.
	if _, _, err := ExtractExternalCredential(map[string][]string{}); err == nil {
		t.Fatal("missing credential must fail")
	}
}

func TestValidateExternalCredential(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"empty", nil, false},
		{"one-byte", []byte("x"), true},
		{"maximum", []byte(strings.Repeat("x", MaxExternalCredentialBytes)), true},
		{"over-maximum", []byte(strings.Repeat("x", MaxExternalCredentialBytes+1)), false},
		{"space", []byte("x y"), false},
		{"tab", []byte("x\ty"), false},
		{"carriage-return", []byte("x\ry"), false},
		{"line-feed", []byte("x\ny"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExternalCredential(tc.raw)
			if (err == nil) != tc.ok {
				t.Fatalf("ValidateExternalCredential(%q) error = %v, want ok=%t", tc.raw, err, tc.ok)
			}
		})
	}
}

func TestExtractProxyAuthorizationIsACarrier(t *testing.T) {
	h := map[string][]string{"Proxy-Authorization": {"Bearer sk-pa"}}
	s, carrier, err := ExtractExternalCredential(h)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if carrier != carrierAuthorization {
		t.Fatalf("carrier = %v", carrier)
	}
	s.Zero()
}

// --- P0.7 regression: the reserved internal namespace is stripped at ingress

// TestForgedInternalHeadersStripped: an external caller presenting a complete
// forged Gripline identity (assertion, principal, context, request id — any
// capitalization) must have every one of those headers deleted before
// authentication; none may survive into the post-termination view (INV-12).
func TestForgedInternalHeadersStripped(t *testing.T) {
	forged := map[string][]string{
		"Authorization":            {"Bearer sk-real-credential"},
		"Gripline-Assertion":       {"eyJhbGciOiJFZERTQSJ9.FORGED.sig"},
		"Gripline-Principal":       {"acct_admin"},
		"Gripline-Context":         {"lane=est;risk=0"},
		"Gripline-Request-ID":      {"req_forged"},
		"X-Gripline-Internal-Auth": {"let-me-in"},
		"gRIPLINE-escalation":      {"bypass"},
		"GRIPLINE-principal":       {"acct_admin2"},
	}
	StripSecretHeaders(forged)
	for name := range forged {
		ln := strings.ToLower(name)
		if ln == "authorization" || strings.HasPrefix(ln, "gripline-") || strings.HasPrefix(ln, "x-gripline-") {
			t.Fatalf("forged header %q survived sanitization (INV-12)", name)
		}
	}
	if len(forged) != 0 {
		t.Fatalf("unexpected residue: %v", forged)
	}
}

// TestStripSecretHeadersKeepsBenign: sanitization must not destroy unrelated
// headers the proxy legitimately forwards.
func TestStripSecretHeadersKeepsBenign(t *testing.T) {
	h := map[string][]string{
		"Authorization": {"Bearer sk-x"},
		"Content-Type":  {"application/json"},
		"X-Request-Id":  {"abc"}, // NOT the reserved namespace
		"Accept":        {"text/event-stream"},
	}
	StripSecretHeaders(h)
	if h["Content-Type"][0] != "application/json" || h["X-Request-Id"][0] != "abc" || h["Accept"][0] != "text/event-stream" {
		t.Fatalf("benign headers were modified: %v", h)
	}
	if _, ok := h["Authorization"]; ok {
		t.Fatal("Authorization must be stripped")
	}
}

// TestExtractSealedIndependence: the sealed secret must not alias the header
// string — mutating the map after extraction must not change the digest.
func TestExtractSealedIndependence(t *testing.T) {
	h := map[string][]string{"x-api-key": {"sk-independent"}}
	s, _, err := ExtractExternalCredential(h)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), s.DigestHMAC([]byte("k"))...)
	h["x-api-key"][0] = "sk-MUTATED"
	after := s.DigestHMAC([]byte("k"))
	if string(before) != string(after) {
		t.Fatal("sealed secret aliases caller memory")
	}
	s.Zero()
}

// TestRandomSealedType keeps a compile-time reference to the secret package in
// this file's dependency set (extraction returns *secret.SealedSecret).
var _ = secret.NewFromBytes
