package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// TestStripHopByHopHeadersConnectionAware proves hop-by-hop parsing is
// Connection-aware (RFC 7230 §6.1): a header the hop names in Connection is
// stripped, as is the fixed hop-by-hop set, and Connection itself is removed so
// it does not pass to the next hop.
func TestStripHopByHopHeadersConnectionAware(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Custom-Hop, keep-alive")
	h.Set("X-Custom-Hop", "secret")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Basic abc")
	h.Set("Te", "trailers")
	h.Set("Upgrade", "websocket")
	h.Set("X-Auth-Token", "keep-me") // end-to-end; must survive
	h.Set("Transfer-Encoding", "chunked")

	stripHopByHopHeaders(h)

	for _, gone := range []string{
		"Connection",   // the header itself is hop-by-hop
		"X-Custom-Hop", // named by Connection
		"Keep-Alive",   // named by Connection AND fixed set
		"Proxy-Authorization", "Te", "Upgrade", "Transfer-Encoding",
	} {
		if _, ok := h[gone]; ok {
			t.Fatalf("header %q must be stripped (hop-by-hop), present: %v", gone, h)
		}
	}
	if got := h.Get("X-Auth-Token"); got != "keep-me" {
		t.Fatalf("end-to-end header must survive hop-by-hop strip, got %q", got)
	}
}

// TestStripHopByHopHeadersConnectionCaseInsensitive proves Connection header
// names are matched case-insensitively (the Co-lowercased value is the
// canonical router key).
func TestStripHopByHopHeadersConnectionCaseInsensitive(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-MixedCase")
	h.Set("x-mixedcase", "value")

	stripHopByHopHeaders(h)

	if got := h.Get("X-MixedCase"); got != "" {
		t.Fatalf("case-insensitive connection-named header must be stripped, got %q in %v", got, h)
	}
}

// TestStripUntrustedProvenanceHeaders proves client-supplied provenance headers
// (X-Forwarded-*, Forwarded, CF-Connecting-IP, ...) are removed before being
// forwarded upstream, and benign headers survive.
func TestStripUntrustedProvenanceHeaders(t *testing.T) {
	h := http.Header{}
	for _, name := range []string{
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Real-IP", "CF-Connecting-IP", "True-Client-IP", "X-Original-URL",
	} {
		h.Set(name, "spoofed")
	}
	h.Set("Authorization", "Bearer keep") // end-to-end auth must survive
	h.Set("Content-Type", "application/json")

	stripUntrustedProvenanceHeaders(h)

	for _, gone := range []string{
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Real-IP", "CF-Connecting-IP", "True-Client-IP", "X-Original-URL",
	} {
		if strings.EqualFold(h.Get(gone), "spoofed") {
			t.Fatalf("provenance header %q must be stripped before upstream, present: %v", gone, h)
		}
	}
	if got := h.Get("Authorization"); got != "Bearer keep" {
		t.Fatalf("Authorization must survive provenance strip, got %q", got)
	}
}
