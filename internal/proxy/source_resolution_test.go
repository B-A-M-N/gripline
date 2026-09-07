package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/B-A-M-N/gripline/internal/terminator"
)

// failingSource is a SourceResolver that simulates a broken trusted-ingress
// path: malformed peer, pseudonymization failure, etc.
type failingSource struct{}

func (failingSource) ResolveSource(Observation) (terminator.TrustedSource, error) {
	return terminator.TrustedSource{}, errTestResolutionFailed
}

var errTestResolutionFailed = &resolutionError{}

type resolutionError struct{}

func (*resolutionError) Error() string { return "ingress: resolution failed" }

// TestSourceResolutionFailureFailsClosed proves P0.11: a configured source
// resolver that ERRORS must fail the request closed (503, backend never
// reached) instead of silently degrading to "no source" — which would disable
// the source boundary exactly when resolution is broken.
func TestSourceResolutionFailureFailsClosed(t *testing.T) {
	backendHits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	signer, _ := terminator.GenerateSigner()
	dp, err := New(Config{
		Terminator: buildTerminatorWithSigner(t, signer),
		BackendURL: bu,
		Audience:   testAudience,
		Sources:    failingSource{},
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+dpRaw())
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("resolver failure must fail closed with 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Gripline-Reason"); got != "source_resolution_failed" {
		t.Fatalf("reason header must be source_resolution_failed, got %q", got)
	}
	if backendHits != 0 {
		t.Fatalf("backend must never be reached on source-resolution failure; hits=%d", backendHits)
	}
}

// TestNoSourceResolutionIsNotAnError proves the unconfigured default (NoSource)
// is a deliberate posture, not a resolution failure: requests flow normally.
func TestNoSourceResolutionIsNotAnError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	signer, _ := terminator.GenerateSigner()
	dp, err := New(Config{
		Terminator: buildTerminatorWithSigner(t, signer),
		BackendURL: bu,
		Audience:   testAudience,
		// Sources nil → NoSource.
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+dpRaw())
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("NoSource must not fail requests; got %d: %s", rec.Code, rec.Body.String())
	}
}
