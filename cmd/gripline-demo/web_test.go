package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/B-A-M-N/gripline/internal/evidence"
)

func TestWebHandlerStateAndControls(t *testing.T) {
	s, err := NewScenario()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := s.WebHandler()

	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "credential_fingerprint") {
		t.Fatalf("GET /api/state: status=%d body=%s", get.Code, get.Body.String())
	}
	root := httptest.NewRecorder()
	h.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Code != http.StatusOK || !strings.Contains(root.Body.String(), "RUN FULL DEMO") {
		t.Fatalf("GET /: status=%d body missing controls", root.Code)
	}
	method := httptest.NewRecorder()
	h.ServeHTTP(method, httptest.NewRequest(http.MethodGet, "/api/run-normal", nil))
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET control status=%d, want %d", method.Code, http.StatusMethodNotAllowed)
	}

	for _, endpoint := range []string{
		"/api/reset",
		"/api/run-normal",
		"/api/steal-key",
		"/api/legit-after-containment",
		"/api/direct-raw",
		"/api/run-full",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, endpoint, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s: status=%d body=%s", endpoint, rec.Code, rec.Body.String())
		}
	}
}

func TestFullDemoUsesProductionSignalsAndPreservesBoundary(t *testing.T) {
	s, err := NewScenario()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RunFullDemo(); err != nil {
		t.Fatal(err)
	}
	snap := s.Snapshot()
	if !snap.Proof.RealEvidence || !snap.Proof.ConcurrencyEvidence || !snap.Proof.SecurityTransition {
		t.Fatalf("demo proof incomplete: %+v", snap.Proof)
	}
	if snap.Protected.RawAuthorization != 0 || snap.Protected.RawAPIKey != 0 || snap.Protected.DirectRawRejected == 0 {
		t.Fatalf("protected boundary proof incomplete: %+v", snap.Protected)
	}
	if snap.Protected.AttackerBlocked == 0 || snap.Protected.LegitimateReached < 2 {
		t.Fatalf("containment proof incomplete: %+v", snap.Protected)
	}
	for _, event := range snap.Timeline {
		for _, code := range event.Evidence {
			if strings.HasPrefix(code, "DEMO_") {
				t.Fatalf("demo emitted synthetic evidence code %q", code)
			}
			if _, ok := evidence.DefaultTable()[code]; !ok {
				t.Fatalf("demo emitted non-production evidence code %q", code)
			}
		}
	}
}
