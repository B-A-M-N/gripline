package main

import (
	"net/http"
	"sync"

	"github.com/B-A-M-N/gripline/internal/proxy"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

type backendStats struct {
	mu                sync.Mutex
	RawAuthorization  int `json:"raw_authorization"`
	RawAPIKey         int `json:"raw_api_key"`
	ValidAssertions   int `json:"valid_assertions"`
	InvalidOrForged   int `json:"invalid_or_forged_assertions"`
	DirectRawRejected int `json:"direct_raw_rejected"`
}

func newProtectedBackend(verifier *terminator.VerifierKeyring, audience string, stats *backendStats) http.Handler {
	bv := proxy.NewBackendVerifierKeyring(verifier, audience)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats.mu.Lock()
		// RawAuthorization/RawAPIKey measure raw credentials arriving on the
		// assertion-bearing proxy hop. Direct raw attempts are counted separately
		// below, so the boundary counter remains a proof that forwarding never
		// carried the external credential.
		if r.Header.Get("Authorization") != "" && r.Header.Get("X-Gripline-Assertion") != "" {
			stats.RawAuthorization++
		}
		if r.Header.Get("X-API-Key") != "" && r.Header.Get("X-Gripline-Assertion") != "" {
			stats.RawAPIKey++
		}
		stats.mu.Unlock()
		claims, err := bv.Verify(r)
		if err != nil {
			stats.mu.Lock()
			stats.InvalidOrForged++
			if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
				stats.DirectRawRejected++
			}
			stats.mu.Unlock()
			http.Error(w, "assertion required", http.StatusUnauthorized)
			return
		}
		bv.StripAssertion(r)
		stats.mu.Lock()
		stats.ValidAssertions++
		stats.mu.Unlock()
		w.Header().Set("X-Demo-Assertion-Verified", "true")
		w.Header().Set("X-Demo-Principal", claims.CredID)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"backend":"protected","identity":"assertion"}`))
	})
}
