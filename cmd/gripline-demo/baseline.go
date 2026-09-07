package main

import (
	"net/http"
	"sync"
)

type baselineStats struct {
	mu                 sync.Mutex
	LegitimateAccepted int `json:"legitimate_accepted"`
	AttackerAccepted   int `json:"attacker_accepted"`
}

func newBaselineBackend(stats *baselineStats, raw string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+raw {
			http.Error(w, "missing credential", http.StatusUnauthorized)
			return
		}
		stats.mu.Lock()
		if r.Header.Get("User-Agent") == "gripline-demo-legit" {
			stats.LegitimateAccepted++
		} else {
			stats.AttackerAccepted++
		}
		stats.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"backend":"baseline","raw_credential":"accepted"}`))
	})
}
