// Command gripline-test-replay is a tiny process-level client for the shared
// replay qualification lab. It exposes the ReplayGuard contract without
// accepting real assertion material.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/B-A-M-N/gripline/internal/replay"
	"github.com/B-A-M-N/gripline/verify"
)

type request struct {
	Issuer    string    `json:"issuer"`
	Audience  string    `json:"audience"`
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:19601", "listen address")
	dsn := flag.String("dsn", "", "shared PostgreSQL replay DSN")
	migrate := flag.Bool("migrate", false, "apply the repository-owned replay schema and exit")
	flag.Parse()
	if *migrate {
		if err := replay.MigratePostgresGuard(context.Background(), *dsn); err != nil {
			log.Fatalf("migrate replay guard: %v", err)
		}
		return
	}
	guard, err := replay.OpenPostgresGuard(context.Background(), *dsn)
	if err != nil {
		log.Fatalf("open replay guard: %v", err)
	}
	defer guard.Close()
	handler := http.NewServeMux()
	handler.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler.HandleFunc("/claim", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		var input request
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, "invalid claim", http.StatusBadRequest)
			return
		}
		accepted, err := guard.Accept(r.Context(), verify.ReplayClaim{Issuer: input.Issuer, Audience: input.Audience, JTI: input.JTI, ExpiresAt: input.ExpiresAt})
		if err != nil {
			http.Error(w, "replay guard unavailable", http.StatusServiceUnavailable)
			return
		}
		if !accepted {
			w.WriteHeader(http.StatusConflict)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": accepted})
	})
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 2 * time.Second}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
