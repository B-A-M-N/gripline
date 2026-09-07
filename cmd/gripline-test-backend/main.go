// Command gripline-test-backend is a minimal private-backend fixture for the
// release harness. It deliberately imports only the public verify package, so
// the compiled black-box test exercises the same trust boundary a provider
// service is expected to use.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/B-A-M-N/gripline/verify"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18081", "private backend listen address")
	keysPath := flag.String("keys", "", "public Gripline key-set JSON path")
	audience := flag.String("audience", "", "expected assertion audience")
	flag.Parse()
	if *keysPath == "" || *audience == "" {
		log.Fatal("-keys and -audience are required")
	}
	keysFile, err := os.Open(*keysPath)
	if err != nil {
		log.Fatalf("open key set: %v", err)
	}
	keySet, err := verify.LoadKeySet(keysFile)
	_ = keysFile.Close()
	if err != nil {
		log.Fatalf("load key set: %v", err)
	}
	verifier, err := verify.New(keySet, *audience)
	if err != nil {
		log.Fatalf("construct verifier: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A protected backend must never accept a raw external credential, even
		// if a caller reaches this private listener directly.
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
			http.Error(w, "raw credential rejected", http.StatusForbidden)
			return
		}
		claims, err := verifier.VerifyAndStrip(r)
		if err != nil {
			http.Error(w, "assertion required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorized":      true,
			"credential_id":   claims.CredID,
			"policy_revision": claims.PolicyRev,
		})
	})
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("backend: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
