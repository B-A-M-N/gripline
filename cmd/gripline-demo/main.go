// gripline-demo is the definitive local causal demonstration for the public
// beta. It starts a conventional baseline, the protected Gripline data plane,
// and a private assertion-verifying backend, then drives all of them with real
// HTTP clients. No evidence is injected by the demo.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	headless := flag.Bool("headless", false, "run the full causal scenario and exit non-zero on any failed proof")
	listen := flag.String("listen", "127.0.0.1:8585", "address for the demo web UI")
	flag.Parse()

	scenario, err := NewScenario()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gripline-demo: %v\n", err)
		os.Exit(1)
	}
	defer scenario.Close()

	if *headless {
		if err := scenario.RunFullDemo(); err != nil {
			fmt.Fprintf(os.Stderr, "gripline-demo: FAILED: %v\n", err)
			os.Exit(1)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(scenario.Snapshot())
		return
	}

	server := &http.Server{
		Addr: *listen, Handler: scenario.WebHandler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "gripline-demo: web server: %v\n", err)
		}
	}()
	fmt.Printf("Gripline causal demo: http://%s\n", *listen)
	fmt.Println("Run FULL DEMO first, then inspect the live timeline and backend counters.")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
}
