// Command gripline is the deployable inference gateway (P0.54): a
// production entry point that wires the terminator data plane behind a
// hardened HTTP server.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/keyexport"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// errSubcommand is a sentinel signaling that the invocation requested a
// non-server subcommand that was handled.
var errSubcommand = errors.New("gripline: subcommand handled")

func main() {
	sub, rest := parseSubcommand(os.Args[1:])
	if sub != "" {
		if err := dispatchSubcommand(sub, rest); err != nil && !errors.Is(err, errSubcommand) {
			log.Fatalf("gripline: %v", err)
		}
		return
	}
	cfgPath := flag.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	flag.Parse()
	if err := run(*cfgPath); err != nil {
		log.Fatalf("gripline: %v", err)
	}
}

// parseSubcommand peeks os.Args for a leading non-flag subcommand token.
// args is os.Args[1:].
func parseSubcommand(args []string) (string, []string) {
	if len(args) == 0 || len(args[0]) == 0 || args[0][0] == '-' {
		return "", nil
	}
	return args[0], args[1:]
}

// dispatchSubcommand runs a non-server subcommand. Supported:
//
//	gripline keys export --config path.json
//
// prints the PUBLIC backend verification material (active kid + all retained
// public keys) as JSON to stdout — never any private/signing material (P0.15).
func dispatchSubcommand(sub string, args []string) error {
	switch sub {
	case "keys":
		// gripline keys export --config path.json
		if len(args) == 0 || args[0] != "export" {
			return fmt.Errorf("keys: expected 'gripline keys export --config path.json'")
		}
		fs := flag.NewFlagSet("keys export", flag.ExitOnError)
		cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return runKeysExport(*cfgPath)
	default:
		return fmt.Errorf("unknown subcommand %q (expected: keys)", sub)
	}
}

// runKeysExport loads the persistent signing keyring from the configured path
// and prints its PUBLIC verification material to stdout as JSON. It is the
// supported delivery surface for acquiring backend verification keys (P0.15):
// a restricted deployment node runs this once and hands the output to the
// protected backend's configuration.
func runKeysExport(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("keys export: %w", err)
	}
	if cfg.Paths.SignerKeyring == "" {
		return fmt.Errorf("keys export: config.paths.signer_keyring is not set")
	}
	kr, err := terminator.LoadKeyring(cfg.Paths.SignerKeyring)
	if err != nil {
		return fmt.Errorf("keys export: load keyring: %w", err)
	}
	verifiers := make(map[int][]byte, 0)
	for kid, pub := range kr.PublicKeys() {
		verifiers[kid] = append([]byte(nil), pub...)
	}
	exp, err := keyexport.GenerateExport(kr.ActiveKid(), verifiers)
	if err != nil {
		return fmt.Errorf("keys export: %w", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(exp); err != nil {
		return fmt.Errorf("keys export: write: %w", err)
	}
	return errSubcommand // success — do not fall through to the server
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.ValidateCertificates(); err != nil {
		return err
	}

	// P0.1/P0.2: Build the shared runtime (single composition root).
	rt, err := BuildRuntime(cfg)
	if err != nil {
		return err
	}
	defer rt.Close()

	// --- Public server -------------------------------------------------------
	root := http.NewServeMux()
	root.Handle("/v1/", rt.DataPlane)
	root.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	var ready atomic.Bool
	ready.Store(true)
	root.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("draining"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           root,
		ReadTimeout:       cfg.Server.ReadTimeout.D(),
		WriteTimeout:      cfg.Server.WriteTimeout.D(),
		IdleTimeout:       cfg.Server.IdleTimeout.D(),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.D(),
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}
	if minV, enabled := cfg.TLSConfig(); enabled {
		srv.TLSConfig = &tls.Config{MinVersion: minV}
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("gripline: listen %s: %w", cfg.Listen, err)
	}
	log.Printf("gripline: data plane listening on %s (tls=%v) → backend %s",
		cfg.Listen, srv.TLSConfig != nil, cfg.Backend.URL)

	// --- Optional admin/control-plane listener (P0.47) ----------------------
	if rt.Admin != nil {
		ln, err := net.Listen("tcp", cfg.Admin.Listen)
		if err != nil {
			return fmt.Errorf("gripline: admin listen %s: %w", cfg.Admin.Listen, err)
		}
		go func() {
			log.Printf("gripline: admin control plane listening on %s", cfg.Admin.Listen)
			if err := rt.Admin.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("gripline: admin server: %v", err)
			}
		}()
	}

	// --- Signal handling + graceful drain ------------------------------------
	errCh := make(chan error, 1)
	go func() {
		var err error
		if srv.TLSConfig != nil {
			err = srv.ServeTLS(ln, cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return fmt.Errorf("gripline: server: %w", err)
	case s := <-sig:
		log.Printf("gripline: %v received — draining", s)
	}

	ready.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if rt.Admin != nil {
		_ = rt.Admin.Shutdown(ctx)
	}
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("gripline: drain: %w", err)
	}
	log.Printf("gripline: drained, exiting")
	return nil
}

// policyFor builds the policy revision this deployment enforces.
func policyFor(cfg *config.Config) *policy.Policy {
	pol := policy.Default()
	pol.Identity.MaxTTLSeconds = 30
	return pol
}

// urlFrom parses the fixed backend origin.
func urlFrom(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("gripline: backend url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("gripline: backend url %q must be an absolute http(s) origin", raw)
	}
	return u, nil
}
