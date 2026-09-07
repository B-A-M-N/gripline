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
	"runtime"
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

var (
	version     = "dev"
	buildCommit = "unknown"
	buildDate   = "unknown"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println(versionString())
		return
	}
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
//	gripline credential list|revoke --config path.json [...]
//	gripline lane list|unblock --config path.json [...]
//	gripline audit list|export --config path.json
//	gripline state check|backup|restore|compact --config path.json
//	gripline policy verify --config path.json
//	gripline status --config path.json
//	gripline version
//
// keys export prints the PUBLIC backend verification material (active kid +
// all retained public keys) as JSON to stdout — never any private/signing
// material (P0.15). The lifecycle subcommands operate through the control
// plane's authorization + atomic mutation/audit seams and never touch raw
// credential secrets (P1-26).
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
	case "credential":
		return runCredentialCLI(args)
	case "lane":
		return runLaneCLI(args)
	case "audit":
		return runAuditCLI(args)
	case "state":
		return runStateCLI(args)
	case "policy":
		return runPolicyCLI(args)
	case "status":
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		cfgPath := fs.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return runStatusCLI(*cfgPath)
	case "version":
		if len(args) != 0 {
			return fmt.Errorf("version: does not accept arguments")
		}
		fmt.Println(versionString())
		return errSubcommand
	default:
		return fmt.Errorf("unknown subcommand %q (expected: keys, credential, lane, audit, state, policy, status, version)", sub)
	}
}

func versionString() string {
	return fmt.Sprintf("gripline %s (commit %s, built %s, %s)", version, buildCommit, buildDate, runtime.Version())
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
	kr, err := terminator.LoadExistingKeyring(cfg.Paths.SignerKeyring)
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

func run(cfgPath string) (retErr error) {
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
	// P1-23: a failed Close (unflushed audit sink, bbolt corruption on
	// final sync) is an operational error, not something to discard — it must
	// propagate after the (successful) shutdown path so supervision sees it.
	defer func() {
		if cerr := rt.Close(); cerr != nil {
			retErr = errors.Join(retErr, cerr)
		}
	}()

	// --- Public server -------------------------------------------------------
	root := http.NewServeMux()
	root.Handle("/v1/", rt.DataPlane)
	root.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	var ready atomic.Bool
	ready.Store(true)
	// P1-24: readiness is a REAL check — the state authority must answer a
	// probe read (when state-backed) and the process must not be draining. A
	// failed probe is a 503 so the load balancer stops routing, not a 200
	// that lies.
	root.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("draining"))
			return
		}
		if err := rt.Ready(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not_ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	writeTimeout := cfg.Server.WriteTimeout.D()
	// P0.16: with stream_write_idle_timeout configured, per-request write
	// deadlines govern (initial budget + per-chunk re-arm inside the data
	// plane). A blanket server WriteTimeout here would kill legitimate
	// long-lived SSE streams at the budget regardless of liveness.
	if cfg.Server.StreamWriteIdleTimeout.D() > 0 {
		writeTimeout = 0
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           root,
		ReadTimeout:       cfg.Server.ReadTimeout.D(),
		WriteTimeout:      writeTimeout,
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

	// Both servers report unexpected termination through one lifecycle channel.
	// An admin failure is therefore a process failure, not a log-only event.
	errCh := make(chan error, 2)
	go func() {
		var serveErr error
		if srv.TLSConfig != nil {
			serveErr = srv.ServeTLS(ln, cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			serveErr = srv.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- fmt.Errorf("gripline: data server: %w", serveErr)
		}
	}()

	// --- Optional admin/control-plane listener (P0.47) ----------------------
	if rt.Admin != nil {
		adminLn, err := net.Listen("tcp", cfg.Admin.Listen)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("gripline: admin listen %s: %w", cfg.Admin.Listen, err)
		}
		go func() {
			log.Printf("gripline: admin control plane listening on %s", cfg.Admin.Listen)
			if serveErr := rt.Admin.Serve(adminLn); serveErr != nil && serveErr != http.ErrServerClosed {
				errCh <- fmt.Errorf("gripline: admin server: %w", serveErr)
			}
		}()
	}

	// --- Signal handling + graceful drain ------------------------------------
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	var lifecycleErr error
	select {
	case lifecycleErr = <-errCh:
		ready.Store(false)
	case s := <-sig:
		log.Printf("gripline: %v received — draining", s)
		ready.Store(false)
	}

	// Give each server its own bounded shutdown context. This lets a stuck
	// admin handler consume its own budget without preventing the data plane
	// from draining, while preserving every shutdown error for the caller.
	shutdownErrCh := make(chan error, 2)
	shutdownCount := 1
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		shutdownErrCh <- srv.Shutdown(ctx)
	}()
	if rt.Admin != nil {
		shutdownCount++
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			shutdownErrCh <- rt.Admin.Shutdown(ctx)
		}()
	}
	var shutdownErrs []error
	for i := 0; i < shutdownCount; i++ {
		if err := <-shutdownErrCh; err != nil {
			shutdownErrs = append(shutdownErrs, err)
		}
	}
	if shutdownErr := errors.Join(shutdownErrs...); shutdownErr != nil {
		lifecycleErr = errors.Join(lifecycleErr, fmt.Errorf("gripline: drain: %w", shutdownErr))
	}
	if lifecycleErr != nil {
		return lifecycleErr
	}
	log.Printf("gripline: drained, exiting")
	return nil
}

// policyFor builds the policy revision this deployment enforces. A configured
// artifact is parsed and compiled at startup; invalid policy is a boot error,
// never a partially initialized data plane.
func policyFor(cfg *config.Config) (*policy.Policy, error) {
	if cfg.Policy.File != "" {
		verifier, err := policy.LoadVerifierKeyFile(cfg.Policy.VerifierKeyFile)
		if err != nil {
			return nil, fmt.Errorf("policy verifier: %w", err)
		}
		compiled, err := policy.LoadAuthenticatedFile(cfg.Policy.File, verifier)
		if err != nil {
			return nil, err
		}
		return &compiled.Policy, nil
	}
	pol := policy.Default()
	pol.Identity.MaxTTLSeconds = 30
	return pol, nil
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
