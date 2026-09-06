// Command gripline is the deployable inference gateway (P0.54): a
// production entry point that wires the terminator data plane behind a
// hardened HTTP server — fixed backend, required TLS posture, bounded
// timeouts/headers/bodies, graceful shutdown, readiness/liveness endpoints,
// and (optionally) the authenticated operator control plane on a private
// listener.
//
// A misconfigured deployment must fail at BOOT, never degrade silently: the
// config loader rejects missing TLS decisions, unbounded timeouts, a missing
// backend, or an incompletely specified admin surface before anything binds.
//
// Usage:
//
//	gripline -config /etc/gripline/config.json
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/proxy"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

func main() {
	cfgPath := flag.String("config", "/etc/gripline/config.json", "path to the deployment configuration")
	flag.Parse()
	if err := run(*cfgPath); err != nil {
		log.Fatalf("gripline: %v", err)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.ValidateCertificates(); err != nil {
		return err
	}

	// --- Wire the data plane ------------------------------------------------
	//
	// The bootstrap here builds the in-process credential registry, pepper
	// ring, and signer. Durable backends (PostgreSQL registry, remote signer)
	// substitute behind the same seams; the wiring point is buildDataPlane.
	plane, err := buildDataPlane(cfg)
	if err != nil {
		return err
	}

	// --- Public server -------------------------------------------------------
	root := http.NewServeMux()
	root.Handle("/v1/", plane) // the inference data plane
	root.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		// Liveness: the process is up. Never checks dependencies.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	var ready atomic.Bool
	ready.Store(true)
	root.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		// Readiness: serving traffic. Draining flips this before shutdown.
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
	adminSrv, err := buildAdmin(cfg)
	if err != nil {
		return err
	}
	if adminSrv != nil {
		ln, err := net.Listen("tcp", cfg.Admin.Listen)
		if err != nil {
			return fmt.Errorf("gripline: admin listen %s: %w", cfg.Admin.Listen, err)
		}
		go func() {
			log.Printf("gripline: admin control plane listening on %s", cfg.Admin.Listen)
			if err := adminSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
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

	// Drain: stop accepting, mark not-ready so load balancers pull us first,
	// give in-flight requests the configured grace period.
	ready.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if adminSrv != nil {
		_ = adminSrv.Shutdown(ctx)
	}
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("gripline: drain: %w", err)
	}
	log.Printf("gripline: drained, exiting")
	return nil
}

// buildDataPlane assembles the terminator + proxy from configuration. The
// in-process stores make the binary self-contained for evaluation; production
// deployments substitute durable implementations behind the same seams.
func buildDataPlane(cfg *config.Config) (http.Handler, error) {
	reg := credential.NewMemoryRegistry()

	pepper := os.Getenv("GRILINE_PEPPER_V1")
	if pepper == "" {
		return nil, fmt.Errorf("gripline: environment variable GRILINE_PEPPER_V1 is required (credential pepper key; injected, never on disk)")
	}
	peppers := credential.MustPepperRing(&credential.PepperKey{Version: 1, Key: []byte(pepper)})

	signer, err := terminator.NewKeyring()
	if err != nil {
		return nil, fmt.Errorf("gripline: assertion signer: %w", err)
	}

	pol := policyFor(cfg)
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg,
		Peppers:  peppers,
		Policy:   pol,
		Signer:   signer,
		Audience: cfg.Identity.Audience,
		Mode:     terminator.ModeTerminate,
	})
	if err != nil {
		return nil, fmt.Errorf("gripline: terminator: %w", err)
	}

	backend, err := urlFrom(cfg.Backend.URL)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		MaxIdleConnsPerHost:   cfg.Backend.MaxIdleConnsPerHost,
		ResponseHeaderTimeout: cfg.Backend.Timeout.D(),
		IdleConnTimeout:       cfg.Server.IdleTimeout.D(),
	}
	if backend.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return proxy.New(proxy.Config{
		Terminator: term,
		BackendURL: backend,
		Transport:  transport,
		Audience:   cfg.Identity.Audience,
	})
}

// buildAdmin assembles the authenticated control-plane listener from config,
// or returns nil when no admin section is configured.
func buildAdmin(cfg *config.Config) (*http.Server, error) {
	if cfg.Admin == nil {
		return nil, nil
	}
	audit, err := control.NewFileAuditRepository(cfg.Paths.AuditLog)
	if err != nil {
		return nil, err
	}
	tokens := make(map[string]*control.Identity, len(cfg.Admin.OperatorTokens))
	for tok, spec := range cfg.Admin.OperatorTokens {
		name, caps, err := parseSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("gripline: admin token: %w", err)
		}
		cs := make([]control.Capability, 0, len(caps))
		for _, c := range caps {
			cs = append(cs, control.Capability(c))
		}
		tokens[tok] = &control.Identity{Name: name, Capabilities: cs}
	}
	auth, err := control.NewTokenAuthenticator(tokens)
	if err != nil {
		return nil, err
	}
	svc, err := control.NewService(control.New(0), auth, audit)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/posture", adminPosture(svc))
	return &http.Server{
		Addr:              cfg.Admin.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}, nil
}

// adminPosture serves POST /admin/posture {"on":bool,"reason":"..."} with the
// operator's bearer token.
func adminPosture(svc *control.Service) http.HandlerFunc {
	type body struct {
		On     bool   `json:"on"`
		Reason string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var b body
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		token := bearer(r.Header.Get("Authorization"))
		posture, err := svc.SetEmergency(r.Context(), token, b.On, b.Reason)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"posture": posture.String()})
	}
}

func bearer(h string) string {
	rest, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(rest)
}

func parseSpec(spec string) (string, []string, error) {
	name, caps, ok := strings.Cut(spec, ":")
	if !ok {
		return "", nil, fmt.Errorf("spec must be \"name:cap1,cap2\"")
	}
	var out []string
	for _, c := range strings.Split(caps, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return strings.TrimSpace(name), out, nil
}

// policyFor builds the policy revision this deployment enforces. The default
// policy is the compiled baseline; production installs versioned policy
// artifacts through the control plane (P0.51 policy manager seam).
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
