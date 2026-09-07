package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/config"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/ingress"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/producers"
	"github.com/B-A-M-N/gripline/internal/proxy"
	"github.com/B-A-M-N/gripline/internal/pseudonym"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// Runtime is the single application composition root (P0.1/P0.2).
// All security-critical state is instantiated once and shared.
type Runtime struct {
	Registry  credential.Registry
	Lanes     *lane.Store
	Evidence  evidence.Store
	Resource  *resource.Governor
	Control   *control.ControlPlane
	Spray     *anomaly.Detector
	Signer    terminator.AssertionSigner
	Policy    *policy.Policy
	State     *statebolt.Store // non-nil when backed by the transactional store
	Audience  string
	DataPlane http.Handler
	Admin     *http.Server
	closers   []func() error
}

// BuildRuntime constructs the full application from configuration.
// P0.1 fix: Every authority is instantiated exactly once and shared.
func BuildRuntime(cfg *config.Config) (*Runtime, error) {
	var closers []func() error

	pepper := os.Getenv("GRIPLINE_PEPPER_V1")
	if pepper == "" {
		pepper = os.Getenv("GRILINE_PEPPER_V1")
		if pepper != "" {
			log.Printf("gripline: WARNING: using misspelled GRILINE_PEPPER_V1")
		}
	}
	if pepper == "" {
		return nil, fmt.Errorf("gripline: GRIPLINE_PEPPER_V1 env var required")
	}
	if len(pepper) < 16 {
		return nil, fmt.Errorf("gripline: GRIPLINE_PEPPER_V1 must be at least 16 bytes")
	}
	peppers := credential.MustPepperRing(&credential.PepperKey{Version: 1, Key: []byte(pepper)})

	// P0.10: when a state DB path is configured, back the credential registry
	// (and operator audit + posture) on one transactional bbolt store instead of
	// the in-memory registry. Every registry mutation is then transactional and
	// durable across restart; bootstrap uses InsertIfAbsent so an env-provided
	// credential never overwrites an operator-managed one.
	var reg credential.Registry
	var state *statebolt.Store
	if cfg.Paths.State != "" {
		s, err := statebolt.Open(cfg.Paths.State, statebolt.Options{})
		if err != nil {
			return nil, fmt.Errorf("gripline: state db: %w", err)
		}
		state = s
		closers = append(closers, func() error { return s.Close() })
		reg = s
	} else {
		reg = credential.NewMemoryRegistry()
	}
	if err := bootstrapCredentials(reg, pepper); err != nil {
		return nil, err
	}

	var evStore evidence.Store
	if cfg.Paths.Evidence != "" {
		durable, closeFn, err := evidence.NewDurableStore(evidence.DurableConfig{
			Path:          cfg.Paths.Evidence,
			FlushInterval: time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("gripline: durable evidence store: %w", err)
		}
		evStore = durable
		closers = append(closers, closeFn)
	} else {
		evStore = evidence.NewMemoryStore()
	}

	signer, err := terminator.LoadKeyring(cfg.Paths.SignerKeyring)
	if err != nil {
		return nil, fmt.Errorf("gripline: signer: %w", err)
	}

	// P0.1 fix: Instantiate each authority exactly once
	lanes := lane.NewStore(nil, time.Now)
	governor := resource.NewGovernor(nil)
	spray := anomaly.NewDetector(time.Now, anomaly.DefaultThresholds())
	ctrl := control.New(0)
	// P0.10: restore the persisted operator posture so a process restart in
	// EMERGENCY_LOCKDOWN does not silently boot into NORMAL.
	if state != nil {
		p, err := state.LoadPosture()
		if err != nil {
			return nil, fmt.Errorf("gripline: load posture: %w", err)
		}
		ctrl.Restore(p)
	}

	pol := policyFor(cfg)

	term, err := terminator.New(terminator.Dependencies{
		Registry: reg,
		Peppers:  peppers,
		Lanes:    lanes, // Shared lane store
		Policy:   pol,
		Signer:   signer,
		Audience: cfg.Identity.Audience,
		Evidence: evStore,
		Mode:     terminator.ModeEnforce,
		Resource: governor, // Shared resource governor
		Control:  ctrl,     // Shared control plane
		Spray:    spray,    // Shared spray detector
		Producers: []producers.Producer{
			producers.NewSourceNoveltyProducer(time.Now),
			producers.NewResourceVelocityProducer(time.Now),
			producers.NewEnumerationProducer(time.Now),
		},
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

	// P0.6: Build the trusted ingress source resolver if configured.
	var srcResolver *proxy.IngressSourceResolver
	if cfg.Ingress != nil && cfg.Ingress.PseudonymKey != "" {
		pseudonyms, err := pseudonymRingFromKey(cfg.Ingress.PseudonymKey)
		if err != nil {
			return nil, fmt.Errorf("gripline: ingress pseudonym key: %w", err)
		}
		prefixes := make([]netip.Prefix, 0, len(cfg.Ingress.TrustedProxies))
		for _, cidr := range cfg.Ingress.TrustedProxies {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("gripline: ingress trusted proxy %q: %w", cidr, err)
			}
			prefixes = append(prefixes, p)
		}
		resolver := &ingress.Resolver{
			Pseudonyms:     pseudonyms,
			TrustedProxies: prefixes,
		}
		srcResolver = proxy.NewIngressSourceResolver(resolver)
	}

	proxyCfg := proxy.Config{
		Terminator:   term,
		BackendURL:   backend,
		Transport:    transport,
		Audience:     cfg.Identity.Audience,
		MaxBodyBytes: cfg.Server.MaxBodyBytes,
	}
	// P0.6: Only wire a source resolver when ingress is configured. Leaving
	// Sources nil defaults to NoSource (source-scoped features inert).
	if srcResolver != nil {
		proxyCfg.Sources = srcResolver
	}
	dp, err := proxy.New(proxyCfg)
	if err != nil {
		return nil, fmt.Errorf("gripline: proxy: %w", err)
	}

	var adminSrv *http.Server
	if cfg.Admin != nil {
		audit, err := control.NewFileAuditRepository(cfg.Paths.AuditLog)
		if err != nil {
			return nil, err
		}
		closers = append(closers, func() error { return audit.Close() })

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

		// P0.1 fix: Use the SAME lane store as the terminator
		opts := []control.ServiceOption{
			control.WithCredentialOperator(reg),
			control.WithLaneOperator(control.LaneUnblockAdapter{Unblock: func(credID, laneID, actor, reason string, now time.Time) error {
				_, err := lanes.Unblock(credID, laneID, actor, reason, now)
				return err
			}}),
		}
		// P0.10: persist + audit emergency transitions atomically through the
		// state store so lockdown survives restart.
		if state != nil {
			opts = append(opts, control.WithPosturePersister(func(ctx context.Context, target control.Posture, actor, reason string) error {
				return state.SetPostureWithAudit(ctx, target, control.OperatorRecord{
					At: time.Now().UTC(), Actor: actor, Action: "posture.set_emergency",
					Target: "global", Reason: reason, Posture: target.String(), Committed: true,
				})
			}))
		}
		svc, err := control.NewService(ctrl, auth, audit, opts...)
		if err != nil {
			return nil, err
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/admin/posture", adminPosture(svc))
		adminSrv = &http.Server{
			Addr:              cfg.Admin.Listen,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
	}

	return &Runtime{
		Registry:  reg,
		Lanes:     lanes, // Shared lane store
		Evidence:  evStore,
		Resource:  governor, // Shared resource governor
		Control:   ctrl,     // Shared control plane
		Spray:     spray,    // Shared spray detector
		Signer:    signer,
		Policy:    pol,
		State:     state,
		Audience:  cfg.Identity.Audience,
		DataPlane: dp,
		Admin:     adminSrv,
		closers:   closers,
	}, nil
}

func (rt *Runtime) Close() error {
	var errs []error
	for _, fn := range rt.closers {
		if err := fn(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("gripline: close errors: %v", errs)
	}
	return nil
}

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

func bootstrapCredentials(reg credential.Registry, pepper string) error {
	// Bootstrap prefers the Provisioner seam (InsertIfAbsent) so an env-provided
	// credential never overwrites a durable, operator-managed one (P0.10). A
	// registry that does not support provisioning (must be provisioned out of
	// band) is left alone.
	prov, ok := reg.(credential.Provisioner)
	if bootstrapJSON := os.Getenv("GRIPLINE_BOOTSTRAP_CREDENTIAL"); bootstrapJSON != "" {
		var rec credential.CredentialRecord
		if err := json.Unmarshal([]byte(bootstrapJSON), &rec); err != nil {
			return fmt.Errorf("gripline: parse GRIPLINE_BOOTSTRAP_CREDENTIAL: %w", err)
		}
		if len(rec.Verifier) == 0 {
			return fmt.Errorf("gripline: GRIPLINE_BOOTSTRAP_CREDENTIAL missing verifier")
		}
		// InsertIfAbsent (P0.10): bootstrap must never overwrite an already
		// provisioned credential that an operator may have since REVOKED or
		// CONSTRAINED.
		if !ok {
			return fmt.Errorf("gripline: registry does not support provisioning; cannot bootstrap credential %s", rec.CredentialID)
		}
		created, err := prov.InsertIfAbsent(&rec)
		if err != nil {
			return fmt.Errorf("gripline: insert bootstrap credential: %w", err)
		}
		if created {
			log.Printf("gripline: bootstrap credential %s wired (status=%s)", rec.CredentialID, rec.Status)
		} else {
			log.Printf("gripline: bootstrap credential %s already present; left untouched", rec.CredentialID)
		}
		return nil
	}

	if credSecret := os.Getenv("GRIPLINE_CREDENTIAL_SECRET"); credSecret != "" {
		sealed := secret.NewFromBytes([]byte(credSecret))
		verifier := credential.Verifier(sealed, &credential.PepperKey{Version: 1, Key: []byte(pepper)})
		credID := os.Getenv("GRIPLINE_CREDENTIAL_ID")
		if credID == "" {
			credID = "cred_bootstrap"
		}
		if !ok {
			return fmt.Errorf("gripline: registry does not support provisioning; cannot derive credential %s", credID)
		}
		if _, err := prov.InsertIfAbsent(&credential.CredentialRecord{
			CredentialID:  credID,
			AccountID:     os.Getenv("GRIPLINE_ACCOUNT_ID"),
			Verifier:      verifier,
			PepperVersion: 1,
			Status:        credential.StatusNormal,
			PolicyID:      "fi-default-v1",
			PlanID:        "plan-a",
			CreatedAt:     time.Now().Add(-time.Hour),
			Revision:      1,
		}); err != nil {
			return fmt.Errorf("gripline: insert derived credential: %w", err)
		}
		log.Printf("gripline: derived credential %s wired", credID)
	}

	return nil
}

// pseudonymRingFromKey builds an ingress.PseudonymRing from a raw HMAC key
// (P0.6). The pseudonym key MUST be distinct from the credential pepper.
func pseudonymRingFromKey(key string) (ingress.PseudonymRing, error) {
	ring, err := pseudonym.NewRing(&pseudonym.Key{Version: 1, Secret: []byte(key)})
	if err != nil {
		return nil, err
	}
	return &pseudonymRingAdapter{ring: ring}, nil
}

// pseudonymRingAdapter adapts a *pseudonym.Ring to ingress.PseudonymRing.
type pseudonymRingAdapter struct {
	ring *pseudonym.Ring
}

func (a *pseudonymRingAdapter) Derive(family []byte, raw []byte) (string, error) {
	return a.ring.Derive(pseudonym.Family(family), raw)
}
