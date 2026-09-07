package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// Runtime is the single application composition root (P0.1/P0.2).
// All security-critical state is instantiated once and shared.
type Runtime struct {
	Registry credential.Registry
	// Lanes is the lane authority (P0.10): the durable Bolt repository when
	// state-backed, the resident store otherwise. The terminator accepts the
	// Repository interface; the runtime no longer forces the memory
	// implementation.
	Lanes lane.Repository
	// AdminService is the production control-plane service (nil when no admin
	// section is configured). CLI/lifecycle tooling uses it; the HTTP admin
	// mux is the operator surface for it.
	AdminService *control.Service

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
	closeOnce sync.Once
	closeErr  error
}

// controlService returns the admin control-plane service (test/CLI seam).
func (rt *Runtime) controlService() *control.Service { return rt.AdminService }

// Ready reports whether the runtime can actually serve: the authorities are
// constructed (guaranteed by BuildRuntime returning) and, when state-backed,
// the Bolt database answers a probe read. A /readyz handler that only echoes a
// static flag is a lie — this is the check behind the endpoint (P1-24).
func (rt *Runtime) Ready() error {
	if rt.State != nil {
		if err := rt.State.Ping(); err != nil {
			return fmt.Errorf("gripline: state store not ready: %w", err)
		}
	}
	return nil
}

// BuildRuntime constructs the full application from configuration.
// P0.1 fix: Every authority is instantiated exactly once and shared.
func BuildRuntime(cfg *config.Config) (_ *Runtime, retErr error) {
	var closers []func() error
	defer func() {
		if retErr == nil {
			return
		}
		for i := len(closers) - 1; i >= 0; i-- {
			_ = closers[i]()
		}
	}()
	if cfg.Server.SpoolDir != "" {
		if err := os.MkdirAll(cfg.Server.SpoolDir, 0o750); err != nil {
			return nil, fmt.Errorf("gripline: create spool dir: %w", err)
		}
		if err := proxy.CleanupSpoolDir(cfg.Server.SpoolDir); err != nil {
			return nil, fmt.Errorf("gripline: cleanup spool dir: %w", err)
		}
	}

	peppers, err := loadPepperRing(cfg)
	if err != nil {
		return nil, err
	}

	// P0.18-fix: persistent state is the REQUIRED production path. paths.state
	// and paths.signer_keyring must be configured unless the operator
	// explicitly opts into ephemeral development mode
	// (deployment.allow_ephemeral_state=true). The safe deployment is the path
	// of least resistance.
	if !cfg.Deployment.AllowEphemeralState {
		if cfg.Paths.State == "" {
			return nil, fmt.Errorf("gripline: paths.state is required (deployment.allow_ephemeral_state is false; set it only for development)")
		}
		if cfg.Paths.SignerKeyring == "" {
			return nil, fmt.Errorf("gripline: paths.signer_keyring is required (deployment.allow_ephemeral_state is false; set it only for development)")
		}
	}

	// P0.2-fix: when a state DB is configured it is the SINGLE security
	// authority — credentials, lanes, evidence, operator audit, and posture
	// all live behind one transactional write path. A second persistence
	// authority (the legacy Gob evidence file) must not silently split
	// security state across databases.
	var reg credential.Registry
	var lanes lane.Repository
	var evStore evidence.Store
	var state *statebolt.Store
	if cfg.Paths.State != "" {
		if cfg.Paths.Evidence != "" {
			return nil, fmt.Errorf("gripline: paths.evidence must be empty when paths.state is configured: the Bolt state database is the single evidence authority (P0.2)")
		}
		s, err := statebolt.Open(cfg.Paths.State, statebolt.Options{})
		if err != nil {
			return nil, fmt.Errorf("gripline: state db: %w", err)
		}
		state = s
		closers = append(closers, func() error { return s.Close() })
		reg = s
		lanes = s   // durable lane.Repository (P0.10)
		evStore = s // durable evidence.Store (P0.2-fix)
	} else {
		reg = credential.NewMemoryRegistry()
		lanes = lane.NewStore(nil, time.Now)
		evStore = evidence.NewMemoryStore()
	}
	if cfg.Deployment.AllowEphemeralState {
		if err := bootstrapCredentials(reg); err != nil {
			return nil, err
		}
	} else if os.Getenv("GRIPLINE_BOOTSTRAP_CREDENTIAL") != "" {
		return nil, fmt.Errorf("gripline: GRIPLINE_BOOTSTRAP_CREDENTIAL is permitted only with deployment.allow_ephemeral_state=true; provision credentials before starting the persistent deployment")
	}

	signer, err := terminator.LoadOrCreateKeyring(cfg.Paths.SignerKeyring)
	if err != nil {
		return nil, fmt.Errorf("gripline: signer: %w", err)
	}

	// P0.1 fix: Instantiate each authority exactly once
	governor := resource.NewGovernor(nil)
	if cfg.Server.MaxSourceScopes > 0 || cfg.Server.SourceScopeIdle.D() > 0 {
		governor.SetSourceScopeLimits(cfg.Server.MaxSourceScopes, cfg.Server.SourceScopeIdle.D())
	}
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

	pol, err := policyFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("gripline: policy: %w", err)
	}

	term, err := terminator.New(terminator.Dependencies{
		Registry: reg,
		Peppers:  peppers,
		Lanes:    lanes, // Shared lane authority
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
		MaxIdleConnsPerHost: cfg.Backend.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.Server.IdleTimeout.D(),
		// Preserve backend response bytes and negotiation semantics. Automatic
		// gzip negotiation/decompression would make this proxy transform a
		// supposedly pass-through response.
		DisableCompression: true,
	}
	// Split backend timeouts (P0.16): each phase defaults to backend.timeout.
	dialTimeout := cfg.Backend.Timeout.D()
	if cfg.Backend.DialTimeout.D() > 0 {
		dialTimeout = cfg.Backend.DialTimeout.D()
	}
	tlsHandshakeTimeout := cfg.Backend.Timeout.D()
	if cfg.Backend.TLSHandshakeTimeout.D() > 0 {
		tlsHandshakeTimeout = cfg.Backend.TLSHandshakeTimeout.D()
	}
	respHeaderTimeout := cfg.Backend.Timeout.D()
	if cfg.Backend.ResponseHeaderTimeout.D() > 0 {
		respHeaderTimeout = cfg.Backend.ResponseHeaderTimeout.D()
	}
	transport.DialContext = (&net.Dialer{Timeout: dialTimeout}).DialContext
	transport.TLSHandshakeTimeout = tlsHandshakeTimeout
	transport.ResponseHeaderTimeout = respHeaderTimeout
	if backend.Scheme == "https" {
		tlsConfig, err := cfg.BackendTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("gripline: backend tls: %w", err)
		}
		transport.TLSClientConfig = tlsConfig
	}

	// P0.6: Build the trusted ingress source resolver if configured.
	var srcResolver *proxy.IngressSourceResolver
	if cfg.Ingress != nil && cfg.Ingress.PseudonymKey != "" {
		pseudoKey, err := decodeSecretKey("ingress.pseudonym_key", cfg.Ingress.PseudonymKey, 32)
		if err != nil {
			return nil, err
		}
		defer zeroBytes(pseudoKey)
		// P0-17: key-separation — the pseudonymization HMAC key must differ
		// from the credential verifier pepper; reusing one secret across two
		// domains lets a value in either domain be replayed into the other.
		for _, version := range peppers.Versions() {
			pepperKey, ok := peppers.Get(version)
			if ok && bytes.Equal(pseudoKey, pepperKey) {
				zeroBytes(pepperKey)
				return nil, fmt.Errorf("gripline: ingress.pseudonym_key must differ from every configured verifier pepper (key separation; version %d)", version)
			}
			zeroBytes(pepperKey)
		}
		pseudonyms, err := pseudonymRingFromKey(pseudoKey)
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
		// P0.16 streaming timeout scheme: when the idle bound is configured the
		// data plane owns per-request write deadlines (initial full budget,
		// re-armed per chunk); main.go must then run the server with
		// WriteTimeout 0 so the per-request deadlines govern instead of the
		// blanket one that would kill long-lived SSE streams.
		WriteTimeout:           cfg.Server.WriteTimeout.D(),
		StreamWriteIdleTimeout: cfg.Server.StreamWriteIdleTimeout.D(),
		SpoolDir:               cfg.Server.SpoolDir,
		SpoolMaxBytes:          cfg.Server.SpoolMaxBytes,
		SpoolMaxFiles:          cfg.Server.SpoolMaxFiles,
	}
	// Admission and completion decisions are shipped as bounded JSONL events
	// on stderr. This is intentionally a real runtime sink, not only a library
	// seam: operators can route stderr to journald, a sidecar, or a collector.
	decisionObserver := newJSONLObserver(os.Stderr)
	closers = append(closers, decisionObserver.Close)
	proxyCfg.Admission = decisionObserver
	proxyCfg.Observer = decisionObserver
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
	var adminSvc *control.Service
	if cfg.Admin != nil {
		// P0.5/P0.7: when state-backed, the Bolt store is the sole operator
		// audit sink — every operator action appends into the same transaction
		// as the mutation it documents. Config validation rejects a JSONL path
		// here so a mirror can never be mistaken for authoritative history.
		var audit control.AuditRepository
		if state != nil {
			audit = state
		} else {
			fileAudit, err := control.NewFileAuditRepository(cfg.Paths.AuditLog)
			if err != nil {
				return nil, err
			}
			audit = fileAudit
			closers = append(closers, func() error { return fileAudit.Close() })
		}

		tokens := make(map[string]*control.Identity, len(cfg.Admin.OperatorTokens))
		for tok, spec := range cfg.Admin.OperatorTokens {
			name, caps, err := parseSpec(spec)
			if err != nil {
				return nil, fmt.Errorf("gripline: admin token: %w", err)
			}
			cs := make([]control.Capability, 0, len(caps))
			for _, c := range caps {
				capability, err := control.ParseCapability(c)
				if err != nil {
					return nil, fmt.Errorf("gripline: admin token: %w", err)
				}
				cs = append(cs, capability)
			}
			tokens[tok] = &control.Identity{Name: name, Capabilities: cs}
		}
		auth, err := control.NewTokenAuthenticator(tokens)
		if err != nil {
			return nil, err
		}

		// P0.1 fix: use the SAME lane authority as the terminator.
		opts := []control.ServiceOption{
			control.WithCredentialOperator(reg),
		}
		// P0.18-fix: when state-backed, EVERY operator mutation (credential
		// revoke, lane unblock, posture) commits with its audit row in one
		// transaction via control.MutationStore. The lane-unblock path also
		// commits its lane-side audit entry atomically inside the state store
		// (P0.49).
		if state != nil {
			opts = append(opts, control.WithMutationStore(state))
		} else {
			opts = append(opts, control.WithLaneOperator(control.LaneUnblockAdapter{Unblock: func(credID, laneID, actor, reason string, now time.Time) error {
				mem, ok := lanes.(*lane.Store)
				if !ok {
					return fmt.Errorf("gripline: lane unblock requires the resident lane store in ephemeral mode")
				}
				_, err := mem.Unblock(credID, laneID, actor, reason, now)
				return err
			}}))
		}
		svc, err := control.NewService(ctrl, auth, audit, opts...)
		if err != nil {
			return nil, err
		}
		adminSvc = svc

		mux := http.NewServeMux()
		mux.HandleFunc("/admin/posture", adminPosture(svc))
		mux.HandleFunc("/admin/credentials", adminCredentials(svc, state))
		mux.HandleFunc("/admin/credentials/add", adminCredentialAdd(svc, state))
		mux.HandleFunc("/admin/credentials/revoke", adminCredentialRevoke(svc))
		mux.HandleFunc("/admin/lanes", adminLanes(svc, state))
		mux.HandleFunc("/admin/lanes/unblock", adminLaneUnblock(svc))
		mux.HandleFunc("/admin/audit", adminAudit(svc, state))
		mux.HandleFunc("/admin/security-events", adminSecurityEvents(svc, state))
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
		Registry:     reg,
		Lanes:        lanes, // Shared lane authority
		AdminService: adminSvc,
		Evidence:     evStore,
		Resource:     governor, // Shared resource governor
		Control:      ctrl,     // Shared control plane
		Spray:        spray,    // Shared spray detector
		Signer:       signer,
		Policy:       pol,
		State:        state,
		Audience:     cfg.Identity.Audience,
		DataPlane:    dp,
		Admin:        adminSrv,
		closers:      closers,
	}, nil
}

// loadPepperRing loads all configured verifier peppers and returns a ring that
// retains only its private copies. The legacy V1 environment variable remains
// a compatibility fallback when no versioned config map is present. New
// verifiers should always use ring.Latest(); older versions stay available for
// authentication until their records are migrated.
func loadPepperRing(cfg *config.Config) (*credential.PepperRing, error) {
	values := cfg.Secrets.PepperVersions
	legacyEnv := false
	if len(values) == 0 {
		legacyEnv = true
		pepper := os.Getenv("GRIPLINE_PEPPER_V1")
		if pepper == "" {
			pepper = os.Getenv("GRILINE_PEPPER_V1")
			if pepper != "" {
				log.Printf("gripline: WARNING: using misspelled GRILINE_PEPPER_V1")
			}
		}
		if pepper == "" {
			return nil, fmt.Errorf("gripline: verifier pepper required: configure secrets.pepper_versions or GRIPLINE_PEPPER_V1 (base64-encoded, >=32 bytes of entropy)")
		}
		values = map[string]string{"1": pepper}
	}
	versions := make([]int, 0, len(values))
	encoded := make(map[int]string, len(values))
	for rawVersion, value := range values {
		version, err := strconv.Atoi(rawVersion)
		if err != nil || version < 1 {
			return nil, fmt.Errorf("gripline: verifier pepper version %q must be a positive decimal", rawVersion)
		}
		if _, exists := encoded[version]; exists {
			return nil, fmt.Errorf("gripline: duplicate verifier pepper version %d", version)
		}
		encoded[version] = value
		versions = append(versions, version)
	}
	sort.Ints(versions)
	keys := make([]*credential.PepperKey, 0, len(versions))
	for _, version := range versions {
		what := fmt.Sprintf("verifier pepper version %d", version)
		if legacyEnv && version == 1 {
			what = "GRIPLINE_PEPPER_V1"
		}
		key, err := decodeSecretKey(what, encoded[version], 32)
		if err != nil {
			for _, prior := range keys {
				zeroBytes(prior.Key)
			}
			return nil, err
		}
		keys = append(keys, &credential.PepperKey{Version: version, Key: key})
	}
	ring, err := credential.NewPepperRing(keys...)
	for _, key := range keys {
		zeroBytes(key.Key)
	}
	if err != nil {
		return nil, fmt.Errorf("gripline: verifier pepper ring: %w", err)
	}
	return ring, nil
}

// Close releases the runtime's resources exactly once (P1.23). Errors from
// individual closers are aggregated.
func (rt *Runtime) Close() error {
	rt.closeOnce.Do(func() {
		var errs []error
		for i := len(rt.closers) - 1; i >= 0; i-- {
			if err := rt.closers[i](); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			rt.closeErr = fmt.Errorf("gripline: close errors: %w", errors.Join(errs...))
		}
	})
	return rt.closeErr
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
		if err := decodeAdminJSON(w, r, &b); err != nil {
			return
		}
		token := bearer(r.Header.Get("Authorization"))
		posture, err := svc.SetEmergency(r.Context(), token, b.On, b.Reason)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"posture": posture.String()})
	}
}

func adminCredentials(svc *control.Service, state *statebolt.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapCredentialLifecycle); err != nil {
			writeAdminError(w, err)
			return
		}
		if state == nil {
			http.Error(w, "persistent credential authority unavailable", http.StatusServiceUnavailable)
			return
		}
		rows, err := state.ListCredentials()
		if err != nil {
			http.Error(w, "credential authority unavailable", http.StatusServiceUnavailable)
			return
		}
		writeAdminJSON(w, rows)
	}
}

func adminCredentialRevoke(svc *control.Service) http.HandlerFunc {
	type request struct {
		CredentialID string `json:"credential_id"`
		Reason       string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		var req request
		if err := decodeAdminJSON(w, r, &req); err != nil {
			return
		}
		if req.CredentialID == "" || req.Reason == "" {
			http.Error(w, "credential_id and reason are required", http.StatusBadRequest)
			return
		}
		if err := svc.RevokeCredential(r.Context(), bearer(r.Header.Get("Authorization")), req.CredentialID, req.Reason); err != nil {
			writeAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]string{"credential_id": req.CredentialID, "status": "REVOKED"})
	}
}

func adminCredentialAdd(svc *control.Service, state *statebolt.Store) http.HandlerFunc {
	type request struct {
		CredentialID    string `json:"credential_id"`
		AccountID       string `json:"account_id"`
		PolicyID        string `json:"policy_id"`
		PlanID          string `json:"plan_id"`
		VerifierB64     string `json:"verifier_b64"`
		VerifierVersion int    `json:"verifier_version"`
		PepperVersion   int    `json:"pepper_version"`
		Reason          string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		var req request
		if err := decodeAdminJSON(w, r, &req); err != nil {
			return
		}
		if state == nil {
			http.Error(w, "persistent credential authority unavailable", http.StatusServiceUnavailable)
			return
		}
		if req.CredentialID == "" || req.AccountID == "" || req.PolicyID == "" || req.PlanID == "" || req.VerifierB64 == "" || req.Reason == "" {
			http.Error(w, "credential_id, account_id, policy_id, plan_id, verifier_b64, and reason are required", http.StatusBadRequest)
			return
		}
		verifier, err := base64.StdEncoding.DecodeString(req.VerifierB64)
		if err != nil || len(verifier) == 0 {
			http.Error(w, "verifier_b64 must be valid base64", http.StatusBadRequest)
			return
		}
		defer func() {
			for i := range verifier {
				verifier[i] = 0
			}
		}()
		if req.VerifierVersion == 0 {
			req.VerifierVersion = 1
		}
		if req.PepperVersion == 0 {
			req.PepperVersion = 1
		}
		rec := credential.CredentialRecord{
			CredentialID: req.CredentialID, AccountID: req.AccountID, Verifier: verifier,
			VerifierVersion: req.VerifierVersion, PepperVersion: req.PepperVersion,
			Status: credential.StatusNormal, PolicyID: req.PolicyID, PlanID: req.PlanID,
			CreatedAt: time.Now().UTC(), Revision: 1,
		}
		if err := svc.ProvisionCredential(r.Context(), bearer(r.Header.Get("Authorization")), rec, req.Reason); err != nil {
			writeAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]string{"credential_id": req.CredentialID, "status": "ACTIVE"})
	}
}

func adminLanes(svc *control.Service, state *statebolt.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapLaneLifecycle); err != nil {
			writeAdminError(w, err)
			return
		}
		if state == nil {
			http.Error(w, "persistent lane authority unavailable", http.StatusServiceUnavailable)
			return
		}
		credentialID := r.URL.Query().Get("credential")
		if credentialID == "" {
			http.Error(w, "credential query parameter is required", http.StatusBadRequest)
			return
		}
		rows, err := state.ListLaneRecords(credentialID)
		if err != nil {
			http.Error(w, "lane authority unavailable", http.StatusServiceUnavailable)
			return
		}
		type summary struct {
			LaneID       string    `json:"lane_id"`
			CredentialID string    `json:"credential_id"`
			State        string    `json:"state"`
			Security     string    `json:"security_state"`
			RiskScore    int       `json:"risk_score"`
			RequestCount int64     `json:"request_count"`
			LastSeenAt   time.Time `json:"last_seen_at"`
			Revision     int       `json:"revision"`
		}
		out := make([]summary, 0, len(rows))
		for _, row := range rows {
			out = append(out, summary{
				LaneID: row.LaneID, CredentialID: row.CredentialID, State: row.State.String(),
				Security: row.Security.Status.String(), RiskScore: row.RiskScore,
				RequestCount: row.RequestCount, LastSeenAt: row.LastSeenAt.UTC(), Revision: row.Revision,
			})
		}
		writeAdminJSON(w, out)
	}
}

func adminLaneUnblock(svc *control.Service) http.HandlerFunc {
	type request struct {
		CredentialID string `json:"credential_id"`
		LaneID       string `json:"lane_id"`
		Reason       string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		var req request
		if err := decodeAdminJSON(w, r, &req); err != nil {
			return
		}
		if req.CredentialID == "" || req.LaneID == "" || req.Reason == "" {
			http.Error(w, "credential_id, lane_id, and reason are required", http.StatusBadRequest)
			return
		}
		if err := svc.UnblockLane(r.Context(), bearer(r.Header.Get("Authorization")), req.CredentialID, req.LaneID, req.Reason); err != nil {
			writeAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]string{"credential_id": req.CredentialID, "lane_id": req.LaneID, "status": "NORMAL"})
	}
}

func adminAudit(svc *control.Service, state *statebolt.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapAuditRead); err != nil {
			writeAdminError(w, err)
			return
		}
		if state == nil {
			http.Error(w, "persistent audit authority unavailable", http.StatusServiceUnavailable)
			return
		}
		after := uint64(0)
		if raw := r.URL.Query().Get("after"); raw != "" {
			var err error
			after, err = strconv.ParseUint(raw, 10, 64)
			if err != nil {
				http.Error(w, "invalid after cursor", http.StatusBadRequest)
				return
			}
		}
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var err error
			limit, err = strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 1000 {
				http.Error(w, "invalid limit", http.StatusBadRequest)
				return
			}
		}
		rows, err := state.ListOperatorAudit(after, limit)
		if err != nil {
			http.Error(w, "audit authority unavailable", http.StatusServiceUnavailable)
			return
		}
		if len(rows) > 0 {
			w.Header().Set("X-Gripline-Next-Audit-After", strconv.FormatUint(rows[len(rows)-1].Sequence, 10))
		}
		w.Header().Set("X-Gripline-Audit-Has-More", strconv.FormatBool(len(rows) == limit))
		writeAdminJSON(w, rows)
	}
}

func adminSecurityEvents(svc *control.Service, state *statebolt.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapAuditRead); err != nil {
			writeAdminError(w, err)
			return
		}
		if state == nil {
			http.Error(w, "persistent security audit authority unavailable", http.StatusServiceUnavailable)
			return
		}
		after, limit, err := auditCursor(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rows, err := state.ListSecurityTransitions(after, limit)
		if err != nil {
			http.Error(w, "security audit authority unavailable", http.StatusServiceUnavailable)
			return
		}
		if len(rows) > 0 {
			w.Header().Set("X-Gripline-Next-Audit-After", strconv.FormatUint(rows[len(rows)-1].Sequence, 10))
		}
		w.Header().Set("X-Gripline-Audit-Has-More", strconv.FormatBool(len(rows) == limit))
		writeAdminJSON(w, rows)
	}
}

func auditCursor(r *http.Request) (uint64, int, error) {
	after := uint64(0)
	if raw := r.URL.Query().Get("after"); raw != "" {
		var err error
		after, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid after cursor")
		}
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 1000 {
			return 0, 0, fmt.Errorf("invalid limit")
		}
	}
	return after, limit, nil
}

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		http.Error(w, "bad request", http.StatusBadRequest)
		if err == nil {
			err = errors.New("admin JSON must be one object")
		}
		return err
	}
	obj := json.NewDecoder(bytes.NewReader(raw))
	obj.DisallowUnknownFields()
	if err := obj.Decode(dst); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return err
	}
	return nil
}

func writeAdminJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func adminMethodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func writeAdminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, control.ErrUnauthenticated):
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case errors.Is(err, control.ErrUnauthorized):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, control.ErrReasonRequired):
		http.Error(w, "reason required", http.StatusBadRequest)
	case errors.Is(err, credential.ErrNotFound), errors.Is(err, lane.ErrLaneNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		http.Error(w, "operator action failed", http.StatusInternalServerError)
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

func bootstrapCredentials(reg credential.Registry) error {
	// This is a development-only compatibility seam for an already-derived
	// verifier record. Raw external credentials are deliberately not accepted
	// here; production credentials are provisioned through the authenticated
	// operator lifecycle before the persistent runtime starts.
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

	return nil
}

// pseudonymRingFromKey builds an ingress.PseudonymRing from a raw HMAC key
// (P0.6). The pseudonym key MUST be distinct from the credential pepper.
func pseudonymRingFromKey(key []byte) (ingress.PseudonymRing, error) {
	ring, err := pseudonym.NewRing(&pseudonym.Key{Version: 1, Secret: key})
	if err != nil {
		return nil, err
	}
	return &pseudonymRingAdapter{ring: ring}, nil
}

// decodeSecretKey decodes a base64 (standard or URL-safe, padding optional)
// secret-material configuration value and enforces a minimum DECODED length
// (P0-17): a deployment key must carry real entropy, not an ASCII passphrase.
// Raw (non-base64) values are rejected so short/low-entropy secrets cannot
// sneak past the length check via encoding confusion.
func decodeSecretKey(what, encoded string, minBytes int) ([]byte, error) {
	enc := strings.TrimSpace(encoded)
	trimmed := strings.TrimRight(enc, "=")
	var key []byte
	var err error
	switch {
	case strings.ContainsAny(trimmed, "-_"):
		key, err = base64.RawURLEncoding.DecodeString(enc)
	default:
		key, err = base64.StdEncoding.DecodeString(enc)
	}
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("gripline: %s must be base64-encoded (got decode error: %v)", what, err)
	}
	if len(key) < minBytes {
		zeroBytes(key)
		return nil, fmt.Errorf("gripline: %s must decode to at least %d bytes of entropy, got %d", what, minBytes, len(key))
	}
	return key, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// pseudonymRingAdapter adapts a *pseudonym.Ring to ingress.PseudonymRing.
type pseudonymRingAdapter struct {
	ring *pseudonym.Ring
}

func (a *pseudonymRingAdapter) Derive(family []byte, raw []byte) (string, error) {
	return a.ring.Derive(pseudonym.Family(family), raw)
}
