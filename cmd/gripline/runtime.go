package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

	publicingress "github.com/B-A-M-N/gripline/adapter/ingress"
	publicusage "github.com/B-A-M-N/gripline/adapter/usage"
	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/authority"
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
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// adminStateAuthority is the read-only administrative view shared by the
// standalone Bolt and clustered PostgreSQL authorities. Handlers depend on
// this contract rather than a particular database implementation.
type adminStateAuthority interface {
	ListCredentials() ([]credential.Summary, error)
	CountCredentialsByPepperVersion() (map[int]int, error)
	ListLaneRecords(string) ([]*lane.LaneRecord, error)
	ListOperatorAudit(uint64, int) ([]control.OperatorRecord, error)
	ListSecurityTransitions(uint64, int) ([]control.SecurityTransitionRecord, error)
}

type adaptiveStateAuthority interface {
	LoadDetectorState(string) ([]byte, bool, error)
	SaveDetectorState(string, []byte) error
}

// StateHealth is the backend-neutral readiness contract. Standalone bbolt and
// clustered PostgreSQL expose the same bounded probe while keeping their
// backend-specific operational APIs private to their own packages.
type StateHealth interface {
	Ready(context.Context) error
}

// PolicyHealth is the policy-specific readiness contract. In clustered mode
// the manager refreshes the shared manifest and refuses readiness when the
// current artifact or activation epoch cannot be resolved.
type PolicyHealth interface {
	Ready(context.Context) error
}

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

	Evidence       evidence.Store
	Resource       resource.ResourceAuthority
	Control        *control.ControlPlane
	Posture        control.PostureAuthority
	Authorities    authority.Bundle
	Spray          *anomaly.Detector
	Signer         terminator.AssertionSigner
	Policy         *policy.Policy
	PolicyManager  *policy.Manager
	StateHealth    StateHealth
	PolicyHealth   PolicyHealth
	State          *statebolt.Store // non-nil when backed by the transactional store
	Postgres       *statepg.Store   // non-nil when backed by the clustered authority
	Audience       string
	DataPlane      http.Handler
	Admin          *http.Server
	adaptiveHealth []terminator.AdaptivePersistenceHealth
	closers        []func() error
	closeOnce      sync.Once
	closeErr       error
}

// controlService returns the admin control-plane service (test/CLI seam).
func (rt *Runtime) controlService() *control.Service { return rt.AdminService }

// Ready reports whether the runtime can actually serve: the authorities are
// constructed (guaranteed by BuildRuntime returning) and, when state-backed,
// the Bolt database answers a probe read. A /readyz handler that only echoes a
// static flag is a lie — this is the check behind the endpoint (P1-24).
func (rt *Runtime) Ready() error {
	if rt.StateHealth != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := rt.StateHealth.Ready(ctx)
		if err != nil {
			return fmt.Errorf("gripline: state authority not ready: %w", err)
		}
		if rt.PolicyHealth != nil {
			if err := rt.PolicyHealth.Ready(ctx); err != nil {
				return fmt.Errorf("gripline: policy authority not ready: %w", err)
			}
		}
	} else {
		// Compatibility for hand-built Runtime values from older embedders.
		if rt.State != nil {
			if err := rt.State.Ping(); err != nil {
				return fmt.Errorf("gripline: state store not ready: %w", err)
			}
		}
		if rt.Postgres != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := rt.Postgres.Ready(ctx); err != nil {
				return fmt.Errorf("gripline: postgres authority not ready: %w", err)
			}
		}
		if rt.PolicyHealth != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := rt.PolicyHealth.Ready(ctx)
			cancel()
			if err != nil {
				return fmt.Errorf("gripline: policy authority not ready: %w", err)
			}
		}
	}
	for _, health := range rt.adaptiveHealth {
		if health != nil && health.PersistenceError() != nil {
			return fmt.Errorf("gripline: adaptive state checkpoint unavailable")
		}
	}
	return nil
}

// MarkDraining withdraws this node from cluster readiness before HTTP
// shutdown. Existing handlers remain able to renew and settle their leases
// while the load balancer stops sending new work.
func (rt *Runtime) MarkDraining(ctx context.Context, until time.Time) error {
	if rt == nil || rt.Authorities.Membership == nil {
		return nil
	}
	return rt.Authorities.Membership.MarkDraining(ctx, until)
}

// BuildRuntime constructs the full application from configuration.
// P0.1 fix: Every authority is instantiated exactly once and shared.
func BuildRuntime(cfg *config.Config) (_ *Runtime, retErr error) {
	var closers []func() error
	var adaptiveHealth []terminator.AdaptivePersistenceHealth
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
	if !cfg.Deployment.AllowEphemeralState && strings.ToLower(strings.TrimSpace(cfg.Authority.Backend)) != "postgres" {
		if cfg.Paths.State == "" {
			return nil, fmt.Errorf("gripline: paths.state is required (deployment.allow_ephemeral_state is false; set it only for development)")
		}
	}
	if !cfg.Deployment.AllowEphemeralState && cfg.Paths.SignerKeyring == "" {
		return nil, fmt.Errorf("gripline: paths.signer_keyring is required (deployment.allow_ephemeral_state is false; set it only for development)")
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
	var postgres *statepg.Store
	var stateHealth StateHealth
	var authorities authority.Bundle
	var adminState adminStateAuthority
	var adaptiveState adaptiveStateAuthority
	connectTimeout := cfg.Authority.ConnectTimeout.D()
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}
	operationTimeout := cfg.Authority.OperationTimeout.D()
	if operationTimeout <= 0 {
		operationTimeout = 2 * time.Second
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Authority.Backend)) {
	case "postgres":
		dsn := os.Getenv(cfg.Authority.DSNEnv)
		if dsn == "" {
			return nil, fmt.Errorf("gripline: authority DSN environment variable %q is empty", cfg.Authority.DSNEnv)
		}
		connectCtx, connectCancel := context.WithTimeout(context.Background(), connectTimeout)
		s, err := statepg.Open(connectCtx, statepg.Options{
			DSN: dsn, MaxConns: cfg.Authority.MaxConns, MinConns: cfg.Authority.MinConns,
			NodeID: cfg.Authority.NodeID, LeaseTTL: cfg.Authority.LeaseTTL.D(), RenewEvery: cfg.Authority.RenewEvery.D(), MaxSourceScopes: cfg.Server.MaxSourceScopes,
			ConnectTimeout: connectTimeout,
		})
		connectCancel()
		if err != nil {
			return nil, fmt.Errorf("gripline: postgres authority: %w", err)
		}
		postgres = s
		stateHealth = s
		closers = append(closers, func() error { s.Close(); return nil })
		reg = s
		lanes = s
		evStore = s
		adminState = s
		authorities = authority.Bundle{
			Credentials: s, Lanes: s, Evidence: s, AdaptiveRows: s, Health: s, Membership: s,
			Posture: s, Mutations: s, AuditSink: s, Audit: s, SecurityLog: s,
		}
	case "", "standalone":
		if cfg.Paths.State != "" {
			if cfg.Paths.Evidence != "" {
				return nil, fmt.Errorf("gripline: paths.evidence must be empty when paths.state is configured: the Bolt state database is the single evidence authority (P0.2)")
			}
			s, err := statebolt.Open(cfg.Paths.State, statebolt.Options{})
			if err != nil {
				return nil, fmt.Errorf("gripline: state db: %w", err)
			}
			state = s
			stateHealth = s
			closers = append(closers, func() error { return s.Close() })
			// Sweep expired evidence that no longer has a live traffic subject. The
			// stop function is appended after the DB close function so close order
			// joins the worker before releasing the database (P1-14).
			closers = append(closers, startStateMaintenance(s))
			reg = s
			lanes = s   // durable lane.Repository (P0.10)
			evStore = s // durable evidence.Store (P0.2-fix)
			adminState = s
			adaptiveState = s
			authorities = authority.Bundle{
				Credentials: s, Lanes: s, Evidence: s, Adaptive: s, Health: s,
				Posture: s, Mutations: s, AuditSink: s, Audit: s, SecurityLog: s,
			}
		} else {
			reg = credential.NewMemoryRegistry()
			lanes = lane.NewStore(nil, time.Now)
			evStore = evidence.NewMemoryStore()
			authorities = authority.Bundle{Credentials: reg, Lanes: lanes, Evidence: evStore}
		}
	default:
		return nil, fmt.Errorf("gripline: unsupported authority backend %q", cfg.Authority.Backend)
	}
	if cfg.Deployment.AllowEphemeralState {
		if err := bootstrapCredentials(reg); err != nil {
			return nil, err
		}
	} else if os.Getenv("GRIPLINE_BOOTSTRAP_CREDENTIAL") != "" {
		return nil, fmt.Errorf("gripline: GRIPLINE_BOOTSTRAP_CREDENTIAL is permitted only with deployment.allow_ephemeral_state=true; provision credentials before starting the persistent deployment")
	}

	var signer *terminator.Keyring
	if postgres != nil {
		// A clustered node must use the pre-provisioned signer identity. Creating
		// a keyring locally would mint a node-specific authority and make the
		// cluster's assertion identity split-brain.
		signer, err = terminator.LoadExistingKeyring(cfg.Paths.SignerKeyring)
	} else {
		signer, err = terminator.LoadOrCreateKeyring(cfg.Paths.SignerKeyring)
	}
	if err != nil {
		return nil, fmt.Errorf("gripline: signer: %w", err)
	}

	// P0.1 fix: Instantiate exactly one hard-resource authority. Standalone
	// mode uses the resident governor; clustered mode uses PostgreSQL-backed
	// leases with the same resource scope ordering and lifecycle contract.
	localGovernor := resource.NewGovernor(nil)
	// A configured idle horizon must not turn a zero max into an unlimited
	// attacker-controlled source table. The governor normalizes zero to its
	// conservative default; calling it for either knob keeps the runtime config
	// semantics explicit (P1-11).
	if cfg.Server.MaxSourceScopes != 0 || cfg.Server.SourceScopeIdle.D() > 0 {
		localGovernor.SetSourceScopeLimits(cfg.Server.MaxSourceScopes, cfg.Server.SourceScopeIdle.D())
	}
	var governor resource.ResourceAuthority = localGovernor
	if postgres != nil {
		governor = postgres
	}
	var spray *anomaly.Detector
	if postgres != nil {
		spray = anomaly.NewDistributedDetector(time.Now, anomaly.DefaultThresholds(), postgres)
		adaptiveHealth = append(adaptiveHealth, spray)
	} else if adaptiveState != nil {
		spray, err = anomaly.NewPersistentDetector(time.Now, anomaly.DefaultThresholds(), adaptiveState, "spray")
		if err != nil {
			return nil, fmt.Errorf("gripline: spray state: %w", err)
		}
		adaptiveHealth = append(adaptiveHealth, spray)
		closers = append(closers, spray.Close)
	} else {
		spray = anomaly.NewDetector(time.Now, anomaly.DefaultThresholds())
	}
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
	if postgres != nil {
		ctrl.SetPostureReader(postgres.LoadPostureContext)
		ctrl.SetAdmissionRecorder(postgres.AppendAdmission)
	}
	var postureAuthority control.PostureAuthority = ctrl
	if state != nil {
		postureAuthority = state
	} else if postgres != nil {
		postureAuthority = postgres
	}
	authorities.Credentials = reg
	authorities.Lanes = lanes
	authorities.Evidence = evStore
	authorities.Resource = governor
	authorities.Posture = postureAuthority
	if postgres != nil {
		authorities.Adaptive = nil
		authorities.AdaptiveRows = postgres
	} else {
		authorities.Adaptive = adaptiveState
	}
	authorities.Health = stateHealth
	if state != nil {
		authorities.Mutations, authorities.AuditSink, authorities.Audit, authorities.SecurityLog = state, state, state, state
	} else if postgres != nil {
		authorities.Mutations, authorities.AuditSink, authorities.Audit, authorities.SecurityLog = postgres, postgres, postgres, postgres
	}

	pol, err := policyFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("gripline: policy: %w", err)
	}
	var policyVerifier ed25519.PublicKey
	if cfg.Policy.VerifierKeyFile != "" {
		policyVerifier, err = policy.LoadVerifierKeyFile(cfg.Policy.VerifierKeyFile)
		if err != nil {
			return nil, fmt.Errorf("gripline: policy verifier: %w", err)
		}
	}
	policyOptions := policy.Options{}
	if state != nil {
		policyOptions = policy.Options{
			Persist:           state.PersistPolicyManifest,
			PersistArtifact:   state.PersistPolicyArtifact,
			PersistTransition: state.PersistPolicyTransition,
			LoadManifest:      state.LoadPolicyManifest,
			LoadArtifact:      state.LoadPolicyArtifact,
		}
	} else if postgres != nil {
		policyOptions = policy.Options{
			PersistContext:           postgres.PersistPolicyManifestContext,
			InitializeContext:        postgres.InitializePolicyManifestContext,
			PersistArtifactContext:   postgres.PersistPolicyArtifactContext,
			PersistTransitionContext: postgres.PersistPolicyTransitionContext,
			LoadManifestContext:      postgres.LoadPolicyManifestContext,
			LoadArtifactContext:      postgres.LoadPolicyArtifactContext,
		}
	}
	policyCtx, policyCancel := context.WithTimeout(context.Background(), operationTimeout)
	policyManager, err := policy.NewManagerContext(policyCtx, pol, policyOptions)
	policyCancel()
	if err != nil {
		return nil, fmt.Errorf("gripline: policy manager: %w", err)
	}
	compiledPolicy := policyManager.Current()
	if compiledPolicy == nil {
		return nil, fmt.Errorf("gripline: policy manager published no active policy")
	}
	pol = &compiledPolicy.Policy
	if postgres != nil {
		stopPolicyWatcher := policyManager.StartWatcher(context.Background(), time.Second, operationTimeout)
		closers = append(closers, func() error { stopPolicyWatcher(); return nil })
	}

	producerList := []producers.Producer{
		producers.NewSourceNoveltyProducer(time.Now),
		producers.NewResourceVelocityProducer(time.Now),
		producers.NewEnumerationProducer(time.Now),
	}
	if postgres != nil {
		producerList = []producers.Producer{
			producers.NewDistributedSourceNoveltyProducer(time.Now, postgres),
			producers.NewDistributedResourceVelocityProducer(time.Now, postgres),
			producers.NewDistributedEnumerationProducer(time.Now, postgres),
		}
		for _, producer := range producerList {
			if health, ok := producer.(terminator.AdaptivePersistenceHealth); ok {
				adaptiveHealth = append(adaptiveHealth, health)
			}
		}
	} else if adaptiveState != nil {
		names := []string{"source_novelty", "resource_velocity", "enumeration"}
		for i, name := range names {
			snapshot, ok := producerList[i].(producers.StateSnapshotter)
			if !ok {
				return nil, fmt.Errorf("gripline: producer %s does not support persistence", name)
			}
			persistent, perr := producers.NewPersistentProducer(producerList[i], snapshot, adaptiveState, name)
			if perr != nil {
				return nil, fmt.Errorf("gripline: producer state %s: %w", name, perr)
			}
			producerList[i] = persistent
			adaptiveHealth = append(adaptiveHealth, persistent)
			closers = append(closers, persistent.Close)
		}
	}

	// Build ingress pseudonyms before the terminator so a clustered node can
	// select the shared active generation before any request is admitted.
	var srcResolver *proxy.IngressSourceResolver
	var pseudonyms ingress.PseudonymRing
	if cfg.Ingress != nil && (cfg.Ingress.PseudonymKey != "" || len(cfg.Ingress.PseudonymKeys) > 0) {
		pseudonyms, err = pseudonymRingFromConfig(cfg, peppers)
		if err != nil {
			return nil, err
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
		if len(cfg.Ingress.Networks) > 0 {
			networks := make(publicingress.StaticNetworks, 0, len(cfg.Ingress.Networks))
			for _, network := range cfg.Ingress.Networks {
				prefix, err := netip.ParsePrefix(network.CIDR)
				if err != nil {
					return nil, fmt.Errorf("gripline: ingress network %q: %w", network.CIDR, err)
				}
				networks = append(networks, publicingress.NetworkMapping{
					Prefix: prefix, ASN: network.ASN, NetworkType: network.NetworkType, Region: network.Region,
				})
			}
			resolver.Networks = networks
		}
		srcResolver = proxy.NewIngressSourceResolver(resolver)
	}
	if postgres != nil {
		pseudonymVersion := 0
		pseudonymFingerprint := "disabled"
		if configured, ok := pseudonyms.(*pseudonymRingAdapter); ok {
			pseudonymVersion = configured.ActiveVersion()
			pseudonymFingerprint = configured.Fingerprint()
		}
		sharedCrypto, err := postgres.SynchronizeCrypto(context.Background(), statepg.CryptoIdentity{
			SignerActiveKID:      signer.ActiveKid(),
			SignerFingerprint:    signer.PublicKeysetFingerprint(),
			PepperActiveVersion:  peppers.ActiveVersion(),
			PepperFingerprint:    peppers.Fingerprint(),
			PseudonymVersion:     pseudonymVersion,
			PseudonymFingerprint: pseudonymFingerprint,
		})
		if err != nil {
			return nil, fmt.Errorf("gripline: cluster crypto identity: %w", err)
		}
		if err := peppers.SetActiveVersion(sharedCrypto.PepperActiveVersion); err != nil {
			return nil, fmt.Errorf("gripline: cluster pepper generation: %w", err)
		}
		if configured, ok := pseudonyms.(*pseudonymRingAdapter); ok {
			if err := configured.SetActiveVersion(sharedCrypto.PseudonymVersion); err != nil {
				return nil, fmt.Errorf("gripline: cluster pseudonym generation: %w", err)
			}
		}
	}

	term, err := terminator.New(terminator.Dependencies{
		Registry:       authorities.Credentials,
		Peppers:        peppers,
		Lanes:          authorities.Lanes, // Shared lane authority
		Policy:         pol,
		Signer:         signer,
		Audience:       cfg.Identity.Audience,
		Evidence:       authorities.Evidence,
		Mode:           terminator.ModeEnforce,
		Resource:       authorities.Resource, // Shared resource authority
		Control:        ctrl,                 // Shared control plane
		Posture:        authorities.Posture,
		Spray:          spray, // Shared spray detector
		Producers:      producerList,
		AdaptiveHealth: adaptiveHealth,
		Policies:       policyManager,
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
		ReservationRenewEvery:  cfg.Authority.RenewEvery.D(),
	}
	if cfg.Usage.Mode == "openai" || cfg.Usage.Mode == "anthropic" {
		format := publicusage.FormatOpenAI
		if cfg.Usage.Mode == "anthropic" {
			format = publicusage.FormatAnthropic
		}
		provider, err := publicusage.NewJSONProvider(format, publicusage.Pricing{
			InputMicrounitsPerToken:  cfg.Usage.InputMicrounitsPerToken,
			OutputMicrounitsPerToken: cfg.Usage.OutputMicrounitsPerToken,
		}, cfg.Usage.DefaultOutputTokens)
		if err != nil {
			return nil, fmt.Errorf("gripline: usage adapter: %w", err)
		}
		provider.MaxOutputTokens = cfg.Usage.MaxOutputTokens
		proxyCfg.Usage = proxy.AdaptUsageProvider(provider)
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
		audit := authorities.AuditSink
		if audit == nil {
			fileAudit, err := control.NewFileAuditRepository(cfg.Paths.AuditLog)
			if err != nil {
				return nil, err
			}
			audit = fileAudit
			authorities.AuditSink = audit
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
		if authorities.Mutations != nil {
			opts = append(opts, control.WithMutationStore(authorities.Mutations))
			if postgres != nil {
				// Every clustered control mutation must carry a durable replay key;
				// otherwise an ambiguous PostgreSQL commit cannot be retried safely.
				opts = append(opts, control.WithRequiredOperationIDs())
			}
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
		mux.HandleFunc("/admin/credentials", adminCredentials(svc, adminState))
		mux.HandleFunc("/admin/credentials/add", adminCredentialAdd(svc, adminState, peppers))
		mux.HandleFunc("/admin/credentials/pepper-status", adminCredentialPepperStatus(svc, adminState))
		mux.HandleFunc("/admin/credentials/revoke", adminCredentialRevoke(svc))
		mux.HandleFunc("/admin/lanes", adminLanes(svc, adminState))
		mux.HandleFunc("/admin/lanes/unblock", adminLaneUnblock(svc))
		mux.HandleFunc("/admin/audit", adminAudit(svc, adminState))
		mux.HandleFunc("/admin/security-events", adminSecurityEvents(svc, adminState))
		mux.HandleFunc("/admin/policy", adminPolicyStatus(svc, policyManager))
		mux.HandleFunc("/admin/policy/prepare", adminPolicyPrepare(svc, policyManager, policyVerifier))
		mux.HandleFunc("/admin/policy/activate", adminPolicyActivate(svc, policyManager))
		mux.HandleFunc("/admin/policy/rollback", adminPolicyRollback(svc, policyManager))
		mux.HandleFunc("/admin/metrics", adminMetrics(svc, dp, governor, state, spray, decisionObserver, policyManager, signer, adaptiveHealth))
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
		Registry:       authorities.Credentials,
		Lanes:          authorities.Lanes, // Shared lane authority
		AdminService:   adminSvc,
		Evidence:       authorities.Evidence,
		Resource:       authorities.Resource, // Shared resource authority
		Control:        ctrl,                 // Shared control plane
		Posture:        authorities.Posture,
		Spray:          spray, // Shared spray detector
		Signer:         signer,
		Policy:         pol,
		PolicyManager:  policyManager,
		StateHealth:    stateHealth,
		PolicyHealth:   policyManager,
		Authorities:    authorities,
		State:          state,
		Postgres:       postgres,
		Audience:       cfg.Identity.Audience,
		DataPlane:      dp,
		Admin:          adminSrv,
		adaptiveHealth: adaptiveHealth,
		closers:        closers,
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

type adminPolicySnapshot struct {
	ID              string `json:"id"`
	Revision        int    `json:"revision"`
	Digest          string `json:"digest"`
	ActivationEpoch uint64 `json:"activation_epoch,omitempty"`
}

func adminPolicySnapshotOf(compiled *policy.CompiledPolicy) *adminPolicySnapshot {
	return adminPolicySnapshotOfWithEpoch(compiled, 0)
}

func adminPolicySnapshotOfWithEpoch(compiled *policy.CompiledPolicy, epoch uint64) *adminPolicySnapshot {
	if compiled == nil {
		return nil
	}
	digest, err := policy.Digest(&compiled.Policy)
	if err != nil {
		return nil
	}
	return &adminPolicySnapshot{ID: compiled.ID, Revision: compiled.Revision, Digest: digest, ActivationEpoch: epoch}
}

// adminPolicyStatus exposes only immutable policy identity metadata. The
// artifact itself is not echoed back through the control plane.
func adminPolicyStatus(svc *control.Service, manager *policy.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapPolicyInstall); err != nil {
			writeAdminError(w, err)
			return
		}
		if err := manager.Reconcile(r.Context()); err != nil {
			writePolicyAdminError(w, err)
			return
		}
		active := manager.Snapshot()
		var activeView *adminPolicySnapshot
		if active != nil {
			activeView = adminPolicySnapshotOfWithEpoch(active.Policy, active.ActivationEpoch)
		}
		writeAdminJSON(w, map[string]any{
			"active":    activeView,
			"candidate": adminPolicySnapshotOf(manager.Candidate()),
		})
	}
}

func adminPolicyPrepare(svc *control.Service, manager *policy.Manager, verifier ed25519.PublicKey) http.HandlerFunc {
	type request struct {
		Artifact json.RawMessage `json:"artifact"`
		Reason   string          `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		id, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapPolicyInstall)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		var body request
		if err := decodeAdminJSONLimit(w, r, &body, 4<<20); err != nil {
			return
		}
		if strings.TrimSpace(body.Reason) == "" {
			writeAdminError(w, control.ErrReasonRequired)
			return
		}
		if len(verifier) != ed25519.PublicKeySize {
			http.Error(w, "policy verifier unavailable", http.StatusServiceUnavailable)
			return
		}
		compiled, err := policy.LoadAuthenticated(body.Artifact, verifier)
		if err != nil {
			writePolicyAdminError(w, err)
			return
		}
		prepared, err := manager.PrepareByContext(r.Context(), &compiled.Policy, id.Name, body.Reason)
		if err != nil {
			writePolicyAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]any{"prepared": adminPolicySnapshotOf(prepared)})
	}
}

func adminPolicyActivate(svc *control.Service, manager *policy.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		id, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapPolicyInstall)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decodeAdminJSON(w, r, &body); err != nil {
			return
		}
		if strings.TrimSpace(body.Reason) == "" {
			writeAdminError(w, control.ErrReasonRequired)
			return
		}
		if err := manager.ActivateByContext(r.Context(), body.Reason, id.Name); err != nil {
			writePolicyAdminError(w, err)
			return
		}
		active := manager.Snapshot()
		if active == nil {
			writeAdminJSON(w, map[string]any{"active": nil})
			return
		}
		writeAdminJSON(w, map[string]any{"active": adminPolicySnapshotOfWithEpoch(active.Policy, active.ActivationEpoch)})
	}
}

func adminPolicyRollback(svc *control.Service, manager *policy.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			adminMethodNotAllowed(w)
			return
		}
		id, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapPolicyInstall)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		var body struct {
			Revision int    `json:"revision"`
			Reason   string `json:"reason"`
		}
		if err := decodeAdminJSON(w, r, &body); err != nil {
			return
		}
		if body.Revision < 1 || strings.TrimSpace(body.Reason) == "" {
			writePolicyAdminError(w, errors.New("policy rollback requires a positive revision and reason"))
			return
		}
		if err := manager.RollbackByContext(r.Context(), body.Revision, body.Reason, id.Name); err != nil {
			writePolicyAdminError(w, err)
			return
		}
		active := manager.Snapshot()
		if active == nil {
			writeAdminJSON(w, map[string]any{"active": nil})
			return
		}
		writeAdminJSON(w, map[string]any{"active": adminPolicySnapshotOfWithEpoch(active.Policy, active.ActivationEpoch)})
	}
}

func writePolicyAdminError(w http.ResponseWriter, err error) {
	if errors.Is(err, control.ErrUnauthenticated) || errors.Is(err, control.ErrUnauthorized) || errors.Is(err, control.ErrReasonRequired) {
		writeAdminError(w, err)
		return
	}
	http.Error(w, "policy action rejected", http.StatusBadRequest)
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
		posture, err := svc.SetEmergencyWithOperationID(r.Context(), token, b.On, b.Reason, adminOperationID(r))
		if err != nil {
			writeAdminError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"posture": posture.String()})
	}
}

func adminCredentials(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
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
		if err := svc.RevokeCredentialWithOperationID(r.Context(), bearer(r.Header.Get("Authorization")), req.CredentialID, req.Reason, adminOperationID(r)); err != nil {
			writeAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]string{"credential_id": req.CredentialID, "status": "REVOKED"})
	}
}

func adminCredentialAdd(svc *control.Service, state adminStateAuthority, peppers *credential.PepperRing) http.HandlerFunc {
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
			if peppers == nil {
				http.Error(w, "verifier pepper authority unavailable", http.StatusServiceUnavailable)
				return
			}
			req.PepperVersion = peppers.Latest()
		}
		if peppers != nil {
			configured := false
			for _, version := range peppers.Versions() {
				if version == req.PepperVersion {
					configured = true
					break
				}
			}
			if !configured {
				http.Error(w, "pepper_version is not configured", http.StatusBadRequest)
				return
			}
		}
		rec := credential.CredentialRecord{
			CredentialID: req.CredentialID, AccountID: req.AccountID, Verifier: verifier,
			VerifierVersion: req.VerifierVersion, PepperVersion: req.PepperVersion,
			Status: credential.StatusNormal, PolicyID: req.PolicyID, PlanID: req.PlanID,
			CreatedAt: time.Now().UTC(), Revision: 1,
		}
		if err := svc.ProvisionCredentialWithOperationID(r.Context(), bearer(r.Header.Get("Authorization")), rec, req.Reason, adminOperationID(r)); err != nil {
			writeAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]string{"credential_id": req.CredentialID, "status": "ACTIVE"})
	}
}

func adminCredentialPepperStatus(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
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
		counts, err := state.CountCredentialsByPepperVersion()
		if err != nil {
			http.Error(w, "credential authority unavailable", http.StatusServiceUnavailable)
			return
		}
		writeAdminJSON(w, counts)
	}
}

func adminLanes(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
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
		if err := svc.UnblockLaneWithOperationID(r.Context(), bearer(r.Header.Get("Authorization")), req.CredentialID, req.LaneID, req.Reason, adminOperationID(r)); err != nil {
			writeAdminError(w, err)
			return
		}
		writeAdminJSON(w, map[string]string{"credential_id": req.CredentialID, "lane_id": req.LaneID, "status": "NORMAL"})
	}
}

func adminAudit(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
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

func adminSecurityEvents(svc *control.Service, state adminStateAuthority) http.HandlerFunc {
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

func adminMetrics(svc *control.Service, dp *proxy.DataPlane, governor resource.Authority, state *statebolt.Store, spray *anomaly.Detector, observer *jsonlObserver, policyManager *policy.Manager, signer *terminator.Keyring, adaptiveHealth []terminator.AdaptivePersistenceHealth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapAuditRead); err != nil {
			writeAdminError(w, err)
			return
		}
		var b strings.Builder
		writeMetric := func(name string, value any) { fmt.Fprintf(&b, "gripline_%s %v\n", name, value) }
		if dp != nil {
			m := dp.Metrics()
			writeMetric("admissions_total", m.Admissions)
			writeMetric("authorizations_total", m.Authorizations)
			writeMetric("denials_total", m.Denials)
			writeMetric("authentication_failures_total", m.AuthenticationFail)
			writeMetric("degraded_decisions_total", m.Degraded)
			writeMetric("resource_denials_total", m.ResourceDenials)
			writeMetric("policy_denials_total", m.PolicyDenials)
			writeMetric("payload_too_large_total", m.PayloadTooLarge)
			writeMetric("spool_rejects_total", m.SpoolRejects)
			writeMetric("completion_failures_total", m.CompletionFailures)
			writeMetric("backend_failures_total", m.BackendFailures)
			writeMetric("backend_4xx_total", m.Backend4xx)
			writeMetric("backend_5xx_total", m.Backend5xx)
			writeMetric("active_streams", m.ActiveStreams)
			writeMetric("evidence_events_total", m.EvidenceEvents)
			for i, count := range m.ResourceDenialsByScope {
				writeMetric("resource_denials_scope_"+strings.ToLower(resource.Scope(i).String())+"_total", count)
			}
			for i, count := range m.ResourceDenialsByDimension {
				writeMetric("resource_denials_dimension_"+resource.Dimension(i).String()+"_total", count)
			}
			writeMetric("spool_bytes", m.Spool.Bytes)
			writeMetric("spool_files", m.Spool.Files)
			writeMetric("spool_max_bytes", m.Spool.MaxBytes)
			writeMetric("spool_max_files", m.Spool.MaxFiles)
		}
		if stats, ok := governor.(interface{ Stats() resource.GovernorStats }); ok {
			m := stats.Stats()
			writeMetric("source_scopes", m.SourceScopes)
			writeMetric("source_scope_saturations_total", m.SourceSaturations)
			writeMetric("source_scope_overflows_total", m.SourceOverflows)
			writeMetric("source_scope_evictions_total", m.SourceEvictions)
		}
		if policyManager != nil {
			if current := policyManager.Current(); current != nil {
				writeMetric("active_policy_revision", current.Revision)
			}
		}
		if signer != nil {
			writeMetric("active_signer_kid", signer.ActiveKid())
		}
		if state != nil {
			m := state.EvidenceSweepStats()
			writeMetric("evidence_sweep_scanned_total", m.Scanned)
			writeMetric("evidence_sweep_deleted_total", m.Deleted)
			tx := state.TransactionStats()
			writeMetric("bbolt_transactions_total", tx.Transactions)
			writeMetric("bbolt_transaction_errors_total", tx.TransactionErrors)
			writeMetric("bbolt_transaction_nanos_total", tx.TransactionNanos)
		}
		if spray != nil {
			writeMetric("detector_drops_total", spray.Stats().Dropped)
		}
		adaptiveHealthy := 1
		for _, health := range adaptiveHealth {
			if health != nil && health.PersistenceError() != nil {
				adaptiveHealthy = 0
				break
			}
		}
		writeMetric("adaptive_persistence_healthy", adaptiveHealthy)
		if observer != nil {
			m := observer.Stats()
			writeMetric("telemetry_drops_total", m.Dropped)
			writeMetric("telemetry_sink_failures_total", m.SinkFailures)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
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
	return decodeAdminJSONLimit(w, r, dst, 4096)
}

func decodeAdminJSONLimit(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
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
	case errors.Is(err, control.ErrOperationIDRequired), errors.Is(err, control.ErrOperationIDInvalid):
		http.Error(w, "valid Idempotency-Key required", http.StatusBadRequest)
	case errors.Is(err, control.ErrOperationConflict):
		http.Error(w, "Idempotency-Key was already used for another operation", http.StatusConflict)
	case errors.Is(err, control.ErrOperationIDUnsupported):
		http.Error(w, "idempotency authority unavailable", http.StatusServiceUnavailable)
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

// adminOperationID returns the client-owned replay key for a mutating admin
// request. PostgreSQL-backed services require this header before making a
// state change; standalone services keep legacy behavior when it is absent.
func adminOperationID(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("Idempotency-Key"))
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

func pseudonymRingFromConfig(cfg *config.Config, peppers *credential.PepperRing) (ingress.PseudonymRing, error) {
	if cfg == nil || cfg.Ingress == nil {
		return nil, fmt.Errorf("gripline: ingress pseudonym configuration missing")
	}
	values := make(map[int]string, len(cfg.Ingress.PseudonymKeys)+1)
	if cfg.Ingress.PseudonymKey != "" {
		values[1] = cfg.Ingress.PseudonymKey
	}
	for rawVersion, encoded := range cfg.Ingress.PseudonymKeys {
		version, err := strconv.Atoi(rawVersion)
		if err != nil || version < 1 {
			return nil, fmt.Errorf("gripline: ingress pseudonym key version %q must be a positive decimal", rawVersion)
		}
		if _, exists := values[version]; exists {
			return nil, fmt.Errorf("gripline: duplicate ingress pseudonym key version %d", version)
		}
		values[version] = encoded
	}
	versions := make([]int, 0, len(values))
	for version := range values {
		versions = append(versions, version)
	}
	sort.Ints(versions)
	keys := make([]*pseudonym.Key, 0, len(versions))
	for _, version := range versions {
		key, err := decodeSecretKey(fmt.Sprintf("ingress pseudonym key version %d", version), values[version], 32)
		if err != nil {
			for _, prior := range keys {
				zeroBytes(prior.Secret)
			}
			return nil, err
		}
		for _, pepperVersion := range peppers.Versions() {
			if peppers.Matches(pepperVersion, key) {
				zeroBytes(key)
				for _, prior := range keys {
					zeroBytes(prior.Secret)
				}
				return nil, fmt.Errorf("gripline: key separation: ingress pseudonym key version %d must differ from verifier pepper version %d", version, pepperVersion)
			}
		}
		keys = append(keys, &pseudonym.Key{Version: version, Secret: key})
	}
	ring, err := pseudonym.NewRing(keys...)
	for _, key := range keys {
		zeroBytes(key.Secret)
	}
	if err != nil {
		return nil, fmt.Errorf("gripline: ingress pseudonym ring: %w", err)
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

func (a *pseudonymRingAdapter) SetActiveVersion(version int) error {
	if a == nil || a.ring == nil {
		return errors.New("gripline: pseudonym ring unavailable")
	}
	return a.ring.SetActiveVersion(version)
}

func (a *pseudonymRingAdapter) ActiveVersion() int {
	if a == nil || a.ring == nil {
		return 0
	}
	return a.ring.ActiveVersion()
}

func (a *pseudonymRingAdapter) Fingerprint() string {
	if a == nil || a.ring == nil {
		return ""
	}
	return a.ring.Fingerprint()
}
