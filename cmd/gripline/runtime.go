package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

	connectTimeout := cfg.Authority.ConnectTimeout.D()
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}
	operationTimeout := cfg.Authority.OperationTimeout.D()
	if operationTimeout <= 0 {
		operationTimeout = 2 * time.Second
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
	transport.MaxResponseHeaderBytes = int64(cfg.Backend.MaxResponseHeaderBytes)
	if backend.Scheme == "https" {
		tlsConfig, err := cfg.BackendTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("gripline: backend tls: %w", err)
		}
		transport.TLSClientConfig = tlsConfig
	}
	authoritySet, authorityClosers, err := openRuntimeAuthorities(cfg, connectTimeout, operationTimeout)
	if err != nil {
		return nil, err
	}
	closers = append(closers, authorityClosers...)
	reg := authoritySet.registry
	lanes := authoritySet.lanes
	evStore := authoritySet.evidence
	state := authoritySet.state
	postgres := authoritySet.postgres
	stateHealth := authoritySet.stateHealth
	authorities := authoritySet.authorities
	adminState := authoritySet.adminState
	adaptiveState := authoritySet.adaptiveState
	var verifierAcceptor preparedSignerAcceptor
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
	if postgres != nil {
		var controlTransport http.RoundTripper
		if strings.TrimSpace(cfg.Backend.VerifierControl.URL) != "" {
			controlTimeout := cfg.Backend.VerifierControl.Timeout.D()
			if controlTimeout <= 0 {
				controlTimeout = operationTimeout
			}
			controlTransport = &http.Transport{
				MaxIdleConnsPerHost:    2,
				IdleConnTimeout:        cfg.Server.IdleTimeout.D(),
				DisableCompression:     true,
				MaxResponseHeaderBytes: int64(cfg.Backend.MaxResponseHeaderBytes),
			}
			controlDialTimeout := controlTimeout
			controlTransport.(*http.Transport).DialContext = (&net.Dialer{Timeout: controlDialTimeout}).DialContext
			controlTransport.(*http.Transport).TLSHandshakeTimeout = controlTimeout
			controlTransport.(*http.Transport).ResponseHeaderTimeout = controlTimeout
			controlURL, parseErr := urlFrom(cfg.Backend.VerifierControl.URL)
			if parseErr != nil {
				return nil, fmt.Errorf("gripline: verifier control URL: %w", parseErr)
			}
			if controlURL.Scheme == "https" {
				tlsConfig, tlsErr := cfg.VerifierControlTLSConfig()
				if tlsErr != nil {
					return nil, fmt.Errorf("gripline: verifier control tls: %w", tlsErr)
				}
				controlTransport.(*http.Transport).TLSClientConfig = tlsConfig
			}
		}
		verifierAcceptor, err = newHTTPVerifierControl(cfg, controlTransport, operationTimeout)
		if err != nil {
			return nil, err
		}
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
		if configured, ok := pseudonyms.(*pseudonymRingAdapter); ok && postgres != nil {
			configured.sourceAliases = postgres
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
		localCrypto, err := localCryptoIdentity(signer, peppers, pseudonyms)
		if err != nil {
			return nil, err
		}
		sharedCrypto, syncErr := postgres.SynchronizeCrypto(context.Background(), localCrypto)
		if syncErr != nil {
			// A node restarted after a shared signer activation may still have the
			// prepared candidate active in its file, or may have the old active
			// signer with that candidate staged. Reconcile against the authority
			// before refusing startup; the signer callback still requires backend
			// canary acceptance and an exact prepared generation.
			if verifierAcceptor == nil {
				return nil, fmt.Errorf("gripline: cluster crypto identity: %w", syncErr)
			}
			authorityCrypto, loadErr := postgres.LoadCryptoIdentity(context.Background())
			if loadErr != nil {
				return nil, fmt.Errorf("gripline: cluster crypto identity: %w", syncErr)
			}
			if err := reconcileClusterCryptoWithSigner(context.Background(), authorityCrypto, postgres, signer, peppers, pseudonyms, cfg.Paths.SignerKeyring, verifierAcceptor); err != nil {
				return nil, fmt.Errorf("gripline: reconcile cluster crypto identity: %w", err)
			}
			sharedCrypto, err = postgres.LoadCryptoIdentity(context.Background())
			if err != nil {
				return nil, fmt.Errorf("gripline: load reconciled cluster crypto identity: %w", err)
			}
		} else {
			err = nil
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

	// Policy reconciliation acknowledges the active shared policy through the
	// authority. Cluster crypto must be synchronized first because the same
	// authority transaction intentionally refuses security-state mutations from
	// an unsynchronized node.
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
			PersistContext:                    postgres.PersistPolicyManifestContext,
			InitializeContext:                 postgres.InitializePolicyManifestContext,
			PersistArtifactContext:            postgres.PersistPolicyArtifactContext,
			PersistTransitionContext:          postgres.PersistPolicyTransitionContext,
			PersistTransitionOperationContext: postgres.PersistPolicyTransitionOperationContext,
			RequireOperationIDs:               true,
			LoadManifestContext:               postgres.LoadPolicyManifestContext,
			LoadArtifactContext:               postgres.LoadPolicyArtifactContext,
			AcknowledgeContext:                postgres.AcknowledgePolicyContext,
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
		WriteTimeout:                   cfg.Server.WriteTimeout.D(),
		StreamWriteIdleTimeout:         cfg.Server.StreamWriteIdleTimeout.D(),
		SpoolDir:                       cfg.Server.SpoolDir,
		SpoolMaxBytes:                  cfg.Server.SpoolMaxBytes,
		SpoolMaxFiles:                  cfg.Server.SpoolMaxFiles,
		ReservationRenewEvery:          cfg.Authority.RenewEvery.D(),
		PreAuthMaxConcurrent:           cfg.Server.PreAuthMaxConcurrent,
		PreAuthRequestsPerSecond:       cfg.Server.PreAuthRequestsPerSecond,
		PreAuthSourceRequestsPerSecond: cfg.Server.PreAuthSourceRequestsPerSecond,
		PreAuthMaxSources:              cfg.Server.PreAuthMaxSources,
		PreAuthSourceIdle:              cfg.Server.SourceScopeIdle.D(),
	}
	if cfg.Backend.AllowedEndpoints != nil {
		proxyCfg.EndpointRules = make([]proxy.EndpointRule, 0, len(cfg.Backend.AllowedEndpoints))
		for _, rule := range cfg.Backend.AllowedEndpoints {
			proxyCfg.EndpointRules = append(proxyCfg.EndpointRules, proxy.EndpointRule{
				Method: rule.Method, Path: rule.Path, RequiredScope: rule.RequiredScope,
			})
		}
	}
	if controlURL := strings.TrimSpace(cfg.Backend.VerifierControl.URL); controlURL != "" {
		if parsed, parseErr := urlFrom(controlURL); parseErr == nil {
			proxyCfg.ForbiddenPath = parsed.Path
		}
	}
	if cfg.Usage.Mode == "openai" || cfg.Usage.Mode == "anthropic" {
		format := publicusage.FormatOpenAI
		if cfg.Usage.Mode == "anthropic" {
			format = publicusage.FormatAnthropic
		}
		provider, err := publicusage.NewJSONProvider(format, publicusage.Pricing{
			InputMicrounitsPerToken:         cfg.Usage.InputMicrounitsPerToken,
			OutputMicrounitsPerToken:        cfg.Usage.OutputMicrounitsPerToken,
			CacheReadMicrounitsPerToken:     cfg.Usage.CacheReadMicrounitsPerToken,
			CacheCreationMicrounitsPerToken: cfg.Usage.CacheCreationMicrounitsPerToken,
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
		proxyCfg.PreAuthSource = srcResolver
	}
	dp, err := proxy.New(proxyCfg)
	if err != nil {
		return nil, fmt.Errorf("gripline: proxy: %w", err)
	}
	if postgres != nil {
		stopCryptoReconciler := postgres.StartCryptoReconciler(context.Background(), time.Second, operationTimeout, func(ctx context.Context, shared statepg.CryptoIdentity) error {
			return reconcileClusterCryptoWithSigner(ctx, shared, postgres, signer, peppers, pseudonyms, cfg.Paths.SignerKeyring, verifierAcceptor)
		})
		closers = append(closers, func() error { stopCryptoReconciler(); return nil })
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
		mux.HandleFunc("/admin/credentials/add", adminCredentialAdd(svc, adminState, peppers, policyManager, postgres))
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
		mux.HandleFunc("/admin/cluster", adminClusterStatus(svc, postgres))
		mux.HandleFunc("/admin/crypto", adminClusterStatus(svc, postgres))
		mux.HandleFunc("/admin/crypto/activate", adminCryptoActivate(svc, postgres, signer, peppers, pseudonyms, cfg.Paths.SignerKeyring, verifierAcceptor))
		mux.HandleFunc("/admin/crypto/retire", adminCryptoRetire(svc, postgres, signer, peppers, pseudonyms, cfg.Paths.SignerKeyring, verifierAcceptor))
		mux.HandleFunc("/admin/metrics", adminMetrics(svc, dp, governor, state, postgres, spray, decisionObserver, policyManager, signer, adaptiveHealth))
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
	mu            sync.RWMutex
	ring          *pseudonym.Ring
	sourceAliases sourcePseudonymAliasLookup
}

type sourcePseudonymAliasLookup interface {
	ResolveExistingSourcePseudonym(context.Context, []string) (string, error)
}

func (a *pseudonymRingAdapter) Derive(family []byte, raw []byte) (string, error) {
	return a.DeriveContext(context.Background(), family, raw)
}

func (a *pseudonymRingAdapter) DeriveContext(ctx context.Context, family []byte, raw []byte) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	a.mu.RLock()
	ring := a.ring
	aliases := a.sourceAliases
	var candidates []string
	var err error
	if string(family) == string(pseudonym.FamilySource) && ring != nil && aliases != nil {
		candidates, err = ring.DeriveAll(pseudonym.FamilySource, raw)
	}
	a.mu.RUnlock()
	if err != nil {
		return "", err
	}
	if len(candidates) > 0 {
		if stable, lookupErr := aliases.ResolveExistingSourcePseudonym(ctx, candidates); lookupErr != nil {
			return "", lookupErr
		} else if stable != "" {
			return stable, nil
		}
		return candidates[len(candidates)-1], nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.ring == nil {
		return "", errors.New("gripline: pseudonym ring unavailable")
	}
	return a.ring.Derive(pseudonym.Family(family), raw)
}

func (a *pseudonymRingAdapter) SetActiveVersion(version int) error {
	if a == nil {
		return errors.New("gripline: pseudonym ring unavailable")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ring == nil {
		return errors.New("gripline: pseudonym ring unavailable")
	}
	return a.ring.SetActiveVersion(version)
}

func (a *pseudonymRingAdapter) RetireVersion(version int) error {
	if a == nil {
		return errors.New("gripline: pseudonym ring unavailable")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ring == nil {
		return errors.New("gripline: pseudonym ring unavailable")
	}
	return a.ring.RetireVersion(version)
}

func (a *pseudonymRingAdapter) ActiveVersion() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.ring == nil {
		return 0
	}
	return a.ring.ActiveVersion()
}

func (a *pseudonymRingAdapter) Fingerprint() string {
	if a == nil {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.ring == nil {
		return ""
	}
	return a.ring.Fingerprint()
}

func (a *pseudonymRingAdapter) VersionFingerprint(version int) (string, bool) {
	if a == nil {
		return "", false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.ring == nil {
		return "", false
	}
	return a.ring.VersionFingerprint(version)
}

func (a *pseudonymRingAdapter) VersionFingerprints() map[int]string {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.ring == nil {
		return nil
	}
	return a.ring.VersionFingerprints()
}
