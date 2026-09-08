package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrOperationIDRequired is returned by a clustered policy manager when a
	// lifecycle mutation does not carry a client-owned replay key.
	ErrOperationIDRequired = errors.New("policy: idempotency key required")
	// ErrOperationIDUnsupported means the manager was configured to require
	// replay-safe mutations without an operation-aware durable hook.
	ErrOperationIDUnsupported = errors.New("policy: idempotency authority unavailable")
	// ErrOperationNotReplayable is returned by a durable transition hook when
	// an operation ID was not previously committed and the requested lifecycle
	// state is no longer applicable. It lets the manager preserve its normal
	// domain error without hiding authority failures.
	ErrOperationNotReplayable = errors.New("policy: operation is not replayable")
)

// Manager owns the policy lifecycle at the control-plane boundary. A policy
// becomes enforceable only after validation, preparation, and one atomic
// activation. The data plane receives immutable CompiledPolicy snapshots and
// never observes a partially loaded candidate.
type Manager struct {
	mu                                sync.Mutex
	current                           *CompiledPolicy
	candidate                         *CompiledPolicy
	knownGood                         map[int]*CompiledPolicy
	activationEpoch                   uint64
	persist                           func(Manifest) error
	persistContext                    func(context.Context, Manifest) error
	audit                             func(Event) error
	auditContext                      func(context.Context, Event) error
	persistArtifact                   func(*CompiledPolicy) error
	persistArtifactContext            func(context.Context, *CompiledPolicy) error
	persistTransition                 func(Manifest, Event) error
	persistTransitionContext          func(context.Context, Manifest, Event) error
	persistTransitionOperationContext func(context.Context, Manifest, Event, string) error
	requireOperationIDs               bool
	loadManifest                      func() (Manifest, error)
	loadManifestContext               func(context.Context) (Manifest, error)
	loadArtifact                      func(PolicyRef) (*CompiledPolicy, error)
	loadArtifactContext               func(context.Context, PolicyRef) (*CompiledPolicy, error)
	acknowledgeContext                func(context.Context, Manifest) error
	lastRevision                      int
	// published is the immutable data-plane view. A nil pointer means the
	// durable authority could not be reconciled and admissions must fail closed.
	published atomic.Pointer[Snapshot]
}

// Manifest is the durable lifecycle marker. Implementations should write it
// with a temp-file/fsync/rename sequence; Manager calls persist before changing
// its in-memory pointer, so a failed durable write cannot activate a policy.
type Manifest struct {
	SchemaVersion   int        `json:"schema_version"`
	ActivationEpoch uint64     `json:"activation_epoch"`
	Active          PolicyRef  `json:"active"`
	Candidate       *PolicyRef `json:"candidate,omitempty"`
	Previous        *PolicyRef `json:"previous,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type PolicyRef struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
	Digest   string `json:"digest"`
}

// Event is the operator-audit payload for prepare, activation, and rollback.
// Reason is required for rollback so an emergency change has an attributable
// explanation rather than an unexplained pointer swap.
type Event struct {
	Action       string    `json:"action"`
	Actor        string    `json:"actor,omitempty"`
	FromRevision int       `json:"from_revision"`
	ToRevision   int       `json:"to_revision"`
	FromEpoch    uint64    `json:"from_epoch,omitempty"`
	ToEpoch      uint64    `json:"to_epoch,omitempty"`
	PolicyID     string    `json:"policy_id"`
	Reason       string    `json:"reason,omitempty"`
	At           time.Time `json:"at"`
}

// Snapshot is the immutable policy view used by the data plane. The compiled
// policy pointer is never mutated by Manager after publication; callers that
// need a defensive copy should use Current instead. ActivationEpoch is
// monotonic even when the active artifact revision moves backwards during an
// explicit rollback.
type Snapshot struct {
	Policy          *CompiledPolicy
	ActivationEpoch uint64
}

// Options supplies durable manifest and audit hooks. Both are optional for
// tests and explicitly ephemeral deployments.
type Options struct {
	Persist        func(Manifest) error
	PersistContext func(context.Context, Manifest) error
	Audit          func(Event) error
	AuditContext   func(context.Context, Event) error
	// PersistArtifact stores the exact compiled candidate before its manifest
	// can reference it. This is what makes last-known-good rollback possible
	// after a process restart rather than only while pointers remain in memory.
	PersistArtifact        func(*CompiledPolicy) error
	PersistArtifactContext func(context.Context, *CompiledPolicy) error
	// PersistTransition is the preferred durable hook: implementations can
	// commit the manifest and transition journal as one crash-visible record.
	// Persist/Audit remain supported for small integrations and tests.
	PersistTransition        func(Manifest, Event) error
	PersistTransitionContext func(context.Context, Manifest, Event) error
	// PersistTransitionOperationContext is the clustered variant. The
	// implementation must claim operationID in the same transaction as the
	// manifest and audit event, returning success for an exact replay.
	PersistTransitionOperationContext func(context.Context, Manifest, Event, string) error
	// RequireOperationIDs makes every lifecycle mutation replay-safe. It is
	// enabled by the PostgreSQL runtime and intentionally off for standalone
	// compatibility callers.
	RequireOperationIDs bool
	// Initialize is a create-only durable hook for the first clustered boot.
	// It must never replace an existing manifest. NewManager rereads the
	// manifest after this hook and rejects a different active policy.
	Initialize          func(Manifest) error
	InitializeContext   func(context.Context, Manifest) error
	LoadManifest        func() (Manifest, error)
	LoadManifestContext func(context.Context) (Manifest, error)
	LoadArtifact        func(PolicyRef) (*CompiledPolicy, error)
	LoadArtifactContext func(context.Context, PolicyRef) (*CompiledPolicy, error)
	// AcknowledgeContext records that this node has loaded and validated the
	// active policy and any prepared candidate. Durable clustered authorities
	// use it as the activation barrier; in-process callers may leave it nil.
	AcknowledgeContext func(context.Context, Manifest) error
}

// NewManager validates the initial policy and starts with it as known-good.
func NewManager(initial *Policy, opts Options) (*Manager, error) {
	return NewManagerContext(context.Background(), initial, opts)
}

// NewManagerContext is the context-aware constructor for durable policy
// authorities. The legacy NewManager wrapper remains for in-process callers.
func NewManagerContext(ctx context.Context, initial *Policy, opts Options) (*Manager, error) {
	ctx = usableContext(ctx)
	compiled, err := Compile(initial)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		current:                           compiled,
		knownGood:                         map[int]*CompiledPolicy{compiled.Revision: compiled},
		persist:                           opts.Persist,
		persistContext:                    opts.PersistContext,
		audit:                             opts.Audit,
		auditContext:                      opts.AuditContext,
		persistArtifact:                   opts.PersistArtifact,
		persistArtifactContext:            opts.PersistArtifactContext,
		persistTransition:                 opts.PersistTransition,
		persistTransitionContext:          opts.PersistTransitionContext,
		persistTransitionOperationContext: opts.PersistTransitionOperationContext,
		requireOperationIDs:               opts.RequireOperationIDs,
		loadManifest:                      opts.LoadManifest,
		loadManifestContext:               opts.LoadManifestContext,
		loadArtifact:                      opts.LoadArtifact,
		loadArtifactContext:               opts.LoadArtifactContext,
		acknowledgeContext:                opts.AcknowledgeContext,
		lastRevision:                      compiled.Revision,
		activationEpoch:                   1,
	}
	if m.hasManifestLoader() {
		manifest, loadErr := m.loadManifestWithContext(ctx)
		if loadErr != nil {
			return nil, loadErr
		}
		if manifest.ActivationEpoch == 0 {
			// Epoch-less manifests predate cluster freshness. Treat the existing
			// active artifact as epoch 1; the next lifecycle mutation will
			// publish a monotonic epoch-bearing manifest.
			manifest.ActivationEpoch = 1
		}
		m.activationEpoch = manifest.ActivationEpoch
		if manifest.Active.Revision != 0 {
			activeDigest, digestErr := Digest(&compiled.Policy)
			if digestErr != nil {
				return nil, digestErr
			}
			if manifest.Active.ID != compiled.ID || manifest.Active.Revision != compiled.Revision || manifest.Active.Digest != activeDigest {
				// A committed activation is authoritative across restart. The
				// configured artifact is still parsed and validated above, but
				// an older deployment input must not silently roll the process
				// back to its previous revision. Recover the exact artifact that
				// the durable manifest names; its digest binds the bytes to the
				// committed lifecycle record.
				if !m.hasArtifactLoader() {
					return nil, errors.New("policy: configured policy differs from durable active manifest and no artifact loader is configured")
				}
				active, activeErr := m.loadArtifactWithContext(ctx, manifest.Active)
				if activeErr != nil {
					return nil, fmt.Errorf("policy: load durable active artifact: %w", activeErr)
				}
				loadedDigest, loadedErr := Digest(&active.Policy)
				if loadedErr != nil || active.ID != manifest.Active.ID || active.Revision != manifest.Active.Revision || loadedDigest != manifest.Active.Digest {
					return nil, errors.New("policy: durable active artifact does not match manifest")
				}
				m.current = active
				m.knownGood = map[int]*CompiledPolicy{active.Revision: active}
				m.lastRevision = active.Revision
			}
		} else {
			initialManifest, manifestErr := manifestFor(compiled, nil)
			if manifestErr != nil {
				return nil, manifestErr
			}
			if m.hasArtifactPersister() {
				if err := m.persistArtifactWithContext(ctx, compiled); err != nil {
					return nil, fmt.Errorf("policy: persist initial artifact: %w", err)
				}
			}
			if opts.InitializeContext != nil || opts.Initialize != nil {
				if err := m.initializeWithContext(ctx, initialManifest, opts); err != nil {
					return nil, fmt.Errorf("policy: initialize manifest: %w", err)
				}
			} else if m.hasManifestPersister() {
				if err := m.persistManifestWithContext(ctx, initialManifest); err != nil {
					return nil, fmt.Errorf("policy: persist initial manifest: %w", err)
				}
			}
			if opts.InitializeContext != nil || opts.Initialize != nil || m.hasManifestPersister() {
				// A create-only initializer may have lost a concurrent first
				// boot. Re-read the winner before constructing any lifecycle
				// state; never let startup policy input overwrite the shared
				// authority.
				manifest, loadErr = m.loadManifestWithContext(ctx)
				if loadErr != nil {
					return nil, loadErr
				}
				if manifest.Active.Revision == 0 {
					return nil, errors.New("policy: initial manifest was not committed")
				}
				if !samePolicyRef(manifest.Active, initialManifest.Active) {
					return nil, errors.New("policy: configured initial policy conflicts with durable active manifest")
				}
				if manifest.ActivationEpoch == 0 {
					manifest.ActivationEpoch = 1
				}
				m.activationEpoch = manifest.ActivationEpoch
			}
		}
		if manifest.Candidate != nil {
			if !m.hasArtifactLoader() {
				return nil, errors.New("policy: durable candidate exists but no artifact loader is configured")
			}
			candidate, candidateErr := m.loadArtifactWithContext(ctx, *manifest.Candidate)
			if candidateErr != nil {
				return nil, candidateErr
			}
			if candidate.Revision <= m.current.Revision {
				return nil, errors.New("policy: durable candidate revision is not newer than active policy")
			}
			candidateDigest, digestErr := Digest(&candidate.Policy)
			if digestErr != nil || candidateDigest != manifest.Candidate.Digest || candidate.ID != manifest.Candidate.ID {
				return nil, errors.New("policy: durable candidate digest mismatch")
			}
			m.candidate = candidate
			m.lastRevision = candidate.Revision
		}
		if manifest.Previous != nil && m.hasArtifactLoader() {
			previous, previousErr := m.loadArtifactWithContext(ctx, *manifest.Previous)
			if previousErr != nil {
				return nil, previousErr
			}
			m.knownGood[previous.Revision] = previous
		}
	}
	// A clustered node must publish its initial active/candidate observation
	// before the runtime can expose a hard resource admission path. This also
	// prevents the first request from being rejected merely because the watcher
	// has not completed its first tick.
	if m.acknowledgeContext != nil && m.hasManifestLoader() {
		if err := m.Reconcile(ctx); err != nil {
			return nil, fmt.Errorf("policy: acknowledge initial shared state: %w", err)
		}
	} else {
		m.publishLocked()
	}
	return m, nil
}

func samePolicyRef(a, b PolicyRef) bool {
	return a.ID == b.ID && a.Revision == b.Revision && a.Digest == b.Digest
}

func policyRefOf(compiled *CompiledPolicy) PolicyRef {
	if compiled == nil {
		return PolicyRef{}
	}
	digest, _ := Digest(&compiled.Policy)
	return PolicyRef{ID: compiled.ID, Revision: compiled.Revision, Digest: digest}
}

// Ready verifies that this process has a usable policy snapshot and, when a
// durable lifecycle store is configured, that the snapshot can be reconciled
// with the shared active manifest. It is intentionally separate from the data
// plane Snapshot method so callers can put a timeout around readiness probes.
func (m *Manager) Ready(ctx context.Context) error {
	if m == nil {
		return errors.New("policy: nil manager")
	}
	if err := m.Reconcile(ctx); err != nil {
		return err
	}
	if m.Snapshot() == nil {
		return errors.New("policy: active snapshot unavailable")
	}
	return nil
}

// Current returns the active immutable snapshot.
func (m *Manager) Current() *CompiledPolicy {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneCompiled(m.current)
}

// Snapshot returns the currently published immutable policy pointer and its
// cluster activation epoch. It never performs I/O or compilation; a bounded
// reconciler or an explicit control-plane/readiness call updates publication.
func (m *Manager) Snapshot() *Snapshot {
	if m == nil {
		return nil
	}
	return m.published.Load()
}

// PolicyEpoch returns the active policy activation epoch for downstream
// freshness verifiers. The boolean is false when the durable policy cannot be
// refreshed or no active policy is available.
func (m *Manager) PolicyEpoch() (uint64, bool) {
	snapshot := m.Snapshot()
	if snapshot == nil || snapshot.ActivationEpoch == 0 {
		return 0, false
	}
	return snapshot.ActivationEpoch, true
}

// Candidate returns the prepared but not yet active snapshot, if any.
func (m *Manager) Candidate() *CompiledPolicy {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneCompiled(m.candidate)
}

// Reconcile reads the shared lifecycle manifest and atomically publishes a
// coherent policy/epoch pair. A failed reconciliation clears publication so
// the data plane cannot continue serving with an unverified shared policy.
func (m *Manager) Reconcile(ctx context.Context) error {
	if m == nil {
		return errors.New("policy: nil manager")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshDurableLocked(ctx); err != nil {
		m.published.Store(nil)
		return err
	}
	m.publishLocked()
	return nil
}

// StartWatcher starts bounded periodic reconciliation for a durable manager.
// The returned stop function is idempotent and should be part of runtime
// shutdown. Notifications may be added later as an acceleration; polling is
// the correctness mechanism.
func (m *Manager) StartWatcher(parent context.Context, interval, operationTimeout time.Duration) func() {
	if m == nil || m.loadManifest == nil && m.loadManifestContext == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = time.Second
	}
	if operationTimeout <= 0 {
		operationTimeout = 2 * time.Second
	}
	parent = usableContext(parent)
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				opCtx, opCancel := context.WithTimeout(ctx, operationTimeout)
				_ = m.Reconcile(opCtx)
				opCancel()
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
}

// refreshDurableLocked reconciles this process with the shared lifecycle
// manifest. It runs before every policy snapshot so a node observes a
// committed activation or rollback without a restart. A read failure returns
// an error; Current then returns nil and the data plane fails closed instead of
// enforcing a potentially stale policy during an authority outage.
func (m *Manager) refreshDurableLocked(ctx context.Context) error {
	if !m.hasManifestLoader() {
		return nil
	}
	manifest, err := m.loadManifestWithContext(ctx)
	if err != nil {
		return err
	}
	if manifest.Active.Revision == 0 {
		return errors.New("policy: shared active manifest unavailable")
	}
	if manifest.ActivationEpoch == 0 {
		manifest.ActivationEpoch = 1
	}
	m.activationEpoch = manifest.ActivationEpoch
	if m.current == nil {
		return errors.New("policy: current policy is nil")
	}
	activeDigest, err := Digest(&m.current.Policy)
	if err != nil {
		return err
	}
	if m.current.ID != manifest.Active.ID || m.current.Revision != manifest.Active.Revision || activeDigest != manifest.Active.Digest {
		if !m.hasArtifactLoader() {
			return errors.New("policy: shared active policy differs and no artifact loader is configured")
		}
		active, err := m.loadArtifactWithContext(ctx, manifest.Active)
		if err != nil {
			return fmt.Errorf("policy: refresh active artifact: %w", err)
		}
		if err := validateCompiledRef(active, manifest.Active); err != nil {
			return err
		}
		m.current = active
		m.knownGood[active.Revision] = active
		if active.Revision > m.lastRevision {
			m.lastRevision = active.Revision
		}
	}
	if manifest.Candidate == nil {
		m.candidate = nil
	} else if m.candidate == nil || m.candidate.ID != manifest.Candidate.ID || m.candidate.Revision != manifest.Candidate.Revision {
		if !m.hasArtifactLoader() {
			return errors.New("policy: shared candidate exists and no artifact loader is configured")
		}
		candidate, err := m.loadArtifactWithContext(ctx, *manifest.Candidate)
		if err != nil {
			return fmt.Errorf("policy: refresh candidate artifact: %w", err)
		}
		if err := validateCompiledRef(candidate, *manifest.Candidate); err != nil {
			return err
		}
		if candidate.Revision <= m.current.Revision {
			return errors.New("policy: durable candidate revision is not newer than active policy")
		}
		m.candidate = candidate
		if candidate.Revision > m.lastRevision {
			m.lastRevision = candidate.Revision
		}
	}
	if manifest.Previous != nil {
		if _, ok := m.knownGood[manifest.Previous.Revision]; !ok {
			if !m.hasArtifactLoader() {
				return errors.New("policy: shared previous policy exists and no artifact loader is configured")
			}
			previous, err := m.loadArtifactWithContext(ctx, *manifest.Previous)
			if err != nil {
				return fmt.Errorf("policy: refresh previous artifact: %w", err)
			}
			if err := validateCompiledRef(previous, *manifest.Previous); err != nil {
				return err
			}
			m.knownGood[previous.Revision] = previous
		}
	}
	if m.acknowledgeContext != nil {
		if err := m.acknowledgeContext(usableContext(ctx), manifest); err != nil {
			return fmt.Errorf("policy: acknowledge shared state: %w", err)
		}
	}
	return nil
}

func usableContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (m *Manager) hasManifestLoader() bool {
	return m.loadManifestContext != nil || m.loadManifest != nil
}

func (m *Manager) hasManifestPersister() bool {
	return m.persistContext != nil || m.persist != nil
}

func (m *Manager) hasArtifactLoader() bool {
	return m.loadArtifactContext != nil || m.loadArtifact != nil
}

func (m *Manager) hasArtifactPersister() bool {
	return m.persistArtifactContext != nil || m.persistArtifact != nil
}

func (m *Manager) loadManifestWithContext(ctx context.Context) (Manifest, error) {
	if m.loadManifestContext != nil {
		return m.loadManifestContext(usableContext(ctx))
	}
	return m.loadManifest()
}

func (m *Manager) loadArtifactWithContext(ctx context.Context, ref PolicyRef) (*CompiledPolicy, error) {
	if m.loadArtifactContext != nil {
		return m.loadArtifactContext(usableContext(ctx), ref)
	}
	return m.loadArtifact(ref)
}

func (m *Manager) persistManifestWithContext(ctx context.Context, manifest Manifest) error {
	if m.persistContext != nil {
		return m.persistContext(usableContext(ctx), manifest)
	}
	return m.persist(manifest)
}

func (m *Manager) persistArtifactWithContext(ctx context.Context, compiled *CompiledPolicy) error {
	if m.persistArtifactContext != nil {
		return m.persistArtifactContext(usableContext(ctx), compiled)
	}
	return m.persistArtifact(compiled)
}

func (m *Manager) initializeWithContext(ctx context.Context, manifest Manifest, opts Options) error {
	if opts.InitializeContext != nil {
		return opts.InitializeContext(usableContext(ctx), manifest)
	}
	return opts.Initialize(manifest)
}

func (m *Manager) publishLocked() {
	if m.current == nil || m.activationEpoch == 0 {
		m.published.Store(nil)
		return
	}
	m.published.Store(&Snapshot{Policy: m.current, ActivationEpoch: m.activationEpoch})
}

func validateCompiledRef(compiled *CompiledPolicy, ref PolicyRef) error {
	if compiled == nil {
		return errors.New("policy: durable artifact is nil")
	}
	digest, err := Digest(&compiled.Policy)
	if err != nil || compiled.ID != ref.ID || compiled.Revision != ref.Revision || digest != ref.Digest {
		return errors.New("policy: durable artifact does not match manifest")
	}
	return nil
}

// cloneCompiled returns a newly compiled copy of a manager-owned snapshot.
// CompiledPolicy contains maps and slices, so returning the internal pointer
// would let callers mutate future enforcement through a supposedly immutable
// lifecycle API.
func cloneCompiled(compiled *CompiledPolicy) *CompiledPolicy {
	if compiled == nil {
		return nil
	}
	copy, err := Compile(&compiled.Policy)
	if err != nil {
		// Manager-owned policies were validated before insertion. Returning nil
		// here is safer than exposing a mutable or partially copied policy if a
		// future change violates that invariant.
		return nil
	}
	return copy
}

// Prepare validates and compiles a candidate. Revisions are strictly
// monotonic; replaying an old artifact cannot replace a newer candidate.
func (m *Manager) Prepare(p *Policy) (*CompiledPolicy, error) {
	return m.PrepareByContext(context.Background(), p, "", "")
}

// PrepareBy prepares a candidate and records the authenticated operator that
// requested it. The actor is part of the same durable transition event as the
// candidate manifest, so an accepted policy cannot be detached from its
// operator identity.
func (m *Manager) PrepareBy(p *Policy, actor, reason string) (*CompiledPolicy, error) {
	return m.PrepareByContext(context.Background(), p, actor, reason)
}

// PrepareContext is the request-scoped policy preparation operation.
func (m *Manager) PrepareContext(ctx context.Context, p *Policy) (*CompiledPolicy, error) {
	return m.PrepareByContext(ctx, p, "", "")
}

// PrepareByContext is the context-aware policy preparation operation.
func (m *Manager) PrepareByContext(ctx context.Context, p *Policy, actor, reason string) (*CompiledPolicy, error) {
	return m.PrepareByContextWithOperationID(ctx, p, actor, reason, "")
}

// PrepareByContextWithOperationID is the replay-safe clustered policy
// preparation operation. The operation ID is committed with the manifest
// transition by the configured durable authority.
func (m *Manager) PrepareByContextWithOperationID(ctx context.Context, p *Policy, actor, reason, operationID string) (*CompiledPolicy, error) {
	if m == nil {
		return nil, errors.New("policy: nil manager")
	}
	var err error
	operationID, err = m.normalizeOperationID(operationID)
	if err != nil {
		return nil, err
	}
	ctx = usableContext(ctx)
	compiled, err := Compile(p)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshDurableLocked(ctx); err != nil {
		return nil, err
	}
	if m.candidate != nil && samePolicyRef(policyRefOf(m.candidate), policyRefOf(compiled)) && operationID != "" && m.persistTransitionOperationContext != nil {
		manifest, err := m.manifestLocked(m.current, m.candidate)
		if err != nil {
			return nil, err
		}
		event := Event{Action: "prepare", Actor: actor, FromRevision: m.current.Revision, ToRevision: compiled.Revision, FromEpoch: m.activationEpoch, ToEpoch: m.activationEpoch, PolicyID: compiled.ID, Reason: reason, At: manifest.UpdatedAt}
		if err := m.commitLocked(ctx, manifest, event, operationID); err != nil {
			return nil, err
		}
		return compiled, nil
	}
	if compiled.Revision <= m.lastRevision {
		return nil, fmt.Errorf("policy: revision %d is not newer than %d", compiled.Revision, m.lastRevision)
	}
	if m.hasArtifactPersister() {
		if err := m.persistArtifactWithContext(ctx, compiled); err != nil {
			return nil, fmt.Errorf("policy: persist candidate artifact: %w", err)
		}
	}
	manifest, err := m.manifestLocked(m.current, compiled)
	if err != nil {
		return nil, err
	}
	event := Event{Action: "prepare", Actor: actor, FromRevision: m.current.Revision, ToRevision: compiled.Revision, FromEpoch: m.activationEpoch, ToEpoch: manifest.ActivationEpoch, PolicyID: compiled.ID, Reason: reason, At: manifest.UpdatedAt}
	if err := m.commitLocked(ctx, manifest, event, operationID); err != nil {
		return nil, err
	}
	m.candidate = compiled
	m.lastRevision = compiled.Revision
	m.publishLocked()
	return compiled, nil
}

// Activate commits the currently prepared candidate. The manifest callback
// runs while the manager lock is held and must be atomic/non-reentrant.
func (m *Manager) Activate(reason string) error {
	return m.ActivateByContext(context.Background(), reason, "")
}

// ActivateBy activates the prepared candidate and records the operator in the
// same durable transition event.
func (m *Manager) ActivateBy(reason, actor string) error {
	return m.ActivateByContext(context.Background(), reason, actor)
}

// ActivateContext is the context-aware policy activation operation.
func (m *Manager) ActivateContext(ctx context.Context, reason string) error {
	return m.ActivateByContext(ctx, reason, "")
}

// ActivateByContext is the context-aware operator policy activation operation.
func (m *Manager) ActivateByContext(ctx context.Context, reason, actor string) error {
	return m.ActivateByContextWithOperationID(ctx, reason, actor, "")
}

// ActivateByContextWithOperationID is the replay-safe clustered policy
// activation operation.
func (m *Manager) ActivateByContextWithOperationID(ctx context.Context, reason, actor, operationID string) error {
	if m == nil {
		return errors.New("policy: nil manager")
	}
	var err error
	operationID, err = m.normalizeOperationID(operationID)
	if err != nil {
		return err
	}
	ctx = usableContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshDurableLocked(ctx); err != nil {
		return err
	}
	if m.candidate == nil {
		// An ambiguous commit can leave the shared manifest activated while
		// this process still has the old in-memory lifecycle state. Give the
		// durable operation claim a chance to recognize that exact replay
		// before returning the misleading "no candidate" error.
		if operationID != "" && m.persistTransitionOperationContext != nil {
			manifest, err := m.manifestLocked(m.current, nil)
			if err != nil {
				return err
			}
			event := Event{Action: "activate", Actor: actor, FromRevision: m.current.Revision, ToRevision: m.current.Revision, FromEpoch: m.activationEpoch, ToEpoch: m.activationEpoch, PolicyID: m.current.ID, Reason: reason, At: manifest.UpdatedAt}
			if err := m.commitLocked(ctx, manifest, event, operationID); err == nil {
				m.publishLocked()
				return nil
			} else if !errors.Is(err, ErrOperationNotReplayable) {
				return err
			}
		}
		return errors.New("policy: no prepared candidate")
	}
	from, to := m.current, m.candidate
	manifest, err := m.manifestWithPrevious(to, nil, from)
	if err != nil {
		return err
	}
	if err := m.advanceManifestEpoch(&manifest); err != nil {
		return err
	}
	if err := m.commitLocked(ctx, manifest, Event{Action: "activate", Actor: actor, FromRevision: from.Revision, ToRevision: to.Revision, FromEpoch: m.activationEpoch, ToEpoch: manifest.ActivationEpoch, PolicyID: to.ID, Reason: reason, At: manifest.UpdatedAt}, operationID); err != nil {
		return err
	}
	m.knownGood[to.Revision] = to
	m.current, m.candidate = to, nil
	m.activationEpoch = manifest.ActivationEpoch
	m.publishLocked()
	return nil
}

// Rollback activates an exact previously-known-good revision. It is explicit,
// auditable, and uses the same durable manifest gate as forward activation.
func (m *Manager) Rollback(revision int, reason string) error {
	return m.RollbackByContext(context.Background(), revision, reason, "")
}

// RollbackBy activates an exact known-good revision and records the operator
// in the durable transition event.
func (m *Manager) RollbackBy(revision int, reason, actor string) error {
	return m.RollbackByContext(context.Background(), revision, reason, actor)
}

// RollbackContext is the context-aware policy rollback operation.
func (m *Manager) RollbackContext(ctx context.Context, revision int, reason string) error {
	return m.RollbackByContext(ctx, revision, reason, "")
}

// RollbackByContext is the context-aware operator policy rollback operation.
func (m *Manager) RollbackByContext(ctx context.Context, revision int, reason, actor string) error {
	return m.RollbackByContextWithOperationID(ctx, revision, reason, actor, "")
}

// RollbackByContextWithOperationID is the replay-safe clustered policy
// rollback operation.
func (m *Manager) RollbackByContextWithOperationID(ctx context.Context, revision int, reason, actor, operationID string) error {
	if m == nil {
		return errors.New("policy: nil manager")
	}
	if len(reason) == 0 {
		return errors.New("policy: rollback reason required")
	}
	var err error
	operationID, err = m.normalizeOperationID(operationID)
	if err != nil {
		return err
	}
	ctx = usableContext(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshDurableLocked(ctx); err != nil {
		return err
	}
	target := m.knownGood[revision]
	if target == nil {
		return fmt.Errorf("policy: revision %d is not known-good", revision)
	}
	if target.Revision == m.current.Revision {
		if operationID != "" && m.persistTransitionOperationContext != nil {
			manifest, err := m.manifestLocked(m.current, nil)
			if err != nil {
				return err
			}
			event := Event{Action: "rollback", Actor: actor, FromRevision: m.current.Revision, ToRevision: m.current.Revision, FromEpoch: m.activationEpoch, ToEpoch: m.activationEpoch, PolicyID: m.current.ID, Reason: reason, At: manifest.UpdatedAt}
			if err := m.commitLocked(ctx, manifest, event, operationID); err == nil {
				m.publishLocked()
				return nil
			} else if !errors.Is(err, ErrOperationNotReplayable) {
				return err
			}
		}
		return errors.New("policy: target is already active")
	}
	from := m.current
	manifest, err := m.manifestWithPrevious(target, nil, from)
	if err != nil {
		return err
	}
	if err := m.advanceManifestEpoch(&manifest); err != nil {
		return err
	}
	if err := m.commitLocked(ctx, manifest, Event{Action: "rollback", Actor: actor, FromRevision: from.Revision, ToRevision: target.Revision, FromEpoch: m.activationEpoch, ToEpoch: manifest.ActivationEpoch, PolicyID: target.ID, Reason: reason, At: manifest.UpdatedAt}, operationID); err != nil {
		return err
	}
	m.current, m.candidate = target, nil
	m.activationEpoch = manifest.ActivationEpoch
	m.publishLocked()
	return nil
}

func (m *Manager) manifestLocked(active *CompiledPolicy, candidate *CompiledPolicy) (Manifest, error) {
	manifest, err := manifestForAt(active, candidate, nil, time.Now().UTC())
	if err == nil {
		manifest.ActivationEpoch = m.activationEpoch
	}
	return manifest, err
}

func (m *Manager) manifestWithPrevious(active, candidate, previous *CompiledPolicy) (Manifest, error) {
	manifest, err := manifestForAt(active, candidate, previous, time.Now().UTC())
	if err == nil {
		manifest.ActivationEpoch = m.activationEpoch
	}
	return manifest, err
}

func manifestFor(active *CompiledPolicy, candidate *CompiledPolicy) (Manifest, error) {
	return manifestForAt(active, candidate, nil, time.Now().UTC())
}

func manifestForAt(active *CompiledPolicy, candidate, previous *CompiledPolicy, at time.Time) (Manifest, error) {
	activeDigest, err := Digest(&active.Policy)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{SchemaVersion: 1, ActivationEpoch: 1, Active: PolicyRef{ID: active.ID, Revision: active.Revision, Digest: activeDigest}, UpdatedAt: at}
	if candidate != nil {
		digest, err := Digest(&candidate.Policy)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Candidate = &PolicyRef{ID: candidate.ID, Revision: candidate.Revision, Digest: digest}
	}
	if previous != nil {
		digest, err := Digest(&previous.Policy)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Previous = &PolicyRef{ID: previous.ID, Revision: previous.Revision, Digest: digest}
	}
	return manifest, nil
}

func (m *Manager) advanceManifestEpoch(manifest *Manifest) error {
	if manifest == nil || m.activationEpoch == ^uint64(0) {
		return errors.New("policy: activation epoch exhausted")
	}
	manifest.ActivationEpoch = m.activationEpoch + 1
	return nil
}

func (m *Manager) normalizeOperationID(operationID string) (string, error) {
	operationID = strings.TrimSpace(operationID)
	if !m.requireOperationIDs {
		return operationID, nil
	}
	if operationID == "" {
		return "", ErrOperationIDRequired
	}
	if m.persistTransitionOperationContext == nil {
		return "", ErrOperationIDUnsupported
	}
	return operationID, nil
}

func (m *Manager) commitLocked(ctx context.Context, manifest Manifest, event Event, operationID string) error {
	if operationID != "" && m.persistTransitionOperationContext != nil {
		if err := m.persistTransitionOperationContext(usableContext(ctx), manifest, event, operationID); err != nil {
			return fmt.Errorf("policy: persist transition: %w", err)
		}
		return nil
	}
	if m.persistTransitionContext != nil {
		if err := m.persistTransitionContext(usableContext(ctx), manifest, event); err != nil {
			return fmt.Errorf("policy: persist transition: %w", err)
		}
		return nil
	}
	if m.persistTransition != nil {
		if err := m.persistTransition(manifest, event); err != nil {
			return fmt.Errorf("policy: persist transition: %w", err)
		}
		return nil
	}
	if m.hasManifestPersister() {
		if err := m.persistManifestWithContext(ctx, manifest); err != nil {
			return fmt.Errorf("policy: persist transition: %w", err)
		}
	}
	return m.emitLocked(ctx, event)
}

func (m *Manager) emitLocked(ctx context.Context, event Event) error {
	if m.auditContext == nil && m.audit == nil {
		return nil
	}
	var err error
	if m.auditContext != nil {
		err = m.auditContext(usableContext(ctx), event)
	} else {
		err = m.audit(event)
	}
	if err != nil {
		return fmt.Errorf("policy: audit lifecycle event: %w", err)
	}
	return nil
}
