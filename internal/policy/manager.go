package policy

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Manager owns the policy lifecycle at the control-plane boundary. A policy
// becomes enforceable only after validation, preparation, and one atomic
// activation. The data plane receives immutable CompiledPolicy snapshots and
// never observes a partially loaded candidate.
type Manager struct {
	mu                sync.Mutex
	current           *CompiledPolicy
	candidate         *CompiledPolicy
	knownGood         map[int]*CompiledPolicy
	persist           func(Manifest) error
	audit             func(Event) error
	persistArtifact   func(*CompiledPolicy) error
	persistTransition func(Manifest, Event) error
	loadManifest      func() (Manifest, error)
	loadArtifact      func(PolicyRef) (*CompiledPolicy, error)
	lastRevision      int
}

// Manifest is the durable lifecycle marker. Implementations should write it
// with a temp-file/fsync/rename sequence; Manager calls persist before changing
// its in-memory pointer, so a failed durable write cannot activate a policy.
type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	Active        PolicyRef  `json:"active"`
	Candidate     *PolicyRef `json:"candidate,omitempty"`
	Previous      *PolicyRef `json:"previous,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
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
	PolicyID     string    `json:"policy_id"`
	Reason       string    `json:"reason,omitempty"`
	At           time.Time `json:"at"`
}

// Options supplies durable manifest and audit hooks. Both are optional for
// tests and explicitly ephemeral deployments.
type Options struct {
	Persist func(Manifest) error
	Audit   func(Event) error
	// PersistArtifact stores the exact compiled candidate before its manifest
	// can reference it. This is what makes last-known-good rollback possible
	// after a process restart rather than only while pointers remain in memory.
	PersistArtifact func(*CompiledPolicy) error
	// PersistTransition is the preferred durable hook: implementations can
	// commit the manifest and transition journal as one crash-visible record.
	// Persist/Audit remain supported for small integrations and tests.
	PersistTransition func(Manifest, Event) error
	LoadManifest      func() (Manifest, error)
	LoadArtifact      func(PolicyRef) (*CompiledPolicy, error)
}

// NewManager validates the initial policy and starts with it as known-good.
func NewManager(initial *Policy, opts Options) (*Manager, error) {
	compiled, err := Compile(initial)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		current:           compiled,
		knownGood:         map[int]*CompiledPolicy{compiled.Revision: compiled},
		persist:           opts.Persist,
		audit:             opts.Audit,
		persistArtifact:   opts.PersistArtifact,
		persistTransition: opts.PersistTransition,
		loadManifest:      opts.LoadManifest,
		loadArtifact:      opts.LoadArtifact,
		lastRevision:      compiled.Revision,
	}
	if opts.LoadManifest != nil {
		manifest, loadErr := opts.LoadManifest()
		if loadErr != nil {
			return nil, loadErr
		}
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
				if opts.LoadArtifact == nil {
					return nil, errors.New("policy: configured policy differs from durable active manifest and no artifact loader is configured")
				}
				active, activeErr := opts.LoadArtifact(manifest.Active)
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
			if opts.PersistArtifact != nil {
				if err := opts.PersistArtifact(compiled); err != nil {
					return nil, fmt.Errorf("policy: persist initial artifact: %w", err)
				}
			}
			if opts.Persist != nil {
				if err := opts.Persist(initialManifest); err != nil {
					return nil, fmt.Errorf("policy: persist initial manifest: %w", err)
				}
			}
		}
		if manifest.Candidate != nil {
			if opts.LoadArtifact == nil {
				return nil, errors.New("policy: durable candidate exists but no artifact loader is configured")
			}
			candidate, candidateErr := opts.LoadArtifact(*manifest.Candidate)
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
		if manifest.Previous != nil && opts.LoadArtifact != nil {
			previous, previousErr := opts.LoadArtifact(*manifest.Previous)
			if previousErr != nil {
				return nil, previousErr
			}
			m.knownGood[previous.Revision] = previous
		}
	}
	return m, nil
}

// Current returns the active immutable snapshot.
func (m *Manager) Current() *CompiledPolicy {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshDurableLocked(); err != nil {
		return nil
	}
	return cloneCompiled(m.current)
}

// Candidate returns the prepared but not yet active snapshot, if any.
func (m *Manager) Candidate() *CompiledPolicy {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshDurableLocked(); err != nil {
		return nil
	}
	return cloneCompiled(m.candidate)
}

// refreshDurableLocked reconciles this process with the shared lifecycle
// manifest. It runs before every policy snapshot so a node observes a
// committed activation or rollback without a restart. A read failure returns
// an error; Current then returns nil and the data plane fails closed instead of
// enforcing a potentially stale policy during an authority outage.
func (m *Manager) refreshDurableLocked() error {
	if m.loadManifest == nil || m.loadArtifact == nil {
		return nil
	}
	manifest, err := m.loadManifest()
	if err != nil {
		return err
	}
	if manifest.Active.Revision == 0 {
		return nil
	}
	if m.current == nil {
		return errors.New("policy: current policy is nil")
	}
	activeDigest, err := Digest(&m.current.Policy)
	if err != nil {
		return err
	}
	if m.current.ID != manifest.Active.ID || m.current.Revision != manifest.Active.Revision || activeDigest != manifest.Active.Digest {
		active, err := m.loadArtifact(manifest.Active)
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
		candidate, err := m.loadArtifact(*manifest.Candidate)
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
	if manifest.Previous == nil {
		return nil
	}
	if _, ok := m.knownGood[manifest.Previous.Revision]; !ok {
		previous, err := m.loadArtifact(*manifest.Previous)
		if err != nil {
			return fmt.Errorf("policy: refresh previous artifact: %w", err)
		}
		if err := validateCompiledRef(previous, *manifest.Previous); err != nil {
			return err
		}
		m.knownGood[previous.Revision] = previous
	}
	return nil
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
	return m.PrepareBy(p, "", "")
}

// PrepareBy prepares a candidate and records the authenticated operator that
// requested it. The actor is part of the same durable transition event as the
// candidate manifest, so an accepted policy cannot be detached from its
// operator identity.
func (m *Manager) PrepareBy(p *Policy, actor, reason string) (*CompiledPolicy, error) {
	if m == nil {
		return nil, errors.New("policy: nil manager")
	}
	compiled, err := Compile(p)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshDurableLocked(); err != nil {
		return nil, err
	}
	if compiled.Revision <= m.lastRevision {
		return nil, fmt.Errorf("policy: revision %d is not newer than %d", compiled.Revision, m.lastRevision)
	}
	if m.persistArtifact != nil {
		if err := m.persistArtifact(compiled); err != nil {
			return nil, fmt.Errorf("policy: persist candidate artifact: %w", err)
		}
	}
	manifest, err := m.manifestLocked(m.current, compiled)
	if err != nil {
		return nil, err
	}
	event := Event{Action: "prepare", Actor: actor, FromRevision: m.current.Revision, ToRevision: compiled.Revision, PolicyID: compiled.ID, Reason: reason, At: manifest.UpdatedAt}
	if err := m.commitLocked(manifest, event); err != nil {
		return nil, err
	}
	m.candidate = compiled
	m.lastRevision = compiled.Revision
	return compiled, nil
}

// Activate commits the currently prepared candidate. The manifest callback
// runs while the manager lock is held and must be atomic/non-reentrant.
func (m *Manager) Activate(reason string) error {
	return m.ActivateBy(reason, "")
}

// ActivateBy activates the prepared candidate and records the operator in the
// same durable transition event.
func (m *Manager) ActivateBy(reason, actor string) error {
	if m == nil {
		return errors.New("policy: nil manager")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshDurableLocked(); err != nil {
		return err
	}
	if m.candidate == nil {
		return errors.New("policy: no prepared candidate")
	}
	from, to := m.current, m.candidate
	manifest, err := m.manifestWithPrevious(to, nil, from)
	if err != nil {
		return err
	}
	if err := m.commitLocked(manifest, Event{Action: "activate", Actor: actor, FromRevision: from.Revision, ToRevision: to.Revision, PolicyID: to.ID, Reason: reason, At: manifest.UpdatedAt}); err != nil {
		return err
	}
	m.knownGood[to.Revision] = to
	m.current, m.candidate = to, nil
	return nil
}

// Rollback activates an exact previously-known-good revision. It is explicit,
// auditable, and uses the same durable manifest gate as forward activation.
func (m *Manager) Rollback(revision int, reason string) error {
	return m.RollbackBy(revision, reason, "")
}

// RollbackBy activates an exact known-good revision and records the operator
// in the durable transition event.
func (m *Manager) RollbackBy(revision int, reason, actor string) error {
	if m == nil {
		return errors.New("policy: nil manager")
	}
	if len(reason) == 0 {
		return errors.New("policy: rollback reason required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshDurableLocked(); err != nil {
		return err
	}
	target := m.knownGood[revision]
	if target == nil {
		return fmt.Errorf("policy: revision %d is not known-good", revision)
	}
	if target.Revision == m.current.Revision {
		return errors.New("policy: target is already active")
	}
	from := m.current
	manifest, err := m.manifestWithPrevious(target, nil, from)
	if err != nil {
		return err
	}
	if err := m.commitLocked(manifest, Event{Action: "rollback", Actor: actor, FromRevision: from.Revision, ToRevision: target.Revision, PolicyID: target.ID, Reason: reason, At: manifest.UpdatedAt}); err != nil {
		return err
	}
	m.current, m.candidate = target, nil
	return nil
}

func (m *Manager) manifestLocked(active *CompiledPolicy, candidate *CompiledPolicy) (Manifest, error) {
	return manifestForAt(active, candidate, nil, time.Now().UTC())
}

func (m *Manager) manifestWithPrevious(active, candidate, previous *CompiledPolicy) (Manifest, error) {
	return manifestForAt(active, candidate, previous, time.Now().UTC())
}

func manifestFor(active *CompiledPolicy, candidate *CompiledPolicy) (Manifest, error) {
	return manifestForAt(active, candidate, nil, time.Now().UTC())
}

func manifestForAt(active *CompiledPolicy, candidate, previous *CompiledPolicy, at time.Time) (Manifest, error) {
	activeDigest, err := Digest(&active.Policy)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{SchemaVersion: 1, Active: PolicyRef{ID: active.ID, Revision: active.Revision, Digest: activeDigest}, UpdatedAt: at}
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

func (m *Manager) commitLocked(manifest Manifest, event Event) error {
	if m.persistTransition != nil {
		if err := m.persistTransition(manifest, event); err != nil {
			return fmt.Errorf("policy: persist transition: %w", err)
		}
		return nil
	}
	if m.persist != nil {
		if err := m.persist(manifest); err != nil {
			return fmt.Errorf("policy: persist transition: %w", err)
		}
	}
	return m.emitLocked(event)
}

func (m *Manager) emitLocked(event Event) error {
	if m.audit == nil {
		return nil
	}
	if err := m.audit(event); err != nil {
		return fmt.Errorf("policy: audit lifecycle event: %w", err)
	}
	return nil
}
