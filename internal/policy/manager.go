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
	mu                sync.RWMutex
	current           *CompiledPolicy
	candidate         *CompiledPolicy
	knownGood         map[int]*CompiledPolicy
	persist           func(Manifest) error
	audit             func(Event) error
	persistArtifact   func(*CompiledPolicy) error
	persistTransition func(Manifest, Event) error
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Candidate returns the prepared but not yet active snapshot, if any.
func (m *Manager) Candidate() *CompiledPolicy {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.candidate
}

// Prepare validates and compiles a candidate. Revisions are strictly
// monotonic; replaying an old artifact cannot replace a newer candidate.
func (m *Manager) Prepare(p *Policy) (*CompiledPolicy, error) {
	if m == nil {
		return nil, errors.New("policy: nil manager")
	}
	compiled, err := Compile(p)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
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
	event := Event{Action: "prepare", FromRevision: m.current.Revision, ToRevision: compiled.Revision, PolicyID: compiled.ID, At: manifest.UpdatedAt}
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
	if m == nil {
		return errors.New("policy: nil manager")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.candidate == nil {
		return errors.New("policy: no prepared candidate")
	}
	from, to := m.current, m.candidate
	manifest, err := m.manifestWithPrevious(to, nil, from)
	if err != nil {
		return err
	}
	if err := m.commitLocked(manifest, Event{Action: "activate", FromRevision: from.Revision, ToRevision: to.Revision, PolicyID: to.ID, Reason: reason, At: manifest.UpdatedAt}); err != nil {
		return err
	}
	m.knownGood[to.Revision] = to
	m.current, m.candidate = to, nil
	return nil
}

// Rollback activates an exact previously-known-good revision. It is explicit,
// auditable, and uses the same durable manifest gate as forward activation.
func (m *Manager) Rollback(revision int, reason string) error {
	if m == nil {
		return errors.New("policy: nil manager")
	}
	if len(reason) == 0 {
		return errors.New("policy: rollback reason required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
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
	if err := m.commitLocked(manifest, Event{Action: "rollback", FromRevision: from.Revision, ToRevision: target.Revision, PolicyID: target.ID, Reason: reason, At: manifest.UpdatedAt}); err != nil {
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
