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
	mu           sync.RWMutex
	current      *CompiledPolicy
	candidate    *CompiledPolicy
	knownGood    map[int]*CompiledPolicy
	persist      func(Manifest) error
	audit        func(Event) error
	lastRevision int
}

// Manifest is the durable lifecycle marker. Implementations should write it
// with a temp-file/fsync/rename sequence; Manager calls persist before changing
// its in-memory pointer, so a failed durable write cannot activate a policy.
type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	Active        PolicyRef  `json:"active"`
	Candidate     *PolicyRef `json:"candidate,omitempty"`
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
}

// NewManager validates the initial policy and starts with it as known-good.
func NewManager(initial *Policy, opts Options) (*Manager, error) {
	compiled, err := Compile(initial)
	if err != nil {
		return nil, err
	}
	m := &Manager{
		current:      compiled,
		knownGood:    map[int]*CompiledPolicy{compiled.Revision: compiled},
		persist:      opts.Persist,
		audit:        opts.Audit,
		lastRevision: compiled.Revision,
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
	manifest, err := m.manifestLocked(to, nil)
	if err != nil {
		return err
	}
	if m.persist != nil {
		if err := m.persist(manifest); err != nil {
			return fmt.Errorf("policy: persist activation: %w", err)
		}
	}
	if err := m.emitLocked(Event{Action: "activate", FromRevision: from.Revision, ToRevision: to.Revision, PolicyID: to.ID, Reason: reason, At: manifest.UpdatedAt}); err != nil {
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
	manifest, err := m.manifestLocked(target, nil)
	if err != nil {
		return err
	}
	if m.persist != nil {
		if err := m.persist(manifest); err != nil {
			return fmt.Errorf("policy: persist rollback: %w", err)
		}
	}
	if err := m.emitLocked(Event{Action: "rollback", FromRevision: from.Revision, ToRevision: target.Revision, PolicyID: target.ID, Reason: reason, At: manifest.UpdatedAt}); err != nil {
		return err
	}
	m.current, m.candidate = target, nil
	return nil
}

func (m *Manager) manifestLocked(active *CompiledPolicy, candidate *CompiledPolicy) (Manifest, error) {
	activeDigest, err := Digest(&active.Policy)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{SchemaVersion: 1, Active: PolicyRef{ID: active.ID, Revision: active.Revision, Digest: activeDigest}, UpdatedAt: time.Now().UTC()}
	if candidate != nil {
		digest, err := Digest(&candidate.Policy)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Candidate = &PolicyRef{ID: candidate.ID, Revision: candidate.Revision, Digest: digest}
	}
	return manifest, nil
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
