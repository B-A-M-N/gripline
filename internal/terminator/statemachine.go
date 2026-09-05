package terminator

import (
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
)

// CredentialStateStore owns per-credential StateMachine instances and
// serializes concurrent observations for the same credential. It must seed
// state from the persisted credential status on first use — not every
// credential starts NORMAL (a credential restored from QUARANTINED storage
// must start in QUARANTINED, but the machine's hysteresis metadata will be
// process-local until retrained).
//
// Important limitation: the StateMachine contains hysteresis metadata such as
// watchStreak, belowSince, lastScoreTime that is not represented in
// CredentialRecord. For the in-memory MVP these remain process-local.
// Restart/multi-node durable hysteresis is NOT solved by merely persisting
// CredentialRecord.Status.
type CredentialStateStore struct {
	mu      sync.Mutex
	hy      credential.Hysteresis
	now     func() time.Time
	// Per-credential lock: maps credID → per-credential mutex + state machine.
	machines map[string]*credMachine
}

type credMachine struct {
	mu       sync.Mutex
	machine  *credential.StateMachine
	status   credential.Status // current known status from registry
}

// NewCredentialStateStore builds a store. hy is the hysteresis config; now is
// the clock.
func NewCredentialStateStore(hy credential.Hysteresis, now func() time.Time) *CredentialStateStore {
	no := now
	if no == nil {
		no = time.Now
	}
	return &CredentialStateStore{
		hy:       hy,
		now:      no,
		machines: make(map[string]*credMachine),
	}
}

// Observe feeds a risk observation for a credential, serializing concurrent
// observations for the same credentialID. It returns the before/after status
// and whether a transition occurred.
//
// On first call for a credentialID, the machine is seeded with the persisted
// status. The machine then observes the score and returns the new status.
//
// The caller (terminator) is responsible for persisting the new status via
// Registry.UpdateStatusCAS.
func (s *CredentialStateStore) Observe(
	credentialID string,
	current credential.Status,
	score int,
) (before credential.Status, after credential.Status, changed bool) {
	s.mu.Lock()
	cm, ok := s.machines[credentialID]
	if !ok {
		cm = &credMachine{
			status:   current,
			machine:  credential.NewStateMachine(s.hy, s.now),
		}
		// Seed the machine's current status. If the credential is already in
		// an elevated state, we set it explicitly. NORMAL is the default.
		if current != credential.StatusNormal {
			cm.machine.SetStatus(current)
		}
		s.machines[credentialID] = cm
	}
	s.mu.Unlock()

	// Per-credential serialization.
	cm.mu.Lock()
	defer cm.mu.Unlock()

	before = cm.status
	after = cm.machine.Observe(score)
	if after != before {
		cm.status = after
	}
	return before, after, after != before
}

// ObserveAndCAS coordinates observation + CAS + rollback under per-credential
// lock. This prevents the CAS-failure divergence where the in-memory machine
// has advanced but the registry did not (INV-14: StateMachine/CAS atomicity).
//
// It returns the updated credential (with new status + revision) and whether
// the CAS succeeded. If CAS fails, the machine is rolled back to before and
// the caller falls back to the re-read authoritative registry state.
func (s *CredentialStateStore) ObserveAndCAS(
	credentialID string,
	current credential.Status,
	currentRev int,
	score int,
	updateStatus func(newStatus credential.Status, rev int) (*credential.CredentialRecord, error),
) (*credential.Credential, credential.Status, error) {
	s.mu.Lock()
	cm, ok := s.machines[credentialID]
	if !ok {
		cm = &credMachine{
			status:   current,
			machine:  credential.NewStateMachine(s.hy, s.now),
		}
		if current != credential.StatusNormal {
			cm.machine.SetStatus(current)
		}
		s.machines[credentialID] = cm
	}
	s.mu.Unlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	before := cm.status
	after := cm.machine.Observe(score)
	changed := after != before

	if changed {
		cm.status = after
		// Attempt CAS.
		rec, err := updateStatus(after, currentRev)
		if err != nil {
			// CAS failed: rollback machine + status.
			cm.machine.SetStatus(before)
			cm.status = before
			// Fall back to re-read authoritative state.
			// Caller must pass a registry that implements Lookup.
			return nil, after, err
		}
		// Sync the machine's internal state to match what just persisted.
		cm.machine.SetStatus(after)
		updatedCred := &credential.Credential{
			CredentialID: rec.CredentialID,
			AccountID:    rec.AccountID,
			PolicyID:     rec.PolicyID,
			PlanID:       rec.PlanID,
			Status:       rec.Status,
			Revision:     rec.Revision,
		}
		return updatedCred, after, nil
	}

	// No transition: return current credential unchanged.
	return nil, after, nil
}

// Status returns the current tracked status for a credential.
func (s *CredentialStateStore) Status(credentialID string) credential.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	cm, ok := s.machines[credentialID]
	if !ok {
		return credential.StatusNormal
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.status
}
