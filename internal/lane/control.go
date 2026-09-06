package lane

import (
	"errors"
	"time"
)

// OperatorAction names a control-plane lifecycle action taken by an operator on
// a lane. These are the explicit interventions that the risk reducer never does
// on its own (a BLOCKED lane only exits via operator action, P0.39/P0.7).
type OperatorAction int

const (
	ActionUnblock OperatorAction = iota
	ActionForceSuspicious
	ActionForceBlock
)

func (a OperatorAction) String() string {
	switch a {
	case ActionUnblock:
		return "UNBLOCK"
	case ActionForceSuspicious:
		return "FORCE_SUSPICIOUS"
	case ActionForceBlock:
		return "FORCE_BLOCK"
	default:
		return "UNKNOWN_ACTION"
	}
}

// AuditEntry is a durable, append-only record of an operator intervention. It is
// written by the control plane so the "authoritative persistent decision" is
// reproducible and reviewable (P0.35): who did what to which lane/credential,
// when, and what the security status was before → after.
type AuditEntry struct {
	LaneID       string
	CredentialID string
	Actor        string // operator or automated system identity performing the action
	Action       OperatorAction
	Before       SecurityStatus
	After        SecurityStatus
	Revision     int // lane revision after the action
	At           time.Time
	Reason       string // human-readable justification (operator note)
}

var (
	// ErrLaneNotFound is returned when the targeted lane does not exist.
	ErrLaneNotFound = errors.New("lane: not found")
	// ErrActionInvalid is returned when an operator action cannot be applied in
	// the current security state (e.g. UNBLOCKing a non-blocked lane).
	ErrActionInvalid = errors.New("lane: operator action invalid for current security state")
)

// AuditSink is the durable destination for operator lifecycle audit entries
// (P0.49). Implementations append the entry to DURABLE storage — a file, a
// database, an append-only log. Returning nil means the entry is committed;
// returning an error FAILS the whole operator transaction, so the audit record
// can never be silently lost behind a state change that did land (and the
// state change can never land without its audit record).
type AuditSink interface {
	AppendOperatorAudit(entry *AuditEntry) error
}

// AuditSinkFunc adapts a function to an AuditSink.
type AuditSinkFunc func(entry *AuditEntry) error

// AppendOperatorAudit implements AuditSink.
func (f AuditSinkFunc) AppendOperatorAudit(entry *AuditEntry) error { return f(entry) }

// WithAuditSink binds a durable audit sink to the store (P0.49). Once set,
// EVERY operator transition commits its AuditEntry through the sink INSIDE the
// same transaction that mutates state — the caller no longer has to remember
// to persist the returned entry, and a sink failure rolls the transition back.
// Without a sink the transition returns the entry as before (the in-memory
// default remains usable by tests); production stores MUST wire a durable sink.
func (s *Store) WithAuditSink(sink AuditSink) *Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditSink = sink
	return s
}

// Unblock is the operator control-plane action that exits a BLOCKED lane. The
// risk reducer never auto-recovers a block; only an explicit authorized operator
// action may clear it (P0.7, §36 lifecycle). It resets the security dimension to
// NORMAL and re-seeds the contiguous-clean window (CleanSince) so promotion
// criteria restart from the operator's clearing, NOT from the pre-abuse quiet
// period (P0.42).
//
// It fails with ErrActionInvalid if the lane is not BLOCKED, so an operator
// cannot accidentally "clear" a lane that never earned a block (which would let
// a FORCE action launder state).
func (s *Store) Unblock(credID, laneID, actor, reason string, now time.Time) (*AuditEntry, error) {
	return s.operatorTransition(ActionUnblock, LaneBlocked, LaneNormal, credID, laneID, actor, reason, now, true)
}

// operatorTransition applies a lifecycle status change under the store lock,
// enforcing that the current status matches an expected precondition and
// committing the audit entry ATOMICALLY with the state change (P0.49): when a
// durable AuditSink is wired, the entry is appended while the store lock is
// held and BEFORE the mutation becomes visible; a sink failure aborts the
// transition (state unchanged, no half-applied operator action, no lost audit
// record). reseedClean controls whether CleanSince is reset to now (true for an
// unblock: the clean window starts fresh after operator clearing).
func (s *Store) operatorTransition(action OperatorAction, expectFrom, to SecurityStatus, credID, laneID, actor, reason string, now time.Time, reseedClean bool) (*AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.lookupLocked(credID, laneID)
	if !ok {
		return nil, ErrLaneNotFound
	}
	if rec.Security.Status != expectFrom {
		return nil, ErrActionInvalid
	}
	entry := &AuditEntry{
		LaneID: laneID, CredentialID: credID, Actor: actor,
		Action: action, Before: rec.Security.Status, After: to,
		At: now, Reason: reason,
	}
	// P0.49: durable audit commit inside the transaction. Failure rolls back —
	// the caller sees the sink's error and the lane is untouched, so the audit
	// trail and the authoritative state can never disagree.
	if s.auditSink != nil {
		if aerr := s.auditSink.AppendOperatorAudit(entry); aerr != nil {
			return nil, aerr
		}
	}
	rec.Security.Status = to
	if reseedClean {
		rec.CleanSince = now
	}
	rec.Security.SuspectStreak = 0
	rec.Security.ClearSince = time.Time{}
	rec.Security.RiskScore = 0
	rec.Revision++
	entry.Revision = rec.Revision
	return entry, nil
}
