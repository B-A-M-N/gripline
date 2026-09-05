// Package control implements the operator control plane (spec §0x, P0.39-P0.41,
// P0.35 audit): the global operational posture switches and the durable audit of
// operator + admission decisions that make the authoritative, persistent state
// reviewable and reversible. It is deployment-facing; the data plane's
// admission pipeline consults it at each gate.
//
// The control plane carries the SECURITY posture (EMERGENCY_LOCKDOWN), not the
// security state itself — that lives in the credential/lane stores. This
// separation lets an operator flip a global switch without mutating per-record
// state, and bounds the blast radius of a firefight.
package control

import (
	"sync"
	"time"
)

// Posture is the operator-set global security posture.
type Posture int

const (
	// Normal: no global override.
	Normal Posture = iota
	// EmergencyLockdown: operator incident mode. The admission pipeline denies
	// NEW lanes and throttles all traffic (P0.40/P0.41), while established
	// capacity and already-persisted restrictions remain in force. This is the
	// firefight switch: reduce attack surface immediately without discarding the
	// authoritative state.
	EmergencyLockdown
)

func (p Posture) String() string {
	switch p {
	case Normal:
		return "NORMAL"
	case EmergencyLockdown:
		return "EMERGENCY_LOCKDOWN"
	default:
		return "UNKNOWN"
	}
}

// EventKind distinguishes audit records.
type EventKind int

const (
	EventAdmission EventKind = iota // one request's admission outcome
	EventOperator                   // an operator posture/lifecycle action
)

func (k EventKind) String() string {
	switch k {
	case EventAdmission:
		return "ADMISSION"
	case EventOperator:
		return "OPERATOR"
	default:
		return "UNKNOWN"
	}
}

// Event is one append-only audit record. It NEVER carries secrets (INV-3): it
// records the request id, outcome, principal ids, and reasons — resolvable but
// not material.
type Event struct {
	Kind         EventKind
	At           time.Time
	Actor        string // operator identity for OPERATOR events; "" for admissions
	Posture      string // posture at event time
	RequestID    string
	CredentialID string
	AccountID    string
	LaneID       string
	Authorized   bool
	Reason       string // safe denial reason or "authorized"
}

// ControlPlane is the operator posture + audit trail. Concurrency-safe.
type ControlPlane struct {
	mu       sync.Mutex
	posture  Posture
	audit    []Event
	auditCap int
}

// New builds a ControlPlane with a bounded, non-lossy-in-practice audit log
// (auditCap 0 = unbounded; a sensible default is used when 0 to bound memory).
func New(auditCap int) *ControlPlane {
	if auditCap <= 0 {
		auditCap = 4096
	}
	return &ControlPlane{posture: Normal, auditCap: auditCap}
}

// Posture returns the current operator posture.
func (c *ControlPlane) Posture() Posture {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.posture
}

// InEmergency reports whether the plane is in EMERGENCY_LOCKDOWN.
func (c *ControlPlane) InEmergency() bool {
	return c.Posture() == EmergencyLockdown
}

// SetEmergency is the operator firefight switch (P0.39). Transitioning INTO
// lockdown records an OPERATOR audit event; exiting does too. The audit event
// carries the actor + reason so the decision is reviewable (P0.35).
func (c *ControlPlane) SetEmergency(on bool, actor, reason string) Posture {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := Normal
	if on {
		next = EmergencyLockdown
	}
	if c.posture == next {
		return c.posture // no-op transition
	}
	prev := c.posture
	c.posture = next
	c.recordLocked(Event{
		Kind:    EventOperator,
		At:      time.Now(),
		Actor:   actor,
		Posture: next.String(),
		Reason:  reason,
		Authorized: false,
	})
	_ = prev
	return c.posture
}

// RecordAdmission appends an admission decision to the audit trail (P0.35). The
// caller supplies only non-secret fields from the decision outcome.
func (c *ControlPlane) RecordAdmission(e Event) {
	e.Kind = EventAdmission
	e.At = time.Now()
	e.Posture = c.Posture().String()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recordLocked(e)
}

// Audit returns a copy of the audit trail (newest-last).
func (c *ControlPlane) Audit() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Event, len(c.audit))
	copy(out, c.audit)
	return out
}

// recordLocked appends, bounded by auditCap (drops oldest to stay bounded).
func (c *ControlPlane) recordLocked(e Event) {
	if len(c.audit) >= c.auditCap {
		c.audit = append(c.audit[:0:0], c.audit[1:]...)
	}
	c.audit = append(c.audit, e)
}