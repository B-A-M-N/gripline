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
	"context"
	"errors"
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

// PostureAuthority is the authoritative, context-aware posture read used by
// admission. A clustered implementation reads the singleton posture from the
// shared store; ControlPlane implements the same seam for standalone and test
// deployments. The data plane must treat an error as unavailable, never as
// NORMAL.
type PostureAuthority interface {
	PostureContext(context.Context) (Posture, error)
}

// PostureSnapshotAuthority optionally exposes the authoritative activation
// time alongside the posture. Cluster admission uses it to distinguish a
// pre-lockdown non-established lane from a NEW lane materialized by a request
// that lockdown already denied.
type PostureSnapshotAuthority interface {
	PostureSnapshotContext(context.Context) (Posture, time.Time, error)
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
	// Remote readers/recorders are installed by a clustered composition root.
	// The resident buffer remains useful as a local cache and test fixture, but
	// security decisions consult the shared authority when one is configured.
	postureReader     func(context.Context) (Posture, error)
	admissionRecorder func(context.Context, Event) error
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

// SetPostureReader binds the shared posture authority used by clustered
// admission. A nil reader restores resident-only behavior.
func (c *ControlPlane) SetPostureReader(reader func(context.Context) (Posture, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.postureReader = reader
}

// SetAdmissionRecorder binds the shared admission-audit authority used by
// clustered deployments. The local bounded audit remains populated as a
// diagnostic cache regardless of recorder success.
func (c *ControlPlane) SetAdmissionRecorder(recorder func(context.Context, Event) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.admissionRecorder = recorder
}

// PostureContext reads the authoritative posture for one request. Clustered
// callers must treat a returned error as unavailable, not as NORMAL.
func (c *ControlPlane) PostureContext(ctx context.Context) (Posture, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	reader := c.postureReader
	local := c.posture
	c.mu.Unlock()
	if reader == nil {
		return local, nil
	}
	p, err := reader(ctx)
	if err != nil {
		return Normal, err
	}
	return p, nil
}

// InEmergencyContext returns the shared posture decision for one request.
// Callers must propagate an error as an unavailable control authority.
func (c *ControlPlane) InEmergencyContext(ctx context.Context) (bool, error) {
	p, err := c.PostureContext(ctx)
	return p == EmergencyLockdown, err
}

// InEmergency reports whether the plane is in EMERGENCY_LOCKDOWN.
func (c *ControlPlane) InEmergency() bool {
	return c.Posture() == EmergencyLockdown
}

// Restore sets the initialized posture without recording an OPERATOR audit
// event (P0.10). BuildRuntime uses it to reload a persisted EMERGENCY_LOCKDOWN
// at boot so a restart never silently returns to NORMAL. It is meant for
// construction-time restore only — live transitions go through SetEmergency.
func (c *ControlPlane) Restore(p Posture) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.posture = p
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
		Kind:       EventOperator,
		At:         time.Now(),
		Actor:      actor,
		Posture:    next.String(),
		Reason:     reason,
		Authorized: false,
	})
	_ = prev
	return c.posture
}

// RecordAdmission appends an admission decision to the audit trail (P0.35). The
// caller supplies only non-secret fields from the decision outcome.
func (c *ControlPlane) RecordAdmission(e Event) {
	_ = c.RecordAdmissionContext(context.Background(), e)
}

// RecordAdmissionContext appends an admission to the shared recorder when
// configured and always updates the local bounded diagnostic trail.
func (c *ControlPlane) RecordAdmissionContext(ctx context.Context, e Event) error {
	e.Kind = EventAdmission
	e.At = time.Now()
	posture, postureErr := c.PostureContext(ctx)
	if postureErr == nil {
		e.Posture = posture.String()
	} else {
		e.Posture = "UNAVAILABLE"
	}
	c.mu.Lock()
	recorder := c.admissionRecorder
	c.recordLocked(e)
	c.mu.Unlock()
	if recorder != nil {
		if err := recorder(ctx, e); err != nil {
			return err
		}
	}
	if postureErr != nil {
		return errors.Join(errors.New("control: posture unavailable"), postureErr)
	}
	return nil
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
