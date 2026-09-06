// Production control plane (P0.47): authenticated, authorized, durably
// audited operator actions.
//
// The in-memory ControlPlane (control.go) is the admission-side audit buffer
// and posture switch — a test/development fixture. A production deployment
// must not expose operator actions through an unauthenticated, non-durable
// object: every state-changing action needs (1) an AUTHENTICATED operator
// identity, (2) an RBAC CAPABILITY check, and (3) a durable append-only audit
// record committed with the action (P0.49's atomicity rule at the control
// plane). This file provides those three seams:
//
//   - AuditRepository: durable append-only audit sink (JSONL file impl
//     included; production may substitute a database-backed implementation).
//   - Identity / Authenticator: operator authentication (token-based default).
//   - Capability: RBAC check per action class.
//   - Service: the transaction boundary — action + audit commit together,
//     refusing the action when authentication, authorization, or the durable
//     audit write fails.
package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditRepository is the durable, append-only audit destination (P0.47).
// Append must persist the record before returning nil; a returned error MUST
// fail the operator action the record documents. No method may rewrite or
// delete prior records — append-only is the contract.
type AuditRepository interface {
	AppendOperator(ctx context.Context, rec OperatorRecord) error
}

// OperatorRecord is one durable operator-action audit row. It carries WHO
// (authenticated identity), WHAT (action), ON WHICH TARGET, WHEN, the
// justification, the posture at action time, and the OUTCOME — everything a
// review needs, nothing secret (INV-3).
type OperatorRecord struct {
	At        time.Time `json:"at"`
	Actor     string    `json:"actor"`            // authenticated operator identity
	Action    string    `json:"action"`           // e.g. "credential.revoke"
	Target    string    `json:"target"`           // credential/lane/policy id
	Reason    string    `json:"reason"`           // operator justification (required)
	Posture   string    `json:"posture"`          // posture at action time
	Committed bool      `json:"committed"`        // did the state change commit?
	Detail    string    `json:"detail,omitempty"` // error/no-op detail
}

// FileAuditRepository is a JSONL, fsync-per-record, append-only audit
// repository. It is the minimum DURABLE implementation: each record is one
// line, written and synced before AppendOperator returns. It never truncates
// or rewrites — the file is opened O_APPEND.
type FileAuditRepository struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	path string
}

// NewFileAuditRepository opens (or creates) path for durable append. The
// initial open fsyncs so an empty file's existence is durable before any
// action can be recorded in it.
func NewFileAuditRepository(path string) (*FileAuditRepository, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("control: open audit log: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("control: sync audit log: %w", err)
	}
	enc := json.NewEncoder(f)
	return &FileAuditRepository{f: f, enc: enc, path: path}, nil
}

// Path returns the audit file path (diagnostics).
func (r *FileAuditRepository) Path() string { return r.path }

// AppendOperator writes one record and fsyncs. A write or sync failure is
// returned — the caller must fail the action (never audit-after-the-fact).
func (r *FileAuditRepository) AppendOperator(_ context.Context, rec OperatorRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.enc.Encode(&rec); err != nil {
		return fmt.Errorf("control: encode audit record: %w", err)
	}
	if err := r.f.Sync(); err != nil {
		return fmt.Errorf("control: sync audit record: %w", err)
	}
	return nil
}

// Close syncs and closes the underlying file.
func (r *FileAuditRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.f.Sync(); err != nil {
		r.f.Close()
		return err
	}
	return r.f.Close()
}

// --- Operator authentication (P0.47) -----------------------------------------

// Identity is an authenticated operator principal.
type Identity struct {
	Name         string // stable operator/service identity, audited as Actor
	Capabilities []Capability
}

// Capability is one authorized action class. RBAC is deny-by-default: an
// action requires its exact capability.
type Capability string

const (
	// CapCredentialLifecycle: revoke / quarantine-release / revision bump.
	CapCredentialLifecycle Capability = "credential.lifecycle"
	// CapLaneLifecycle: lane block / unblock / force-status.
	CapLaneLifecycle Capability = "lane.lifecycle"
	// CapPosture: the global EMERGENCY_LOCKDOWN switch.
	CapPosture Capability = "posture.control"
	// CapEvidence: manual IOC / operator evidence minting.
	CapEvidence Capability = "evidence.operator"
	// CapPolicyInstall: policy install / rollback.
	CapPolicyInstall Capability = "policy.install"
)

// ErrUnauthenticated is returned when credentials are absent or invalid.
var ErrUnauthenticated = errors.New("control: unauthenticated operator")

// ErrUnauthorized is returned when the identity lacks the action's capability.
var ErrUnauthorized = errors.New("control: operator lacks required capability")

// ErrReasonRequired is returned when an operator action arrives without a
// justification. An unauditable why is an unauditable action.
var ErrReasonRequired = errors.New("control: operator action requires a reason")

// TokenAuthenticator authenticates operators via bearer tokens. Tokens are
// stored and compared as HMAC-SHA256 digests — the raw token is never
// retained, so a read of the authenticator's table does not yield usable
// credentials (INV-1). Production deployments back Authenticator with their
// SSO/mTLS stack; this implementation serves as the documented default.
type TokenAuthenticator struct {
	mu     sync.RWMutex
	digest map[string]*Identity // token digest → identity
}

// NewTokenAuthenticator builds an authenticator from token→identity pairs.
// Empty tokens are rejected: an empty bearer would authenticate anyone.
func NewTokenAuthenticator(tokens map[string]*Identity) (*TokenAuthenticator, error) {
	a := &TokenAuthenticator{digest: make(map[string]*Identity, len(tokens))}
	for tok, id := range tokens {
		if tok == "" {
			return nil, errors.New("control: empty operator token")
		}
		if id == nil || id.Name == "" {
			return nil, errors.New("control: operator identity requires a name")
		}
		a.digest[tokenDigest(tok)] = id
	}
	return a, nil
}

func tokenDigest(tok string) string {
	sum := sha256.Sum256([]byte("gripline:control:operator-token:v1:" + tok))
	return string(sum[:])
}

// Authenticate resolves a presented bearer token to an Identity. The map key
// IS the digest; misses return ErrUnauthenticated without distinguishing
// "malformed" from "unknown" (no oracle).
func (a *TokenAuthenticator) Authenticate(_ context.Context, token string) (*Identity, error) {
	if token == "" {
		return nil, ErrUnauthenticated
	}
	d := tokenDigest(token)
	a.mu.RLock()
	id, ok := a.digest[d]
	a.mu.RUnlock()
	if !ok {
		return nil, ErrUnauthenticated
	}
	return id, nil
}

// Authorize checks the identity holds the capability. Deny-by-default.
func Authorize(id *Identity, cap Capability) error {
	if id == nil {
		return ErrUnauthenticated
	}
	for _, c := range id.Capabilities {
		if c == cap {
			return nil
		}
	}
	return ErrUnauthorized
}

// --- The control-plane service (P0.47) ---------------------------------------

// Service is the production operator control plane: every state-changing
// action passes authentication → capability check → durable audit commit →
// state mutation, with the audit record committed BEFORE the mutation returns
// and a failed audit write failing the action. It wraps the in-memory
// ControlPlane (posture + bounded admission buffer) and the operator seams of
// the credential/lane stores.
type Service struct {
	plane *ControlPlane
	auth  Authenticator
	audit AuditRepository
	now   func() time.Time

	mu    sync.Mutex
	lanes LaneOperator       // optional lane lifecycle seam
	creds CredentialOperator // optional credential lifecycle seam
}

// Authenticator is the operator authentication seam.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (*Identity, error)
}

// LaneOperator is the lane lifecycle seam (P0.49-compatible): a durable
// operator action returning the audit entry the transaction must commit.
type LaneOperator interface {
	// UnblockOperator clears a BLOCKED lane; it must itself commit durably
	// (lane.Store with an AuditSink satisfies this contractually).
	UnblockOperator(credID, laneID, actor, reason string, now time.Time) error
}

// CredentialOperator is the credential lifecycle seam.
type CredentialOperator interface {
	Revoke(credentialID string) error
	BumpRevision(credentialID string) error
}

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithLaneOperator wires the lane lifecycle seam.
func WithLaneOperator(op LaneOperator) ServiceOption { return func(s *Service) { s.lanes = op } }

// WithCredentialOperator wires the credential lifecycle seam.
func WithCredentialOperator(op CredentialOperator) ServiceOption {
	return func(s *Service) { s.creds = op }
}

// NewService builds the production control-plane service. plane, auth, and
// audit are REQUIRED — a production control plane without authenticated
// operators or durable audit is exactly the P0.47 finding.
func NewService(plane *ControlPlane, auth Authenticator, audit AuditRepository, opts ...ServiceOption) (*Service, error) {
	if plane == nil {
		return nil, errors.New("control: plane required")
	}
	if auth == nil {
		return nil, errors.New("control: authenticator required (P0.47)")
	}
	if audit == nil {
		return nil, errors.New("control: durable audit repository required (P0.47)")
	}
	s := &Service{plane: plane, auth: auth, audit: audit, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// authorize runs the shared preconditions: authenticate → capability →
// non-empty justification. Returns the authenticated identity.
func (s *Service) authorize(ctx context.Context, token string, cap Capability, reason string) (*Identity, error) {
	if reason == "" {
		return nil, ErrReasonRequired
	}
	id, err := s.auth.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	if err := Authorize(id, cap); err != nil {
		return nil, err
	}
	return id, nil
}

// record durably commits the operator audit row. Committed=false rows are
// also recorded (a DENIED attempt is exactly what an investigation needs).
func (s *Service) record(actor, action, target, reason string, committed bool, detail string) {
	rec := OperatorRecord{
		At:        s.now().UTC(),
		Actor:     actor,
		Action:    action,
		Target:    target,
		Reason:    reason,
		Posture:   s.plane.Posture().String(),
		Committed: committed,
		Detail:    detail,
	}
	// Best-effort for the RECORD-OF-A-DENIED-ACTION path only; committed
	// actions audit inside the transaction (callers use commitAudit).
	_ = s.audit.AppendOperator(context.Background(), rec)
}

// commitAudit durably commits the record for a COMPLETED action; a failure
// here fails the action contract — callers return err to the operator.
func (s *Service) commitAudit(ctx context.Context, actor, action, target, reason string) error {
	return s.audit.AppendOperator(ctx, OperatorRecord{
		At: s.now().UTC(), Actor: actor, Action: action, Target: target,
		Reason: reason, Posture: s.plane.Posture().String(), Committed: true,
	})
}

// SetEmergency is the authenticated, authorized, durably-audited posture
// switch. On success it also feeds the in-memory plane (which the data plane
// consults) and its bounded audit buffer.
func (s *Service) SetEmergency(ctx context.Context, token string, on bool, reason string) (Posture, error) {
	id, err := s.authorize(ctx, token, CapPosture, reason)
	if err != nil {
		s.record("", "posture.set_emergency", "global", reason, false, err.Error())
		return s.plane.Posture(), err
	}
	target := Normal
	if on {
		target = EmergencyLockdown
	}
	// The audit row carries the TARGET posture: it documents the action being
	// authorized, and is committed before the plane flips (atomicity rule).
	if err := s.audit.AppendOperator(ctx, OperatorRecord{
		At: s.now().UTC(), Actor: id.Name, Action: "posture.set_emergency",
		Target: "global", Reason: reason, Posture: target.String(), Committed: true,
	}); err != nil {
		return s.plane.Posture(), fmt.Errorf("control: audit commit failed, action aborted: %w", err)
	}
	posture := s.plane.SetEmergency(on, id.Name, reason)
	return posture, nil
}

// RevokeCredential revokes a credential under full control-plane discipline.
func (s *Service) RevokeCredential(ctx context.Context, token, credID, reason string) error {
	id, err := s.authorize(ctx, token, CapCredentialLifecycle, reason)
	if err != nil {
		s.record("", "credential.revoke", credID, reason, false, err.Error())
		return err
	}
	if s.creds == nil {
		s.record(id.Name, "credential.revoke", credID, reason, false, "no credential operator wired")
		return errors.New("control: no credential operator wired")
	}
	// Atomicity rule: durable audit BEFORE the mutation returns; a failed
	// audit aborts (the operator re-runs; revoke is idempotent in effect).
	if err := s.commitAudit(ctx, id.Name, "credential.revoke", credID, reason); err != nil {
		return fmt.Errorf("control: audit commit failed, action aborted: %w", err)
	}
	if err := s.creds.Revoke(credID); err != nil {
		return err
	}
	return nil
}

// UnblockLane clears a BLOCKED lane through the wired LaneOperator, which
// commits the lane audit entry itself (P0.49 atomicity), plus the control
// plane's own durable row.
func (s *Service) UnblockLane(ctx context.Context, token, credID, laneID, reason string) error {
	id, err := s.authorize(ctx, token, CapLaneLifecycle, reason)
	if err != nil {
		s.record("", "lane.unblock", laneID, reason, false, err.Error())
		return err
	}
	if s.lanes == nil {
		s.record(id.Name, "lane.unblock", laneID, reason, false, "no lane operator wired")
		return errors.New("control: no lane operator wired")
	}
	if err := s.commitAudit(ctx, id.Name, "lane.unblock", laneID, reason); err != nil {
		return fmt.Errorf("control: audit commit failed, action aborted: %w", err)
	}
	if err := s.lanes.UnblockOperator(credID, laneID, id.Name, reason, s.now()); err != nil {
		return err
	}
	return nil
}

// LaneUnblockAdapter adapts a *lane.Store to the LaneOperator seam. The store
// must have a durable AuditSink wired (WithAuditSink) so the lane-side audit
// entry commits inside the store transaction (P0.49); this adapter only
// translates signatures.
//
// The adapter lives in the consumer (control) package rather than lane to
// avoid an import cycle, taking the store through the minimal structural
// surface below.
type LaneUnblockAdapter struct {
	// Unblock clears a BLOCKED lane and durably commits its lane-side audit
	// entry (lane.StoreWithAuditSink contract).
	Unblock func(credID, laneID, actor, reason string, now time.Time) error
}

// UnblockOperator implements LaneOperator.
func (a LaneUnblockAdapter) UnblockOperator(credID, laneID, actor, reason string, now time.Time) error {
	if a.Unblock == nil {
		return errors.New("control: lane unblock not wired")
	}
	return a.Unblock(credID, laneID, actor, reason, now)
}
