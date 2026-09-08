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
	"strings"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
)

// AuditRepository is the durable, append-only audit destination (P0.47).
// Append must persist the record before returning nil; a returned error MUST
// fail the operator action the record documents. No method may rewrite or
// delete prior records — append-only is the contract.
type AuditRepository interface {
	AppendOperator(ctx context.Context, rec OperatorRecord) error
}

// AuditRecordReader is the read-only operator-audit surface used by the
// authenticated admin API and CLI export. It exposes sanitized records only;
// the caller never receives credential or signer material.
type AuditRecordReader interface {
	ListOperatorAudit(after uint64, limit int) ([]OperatorRecord, error)
}

// OperatorRecord is one durable operator-action audit row. It carries WHO
// (authenticated identity), WHAT (action), ON WHICH TARGET, WHEN, the
// justification, the posture at action time, and the OUTCOME — everything a
// review needs, nothing secret (INV-3).
type OperatorRecord struct {
	Sequence  uint64    `json:"sequence,omitempty"` // durable cursor assigned by the store
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
	// CapAuditRead: read operator and automatic security audit history.
	CapAuditRead Capability = "audit.read"
	// CapClusterRead: read shared membership and crypto-generation status.
	CapClusterRead Capability = "cluster.read"
)

// ErrUnauthenticated is returned when credentials are absent or invalid.
var ErrUnauthenticated = errors.New("control: unauthenticated operator")

// ErrUnauthorized is returned when the identity lacks the action's capability.
var ErrUnauthorized = errors.New("control: operator lacks required capability")

// ErrReasonRequired is returned when an operator action arrives without a
// justification. An unauditable why is an unauditable action.
var ErrReasonRequired = errors.New("control: operator action requires a reason")

// ErrOperationIDRequired is returned by clustered control planes when a
// mutating request omits the client-owned idempotency key. Without that key an
// ambiguous commit cannot be retried safely after a database failover.
var ErrOperationIDRequired = errors.New("control: idempotency key required")

// ErrOperationIDUnsupported indicates that a caller supplied an idempotency
// key to a mutation store that cannot durably claim it.
var ErrOperationIDUnsupported = errors.New("control: idempotency keys unsupported by mutation store")

// ErrOperationIDInvalid indicates a malformed client-owned idempotency key.
var ErrOperationIDInvalid = errors.New("control: invalid idempotency key")

// ErrOperationConflict indicates that an idempotency key was reused for a
// different operation or payload.
var ErrOperationConflict = errors.New("control: idempotency key payload conflict")

// TokenAuthenticator authenticates operators via bearer tokens. Tokens are
// stored and compared as domain-separated SHA-256 digests — the raw token is never
// retained, so a read of the authenticator's table does not yield usable
// credentials (INV-1). Production deployments back Authenticator with their
// SSO/mTLS stack; this implementation serves as the documented default.
type TokenAuthenticator struct {
	mu     sync.RWMutex
	digest map[string]*Identity // token digest → identity
}

// MinOperatorTokenBytes is the minimum bearer-token length accepted by the
// built-in authenticator. Deployments should use generated values such as
// `openssl rand -base64 32`, not human-chosen passphrases.
const MinOperatorTokenBytes = 32

// NewTokenAuthenticator builds an authenticator from token→identity pairs.
// Empty tokens are rejected: an empty bearer would authenticate anyone.
func NewTokenAuthenticator(tokens map[string]*Identity) (*TokenAuthenticator, error) {
	a := &TokenAuthenticator{digest: make(map[string]*Identity, len(tokens))}
	for tok, id := range tokens {
		if tok == "" {
			return nil, errors.New("control: empty operator token")
		}
		if len([]byte(tok)) < MinOperatorTokenBytes {
			return nil, fmt.Errorf("control: operator token must contain at least %d bytes", MinOperatorTokenBytes)
		}
		if id == nil || id.Name == "" {
			return nil, errors.New("control: operator identity requires a name")
		}
		a.digest[tokenDigest(tok)] = cloneIdentity(id)
	}
	return a, nil
}

// ParseCapability validates and returns one of the capabilities understood by
// the control plane. Configuration must fail closed on typos rather than boot
// with an operator identity that can never authorize its intended action.
func ParseCapability(s string) (Capability, error) {
	capability := Capability(s)
	switch capability {
	case CapCredentialLifecycle, CapLaneLifecycle, CapPosture, CapEvidence, CapPolicyInstall, CapAuditRead, CapClusterRead:
		return capability, nil
	default:
		return "", fmt.Errorf("control: unknown capability %q", s)
	}
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
	return cloneIdentity(id), nil
}

func cloneIdentity(id *Identity) *Identity {
	if id == nil {
		return nil
	}
	return &Identity{Name: id.Name, Capabilities: append([]Capability(nil), id.Capabilities...)}
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

	lanes LaneOperator       // optional lane lifecycle seam
	creds CredentialOperator // optional credential lifecycle seam

	// mutations, when wired, is the transactional mutation+audit authority
	// (P0.18) and takes precedence over the per-action seams above.
	mutations MutationStore

	// posturePersist is an optional transactional posture persist + audit seam
	// (P0.10/P0.18). When wired, SetEmergency persists the posture and its audit
	// row atomically (state store: SetPostureWithAudit) instead of the separate
	// audit-append + in-memory plane flip. A restart then restores the same
	// posture — locking down does not silently vanish on reboot.
	posturePersist func(ctx context.Context, target Posture, actor, reason string) error
	// requireOperationIDs is enabled for the PostgreSQL cluster authority. It
	// is deliberately opt-in so standalone/legacy test seams remain source
	// compatible while clustered mutations fail closed without replay keys.
	requireOperationIDs bool
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

// WithPosturePersister wires the transactional posture persist + audit seam
// (P0.10). fn must commit the posture AND its operator-audit row atomically
// (or reject both) — a failed persist aborts the emergency transition.
func WithPosturePersister(fn func(ctx context.Context, target Posture, actor, reason string) error) ServiceOption {
	return func(s *Service) { s.posturePersist = fn }
}

// WithRequiredOperationIDs makes transactional cluster mutations require a
// client-supplied Idempotency-Key. The key is validated and claimed by the
// operation-aware mutation store.
func WithRequiredOperationIDs() ServiceOption {
	return func(s *Service) { s.requireOperationIDs = true }
}

// MutationStore is the narrow, transactional operator-mutation seam (P0.18,
// defined in the CONSUMER package so the state store never imports control
// semantics it does not need): each action mutates state AND appends its
// operator-audit record in ONE transaction. If either fails, nothing commits —
// a mutation is never durably audited separately from, or in spite of, the
// state change it documents. This is the authority the control plane uses for
// EVERY state-changing action when the deployment is state-backed; the plain
// operator seams (CredentialOperator/LaneOperator + separate audit append)
// remain only for non-durable test/dev wiring.
type MutationStore interface {
	// ProvisionCredentialWithAudit inserts a new credential and its audit row
	// atomically. Existing ids are rejected; provisioning is never replacement.
	ProvisionCredentialWithAudit(ctx context.Context, rec credential.CredentialRecord, audit OperatorRecord) error
	// RevokeCredentialWithAudit revokes a credential and commits its audit row
	// atomically.
	RevokeCredentialWithAudit(ctx context.Context, credID string, audit OperatorRecord) error

	// UnblockLaneWithAudit clears a BLOCKED lane and commits the control
	// plane's audit row atomically.
	UnblockLaneWithAudit(ctx context.Context, credID, laneID string, audit OperatorRecord, now time.Time) error

	// SetPostureWithAudit persists a new operator posture and commits its audit
	// row atomically.
	SetPostureWithAudit(ctx context.Context, posture Posture, audit OperatorRecord) error
}

// OperationMutationStore extends MutationStore with durable operation claims.
// The operation ID is stored in the same transaction as the state mutation and
// its audit row. Implementations must return nil for an exact replay and
// ErrOperationConflict for a reused ID with a different action or payload.
type OperationMutationStore interface {
	ProvisionCredentialWithAuditOperation(ctx context.Context, rec credential.CredentialRecord, audit OperatorRecord, operationID string) error
	RevokeCredentialWithAuditOperation(ctx context.Context, credID string, audit OperatorRecord, operationID string) error
	UnblockLaneWithAuditOperation(ctx context.Context, credID, laneID string, audit OperatorRecord, now time.Time, operationID string) error
	SetPostureWithAuditOperation(ctx context.Context, posture Posture, audit OperatorRecord, operationID string) error
}

// ProvisionCredential adds a verifier-only credential through the authenticated
// lifecycle surface. Raw secrets are intentionally absent from this API.
func (s *Service) ProvisionCredential(ctx context.Context, token string, rec credential.CredentialRecord, reason string) error {
	return s.ProvisionCredentialWithOperationID(ctx, token, rec, reason, "")
}

// ProvisionCredentialWithOperationID is the replay-safe clustered variant of
// ProvisionCredential. operationID is normally the HTTP Idempotency-Key.
func (s *Service) ProvisionCredentialWithOperationID(ctx context.Context, token string, rec credential.CredentialRecord, reason, operationID string) error {
	id, err := s.authorize(ctx, token, CapCredentialLifecycle, reason)
	if err != nil {
		s.record(ctx, "", "credential.add", rec.CredentialID, reason, false, err.Error())
		return err
	}
	ops, err := s.operationMutations(operationID)
	if err != nil {
		s.record(ctx, id.Name, "credential.add", rec.CredentialID, reason, false, err.Error())
		return err
	}
	if s.mutations == nil {
		s.record(ctx, id.Name, "credential.add", rec.CredentialID, reason, false, "no transactional credential provisioner wired")
		return errors.New("control: credential provisioning requires a transactional state store")
	}
	audit := OperatorRecord{
		At: s.now().UTC(), Actor: id.Name, Action: "credential.add", Target: rec.CredentialID,
		Reason: reason, Posture: s.postureString(ctx), Committed: true,
	}
	if err := provisionCredentialMutation(s.mutations, ops, ctx, rec, audit, operationID); err != nil {
		s.record(ctx, id.Name, "credential.add", rec.CredentialID, reason, false, err.Error())
		return err
	}
	return nil
}

// WithMutationStore wires the transactional mutation seam (P0.18). When set,
// it takes precedence over the per-action operator seams: credential revoke,
// lane unblock, and posture set all become single-transaction mutation+audit
// operations against the state authority.
func WithMutationStore(ms MutationStore) ServiceOption {
	return func(s *Service) { s.mutations = ms }
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

// AuthorizeCapability authenticates a read-only operator request and checks its
// capability without creating an audit row. State-changing requests must use
// the reason-bearing methods below so their mutation and audit remain coupled.
func (s *Service) AuthorizeCapability(ctx context.Context, token string, cap Capability) (*Identity, error) {
	id, err := s.auth.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	if err := Authorize(id, cap); err != nil {
		return nil, err
	}
	return id, nil
}

func (s *Service) postureString(ctx context.Context) string {
	posture, err := s.plane.PostureContext(ctx)
	if err != nil {
		return "UNAVAILABLE"
	}
	return posture.String()
}

// record durably commits the operator audit row. Committed=false rows are
// also recorded (a DENIED attempt is exactly what an investigation needs).
func (s *Service) record(ctx context.Context, actor, action, target, reason string, committed bool, detail string) {
	rec := OperatorRecord{
		At:        s.now().UTC(),
		Actor:     actor,
		Action:    action,
		Target:    target,
		Reason:    reason,
		Posture:   s.postureString(ctx),
		Committed: committed,
		Detail:    detail,
	}
	// Best-effort for the RECORD-OF-A-DENIED-ACTION path only; committed
	// actions audit inside the transaction (callers use commitAudit).
	// Preserve the request's values for traceability while detaching cancellation
	// so a client disconnect cannot erase the denied-action record. The timeout
	// bounds the amount of work a failing remote authority may retain.
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = s.audit.AppendOperator(auditCtx, rec)
}

// commitAudit durably commits the record for a COMPLETED action; a failure
// here fails the action contract — callers return err to the operator.
// BETA-11: The mutation MUST succeed before this is called — the audit
// records only facts, never intentions.
func (s *Service) commitAudit(ctx context.Context, actor, action, target, reason string) error {
	return s.audit.AppendOperator(ctx, OperatorRecord{
		At: s.now().UTC(), Actor: actor, Action: action, Target: target,
		Reason: reason, Posture: s.postureString(ctx), Committed: true,
	})
}

// SetEmergency is the authenticated, authorized, durably-audited posture
// switch. On success it also feeds the in-memory plane (which the data plane
// consults) and its bounded audit buffer.
func (s *Service) SetEmergency(ctx context.Context, token string, on bool, reason string) (Posture, error) {
	return s.SetEmergencyWithOperationID(ctx, token, on, reason, "")
}

// SetEmergencyWithOperationID is the replay-safe clustered variant of
// SetEmergency. Replaying an exact committed operation returns the same
// target posture without appending a second mutation audit row.
func (s *Service) SetEmergencyWithOperationID(ctx context.Context, token string, on bool, reason, operationID string) (Posture, error) {
	id, err := s.authorize(ctx, token, CapPosture, reason)
	if err != nil {
		s.record(ctx, "", "posture.set_emergency", "global", reason, false, err.Error())
		return s.plane.Posture(), err
	}
	target := Normal
	if on {
		target = EmergencyLockdown
	}
	ops, err := s.operationMutations(operationID)
	if err != nil {
		s.record(ctx, id.Name, "posture.set_emergency", "global", reason, false, err.Error())
		return s.plane.Posture(), err
	}
	// P0.10/P0.18: when the transactional mutation store is wired, the posture
	// AND its audit row commit atomically — a failed persist aborts the
	// transition. The legacy posturePersist seam behaves identically for
	// deployments that wired only posture; the plain path remains for
	// non-durable test/dev wiring.
	if s.mutations != nil {
		if err := setPostureMutation(s.mutations, ops, ctx, target, OperatorRecord{
			At: s.now().UTC(), Actor: id.Name, Action: "posture.set_emergency",
			Target: "global", Reason: reason, Posture: target.String(), Committed: true,
		}, operationID); err != nil {
			s.record(ctx, id.Name, "posture.set_emergency", "global", reason, false, err.Error())
			return s.plane.Posture(), fmt.Errorf("control: posture persist + audit failed, action aborted: %w", err)
		}
		posture := s.plane.SetEmergency(on, id.Name, reason)
		return posture, nil
	}
	if s.posturePersist != nil {
		if err := s.posturePersist(ctx, target, id.Name, reason); err != nil {
			s.record(ctx, id.Name, "posture.set_emergency", "global", reason, false, err.Error())
			return s.plane.Posture(), fmt.Errorf("control: posture persist + audit failed, action aborted: %w", err)
		}
		posture := s.plane.SetEmergency(on, id.Name, reason)
		return posture, nil
	}
	// The audit row carries the TARGET posture: it documents the action being
	// authorized, and is committed before the plane flips (atomicity rule).
	if err := s.audit.AppendOperator(ctx, OperatorRecord{
		At: s.now().UTC(), Actor: id.Name, Action: "posture.set_emergency",
		Target: "global", Reason: reason, Posture: target.String(), Committed: true,
	}); err != nil {
		s.record(ctx, id.Name, "posture.set_emergency", "global", reason, false, err.Error())
		return s.plane.Posture(), fmt.Errorf("control: audit commit failed, action aborted: %w", err)
	}
	posture := s.plane.SetEmergency(on, id.Name, reason)
	return posture, nil
}

// RevokeCredential revokes a credential under full control-plane discipline.
// When the transactional MutationStore is wired (P0.18), the revocation and
// its audit row commit in ONE transaction — neither lands without the other.
// Otherwise the legacy path applies: mutation FIRST, then audit; a failed
// audit after a successful mutation returns an error but the credential IS
// revoked (the operator sees the failure and can re-audit).
func (s *Service) RevokeCredential(ctx context.Context, token, credID, reason string) error {
	return s.RevokeCredentialWithOperationID(ctx, token, credID, reason, "")
}

// RevokeCredentialWithOperationID is the replay-safe clustered variant of
// RevokeCredential. The operation ID is durable across node/failover retries.
func (s *Service) RevokeCredentialWithOperationID(ctx context.Context, token, credID, reason, operationID string) error {
	id, err := s.authorize(ctx, token, CapCredentialLifecycle, reason)
	if err != nil {
		s.record(ctx, "", "credential.revoke", credID, reason, false, err.Error())
		return err
	}
	ops, err := s.operationMutations(operationID)
	if err != nil {
		s.record(ctx, id.Name, "credential.revoke", credID, reason, false, err.Error())
		return err
	}
	if s.mutations != nil {
		if err := revokeCredentialMutation(s.mutations, ops, ctx, credID, OperatorRecord{
			At: s.now().UTC(), Actor: id.Name, Action: "credential.revoke",
			Target: credID, Reason: reason, Posture: s.postureString(ctx), Committed: true,
		}, operationID); err != nil {
			s.record(ctx, id.Name, "credential.revoke", credID, reason, false, err.Error())
			return err
		}
		return nil
	}
	if s.creds == nil {
		s.record(ctx, id.Name, "credential.revoke", credID, reason, false, "no credential operator wired")
		return errors.New("control: no credential operator wired")
	}
	// BETA-11: Mutation FIRST, then audit. The audit records what HAPPENED,
	// not what was attempted.
	if err := s.creds.Revoke(credID); err != nil {
		s.record(ctx, id.Name, "credential.revoke", credID, reason, false, err.Error())
		return err
	}
	if err := s.commitAudit(ctx, id.Name, "credential.revoke", credID, reason); err != nil {
		return fmt.Errorf("control: audit commit failed after revoke: %w", err)
	}
	return nil
}

// UnblockLane clears a BLOCKED lane under full control-plane discipline. When
// the transactional MutationStore is wired (P0.18), the lane mutation and the
// control plane's audit row commit in ONE transaction. Otherwise the legacy
// path applies: the wired LaneOperator commits the lane audit entry itself
// (P0.49 atomicity), then the control plane commits its own durable row —
// mutation FIRST, then audit, same transactional truthfulness as
// RevokeCredential.
func (s *Service) UnblockLane(ctx context.Context, token, credID, laneID, reason string) error {
	return s.UnblockLaneWithOperationID(ctx, token, credID, laneID, reason, "")
}

// UnblockLaneWithOperationID is the replay-safe clustered variant of
// UnblockLane.
func (s *Service) UnblockLaneWithOperationID(ctx context.Context, token, credID, laneID, reason, operationID string) error {
	id, err := s.authorize(ctx, token, CapLaneLifecycle, reason)
	if err != nil {
		s.record(ctx, "", "lane.unblock", laneID, reason, false, err.Error())
		return err
	}
	ops, err := s.operationMutations(operationID)
	if err != nil {
		s.record(ctx, id.Name, "lane.unblock", laneID, reason, false, err.Error())
		return err
	}
	if s.mutations != nil {
		if err := unblockLaneMutation(s.mutations, ops, ctx, credID, laneID, OperatorRecord{
			At: s.now().UTC(), Actor: id.Name, Action: "lane.unblock",
			Target: credID + "/" + laneID, Reason: reason, Posture: s.postureString(ctx), Committed: true,
		}, s.now(), operationID); err != nil {
			s.record(ctx, id.Name, "lane.unblock", laneID, reason, false, err.Error())
			return err
		}
		return nil
	}
	if s.lanes == nil {
		s.record(ctx, id.Name, "lane.unblock", laneID, reason, false, "no lane operator wired")
		return errors.New("control: no lane operator wired")
	}
	// BETA-11: Mutation FIRST.
	if err := s.lanes.UnblockOperator(credID, laneID, id.Name, reason, s.now()); err != nil {
		s.record(ctx, id.Name, "lane.unblock", laneID, reason, false, err.Error())
		return err
	}
	if err := s.commitAudit(ctx, id.Name, "lane.unblock", laneID, reason); err != nil {
		return fmt.Errorf("control: audit commit failed after unblock: %w", err)
	}
	return nil
}

func (s *Service) operationMutations(operationID string) (OperationMutationStore, error) {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		if s.requireOperationIDs && s.mutations != nil {
			return nil, ErrOperationIDRequired
		}
		return nil, nil
	}
	if s.mutations == nil {
		return nil, ErrOperationIDUnsupported
	}
	ops, ok := s.mutations.(OperationMutationStore)
	if !ok {
		return nil, ErrOperationIDUnsupported
	}
	return ops, nil
}

func provisionCredentialMutation(ms MutationStore, ops OperationMutationStore, ctx context.Context, rec credential.CredentialRecord, audit OperatorRecord, operationID string) error {
	if ops != nil {
		return ops.ProvisionCredentialWithAuditOperation(ctx, rec, audit, operationID)
	}
	return ms.ProvisionCredentialWithAudit(ctx, rec, audit)
}

func revokeCredentialMutation(ms MutationStore, ops OperationMutationStore, ctx context.Context, credID string, audit OperatorRecord, operationID string) error {
	if ops != nil {
		return ops.RevokeCredentialWithAuditOperation(ctx, credID, audit, operationID)
	}
	return ms.RevokeCredentialWithAudit(ctx, credID, audit)
}

func unblockLaneMutation(ms MutationStore, ops OperationMutationStore, ctx context.Context, credID, laneID string, audit OperatorRecord, now time.Time, operationID string) error {
	if ops != nil {
		return ops.UnblockLaneWithAuditOperation(ctx, credID, laneID, audit, now, operationID)
	}
	return ms.UnblockLaneWithAudit(ctx, credID, laneID, audit, now)
}

func setPostureMutation(ms MutationStore, ops OperationMutationStore, ctx context.Context, posture Posture, audit OperatorRecord, operationID string) error {
	if ops != nil {
		return ops.SetPostureWithAuditOperation(ctx, posture, audit, operationID)
	}
	return ms.SetPostureWithAudit(ctx, posture, audit)
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
