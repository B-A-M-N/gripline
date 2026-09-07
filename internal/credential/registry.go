package credential

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"sync"
	"time"
)

// Registry is the credential lookup store. Implementations persist verifiers
// only — never raw keys (INV-1). A production implementation sits on
// PostgreSQL (suggested §76); the in-memory store serves tests and the
// terminator's fast path behind the same interface.
type Registry interface {
	// Lookup resolves a credential record by its credential id.
	Lookup(credentialID string) (*CredentialRecord, bool)

	// FindByVerifier resolves a credential record by the derived verifier for a
	// given pepper version (spec §16: derive verifier → lookup). This is the
	// lookup path used on authentication. Implementations SHOULD index the
	// verifier, which is a one-way digest — raw keys are never indexable.
	FindByVerifier(verifier []byte, pepperVersion int) (*CredentialRecord, bool)

	// Revoke marks a credential revoked and bumps its revision (INV-13).
	Revoke(credentialID string) error

	// BumpRevision increments a credential's monotonic revision (used on any
	// lifecycle mutation so internal assertions minted earlier become stale).
	BumpRevision(credentialID string) error

	// UpdateStatusCAS atomically transitions a credential's status, bumping
	// revision exactly once. Requirements:
	//   - fromStatus must match the current record status (CAS semantics)
	//   - expectedRevision must match the current record revision
	//   - status must not be downgraded from QUARANTINED or REVOKED through
	//     this path (QUARANTINED requires explicit lifecycle action)
	//   - revision is incremented by exactly 1
	//   - returns the authoritative record with updated status and revision
	//   - stale concurrent writers return ErrStaleCAS
	//
	// This is the ONLY state-transition path. Do NOT call BumpRevision
	// separately from this.
	UpdateStatusCAS(credentialID string, expectedRevision int, fromStatus Status, toStatus Status) (*CredentialRecord, error)

	// SecurityStateRepository is embedded so any Registry can serve as the
	// authoritative, atomic security-state store (P0.5/P0.6/P0.20).
	SecurityStateRepository

	// TouchLastSeen records the timestamp of the last authenticated activity.
	// It is analytics-grade: it must NOT be able to fail an admission and is
	// intentionally outside the strong authorization transaction (P0.22). A
	// registry MAY no-op if it does not track last-seen.
	TouchLastSeen(credentialID string, at time.Time)
}

// ErrStaleCAS indicates a concurrent revision conflict — the caller's
// expected revision is older than what's stored.
var ErrStaleCAS = errors.New("credential: stale concurrent CAS")

// ErrNotFound is returned by mutations for absent credentials.
var ErrNotFound = errors.New("credential: not found")

// Typed authentication-lookup errors (P0.28): authentication must distinguish
// "unknown credential" from "registry unavailable/timeout/corrupt". Collapsing
// them means an outage looks like an unknown credential (fail-open to the
// unknown-credential path) or an unknown credential looks like an outage
// (lock the edge on spray traffic).
var (
	// ErrLookupUnavailable is the registry backend being down/degraded. The
	// documented response is the recently-authenticated cache + fail closed
	// for credentials not in that cache.
	ErrLookupUnavailable = errors.New("credential: registry unavailable")
	// ErrLookupTimeout is a bounded-time lookup that exceeded its budget.
	ErrLookupTimeout = errors.New("credential: registry lookup timed out")
	// ErrLookupCorrupt is durable state that cannot be decoded/validated.
	ErrLookupCorrupt = errors.New("credential: registry state corrupt")
)

// VerifierLookup is the production authentication-lookup seam (P0.28): a
// Registry implementation MAY additionally implement it. Unlike
// FindByVerifier (which folds outage into "not found" via a bool), it returns
// typed errors so the terminator can treat UNKNOWN, UNAVAILABLE, TIMEOUT, and
// CORRUPT as distinct failure classes — an outage must never masquerade as an
// unknown credential.
type VerifierLookup interface {
	FindByVerifierContext(ctx context.Context, verifier []byte, pepperVersion int) (*CredentialRecord, error)
}

// IsUnknownCredential reports whether err is the typed "no such credential"
// answer from a VerifierLookup (as opposed to an outage/timeouts/corruption).
func IsUnknownCredential(err error) bool { return errors.Is(err, ErrNotFound) }

// ErrVerifierOwned is returned when an insert would map a verifier to a
// credential id that already owns a different verifier under the same pepper
// version. Two live credentials must never share a verifier — it would let
// one credential authenticate as another.
var ErrVerifierOwned = errors.New("credential: verifier already owned by another credential")

// Provisioner is the startup-provisioning seam (P0.10). Bootstrap uses
// InsertIfAbsent so an env-provided GRIPLINE_CREDENTIAL_SECRET never overwrites
// an operator-managed (e.g. CONSTRAINED/REVOKED) credential on restart.
// Rotation/replacement is the explicit lifecycle path (Insert / UpdateStatusCAS),
// not bootstrap.
type Provisioner interface {
	InsertIfAbsent(rec *CredentialRecord) (created bool, err error)
}

// MemoryRegistry is a concurrency-safe in-memory Registry. For development and
// tests only; not durable.
type MemoryRegistry struct {
	mu      sync.RWMutex
	records map[string]*CredentialRecord
	byVer   map[string]string // "pepVer/verifierB64" -> credentialID
	now     func() time.Time
}

// NewMemoryRegistry builds an empty in-memory registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{
		records: make(map[string]*CredentialRecord),
		byVer:   make(map[string]string),
		now:     time.Now,
	}
}

// Insert adds a record, or replaces an existing record for the same
// credential id. Replacement is rotation: the PREVIOUS verifier's index entry
// is removed in the same critical section, so a replaced credential's old
// verifier can never remain an authentication path (a stale index here is
// exactly the rotation failure INV-13 guards against). Verifiers are never
// indexed raw — the index key is pepper-versioned. Conflicting verifier
// ownership (another credential already holds this verifier under the same
// pepper version) is rejected.
func (m *MemoryRegistry) Insert(rec *CredentialRecord) error {
	if rec == nil {
		return errors.New("credential: nil record")
	}
	// Refuse malformed records rather than letting them occupy storage
	// (P0.17): unknown verifier algorithm, empty verifier, revision < 1.
	if err := rec.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	newKey := ""
	if len(rec.Verifier) > 0 {
		newKey = verKeyFor(rec.PepperVersion, rec.Verifier)
		if owner, taken := m.byVer[newKey]; taken && owner != rec.CredentialID {
			return ErrVerifierOwned
		}
	}

	if prev, exists := m.records[rec.CredentialID]; exists && len(prev.Verifier) > 0 {
		prevKey := verKeyFor(prev.PepperVersion, prev.Verifier)
		if prevKey != newKey { // same-key replacement keeps its index entry
			delete(m.byVer, prevKey)
		}
	}

	// Clone verifier bytes so the caller and the registry never alias the same
	// slice; a post-insert mutation must not diverge the byVer index from the
	// stored record (P0.17).
	c := cloneRecord(rec)
	m.records[rec.CredentialID] = c
	if newKey != "" {
		m.byVer[newKey] = rec.CredentialID
	}
	return nil
}

// InsertIfAbsent implements credential.Provisioner (P0.10): it creates the
// credential ONLY if one with that id is not already present, returning
// created=false when present. Startup bootstrap MUST use this so an env-provided
// credential never overwrites an operator-managed (e.g. CONSTRAINED/REVOKED)
// credential on every restart.
func (m *MemoryRegistry) InsertIfAbsent(rec *CredentialRecord) (bool, error) {
	if rec == nil {
		return false, errors.New("credential: nil record")
	}
	if err := rec.Validate(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.records[rec.CredentialID]; exists {
		return false, nil // already present — leave untouched
	}
	newKey := ""
	if len(rec.Verifier) > 0 {
		newKey = verKeyFor(rec.PepperVersion, rec.Verifier)
		if owner, taken := m.byVer[newKey]; taken && owner != rec.CredentialID {
			return false, ErrVerifierOwned
		}
	}
	c := cloneRecord(rec)
	m.records[rec.CredentialID] = c
	if newKey != "" {
		m.byVer[newKey] = rec.CredentialID
	}
	return true, nil
}

// Lookup implements SecurityStateRepository with typed errors (P0.20): the
// caller can distinguish ErrNotFound (credential absent) from the outage classes.
func (m *MemoryRegistry) LookupAuthoritative(ctx context.Context, credentialID string) (*CredentialRecord, error) {
	rec, ok := m.Lookup(credentialID)
	if !ok {
		return nil, ErrNotFound
	}
	_ = ctx
	return rec, nil
}

// ObserveAndCommit implements the authoritative, atomic risk-observation apply
// (P0.5/P0.6/P0.44). It loads the credential + its persisted SecurityState,
// reduces one observation via the pure transition function, and if the status
// changed, CASes status/security/revision all in one critical section with a
// single revision bump. No change leaves the record untouched (NoChange). A
// stale revision or concurrent writer yields Conflict.
//
// The in-memory registry is non-failing, so Unavailable is never produced here;
// a durable/remote implementation returns it on outage (M6). The caller of a
// remote registry must treat Unavailable as fail-safe, never as risk=0.
func (m *MemoryRegistry) ObserveAndCommit(
	ctx context.Context,
	credentialID string,
	score int,
	hy Hysteresis,
	now time.Time,
) (TransitionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.records[credentialID]
	if !ok {
		return TransitionResult{}, ErrNotFound
	}

	before := cloneRecord(rec)
	reduced := ReduceTransition(hy, rec.Status, rec.Security, score, now)

	if !reduced.Changed {
		// Observation applied but no status change: persist only the security
		// state (risk score, streaks, timestamps) — the durable hysteresis
		// record must reflect the observation even when status is stable. This
		// does not bump Revision (no lifecycle transition; P0.44 keeps one
		// bump per state mutation).
		rec.Security = reduced.Next
		return TransitionResult{
			Status: TransitionNoChange,
			Before: before,
			Record: cloneRecord(rec),
		}, nil
	}

	// Status changed — serial CAS: guard against a stale concurrent transition.
	if rec.Revision != before.Revision {
		return TransitionResult{}, ErrStaleCAS
	}
	if rec.Status != before.Status {
		return TransitionResult{}, ErrStaleCAS
	}
	// QUARANTINED and REVOKED never automatically downgrade through admission.
	if rec.Status == StatusQuarantined || rec.Status == StatusRevoked {
		return TransitionResult{}, errors.New("credential: terminal/elevated state cannot be transitioned through admission")
	}

	rec.Status = reduced.Status
	rec.Security = reduced.Next
	rec.Revision++
	rec.Security.LastStateChangeAt = now
	rec.RotatedAt = now // preserved: RotatedAt is the last lifecycle mutation time
	return TransitionResult{
		Status: TransitionCommitted,
		Before: before,
		Record: cloneRecord(rec),
	}, nil
}

// verKeyFor derives the index key (pepper version + verifier). The verifier is
// a one-way digest; safe to index under the registry's own namespace.
func verKeyFor(pepperVersion int, verifier []byte) string {
	return strconv.Itoa(pepperVersion) + "/" + base64.StdEncoding.EncodeToString(verifier)
}

// Lookup returns a copy of the record for the id.
func (m *MemoryRegistry) Lookup(credentialID string) (*CredentialRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.records[credentialID]
	if !ok {
		return nil, false
	}
	return cloneRecord(rec), true
}

// FindByVerifier resolves a record by derived verifier + pepper version. It
// DEFENSIVELY re-checks that the resolved record's current verifier and
// pepper version match the lookup inputs: the index is an optimization, and
// the record's own verifier fields are authoritative. A stale index entry
// (e.g. from a concurrent rotation, or any future index bug) fails closed
// instead of authenticating a replaced credential.
func (m *MemoryRegistry) FindByVerifier(verifier []byte, pepperVersion int) (*CredentialRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byVer[verKeyFor(pepperVersion, verifier)]
	if !ok {
		return nil, false
	}
	rec, ok := m.records[id]
	if !ok {
		return nil, false
	}
	if rec.PepperVersion != pepperVersion || !bytes.Equal(rec.Verifier, verifier) {
		return nil, false
	}
	return cloneRecord(rec), true
}

// FindByVerifierContext implements the typed-error lookup seam (P0.28). The
// memory registry is always available, so it distinguishes only
// ErrNotFound (unknown credential) from success; a durable implementation
// maps its backend failures to ErrLookupUnavailable/Timeout/Corrupt.
func (m *MemoryRegistry) FindByVerifierContext(ctx context.Context, verifier []byte, pepperVersion int) (*CredentialRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrLookupTimeout
	}
	if rec, ok := m.FindByVerifier(verifier, pepperVersion); ok {
		return rec, nil
	}
	return nil, ErrNotFound
}

func cloneRecord(rec *CredentialRecord) *CredentialRecord {
	c := *rec
	if rec.Verifier != nil {
		c.Verifier = append([]byte(nil), rec.Verifier...)
	}
	return &c
}

// TouchLastSeen updates LastSeenAt. Best-effort and out of the critical path:
// a record absent here is not an error the admission loop must handle (P0.22).
func (m *MemoryRegistry) TouchLastSeen(credentialID string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[credentialID]
	if !ok {
		return
	}
	rec.LastSeenAt = at
}

// Revoke marks a credential revoked and bumps revision.
func (m *MemoryRegistry) Revoke(credentialID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[credentialID]
	if !ok {
		return ErrNotFound
	}
	rec.Status = StatusRevoked
	rec.Revision++
	rec.RotatedAt = m.now()
	return nil
}

// BumpRevision increments a credential's revision.
func (m *MemoryRegistry) BumpRevision(credentialID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[credentialID]
	if !ok {
		return ErrNotFound
	}
	rec.Revision++
	return nil
}

// UpdateStatusCAS atomically transitions status, incrementing revision by 1.
// Rejected if:
//   - credential not found
//   - expectedRevision != current revision
//   - fromStatus != current status
//   - fromStatus is QUARANTINED (no automatic downgrade)
//   - fromStatus is REVOKED (terminal)
//   - toStatus is REVOKED → allowed (escalation is fine)
//   - toStatus == fromStatus → rejected (no-op transition)
func (m *MemoryRegistry) UpdateStatusCAS(credentialID string, expectedRevision int, fromStatus, toStatus Status) (*CredentialRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.records[credentialID]
	if !ok {
		return nil, ErrNotFound
	}
	if rec.Revision != expectedRevision {
		return nil, ErrStaleCAS
	}
	if rec.Status != fromStatus {
		return nil, ErrStaleCAS
	}
	if toStatus == fromStatus {
		return nil, errors.New("credential: no status change requested")
	}
	// QUARANTINED never automatically downgrades.
	if fromStatus == StatusQuarantined {
		return nil, errors.New("credential: quarantined status cannot be downgraded through admission")
	}
	// REVOKED is terminal — nothing can exit it.
	if fromStatus == StatusRevoked {
		return nil, errors.New("credential: revoked is terminal")
	}

	rec.Status = toStatus
	rec.Revision++
	rec.RotatedAt = m.now()
	c := cloneRecord(rec)
	return c, nil
}

// Summary is a credential's operator-facing view (CLI/diagnostics, P1-26).
// It never carries verifier material — only identity, state, and bookkeeping.
type Summary struct {
	CredentialID string    `json:"credential_id"`
	AccountID    string    `json:"account_id"`
	Status       string    `json:"status"`
	PolicyID     string    `json:"policy_id"`
	PlanID       string    `json:"plan_id"`
	CreatedAt    time.Time `json:"created_at"`
	Revision     int       `json:"revision"`
}

// Lister is the optional enumeration seam for operator tooling: list every
// credential's summary. Implemented by the durable store; the memory registry
// does not implement it (ephemeral mode has nothing worth listing).
type Lister interface {
	ListCredentials() ([]Summary, error)
}
