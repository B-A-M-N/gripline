package credential

import (
	"bytes"
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
}

// ErrNotFound is returned by mutations for absent credentials.
var ErrNotFound = errors.New("credential: not found")

// ErrVerifierOwned is returned when an insert would map a verifier to a
// credential id that already owns a different verifier under the same pepper
// version. Two live credentials must never share a verifier — it would let
// one credential authenticate as another.
var ErrVerifierOwned = errors.New("credential: verifier already owned by another credential")

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

	c := *rec
	m.records[rec.CredentialID] = &c
	if newKey != "" {
		m.byVer[newKey] = rec.CredentialID
	}
	return nil
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

func cloneRecord(rec *CredentialRecord) *CredentialRecord {
	c := *rec
	if rec.Verifier != nil {
		c.Verifier = append([]byte(nil), rec.Verifier...)
	}
	return &c
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
