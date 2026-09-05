package credential

import (
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

// Insert adds (or replaces) a record. The verifier must already be derived.
// Indexes the verifier for FindByVerifier; raw keys are never indexed.
func (m *MemoryRegistry) Insert(rec *CredentialRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *rec
	m.records[rec.CredentialID] = &c
	if rec.Verifier != nil {
		m.byVer[verKeyFor(rec.PepperVersion, rec.Verifier)] = rec.CredentialID
	}
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

// FindByVerifier resolves a record by derived verifier + pepper version.
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