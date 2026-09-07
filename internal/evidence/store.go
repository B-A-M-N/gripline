package evidence

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrEvidenceStoreUnavailable signals the evidence backend cannot serve
// snapshots or prunes. Callers must NOT interpret this as an empty evidence
// set (which would mean risk=0). It is a degraded-admission indicator.
var ErrEvidenceStoreUnavailable = errors.New("evidence: store backend unavailable")

// ErrInvalidEvidence signals an Append batch was rejected because an item
// failed validation. The whole batch is stored or none is (atomic) (P0.13).
var ErrInvalidEvidence = errors.New("evidence: invalid evidence item")

// SubjectKey identifies the enforcement scope of an evidence subject.
type SubjectKey struct {
	Scope Scope
	ID    string
}

// Store is the interface for persistent evidence across admission requests.
// Snapshot and Prune return errors so callers can distinguish "no evidence"
// from "backend failure" — a failure must never look like risk=0.
type Store interface {
	// Append persists one or more evidence items. Returns an error if the
	// backend is unavailable or an item is structurally invalid (empty
	// SubjectID, invalid/unknown scope). Invalid items are rejected without
	// consuming the per-subject storage bound.
	Append(items ...Evidence) error

	// Snapshot returns all non-expired evidence for the requested subjects.
	// Returns an error if the backend is unavailable — callers must NOT
	// treat this as an empty evidence set. Returns copies, not internal
	// references.
	Snapshot(subjects []SubjectKey, now time.Time) ([]Evidence, error)

	// Prune removes expired evidence for the requested subjects and returns
	// the count of entries removed and any error. Pruning is optimization
	// only; Snapshot already excludes expired evidence.
	Prune(subjects []SubjectKey, now time.Time) (int, error)
}

const (
	maxEvidencePerSubject = 2048
)

// memoryStore is an in-memory concurrency-safe Store.
type memoryStore struct {
	mu   sync.Mutex
	data map[string][]Evidence // "scope/id" -> evidence items
	now  func() time.Time
}

// NewMemoryStore returns a new in-memory Store.
func NewMemoryStore() Store {
	return &memoryStore{
		data: make(map[string][]Evidence),
		now:  time.Now,
	}
}

func subjectKey(sk SubjectKey) string {
	return sk.Scope.String() + "/" + sk.ID
}

// validate checks the STRUCTURAL well-formedness of evidence before storage
// (P0.13): missing IDs, out-of-range enums, empty code. It deliberately does
// NOT reject valid-but-expired items or items with a CreatedAt that has not yet
// been reached — those are *evaluation* concerns handled by Snapshot/Valid(now),
// and persistence happens independently of evaluation (P0.3). This keeps
// Append safe to persist an item that Snapshot then correctly excludes.
func validate(e Evidence) error {
	if e.SubjectID == "" {
		return fmt.Errorf("evidence: empty SubjectID")
	}
	if e.Scope < ScopeRequest || e.Scope > ScopeGlobal {
		return fmt.Errorf("evidence: invalid scope %d", e.Scope)
	}
	if e.Family < FamilySourceDiscontinuity || e.Family > FamilyOperatorIOC {
		return fmt.Errorf("evidence: invalid family %d", e.Family)
	}
	if e.Code == "" {
		return fmt.Errorf("evidence: empty code")
	}
	if e.EvidenceID == "" {
		return fmt.Errorf("evidence: empty EvidenceID")
	}
	if e.Score < 0 || e.Score > 100 {
		return fmt.Errorf("evidence: invalid score %d", e.Score)
	}
	if e.Confidence < 0 || e.Confidence > 100 {
		return fmt.Errorf("evidence: invalid confidence %d", e.Confidence)
	}
	return nil
}

// Append persists a batch of evidence atomically (P0.13): either EVERY item is
// valid and all are appended, or the first invalid item fails the whole batch
// with ErrInvalidEvidence and NOTHING is stored. It is idempotent: re-appending
// an EvidenceID already present is a no-op (does not duplicate or evict). The
// per-subject bound is enforced by bounded compaction that never evicts
// security-critical (NonEvictable) items (P0.12).
func (s *memoryStore) Append(items ...Evidence) error {
	if len(items) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Atomic gate: validate the WHOLE batch first; one structurally-malformed
	// item rejects all. Valid-but-expired items are persisted (P0.3: persistence
	// is independent) and excluded at Snapshot/evaluation time.
	for _, item := range items {
		if err := validate(item); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidEvidence, err)
		}
	}

	bySubject := make(map[string][]Evidence)
	for _, item := range items {
		k := subjectKey(SubjectKey{Scope: item.Scope, ID: item.SubjectID})
		bySubject[k] = append(bySubject[k], item)
	}
	for k, incoming := range bySubject {
		merged := MergeSubject(s.data[k], incoming, s.now())
		if len(merged) == 0 {
			delete(s.data, k)
			continue
		}
		s.data[k] = merged
	}
	return nil
}

func (s *memoryStore) Snapshot(subjects []SubjectKey, now time.Time) ([]Evidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Evidence, 0)
	for _, sk := range subjects {
		k := subjectKey(sk)
		items, ok := s.data[k]
		if !ok {
			continue
		}
		for i := range items {
			if items[i].Valid(now) {
				e := items[i]
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (s *memoryStore) Prune(subjects []SubjectKey, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var pruned int
	for _, sk := range subjects {
		k := subjectKey(sk)
		items, ok := s.data[k]
		if !ok {
			continue
		}
		kept := make([]Evidence, 0, len(items))
		changed := false
		for i := range items {
			if items[i].Valid(now) {
				kept = append(kept, items[i])
			} else {
				pruned++
				changed = true
			}
		}
		if !changed {
			continue
		}
		if len(kept) == 0 {
			// Remove empty subject entries so keys do not accumulate (P0.13).
			delete(s.data, k)
			continue
		}
		s.data[k] = kept
	}
	return pruned, nil
}

// --- shared store semantics (P0.2-fix) ----------------------------------------
//
// Every Store backend — resident memory, legacy Gob file, and the durable Bolt
// authority — must apply IDENTICAL validation, expiration, and pressure rules.
// These helpers are the one implementation; backends that roll their own drift
// into non-interchangeable behavior (the Gob store hard-erroring at the cap
// while memory priority-compacts was exactly that drift).

// MaxEvidencePerSubject is the per-subject storage bound shared by all
// backends. Exported so durable implementations enforce the same cap instead
// of inventing their own.
const MaxEvidencePerSubject = maxEvidencePerSubject

// ValidateForStore checks the STRUCTURAL well-formedness of evidence before
// storage (P0.13). Shared by every backend: missing IDs, out-of-range enums,
// empty code are rejected; valid-but-expired items are persisted (persistence
// is independent of evaluation, P0.3) and excluded at Snapshot time.
func ValidateForStore(e Evidence) error { return validate(e) }

// IsExpired reports whether ev is expired at now, with the inclusive-invalid
// rule shared across backends: evidence is expired exactly AT ExpiresAt
// (now == ExpiresAt expires), matching Evidence.Valid (P0.14). A zero
// ExpiresAt never expires.
func IsExpired(ev Evidence, now time.Time) bool {
	return !ev.ExpiresAt.IsZero() && !ev.ExpiresAt.After(now)
}

// CompactSubject bounds one subject's evidence via priority compaction (P0.12):
// it drops the oldest NON-critical item when over the cap, but never evicts a
// security-critical (NonEvictable) item through generic pressure. Returns the
// bounded slice. Shared by every backend so pressure behavior is
// interchangeable.
func CompactSubject(list []Evidence) []Evidence {
	out := append([]Evidence(nil), list...)
	for len(out) > maxEvidencePerSubject {
		// Find the oldest EVICTABLE index (non-evictable items are retained).
		oldestEvictable := -1
		for i := range out {
			if out[i].NonEvictable() {
				continue
			}
			if oldestEvictable < 0 || out[i].CreatedAt.Before(out[oldestEvictable].CreatedAt) {
				oldestEvictable = i
			}
		}
		if oldestEvictable < 0 {
			// All items are security-critical; the bound cannot be enforced
			// without dropping authority. Keep them.
			return out
		}
		out = append(out[:oldestEvictable], out[oldestEvictable+1:]...)
	}
	return out
}

// MergeSubject applies the complete append contract for one subject. Expired
// persisted rows are removed before pressure is applied, while incoming rows
// are retained even when already expired so persistence remains independent of
// evaluation. IDs are deduplicated before compaction so duplicate input cannot
// evict unrelated evidence.
func MergeSubject(existing, incoming []Evidence, now time.Time) []Evidence {
	out := make([]Evidence, 0, len(existing)+len(incoming))
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, ev := range existing {
		if IsExpired(ev, now) {
			continue
		}
		if _, ok := seen[ev.EvidenceID]; ok {
			continue
		}
		seen[ev.EvidenceID] = struct{}{}
		out = append(out, ev)
	}
	for _, ev := range incoming {
		if _, ok := seen[ev.EvidenceID]; ok {
			continue
		}
		seen[ev.EvidenceID] = struct{}{}
		out = append(out, ev)
	}
	return CompactSubject(out)
}
