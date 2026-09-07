package statebolt

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/evidence"
)

// Evidence under the same transactional authority as credentials, lanes, and
// operator state (P0.2-fix). Keys are subjectKey + 0x00 + EvidenceID; rows are
// versioned JSON envelopes. Append/Snapshot/Prune apply the SHARED evidence
// semantics (evidence.ValidateForStore / evidence.IsExpired /
// evidence.CompactSubject) so the Bolt backend is behaviorally
// interchangeable with the resident memory store — not a third dialect.

// persistedEvidence is one versioned evidence row.
type persistedEvidence struct {
	SchemaVersion int               `json:"schema_version"`
	Item          evidence.Evidence `json:"item"`
}

const evidenceSchemaVersion = 1

// compile-time assertion: the Bolt store is a full evidence.Store (P0.2-fix).
var _ evidence.Store = (*Store)(nil)

func evidenceKey(sk evidence.SubjectKey, evidenceID string) ([]byte, error) {
	if sk.ID == "" || evidenceID == "" {
		return nil, errNulInID
	}
	if strings.ContainsRune(sk.ID, 0) || strings.ContainsRune(evidenceID, 0) {
		return nil, errNulInID
	}
	return []byte(sk.Scope.String() + "\x00" + sk.ID + "\x00" + evidenceID), nil
}

func evidencePrefix(sk evidence.SubjectKey) ([]byte, error) {
	if sk.ID == "" || strings.ContainsRune(sk.ID, 0) {
		return nil, errNulInID
	}
	return []byte(sk.Scope.String() + "\x00" + sk.ID + "\x00"), nil
}

// Append implements evidence.Store: the whole batch validates first (atomic
// all-or-nothing), duplicates are idempotent no-ops, and per-subject pressure
// uses the shared priority compaction (never evicting NonEvictable items).
func (s *Store) Append(items ...evidence.Evidence) error {
	if len(items) == 0 {
		return nil
	}
	for _, item := range items {
		if err := evidence.ValidateForStore(item); err != nil {
			return err
		}
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEvidence)
		// Group by subject so compaction runs once per subject after its batch
		// items are appended.
		bySubject := make(map[string][]evidence.Evidence)
		for _, item := range items {
			sk := evidence.SubjectKey{Scope: item.Scope, ID: item.SubjectID}
			k := subjectKeyString(sk)
			bySubject[k] = append(bySubject[k], item)
		}
		for k, batch := range bySubject {
			sk := evidence.SubjectKey{Scope: batch[0].Scope, ID: batch[0].SubjectID}
			existing, err := loadSubjectTx(tx, k)
			if err != nil {
				return err
			}
			for _, item := range batch {
				key, err := evidenceKey(sk, item.EvidenceID)
				if err != nil {
					return err
				}
				if b.Get(key) != nil {
					continue // idempotent: already stored
				}
				existing = append(existing, item)
			}
			compacted := evidence.CompactSubject(existing)
			if len(compacted) != len(existing) {
				// Priority compaction evicted items: delete every stored row
				// that did not survive, then rewrite the survivors (their row
				// content is unchanged; the rewrite keeps rows canonical).
				survive := make(map[string]struct{}, len(compacted))
				for _, item := range compacted {
					survive[item.EvidenceID] = struct{}{}
				}
				prefix := []byte(k + "\x00")
				c := b.Cursor()
				for key, _ := c.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = c.Next() {
					id := evidenceIDFromKey(key, len(prefix))
					if _, keep := survive[id]; !keep {
						if err := b.Delete(append([]byte(nil), key...)); err != nil {
							return err
						}
					}
				}
			}
			for _, item := range compacted {
				if err := putEvidenceTx(tx, item); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Snapshot implements evidence.Store: non-expired evidence for the requested
// subjects, with the shared inclusive-expiry rule.
func (s *Store) Snapshot(subjects []evidence.SubjectKey, now time.Time) ([]evidence.Evidence, error) {
	var out []evidence.Evidence
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, sk := range subjects {
			items, err := loadSubjectTx(tx, subjectKeyString(sk))
			if err != nil {
				return err
			}
			for _, ev := range items {
				if !evidence.IsExpired(ev, now) {
					out = append(out, ev)
				}
			}
		}
		return nil
	})
	return out, err
}

// Prune implements evidence.Store: removes expired evidence for the requested
// subjects and returns the count removed. Empty subjects are deleted so keys
// do not accumulate (P0.13).
func (s *Store) Prune(subjects []evidence.SubjectKey, now time.Time) (int, error) {
	pruned := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEvidence)
		for _, sk := range subjects {
			prefix, err := evidencePrefix(sk)
			if err != nil {
				return err
			}
			type keepRow struct {
				key []byte
				ev  evidence.Evidence
			}
			var kept []keepRow
			c := b.Cursor()
			for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
				var p persistedEvidence
				if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion > evidenceSchemaVersion {
					return errCorruptEvidence
				}
				if evidence.IsExpired(p.Item, now) {
					pruned++
					continue
				}
				keyCopy := append([]byte(nil), k...)
				kept = append(kept, keepRow{key: keyCopy, ev: p.Item})
			}
			if len(kept) == 0 {
				// Delete the subject's rows (may be none — the subject simply
				// does not exist; that is a successful no-op prune).
				c2 := b.Cursor()
				for k, _ := c2.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c2.Next() {
					if err := b.Delete(append([]byte(nil), k...)); err != nil {
						return err
					}
				}
				continue
			}
			for _, row := range kept {
				env, err := json.Marshal(persistedEvidence{SchemaVersion: evidenceSchemaVersion, Item: row.ev})
				if err != nil {
					return err
				}
				if err := b.Put(row.key, env); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return pruned, err
}

// loadSubjectTx loads one subject's evidence rows inside an open transaction.
func loadSubjectTx(tx *bolt.Tx, subjKey string) ([]evidence.Evidence, error) {
	b := tx.Bucket(bucketEvidence)
	prefix := []byte(subjKey + "\x00")
	var out []evidence.Evidence
	c := b.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		var p persistedEvidence
		if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion > evidenceSchemaVersion {
			return nil, errCorruptEvidence
		}
		out = append(out, p.Item)
	}
	return out, nil
}

func putEvidenceTx(tx *bolt.Tx, ev evidence.Evidence) error {
	sk := evidence.SubjectKey{Scope: ev.Scope, ID: ev.SubjectID}
	key, err := evidenceKey(sk, ev.EvidenceID)
	if err != nil {
		return err
	}
	env, err := json.Marshal(persistedEvidence{SchemaVersion: evidenceSchemaVersion, Item: ev})
	if err != nil {
		return err
	}
	return tx.Bucket(bucketEvidence).Put(key, env)
}

func subjectKeyString(sk evidence.SubjectKey) string {
	return sk.Scope.String() + "\x00" + sk.ID
}

// evidenceIDFromKey extracts the EvidenceID segment from a stored key
// (scope\x00id\x00evidenceID) given the subject-prefix length.
func evidenceIDFromKey(key []byte, prefixLen int) string {
	return string(key[prefixLen:])
}

var errCorruptEvidence = errEvidenceCorrupt{}

type errEvidenceCorrupt struct{}

func (errEvidenceCorrupt) Error() string { return "statebolt: corrupt evidence record" }

// CountEvidence returns the total number of stored evidence rows (diagnostics).
func (s *Store) CountEvidence() (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketEvidence).ForEach(func(_, _ []byte) error {
			n++
			return nil
		})
	})
	return n, err
}
