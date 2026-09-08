package statebolt

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/evidence"
)

// Evidence under the same transactional authority as credentials, lanes, and
// operator state (P0.2-fix). Keys are subjectKey + 0x00 + EvidenceID; rows are
// versioned JSON envelopes. Append/Snapshot/Prune apply the SHARED evidence
// semantics (evidence.ValidateForStore / evidence.MergeSubject /
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
	return s.update(func(tx *bolt.Tx) error {
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
				if _, err := evidenceKey(sk, item.EvidenceID); err != nil {
					return err
				}
			}
			merged := evidence.MergeSubject(existing, batch, s.now())
			// Delete every persisted row that did not survive the shared merge.
			// This also removes expired rows and any duplicate rows written by an
			// older implementation, even when the resulting count is unchanged.
			survive := make(map[string]struct{}, len(merged))
			for _, item := range merged {
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
			for _, item := range merged {
				if err := putEvidenceTx(tx, item); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Store) AppendContext(ctx context.Context, items ...evidence.Evidence) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	return s.Append(items...)
}

// Snapshot implements evidence.Store: non-expired evidence for the requested
// subjects, with the shared inclusive-expiry rule.
func (s *Store) Snapshot(subjects []evidence.SubjectKey, now time.Time) ([]evidence.Evidence, error) {
	var out []evidence.Evidence
	err := s.view(func(tx *bolt.Tx) error {
		for _, sk := range subjects {
			items, err := loadSubjectTx(tx, subjectKeyString(sk))
			if err != nil {
				return err
			}
			for _, ev := range items {
				if ev.Valid(now) {
					out = append(out, ev)
				}
			}
		}
		return nil
	})
	return out, err
}

func (s *Store) SnapshotContext(ctx context.Context, subjects []evidence.SubjectKey, now time.Time) ([]evidence.Evidence, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	return s.Snapshot(subjects, now)
}

// Prune implements evidence.Store: removes expired evidence for the requested
// subjects and returns the count removed. Empty subjects are deleted so keys
// do not accumulate (P0.13).
func (s *Store) Prune(subjects []evidence.SubjectKey, now time.Time) (int, error) {
	pruned := 0
	err := s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEvidence)
		for _, sk := range subjects {
			prefix, err := evidencePrefix(sk)
			if err != nil {
				return err
			}
			var deleteKeys [][]byte
			c := b.Cursor()
			for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
				var p persistedEvidence
				if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != evidenceSchemaVersion {
					return errCorruptEvidence
				}
				if !p.Item.Valid(now) {
					pruned++
					deleteKeys = append(deleteKeys, append([]byte(nil), k...))
					continue
				}
			}
			for _, key := range deleteKeys {
				if err := b.Delete(key); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return pruned, err
}

func (s *Store) PruneContext(ctx context.Context, subjects []evidence.SubjectKey, now time.Time) (int, error) {
	if err := contextErr(ctx); err != nil {
		return 0, err
	}
	return s.Prune(subjects, now)
}

// loadSubjectTx loads one subject's evidence rows inside an open transaction.
func loadSubjectTx(tx *bolt.Tx, subjKey string) ([]evidence.Evidence, error) {
	b := tx.Bucket(bucketEvidence)
	prefix := []byte(subjKey + "\x00")
	var out []evidence.Evidence
	c := b.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		var p persistedEvidence
		if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != evidenceSchemaVersion {
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
	err := s.view(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketEvidence).ForEach(func(_, _ []byte) error {
			n++
			return nil
		})
	})
	return n, err
}

// EvidenceSweepStats reports bounded global evidence-maintenance activity.
type EvidenceSweepStats struct {
	Scanned     uint64
	Deleted     uint64
	LastSuccess time.Time
	LastError   string
}

// SweepExpiredEvidence removes expired rows across all subjects with a bounded
// cursor. Unlike Prune, it eventually reaches one-shot sources that no longer
// participate in traffic. The cursor is retained in memory and resets after a
// complete pass.
func (s *Store) SweepExpiredEvidence(now time.Time, batch int) (int, error) {
	if batch <= 0 {
		batch = 256
	}
	s.evidenceSweepMu.Lock()
	defer s.evidenceSweepMu.Unlock()
	var deleted int
	err := s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEvidence)
		c := b.Cursor()
		var k, v []byte
		if len(s.evidenceSweepAfter) == 0 {
			k, v = c.First()
		} else {
			k, v = c.Seek(s.evidenceSweepAfter)
			if k != nil && bytes.Equal(k, s.evidenceSweepAfter) {
				k, v = c.Next()
			}
		}
		var remove [][]byte
		processed := 0
		for k != nil && processed < batch {
			last := append([]byte(nil), k...)
			var p persistedEvidence
			if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != evidenceSchemaVersion {
				return errCorruptEvidence
			}
			processed++
			if !p.Item.Valid(now) {
				remove = append(remove, last)
			}
			s.evidenceSweepAfter = last
			k, v = c.Next()
		}
		for _, key := range remove {
			if err := b.Delete(key); err != nil {
				return err
			}
			deleted++
		}
		if k == nil {
			s.evidenceSweepAfter = nil
		}
		s.evidenceSweepStats.Scanned += uint64(processed)   // #nosec G115 -- processed is a non-negative bounded page count.
		s.evidenceSweepStats.Deleted += uint64(len(remove)) // #nosec G115 -- remove length is a non-negative bounded page count.
		return nil
	})
	if err == nil {
		s.evidenceSweepStats.LastSuccess = s.now()
		s.evidenceSweepStats.LastError = ""
	} else {
		s.evidenceSweepStats.LastError = err.Error()
	}
	return deleted, err
}

// EvidenceSweepStats returns maintenance counters without exposing evidence
// contents or subject identifiers.
func (s *Store) EvidenceSweepStats() EvidenceSweepStats {
	s.evidenceSweepMu.Lock()
	defer s.evidenceSweepMu.Unlock()
	return s.evidenceSweepStats
}
