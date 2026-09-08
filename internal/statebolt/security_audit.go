package statebolt

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/control"
)

type persistedSecurityTransition struct {
	SchemaVersion int                              `json:"schema_version"`
	Record        control.SecurityTransitionRecord `json:"record"`
}

const securityTransitionSchemaVersion = 1

// appendSecurityTransitionTx appends a machine-generated security transition
// to the dedicated bucket. The caller owns the surrounding transaction, so a
// state change cannot commit without its transition row.
func appendSecurityTransitionTx(tx *bolt.Tx, rec control.SecurityTransitionRecord) error {
	b := tx.Bucket(bucketSecurityAudit)
	seq := btoi(b.Get(keySecuritySequence)) + 1
	rec.Sequence = seq
	env, err := json.Marshal(persistedSecurityTransition{SchemaVersion: securityTransitionSchemaVersion, Record: rec})
	if err != nil {
		return err
	}
	if err := b.Put(itob(seq), env); err != nil {
		return err
	}
	return b.Put(keySecuritySequence, itob(seq))
}

// ListSecurityTransitions returns automatic security transitions in append
// order for the authenticated admin/read-only surfaces.
func (s *Store) ListSecurityTransitions(after uint64, limit int) ([]control.SecurityTransitionRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var out []control.SecurityTransitionRecord
	err := s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSecurityAudit).Cursor()
		for k, v := c.First(); k != nil && len(out) < limit; k, v = c.Next() {
			if string(k) == string(keySecuritySequence) {
				continue
			}
			if len(k) != 8 {
				return fmt.Errorf("statebolt: corrupt security audit key: %w", ErrMigrationRequired)
			}
			seq := btoi(k)
			if seq <= after {
				continue
			}
			var p persistedSecurityTransition
			if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != securityTransitionSchemaVersion {
				return fmt.Errorf("statebolt: corrupt security audit record: %w", ErrMigrationRequired)
			}
			out = append(out, p.Record)
		}
		return nil
	})
	return out, err
}

// CountSecurityTransitions is a diagnostic/test helper.
func (s *Store) CountSecurityTransitions() (int, error) {
	var n int
	err := s.view(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecurityAudit).ForEach(func(k, _ []byte) error {
			if string(k) != string(keySecuritySequence) {
				n++
			}
			return nil
		})
	})
	return n, err
}
