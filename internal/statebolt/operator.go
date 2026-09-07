package statebolt

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
)

// persistedOperatorRecord is the versioned operator-audit row. It reuses the
// control package's OperatorRecord (already INV-3: no secrets) inside a
// schema-versioned envelope.
type persistedOperatorRecord struct {
	SchemaVersion int
	Record        control.OperatorRecord
}

const operatorRecordSchemaVersion = 1

// SavePosture durably records the current operator posture so a restart in
// EMERGENCY_LOCKDOWN does not silently boot into NORMAL (P0.10). The posture is
// stored under operator_state/posture.
func (s *Store) SavePosture(p control.Posture) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOperatorState).Put(keyPosture, []byte(strconv.Itoa(int(p))))
	})
}

// LoadPosture restores the persisted operator posture, defaulting to NORMAL
// when none was ever saved (a fresh database starts normal). A corrupted value
// fails closed to an error rather than guessing.
func (s *Store) LoadPosture() (control.Posture, error) {
	var out control.Posture
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketOperatorState).Get(keyPosture)
		if v == nil {
			out = control.Normal
			return nil
		}
		n, err := strconv.Atoi(string(v))
		if err != nil {
			return fmt.Errorf("statebolt: corrupt persisted posture %q: %w", v, err)
		}
		if n < int(control.Normal) || n > int(control.EmergencyLockdown) {
			return fmt.Errorf("statebolt: unknown persisted posture %d", n)
		}
		out = control.Posture(n)
		return nil
	})
	return out, err
}

// AppendOperator implements control.AuditRepository for the Bolt store (an
// alternative to FileAuditRepository): every operator row is appended into the
// operator_audit bucket. This is the durable audit sink the control plane can
// use when the deployment backs its state on the same Bolt database.
//
// Unlike the JSONL file sink, audit rows written through the Bolt store share
// its transaction, so a mutation committed together with its audit row (the
// MutationStore seam below, P0.18) fails or commits atomically.
func (s *Store) AppendOperator(_ context.Context, rec control.OperatorRecord) error {
	return s.appendOperator(rec)
}

// appendOperator writes one audit row under a monotonically increasing sequence
// (big-endian key → chronological order). Called inside an already-open write
// transaction by transactional mutations, or on its own for standalone records.
func (s *Store) appendOperator(rec control.OperatorRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return appendOperatorTx(tx, rec)
	})
}

func appendOperatorTx(tx *bolt.Tx, rec control.OperatorRecord) error {
	audit := tx.Bucket(bucketOperatorAudit)
	seq := btoi(audit.Get(keyAuditSequence))
	seq++
	env, err := json.Marshal(persistedOperatorRecord{SchemaVersion: operatorRecordSchemaVersion, Record: rec})
	if err != nil {
		return err
	}
	if err := audit.Put(itob(uint64(seq)), env); err != nil {
		return err
	}
	return audit.Put(keyAuditSequence, itob(uint64(seq)))
}

// MutationStore is the narrow, transactional operator-mutation seam (P0.18):
// each action mutates state AND appends its operator-audit record in ONE
// transaction. If either fails, nothing commits — a mutation is never durably
// audited separately from, or in spite of, the state change it documents. This
// is the authority the control plane should use for state-changing actions;
// FileAuditRepository remains only an optional mirrored/external sink.
//
// The concrete *Store implements this surface via the methods below.
type MutationStore interface {
	// RevokeCredentialWithAudit revokes a credential and commits its audit row
	// atomically. Provided for the transaction boundary used by the control
	// plane's CredentialOperator seam.
	RevokeCredentialWithAudit(ctx context.Context, credID string, audit control.OperatorRecord) error

	// SetPostureWithAudit persists a new operator posture and commits its audit
	// row atomically.
	SetPostureWithAudit(ctx context.Context, posture control.Posture, audit control.OperatorRecord) error
}

// compile-time assertion that *Store satisfies the transactional seams.
var (
	_ control.AuditRepository = (*Store)(nil)
	_ MutationStore           = (*Store)(nil)
)

// RevokeCredentialWithAudit revokes the credential and appends the audit row in
// a single write transaction: a failed audit write fails the revocation and
// vice versa — no mutation-then-audit gap.
func (s *Store) RevokeCredentialWithAudit(ctx context.Context, credID string, audit control.OperatorRecord) error {
	if err := ctx.Err(); err != nil {
		return ctx.Err()
	}
	var outErr error
	err := s.db.Update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		env := creds.Get([]byte(credID))
		if env == nil {
			outErr = credential.ErrNotFound
			return nil
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil {
			outErr = credential.ErrCorrupt
			return nil
		}
		p.Record.Status = credential.StatusRevoked
		p.Record.Revision++
		p.Record.RotatedAt = s.now()
		b, err := json.Marshal(p)
		if err != nil {
			outErr = err
			return nil
		}
		if err := creds.Put([]byte(credID), b); err != nil {
			outErr = err
			return nil
		}
		return appendOperatorTx(tx, audit) // audit commits in the SAME transaction
	})
	if err != nil {
		return err
	}
	return outErr
}

// SetPostureWithAudit persists the posture and appends its audit row atomically.
func (s *Store) SetPostureWithAudit(ctx context.Context, posture control.Posture, audit control.OperatorRecord) error {
	if err := ctx.Err(); err != nil {
		return ctx.Err()
	}
	var outErr error
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketOperatorState).Put(keyPosture, []byte(strconv.Itoa(int(posture)))); err != nil {
			outErr = err
			return nil
		}
		return appendOperatorTx(tx, audit) // audit commits in the SAME transaction
	})
	if err != nil {
		return err
	}
	return outErr
}

// CountAuditRecords returns how many operator audit rows are stored (test/diag).
func (s *Store) CountAuditRecords() (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOperatorAudit).ForEach(func(k, _ []byte) error {
			if string(k) != string(keyAuditSequence) {
				n++
			}
			return nil
		})
	})
	return n, err
}
