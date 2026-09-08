package statebolt

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/lane"
)

// persistedOperatorRecord is the versioned operator-audit row. It reuses the
// control package's OperatorRecord (already INV-3: no secrets) inside a
// schema-versioned envelope.
type persistedOperatorRecord struct {
	SchemaVersion int                    `json:"schema_version"`
	Record        control.OperatorRecord `json:"record"`
}

const operatorRecordSchemaVersion = 1

// SavePosture durably records the current operator posture so a restart in
// EMERGENCY_LOCKDOWN does not silently boot into NORMAL (P0.10). The posture is
// stored under operator_state/posture.
func (s *Store) SavePosture(p control.Posture) error {
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOperatorState).Put(keyPosture, []byte(strconv.Itoa(int(p))))
	})
}

// LoadPosture restores the persisted operator posture, defaulting to NORMAL
// when none was ever saved (a fresh database starts normal). A corrupted value
// fails closed to an error rather than guessing.
func (s *Store) LoadPosture() (control.Posture, error) {
	var out control.Posture
	err := s.view(func(tx *bolt.Tx) error {
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

// LoadPostureContext implements control.PostureAuthority. bbolt is local and
// does not expose cancellable transactions, so honor cancellation at the
// boundary and preserve the strict persisted-read error semantics.
func (s *Store) LoadPostureContext(ctx context.Context) (control.Posture, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return control.Normal, err
		}
	}
	posture, err := s.LoadPosture()
	if err != nil {
		return control.Normal, err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return control.Normal, err
		}
	}
	return posture, nil
}

// PostureContext implements control.PostureAuthority.
func (s *Store) PostureContext(ctx context.Context) (control.Posture, error) {
	return s.LoadPostureContext(ctx)
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
	return s.update(func(tx *bolt.Tx) error {
		return appendOperatorTx(tx, rec)
	})
}

func appendOperatorTx(tx *bolt.Tx, rec control.OperatorRecord) error {
	audit := tx.Bucket(bucketOperatorAudit)
	seq := btoi(audit.Get(keyAuditSequence))
	seq++
	rec.Sequence = uint64(seq)
	env, err := json.Marshal(persistedOperatorRecord{SchemaVersion: operatorRecordSchemaVersion, Record: rec})
	if err != nil {
		return err
	}
	if err := audit.Put(itob(uint64(seq)), env); err != nil {
		return err
	}
	return audit.Put(keyAuditSequence, itob(uint64(seq)))
}

// The transactional operator-mutation surface (P0.18) is defined by the
// consumer package as control.MutationStore; the *Store implements it with the
// three WithAudit methods below. Each performs the mutation AND its
// operator-audit append in ONE write transaction — a failed audit write fails
// the mutation and vice versa, so the audit trail and the authoritative state
// can never disagree. FileAuditRepository remains only an optional
// mirrored/external sink.

// compile-time assertion that *Store satisfies the transactional seams.
var (
	_ control.AuditRepository = (*Store)(nil)
	_ control.MutationStore   = (*Store)(nil)
)

// ProvisionCredentialWithAudit inserts a new verifier-only credential and its
// operator audit row in one Bolt transaction. Existing ids and verifier
// ownership conflicts fail without changing either index or audit history.
func (s *Store) ProvisionCredentialWithAudit(ctx context.Context, rec credential.CredentialRecord, audit control.OperatorRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rec.Validate(); err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		byVer := tx.Bucket(bucketCredVerifier)
		if creds.Get([]byte(rec.CredentialID)) != nil {
			return credential.ErrAlreadyExists
		}
		key := verKeyFor(rec.PepperVersion, rec.Verifier)
		if owner := byVer.Get([]byte(key)); owner != nil {
			return credential.ErrVerifierOwned
		}
		env, err := json.Marshal(persistedCredential{SchemaVersion: credentialSchemaVersion, Record: rec})
		if err != nil {
			return err
		}
		if err := creds.Put([]byte(rec.CredentialID), env); err != nil {
			return err
		}
		if err := byVer.Put([]byte(key), []byte(rec.CredentialID)); err != nil {
			return err
		}
		return appendOperatorTx(tx, audit)
	})
}

// UnblockLaneWithAudit clears a BLOCKED lane and appends the control plane's
// audit row in a single write transaction (P0.18/P0.49): the lane mutation
// (pure lane.ApplyUnblock semantics), the lane-side audit entry, and the
// control-plane audit row commit together or not at all.
func (s *Store) UnblockLaneWithAudit(ctx context.Context, credID, laneID string, audit control.OperatorRecord, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return ctx.Err()
	}
	key, err := laneKey(credID, laneID)
	if err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLanes).Get(key)
		if v == nil {
			return lane.ErrLaneNotFound
		}
		var p persistedLane
		if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != laneSchemaVersion {
			return errCorruptLane
		}
		rec := p.Record
		before, err := lane.ApplyUnblock(&rec, now)
		if err != nil {
			return err
		}
		if err := appendLaneAuditTx(tx, lane.AuditEntry{
			LaneID: laneID, CredentialID: credID, Actor: audit.Actor,
			Action: lane.ActionUnblock, Before: before, After: lane.LaneNormal,
			At: now, Reason: audit.Reason, Revision: rec.Revision,
		}); err != nil {
			return err // rolls back the whole unblock
		}
		if err := putLaneTx(tx, &rec); err != nil {
			return err
		}
		return appendOperatorTx(tx, audit) // control audit commits in the SAME transaction
	})
}

// RevokeCredentialWithAudit revokes the credential and appends the audit row in
// a single write transaction: a failed audit write fails the revocation and
// vice versa — no mutation-then-audit gap. All failures return from the
// callback so bbolt rolls back atomically (P0.3-fix).
func (s *Store) RevokeCredentialWithAudit(ctx context.Context, credID string, audit control.OperatorRecord) error {
	if err := ctx.Err(); err != nil {
		return ctx.Err()
	}
	return s.update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		env := creds.Get([]byte(credID))
		if env == nil {
			return credential.ErrNotFound
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil || p.SchemaVersion != credentialSchemaVersion {
			return credential.ErrCorrupt
		}
		p.Record.Status = credential.StatusRevoked
		p.Record.Revision++
		p.Record.RotatedAt = s.now()
		b, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if err := creds.Put([]byte(credID), b); err != nil {
			return err
		}
		return appendOperatorTx(tx, audit) // audit commits in the SAME transaction
	})
}

// SetPostureWithAudit persists the posture and appends its audit row atomically.
func (s *Store) SetPostureWithAudit(ctx context.Context, posture control.Posture, audit control.OperatorRecord) error {
	if err := ctx.Err(); err != nil {
		return ctx.Err()
	}
	return s.update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketOperatorState).Put(keyPosture, []byte(strconv.Itoa(int(posture)))); err != nil {
			return err
		}
		return appendOperatorTx(tx, audit) // audit commits in the SAME transaction
	})
}

// CountAuditRecords returns how many operator audit rows are stored (test/diag).
func (s *Store) CountAuditRecords() (int, error) {
	n := 0
	err := s.view(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOperatorAudit).ForEach(func(k, _ []byte) error {
			if string(k) != string(keyAuditSequence) {
				n++
			}
			return nil
		})
	})
	return n, err
}

// ListOperatorAudit returns committed operator records after the supplied
// sequence number in append order. The sequence is a cursor only; record
// contents remain the sanitized control.OperatorRecord envelope.
func (s *Store) ListOperatorAudit(after uint64, limit int) ([]control.OperatorRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var out []control.OperatorRecord
	err := s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketOperatorAudit).Cursor()
		for k, v := c.First(); k != nil && len(out) < limit; k, v = c.Next() {
			if string(k) == string(keyAuditSequence) {
				continue
			}
			if len(k) != 8 {
				return fmt.Errorf("statebolt: corrupt operator audit key: %w", ErrMigrationRequired)
			}
			seq := btoi(k)
			if uint64(seq) <= after {
				continue
			}
			var p persistedOperatorRecord
			if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != operatorRecordSchemaVersion {
				return fmt.Errorf("statebolt: corrupt operator audit record: %w", ErrMigrationRequired)
			}
			p.Record.Sequence = uint64(seq)
			out = append(out, p.Record)
		}
		return nil
	})
	return out, err
}
