package statebolt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/credential"
)

// persistedCredential is the versioned on-disk envelope for a credential row.
// The record carries the verifier (a one-way digest, INV-1) — never a raw key.
type persistedCredential struct {
	SchemaVersion int                         `json:"schema_version"`
	Record        credential.CredentialRecord `json:"record"`
}

// schemaVersion for the credential envelope. Bump + migrate if CredentialRecord
// changes shape in a way old rows cannot be read.
const credentialSchemaVersion = 1

// Insert implements credential.Registry. It replaces (rotates) a credential's
// row in ONE transaction: the previous verifier's index entry is removed under
// the same lock that writes the new one, so a replaced credential's old
// verifier can never remain an authentication path. Verifier ownership
// conflicts (another credential holding this verifier) are rejected.
func (s *Store) Insert(rec *credential.CredentialRecord) error {
	if rec == nil {
		return errors.New("credential: nil record")
	}
	if err := rec.Validate(); err != nil {
		return err
	}
	var outErr error
	s.db.Update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		byVer := tx.Bucket(bucketCredVerifier)

		newKey := ""
		if len(rec.Verifier) > 0 {
			newKey = verKeyFor(rec.PepperVersion, rec.Verifier)
			if owner := byVer.Get([]byte(newKey)); owner != nil {
				if string(owner) != rec.CredentialID {
					outErr = credential.ErrVerifierOwned
					return nil
				}
			}
		}
		if prev := creds.Get([]byte(rec.CredentialID)); prev != nil {
			var old persistedCredential
			if err := json.Unmarshal(prev, &old); err != nil {
				outErr = credential.ErrCorrupt
				return nil
			}
			if len(old.Record.Verifier) > 0 {
				oldKey := verKeyFor(old.Record.PepperVersion, old.Record.Verifier)
				if oldKey != newKey { // same-key replacement keeps its index entry
					if err := byVer.Delete([]byte(oldKey)); err != nil {
						outErr = err
						return nil
					}
				}
			}
		}
		env, err := json.Marshal(persistedCredential{SchemaVersion: credentialSchemaVersion, Record: *rec})
		if err != nil {
			outErr = err
			return nil
		}
		if err := creds.Put([]byte(rec.CredentialID), env); err != nil {
			outErr = err
			return nil
		}
		if newKey != "" {
			return byVer.Put([]byte(newKey), []byte(rec.CredentialID))
		}
		return nil
	})
	return outErr
}

// InsertIfAbsent implements provisioning (P0.10/§6): it creates the credential
// ONLY if one with that id does not already exist, returning created=false when
// present. Startup bootstrap MUST use this so GRIPLINE_CREDENTIAL_SECRET never
// overwrites an operator-managed (e.g. CONSTRAINED/REVOKED) credential on
// every restart. Credential rotation/replacement is the explicit lifecycle path
// (Insert / UpdateStatusCAS), not bootstrap.
func (s *Store) InsertIfAbsent(rec *credential.CredentialRecord) (bool, error) {
	if rec == nil {
		return false, errors.New("credential: nil record")
	}
	if err := rec.Validate(); err != nil {
		return false, err
	}
	var created bool
	var outErr error
	err := s.db.Update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		byVer := tx.Bucket(bucketCredVerifier)
		if creds.Get([]byte(rec.CredentialID)) != nil {
			return nil // already present — leave untouched
		}
		if len(rec.Verifier) > 0 {
			k := verKeyFor(rec.PepperVersion, rec.Verifier)
			if owner := byVer.Get([]byte(k)); owner != nil && string(owner) != rec.CredentialID {
				outErr = credential.ErrVerifierOwned
				return nil
			}
		}
		env, err := json.Marshal(persistedCredential{SchemaVersion: credentialSchemaVersion, Record: *rec})
		if err != nil {
			outErr = err
			return nil
		}
		if err := creds.Put([]byte(rec.CredentialID), env); err != nil {
			outErr = err
			return nil
		}
		if len(rec.Verifier) > 0 {
			if err := byVer.Put([]byte(verKeyFor(rec.PepperVersion, rec.Verifier)), []byte(rec.CredentialID)); err != nil {
				outErr = err
				return nil
			}
		}
		created = true
		return nil
	})
	if err != nil {
		return created, err
	}
	return created, outErr
}

// Lookup implements credential.Registry: resolve a record by id, inside a
// read transaction.
func (s *Store) Lookup(credentialID string) (*credential.CredentialRecord, bool) {
	rec, err := s.lookup(credentialID)
	if err != nil || rec == nil {
		return nil, false
	}
	return rec, true
}

// LookupAuthoritative implements credential.SecurityStateRepository.
func (s *Store) LookupAuthoritative(ctx context.Context, credentialID string) (*credential.CredentialRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, credential.ErrLookupTimeout
	}
	rec, err := s.lookup(credentialID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, credential.ErrNotFound
	}
	return rec, nil
}

func (s *Store) lookup(credentialID string) (*credential.CredentialRecord, error) {
	var rec *credential.CredentialRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		env := tx.Bucket(bucketCredentials).Get([]byte(credentialID))
		if env == nil {
			return nil
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil {
			return credential.ErrCorrupt
		}
		r := p.Record
		r.Verifier = append([]byte(nil), p.Record.Verifier...)
		rec = &r
		return nil
	})
	return rec, err
}

// FindByVerifier implements credential.Registry: resolve by indexed verifier.
// Defensively re-checks the resolved record: the index is an optimization, and
// the record's own verifier fields are authoritative (a stale index fails
// closed rather than authenticating a replaced credential).
func (s *Store) FindByVerifier(verifier []byte, pepperVersion int) (*credential.CredentialRecord, bool) {
	rec, err := s.lookupByVerifier(verifier, pepperVersion)
	if err != nil || rec == nil {
		return nil, false
	}
	return rec, true
}

// FindByVerifierContext implements credential.VerifierLookup with typed errors.
func (s *Store) FindByVerifierContext(ctx context.Context, verifier []byte, pepperVersion int) (*credential.CredentialRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, credential.ErrLookupTimeout
	}
	rec, err := s.lookupByVerifier(verifier, pepperVersion)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, credential.ErrNotFound
	}
	return rec, nil
}

func (s *Store) lookupByVerifier(verifier []byte, pepperVersion int) (*credential.CredentialRecord, error) {
	var rec *credential.CredentialRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		key := verKeyFor(pepperVersion, verifier)
		id := tx.Bucket(bucketCredVerifier).Get([]byte(key))
		if id == nil {
			return nil
		}
		env := tx.Bucket(bucketCredentials).Get(id)
		if env == nil {
			return nil
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil {
			return credential.ErrCorrupt
		}
		if p.Record.PepperVersion != pepperVersion || !bytes.Equal(p.Record.Verifier, verifier) {
			return nil // stale index — record's own verifier is authoritative
		}
		r := p.Record
		r.Verifier = append([]byte(nil), p.Record.Verifier...)
		rec = &r
		return nil
	})
	return rec, err
}

// Revoke implements credential.Registry (idempotent revoke, bump revision).
func (s *Store) Revoke(credentialID string) error {
	return s.updateInPlace(credentialID, func(rec *credential.CredentialRecord) error {
		rec.Status = credential.StatusRevoked
		rec.Revision++
		rec.RotatedAt = s.now()
		return nil
	})
}

// BumpRevision implements credential.Registry.
func (s *Store) BumpRevision(credentialID string) error {
	return s.updateInPlace(credentialID, func(rec *credential.CredentialRecord) error {
		rec.Revision++
		return nil
	})
}

// TouchLastSeen implements credential.Registry (analytics, best-effort).
func (s *Store) TouchLastSeen(credentialID string, at time.Time) {
	_ = s.updateInPlace(credentialID, func(rec *credential.CredentialRecord) error {
		rec.LastSeenAt = at
		return nil
	})
}

// UpdateStatusCAS implements the one authoritative status-transition path
// (same CAS semantics as MemoryRegistry): fromStatus + expectedRevision must
// match, status must not downgrade QUARANTINED/REVOKED through this path, and
// revision increments by exactly 1 — all in one transaction.
func (s *Store) UpdateStatusCAS(credentialID string, expectedRevision int, fromStatus, toStatus credential.Status) (*credential.CredentialRecord, error) {
	var result *credential.CredentialRecord
	var outErr error
	err := s.db.Update(func(tx *bolt.Tx) error {
		env := tx.Bucket(bucketCredentials).Get([]byte(credentialID))
		if env == nil {
			outErr = credential.ErrNotFound
			return nil
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil {
			outErr = credential.ErrCorrupt
			return nil
		}
		rec := &p.Record
		if rec.Revision != expectedRevision {
			outErr = credential.ErrStaleCAS
			return nil
		}
		if rec.Status != fromStatus {
			outErr = credential.ErrStaleCAS
			return nil
		}
		if toStatus == fromStatus {
			outErr = errors.New("credential: no status change requested")
			return nil
		}
		if fromStatus == credential.StatusQuarantined {
			outErr = errors.New("credential: quarantined status cannot be downgraded through admission")
			return nil
		}
		if fromStatus == credential.StatusRevoked {
			outErr = errors.New("credential: revoked is terminal")
			return nil
		}
		rec.Status = toStatus
		rec.Revision++
		rec.RotatedAt = s.now()
		p.Record = *rec
		b, err := json.Marshal(p)
		if err != nil {
			outErr = err
			return nil
		}
		if err := tx.Bucket(bucketCredentials).Put([]byte(credentialID), b); err != nil {
			outErr = err
			return nil
		}
		r := *rec
		r.Verifier = append([]byte(nil), rec.Verifier...)
		result = &r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, outErr
}

// ObserveAndCommit implements the authoritative atomic risk-observation apply
// (P0.5/P0.6) in ONE write transaction: load → reduce via the PURE reducer →
// if status changed, CAS revision/status; persist resulting security state even
// when status is stable. No load-then-reopen window exists: the whole operation
// is inside the single write transaction, exactly the txn the design calls for.
func (s *Store) ObserveAndCommit(
	ctx context.Context,
	credentialID string,
	score int,
	hy credential.Hysteresis,
	now time.Time,
) (credential.TransitionResult, error) {
	if err := ctx.Err(); err != nil {
		return credential.TransitionResult{}, credential.ErrLookupTimeout
	}
	var result credential.TransitionResult
	var outErr error
	err := s.db.Update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		env := creds.Get([]byte(credentialID))
		if env == nil {
			outErr = credential.ErrNotFound
			return nil
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil {
			outErr = credential.ErrCorrupt
			return nil
		}
		rec := &p.Record
		before := clone(rec)
		reduced := credential.ReduceTransition(hy, rec.Status, rec.Security, score, now)

		if !reduced.Changed {
			// Observation applied, no status transition: persist the updated
			// security state (risk, streaks, timestamps) without a revision bump
			// (P0.44: one bump per state mutation).
			rec.Security = reduced.Next
			b, err := json.Marshal(p)
			if err != nil {
				outErr = err
				return nil
			}
			if err := creds.Put([]byte(credentialID), b); err != nil {
				outErr = err
				return nil
			}
			result = credential.TransitionResult{
				Status: credential.TransitionNoChange,
				Before: before,
				Record: clone(rec),
			}
			return nil
		}
		// Status changed — serial CAS (single writer, but keep the guard for
		// revision hygiene across callers).
		if rec.Revision != before.Revision || rec.Status != before.Status {
			outErr = credential.ErrStaleCAS
			return nil
		}
		if rec.Status == credential.StatusQuarantined || rec.Status == credential.StatusRevoked {
			outErr = errors.New("credential: terminal/elevated state cannot be transitioned through admission")
			return nil
		}
		rec.Status = reduced.Status
		rec.Security = reduced.Next
		rec.Revision++
		rec.Security.LastStateChangeAt = now
		rec.RotatedAt = now
		b, err := json.Marshal(p)
		if err != nil {
			outErr = err
			return nil
		}
		if err := creds.Put([]byte(credentialID), b); err != nil {
			outErr = err
			return nil
		}
		result = credential.TransitionResult{
			Status: credential.TransitionCommitted,
			Before: before,
			Record: clone(rec),
		}
		return nil
	})
	if err != nil {
		return credential.TransitionResult{}, err
	}
	return result, outErr
}

// updateInPlace mutates a credential's row inside one write transaction.
func (s *Store) updateInPlace(credentialID string, mutate func(*credential.CredentialRecord) error) error {
	var outErr error
	s.db.Update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		env := creds.Get([]byte(credentialID))
		if env == nil {
			outErr = credential.ErrNotFound
			return nil
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil {
			outErr = credential.ErrCorrupt
			return nil
		}
		if err := mutate(&p.Record); err != nil {
			outErr = err
			return nil
		}
		b, err := json.Marshal(p)
		if err != nil {
			outErr = err
			return nil
		}
		outErr = creds.Put([]byte(credentialID), b)
		return nil
	})
	return outErr
}

func clone(rec *credential.CredentialRecord) *credential.CredentialRecord {
	c := *rec
	if rec.Verifier != nil {
		c.Verifier = append([]byte(nil), rec.Verifier...)
	}
	return &c
}

func verKeyFor(pepperVersion int, verifier []byte) string {
	return strconv.Itoa(pepperVersion) + "/" + base64.StdEncoding.EncodeToString(verifier)
}
