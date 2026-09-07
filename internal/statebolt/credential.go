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

	"github.com/B-A-M-N/gripline/internal/control"
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
//
// Transaction discipline (P0.3-fix): every failure — domain or I/O — is
// returned FROM the callback so bbolt rolls the transaction back. A
// mid-mutation I/O failure can never commit a partially transformed row.
func (s *Store) Insert(rec *credential.CredentialRecord) error {
	if rec == nil {
		return errors.New("credential: nil record")
	}
	if err := rec.Validate(); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		byVer := tx.Bucket(bucketCredVerifier)

		newKey := ""
		if len(rec.Verifier) > 0 {
			newKey = verKeyFor(rec.PepperVersion, rec.Verifier)
			if owner := byVer.Get([]byte(newKey)); owner != nil {
				if string(owner) != rec.CredentialID {
					return credential.ErrVerifierOwned
				}
			}
		}
		if prev := creds.Get([]byte(rec.CredentialID)); prev != nil {
			var old persistedCredential
			if err := json.Unmarshal(prev, &old); err != nil || old.SchemaVersion != credentialSchemaVersion {
				return credential.ErrCorrupt
			}
			if len(old.Record.Verifier) > 0 {
				oldKey := verKeyFor(old.Record.PepperVersion, old.Record.Verifier)
				if oldKey != newKey { // same-key replacement keeps its index entry
					if err := byVer.Delete([]byte(oldKey)); err != nil {
						return err
					}
				}
			}
		}
		env, err := json.Marshal(persistedCredential{SchemaVersion: credentialSchemaVersion, Record: *rec})
		if err != nil {
			return err
		}
		if err := creds.Put([]byte(rec.CredentialID), env); err != nil {
			return err
		}
		if newKey != "" {
			return byVer.Put([]byte(newKey), []byte(rec.CredentialID))
		}
		return nil
	})
}

// InsertIfAbsent implements provisioning (P0.10/§6): it creates the credential
// ONLY if one with that id does not already exist, returning created=false when
// present. Development bootstrap MUST use this so a verifier record never
// overwrites an operator-managed (e.g. CONSTRAINED/REVOKED) credential on
// every restart. Credential rotation/replacement is the explicit lifecycle
// path (Insert / UpdateStatusCAS), not bootstrap.
func (s *Store) InsertIfAbsent(rec *credential.CredentialRecord) (bool, error) {
	if rec == nil {
		return false, errors.New("credential: nil record")
	}
	if err := rec.Validate(); err != nil {
		return false, err
	}
	created := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		byVer := tx.Bucket(bucketCredVerifier)
		if creds.Get([]byte(rec.CredentialID)) != nil {
			return nil // already present — leave untouched
		}
		if len(rec.Verifier) > 0 {
			k := verKeyFor(rec.PepperVersion, rec.Verifier)
			if owner := byVer.Get([]byte(k)); owner != nil && string(owner) != rec.CredentialID {
				return credential.ErrVerifierOwned
			}
		}
		env, err := json.Marshal(persistedCredential{SchemaVersion: credentialSchemaVersion, Record: *rec})
		if err != nil {
			return err
		}
		if err := creds.Put([]byte(rec.CredentialID), env); err != nil {
			return err
		}
		if len(rec.Verifier) > 0 {
			if err := byVer.Put([]byte(verKeyFor(rec.PepperVersion, rec.Verifier)), []byte(rec.CredentialID)); err != nil {
				return err
			}
		}
		created = true
		return nil
	})
	return created, err
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
		if err := json.Unmarshal(env, &p); err != nil || p.SchemaVersion != credentialSchemaVersion {
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
		if err := json.Unmarshal(env, &p); err != nil || p.SchemaVersion != credentialSchemaVersion {
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
	// LastSeenAt is analytics-grade, not authorization state. Avoid a bbolt
	// write transaction on every successful inference request; the coarse
	// interval keeps the DB out of the hot path while preserving useful recency.
	s.lastSeenMu.Lock()
	if previous, ok := s.lastSeen[credentialID]; ok && at.Sub(previous) < s.lastSeenInterval {
		s.lastSeenMu.Unlock()
		return
	}
	s.lastSeen[credentialID] = at
	s.lastSeenMu.Unlock()
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
	err := s.db.Update(func(tx *bolt.Tx) error {
		env := tx.Bucket(bucketCredentials).Get([]byte(credentialID))
		if env == nil {
			return credential.ErrNotFound
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil || p.SchemaVersion != credentialSchemaVersion {
			return credential.ErrCorrupt
		}
		rec := &p.Record
		if rec.Revision != expectedRevision {
			return credential.ErrStaleCAS
		}
		if rec.Status != fromStatus {
			return credential.ErrStaleCAS
		}
		if toStatus == fromStatus {
			return errors.New("credential: no status change requested")
		}
		if fromStatus == credential.StatusQuarantined {
			return errors.New("credential: quarantined status cannot be downgraded through admission")
		}
		if fromStatus == credential.StatusRevoked {
			return errors.New("credential: revoked is terminal")
		}
		rec.Status = toStatus
		rec.Revision++
		rec.RotatedAt = s.now()
		p.Record = *rec
		b, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bucketCredentials).Put([]byte(credentialID), b); err != nil {
			return err
		}
		r := *rec
		r.Verifier = append([]byte(nil), rec.Verifier...)
		result = &r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
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
	err := s.db.Update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		env := creds.Get([]byte(credentialID))
		if env == nil {
			return credential.ErrNotFound
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil || p.SchemaVersion != credentialSchemaVersion {
			return credential.ErrCorrupt
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
				return err
			}
			if err := creds.Put([]byte(credentialID), b); err != nil {
				return err
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
			return credential.ErrStaleCAS
		}
		if rec.Status == credential.StatusQuarantined || rec.Status == credential.StatusRevoked {
			return errors.New("credential: terminal/elevated state cannot be transitioned through admission")
		}
		rec.Status = reduced.Status
		rec.Security = reduced.Next
		rec.Revision++
		rec.Security.LastStateChangeAt = now
		rec.RotatedAt = now
		b, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if err := creds.Put([]byte(credentialID), b); err != nil {
			return err
		}
		meta := credential.TransitionMetadataFromContext(ctx)
		if err := appendSecurityTransitionTx(tx, control.SecurityTransitionRecord{
			At: now.UTC(), Kind: "credential_status", RequestID: meta.RequestID,
			CredentialID: credentialID, Before: before.Status.String(), After: rec.Status.String(),
			RiskScore: score, Revision: rec.Revision, PolicyRevision: meta.PolicyRevision,
			EvidenceCodes: append([]string(nil), meta.EvidenceCodes...),
		}); err != nil {
			return err
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
	return result, nil
}

// updateInPlace mutates a credential's row inside one write transaction. Every
// failure is returned from the callback so bbolt rolls back (P0.3-fix).
func (s *Store) updateInPlace(credentialID string, mutate func(*credential.CredentialRecord) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		creds := tx.Bucket(bucketCredentials)
		env := creds.Get([]byte(credentialID))
		if env == nil {
			return credential.ErrNotFound
		}
		var p persistedCredential
		if err := json.Unmarshal(env, &p); err != nil || p.SchemaVersion != credentialSchemaVersion {
			return credential.ErrCorrupt
		}
		if err := mutate(&p.Record); err != nil {
			return err
		}
		b, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return creds.Put([]byte(credentialID), b)
	})
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

// ListCredentials returns every credential's summary (CLI/diagnostics seam,
// P1-26). Rows are returned in credential-id order. Verifier material is NOT
// included — the summary never carries authentication material.
type CredentialSummary = credential.Summary

func (s *Store) ListCredentials() ([]credential.Summary, error) {
	var out []credential.Summary
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketCredentials).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var p persistedCredential
			if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != credentialSchemaVersion {
				return credential.ErrCorrupt
			}
			out = append(out, credential.Summary{
				CredentialID: p.Record.CredentialID,
				AccountID:    p.Record.AccountID,
				Status:       p.Record.Status.String(),
				PolicyID:     p.Record.PolicyID,
				PlanID:       p.Record.PlanID,
				CreatedAt:    p.Record.CreatedAt,
				Revision:     p.Record.Revision,
			})
		}
		return nil
	})
	return out, err
}
