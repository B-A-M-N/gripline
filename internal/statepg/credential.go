package statepg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/jackc/pgx/v5"
)

var credentialColumns = `credential_id, account_id, verifier, verifier_version, pepper_version, status, security, policy_id, plan_id, created_at, expires_at, rotated_at, last_seen_at, revision`

func encodeSecurity(state credential.SecurityState) ([]byte, error) {
	b, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("statepg: encode credential security: %w", err)
	}
	return b, nil
}

func scanCredential(row pgx.Row) (*credential.CredentialRecord, error) {
	var (
		rec                                 credential.CredentialRecord
		security                            []byte
		created, expires, rotated, lastSeen *time.Time
	)
	if err := row.Scan(&rec.CredentialID, &rec.AccountID, &rec.Verifier, &rec.VerifierVersion, &rec.PepperVersion, &rec.Status, &security, &rec.PolicyID, &rec.PlanID, &created, &expires, &rotated, &lastSeen, &rec.Revision); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(security, &rec.Security); err != nil {
		return nil, credential.ErrLookupCorrupt
	}
	if created != nil {
		rec.CreatedAt = *created
	}
	if expires != nil {
		rec.ExpiresAt = *expires
	}
	if rotated != nil {
		rec.RotatedAt = *rotated
	}
	if lastSeen != nil {
		rec.LastSeenAt = *lastSeen
	}
	if err := rec.Validate(); err != nil {
		return nil, credential.ErrLookupCorrupt
	}
	return &rec, nil
}

func insertArgs(rec *credential.CredentialRecord, security []byte) []any {
	return []any{rec.CredentialID, rec.AccountID, rec.Verifier, rec.VerifierVersion, rec.PepperVersion, rec.Status, security, rec.PolicyID, rec.PlanID, rec.CreatedAt, zeroTime(rec.ExpiresAt), zeroTime(rec.RotatedAt), zeroTime(rec.LastSeenAt), rec.Revision}
}

// Insert atomically replaces one credential row and its unique verifier index.
func (s *Store) Insert(rec *credential.CredentialRecord) error {
	if rec == nil {
		return errors.New("credential: nil record")
	}
	if err := rec.Validate(); err != nil {
		return err
	}
	security, err := encodeSecurity(rec.Security)
	if err != nil {
		return err
	}
	ctx := context.Background()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO gripline_credentials (`+credentialColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (credential_id) DO UPDATE SET account_id=EXCLUDED.account_id, verifier=EXCLUDED.verifier, verifier_version=EXCLUDED.verifier_version, pepper_version=EXCLUDED.pepper_version, status=EXCLUDED.status, security=EXCLUDED.security, policy_id=EXCLUDED.policy_id, plan_id=EXCLUDED.plan_id, created_at=EXCLUDED.created_at, expires_at=EXCLUDED.expires_at, rotated_at=EXCLUDED.rotated_at, last_seen_at=EXCLUDED.last_seen_at, revision=EXCLUDED.revision`, insertArgs(rec, security)...)
	if err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

// InsertIfAbsent never overwrites operator-managed state.
func (s *Store) InsertIfAbsent(rec *credential.CredentialRecord) (bool, error) {
	if rec == nil {
		return false, errors.New("credential: nil record")
	}
	if err := rec.Validate(); err != nil {
		return false, err
	}
	security, err := encodeSecurity(rec.Security)
	if err != nil {
		return false, err
	}
	ctx := context.Background()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return false, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO gripline_credentials (`+credentialColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (credential_id) DO NOTHING RETURNING credential_id`, insertArgs(rec, security)...).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, mapDBError(tx.Commit(ctx))
	}
	if err != nil {
		return false, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, mapDBError(err)
	}
	return id != "", nil
}

func (s *Store) Lookup(credentialID string) (*credential.CredentialRecord, bool) {
	rec, err := s.LookupAuthoritative(context.Background(), credentialID)
	return rec, err == nil
}

func (s *Store) LookupAuthoritative(ctx context.Context, credentialID string) (*credential.CredentialRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, credential.ErrLookupTimeout
	}
	rec, err := scanCredential(s.pool.QueryRow(ctx, `SELECT `+credentialColumns+` FROM gripline_credentials WHERE credential_id=$1`, credentialID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, credential.ErrNotFound
	}
	if err != nil {
		return nil, mapCredentialReadError(err)
	}
	return rec, nil
}

func (s *Store) FindByVerifier(verifier []byte, pepperVersion int) (*credential.CredentialRecord, bool) {
	rec, err := s.FindByVerifierContext(context.Background(), verifier, pepperVersion)
	return rec, err == nil
}

func (s *Store) FindByVerifierContext(ctx context.Context, verifier []byte, pepperVersion int) (*credential.CredentialRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, credential.ErrLookupTimeout
	}
	rec, err := scanCredential(s.pool.QueryRow(ctx, `SELECT `+credentialColumns+` FROM gripline_credentials WHERE verifier=$1 AND pepper_version=$2`, verifier, pepperVersion))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, credential.ErrNotFound
	}
	if err != nil {
		return nil, mapCredentialReadError(err)
	}
	if rec.PepperVersion != pepperVersion || !bytes.Equal(rec.Verifier, verifier) {
		return nil, credential.ErrNotFound
	}
	return rec, nil
}

func mapCredentialReadError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return credential.ErrLookupTimeout
	}
	if errors.Is(err, context.Canceled) {
		return credential.ErrLookupTimeout
	}
	if errors.Is(err, credential.ErrLookupCorrupt) {
		return credential.ErrLookupCorrupt
	}
	return credential.ErrLookupUnavailable
}

func (s *Store) Revoke(credentialID string) error {
	return s.updateCredential(context.Background(), credentialID, func(rec *credential.CredentialRecord) error {
		rec.Status = credential.StatusRevoked
		rec.Revision++
		rec.RotatedAt = s.now()
		return nil
	})
}

func (s *Store) BumpRevision(credentialID string) error {
	return s.updateCredential(context.Background(), credentialID, func(rec *credential.CredentialRecord) error {
		rec.Revision++
		return nil
	})
}

func (s *Store) TouchLastSeen(credentialID string, at time.Time) {
	_, _ = s.pool.Exec(context.Background(), `UPDATE gripline_credentials SET last_seen_at=$2 WHERE credential_id=$1`, credentialID, at)
}

func (s *Store) UpdateStatusCAS(credentialID string, expectedRevision int, fromStatus, toStatus credential.Status) (*credential.CredentialRecord, error) {
	ctx := context.Background()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	rec, err := scanCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM gripline_credentials WHERE credential_id=$1 FOR UPDATE`, credentialID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, credential.ErrNotFound
	}
	if err != nil {
		return nil, mapCredentialReadError(err)
	}
	if rec.Revision != expectedRevision || rec.Status != fromStatus {
		return nil, credential.ErrStaleCAS
	}
	if toStatus == fromStatus || fromStatus == credential.StatusQuarantined || fromStatus == credential.StatusRevoked {
		return nil, credential.ErrStaleCAS
	}
	rec.Status = toStatus
	rec.Revision++
	rec.RotatedAt = s.now()
	if err := updateCredentialRow(ctx, tx, rec); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapDBError(err)
	}
	return rec, nil
}

func (s *Store) RotateVerifierCAS(credentialID string, expectedRevision, pepperVersion int, verifier []byte) (*credential.CredentialRecord, error) {
	if pepperVersion < 1 || len(verifier) == 0 {
		return nil, errors.New("credential: invalid rotated verifier")
	}
	ctx := context.Background()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	rec, err := scanCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM gripline_credentials WHERE credential_id=$1 FOR UPDATE`, credentialID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, credential.ErrNotFound
	}
	if err != nil {
		return nil, mapCredentialReadError(err)
	}
	if rec.Revision != expectedRevision {
		return nil, credential.ErrStaleCAS
	}
	rec.Verifier = append([]byte(nil), verifier...)
	rec.VerifierVersion = 1
	rec.PepperVersion = pepperVersion
	rec.Revision++
	rec.RotatedAt = s.now()
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if err := updateCredentialRow(ctx, tx, rec); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapDBError(err)
	}
	return rec, nil
}

func (s *Store) updateCredential(ctx context.Context, id string, mutate func(*credential.CredentialRecord) error) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	rec, err := scanCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM gripline_credentials WHERE credential_id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrNotFound
	}
	if err != nil {
		return mapCredentialReadError(err)
	}
	if err := mutate(rec); err != nil {
		return err
	}
	if err := updateCredentialRow(ctx, tx, rec); err != nil {
		return err
	}
	return mapDBError(tx.Commit(ctx))
}

func updateCredentialRow(ctx context.Context, tx pgx.Tx, rec *credential.CredentialRecord) error {
	security, err := encodeSecurity(rec.Security)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE gripline_credentials SET account_id=$2, verifier=$3, verifier_version=$4, pepper_version=$5, status=$6, security=$7, policy_id=$8, plan_id=$9, created_at=$10, expires_at=$11, rotated_at=$12, last_seen_at=$13, revision=$14 WHERE credential_id=$1`, insertArgs(rec, security)...)
	return mapDBError(err)
}

// ObserveAndCommit serializes the reducer against the shared credential row.
func (s *Store) ObserveAndCommit(ctx context.Context, credentialID string, score int, hy credential.Hysteresis, now time.Time) (credential.TransitionResult, error) {
	if err := ctx.Err(); err != nil {
		return credential.TransitionResult{}, credential.ErrTimeout
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return credential.TransitionResult{}, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	rec, err := scanCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM gripline_credentials WHERE credential_id=$1 FOR UPDATE`, credentialID))
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.TransitionResult{}, credential.ErrNotFound
	}
	if err != nil {
		return credential.TransitionResult{}, mapCredentialReadError(err)
	}
	before := cloneCredential(rec)
	reduced := credential.ReduceTransition(hy, rec.Status, rec.Security, score, now)
	rec.Security = reduced.Next
	if reduced.Changed {
		if rec.Status == credential.StatusQuarantined || rec.Status == credential.StatusRevoked {
			return credential.TransitionResult{}, errors.New("credential: terminal/elevated state cannot be transitioned through admission")
		}
		rec.Status = reduced.Status
		rec.Revision++
		rec.Security.LastStateChangeAt = now
		rec.RotatedAt = now
	}
	if err := updateCredentialRow(ctx, tx, rec); err != nil {
		return credential.TransitionResult{}, err
	}
	meta := credential.TransitionMetadataFromContext(ctx)
	codes, _ := json.Marshal(meta.EvidenceCodes)
	if reduced.Changed {
		if _, err := tx.Exec(ctx, `INSERT INTO gripline_credential_transitions (at, request_id, credential_id, before_status, after_status, risk_score, revision, policy_revision, evidence_codes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, now.UTC(), meta.RequestID, credentialID, before.Status, rec.Status, score, rec.Revision, meta.PolicyRevision, codes); err != nil {
			return credential.TransitionResult{}, mapDBError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.TransitionResult{}, mapDBError(err)
	}
	status := credential.TransitionNoChange
	if reduced.Changed {
		status = credential.TransitionCommitted
	}
	return credential.TransitionResult{Status: status, Before: before, Record: rec}, nil
}

func cloneCredential(rec *credential.CredentialRecord) *credential.CredentialRecord {
	copy := *rec
	copy.Verifier = append([]byte(nil), rec.Verifier...)
	return &copy
}

var (
	_ credential.Registry       = (*Store)(nil)
	_ credential.VerifierLookup = (*Store)(nil)
	_ credential.Provisioner    = (*Store)(nil)
)
