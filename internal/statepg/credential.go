package statepg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
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
	return withTransactionRetry(ctx, "credential insert", func() error {
		return s.insertCredentialOnce(ctx, rec, security)
	})
}

func (s *Store) insertCredentialOnce(ctx context.Context, rec *credential.CredentialRecord, security []byte) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return err
	}
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
	var created bool
	err = withTransactionRetry(ctx, "credential insert-if-absent", func() error {
		var err error
		created, err = s.insertCredentialIfAbsentOnce(ctx, rec, security)
		return err
	})
	return created, err
}

func (s *Store) insertCredentialIfAbsentOnce(ctx context.Context, rec *credential.CredentialRecord, security []byte) (bool, error) {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return false, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return false, err
	}
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

// ListCredentials returns sanitized credential summaries for administrative
// consumers. Verifier material is intentionally excluded.
func (s *Store) ListCredentials() ([]credential.Summary, error) {
	rows, err := s.pool.Query(context.Background(), `SELECT credential_id, account_id,
		status, policy_id, plan_id, created_at, revision FROM gripline_credentials ORDER BY credential_id`)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer rows.Close()
	var out []credential.Summary
	for rows.Next() {
		var rec credential.Summary
		var status int
		if err := rows.Scan(&rec.CredentialID, &rec.AccountID, &status, &rec.PolicyID, &rec.PlanID, &rec.CreatedAt, &rec.Revision); err != nil {
			return nil, mapDBError(err)
		}
		rec.Status = credential.Status(status).String()
		out = append(out, rec)
	}
	return out, mapDBError(rows.Err())
}

// CountCredentialsByPepperVersion is the operator safety check used before a
// pepper generation is retired.
func (s *Store) CountCredentialsByPepperVersion() (map[int]int, error) {
	rows, err := s.pool.Query(context.Background(), `SELECT pepper_version, COUNT(*) FROM gripline_credentials GROUP BY pepper_version ORDER BY pepper_version`)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer rows.Close()
	counts := make(map[int]int)
	for rows.Next() {
		var version, count int
		if err := rows.Scan(&version, &count); err != nil {
			return nil, mapDBError(err)
		}
		counts[version] = count
	}
	return counts, mapDBError(rows.Err())
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
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = s.TouchLastSeenContext(ctx, credentialID, at)
}

// TouchLastSeenContext is analytics-only and honors the caller's bounded
// context. It must never be used as an authorization prerequisite.
func (s *Store) TouchLastSeenContext(ctx context.Context, credentialID string, at time.Time) error {
	if ctx == nil {
		ctx = context.Background()
	}
	_, err := s.pool.Exec(ctx, `UPDATE gripline_credentials SET last_seen_at=$2 WHERE credential_id=$1`, credentialID, at)
	return mapDBError(err)
}

func (s *Store) UpdateStatusCAS(credentialID string, expectedRevision int, fromStatus, toStatus credential.Status) (*credential.CredentialRecord, error) {
	ctx := context.Background()
	var out *credential.CredentialRecord
	err := withTransactionRetry(ctx, "credential status transition", func() error {
		var err error
		out, err = s.updateStatusCASOnce(ctx, credentialID, expectedRevision, fromStatus, toStatus)
		return err
	})
	return out, err
}

func (s *Store) updateStatusCASOnce(ctx context.Context, credentialID string, expectedRevision int, fromStatus, toStatus credential.Status) (*credential.CredentialRecord, error) {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return nil, err
	}
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
	return s.RotateVerifierCASContext(context.Background(), credentialID, expectedRevision, pepperVersion, verifier)
}

// RotateVerifierCASContext performs the same row-locked atomic migration while
// honoring the request's cancellation/deadline.
func (s *Store) RotateVerifierCASContext(ctx context.Context, credentialID string, expectedRevision, pepperVersion int, verifier []byte) (*credential.CredentialRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pepperVersion < 1 || len(verifier) == 0 {
		return nil, errors.New("credential: invalid rotated verifier")
	}
	var out *credential.CredentialRecord
	err := withTransactionRetry(ctx, "credential verifier rotation", func() error {
		var err error
		out, err = s.rotateVerifierCASOnce(ctx, credentialID, expectedRevision, pepperVersion, verifier)
		return err
	})
	return out, err
}

func (s *Store) rotateVerifierCASOnce(ctx context.Context, credentialID string, expectedRevision, pepperVersion int, verifier []byte) (*credential.CredentialRecord, error) {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return nil, err
	}
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
	return withTransactionRetry(ctx, "credential mutation", func() error {
		return s.updateCredentialOnce(ctx, id, mutate)
	})
}

func (s *Store) updateCredentialOnce(ctx context.Context, id string, mutate func(*credential.CredentialRecord) error) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return err
	}
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

// credentialReceipt is the durable result of one request-correlated security
// observation. Keeping the complete validated records makes a replay return
// the original authoritative result even if a later observation has already
// advanced the live credential row.
type credentialReceipt struct {
	Changed bool
	Before  *credential.CredentialRecord
	After   *credential.CredentialRecord
}

func loadCredentialReceipt(ctx context.Context, tx pgx.Tx, requestID, credentialID string) (credentialReceipt, bool, error) {
	var (
		changed             bool
		beforeRaw, afterRaw []byte
	)
	err := tx.QueryRow(ctx, `SELECT changed, before_record, after_record
		FROM gripline_credential_receipts WHERE request_id=$1 AND credential_id=$2`, requestID, credentialID).
		Scan(&changed, &beforeRaw, &afterRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return credentialReceipt{}, false, nil
	}
	if err != nil {
		return credentialReceipt{}, false, mapDBError(err)
	}
	var before, after credential.CredentialRecord
	if json.Unmarshal(beforeRaw, &before) != nil || json.Unmarshal(afterRaw, &after) != nil || before.Validate() != nil || after.Validate() != nil {
		return credentialReceipt{}, false, credential.ErrLookupCorrupt
	}
	return credentialReceipt{Changed: changed, Before: cloneCredential(&before), After: cloneCredential(&after)}, true, nil
}

func storeCredentialReceipt(ctx context.Context, tx pgx.Tx, requestID, credentialID string, changed bool, before, after *credential.CredentialRecord) error {
	if requestID == "" {
		return nil
	}
	beforeRaw, err := json.Marshal(before)
	if err != nil {
		return err
	}
	afterRaw, err := json.Marshal(after)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gripline_credential_receipts
		(request_id, credential_id, changed, before_record, after_record)
		VALUES ($1,$2,$3,$4,$5) ON CONFLICT (request_id, credential_id) DO NOTHING`, requestID, credentialID, changed, beforeRaw, afterRaw)
	return mapDBError(err)
}

// ObserveAndCommit serializes the reducer against the shared credential row.
func (s *Store) ObserveAndCommit(ctx context.Context, credentialID string, score int, hy credential.Hysteresis, now time.Time) (credential.TransitionResult, error) {
	if err := ctx.Err(); err != nil {
		return credential.TransitionResult{}, credential.ErrTimeout
	}
	meta := credential.TransitionMetadataFromContext(ctx)
	var out credential.TransitionResult
	err := withTransactionRetry(ctx, "credential observation", func() error {
		var err error
		out, err = s.observeAndCommitOnce(ctx, credentialID, score, hy, now, meta)
		return err
	})
	return out, err
}

func (s *Store) observeAndCommitOnce(ctx context.Context, credentialID string, score int, hy credential.Hysteresis, now time.Time, meta credential.TransitionMetadata) (credential.TransitionResult, error) {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return credential.TransitionResult{}, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return credential.TransitionResult{}, err
	}
	if meta.RequestID != "" {
		if receipt, ok, err := loadCredentialReceipt(ctx, tx, meta.RequestID, credentialID); err != nil {
			return credential.TransitionResult{}, err
		} else if ok {
			status := credential.TransitionNoChange
			if receipt.Changed {
				status = credential.TransitionCommitted
			}
			return credential.TransitionResult{Status: status, Before: receipt.Before, Record: receipt.After}, nil
		}
	}
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
	if reduced.Changed {
		if err := appendSecurityTransition(ctx, tx, control.SecurityTransitionRecord{
			At: now.UTC(), Kind: "credential_status", RequestID: meta.RequestID,
			CredentialID: credentialID, Before: before.Status.String(), After: rec.Status.String(),
			RiskScore: score, Revision: rec.Revision, PolicyRevision: meta.PolicyRevision,
			EvidenceCodes: append([]string(nil), meta.EvidenceCodes...),
		}); err != nil {
			return credential.TransitionResult{}, err
		}
	}
	if err := storeCredentialReceipt(ctx, tx, meta.RequestID, credentialID, reduced.Changed, before, rec); err != nil {
		return credential.TransitionResult{}, err
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
