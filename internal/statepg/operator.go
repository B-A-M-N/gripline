package statepg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func appendOperator(ctx context.Context, tx pgx.Tx, rec control.OperatorRecord) error {
	var sequence int64
	err := tx.QueryRow(ctx, `INSERT INTO gripline_operator_audit
		(at, actor, action, target, reason, posture, committed, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING sequence`,
		rec.At.UTC(), rec.Actor, rec.Action, rec.Target, rec.Reason, rec.Posture,
		rec.Committed, rec.Detail).Scan(&sequence)
	if err != nil {
		return err
	}
	if sequence < 0 {
		return errors.New("statepg: negative operator audit sequence")
	}
	return nil
}

// AppendOperator implements the durable operator-audit sink. The request
// context is honored because denied-action audit is best effort but bounded by
// the caller's detached timeout.
func (s *Store) AppendOperator(ctx context.Context, rec control.OperatorRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := appendOperator(ctx, tx, rec); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

// LoadPostureContext reads the current cluster-wide operator posture.
func (s *Store) LoadPostureContext(ctx context.Context) (control.Posture, error) {
	if err := ctx.Err(); err != nil {
		return control.Normal, err
	}
	var raw int
	err := s.pool.QueryRow(ctx, `SELECT posture FROM gripline_operator_posture WHERE singleton=TRUE`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return control.Normal, nil
	}
	if err != nil {
		return control.Normal, mapDBError(err)
	}
	if raw < int(control.Normal) || raw > int(control.EmergencyLockdown) {
		return control.Normal, fmt.Errorf("statepg: unknown persisted posture %d", raw)
	}
	return control.Posture(raw), nil
}

func (s *Store) LoadPosture() (control.Posture, error) {
	return s.LoadPostureContext(context.Background())
}

// SavePosture is retained for lifecycle tooling. Operator actions should use
// SetPostureWithAudit so posture and its audit row are one transaction.
func (s *Store) SavePosture(posture control.Posture) error {
	ctx := context.Background()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := putPosture(ctx, tx, posture, s.now()); err != nil {
		return err
	}
	return mapDBError(tx.Commit(ctx))
}

func putPosture(ctx context.Context, tx pgx.Tx, posture control.Posture, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO gripline_operator_posture (singleton, posture, updated_at)
		VALUES (TRUE,$1,$2) ON CONFLICT (singleton) DO UPDATE SET posture=EXCLUDED.posture, updated_at=EXCLUDED.updated_at`, posture, now)
	return mapDBError(err)
}

// AppendAdmission records the durable data-plane decision stream used by a
// clustered ControlPlane recorder. It contains identifiers and reasons only.
func (s *Store) AppendAdmission(ctx context.Context, e control.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO gripline_admission_audit
		(at, request_id, credential_id, account_id, lane_id, posture, authorized, reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, e.At.UTC(), e.RequestID, e.CredentialID,
		e.AccountID, e.LaneID, e.Posture, e.Authorized, e.Reason)
	return mapDBError(err)
}

// ListOperatorAudit returns committed operator records in sequence order.
func (s *Store) ListOperatorAudit(after uint64, limit int) ([]control.OperatorRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := s.pool.Query(context.Background(), `SELECT sequence, at, actor, action,
		target, reason, posture, committed, detail FROM gripline_operator_audit
		WHERE sequence > $1 ORDER BY sequence LIMIT $2`, after, limit)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer rows.Close()
	var out []control.OperatorRecord
	for rows.Next() {
		var rec control.OperatorRecord
		var sequence int64
		if err := rows.Scan(&sequence, &rec.At, &rec.Actor, &rec.Action, &rec.Target,
			&rec.Reason, &rec.Posture, &rec.Committed, &rec.Detail); err != nil {
			return nil, mapDBError(err)
		}
		if sequence < 0 {
			return nil, errors.New("statepg: negative operator audit sequence")
		}
		rec.Sequence = uint64(sequence)
		out = append(out, rec)
	}
	return out, mapDBError(rows.Err())
}

func (s *Store) CountAuditRecords() (int, error) {
	var count int
	err := s.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM gripline_operator_audit`).Scan(&count)
	return count, mapDBError(err)
}

func mapCredentialMutationError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if strings.Contains(pgErr.ConstraintName, "pepper_version_verifier") {
			return credential.ErrVerifierOwned
		}
		return credential.ErrAlreadyExists
	}
	return mapDBError(err)
}

func (s *Store) ProvisionCredentialWithAudit(ctx context.Context, rec credential.CredentialRecord, audit control.OperatorRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rec.Validate(); err != nil {
		return err
	}
	security, err := encodeSecurity(rec.Security)
	if err != nil {
		return err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO gripline_credentials (`+credentialColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, insertArgs(&rec, security)...)
	if err != nil {
		return mapCredentialMutationError(err)
	}
	if err := appendOperator(ctx, tx, audit); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

func (s *Store) UnblockLaneWithAudit(ctx context.Context, credID, laneID string, audit control.OperatorRecord, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.lockLaneGuard(ctx, tx, credID); err != nil {
		return mapDBError(err)
	}
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT record FROM gripline_lanes WHERE credential_id=$1 AND lane_id=$2 FOR UPDATE`, credID, laneID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return lane.ErrLaneNotFound
	}
	if err != nil {
		return mapDBError(err)
	}
	rec, err := decodeLane(raw)
	if err != nil {
		return err
	}
	before, err := lane.ApplyUnblock(rec, now)
	if err != nil {
		return err
	}
	if err := putLane(ctx, tx, rec); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_lane_operator_audit
		(at, credential_id, lane_id, actor, action, before_state, after_state, revision, reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, now.UTC(), credID, laneID, audit.Actor,
		lane.ActionUnblock, before.String(), rec.Security.Status.String(), rec.Revision, audit.Reason); err != nil {
		return mapDBError(err)
	}
	if err := appendOperator(ctx, tx, audit); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

func (s *Store) RevokeCredentialWithAudit(ctx context.Context, credID string, audit control.OperatorRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	var rec *credential.CredentialRecord
	rec, err = scanCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM gripline_credentials WHERE credential_id=$1 FOR UPDATE`, credID))
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrNotFound
	}
	if err != nil {
		return mapCredentialReadError(err)
	}
	rec.Status = credential.StatusRevoked
	rec.Revision++
	rec.RotatedAt = s.now()
	if err := updateCredentialRow(ctx, tx, rec); err != nil {
		return err
	}
	if err := appendOperator(ctx, tx, audit); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

func (s *Store) SetPostureWithAudit(ctx context.Context, posture control.Posture, audit control.OperatorRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := putPosture(ctx, tx, posture, s.now()); err != nil {
		return err
	}
	if err := appendOperator(ctx, tx, audit); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

var (
	_ control.AuditRepository = (*Store)(nil)
	_ control.MutationStore   = (*Store)(nil)
)
