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
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return withTransactionRetry(ctx, "operator audit append", func() error {
		return s.appendOperatorOnce(ctx, rec)
	})
}

func (s *Store) appendOperatorOnce(ctx context.Context, rec control.OperatorRecord) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, true); err != nil {
		return err
	}
	if err := appendOperator(ctx, tx, rec); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

// LoadPostureContext reads the current cluster-wide operator posture.
func (s *Store) LoadPostureContext(ctx context.Context) (control.Posture, error) {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
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

// PostureContext implements control.PostureAuthority.
func (s *Store) PostureContext(ctx context.Context) (control.Posture, error) {
	posture, _, err := s.PostureSnapshotContext(ctx)
	return posture, err
}

// PostureSnapshotContext reads the shared posture and its activation time.
// The timestamp is used only to classify whether a lane was materialized
// during the current lockdown; the posture value remains the authorization
// authority.
func (s *Store) PostureSnapshotContext(ctx context.Context) (control.Posture, time.Time, error) {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return control.Normal, time.Time{}, err
	}
	if s.nodeID == "" {
		var raw int
		var updatedAt time.Time
		err := s.pool.QueryRow(ctx, `SELECT posture, updated_at FROM gripline_operator_posture WHERE singleton=TRUE`).Scan(&raw, &updatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return control.Normal, time.Time{}, nil
		}
		if err != nil {
			return control.Normal, time.Time{}, mapDBError(err)
		}
		if raw < int(control.Normal) || raw > int(control.EmergencyLockdown) {
			return control.Normal, time.Time{}, fmt.Errorf("statepg: unknown persisted posture %d", raw)
		}
		return control.Posture(raw), updatedAt, nil
	}
	if err := ctx.Err(); err != nil {
		return control.Normal, time.Time{}, err
	}
	var raw int
	var state string
	var lastSeen, now, updatedAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(p.posture,0), m.state, m.last_seen_at,
		CURRENT_TIMESTAMP, COALESCE(p.updated_at, TIMESTAMPTZ 'epoch') FROM gripline_membership m LEFT JOIN gripline_operator_posture p
		ON p.singleton=TRUE WHERE m.node_id=$1 AND m.instance_id=$2 AND m.node_epoch=$3`,
		s.nodeID, s.instanceID, s.nodeEpoch).Scan(&raw, &state, &lastSeen, &now, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		s.fenced.Store(true)
		return control.Normal, time.Time{}, ErrNodeFenced
	}
	if err != nil {
		return control.Normal, time.Time{}, mapDBError(err)
	}
	if now.Sub(lastSeen) >= s.leaseTTL {
		s.fenced.Store(true)
		return control.Normal, time.Time{}, ErrNodeFenced
	}
	if state == "draining" {
		return control.Normal, time.Time{}, ErrNodeDraining
	}
	if state != "ready" {
		s.fenced.Store(true)
		return control.Normal, time.Time{}, ErrNodeFenced
	}
	if raw < int(control.Normal) || raw > int(control.EmergencyLockdown) {
		return control.Normal, time.Time{}, fmt.Errorf("statepg: unknown persisted posture %d", raw)
	}
	return control.Posture(raw), updatedAt, nil
}

func (s *Store) LoadPosture() (control.Posture, error) {
	return s.LoadPostureContext(context.Background())
}

// SavePosture is retained for lifecycle tooling. Operator actions should use
// SetPostureWithAudit so posture and its audit row are one transaction.
func (s *Store) SavePosture(posture control.Posture) error {
	ctx, cancel := s.operationContext(context.Background())
	defer cancel()
	return withTransactionRetry(ctx, "posture mutation", func() error {
		return s.savePostureOnce(ctx, posture)
	})
}

func (s *Store) savePostureOnce(ctx context.Context, posture control.Posture) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return err
	}
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
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return withTransactionRetry(ctx, "admission audit append", func() error {
		return s.appendAdmissionOnce(ctx, e)
	})
}

func (s *Store) appendAdmissionOnce(ctx context.Context, e control.Event) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, true); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gripline_admission_audit
		(at, request_id, credential_id, account_id, lane_id, posture, authorized, reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, e.At.UTC(), e.RequestID, e.CredentialID,
		e.AccountID, e.LaneID, e.Posture, e.Authorized, e.Reason)
	if err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

// ListOperatorAudit returns committed operator records in sequence order.
func (s *Store) ListOperatorAudit(after uint64, limit int) ([]control.OperatorRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	ctx, cancel := s.operationContext(context.Background())
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT sequence, at, actor, action,
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
	ctx, cancel := s.operationContext(context.Background())
	defer cancel()
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_operator_audit`).Scan(&count)
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
	return s.ProvisionCredentialWithAuditOperation(ctx, rec, audit, "")
}

// ProvisionCredentialWithAuditOperation atomically claims operationID, inserts
// the credential, and appends its operator audit row. An exact retry returns
// nil without replaying either mutation or audit.
func (s *Store) ProvisionCredentialWithAuditOperation(ctx context.Context, rec credential.CredentialRecord, audit control.OperatorRecord, operationID string) error {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
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
	return withTransactionRetry(ctx, "operator credential provision", func() error {
		return s.provisionCredentialWithAuditOperationOnce(ctx, rec, audit, operationID, security)
	})
}

func (s *Store) provisionCredentialWithAuditOperationOnce(ctx context.Context, rec credential.CredentialRecord, audit control.OperatorRecord, operationID string, security []byte) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return err
	}
	replayed, err := claimControlOperation(ctx, tx, operationID, audit.Action,
		operatorMutationPayload(audit, rec), s.now())
	if err != nil {
		return err
	}
	if replayed {
		return nil
	}
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
	return s.UnblockLaneWithAuditOperation(ctx, credID, laneID, audit, now, "")
}

// UnblockLaneWithAuditOperation atomically claims operationID and applies the
// lane mutation plus both audit records. Exact retries are no-ops.
func (s *Store) UnblockLaneWithAuditOperation(ctx context.Context, credID, laneID string, audit control.OperatorRecord, now time.Time, operationID string) error {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return withTransactionRetry(ctx, "operator lane unblock", func() error {
		return s.unblockLaneWithAuditOperationOnce(ctx, credID, laneID, audit, now, operationID)
	})
}

func (s *Store) unblockLaneWithAuditOperationOnce(ctx context.Context, credID, laneID string, audit control.OperatorRecord, now time.Time, operationID string) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return err
	}
	replayed, err := claimControlOperation(ctx, tx, operationID, audit.Action,
		operatorMutationPayload(audit, struct {
			CredentialID string `json:"credential_id"`
			LaneID       string `json:"lane_id"`
		}{CredentialID: credID, LaneID: laneID}), s.now())
	if err != nil {
		return err
	}
	if replayed {
		return nil
	}
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
	return s.RevokeCredentialWithAuditOperation(ctx, credID, audit, "")
}

// RevokeCredentialWithAuditOperation atomically claims operationID and
// revokes the credential. Re-revoking an already revoked credential is
// intentionally a state no-op: operator retries must not keep increasing its
// revision. Exact operation retries do not append a duplicate audit row.
func (s *Store) RevokeCredentialWithAuditOperation(ctx context.Context, credID string, audit control.OperatorRecord, operationID string) error {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return withTransactionRetry(ctx, "operator credential revoke", func() error {
		return s.revokeCredentialWithAuditOperationOnce(ctx, credID, audit, operationID)
	})
}

func (s *Store) revokeCredentialWithAuditOperationOnce(ctx context.Context, credID string, audit control.OperatorRecord, operationID string) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return err
	}
	replayed, err := claimControlOperation(ctx, tx, operationID, audit.Action,
		operatorMutationPayload(audit, struct {
			CredentialID string `json:"credential_id"`
		}{CredentialID: credID}), s.now())
	if err != nil {
		return err
	}
	if replayed {
		return nil
	}
	var rec *credential.CredentialRecord
	rec, err = scanCredential(tx.QueryRow(ctx, `SELECT `+credentialColumns+` FROM gripline_credentials WHERE credential_id=$1 FOR UPDATE`, credID))
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrNotFound
	}
	if err != nil {
		return mapCredentialReadError(err)
	}
	if rec.Status != credential.StatusRevoked {
		rec.Status = credential.StatusRevoked
		rec.Revision++
		rec.RotatedAt = s.now()
		if err := updateCredentialRow(ctx, tx, rec); err != nil {
			return err
		}
	}
	if err := appendOperator(ctx, tx, audit); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

func (s *Store) SetPostureWithAudit(ctx context.Context, posture control.Posture, audit control.OperatorRecord) error {
	return s.SetPostureWithAuditOperation(ctx, posture, audit, "")
}

// SetPostureWithAuditOperation atomically claims operationID and persists the
// cluster posture with its operator audit row. Exact retries are no-ops.
func (s *Store) SetPostureWithAuditOperation(ctx context.Context, posture control.Posture, audit control.OperatorRecord, operationID string) error {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return withTransactionRetry(ctx, "operator posture mutation", func() error {
		return s.setPostureWithAuditOperationOnce(ctx, posture, audit, operationID)
	})
}

func (s *Store) setPostureWithAuditOperationOnce(ctx context.Context, posture control.Posture, audit control.OperatorRecord, operationID string) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return err
	}
	replayed, err := claimControlOperation(ctx, tx, operationID, audit.Action,
		operatorMutationPayload(audit, struct {
			Posture control.Posture `json:"posture"`
		}{Posture: posture}), s.now())
	if err != nil {
		return err
	}
	if replayed {
		return nil
	}
	if err := putPosture(ctx, tx, posture, s.now()); err != nil {
		return err
	}
	if err := appendOperator(ctx, tx, audit); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

var (
	_ control.AuditRepository        = (*Store)(nil)
	_ control.MutationStore          = (*Store)(nil)
	_ control.OperationMutationStore = (*Store)(nil)
)
