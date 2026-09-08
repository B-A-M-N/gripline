package statepg

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/jackc/pgx/v5"
)

// appendSecurityTransition records machine-generated state changes in the
// shared ordered stream. The caller owns the transaction, so the state change
// and its provenance commit or roll back together.
func appendSecurityTransition(ctx context.Context, tx pgx.Tx, rec control.SecurityTransitionRecord) error {
	codes, err := json.Marshal(rec.EvidenceCodes)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gripline_security_transitions
		(at, kind, request_id, credential_id, lane_id, before_state, after_state,
		 risk_score, revision, policy_revision, evidence_codes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		rec.At.UTC(), rec.Kind, rec.RequestID, rec.CredentialID, rec.LaneID,
		rec.Before, rec.After, rec.RiskScore, rec.Revision, rec.PolicyRevision, codes)
	return mapDBError(err)
}

// ListSecurityTransitions reads the shared cursor-ordered transition stream.
// It is intentionally a strict read: database failures are returned rather
// than being confused with an empty history.
func (s *Store) ListSecurityTransitions(after uint64, limit int) ([]control.SecurityTransitionRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	ctx, cancel := s.operationContext(context.Background())
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT sequence, at, kind,
		request_id, credential_id, lane_id, before_state, after_state, risk_score,
		revision, policy_revision, evidence_codes
		FROM gripline_security_transitions WHERE sequence > $1 ORDER BY sequence LIMIT $2`, after, limit)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer rows.Close()
	var out []control.SecurityTransitionRecord
	for rows.Next() {
		var (
			seq   int64
			rec   control.SecurityTransitionRecord
			codes []byte
		)
		if err := rows.Scan(&seq, &rec.At, &rec.Kind, &rec.RequestID, &rec.CredentialID, &rec.LaneID,
			&rec.Before, &rec.After, &rec.RiskScore, &rec.Revision, &rec.PolicyRevision, &codes); err != nil {
			return nil, mapDBError(err)
		}
		if seq < 0 || json.Unmarshal(codes, &rec.EvidenceCodes) != nil {
			return nil, errors.New("statepg: corrupt security transition")
		}
		rec.Sequence = uint64(seq)
		out = append(out, rec)
	}
	return out, mapDBError(rows.Err())
}

var _ control.SecurityTransitionReader = (*Store)(nil)
