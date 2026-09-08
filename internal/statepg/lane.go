package statepg

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/jackc/pgx/v5"
)

func decodeLane(raw []byte) (*lane.LaneRecord, error) {
	var rec lane.LaneRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.LaneID == "" || rec.CredentialID == "" {
		return nil, errors.New("statepg: corrupt lane record")
	}
	return &rec, nil
}

func encodeLane(rec *lane.LaneRecord) ([]byte, error) {
	if rec == nil || rec.LaneID == "" || rec.CredentialID == "" {
		return nil, errors.New("statepg: invalid lane record")
	}
	return json.Marshal(rec)
}

func loadLanes(ctx context.Context, tx pgx.Tx, credID string, lock bool) ([]*lane.LaneRecord, error) {
	query := `SELECT record FROM gripline_lanes WHERE credential_id=$1 ORDER BY lane_id`
	if lock {
		query += ` FOR UPDATE`
	}
	rows, err := tx.Query(ctx, query, credID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*lane.LaneRecord
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		rec, err := decodeLane(raw)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func putLane(ctx context.Context, tx pgx.Tx, rec *lane.LaneRecord) error {
	raw, err := encodeLane(rec)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gripline_lanes (credential_id, lane_id, record) VALUES ($1,$2,$3) ON CONFLICT (credential_id,lane_id) DO UPDATE SET record=EXCLUDED.record`, rec.CredentialID, rec.LaneID, raw)
	return err
}

// lockLaneGuard serializes every mutation for one credential, including
// operations that touch different lane rows. Serializable isolation alone can
// report retryable serialization failures; the explicit guard makes the
// bounded lane-set reducer's ordering deterministic before it runs.
func (s *Store) lockLaneGuard(ctx context.Context, tx pgx.Tx, credID string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_lane_guards (credential_id, created_at) VALUES ($1,$2) ON CONFLICT (credential_id) DO NOTHING`, credID, s.now().UTC()); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT credential_id FROM gripline_lane_guards WHERE credential_id=$1 FOR UPDATE`, credID)
	return err
}

// BorrowOrCreate implements lane.Repository with a serializable transaction
// over the complete credential lane set. This preserves the bounded-set
// reducer's all-or-nothing behavior across gateway processes.
func (s *Store) BorrowOrCreate(credID, candidateID string, features lane.Features, classification lane.ClassificationContext) (*lane.LaneRecord, bool, error) {
	policy := lane.DefaultPolicyContext()
	policy.Classification = classification
	return s.BorrowOrCreateWithPolicy(context.Background(), credID, candidateID, features, policy)
}

func (s *Store) BorrowOrCreateWithPolicy(ctx context.Context, credID, candidateID string, features lane.Features, policy lane.PolicyContext) (*lane.LaneRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return nil, false, err
	}
	if err := s.lockLaneGuard(ctx, tx, credID); err != nil {
		return nil, false, err
	}
	records, err := loadLanes(ctx, tx, credID, true)
	if err != nil {
		return nil, false, err
	}
	limits := policy.Limits
	if limits.MaxActiveLanesPerCredential <= 0 {
		limits = lane.DefaultLimits()
	}
	result, domainErr := lane.ApplyBorrowOrCreate(records, credID, candidateID, features, policy.Classification, limits, s.now())
	for _, id := range result.Deletes {
		if _, err := tx.Exec(ctx, `DELETE FROM gripline_lanes WHERE credential_id=$1 AND lane_id=$2`, credID, id); err != nil {
			return nil, false, err
		}
	}
	if domainErr != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		return nil, false, domainErr
	}
	if result.Upsert == nil {
		return nil, false, errors.New("statepg: lane reducer returned no record")
	}
	if err := putLane(ctx, tx, result.Upsert); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return result.Upsert, result.Created, nil
}

func (s *Store) Get(credID, laneID string) (*lane.LaneRecord, bool) {
	rec, ok, _ := s.LookupLane(context.Background(), credID, laneID)
	return rec, ok
}

func (s *Store) LookupLane(ctx context.Context, credID, laneID string) (*lane.LaneRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT record FROM gripline_lanes WHERE credential_id=$1 AND lane_id=$2`, credID, laneID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rec, err := decodeLane(raw)
	if err != nil {
		return nil, false, err
	}
	return rec, true, nil
}

func (s *Store) ListLaneIDs(credID string) []string {
	ids, _ := s.ListIDs(context.Background(), credID)
	return ids
}

func (s *Store) ListIDs(ctx context.Context, credID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT lane_id FROM gripline_lanes WHERE credential_id=$1 ORDER BY lane_id`, credID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListLaneRecords returns fully decoded authoritative rows for administrative
// inspection. Decode failures remain visible to the caller.
func (s *Store) ListLaneRecords(credID string) ([]*lane.LaneRecord, error) {
	rows, err := s.pool.Query(context.Background(), `SELECT record FROM gripline_lanes WHERE credential_id=$1 ORDER BY lane_id`, credID)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer rows.Close()
	var out []*lane.LaneRecord
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, mapDBError(err)
		}
		rec, err := decodeLane(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, mapDBError(rows.Err())
}

func (s *Store) ObserveRisk(credID, laneID string, riskScore int, now time.Time) (*lane.LaneRecord, error) {
	return s.ObserveRiskWithPolicy(context.Background(), credID, laneID, riskScore, now, lane.DefaultPolicyContext(), lane.TransitionMetadata{})
}

func (s *Store) ObserveRiskWithRequestID(credID, laneID string, riskScore int, now time.Time, requestID string) (*lane.LaneRecord, error) {
	return s.ObserveRiskWithPolicy(context.Background(), credID, laneID, riskScore, now, lane.DefaultPolicyContext(), lane.TransitionMetadata{RequestID: requestID})
}

func (s *Store) ObserveRiskWithMetadata(credID, laneID string, riskScore int, now time.Time, meta lane.TransitionMetadata) (*lane.LaneRecord, error) {
	return s.ObserveRiskWithPolicy(context.Background(), credID, laneID, riskScore, now, lane.DefaultPolicyContext(), meta)
}

func (s *Store) ObserveRiskWithPolicy(ctx context.Context, credID, laneID string, riskScore int, now time.Time, policy lane.PolicyContext, meta lane.TransitionMetadata) (*lane.LaneRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return nil, err
	}
	if err := s.lockLaneGuard(ctx, tx, credID); err != nil {
		return nil, err
	}
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT record FROM gripline_lanes WHERE credential_id=$1 AND lane_id=$2 FOR UPDATE`, credID, laneID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, lane.ErrLaneNotFound
	}
	if err != nil {
		return nil, err
	}
	rec, err := decodeLane(raw)
	if err != nil {
		return nil, err
	}
	security := lane.EffectiveSecurityHysteresis(policy.Security, policy.Limits.Security)
	if meta.PolicyRevision == 0 {
		meta.PolicyRevision = policy.PolicyRevision
	}
	before := rec.Security.Status
	lane.ApplyRiskObservation(rec, riskScore, security, now)
	if err := putLane(ctx, tx, rec); err != nil {
		return nil, err
	}
	if before != rec.Security.Status {
		if err := appendSecurityTransition(ctx, tx, control.SecurityTransitionRecord{
			At: now.UTC(), Kind: "lane_security", RequestID: meta.RequestID,
			CredentialID: credID, LaneID: laneID, Before: before.String(), After: rec.Security.Status.String(),
			RiskScore: riskScore, Revision: rec.Revision, PolicyRevision: meta.PolicyRevision,
			EvidenceCodes: append([]string(nil), meta.EvidenceCodes...),
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *Store) RecordCleanAuthorizedAndPromote(credID, laneID string, riskScore int, criteria lane.PromotionCriteria, now time.Time) (*lane.LaneRecord, bool, error) {
	return s.RecordCleanAuthorizedAndPromoteWithPolicy(context.Background(), credID, laneID, riskScore, criteria, now, lane.DefaultPolicyContext(), lane.TransitionMetadata{})
}

func (s *Store) RecordCleanAuthorizedAndPromoteWithRequestID(credID, laneID string, riskScore int, criteria lane.PromotionCriteria, now time.Time, requestID string) (*lane.LaneRecord, bool, error) {
	return s.RecordCleanAuthorizedAndPromoteWithPolicy(context.Background(), credID, laneID, riskScore, criteria, now, lane.DefaultPolicyContext(), lane.TransitionMetadata{RequestID: requestID})
}

func (s *Store) RecordCleanAuthorizedAndPromoteWithMetadata(credID, laneID string, riskScore int, criteria lane.PromotionCriteria, now time.Time, meta lane.TransitionMetadata) (*lane.LaneRecord, bool, error) {
	return s.RecordCleanAuthorizedAndPromoteWithPolicy(context.Background(), credID, laneID, riskScore, criteria, now, lane.DefaultPolicyContext(), meta)
}

func (s *Store) RecordCleanAuthorizedAndPromoteWithPolicy(ctx context.Context, credID, laneID string, riskScore int, criteria lane.PromotionCriteria, now time.Time, policy lane.PolicyContext, meta lane.TransitionMetadata) (*lane.LaneRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return nil, false, err
	}
	if err := s.lockLaneGuard(ctx, tx, credID); err != nil {
		return nil, false, err
	}
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT record FROM gripline_lanes WHERE credential_id=$1 AND lane_id=$2 FOR UPDATE`, credID, laneID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, lane.ErrLaneNotFound
	}
	if err != nil {
		return nil, false, err
	}
	rec, err := decodeLane(raw)
	if err != nil {
		return nil, false, err
	}
	if meta.PolicyRevision == 0 {
		meta.PolicyRevision = policy.PolicyRevision
	}
	before := rec.State
	promoted := lane.ApplyCleanAuthorizedAndPromote(rec, riskScore, criteria, now)
	if err := putLane(ctx, tx, rec); err != nil {
		return nil, false, err
	}
	if before != rec.State {
		if err := appendSecurityTransition(ctx, tx, control.SecurityTransitionRecord{
			At: now.UTC(), Kind: "lane_trust", RequestID: meta.RequestID,
			CredentialID: credID, LaneID: laneID, Before: before.String(), After: rec.State.String(),
			RiskScore: riskScore, Revision: rec.Revision, PolicyRevision: meta.PolicyRevision,
			EvidenceCodes: append([]string(nil), meta.EvidenceCodes...),
		}); err != nil {
			return nil, false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return rec, promoted, nil
}

var _ lane.Repository = (*Store)(nil)
var _ lane.PolicyAwareRepository = (*Store)(nil)
var _ lane.ReadRepository = (*Store)(nil)
