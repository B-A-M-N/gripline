package statepg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// MaintenanceOptions bounds the amount of historical authority data retained
// by a serving cluster node. Zero values receive conservative defaults. The
// idempotency windows are deliberately explicit: a retry received after its
// receipt has been retired is a new operation, not a replay.
type MaintenanceOptions struct {
	Interval                    time.Duration
	BatchSize                   int
	EvidenceGrace               time.Duration
	ReleasedLeaseRetention      time.Duration
	CredentialReceiptRetention  time.Duration
	ControlOperationRetention   time.Duration
	AdmissionAuditRetention     time.Duration
	SecurityTransitionRetention time.Duration
	OperatorAuditRetention      time.Duration
	PolicyAuditRetention        time.Duration
	MembershipRetention         time.Duration
	AdaptiveRetention           time.Duration
	EvidenceGuardRetention      time.Duration
	LaneOperatorAuditRetention  time.Duration
	PolicyNodeStateRetention    time.Duration
	ClusterCryptoAckRetention   time.Duration
}

const (
	defaultMaintenanceInterval         = time.Minute
	defaultMaintenanceBatchSize        = 256
	defaultReleasedLeaseRetention      = 24 * time.Hour
	defaultCredentialReceiptRetention  = 24 * time.Hour
	defaultControlOperationRetention   = 24 * time.Hour
	defaultAdmissionAuditRetention     = 90 * 24 * time.Hour
	defaultSecurityTransitionRetention = 90 * 24 * time.Hour
	defaultOperatorAuditRetention      = 365 * 24 * time.Hour
	defaultPolicyAuditRetention        = 365 * 24 * time.Hour
	defaultMembershipRetention         = 24 * time.Hour
	defaultAdaptiveRetention           = 7 * 24 * time.Hour
	defaultEvidenceGuardRetention      = 24 * time.Hour
	defaultLaneOperatorAuditRetention  = 365 * 24 * time.Hour
	defaultPolicyNodeStateRetention    = 24 * time.Hour
	defaultClusterCryptoAckRetention   = 24 * time.Hour
)

func (o MaintenanceOptions) withDefaults() MaintenanceOptions {
	if o.Interval <= 0 {
		o.Interval = defaultMaintenanceInterval
	}
	if o.BatchSize <= 0 {
		o.BatchSize = defaultMaintenanceBatchSize
	}
	if o.BatchSize > 4096 {
		o.BatchSize = 4096
	}
	if o.EvidenceGrace < 0 {
		o.EvidenceGrace = 0
	}
	if o.ReleasedLeaseRetention <= 0 {
		o.ReleasedLeaseRetention = defaultReleasedLeaseRetention
	}
	if o.CredentialReceiptRetention <= 0 {
		o.CredentialReceiptRetention = defaultCredentialReceiptRetention
	}
	if o.ControlOperationRetention <= 0 {
		o.ControlOperationRetention = defaultControlOperationRetention
	}
	if o.AdmissionAuditRetention <= 0 {
		o.AdmissionAuditRetention = defaultAdmissionAuditRetention
	}
	if o.SecurityTransitionRetention <= 0 {
		o.SecurityTransitionRetention = defaultSecurityTransitionRetention
	}
	if o.OperatorAuditRetention <= 0 {
		o.OperatorAuditRetention = defaultOperatorAuditRetention
	}
	if o.PolicyAuditRetention <= 0 {
		o.PolicyAuditRetention = defaultPolicyAuditRetention
	}
	if o.MembershipRetention <= 0 {
		o.MembershipRetention = defaultMembershipRetention
	}
	if o.AdaptiveRetention <= 0 {
		o.AdaptiveRetention = defaultAdaptiveRetention
	}
	if o.EvidenceGuardRetention <= 0 {
		o.EvidenceGuardRetention = defaultEvidenceGuardRetention
	}
	if o.LaneOperatorAuditRetention <= 0 {
		o.LaneOperatorAuditRetention = defaultLaneOperatorAuditRetention
	}
	if o.PolicyNodeStateRetention <= 0 {
		o.PolicyNodeStateRetention = defaultPolicyNodeStateRetention
	}
	if o.ClusterCryptoAckRetention <= 0 {
		o.ClusterCryptoAckRetention = defaultClusterCryptoAckRetention
	}
	return o
}

// MaintenanceStats reports only aggregate row counts. It is safe to expose as
// low-cardinality health telemetry and contains no subject identifiers.
type MaintenanceStats struct {
	EvidenceDeleted            int
	EvidenceGuardsDeleted      int
	ReleasedLeasesDeleted      int
	CredentialReceiptsDeleted  int
	ControlOperationsDeleted   int
	AdmissionAuditDeleted      int
	SecurityTransitionsDeleted int
	OperatorAuditDeleted       int
	PolicyAuditDeleted         int
	MembershipDeleted          int
	AdaptiveRowsDeleted        int
	LaneOperatorAuditDeleted   int
	PolicyNodeStateDeleted     int
	ClusterCryptoAcksDeleted   int
}

// maintenanceLoop runs on serving nodes only. Each pass uses short
// transactions and SKIP LOCKED, so several replicas can maintain the same
// authority without a coordinator or a long table lock.
func (s *Store) maintenanceLoop() {
	ticker := time.NewTicker(s.maintenance.Interval)
	defer ticker.Stop()
	defer close(s.maintenanceDone)
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), s.maintenance.Interval)
			_, _ = s.RunMaintenance(ctx)
			cancel()
		case <-s.maintenanceStop:
			return
		}
	}
}

// RunMaintenance executes one bounded cleanup pass. It is public so
// operators and tests can trigger a pass without waiting for the periodic
// interval. A failure is returned instead of being treated as an empty table;
// retention is operational hygiene, not a security fallback.
func (s *Store) RunMaintenance(ctx context.Context) (MaintenanceStats, error) {
	if s == nil || s.pool == nil {
		return MaintenanceStats{}, errors.New("statepg: authority is unavailable")
	}
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	var stats MaintenanceStats
	var err error
	if stats.EvidenceDeleted, stats.EvidenceGuardsDeleted, err = s.maintainExpiredEvidence(ctx); err != nil {
		return stats, err
	}
	if stats.ReleasedLeasesDeleted, err = s.maintainReleasedLeases(ctx); err != nil {
		return stats, err
	}
	if stats.CredentialReceiptsDeleted, err = s.maintainCutoff(ctx, s.maintenance.CredentialReceiptRetention, `
		WITH doomed AS (
			SELECT request_id, credential_id FROM gripline_credential_receipts
			WHERE created_at < $1 ORDER BY created_at, request_id, credential_id
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_credential_receipts r USING doomed d
		WHERE r.request_id=d.request_id AND r.credential_id=d.credential_id`); err != nil {
		return stats, err
	}
	if stats.ControlOperationsDeleted, err = s.maintainCutoff(ctx, s.maintenance.ControlOperationRetention, `
		WITH doomed AS (
			SELECT operation_id FROM gripline_control_operations
			WHERE created_at < $1 ORDER BY created_at, operation_id
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_control_operations o USING doomed d
		WHERE o.operation_id=d.operation_id`); err != nil {
		return stats, err
	}
	if stats.AdmissionAuditDeleted, err = s.maintainCutoff(ctx, s.maintenance.AdmissionAuditRetention, `
		WITH doomed AS (
			SELECT sequence FROM gripline_admission_audit
			WHERE at < $1 ORDER BY at, sequence
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_admission_audit a USING doomed d WHERE a.sequence=d.sequence`); err != nil {
		return stats, err
	}
	if stats.SecurityTransitionsDeleted, err = s.maintainCutoff(ctx, s.maintenance.SecurityTransitionRetention, `
		WITH doomed AS (
			SELECT sequence FROM gripline_security_transitions
			WHERE at < $1 ORDER BY at, sequence
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_security_transitions a USING doomed d WHERE a.sequence=d.sequence`); err != nil {
		return stats, err
	}
	if stats.OperatorAuditDeleted, err = s.maintainCutoff(ctx, s.maintenance.OperatorAuditRetention, `
		WITH doomed AS (
			SELECT sequence FROM gripline_operator_audit
			WHERE at < $1 ORDER BY at, sequence
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_operator_audit a USING doomed d WHERE a.sequence=d.sequence`); err != nil {
		return stats, err
	}
	if stats.LaneOperatorAuditDeleted, err = s.maintainCutoff(ctx, s.maintenance.LaneOperatorAuditRetention, `
		WITH doomed AS (
			SELECT id FROM gripline_lane_operator_audit
			WHERE at < $1 ORDER BY at, id
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_lane_operator_audit a USING doomed d WHERE a.id=d.id`); err != nil {
		return stats, err
	}
	if stats.PolicyAuditDeleted, err = s.maintainCutoff(ctx, s.maintenance.PolicyAuditRetention, `
		WITH doomed AS (
			SELECT sequence FROM gripline_policy_audit
			WHERE created_at < $1 ORDER BY created_at, sequence
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_policy_audit a USING doomed d WHERE a.sequence=d.sequence`); err != nil {
		return stats, err
	}
	if stats.MembershipDeleted, err = s.maintainCutoff(ctx, s.maintenance.MembershipRetention, `
		WITH doomed AS (
			SELECT node_id FROM gripline_membership
			WHERE state='stopped' AND last_seen_at < $1 ORDER BY last_seen_at, node_id
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_membership m USING doomed d WHERE m.node_id=d.node_id AND m.state='stopped'`); err != nil {
		return stats, err
	}
	if stats.PolicyNodeStateDeleted, err = s.maintainStaleNodeEpochs(ctx, s.maintenance.PolicyNodeStateRetention, `gripline_policy_node_state`, `updated_at`); err != nil {
		return stats, err
	}
	if stats.ClusterCryptoAcksDeleted, err = s.maintainStaleNodeEpochs(ctx, s.maintenance.ClusterCryptoAckRetention, `gripline_cluster_crypto_acks`, `acknowledged_at`); err != nil {
		return stats, err
	}
	if stats.AdaptiveRowsDeleted, err = s.maintainAdaptive(ctx); err != nil {
		return stats, err
	}
	return stats, nil
}

func (s *Store) maintainCutoff(ctx context.Context, retention time.Duration, query string) (int, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, query, now.Add(-retention), s.maintenance.BatchSize)
	if err != nil {
		return 0, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, mapDBError(err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) maintainReleasedLeases(ctx context.Context) (int, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `
		WITH doomed AS (
			SELECT l.lease_id FROM gripline_resource_leases l
			WHERE l.state=$1 AND COALESCE(l.released_at, l.created_at) < $2
			  AND NOT EXISTS (SELECT 1 FROM gripline_resource_holds h WHERE h.lease_id=l.lease_id)
			ORDER BY COALESCE(l.released_at, l.created_at), l.lease_id
			LIMIT $3 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_resource_leases l USING doomed d WHERE l.lease_id=d.lease_id`, leaseReleased, now.Add(-s.maintenance.ReleasedLeaseRetention), s.maintenance.BatchSize)
	if err != nil {
		return 0, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, mapDBError(err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) maintainExpiredEvidence(ctx context.Context) (int, int, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, 0, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return 0, 0, err
	}
	result, err := tx.Exec(ctx, `
		WITH doomed AS (
			SELECT scope, subject_id, evidence_id
			FROM gripline_evidence
			WHERE expires_at IS NOT NULL AND expires_at <= $1
			ORDER BY expires_at, scope, subject_id, evidence_id
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_evidence e USING doomed d
		WHERE e.scope=d.scope AND e.subject_id=d.subject_id AND e.evidence_id=d.evidence_id`, now.Add(-s.maintenance.EvidenceGrace), s.maintenance.BatchSize)
	if err != nil {
		return 0, 0, mapDBError(err)
	}
	// Empty guards would otherwise become an unbounded historical subject
	// index. An append creates/locks the guard again when the subject reappears.
	guardResult, err := tx.Exec(ctx, `
		WITH doomed AS (
			SELECT g.scope, g.subject_id
			FROM gripline_evidence_guards g
			WHERE g.created_at < $1
			  AND NOT EXISTS (SELECT 1 FROM gripline_evidence e
				WHERE e.scope=g.scope AND e.subject_id=g.subject_id)
			ORDER BY g.created_at, g.scope, g.subject_id
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_evidence_guards g USING doomed d
		WHERE g.scope=d.scope AND g.subject_id=d.subject_id`, now.Add(-s.maintenance.EvidenceGuardRetention), s.maintenance.BatchSize)
	if err != nil {
		return 0, 0, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, mapDBError(err)
	}
	return int(result.RowsAffected()), int(guardResult.RowsAffected()), nil
}

func (s *Store) maintainStaleNodeEpochs(ctx context.Context, retention time.Duration, table, timestampColumn string) (int, error) {
	query := `
		WITH doomed AS (
			SELECT t.node_id, t.node_epoch
			FROM ` + table + ` t
			LEFT JOIN gripline_membership m ON m.node_id=t.node_id AND m.node_epoch=t.node_epoch
			WHERE m.node_id IS NULL AND t.` + timestampColumn + ` < $1
			ORDER BY t.` + timestampColumn + `, t.node_id, t.node_epoch
			LIMIT $2 FOR UPDATE OF t SKIP LOCKED
		)
		DELETE FROM ` + table + ` t USING doomed d
		WHERE t.node_id=d.node_id AND t.node_epoch=d.node_epoch`
	return s.maintainCutoff(ctx, retention, query)
}

func (s *Store) maintainAdaptive(ctx context.Context) (int, error) {
	keys, err := s.maintainCutoff(ctx, s.maintenance.AdaptiveRetention, `
		WITH doomed AS (
			SELECT detector, subject, observation_key FROM gripline_adaptive_window_keys
			WHERE observed_at < $1 ORDER BY observed_at, detector, subject, observation_key
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_adaptive_window_keys k USING doomed d
		WHERE k.detector=d.detector AND k.subject=d.subject AND k.observation_key=d.observation_key`)
	if err != nil {
		return 0, err
	}
	baselines, err := s.maintainCutoff(ctx, s.maintenance.AdaptiveRetention, `
		WITH doomed AS (
			SELECT detector, subject, metric FROM gripline_adaptive_baselines
			WHERE last_seen_at < $1 ORDER BY last_seen_at, detector, subject, metric
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_adaptive_baselines b USING doomed d
		WHERE b.detector=d.detector AND b.subject=d.subject AND b.metric=d.metric`)
	if err != nil {
		return keys, err
	}
	subjects, err := s.maintainCutoff(ctx, s.maintenance.AdaptiveRetention, `
		WITH doomed AS (
			SELECT detector, subject FROM gripline_adaptive_window_subjects
			WHERE last_seen_at < $1 ORDER BY last_seen_at, detector, subject
			LIMIT $2 FOR UPDATE SKIP LOCKED
		)
		DELETE FROM gripline_adaptive_window_subjects w USING doomed d
		WHERE w.detector=d.detector AND w.subject=d.subject`)
	if err != nil {
		return keys + baselines, err
	}
	return keys + baselines + subjects, nil
}
