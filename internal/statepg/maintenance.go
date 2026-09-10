package statepg

import (
	"context"
	"errors"
	"time"

	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/jackc/pgx/v5"
)

// MaintenanceOptions bounds the amount of historical authority data retained
// by a serving cluster node. Zero values receive conservative defaults. The
// idempotency windows are deliberately explicit: a retry received after its
// receipt has been retired is a new operation, not a replay.
type MaintenanceOptions struct {
	Interval                    time.Duration
	BatchSize                   int
	MaxBatchesPerPass           int
	MaxRowsPerPass              int
	MaxRuntimePerPass           time.Duration
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
	SourceAliasRetention        time.Duration
}

const (
	defaultMaintenanceInterval         = time.Minute
	defaultMaintenanceBatchSize        = 256
	defaultMaintenanceMaxBatches       = 64
	defaultMaintenanceMaxRows          = 4096
	defaultMaintenanceMaxRuntime       = 5 * time.Second
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
	defaultSourceAliasRetention        = 7 * 24 * time.Hour
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
	if o.MaxBatchesPerPass <= 0 {
		o.MaxBatchesPerPass = defaultMaintenanceMaxBatches
	}
	if o.MaxBatchesPerPass > 4096 {
		o.MaxBatchesPerPass = 4096
	}
	if o.MaxRowsPerPass <= 0 {
		o.MaxRowsPerPass = defaultMaintenanceMaxRows
	}
	if o.MaxRowsPerPass > 1<<20 {
		o.MaxRowsPerPass = 1 << 20
	}
	if o.MaxRuntimePerPass <= 0 {
		o.MaxRuntimePerPass = defaultMaintenanceMaxRuntime
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
	if o.SourceAliasRetention <= 0 {
		o.SourceAliasRetention = defaultSourceAliasRetention
	}
	return o
}

// MaintenanceStats reports only aggregate row counts. It is safe to expose as
// low-cardinality health telemetry and contains no subject identifiers.
type MaintenanceStats struct {
	EvidenceDeleted             int
	EvidenceGuardsDeleted       int
	ReleasedLeasesDeleted       int
	CredentialReceiptsDeleted   int
	ControlOperationsDeleted    int
	AdmissionAuditDeleted       int
	SecurityTransitionsDeleted  int
	OperatorAuditDeleted        int
	PolicyAuditDeleted          int
	MembershipDeleted           int
	AdaptiveRowsDeleted         int
	LaneOperatorAuditDeleted    int
	PolicyNodeStateDeleted      int
	ClusterCryptoAcksDeleted    int
	SourceAliasesDeleted        int
	ResourceSourceScopesDeleted int
	RowsDeleted                 int
	Batches                     int
	BacklogEstimate             int
	Duration                    time.Duration
}

func (s MaintenanceStats) rowsDeleted() int {
	return s.EvidenceDeleted + s.EvidenceGuardsDeleted + s.ReleasedLeasesDeleted +
		s.CredentialReceiptsDeleted + s.ControlOperationsDeleted + s.AdmissionAuditDeleted +
		s.SecurityTransitionsDeleted + s.OperatorAuditDeleted + s.PolicyAuditDeleted +
		s.MembershipDeleted + s.AdaptiveRowsDeleted + s.LaneOperatorAuditDeleted +
		s.PolicyNodeStateDeleted + s.ClusterCryptoAcksDeleted + s.SourceAliasesDeleted +
		s.ResourceSourceScopesDeleted
}

func (s *MaintenanceStats) add(other MaintenanceStats) {
	s.EvidenceDeleted += other.EvidenceDeleted
	s.EvidenceGuardsDeleted += other.EvidenceGuardsDeleted
	s.ReleasedLeasesDeleted += other.ReleasedLeasesDeleted
	s.CredentialReceiptsDeleted += other.CredentialReceiptsDeleted
	s.ControlOperationsDeleted += other.ControlOperationsDeleted
	s.AdmissionAuditDeleted += other.AdmissionAuditDeleted
	s.SecurityTransitionsDeleted += other.SecurityTransitionsDeleted
	s.OperatorAuditDeleted += other.OperatorAuditDeleted
	s.PolicyAuditDeleted += other.PolicyAuditDeleted
	s.MembershipDeleted += other.MembershipDeleted
	s.AdaptiveRowsDeleted += other.AdaptiveRowsDeleted
	s.LaneOperatorAuditDeleted += other.LaneOperatorAuditDeleted
	s.PolicyNodeStateDeleted += other.PolicyNodeStateDeleted
	s.ClusterCryptoAcksDeleted += other.ClusterCryptoAcksDeleted
	s.SourceAliasesDeleted += other.SourceAliasesDeleted
	s.ResourceSourceScopesDeleted += other.ResourceSourceScopesDeleted
	s.RowsDeleted += other.RowsDeleted
	s.Batches += other.Batches
	if other.BacklogEstimate > s.BacklogEstimate {
		s.BacklogEstimate = other.BacklogEstimate
	}
}

type maintenanceBudget struct {
	remainingRows int
	maxBatches    int
	batches       int
}

func (b *maintenanceBudget) batchSize(defaultSize int) int {
	if b == nil || b.batches >= b.maxBatches || b.remainingRows <= 0 {
		return 0
	}
	if defaultSize > b.remainingRows {
		return b.remainingRows
	}
	return defaultSize
}

func (b *maintenanceBudget) record(rows int) {
	if b == nil {
		return
	}
	b.batches++
	if rows > 0 {
		b.remainingRows -= rows
	}
}

func (b *maintenanceBudget) exhausted() bool {
	return b == nil || b.batches >= b.maxBatches || b.remainingRows <= 0
}

type maintenanceBudgetContextKey struct{}

func withMaintenanceBudget(ctx context.Context, budget *maintenanceBudget) context.Context {
	return context.WithValue(ctx, maintenanceBudgetContextKey{}, budget)
}

func maintenanceBatchSize(ctx context.Context, configured int) int {
	if budget, ok := ctx.Value(maintenanceBudgetContextKey{}).(*maintenanceBudget); ok {
		return budget.batchSize(configured)
	}
	return configured
}

func recordMaintenanceBatch(ctx context.Context, rows int) {
	if budget, ok := ctx.Value(maintenanceBudgetContextKey{}).(*maintenanceBudget); ok {
		budget.record(rows)
	}
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
func (s *Store) RunMaintenance(ctx context.Context) (stats MaintenanceStats, retErr error) {
	if s == nil || s.pool == nil {
		return MaintenanceStats{}, errors.New("statepg: authority is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.maintenance.MaxRuntimePerPass)
	defer cancel()
	budget := &maintenanceBudget{remainingRows: s.maintenance.MaxRowsPerPass, maxBatches: s.maintenance.MaxBatchesPerPass}
	ctx = withMaintenanceBudget(ctx, budget)
	for {
		batch, err := s.runMaintenanceBatch(ctx)
		stats.add(batch)
		if err != nil {
			retErr = err
			break
		}
		if batch.rowsDeleted() == 0 || budget.exhausted() || ctx.Err() != nil {
			break
		}
	}
	stats.RowsDeleted = stats.rowsDeleted()
	stats.Duration = time.Since(started)
	// A pass can exhaust its wall-clock budget before the row/batch budget. A
	// zero deletion count is not evidence that the queue is empty in that case;
	// publish a conservative non-zero backlog so readiness/telemetry cannot
	// claim retention is caught up after a timed-out pass.
	if budget.batches >= budget.maxBatches || budget.remainingRows <= 0 || ctx.Err() != nil {
		stats.BacklogEstimate = 1
	}
	s.recordMaintenance(stats, retErr)
	return stats, retErr
}

func (s *Store) runMaintenanceBatch(ctx context.Context) (stats MaintenanceStats, retErr error) {
	var err error
	var batchesBefore int
	if budget, ok := ctx.Value(maintenanceBudgetContextKey{}).(*maintenanceBudget); ok {
		batchesBefore = budget.batches
	}
	defer func() {
		if budget, ok := ctx.Value(maintenanceBudgetContextKey{}).(*maintenanceBudget); ok {
			stats.Batches = budget.batches - batchesBefore
		}
	}()
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
	if stats.ResourceSourceScopesDeleted, err = s.maintainSourceScopes(ctx); err != nil {
		return stats, err
	}
	if stats.SourceAliasesDeleted, err = s.maintainSourceAliases(ctx); err != nil {
		return stats, err
	}
	return stats, nil
}

func (s *Store) maintainSourceAliases(ctx context.Context) (int, error) {
	batchSize := maintenanceBatchSize(ctx, s.maintenance.BatchSize)
	if batchSize <= 0 {
		return 0, nil
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return 0, err
	}
	query := `WITH doomed AS (
		SELECT a.alias
		FROM gripline_source_aliases a
		WHERE (
			(
				a.last_seen_at < $1
				AND NOT ` + sourceIdentityReferencePredicate("a.canonical_source_id") + `
			)
			OR (
				EXISTS (SELECT 1 FROM gripline_cluster_crypto_generations g
					WHERE g.kind='pseudonym' AND g.generation=a.generation AND g.state='retired')
				AND EXISTS (SELECT 1 FROM gripline_source_aliases retained
					WHERE retained.canonical_source_id=a.canonical_source_id
					  AND retained.generation<>a.generation)
			)
		)
		ORDER BY a.last_seen_at, a.alias
		LIMIT $2 FOR UPDATE SKIP LOCKED
	)
	DELETE FROM gripline_source_aliases a USING doomed d WHERE a.alias=d.alias`
	tag, err := tx.Exec(ctx, query, now.Add(-s.maintenance.SourceAliasRetention), batchSize)
	if err != nil {
		return 0, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, mapDBError(err)
	}
	recordMaintenanceBatch(ctx, int(tag.RowsAffected()))
	return int(tag.RowsAffected()), nil
}

func (s *Store) maintainSourceScopes(ctx context.Context) (int, error) {
	batchSize := maintenanceBatchSize(ctx, s.maintenance.BatchSize)
	if batchSize <= 0 {
		return 0, nil
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return 0, err
	}
	ids, err := s.safeIdleSourceScopeIDs(ctx, tx, now, batchSize)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return 0, mapDBError(err)
		}
		return 0, nil
	}
	result, err := tx.Exec(ctx, `DELETE FROM gripline_resource_buckets WHERE scope=$1 AND scope_id=ANY($2::text[])`, resource.ScopeSource, ids)
	if err != nil {
		return 0, mapDBError(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM gripline_resource_source_scopes WHERE scope_id=ANY($1::text[])`, ids); err != nil {
		return 0, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, mapDBError(err)
	}
	recordMaintenanceBatch(ctx, len(ids)+int(result.RowsAffected()))
	return len(ids), nil
}

func (s *Store) maintainCutoff(ctx context.Context, retention time.Duration, query string) (int, error) {
	batchSize := maintenanceBatchSize(ctx, s.maintenance.BatchSize)
	if batchSize <= 0 {
		return 0, nil
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, query, now.Add(-retention), batchSize)
	if err != nil {
		return 0, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, mapDBError(err)
	}
	recordMaintenanceBatch(ctx, int(tag.RowsAffected()))
	return int(tag.RowsAffected()), nil
}

func (s *Store) maintainReleasedLeases(ctx context.Context) (int, error) {
	batchSize := maintenanceBatchSize(ctx, s.maintenance.BatchSize)
	if batchSize <= 0 {
		return 0, nil
	}
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
		DELETE FROM gripline_resource_leases l USING doomed d WHERE l.lease_id=d.lease_id`, leaseReleased, now.Add(-s.maintenance.ReleasedLeaseRetention), batchSize)
	if err != nil {
		return 0, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, mapDBError(err)
	}
	recordMaintenanceBatch(ctx, int(tag.RowsAffected()))
	return int(tag.RowsAffected()), nil
}

func (s *Store) maintainExpiredEvidence(ctx context.Context) (int, int, error) {
	batchSize := maintenanceBatchSize(ctx, s.maintenance.BatchSize)
	if batchSize <= 0 {
		return 0, 0, nil
	}
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
		WHERE e.scope=d.scope AND e.subject_id=d.subject_id AND e.evidence_id=d.evidence_id`, now.Add(-s.maintenance.EvidenceGrace), batchSize)
	if err != nil {
		return 0, 0, mapDBError(err)
	}
	recordMaintenanceBatch(ctx, int(result.RowsAffected()))
	guardBatchSize := maintenanceBatchSize(ctx, s.maintenance.BatchSize)
	if guardBatchSize <= 0 {
		if err := tx.Commit(ctx); err != nil {
			return 0, 0, mapDBError(err)
		}
		return int(result.RowsAffected()), 0, nil
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
		WHERE g.scope=d.scope AND g.subject_id=d.subject_id`, now.Add(-s.maintenance.EvidenceGuardRetention), guardBatchSize)
	if err != nil {
		return 0, 0, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, mapDBError(err)
	}
	recordMaintenanceBatch(ctx, int(guardResult.RowsAffected()))
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
