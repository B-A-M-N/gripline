package statepg

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/jackc/pgx/v5"
)

var (
	ErrLeaseExpired = errors.New("statepg: resource lease expired")
	ErrLeaseOwner   = errors.New("statepg: resource lease owned by another node")
)

const (
	leaseReserved           = "reserved"
	leaseForwarded          = "forwarded"
	leaseSettled            = "settled"
	leaseReleased           = "released"
	resourceOverflowBuckets = 64
)

var resourceDimensions = []resource.Dimension{
	resource.DimRequests, resource.DimInputTokens, resource.DimOutputTokens,
	resource.DimCombinedTokens, resource.DimCost,
}

func (s *Store) ProvisionDistributed(ctx context.Context, scopes []resource.ScopeSpec, estimate resource.UsageEstimate) (resource.UsageReservation, error) {
	return s.provisionDistributed(ctx, "", scopes, estimate)
}

func (s *Store) ProvisionDistributedWithRequestID(ctx context.Context, requestID string, scopes []resource.ScopeSpec, estimate resource.UsageEstimate) (resource.UsageReservation, error) {
	return s.provisionDistributed(ctx, requestID, scopes, estimate)
}

func (s *Store) provisionDistributed(ctx context.Context, requestID string, scopes []resource.ScopeSpec, estimate resource.UsageEstimate) (resource.UsageReservation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		return nil, errors.New("resource: no scopes to provision")
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return nil, err
	}
	leaseID, err := newLeaseID()
	if err != nil {
		return nil, err
	}
	expiresAt := now.Add(s.leaseTTL)
	if requestID == "" {
		requestID = leaseID
	} else {
		var existingID, existingNode, existingState string
		var existingExpiry time.Time
		err := tx.QueryRow(ctx, `SELECT lease_id, node_id, state, expires_at FROM gripline_resource_leases WHERE request_id=$1`, requestID).Scan(&existingID, &existingNode, &existingState, &existingExpiry)
		if err == nil {
			if existingNode != s.nodeID {
				return nil, ErrLeaseOwner
			}
			if existingState == leaseReleased || !existingExpiry.After(now) {
				return nil, ErrLeaseExpired
			}
			return &distributedReservation{store: s, leaseID: existingID, expiresAt: existingExpiry, forwarded: existingState == leaseForwarded, settled: existingState == leaseSettled}, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, mapDBError(err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_resource_leases (lease_id, request_id, node_id, state, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6)`, leaseID, requestID, s.nodeID, leaseReserved, expiresAt, now); err != nil {
		return nil, mapDBError(err)
	}
	for _, original := range scopes {
		sp, err := s.resolveResourceScope(ctx, tx, original, now)
		if err != nil {
			return nil, err
		}
		if sp.ID == "" {
			return nil, errors.New("resource: scope id required")
		}
		if shouldReserveConcurrency(sp.Buckets) {
			if err := s.reserveResourceGauge(ctx, tx, leaseID, sp, resource.DimConcurrency, 1, now); err != nil {
				return nil, err
			}
		}
		for _, dim := range resourceDimensions {
			cfg := bucketConfig(sp.Buckets, dim)
			if cfg.Capacity <= 0 {
				continue
			}
			amount := usageAmount(estimate, dim)
			if amount < 0 {
				amount = 0
			}
			if err := s.reserveResourceGauge(ctx, tx, leaseID, sp, dim, float64(amount), now); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, mapDBError(err)
	}
	return &distributedReservation{store: s, leaseID: leaseID, expiresAt: expiresAt}, nil
}

func shouldReserveConcurrency(spec resource.BucketSpec) bool {
	return spec.ConcurrencyCap > 0 || (spec.RequestsBurst.Capacity <= 0 && spec.TokensBurst.Capacity <= 0 && spec.CostBurst.Capacity <= 0)
}

func bucketConfig(spec resource.BucketSpec, dim resource.Dimension) resource.BucketConfig {
	switch dim {
	case resource.DimRequests:
		return spec.RequestsBurst
	case resource.DimInputTokens, resource.DimOutputTokens, resource.DimCombinedTokens:
		return spec.TokensBurst
	case resource.DimCost:
		return spec.CostBurst
	default:
		return resource.BucketConfig{}
	}
}

func usageAmount(estimate resource.UsageEstimate, dim resource.Dimension) int64 {
	switch dim {
	case resource.DimRequests:
		return estimate.Requests
	case resource.DimInputTokens:
		return estimate.InputTokens
	case resource.DimOutputTokens:
		return estimate.OutputTokens
	case resource.DimCombinedTokens:
		return estimate.CombinedTokens
	case resource.DimCost:
		return estimate.CostMicrounits
	default:
		return 0
	}
}

func (s *Store) resolveResourceScope(ctx context.Context, tx pgx.Tx, sp resource.ScopeSpec, now time.Time) (resource.ScopeSpec, error) {
	if sp.Scope != resource.ScopeSource || sp.ID == "" {
		return sp, nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM gripline_resource_source_scopes WHERE scope_id=$1)`, sp.ID).Scan(&exists); err != nil {
		return sp, mapDBError(err)
	}
	if !exists {
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_resource_source_scopes`).Scan(&count); err != nil {
			return sp, mapDBError(err)
		}
		if count >= s.maxSourceScopes {
			h := sha256.Sum256([]byte(sp.ID))
			sp.ID = "__source_overflow_" + fmt.Sprintf("%d", uint64(h[0])%resourceOverflowBuckets)
			return sp, nil
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_resource_source_scopes (scope_id, last_used_at) VALUES ($1,$2)
		ON CONFLICT (scope_id) DO UPDATE SET last_used_at=EXCLUDED.last_used_at`, sp.ID, now); err != nil {
		return sp, mapDBError(err)
	}
	return sp, nil
}

type resourceBucketRow struct {
	capacity, refillPer, available float64
	refillInNS                     int64
	concurrencyUsed                int
	updatedAt                      time.Time
}

func (s *Store) loadResourceBucket(ctx context.Context, tx pgx.Tx, sp resource.ScopeSpec, dim resource.Dimension, cfg resource.BucketConfig, now time.Time) (resourceBucketRow, error) {
	var row resourceBucketRow
	err := tx.QueryRow(ctx, `SELECT capacity, refill_per, refill_in_ns, available, concurrency_used, updated_at
		FROM gripline_resource_buckets WHERE scope=$1 AND scope_id=$2 AND dimension=$3 FOR UPDATE`, sp.Scope, sp.ID, dim).
		Scan(&row.capacity, &row.refillPer, &row.refillInNS, &row.available, &row.concurrencyUsed, &row.updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		capacity := cfg.Capacity
		if dim == resource.DimConcurrency {
			capacity = float64(cfgCapacity(sp.Buckets))
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gripline_resource_buckets
			(scope, scope_id, dimension, capacity, refill_per, refill_in_ns, available, concurrency_used, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$4,0,$7)`, sp.Scope, sp.ID, dim, capacity, cfg.RefillPer, cfg.RefillIn.Nanoseconds(), now); err != nil {
			return row, mapDBError(err)
		}
		row = resourceBucketRow{capacity: capacity, refillPer: cfg.RefillPer, refillInNS: cfg.RefillIn.Nanoseconds(), available: capacity, updatedAt: now}
		return row, nil
	}
	if err != nil {
		return row, mapDBError(err)
	}
	oldCapacity, oldRefill, oldInterval := row.capacity, row.refillPer, row.refillInNS
	if dim != resource.DimConcurrency && oldRefill > 0 && oldInterval > 0 && now.After(row.updatedAt) {
		row.available += oldRefill * float64(now.Sub(row.updatedAt).Nanoseconds()) / float64(oldInterval)
		if row.available > oldCapacity {
			row.available = oldCapacity
		}
	}
	capacity := cfg.Capacity
	if dim == resource.DimConcurrency {
		capacity = float64(cfgCapacity(sp.Buckets))
	}
	if row.available > capacity {
		row.available = capacity
	}
	row.capacity, row.refillPer, row.refillInNS, row.updatedAt = capacity, cfg.RefillPer, cfg.RefillIn.Nanoseconds(), now
	if _, err := tx.Exec(ctx, `UPDATE gripline_resource_buckets SET capacity=$4, refill_per=$5, refill_in_ns=$6, available=$7, updated_at=$8
		WHERE scope=$1 AND scope_id=$2 AND dimension=$3`, sp.Scope, sp.ID, dim, row.capacity, row.refillPer, row.refillInNS, row.available, row.updatedAt); err != nil {
		return row, mapDBError(err)
	}
	return row, nil
}

func cfgCapacity(spec resource.BucketSpec) int {
	return spec.ConcurrencyCap
}

func (s *Store) reserveResourceGauge(ctx context.Context, tx pgx.Tx, leaseID string, sp resource.ScopeSpec, dim resource.Dimension, amount float64, now time.Time) error {
	cfg := resource.BucketConfig{}
	if dim == resource.DimConcurrency {
		cfg.Capacity = float64(sp.Buckets.ConcurrencyCap)
	} else {
		cfg = bucketConfig(sp.Buckets, dim)
	}
	row, err := s.loadResourceBucket(ctx, tx, sp, dim, cfg, now)
	if err != nil {
		return err
	}
	if dim == resource.DimConcurrency {
		if row.concurrencyUsed+1 > int(row.capacity) {
			return &resource.ScopeLimitError{Scope: sp.Scope, Dimension: dim}
		}
		row.concurrencyUsed++
	} else {
		if row.available+1e-9 < amount {
			return &resource.ScopeLimitError{Scope: sp.Scope, Dimension: dim}
		}
		row.available -= amount
	}
	if _, err := tx.Exec(ctx, `UPDATE gripline_resource_buckets SET available=$4, concurrency_used=$5, updated_at=$6
		WHERE scope=$1 AND scope_id=$2 AND dimension=$3`, sp.Scope, sp.ID, dim, row.available, row.concurrencyUsed, now); err != nil {
		return mapDBError(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_resource_holds (lease_id, scope, scope_id, dimension, amount, settled) VALUES ($1,$2,$3,$4,$5,FALSE)`, leaseID, sp.Scope, sp.ID, dim, amount); err != nil {
		return mapDBError(err)
	}
	return nil
}

func dbNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return time.Time{}, mapDBError(err)
	}
	return now.UTC(), nil
}

func newLeaseID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("statepg: generate resource lease id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

type distributedReservation struct {
	store                        *Store
	leaseID                      string
	mu                           sync.Mutex
	expiresAt                    time.Time
	forwarded, settled, released bool
}

func (r *distributedReservation) MarkForwarded(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.settled || r.forwarded {
		return nil
	}
	tx, err := begin(ctx, r.store.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	var expires time.Time
	err = tx.QueryRow(ctx, `UPDATE gripline_resource_leases SET state=$1, forwarded_at=$2 WHERE lease_id=$3 AND node_id=$4 AND state=$5 AND expires_at>$2 RETURNING expires_at`, leaseForwarded, now, r.leaseID, r.store.nodeID, leaseReserved).Scan(&expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseExpired
	}
	if err != nil {
		return mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapDBError(err)
	}
	r.forwarded, r.expiresAt = true, expires
	return nil
}

func (r *distributedReservation) Renew(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.settled {
		return ErrLeaseExpired
	}
	tx, err := begin(ctx, r.store.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	var expires time.Time
	err = tx.QueryRow(ctx, `UPDATE gripline_resource_leases SET expires_at=$1 WHERE lease_id=$2 AND node_id=$3 AND state IN ($4,$5) AND expires_at>$6 RETURNING expires_at`, now.Add(r.store.leaseTTL), r.leaseID, r.store.nodeID, leaseReserved, leaseForwarded, now).Scan(&expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseExpired
	}
	if err != nil {
		return mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapDBError(err)
	}
	r.expiresAt = expires
	return nil
}

func (r *distributedReservation) SettleContext(ctx context.Context, actual resource.UsageEstimate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released || r.settled {
		return nil
	}
	tx, err := begin(ctx, r.store.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	var state string
	var expires time.Time
	err = tx.QueryRow(ctx, `SELECT state, expires_at FROM gripline_resource_leases WHERE lease_id=$1 AND node_id=$2 FOR UPDATE`, r.leaseID, r.store.nodeID).Scan(&state, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseOwner
	}
	if err != nil {
		return mapDBError(err)
	}
	if state == leaseReleased || state == leaseSettled {
		return nil
	}
	if !expires.After(now) {
		return ErrLeaseExpired
	}
	holds, err := loadLeaseHolds(ctx, tx, r.leaseID)
	if err != nil {
		return err
	}
	for _, hold := range holds {
		if hold.dimension == int(resource.DimConcurrency) {
			continue
		}
		actualAmount := float64(usageAmount(actual, resource.Dimension(hold.dimension)))
		if actualAmount < 0 {
			actualAmount = 0
		}
		if err := settleBucket(ctx, tx, hold, actualAmount, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE gripline_resource_holds SET amount=$5, settled=TRUE WHERE lease_id=$1 AND scope=$2 AND scope_id=$3 AND dimension=$4`, r.leaseID, hold.scope, hold.scopeID, hold.dimension, actualAmount); err != nil {
			return mapDBError(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE gripline_resource_leases SET state=$1, settled_at=$2 WHERE lease_id=$3`, leaseSettled, now, r.leaseID); err != nil {
		return mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapDBError(err)
	}
	r.settled = true
	return nil
}

type leaseHold struct {
	scope     int
	scopeID   string
	dimension int
	amount    float64
	settled   bool
}

func loadLeaseHolds(ctx context.Context, tx pgx.Tx, leaseID string) ([]leaseHold, error) {
	rows, err := tx.Query(ctx, `SELECT scope, scope_id, dimension, amount, settled FROM gripline_resource_holds WHERE lease_id=$1 ORDER BY scope, scope_id, dimension FOR UPDATE`, leaseID)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer rows.Close()
	var out []leaseHold
	for rows.Next() {
		var h leaseHold
		if err := rows.Scan(&h.scope, &h.scopeID, &h.dimension, &h.amount, &h.settled); err != nil {
			return nil, mapDBError(err)
		}
		out = append(out, h)
	}
	return out, mapDBError(rows.Err())
}

func settleBucket(ctx context.Context, tx pgx.Tx, hold leaseHold, actual float64, now time.Time) error {
	var capacity, refillPer, available float64
	var refillInNS int64
	var used int
	var updated time.Time
	err := tx.QueryRow(ctx, `SELECT capacity, refill_per, refill_in_ns, available, concurrency_used, updated_at FROM gripline_resource_buckets WHERE scope=$1 AND scope_id=$2 AND dimension=$3 FOR UPDATE`, hold.scope, hold.scopeID, hold.dimension).Scan(&capacity, &refillPer, &refillInNS, &available, &used, &updated)
	if err != nil {
		return mapDBError(err)
	}
	if refillPer > 0 && refillInNS > 0 && now.After(updated) {
		available += refillPer * float64(now.Sub(updated).Nanoseconds()) / float64(refillInNS)
		if available > capacity {
			available = capacity
		}
	}
	available -= actual - hold.amount
	if available > capacity {
		available = capacity
	}
	_, err = tx.Exec(ctx, `UPDATE gripline_resource_buckets SET available=$4, updated_at=$5 WHERE scope=$1 AND scope_id=$2 AND dimension=$3`, hold.scope, hold.scopeID, hold.dimension, available, now)
	return mapDBError(err)
}

func (r *distributedReservation) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := releaseLease(ctx, r.store, r.leaseID, r.store.nodeID); err == nil {
		r.released = true
	}
}

func (r *distributedReservation) ExpiresAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.expiresAt
}

func releaseLease(ctx context.Context, s *Store, leaseID, nodeID string) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	var state string
	err = tx.QueryRow(ctx, `SELECT state FROM gripline_resource_leases WHERE lease_id=$1 AND node_id=$2 FOR UPDATE`, leaseID, nodeID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return mapDBError(err)
	}
	if state == leaseReleased {
		return nil
	}
	holds, err := loadLeaseHolds(ctx, tx, leaseID)
	if err != nil {
		return err
	}
	for _, hold := range holds {
		if err := releaseBucket(ctx, tx, hold, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM gripline_resource_holds WHERE lease_id=$1`, leaseID); err != nil {
		return mapDBError(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE gripline_resource_leases SET state=$1, released_at=$2 WHERE lease_id=$3`, leaseReleased, now, leaseID); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

func releaseBucket(ctx context.Context, tx pgx.Tx, hold leaseHold, now time.Time) error {
	var capacity, refillPer, available float64
	var refillInNS int64
	var used int
	var updated time.Time
	err := tx.QueryRow(ctx, `SELECT capacity, refill_per, refill_in_ns, available, concurrency_used, updated_at FROM gripline_resource_buckets WHERE scope=$1 AND scope_id=$2 AND dimension=$3 FOR UPDATE`, hold.scope, hold.scopeID, hold.dimension).Scan(&capacity, &refillPer, &refillInNS, &available, &used, &updated)
	if err != nil {
		return mapDBError(err)
	}
	if hold.dimension == int(resource.DimConcurrency) {
		if used > 0 {
			used--
		}
	} else if !hold.settled {
		if refillPer > 0 && refillInNS > 0 && now.After(updated) {
			available += refillPer * float64(now.Sub(updated).Nanoseconds()) / float64(refillInNS)
			if available > capacity {
				available = capacity
			}
		}
		available += hold.amount
		if available > capacity {
			available = capacity
		}
	}
	_, err = tx.Exec(ctx, `UPDATE gripline_resource_buckets SET available=$4, concurrency_used=$5, updated_at=$6 WHERE scope=$1 AND scope_id=$2 AND dimension=$3`, hold.scope, hold.scopeID, hold.dimension, available, used, now)
	return mapDBError(err)
}

func (s *Store) leaseReaper() {
	interval := s.leaseTTL / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(s.leaseDone)
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			_ = s.reapExpired(ctx)
			cancel()
		case <-s.leaseStop:
			return
		}
	}
}

func (s *Store) reapExpired(ctx context.Context) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT lease_id, node_id FROM gripline_resource_leases WHERE state <> $1 AND expires_at <= $2 ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED`, leaseReleased, now)
	if err != nil {
		return mapDBError(err)
	}
	var expired []struct{ id, node string }
	for rows.Next() {
		var item struct{ id, node string }
		if err := rows.Scan(&item.id, &item.node); err != nil {
			rows.Close()
			return mapDBError(err)
		}
		expired = append(expired, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return mapDBError(err)
	}
	rows.Close()
	for _, item := range expired {
		holds, err := loadLeaseHolds(ctx, tx, item.id)
		if err != nil {
			return err
		}
		for _, hold := range holds {
			if err := releaseBucket(ctx, tx, hold, now); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM gripline_resource_holds WHERE lease_id=$1`, item.id); err != nil {
			return mapDBError(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE gripline_resource_leases SET state=$1, released_at=$2 WHERE lease_id=$3`, leaseReleased, now, item.id); err != nil {
			return mapDBError(err)
		}
	}
	return mapDBError(tx.Commit(ctx))
}

func (s *Store) RemoveScope(scope resource.Scope, id string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return false
	}
	defer tx.Rollback(ctx)
	var active int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_resource_holds h JOIN gripline_resource_leases l ON l.lease_id=h.lease_id WHERE h.scope=$1 AND h.scope_id=$2 AND l.state <> $3`, scope, id, leaseReleased).Scan(&active); err != nil || active != 0 {
		return false
	}
	if _, err := tx.Exec(ctx, `DELETE FROM gripline_resource_buckets WHERE scope=$1 AND scope_id=$2`, scope, id); err != nil {
		return false
	}
	if scope == resource.ScopeSource {
		if _, err := tx.Exec(ctx, `DELETE FROM gripline_resource_source_scopes WHERE scope_id=$1`, id); err != nil {
			return false
		}
	}
	return tx.Commit(ctx) == nil
}

func (s *Store) InUseFor(scope resource.Scope, id string) int {
	var used int
	err := s.pool.QueryRow(context.Background(), `SELECT COALESCE(SUM(concurrency_used),0) FROM gripline_resource_buckets WHERE scope=$1 AND scope_id=$2 AND dimension=$3`, scope, id, resource.DimConcurrency).Scan(&used)
	if err != nil {
		return 0
	}
	return used
}

var (
	_ resource.Authority            = (*Store)(nil)
	_ resource.DistributedAuthority = (*Store)(nil)
)
