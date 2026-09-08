package statepg

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

const currentProtocolVersion = 1

var (
	ErrNodeAlreadyActive = errors.New("statepg: node id already has a live instance")
	ErrNodeFenced        = errors.New("statepg: node instance has been fenced")
	ErrNodeDraining      = errors.New("statepg: node is draining")
)

func (s *Store) registerNode(ctx context.Context) error {
	var instanceID string
	var epoch int64
	err := s.withTransactionRetry(ctx, "node registration", func() error {
		var err error
		instanceID, epoch, err = s.registerNodeOnce(ctx)
		return err
	})
	if err != nil {
		return err
	}
	s.instanceID = instanceID
	s.nodeEpoch = epoch
	s.fenced.Store(false)
	return nil
}

func (s *Store) registerNodeOnce(ctx context.Context) (string, int64, error) {
	instanceID, err := newLeaseID()
	if err != nil {
		return "", 0, fmt.Errorf("statepg: generate node instance id: %w", err)
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return "", 0, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return "", 0, err
	}

	var (
		existingInstance string
		existingEpoch    int64
		existingProtocol int
		existingSchema   int
		existingState    string
		existingLastSeen time.Time
	)
	err = tx.QueryRow(ctx, `SELECT instance_id, node_epoch, protocol_version, schema_version, state, last_seen_at
		FROM gripline_membership WHERE node_id=$1 FOR UPDATE`, s.nodeID).
		Scan(&existingInstance, &existingEpoch, &existingProtocol, &existingSchema, &existingState, &existingLastSeen)
	hasExisting := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", 0, mapDBError(err)
	}
	if hasExisting && isLiveMembershipState(existingState) && now.Sub(existingLastSeen) < s.leaseTTL {
		return "", 0, ErrNodeAlreadyActive
	}

	// Check protocol/schema compatibility before taking ownership. A node that
	// is being replaced is checked above; other live nodes must still agree on
	// the exact authority layout this process will use.
	rows, err := tx.Query(ctx, `SELECT protocol_version, schema_version FROM gripline_membership
		WHERE node_id <> $1 AND state IN ('ready','draining') AND last_seen_at > $2::timestamptz - ($3::double precision * interval '1 second')`, s.nodeID, now, int64(s.leaseTTL/time.Second))
	if err != nil {
		return "", 0, mapDBError(err)
	}
	for rows.Next() {
		var protocol, schema int
		if err := rows.Scan(&protocol, &schema); err != nil {
			rows.Close()
			return "", 0, mapDBError(err)
		}
		if protocol != currentProtocolVersion || schema != currentSchemaVersion {
			rows.Close()
			return "", 0, fmt.Errorf("statepg: incompatible live node protocol=%d schema=%d (local protocol=%d schema=%d)", protocol, schema, currentProtocolVersion, currentSchemaVersion)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", 0, mapDBError(err)
	}
	rows.Close()

	epoch := int64(1)
	if hasExisting {
		if existingEpoch == math.MaxInt64 {
			return "", 0, errors.New("statepg: node fencing generation exhausted")
		}
		epoch = existingEpoch + 1
		if _, err := tx.Exec(ctx, `UPDATE gripline_membership SET instance_id=$1, node_epoch=$2,
			protocol_version=$3, schema_version=$4, state='ready', last_seen_at=$5, drain_until=NULL
			WHERE node_id=$6`, instanceID, epoch, currentProtocolVersion, currentSchemaVersion, now, s.nodeID); err != nil {
			return "", 0, mapDBError(err)
		}
	} else if _, err := tx.Exec(ctx, `INSERT INTO gripline_membership
		(node_id, instance_id, node_epoch, protocol_version, schema_version, state, last_seen_at)
		VALUES ($1,$2,$3,$4,$5,'ready',$6)`, s.nodeID, instanceID, epoch, currentProtocolVersion, currentSchemaVersion, now); err != nil {
		return "", 0, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", 0, mapDBError(err)
	}
	return instanceID, epoch, nil
}

func isLiveMembershipState(state string) bool {
	return state == "ready" || state == "draining"
}

func (s *Store) membershipHeartbeat() {
	interval := s.leaseTTL / 3
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(s.membershipDone)
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			_ = s.heartbeatNode(ctx)
			cancel()
		case <-s.membershipStop:
			return
		}
	}
}

func (s *Store) heartbeatNode(ctx context.Context) error {
	if s.fenced.Load() {
		return ErrNodeFenced
	}
	tag, err := s.pool.Exec(ctx, `UPDATE gripline_membership SET last_seen_at=CURRENT_TIMESTAMP
		WHERE node_id=$1 AND instance_id=$2 AND node_epoch=$3 AND state IN ('ready','draining')`, s.nodeID, s.instanceID, s.nodeEpoch)
	if err != nil {
		return mapDBError(err)
	}
	if tag.RowsAffected() == 0 {
		s.fenced.Store(true)
		return ErrNodeFenced
	}
	return nil
}

// requireNodeOwnership is used inside authority transactions. The row lock
// makes a replacement wait until the current mutation commits, so a stale
// process cannot pass an ownership check and then create or mutate state after
// its node ID has been acquired by a new instance.
func (s *Store) requireNodeOwnership(ctx context.Context, tx pgx.Tx, allowDraining bool) error {
	return s.requireNodeMembership(ctx, tx, allowDraining, true)
}

// requireNodeMembership validates the fenced node instance before crypto
// identity synchronization. That first binding cannot use the normal serving
// guard because serving ownership intentionally requires cryptoReady.
func (s *Store) requireNodeMembership(ctx context.Context, tx pgx.Tx, allowDraining, requireCrypto bool) error {
	if s.nodeID == "" {
		return nil
	}
	if requireCrypto && !s.cryptoReady.Load() {
		return errors.New("statepg: cluster crypto identity is not synchronized")
	}
	if s.fenced.Load() {
		return ErrNodeFenced
	}
	var state string
	var lastSeen, now time.Time
	err := tx.QueryRow(ctx, `SELECT state, last_seen_at, CURRENT_TIMESTAMP FROM gripline_membership
		WHERE node_id=$1 AND instance_id=$2 AND node_epoch=$3 FOR UPDATE`, s.nodeID, s.instanceID, s.nodeEpoch).
		Scan(&state, &lastSeen, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		s.fenced.Store(true)
		return ErrNodeFenced
	}
	if err != nil {
		return mapDBError(err)
	}
	if now.Sub(lastSeen) >= s.leaseTTL {
		s.fenced.Store(true)
		return ErrNodeFenced
	}
	if state == "draining" && allowDraining {
		return nil
	}
	if state == "draining" {
		return ErrNodeDraining
	}
	if state != "ready" {
		s.fenced.Store(true)
		return ErrNodeFenced
	}
	return nil
}

// MarkDraining removes this instance from readiness while preserving its
// ownership epoch. Heartbeats intentionally preserve DRAINING until shutdown
// has released its work and marked the row stopped.
func (s *Store) MarkDraining(ctx context.Context, drainUntil time.Time) error {
	if s.fenced.Load() {
		return ErrNodeFenced
	}
	var until any
	if !drainUntil.IsZero() {
		until = drainUntil
	}
	tag, err := s.pool.Exec(ctx, `UPDATE gripline_membership SET state='draining', drain_until=$1,
		last_seen_at=CURRENT_TIMESTAMP WHERE node_id=$2 AND instance_id=$3 AND node_epoch=$4
		AND state IN ('ready','draining')`, until, s.nodeID, s.instanceID, s.nodeEpoch)
	if err != nil {
		return mapDBError(err)
	}
	if tag.RowsAffected() == 0 {
		s.fenced.Store(true)
		return ErrNodeFenced
	}
	return nil
}

func (s *Store) markNodeStopped(ctx context.Context) error {
	tag, err := s.pool.Exec(ctx, `UPDATE gripline_membership SET state='stopped', last_seen_at=CURRENT_TIMESTAMP
		WHERE node_id=$1 AND instance_id=$2 AND node_epoch=$3 AND state IN ('ready','draining')`, s.nodeID, s.instanceID, s.nodeEpoch)
	if err != nil {
		return mapDBError(err)
	}
	if tag.RowsAffected() == 0 && !s.fenced.Load() {
		s.fenced.Store(true)
		return ErrNodeFenced
	}
	return nil
}

// Ready verifies both database reachability and this instance's live
// membership lease. A connection that responds while the process has been
// fenced is not sufficient to receive traffic from a load balancer.
func (s *Store) Ready(ctx context.Context) error {
	if err := s.Ping(ctx); err != nil {
		return err
	}
	if s.nodeID == "" {
		return nil
	}
	if s.fenced.Load() {
		return ErrNodeFenced
	}
	var state string
	var lastSeen, now time.Time
	err := s.pool.QueryRow(ctx, `SELECT state, last_seen_at, CURRENT_TIMESTAMP FROM gripline_membership
		WHERE node_id=$1 AND instance_id=$2 AND node_epoch=$3`, s.nodeID, s.instanceID, s.nodeEpoch).Scan(&state, &lastSeen, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		s.fenced.Store(true)
		return ErrNodeFenced
	}
	if err != nil {
		return mapDBError(err)
	}
	if state != "ready" || now.Sub(lastSeen) >= s.leaseTTL {
		return errors.New("statepg: node membership heartbeat expired or draining")
	}
	return nil
}
