package statepg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const currentProtocolVersion = 1

func (s *Store) registerNode(ctx context.Context) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT protocol_version, schema_version FROM gripline_membership
		WHERE node_id <> $1 AND state='ready' AND last_seen_at > $2 - ($3 * interval '1 second')`, s.nodeID, now, int64(s.leaseTTL/time.Second))
	if err != nil {
		return mapDBError(err)
	}
	for rows.Next() {
		var protocol, schema int
		if err := rows.Scan(&protocol, &schema); err != nil {
			rows.Close()
			return mapDBError(err)
		}
		if protocol != currentProtocolVersion || schema != currentSchemaVersion {
			rows.Close()
			return fmt.Errorf("statepg: incompatible live node protocol=%d schema=%d (local protocol=%d schema=%d)", protocol, schema, currentProtocolVersion, currentSchemaVersion)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return mapDBError(err)
	}
	rows.Close()
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_membership (node_id, protocol_version, schema_version, state, last_seen_at)
		VALUES ($1,$2,$3,'ready',$4) ON CONFLICT (node_id) DO UPDATE SET protocol_version=EXCLUDED.protocol_version,
		schema_version=EXCLUDED.schema_version, state='ready', last_seen_at=EXCLUDED.last_seen_at, drain_until=NULL`,
		s.nodeID, currentProtocolVersion, currentSchemaVersion, now); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
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
	_, err := s.pool.Exec(ctx, `UPDATE gripline_membership SET state='ready', last_seen_at=CURRENT_TIMESTAMP WHERE node_id=$1`, s.nodeID)
	return mapDBError(err)
}

func (s *Store) markNodeStopped(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE gripline_membership SET state='stopped', last_seen_at=CURRENT_TIMESTAMP WHERE node_id=$1`, s.nodeID)
	return mapDBError(err)
}

// Ready verifies both database reachability and this node's live membership
// lease. A connection that responds while the node has lost its heartbeat is
// not sufficient to receive traffic from a load balancer.
func (s *Store) Ready(ctx context.Context) error {
	if err := s.Ping(ctx); err != nil {
		return err
	}
	if s.nodeID == "" {
		return nil
	}
	var state string
	var lastSeen, now time.Time
	err := s.pool.QueryRow(ctx, `SELECT state, last_seen_at, CURRENT_TIMESTAMP FROM gripline_membership WHERE node_id=$1`, s.nodeID).Scan(&state, &lastSeen, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("statepg: node is not registered")
	}
	if err != nil {
		return mapDBError(err)
	}
	if state != "ready" || now.Sub(lastSeen) >= s.leaseTTL {
		return errors.New("statepg: node membership heartbeat expired")
	}
	return nil
}
