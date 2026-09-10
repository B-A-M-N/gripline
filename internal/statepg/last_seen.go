package statepg

import (
	"context"
	"time"
)

const (
	lastSeenInterval  = time.Minute
	lastSeenTimeout   = 500 * time.Millisecond
	lastSeenQueueSize = 4096
	lastSeenBatchSize = 128
)

// QueueLastSeen records analytics without opening a database operation per
// successful request. It is deliberately non-blocking and deduplicates each
// credential while it waits for the fixed worker.
func (s *Store) QueueLastSeen(credentialID string, at time.Time) {
	if s == nil || s.pool == nil || credentialID == "" || at.IsZero() {
		return
	}
	s.lastSeenMu.Lock()
	if previous, exists := s.lastSeenPending[credentialID]; exists {
		if at.After(previous) {
			s.lastSeenPending[credentialID] = at
		}
		s.lastSeenMu.Unlock()
		return
	}
	select {
	case s.lastSeenQueue <- credentialID:
		s.lastSeenPending[credentialID] = at
	default:
		s.metrics.credentialLastSeenDropped.Add(1)
	}
	s.lastSeenMu.Unlock()
}

func (s *Store) lastSeenLoop() {
	if s == nil || s.lastSeenDone == nil {
		return
	}
	defer close(s.lastSeenDone)
	ticker := time.NewTicker(lastSeenInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.flushLastSeen(false)
		case <-s.lastSeenStop:
			for s.flushLastSeen(true) > 0 {
			}
			return
		}
	}
}

func (s *Store) flushLastSeen(drain bool) int {
	entries := make([]lastSeenEntry, 0, lastSeenBatchSize)
	s.lastSeenMu.Lock()
drainQueue:
	for len(entries) < lastSeenBatchSize {
		var credentialID string
		select {
		case credentialID = <-s.lastSeenQueue:
		default:
			break drainQueue
		}
		at, exists := s.lastSeenPending[credentialID]
		if !exists {
			continue
		}
		delete(s.lastSeenPending, credentialID)
		entries = append(entries, lastSeenEntry{credentialID: credentialID, at: at})
	}
	s.lastSeenMu.Unlock()
	if len(entries) == 0 {
		return 0
	}
	ids := make([]string, 0, len(entries))
	times := make([]time.Time, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.credentialID)
		times = append(times, entry.at)
	}
	ctx, cancel := context.WithTimeout(context.Background(), lastSeenTimeout)
	query := `UPDATE gripline_credentials AS c SET last_seen_at=GREATEST(COALESCE(c.last_seen_at, 'epoch'::timestamptz), u.last_seen_at)
		FROM unnest($1::text[], $2::timestamptz[]) AS u(credential_id, last_seen_at)
		WHERE c.credential_id=u.credential_id`
	args := []any{ids, times}
	if s.nodeID != "" {
		query += ` AND EXISTS (
			SELECT 1 FROM gripline_membership
			WHERE node_id=$3 AND instance_id=$4 AND node_epoch=$5
			  AND state IN ('ready','draining')
			  AND last_seen_at > CURRENT_TIMESTAMP - ($6::double precision * interval '1 second'))`
		args = append(args, s.nodeID, s.instanceID, s.nodeEpoch, s.leaseTTL.Seconds())
	}
	tag, err := s.pool.Exec(ctx, query, args...)
	cancel()
	if err != nil {
		if !drain {
			s.requeueLastSeen(entries)
		}
		return len(entries)
	}
	s.metrics.credentialLastSeenBatches.Add(1)
	s.metrics.credentialLastSeenRows.Add(tag.RowsAffected())
	if !drain {
		return len(entries)
	}
	return len(entries)
}

type lastSeenEntry struct {
	credentialID string
	at           time.Time
}

func (s *Store) requeueLastSeen(entries []lastSeenEntry) {
	s.lastSeenMu.Lock()
	defer s.lastSeenMu.Unlock()
	for _, entry := range entries {
		if _, exists := s.lastSeenPending[entry.credentialID]; exists {
			continue
		}
		select {
		case s.lastSeenQueue <- entry.credentialID:
			s.lastSeenPending[entry.credentialID] = entry.at
		default:
			s.metrics.credentialLastSeenDropped.Add(1)
		}
	}
}
