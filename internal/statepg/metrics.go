package statepg

import "time"

// PoolStats is a point-in-time, low-cardinality snapshot of the PostgreSQL
// connection pool. It contains no request, credential, lane, or source data
// and is safe to expose through the authenticated operator metrics surface.
type PoolStats struct {
	TotalConns           int32
	IdleConns            int32
	AcquiredConns        int32
	ConstructingConns    int32
	MaxConns             int32
	AcquireCount         int64
	AcquireDuration      time.Duration
	EmptyAcquireCount    int64
	EmptyAcquireWait     time.Duration
	CanceledAcquireCount int64
}

// PoolStats returns the current local pool counters without performing a
// database operation. A closed or unavailable store returns the zero value;
// request-time authority health continues to use StatsContext, which preserves
// errors rather than treating an outage as an empty system.
func (s *Store) PoolStats() PoolStats {
	if s == nil || s.pool == nil {
		return PoolStats{}
	}
	stat := s.pool.Stat()
	if stat == nil {
		return PoolStats{}
	}
	return PoolStats{
		TotalConns:           stat.TotalConns(),
		IdleConns:            stat.IdleConns(),
		AcquiredConns:        stat.AcquiredConns(),
		ConstructingConns:    stat.ConstructingConns(),
		MaxConns:             stat.MaxConns(),
		AcquireCount:         stat.AcquireCount(),
		AcquireDuration:      stat.AcquireDuration(),
		EmptyAcquireCount:    stat.EmptyAcquireCount(),
		EmptyAcquireWait:     stat.EmptyAcquireWaitTime(),
		CanceledAcquireCount: stat.CanceledAcquireCount(),
	}
}
