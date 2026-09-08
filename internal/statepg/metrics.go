package statepg

import (
	"sync/atomic"
	"time"
)

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

// AuthorityMetrics is the local, low-cardinality activity snapshot for the
// shared authority. Counters contain no request, credential, lane, or source
// identifiers and are safe to expose through the authenticated metrics
// surface. Latency is accumulated wall-clock time at the authority boundary.
type AuthorityMetrics struct {
	TransactionAttempts        int64
	TransactionErrors          int64
	TransactionLatency         time.Duration
	SerializationRetries       int64
	DeadlockRetries            int64
	ReservationAttempts        int64
	ReservationsGranted        int64
	ReservationFailures        int64
	ReservationLatency         time.Duration
	ForwardAttempts            int64
	Forwarded                  int64
	ForwardFailures            int64
	LeaseRenewalAttempts       int64
	LeasesRenewed              int64
	LeaseRenewalFailures       int64
	SettlementAttempts         int64
	Settlements                int64
	SettlementFailures         int64
	ExpiredLeases              int64
	ForwardedUnsettledConsumed int64
	ReleaseFailures            int64
}

type authorityMetrics struct {
	transactionAttempts        atomic.Int64
	transactionErrors          atomic.Int64
	transactionLatencyNanos    atomic.Int64
	serializationRetries       atomic.Int64
	deadlockRetries            atomic.Int64
	reservationAttempts        atomic.Int64
	reservationsGranted        atomic.Int64
	reservationFailures        atomic.Int64
	reservationLatencyNanos    atomic.Int64
	forwardAttempts            atomic.Int64
	forwarded                  atomic.Int64
	forwardFailures            atomic.Int64
	leaseRenewalAttempts       atomic.Int64
	leasesRenewed              atomic.Int64
	leaseRenewalFailures       atomic.Int64
	settlementAttempts         atomic.Int64
	settlements                atomic.Int64
	settlementFailures         atomic.Int64
	expiredLeases              atomic.Int64
	forwardedUnsettledConsumed atomic.Int64
	releaseFailures            atomic.Int64
}

// Metrics returns a point-in-time copy of authority activity counters.
func (s *Store) Metrics() AuthorityMetrics {
	if s == nil {
		return AuthorityMetrics{}
	}
	return AuthorityMetrics{
		TransactionAttempts:        s.metrics.transactionAttempts.Load(),
		TransactionErrors:          s.metrics.transactionErrors.Load(),
		TransactionLatency:         time.Duration(s.metrics.transactionLatencyNanos.Load()),
		SerializationRetries:       s.metrics.serializationRetries.Load(),
		DeadlockRetries:            s.metrics.deadlockRetries.Load(),
		ReservationAttempts:        s.metrics.reservationAttempts.Load(),
		ReservationsGranted:        s.metrics.reservationsGranted.Load(),
		ReservationFailures:        s.metrics.reservationFailures.Load(),
		ReservationLatency:         time.Duration(s.metrics.reservationLatencyNanos.Load()),
		ForwardAttempts:            s.metrics.forwardAttempts.Load(),
		Forwarded:                  s.metrics.forwarded.Load(),
		ForwardFailures:            s.metrics.forwardFailures.Load(),
		LeaseRenewalAttempts:       s.metrics.leaseRenewalAttempts.Load(),
		LeasesRenewed:              s.metrics.leasesRenewed.Load(),
		LeaseRenewalFailures:       s.metrics.leaseRenewalFailures.Load(),
		SettlementAttempts:         s.metrics.settlementAttempts.Load(),
		Settlements:                s.metrics.settlements.Load(),
		SettlementFailures:         s.metrics.settlementFailures.Load(),
		ExpiredLeases:              s.metrics.expiredLeases.Load(),
		ForwardedUnsettledConsumed: s.metrics.forwardedUnsettledConsumed.Load(),
		ReleaseFailures:            s.metrics.releaseFailures.Load(),
	}
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
