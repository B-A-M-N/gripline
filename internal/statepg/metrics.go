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
	TransactionAttempts                int64
	TransactionErrors                  int64
	AuthorityTimeouts                  int64
	TransactionLatency                 time.Duration
	SerializationRetries               int64
	DeadlockRetries                    int64
	TransactionRetriesAdaptiveWindow   int64
	TransactionRetriesAdaptiveBaseline int64
	TransactionRetriesLaneBorrow       int64
	TransactionRetriesLaneRisk         int64
	TransactionRetriesCredential       int64
	TransactionRetriesResource         int64
	TransactionRetriesSourceAlias      int64
	TransactionRetriesOther            int64
	SourceAliasAttempts                int64
	SourceAliasRegistrations           int64
	SourceAliasConflicts               int64
	SourceAliasFailures                int64
	SourceAliasResolutionLatency       time.Duration
	SourceAliasTouchBatches            int64
	SourceAliasTouchDropped            int64
	ReservationAttempts                int64
	ReservationsGranted                int64
	ReservationFailures                int64
	ReservationLatency                 time.Duration
	ForwardAttempts                    int64
	Forwarded                          int64
	ForwardFailures                    int64
	LeaseRenewalAttempts               int64
	LeasesRenewed                      int64
	LeaseRenewalFailures               int64
	SettlementAttempts                 int64
	Settlements                        int64
	SettlementFailures                 int64
	ExpiredLeases                      int64
	ForwardedUnsettledConsumed         int64
	ReleaseFailures                    int64
	MaintenanceRuns                    int64
	MaintenanceErrors                  int64
	MaintenanceConsecutiveErrors       int64
	MaintenanceRowsDeleted             int64
	MaintenanceSourceAliasesDeleted    int64
	MaintenanceSourceScopesDeleted     int64
	MaintenanceBatches                 int64
	MaintenanceBacklogEstimate         int64
	MaintenanceLastSuccess             time.Time
	MaintenanceLastFailure             time.Time
	MaintenanceLastDuration            time.Duration
}

type authorityMetrics struct {
	transactionAttempts                atomic.Int64
	transactionErrors                  atomic.Int64
	authorityTimeouts                  atomic.Int64
	transactionLatencyNanos            atomic.Int64
	serializationRetries               atomic.Int64
	deadlockRetries                    atomic.Int64
	transactionRetriesAdaptiveWindow   atomic.Int64
	transactionRetriesAdaptiveBaseline atomic.Int64
	transactionRetriesLaneBorrow       atomic.Int64
	transactionRetriesLaneRisk         atomic.Int64
	transactionRetriesCredential       atomic.Int64
	transactionRetriesResource         atomic.Int64
	transactionRetriesSourceAlias      atomic.Int64
	transactionRetriesOther            atomic.Int64
	sourceAliasAttempts                atomic.Int64
	sourceAliasRegistrations           atomic.Int64
	sourceAliasConflicts               atomic.Int64
	sourceAliasFailures                atomic.Int64
	sourceAliasResolutionLatencyNanos  atomic.Int64
	sourceAliasTouchBatches            atomic.Int64
	sourceAliasTouchDropped            atomic.Int64
	reservationAttempts                atomic.Int64
	reservationsGranted                atomic.Int64
	reservationFailures                atomic.Int64
	reservationLatencyNanos            atomic.Int64
	forwardAttempts                    atomic.Int64
	forwarded                          atomic.Int64
	forwardFailures                    atomic.Int64
	leaseRenewalAttempts               atomic.Int64
	leasesRenewed                      atomic.Int64
	leaseRenewalFailures               atomic.Int64
	settlementAttempts                 atomic.Int64
	settlements                        atomic.Int64
	settlementFailures                 atomic.Int64
	expiredLeases                      atomic.Int64
	forwardedUnsettledConsumed         atomic.Int64
	releaseFailures                    atomic.Int64
	maintenanceRuns                    atomic.Int64
	maintenanceErrors                  atomic.Int64
	maintenanceConsecutiveErrors       atomic.Int64
	maintenanceRowsDeleted             atomic.Int64
	maintenanceSourceAliasesDeleted    atomic.Int64
	maintenanceSourceScopesDeleted     atomic.Int64
	maintenanceBatches                 atomic.Int64
	maintenanceBacklogEstimate         atomic.Int64
	maintenanceLastSuccess             atomic.Int64
	maintenanceLastFailure             atomic.Int64
	maintenanceLastDurationNanos       atomic.Int64
}

func (s *Store) recordMaintenance(stats MaintenanceStats, err error) {
	if s == nil {
		return
	}
	now := time.Now().UTC().UnixNano()
	s.metrics.maintenanceRuns.Add(1)
	s.metrics.maintenanceRowsDeleted.Add(int64(stats.RowsDeleted))
	s.metrics.maintenanceSourceAliasesDeleted.Add(int64(stats.SourceAliasesDeleted))
	s.metrics.maintenanceSourceScopesDeleted.Add(int64(stats.ResourceSourceScopesDeleted))
	s.metrics.maintenanceBatches.Add(int64(stats.Batches))
	s.metrics.maintenanceBacklogEstimate.Store(int64(stats.BacklogEstimate))
	s.metrics.maintenanceLastDurationNanos.Store(stats.Duration.Nanoseconds())
	if err != nil {
		s.metrics.maintenanceErrors.Add(1)
		s.metrics.maintenanceConsecutiveErrors.Add(1)
		s.metrics.maintenanceLastFailure.Store(now)
		return
	}
	s.metrics.maintenanceConsecutiveErrors.Store(0)
	s.metrics.maintenanceLastSuccess.Store(now)
}

func (m *authorityMetrics) recordTransactionRetry(operation string) {
	var counter *atomic.Int64
	switch operation {
	case "adaptive window observation":
		counter = &m.transactionRetriesAdaptiveWindow
	case "adaptive baseline observation":
		counter = &m.transactionRetriesAdaptiveBaseline
	case "lane borrow/create":
		counter = &m.transactionRetriesLaneBorrow
	case "lane risk observation":
		counter = &m.transactionRetriesLaneRisk
	case "credential observation":
		counter = &m.transactionRetriesCredential
	case "resource admission", "resource forward", "resource lease expiration", "resource lease release", "resource lease renewal", "resource lease settlement", "resource scope removal":
		counter = &m.transactionRetriesResource
	case "source alias resolution", "source alias registration":
		counter = &m.transactionRetriesSourceAlias
	default:
		counter = &m.transactionRetriesOther
	}
	counter.Add(1)
}

func metricTime(nanos int64) time.Time {
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos).UTC()
}

// Metrics returns a point-in-time copy of authority activity counters.
func (s *Store) Metrics() AuthorityMetrics {
	if s == nil {
		return AuthorityMetrics{}
	}
	return AuthorityMetrics{
		TransactionAttempts:                s.metrics.transactionAttempts.Load(),
		TransactionErrors:                  s.metrics.transactionErrors.Load(),
		AuthorityTimeouts:                  s.metrics.authorityTimeouts.Load(),
		TransactionLatency:                 time.Duration(s.metrics.transactionLatencyNanos.Load()),
		SerializationRetries:               s.metrics.serializationRetries.Load(),
		DeadlockRetries:                    s.metrics.deadlockRetries.Load(),
		TransactionRetriesAdaptiveWindow:   s.metrics.transactionRetriesAdaptiveWindow.Load(),
		TransactionRetriesAdaptiveBaseline: s.metrics.transactionRetriesAdaptiveBaseline.Load(),
		TransactionRetriesLaneBorrow:       s.metrics.transactionRetriesLaneBorrow.Load(),
		TransactionRetriesLaneRisk:         s.metrics.transactionRetriesLaneRisk.Load(),
		TransactionRetriesCredential:       s.metrics.transactionRetriesCredential.Load(),
		TransactionRetriesResource:         s.metrics.transactionRetriesResource.Load(),
		TransactionRetriesSourceAlias:      s.metrics.transactionRetriesSourceAlias.Load(),
		TransactionRetriesOther:            s.metrics.transactionRetriesOther.Load(),
		SourceAliasAttempts:                s.metrics.sourceAliasAttempts.Load(),
		SourceAliasRegistrations:           s.metrics.sourceAliasRegistrations.Load(),
		SourceAliasConflicts:               s.metrics.sourceAliasConflicts.Load(),
		SourceAliasFailures:                s.metrics.sourceAliasFailures.Load(),
		SourceAliasResolutionLatency:       time.Duration(s.metrics.sourceAliasResolutionLatencyNanos.Load()),
		SourceAliasTouchBatches:            s.metrics.sourceAliasTouchBatches.Load(),
		SourceAliasTouchDropped:            s.metrics.sourceAliasTouchDropped.Load(),
		ReservationAttempts:                s.metrics.reservationAttempts.Load(),
		ReservationsGranted:                s.metrics.reservationsGranted.Load(),
		ReservationFailures:                s.metrics.reservationFailures.Load(),
		ReservationLatency:                 time.Duration(s.metrics.reservationLatencyNanos.Load()),
		ForwardAttempts:                    s.metrics.forwardAttempts.Load(),
		Forwarded:                          s.metrics.forwarded.Load(),
		ForwardFailures:                    s.metrics.forwardFailures.Load(),
		LeaseRenewalAttempts:               s.metrics.leaseRenewalAttempts.Load(),
		LeasesRenewed:                      s.metrics.leasesRenewed.Load(),
		LeaseRenewalFailures:               s.metrics.leaseRenewalFailures.Load(),
		SettlementAttempts:                 s.metrics.settlementAttempts.Load(),
		Settlements:                        s.metrics.settlements.Load(),
		SettlementFailures:                 s.metrics.settlementFailures.Load(),
		ExpiredLeases:                      s.metrics.expiredLeases.Load(),
		ForwardedUnsettledConsumed:         s.metrics.forwardedUnsettledConsumed.Load(),
		ReleaseFailures:                    s.metrics.releaseFailures.Load(),
		MaintenanceRuns:                    s.metrics.maintenanceRuns.Load(),
		MaintenanceErrors:                  s.metrics.maintenanceErrors.Load(),
		MaintenanceConsecutiveErrors:       s.metrics.maintenanceConsecutiveErrors.Load(),
		MaintenanceRowsDeleted:             s.metrics.maintenanceRowsDeleted.Load(),
		MaintenanceSourceAliasesDeleted:    s.metrics.maintenanceSourceAliasesDeleted.Load(),
		MaintenanceSourceScopesDeleted:     s.metrics.maintenanceSourceScopesDeleted.Load(),
		MaintenanceBatches:                 s.metrics.maintenanceBatches.Load(),
		MaintenanceBacklogEstimate:         s.metrics.maintenanceBacklogEstimate.Load(),
		MaintenanceLastSuccess:             metricTime(s.metrics.maintenanceLastSuccess.Load()),
		MaintenanceLastFailure:             metricTime(s.metrics.maintenanceLastFailure.Load()),
		MaintenanceLastDuration:            time.Duration(s.metrics.maintenanceLastDurationNanos.Load()),
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
