package main

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/proxy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/statepg"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// adminMetrics is kept in its own module because it is an observability
// projection, not part of the control-plane mutation/read handlers. The
// projection remains intentionally low-cardinality and request-context aware.
func adminMetrics(svc *control.Service, dp *proxy.DataPlane, governor resource.Authority, state *statebolt.Store, postgres *statepg.Store, spray *anomaly.Detector, observer *jsonlObserver, policyManager *policy.Manager, signer *terminator.Keyring, term *terminator.Terminator, adaptiveHealth []terminator.AdaptivePersistenceHealth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			adminMethodNotAllowed(w)
			return
		}
		if _, err := svc.AuthorizeCapability(r.Context(), bearer(r.Header.Get("Authorization")), control.CapAuditRead); err != nil {
			writeAdminError(w, err)
			return
		}
		var b strings.Builder
		writeMetric := func(name string, value any) { fmt.Fprintf(&b, "gripline_%s %v\n", name, value) }
		metricTimestamp := func(value time.Time) int64 {
			if value.IsZero() {
				return 0
			}
			return value.Unix()
		}
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		writeMetric("runtime_goroutines", runtime.NumGoroutine())
		writeMetric("runtime_heap_alloc_bytes", mem.HeapAlloc)
		writeMetric("runtime_heap_objects", mem.HeapObjects)
		if dp != nil {
			m := dp.Metrics()
			writeMetric("admissions_total", m.Admissions)
			writeMetric("authorizations_total", m.Authorizations)
			writeMetric("denials_total", m.Denials)
			writeMetric("authentication_failures_total", m.AuthenticationFail)
			writeMetric("degraded_decisions_total", m.Degraded)
			writeMetric("resource_denials_total", m.ResourceDenials)
			writeMetric("policy_denials_total", m.PolicyDenials)
			writeMetric("payload_too_large_total", m.PayloadTooLarge)
			writeMetric("spool_rejects_total", m.SpoolRejects)
			writeMetric("completion_failures_total", m.CompletionFailures)
			writeMetric("backend_failures_total", m.BackendFailures)
			writeMetric("backend_4xx_total", m.Backend4xx)
			writeMetric("backend_5xx_total", m.Backend5xx)
			writeMetric("active_streams", m.ActiveStreams)
			writeMetric("evidence_events_total", m.EvidenceEvents)
			writeMetric("usage_sessions_total", m.UsageSessions)
			writeMetric("usage_input_tokens_total", m.UsageInputTokens)
			writeMetric("usage_output_tokens_total", m.UsageOutputTokens)
			writeMetric("usage_combined_tokens_total", m.UsageCombinedTokens)
			writeMetric("usage_cost_microunits_total", m.UsageCostMicrounits)
			writeMetric("usage_conservative_settlements_total", m.UsageConservativeSettlements)
			writeMetric("http2_errors_total", m.HTTP2Errors)
			for i, count := range m.ResourceDenialsByScope {
				writeMetric("resource_denials_scope_"+strings.ToLower(resource.Scope(i).String())+"_total", count)
			}
			for i, count := range m.ResourceDenialsByDimension {
				writeMetric("resource_denials_dimension_"+resource.Dimension(i).String()+"_total", count)
			}
			writeMetric("spool_bytes", m.Spool.Bytes)
			writeMetric("spool_files", m.Spool.Files)
			writeMetric("spool_max_bytes", m.Spool.MaxBytes)
			writeMetric("spool_max_files", m.Spool.MaxFiles)
		}
		if stats, ok := governor.(interface{ Stats() resource.GovernorStats }); ok {
			m := stats.Stats()
			writeMetric("source_scopes", m.SourceScopes)
			writeMetric("source_scope_saturations_total", m.SourceSaturations)
			writeMetric("source_scope_overflows_total", m.SourceOverflows)
			writeMetric("source_scope_evictions_total", m.SourceEvictions)
		}
		if statsAuthority, ok := governor.(resource.ContextStatsAuthority); ok {
			if m, err := statsAuthority.StatsContext(r.Context()); err == nil {
				writeMetric("resource_stats_available", 1)
				writeMetric("resource_active_concurrency", m.ActiveConcurrency)
				writeMetric("resource_active_leases", m.ActiveLeases)
				writeMetric("resource_forwarded_leases", m.ForwardedLeases)
				writeMetric("resource_settled_leases", m.SettledLeases)
				writeMetric("resource_released_leases", m.ReleasedLeases)
				writeMetric("resource_active_holds", m.ActiveHolds)
				writeMetric("resource_source_scopes", m.SourceScopes)
				writeMetric("resource_source_overflows", m.SourceOverflows)
			} else {
				writeMetric("resource_stats_available", 0)
			}
		}
		if policyManager != nil {
			if current := policyManager.Current(); current != nil {
				writeMetric("active_policy_revision", current.Revision)
			}
		}
		if signer != nil {
			writeMetric("active_signer_kid", signer.ActiveKid())
		}
		if state != nil {
			m := state.EvidenceSweepStats()
			writeMetric("evidence_sweep_scanned_total", m.Scanned)
			writeMetric("evidence_sweep_deleted_total", m.Deleted)
			tx := state.TransactionStats()
			writeMetric("bbolt_transactions_total", tx.Transactions)
			writeMetric("bbolt_transaction_errors_total", tx.TransactionErrors)
			writeMetric("bbolt_transaction_nanos_total", tx.TransactionNanos)
		}
		if postgres != nil {
			m := postgres.PoolStats()
			writeMetric("postgres_pool_total_conns", m.TotalConns)
			writeMetric("postgres_pool_idle_conns", m.IdleConns)
			writeMetric("postgres_pool_acquired_conns", m.AcquiredConns)
			writeMetric("postgres_pool_constructing_conns", m.ConstructingConns)
			writeMetric("postgres_pool_max_conns", m.MaxConns)
			writeMetric("postgres_pool_acquires_total", m.AcquireCount)
			writeMetric("postgres_pool_acquire_duration_seconds", m.AcquireDuration.Seconds())
			writeMetric("postgres_pool_empty_acquires_total", m.EmptyAcquireCount)
			writeMetric("postgres_pool_empty_acquire_wait_seconds", m.EmptyAcquireWait.Seconds())
			writeMetric("postgres_pool_canceled_acquires_total", m.CanceledAcquireCount)
			a := postgres.Metrics()
			writeMetric("postgres_transaction_attempts_total", a.TransactionAttempts)
			writeMetric("postgres_transaction_errors_total", a.TransactionErrors)
			writeMetric("postgres_transaction_latency_seconds_total", a.TransactionLatency.Seconds())
			writeMetric("postgres_serialization_retries_total", a.SerializationRetries)
			writeMetric("postgres_deadlock_retries_total", a.DeadlockRetries)
			writeMetric("postgres_transaction_retries_adaptive_window_total", a.TransactionRetriesAdaptiveWindow)
			writeMetric("postgres_transaction_retries_adaptive_baseline_total", a.TransactionRetriesAdaptiveBaseline)
			writeMetric("postgres_transaction_retries_lane_borrow_total", a.TransactionRetriesLaneBorrow)
			writeMetric("postgres_transaction_retries_lane_risk_total", a.TransactionRetriesLaneRisk)
			writeMetric("postgres_transaction_retries_credential_total", a.TransactionRetriesCredential)
			writeMetric("postgres_transaction_retries_resource_total", a.TransactionRetriesResource)
			writeMetric("postgres_transaction_retries_other_total", a.TransactionRetriesOther)
			writeMetric("postgres_reservation_attempts_total", a.ReservationAttempts)
			writeMetric("postgres_reservations_granted_total", a.ReservationsGranted)
			writeMetric("postgres_reservation_failures_total", a.ReservationFailures)
			writeMetric("postgres_reservation_latency_seconds_total", a.ReservationLatency.Seconds())
			writeMetric("postgres_forward_attempts_total", a.ForwardAttempts)
			writeMetric("postgres_forwarded_total", a.Forwarded)
			writeMetric("postgres_forward_failures_total", a.ForwardFailures)
			writeMetric("postgres_lease_renewal_attempts_total", a.LeaseRenewalAttempts)
			writeMetric("postgres_leases_renewed_total", a.LeasesRenewed)
			writeMetric("postgres_lease_renewal_failures_total", a.LeaseRenewalFailures)
			writeMetric("postgres_settlement_attempts_total", a.SettlementAttempts)
			writeMetric("postgres_settlements_total", a.Settlements)
			writeMetric("postgres_settlement_failures_total", a.SettlementFailures)
			writeMetric("postgres_expired_leases_total", a.ExpiredLeases)
			writeMetric("postgres_forwarded_unsettled_consumed_total", a.ForwardedUnsettledConsumed)
			writeMetric("postgres_release_failures_total", a.ReleaseFailures)
			writeMetric("postgres_maintenance_runs_total", a.MaintenanceRuns)
			writeMetric("postgres_maintenance_errors_total", a.MaintenanceErrors)
			writeMetric("postgres_maintenance_consecutive_errors", a.MaintenanceConsecutiveErrors)
			writeMetric("postgres_maintenance_rows_deleted_total", a.MaintenanceRowsDeleted)
			writeMetric("postgres_maintenance_batches_total", a.MaintenanceBatches)
			writeMetric("postgres_maintenance_backlog_estimate", a.MaintenanceBacklogEstimate)
			writeMetric("postgres_maintenance_last_success_timestamp", metricTimestamp(a.MaintenanceLastSuccess))
			writeMetric("postgres_maintenance_last_failure_timestamp", metricTimestamp(a.MaintenanceLastFailure))
			writeMetric("postgres_maintenance_last_duration_seconds", a.MaintenanceLastDuration.Seconds())
		}
		if spray != nil {
			writeMetric("detector_drops_total", spray.Stats().Dropped)
		}
		adaptiveHealthy := 1
		for _, health := range adaptiveHealth {
			if health != nil && health.PersistenceError() != nil {
				adaptiveHealthy = 0
				break
			}
		}
		writeMetric("adaptive_persistence_healthy", adaptiveHealthy)
		if term != nil {
			writeMetric("evidence_append_failures_total", term.EvidenceAppendFailures())
		}
		if observer != nil {
			m := observer.Stats()
			writeMetric("telemetry_drops_total", m.Dropped)
			writeMetric("telemetry_sink_failures_total", m.SinkFailures)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	}
}
