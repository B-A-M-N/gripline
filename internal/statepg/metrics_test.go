package statepg

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestAuthorityMetricsSnapshot(t *testing.T) {
	var store Store
	store.metrics.transactionAttempts.Store(12)
	store.metrics.transactionErrors.Store(3)
	store.metrics.transactionLatencyNanos.Store((250 * time.Millisecond).Nanoseconds())
	store.metrics.serializationRetries.Store(2)
	store.metrics.deadlockRetries.Store(1)
	store.metrics.reservationAttempts.Store(3)
	store.metrics.reservationsGranted.Store(2)
	store.metrics.reservationFailures.Store(1)
	store.metrics.reservationLatencyNanos.Store((125 * time.Millisecond).Nanoseconds())
	store.metrics.forwardAttempts.Store(4)
	store.metrics.forwarded.Store(3)
	store.metrics.forwardFailures.Store(1)
	store.metrics.leaseRenewalAttempts.Store(8)
	store.metrics.leasesRenewed.Store(7)
	store.metrics.leaseRenewalFailures.Store(1)
	store.metrics.settlementAttempts.Store(5)
	store.metrics.settlements.Store(4)
	store.metrics.settlementFailures.Store(1)
	store.metrics.expiredLeases.Store(2)
	store.metrics.forwardedUnsettledConsumed.Store(1)
	store.metrics.releaseFailures.Store(1)

	got := store.Metrics()
	if got.TransactionAttempts != 12 || got.TransactionErrors != 3 || got.TransactionLatency != 250*time.Millisecond || got.SerializationRetries != 2 || got.DeadlockRetries != 1 {
		t.Fatalf("transaction metrics=%+v", got)
	}
	if got.ReservationAttempts != 3 || got.ReservationsGranted != 2 || got.ReservationFailures != 1 {
		t.Fatalf("reservation metrics=%+v", got)
	}
	if got.ReservationLatency != 125*time.Millisecond {
		t.Fatalf("reservation latency=%s, want 125ms", got.ReservationLatency)
	}
	if got.ForwardAttempts != 4 || got.Forwarded != 3 || got.ForwardFailures != 1 {
		t.Fatalf("forward metrics=%+v", got)
	}
	if got.LeaseRenewalAttempts != 8 || got.LeasesRenewed != 7 || got.LeaseRenewalFailures != 1 {
		t.Fatalf("renewal metrics=%+v", got)
	}
	if got.SettlementAttempts != 5 || got.Settlements != 4 || got.SettlementFailures != 1 {
		t.Fatalf("settlement metrics=%+v", got)
	}
	if got.ExpiredLeases != 2 || got.ForwardedUnsettledConsumed != 1 || got.ReleaseFailures != 1 {
		t.Fatalf("cleanup metrics=%+v", got)
	}
}

func TestAuthorityMetricsNilStoreIsZero(t *testing.T) {
	var store *Store
	if got := store.Metrics(); got != (AuthorityMetrics{}) {
		t.Fatalf("nil store metrics=%+v, want zero", got)
	}
}

func TestStoreTransactionMetricsIncludeRetry(t *testing.T) {
	var store Store
	attempts := 0
	err := store.withTransactionRetry(context.Background(), "metrics retry", func() error {
		attempts++
		if attempts == 1 {
			return &pgconn.PgError{Code: "40001", Message: "serialization failure"}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("transaction retry: %v", err)
	}
	got := store.Metrics()
	if got.TransactionAttempts != 2 || got.TransactionErrors != 1 || got.SerializationRetries != 1 || got.DeadlockRetries != 0 {
		t.Fatalf("retry metrics=%+v", got)
	}
}
