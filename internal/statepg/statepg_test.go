package statepg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/adaptive"
	"github.com/B-A-M-N/gripline/internal/authority"
	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOpenRequiresDSNBeforeDialing(t *testing.T) {
	_, err := Open(context.Background(), Options{})
	if err == nil || !errors.Is(err, ErrDSNRequired) {
		t.Fatalf("Open without DSN = %v", err)
	}
}

func TestValidateTransport(t *testing.T) {
	tests := []struct {
		name    string
		dsn     string
		wantErr bool
	}{
		{name: "loopback without TLS", dsn: "postgres://user@127.0.0.1/db?sslmode=disable"},
		{name: "localhost without TLS", dsn: "postgres://user@localhost/db?sslmode=disable"},
		{name: "unix socket without TLS", dsn: "host=/var/run/postgresql user=user dbname=db sslmode=disable"},
		{name: "remote plaintext", dsn: "postgres://user@db.internal/db?sslmode=disable", wantErr: true},
		{name: "remote prefer fallback", dsn: "postgres://user@db.internal/db?sslmode=prefer", wantErr: true},
		{name: "remote unauthenticated TLS", dsn: "postgres://user@db.internal/db?sslmode=require", wantErr: true},
		{name: "remote verified TLS", dsn: "postgres://user@db.internal/db?sslmode=verify-full", wantErr: false},
		{name: "remote fallback plaintext", dsn: "postgres://user@localhost,db.internal/db?sslmode=disable", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := pgxpool.ParseConfig(tt.dsn)
			if err != nil {
				t.Fatalf("ParseConfig() error = %v", err)
			}
			err = validateTransport(config)
			if tt.wantErr {
				if !errors.Is(err, ErrInsecureTransport) {
					t.Fatalf("validateTransport() error = %v, want ErrInsecureTransport", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateTransport() error = %v", err)
			}
		})
	}
}

func TestSharedAuthorityInterfaceConformance(t *testing.T) {
	var _ credential.Registry = (*Store)(nil)
	var _ credential.VerifierLookup = (*Store)(nil)
	var _ credential.Provisioner = (*Store)(nil)
	var _ lane.Repository = (*Store)(nil)
	var _ lane.PolicyAwareRepository = (*Store)(nil)
	var _ lane.ReadRepository = (*Store)(nil)
	var _ evidence.Store = (*Store)(nil)
	var _ evidence.ContextStore = (*Store)(nil)
	var _ control.AuditRepository = (*Store)(nil)
	var _ control.MutationStore = (*Store)(nil)
	var _ control.PostureAuthority = (*Store)(nil)
	var _ control.SecurityTransitionReader = (*Store)(nil)
	var _ resource.Authority = (*Store)(nil)
	var _ resource.ResourceAuthority = (*Store)(nil)
	var _ resource.DistributedAuthority = (*Store)(nil)
	var _ resource.RequestDistributedAuthority = (*Store)(nil)
	var _ authority.Membership = (*Store)(nil)
	var _ adaptive.Store = (*Store)(nil)
}

func TestMembershipStateClassification(t *testing.T) {
	for _, state := range []string{"ready", "draining"} {
		if !isLiveMembershipState(state) {
			t.Fatalf("%q should be live for takeover protection", state)
		}
	}
	for _, state := range []string{"stopped", ""} {
		if isLiveMembershipState(state) {
			t.Fatalf("%q should not block a replacement instance", state)
		}
	}
}

func TestResourceLeaseRefundRequiresUnforwardedState(t *testing.T) {
	tests := []struct {
		name      string
		state     string
		settled   bool
		shouldRef bool
	}{
		{name: "reserved", state: leaseReserved, shouldRef: true},
		{name: "forwarded", state: leaseForwarded},
		{name: "forwarded settled", state: leaseForwarded, settled: true},
		{name: "settled", state: leaseSettled, settled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRefundLeaseHold(tt.state, tt.settled); got != tt.shouldRef {
				t.Fatalf("shouldRefundLeaseHold(%q, %t) = %t, want %t", tt.state, tt.settled, got, tt.shouldRef)
			}
		})
	}
}

func TestTransactionRetryHonorsContextDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	started := time.Now()
	err := withTransactionRetry(ctx, "test retry", func() error {
		return &pgconn.PgError{Code: "40001", Message: "serialization failure"}
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retry error=%v, want context deadline", err)
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatalf("retry backoff ignored context: elapsed=%s", time.Since(started))
	}
}

func TestOperationContextAppliesStoreTimeout(t *testing.T) {
	store := &Store{operationTimeout: 5 * time.Millisecond}
	ctx, cancel := store.operationContext(context.Background())
	defer cancel()
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("operation context error=%v, want deadline exceeded", ctx.Err())
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("operation context did not enforce the configured timeout")
	}
}
