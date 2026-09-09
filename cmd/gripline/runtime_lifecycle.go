package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/B-A-M-N/gripline/internal/resource"
)

// Ready reports whether the runtime can actually serve: the authorities are
// constructed (guaranteed by BuildRuntime returning) and, when state-backed,
// the selected authority answers a bounded probe. A /readyz handler that only
// echoes a static flag is a lie — this is the check behind the endpoint.
func (rt *Runtime) Ready() error {
	readinessCtx, readinessCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer readinessCancel()
	check := func(reason string, fn func(context.Context) error) error {
		ctx, cancel := context.WithTimeout(readinessCtx, 500*time.Millisecond)
		defer cancel()
		if err := fn(ctx); err != nil {
			return fmt.Errorf("gripline: readiness.%s: %w", reason, err)
		}
		return nil
	}
	if rt.StateHealth != nil {
		if err := check("state_authority", rt.StateHealth.Ready); err != nil {
			return err
		}
		if rt.Postgres != nil {
			if err := check("cluster_crypto", rt.Postgres.CryptoReady); err != nil {
				return err
			}
		}
		if rt.PolicyHealth != nil {
			if err := check("policy_authority", rt.PolicyHealth.Ready); err != nil {
				return err
			}
		}
	} else {
		// Compatibility for hand-built Runtime values from older embedders.
		if rt.State != nil {
			if err := rt.State.Ping(); err != nil {
				return fmt.Errorf("gripline: state store not ready: %w", err)
			}
		}
		if rt.Postgres != nil {
			if err := check("postgres_authority", rt.Postgres.Ready); err != nil {
				return err
			}
			if err := check("cluster_crypto", rt.Postgres.CryptoReady); err != nil {
				return err
			}
		}
		if rt.PolicyHealth != nil {
			if err := check("policy_authority", rt.PolicyHealth.Ready); err != nil {
				return err
			}
		}
	}
	for _, health := range rt.adaptiveHealth {
		if health != nil && health.PersistenceError() != nil {
			if recovery, ok := health.(interface {
				RecoverPersistence(context.Context) error
			}); ok {
				if err := check("adaptive_recovery", recovery.RecoverPersistence); err != nil {
					return err
				}
			}
			if health.PersistenceError() != nil {
				return fmt.Errorf("gripline: adaptive state checkpoint unavailable")
			}
		}
	}
	if rt.Resource != nil {
		if statsAuthority, ok := rt.Resource.(resource.ContextStatsAuthority); ok {
			if err := check("resource_authority", func(ctx context.Context) error {
				_, err := statsAuthority.StatsContext(ctx)
				return err
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// MarkDraining withdraws this node from cluster readiness before HTTP
// shutdown. Existing handlers remain able to renew and settle their leases
// while the load balancer stops sending new work.
func (rt *Runtime) MarkDraining(ctx context.Context, until time.Time) error {
	if rt == nil || rt.Authorities.Membership == nil {
		return nil
	}
	return rt.Authorities.Membership.MarkDraining(ctx, until)
}

// Close releases the runtime's resources exactly once. Errors from individual
// closers are aggregated so callers can surface an incomplete shutdown.
func (rt *Runtime) Close() error {
	rt.closeOnce.Do(func() {
		var errs []error
		for i := len(rt.closers) - 1; i >= 0; i-- {
			if err := rt.closers[i](); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			rt.closeErr = fmt.Errorf("gripline: close errors: %w", errors.Join(errs...))
		}
	})
	return rt.closeErr
}
