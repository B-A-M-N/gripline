package resource

import "context"

// Authority is the backend-neutral hard-resource admission contract. The
// built-in Governor is one implementation; a clustered lease service can
// implement the same operation without making the terminator depend on its
// in-process maps. Returned reservations remain ownership-safe and are
// settled/released by the caller exactly once.
type Authority interface {
	ProvisionUsage(scopes []ScopeSpec, estimate UsageEstimate) (*MultiReservation, error)
	RemoveScope(scope Scope, id string) bool
	InUseFor(scope Scope, id string) int
}

// ContextAuthority is the cancellable extension of Authority. The terminator
// prefers it when available and retains the non-context method only for
// source-compatible legacy embedders.
type ContextAuthority interface {
	ProvisionUsageContext(ctx context.Context, scopes []ScopeSpec, estimate UsageEstimate) (*MultiReservation, error)
}

// AdmissionReservation is the ONE lifecycle abstraction for capacity an
// authorization is holding (P0.8). Callers (the proxy) defer Release on this
// immediately after admission and never need to know whether the hold is a
// legacy single-scope concurrency lease, a multi-scope governor reservation,
// or a future distributed lease. Release must be idempotent on every
// implementation so a defer plus explicit release path cannot double-refund.
type AdmissionReservation interface {
	Release()
}

// NoopReservation is the zero-hold reservation: an admission that acquired no
// capacity (or a nil Outcome) still yields a usable handle so callers can
// defer Release unconditionally.
type NoopReservation struct{}

// Release is a no-op.
func (NoopReservation) Release() {}

// Compile-time conformance: every reservation shape callers may receive from
// an Outcome must satisfy the interface.
var (
	_ Authority            = (*Governor)(nil)
	_ ContextAuthority     = (*Governor)(nil)
	_ AdmissionReservation = (*MultiReservation)(nil)
	_ AdmissionReservation = (*LeaseHandle)(nil)
	_ AdmissionReservation = NoopReservation{}
)
