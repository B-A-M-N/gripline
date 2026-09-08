package resource

import (
	"context"
	"time"
)

// Authority is the backend-neutral hard-resource admission contract. The
// built-in Governor is one implementation; a clustered lease service can
// implement the same operation without making the terminator depend on its
// in-process maps. Returned reservations remain ownership-safe and are
// settled/released by the caller exactly once.
type Authority interface {
	RemoveScope(scope Scope, id string) bool
	InUseFor(scope Scope, id string) int
}

// ReserveRequest is the backend-neutral resource admission request. RequestID
// is the ingress operation key used by durable authorities for retry-safe
// replay; in-process authorities may ignore it.
type ReserveRequest struct {
	RequestID string
	Scopes    []ScopeSpec
	Estimate  UsageEstimate
}

// UsageReservation is the one lifecycle contract for an admitted resource hold.
// Release stays synchronous so callers can defer it on every exit path;
// remote-sensitive transitions accept a context.
type UsageReservation interface {
	AdmissionReservation
	MarkForwarded(context.Context) error
	Renew(context.Context) error
	SettleContext(context.Context, UsageEstimate) error
	ExpiresAt() time.Time
}

// ResourceAuthority is the complete hard-resource boundary used by the
// terminator. Local and clustered authorities share the same Reserve path.
type ResourceAuthority interface {
	Authority
	Reserve(context.Context, ReserveRequest) (UsageReservation, error)
}

// UsageAuthority is the legacy in-process usage-admission extension. It is
// separate from Authority so a remote implementation can expose an abstract
// reservation lifecycle without returning an in-memory concrete type.
type UsageAuthority interface {
	ProvisionUsage(scopes []ScopeSpec, estimate UsageEstimate) (*MultiReservation, error)
}

// ContextAuthority is the cancellable extension of Authority. The terminator
// prefers it when available and retains the non-context method only for
// source-compatible legacy embedders.
type ContextAuthority interface {
	ProvisionUsageContext(ctx context.Context, scopes []ScopeSpec, estimate UsageEstimate) (*MultiReservation, error)
}

// DistributedAuthority is implemented by a shared lease authority. The
// returned reservation owns every scope hold and may be renewed for a stream.
type DistributedAuthority interface {
	ProvisionDistributed(ctx context.Context, scopes []ScopeSpec, estimate UsageEstimate) (UsageReservation, error)
}

// RequestDistributedAuthority adds an ingress request key to distributed
// provisioning. Authorities use it to return the original lease on a retry
// after a lost response instead of charging the request twice.
type RequestDistributedAuthority interface {
	ProvisionDistributedWithRequestID(ctx context.Context, requestID string, scopes []ScopeSpec, estimate UsageEstimate) (UsageReservation, error)
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
	_ ResourceAuthority    = (*Governor)(nil)
	_ UsageAuthority       = (*Governor)(nil)
	_ ContextAuthority     = (*Governor)(nil)
	_ AdmissionReservation = (*MultiReservation)(nil)
	_ UsageReservation     = (*MultiReservation)(nil)
	_ AdmissionReservation = (*LeaseHandle)(nil)
	_ AdmissionReservation = NoopReservation{}
)
