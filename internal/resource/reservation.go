package resource

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
	_ AdmissionReservation = (*MultiReservation)(nil)
	_ AdmissionReservation = (*LeaseHandle)(nil)
	_ AdmissionReservation = NoopReservation{}
)
