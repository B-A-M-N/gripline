package terminator

// AdaptiveStateStatus describes whether the admission path had access to
// authoritative, complete security state for this request (P0.1). An
// unavailable adaptive history is UNKNOWN, never zero.
type AdaptiveStateStatus int

const (
	// AdaptiveAvailable: the evidence/risk snapshot and the authoritative
	// security-state store served this request; the normal transition applies.
	AdaptiveAvailable AdaptiveStateStatus = iota
	// AdaptiveDegraded: at least one authoritative evidence snapshot or the
	// security-state store was unavailable. The request must NOT feed synthetic
	// zero risk into the state machine, must NOT start/advance a downgrade
	// dwell, must NOT promote a lane, and must NOT update clean baselines. It
	// preserves persisted restrictions and enforces static hard limits.
	AdaptiveDegraded
)

func (s AdaptiveStateStatus) String() string {
	if s == AdaptiveDegraded {
		return "DEGRADED"
	}
	return "AVAILABLE"
}