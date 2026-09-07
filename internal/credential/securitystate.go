// Package credential: authoritative, durable security state (P0.5/P0.6).
//
// The credential's security state is the hysteresis metadata necessary to
// reproduce status transitions deterministically after a restart, across
// replicas, and after a CAS conflict. Previously this metadata lived only in a
// process-local StateMachine, so a restart erased watchStreak/belowSince and two
// replicas each saw only their own observations — NORMAL→WATCH "after 2
// observations" was not actually reproducible (P0.5).
//
// Design: the state transition is a PURE function over a serializable
// SecurityState plus the current status. It has no mutable state of its own; it
// takes the current SecurityState + current status + one risk observation and
// returns the next SecurityState plus the resulting status. The durable
// authority is the credential row itself: SecurityState is embedded in
// CredentialRecord, and the registry's ObserveAndCommit loads → reduces → CAS →
// commits atomically, bumping the single monotonic Revision exactly once per
// status mutation (P0.44).
package credential

import (
	"context"
	"errors"
	"time"
)

type requestIDContextKey struct{}

// WithRequestID associates the outer ingress request id with an authoritative
// security-state mutation. Stores use it only for correlation; it never affects
// the transition result.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

// RequestIDFromContext returns the optional ingress correlation id.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDContextKey{}).(string)
	return id
}

// SecurityState is the persisted hysteresis metadata needed to reproduce a
// credential's security-state transitions (P0.5). It does not carry Status —
// Status is the top-level CredentialRecord.Status, which ObserveAndCommit keeps
// in sync with the reduced outcome.
//
// Persisting these fields is what makes downgrade-dwell and watch-entry
// reproducible across restart and replication, so an unavailable risk history
// can never be re-interpreted as a clean history that lowers security state.
type SecurityState struct {
	RiskScore         int       // last observed risk score
	WatchStreak       int       // qualifying watch observations since reset
	BelowSince        time.Time // when score last fell below the current down-threshold
	LastObservedAt    time.Time // last risk observation timestamp
	LastStateChangeAt time.Time // dedicated state-change timestamp (P0.22; do NOT overload RotatedAt)
}

// TransitionStatus is the outcome classification of one ObserveAndCommit call
// (P0.6): a state-transition operation must return ONE unambiguous result so the
// admission path never fuses a local observed status with a stale persisted
// revision into a single decision.
type TransitionStatus int

const (
	// TransitionCommitted: the observation was applied and the authoritative
	// record (status + security state + revision) was committed.
	TransitionCommitted TransitionStatus = iota
	// TransitionNoChange: the observation was applied but produced no status
	// change; the authoritative record is returned unmodified in status.
	TransitionNoChange
	// TransitionConflict: a concurrent writer advanced the revision; the
	// observation was NOT applied. Caller should re-read and retry (bounded).
	TransitionConflict
	// TransitionUnavailable: the authoritative store could not be reached; the
	// caller MUST degrade fail-safe (never synthesize state from a local machine).
	TransitionUnavailable
)

func (s TransitionStatus) String() string {
	switch s {
	case TransitionCommitted:
		return "COMMITTED"
	case TransitionNoChange:
		return "NO_CHANGE"
	case TransitionConflict:
		return "CONFLICT"
	case TransitionUnavailable:
		return "UNAVAILABLE"
	default:
		return "UNKNOWN"
	}
}

// TransitionResult is the full, atomic outcome of an ObserveAndCommit.
type TransitionResult struct {
	Status TransitionStatus
	// Record is the authoritative post-operation record for Committed and
	// NoChange. It is nil for Conflict (re-read required) and Unavailable.
	Record *CredentialRecord
	// Before is the authoritative pre-operation record (status+state+revision),
	// available for Committed/NoChange so audit can record before/after.
	Before *CredentialRecord
}

// ErrUnavailable reports that the authoritative store could not serve the
// request. Callers MUST NOT interpret this as a NORMAL lookmiss — the failure
// semantics (degraded/fail-safe) differ from a not-found.
var ErrUnavailable = errors.New("credential: authoritative state unavailable")

// ErrCorrupt reports that a stored record failed structural validation.
var ErrCorrupt = errors.New("credential: corrupt record")

// ErrTimeout reports that the authoritative store did not respond in time.
var ErrTimeout = errors.New("credential: authoritative state timeout")

// SecurityStateRepository is the authoritative, atomic security-state store
// (P0.5/P0.6/P0.20). The concrete registry implements it; the admission path
// depends on this interface, and a durable multi-node implementation (M6)
// satisfies the same contract behind a shared store.
type SecurityStateRepository interface {
	// LookupAuthoritative returns the authoritative record (status + security
	// state + revision) for a credential. It returns ErrNotFound when the
	// credential does not exist, ErrUnavailable/ErrTimeout/ErrCorrupt for the
	// corresponding failure classes — never a plain (nil,false) that blends
	// outage with absence.
	LookupAuthoritative(ctx context.Context, credentialID string) (*CredentialRecord, error)

	// ObserveAndCommit atomically applies a single deterministic risk
	// observation: load authoritative state → reduce via the pure state
	// reducer → if the status changed, CAS the record (revision+1 exactly
	// once) → commit the resulting security state + status → return the
	// authoritative result. It returns a single TransitionStatus so the caller
	// can distinguish committed from conflict from outage.
	ObserveAndCommit(
		ctx context.Context,
		credentialID string,
		score int,
		hy Hysteresis,
		now time.Time,
	) (TransitionResult, error)
}

// Reduced is the pure output of the state transition for one observation.
type Reduced struct {
	Next SecurityState
	// Status is the resulting lifecycle status (top-level credential status).
	Status Status
	// Changed reports whether Status changed as a result of this observation.
	Changed bool
}

// ReduceTransition is the PURE, deterministic state transition over a
// SecurityState. It takes current status + security state and one risk
// observation, returning the next status + security state. It must be a pure
// function of its inputs (no clock reads, no shared mutable state) so it is
// replayable across restart/replica and testable via Gate E.
//
// The reason the reducer takes currentStatus separately (not from SecurityState)
// is to keep a single source of truth: CredentialRecord.Status is authoritative
// and is what assertions, revocation, and quarantine gates read.
func ReduceTransition(
	hy Hysteresis,
	currentStatus Status,
	before SecurityState,
	score int,
	now time.Time,
) Reduced {
	score = clamp01(score)
	after := before
	after.RiskScore = score
	after.LastObservedAt = now
	status := currentStatus
	orig := status

	// MaxAutomaticStatus caps AUTOMATIC escalation only (P0.14). The score is
	// recorded truthfully; transitions beyond the ceiling are withheld. A
	// quarantine-warranting score escalates DIRECTLY to the ceiling status when
	// the ceiling withholds QUARANTINE — a hot credential is resource-
	// restricted NOW (CONSTRAINED under the Gate H default), not held at WATCH
	// waiting for streaks (the old score-mutilation bug) and not committed to
	// an operator-unvalidated QUARANTINED status. When the ceiling sits at or
	// below the current status, no automatic escalation occurs but the truthful
	// score is still recorded. QUARANTINED/REVOKED remain terminal regardless.
	//
	// Direct escalation: a score at or above the quarantine threshold escalates
	// immediately from any active state (spec §36), capped by the ceiling.
	if status != StatusQuarantined && status != StatusRevoked && score >= hy.QuarantineThresh {
		target := StatusQuarantined
		if escalationExceedsCeiling(target, hy.MaxAutomaticStatus) {
			target = hy.MaxAutomaticStatus
		}
		if statusRank(target) > statusRank(status) {
			status = target
			after.BelowSince = time.Time{}
			after.WatchStreak = 0
			after.LastStateChangeAt = now
			return Reduced{Next: after, Status: status, Changed: true}
		}
		// Ceiling at/below current status: record the score, change nothing.
		return Reduced{Next: after, Status: status, Changed: status != orig}
	}

	switch status {
	case StatusNormal:
		if score >= hy.WatchThresh {
			after.WatchStreak++
			if after.WatchStreak >= hy.WatchObs && !escalationExceedsCeiling(StatusWatch, hy.MaxAutomaticStatus) {
				status = StatusWatch
				after.BelowSince = time.Time{}
				after.LastStateChangeAt = now
			}
		} else {
			after.WatchStreak = 0
		}

	case StatusWatch:
		if score >= hy.ConstrainedThresh && !escalationExceedsCeiling(StatusConstrained, hy.MaxAutomaticStatus) {
			status = StatusConstrained
			after.BelowSince = time.Time{}
			after.LastStateChangeAt = now
		} else if score < hy.WatchDownThresh {
			if after.BelowSince.IsZero() {
				after.BelowSince = now
			} else if now.Sub(after.BelowSince) >= hy.WatchDwell {
				status = StatusNormal
				after.WatchStreak = 0
				after.BelowSince = time.Time{}
				after.LastStateChangeAt = now
			}
		} else {
			after.BelowSince = time.Time{}
		}

	case StatusConstrained:
		if score >= hy.QuarantineThresh && !escalationExceedsCeiling(StatusQuarantined, hy.MaxAutomaticStatus) {
			status = StatusQuarantined
			after.BelowSince = time.Time{}
			after.LastStateChangeAt = now
		} else if score < hy.ConstrainedDownThresh {
			if after.BelowSince.IsZero() {
				after.BelowSince = now
			} else if now.Sub(after.BelowSince) >= hy.ConstrainedDwell {
				status = StatusWatch
				after.BelowSince = time.Time{}
				after.LastStateChangeAt = now
			}
		} else {
			after.BelowSince = time.Time{}
		}

	case StatusQuarantined, StatusRevoked:
		// Quarantine and Revoked require explicit lifecycle action to exit; no
		// automatic downgrade through observations.
	}

	return Reduced{Next: after, Status: status, Changed: status != orig}
}

// statusRank orders the escalation ladder for ceiling comparisons.
func statusRank(s Status) int {
	switch s {
	case StatusNormal:
		return 0
	case StatusWatch:
		return 1
	case StatusConstrained:
		return 2
	case StatusQuarantined, StatusRevoked:
		return 3
	default:
		return 0
	}
}

// escalationExceedsCeiling reports whether an automatic transition to target
// would exceed the configured MaxAutomaticStatus ceiling. A zero ceiling means
// unbounded (no Gate H restriction configured).
func escalationExceedsCeiling(target, ceiling Status) bool {
	if ceiling == 0 {
		return false
	}
	return statusRank(target) > statusRank(ceiling)
}
