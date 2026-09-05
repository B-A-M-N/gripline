package lane

import "time"

// SecurityStatus is the RISK-DRIVEN enforcement dimension of a lane, separate
// from the TRUST ladder (State: NEW/PROBATION/ESTABLISHED) and the lifecycle
// permissions. Splitting the two solves the P0.7 ambiguity "what does a
// SUSPICIOUS established lane recover to?": trust and security are orthogonal
// axes. A lane's TrustState governs promotion; its SecurityStatus governs
// request-level limits and denial, driven by lane-scoped risk.
type SecurityStatus int

const (
	// LaneNormal: no lane-scoped risk elevation; the lane operates under normal
	// limits and may promote (when its trust ladder allows).
	LaneNormal SecurityStatus = iota
	// LaneSuspicious: lane-scoped risk crossed the suspect threshold; the lane
	// is restricted to constrained lane limits and must NOT promote.
	LaneSuspicious
	// LaneBlocked: high-confidence lane-scoped abuse; the lane is denied
	// outright (equivalent to a per-lane block).
	LaneBlocked
)

func (s SecurityStatus) String() string {
	switch s {
	case LaneNormal:
		return "NORMAL"
	case LaneSuspicious:
		return "SUSPICIOUS"
	case LaneBlocked:
		return "BLOCKED"
	default:
		return "UNKNOWN"
	}
}

// SecurityHysteresis controls lane risk→security-status transitions. These are
// policy-controlled (P0.11) and deliberately separate from credential
// hysteresis: a lane elevates/recovers on its own observed risk, not the
// credential's.
type SecurityHysteresis struct {
	SuspectThresh int           // risk >= this → SUSPICIOUS
	BlockThresh   int           // risk >= this → BLOCKED
	ClearThresh   int           // risk < this for ClearDwell → NORMAL
	ClearDwell    time.Duration // dwell below ClearThresh to recover SUSPICIOUS→NORMAL
	SuspectObs    int           // qualifying observations to enter SUSPICIOUS
}

// DefaultSecurityHysteresis returns conservative defaults. A single high-score
// or repeated moderate-score lane observation elevates; recovery needs a
// sustained clean window so a lane cannot flip-flop on a single low score.
func DefaultSecurityHysteresis() SecurityHysteresis {
	return SecurityHysteresis{
		SuspectThresh: 30,
		BlockThresh:   70,
		ClearThresh:   15,
		ClearDwell:    30 * time.Minute,
		SuspectObs:    2,
	}
}

// SecurityState is the persisted hysteresis metadata for the lane security
// dimension, so SUSPICIOUS/BLOCKED elevation and recovery reproduce across
// restart and replicas (same authoritative-state requirement as credential P0.5).
type SecurityState struct {
	Status         SecurityStatus
	RiskScore      int
	SuspectStreak  int
	ClearSince     time.Time // when risk last fell below ClearThresh
	LastObservedAt time.Time
}

// ReduceLaneSecurity is the PURE, deterministic reducer for the lane security
// dimension (P0.7). Given the current security state + one risk observation it
// returns the next state. No clock reads, no shared state — replayable.
func ReduceLaneSecurity(hy SecurityHysteresis, before SecurityState, score int, now time.Time) SecurityState {
	score = clamp(score)
	after := before
	after.RiskScore = score
	after.LastObservedAt = now

	switch before.Status {
	case LaneNormal:
		if score >= hy.BlockThresh {
			// High-confidence abuse blocks immediately (analogous to §36).
			after.Status = LaneBlocked
			after.ClearSince = time.Time{}
		} else if score >= hy.SuspectThresh {
			after.SuspectStreak++
			if after.SuspectStreak >= hy.SuspectObs {
				after.Status = LaneSuspicious
				after.ClearSince = time.Time{}
			}
		} else {
			after.SuspectStreak = 0
			after.ClearSince = time.Time{}
		}

	case LaneSuspicious:
		if score >= hy.BlockThresh {
			after.Status = LaneBlocked
			after.ClearSince = time.Time{}
		} else if score < hy.ClearThresh {
			if after.ClearSince.IsZero() {
				after.ClearSince = now
			} else if now.Sub(after.ClearSince) >= hy.ClearDwell {
				// Recovered: SUSPICIOUS → NORMAL only after a sustained clean
				// window (P0.7's "what does a suspicious lane recover to").
				after.Status = LaneNormal
				after.SuspectStreak = 0
				after.ClearSince = time.Time{}
			}
		} else {
			after.ClearSince = time.Time{}
		}

	case LaneBlocked:
		// BLOCKED requires explicit lifecycle action (operator unblock) to exit;
		// no automatic recovery from a block.
	}

	return after
}

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// Elevated reports whether a lane security status imposes restriction.
func (s SecurityStatus) Elevated() bool { return s == LaneSuspicious }

// Denied reports whether a lane security status denies requests outright.
func (s SecurityStatus) Denied() bool { return s == LaneBlocked }