package lane

import "time"

// PromotionCriteria is the explicit policy a lane must satisfy to become
// ESTABLISHED (§29, §8 of the spec's lane doc).
type PromotionCriteria struct {
	MinCleanAge          time.Duration
	MinCleanRequests     int64
	MinCleanActiveDays   int
	MaxEstablishmentRisk int
	AllowNewLanes        bool // if false, new lanes stay NEW and never promote
	AllowSuspicious      bool // if false, SUSPICIOUS lanes cannot promote
}

// DefaultPromotionCriteria returns conservative defaults. Options mirror the
// spec: minimum clean age, minimum clean requests, minimum clean active
// periods, risk below establishment threshold, no active high-confidence abuse.
func DefaultPromotionCriteria() PromotionCriteria {
	return PromotionCriteria{
		MinCleanAge:          7 * 24 * time.Hour,
		MinCleanRequests:     200,
		MinCleanActiveDays:   3,
		MaxEstablishmentRisk: 15,
		AllowNewLanes:        false,
		AllowSuspicious:      false,
	}
}

// PromoteIfEligible evaluates whether a lane should advance to ESTABLISHED and
// applies the transition if the criteria are met. It returns the new state and
// whether a promotion occurred.
//
// NEW→PROBATION: only requires AllowNewLanes (policy seeding). No age or
// request count threshold — the lane just needs policy permission to exist.
//
// PROBATION→ESTABLISHED: requires ALL criteria: MinCleanAge,
// MinCleanRequests (AuthorizedCleanRequests), CleanActiveDays, and
// MaxEstablishmentRisk. This is the real trust threshold.
//
// SUSPICIOUS/BLOCKED lanes never promote (INV-8: suspicious traffic must not
// become trusted baseline material). Established lanes stay established.
//
// The EstablishmentScore is set to 100 only when the PROBATION→ESTABLISHED
// criteria are met.
//
// Note: promotion should only be called after a request has been fully
// authorized (clean). Denied requests must not advance a lane toward promotion.
func PromoteIfEligible(rec *LaneRecord, crit PromotionCriteria, now time.Time) (State, bool) {
	// Security gate (P0.7/P0.43): a lane whose risk-driven security status is
	// not NORMAL must NEVER promote, regardless of its trust ladder or clean
	// counters. This decouples trust from risk: a SUSPICIOUS/BLOCKED lane does
	// not advance toward trusted-baseline material even if it has accumulated
	// clean requests historically.
	if rec.Security.Status != LaneNormal {
		return rec.State, false
	}
	switch rec.State {
	case StateNew:
		if !crit.AllowNewLanes {
			return rec.State, false
		}
		// NEW→PROBATION: only needs policy permission. No age/request
		// threshold — this is purely a seeding control.
		rec.State = StateProbation
		rec.Revision++
		return rec.State, false
	case StateProbation:
		// PROBATION→ESTABLISHED: full trust criteria.
		// MinCleanAge is the CONTIGUOUS clean window since CleanSince, not the
		// lane's age since FirstSeenAt (P0.42): a lane that misbehaved then went
		// quiet must NOT pass an age check immediately.
		cleanAnchor := rec.CleanSince
		if cleanAnchor.IsZero() {
			cleanAnchor = rec.FirstSeenAt
		}
		if now.Sub(cleanAnchor) < crit.MinCleanAge {
			return rec.State, false
		}
		// MinCleanRequests checks AuthorizedCleanRequests (not RequestCount),
		// because only clean authorized requests contribute to baseline trust.
		if rec.AuthorizedCleanRequests < crit.MinCleanRequests {
			return rec.State, false
		}
		// MinCleanActiveDays checks CleanActiveDays (not ActiveDays),
		// because only distinct days with a clean history count.
		if rec.CleanActiveDays < crit.MinCleanActiveDays {
			return rec.State, false
		}
		if rec.RiskScore > crit.MaxEstablishmentRisk {
			return rec.State, false
		}

		// EstablishmentScore: exactly 100 when all criteria satisfied.
		rec.EstablishmentScore = 100
		rec.State = StateEstablished
		rec.Revision++
		return rec.State, true
	case StateEstablished:
		return StateEstablished, false
	default: // trust SUSPICIOUS/BLOCKED ladder states (legacy) — never promote
		return rec.State, false
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
