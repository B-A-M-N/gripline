package lane

import "time"

// PromotionCriteria is the explicit policy a lane must satisfy to become
// ESTABLISHED (§29, §8 of the spec's lane doc).
type PromotionCriteria struct {
	MinCleanAge        time.Duration
	MinCleanRequests   int64
	MinCleanActiveDays  int
	MaxEstablishmentRisk int
	AllowNewLanes      bool // if false, new lanes stay NEW and never promote
	AllowSuspicious    bool // if false, SUSPICIOUS lanes cannot promote
}

// DefaultPromotionCriteria returns conservative defaults. Options mirror the
// spec: minimum clean age, minimum clean requests, minimum clean active
// periods, risk below establishment threshold, no active high-confidence abuse.
func DefaultPromotionCriteria() PromotionCriteria {
	return PromotionCriteria{
		MinCleanAge:         7 * 24 * time.Hour,
		MinCleanRequests:    200,
		MinCleanActiveDays:  3,
		MaxEstablishmentRisk: 15,
		AllowNewLanes:       false,
		AllowSuspicious:     false,
	}
}

// PromoteIfEligible evaluates whether a lane should advance to ESTABLISHED and
// applies the transition if the criteria are met. It returns the new state and
// whether a promotion occurred.
//
// New lanes only promote if policy allows seeding; SUSPICIOUS/BLOCKED lanes
// never promote (INV-8: suspicious traffic must not become trusted baseline
// material). Established lanes stay established.
func PromoteIfEligible(rec *LaneRecord, crit PromotionCriteria, now time.Time) (State, bool) {
	switch rec.State {
	case StateNew:
		if !crit.AllowNewLanes {
			return rec.State, false
		}
		// fall through to the probation/established check
	case StateProbation:
		break
	case StateEstablished:
		return StateEstablished, false
	default: // SUSPICIOUS / BLOCKED
		return rec.State, false
	}

	age := now.Sub(rec.FirstSeenAt)
	if age < crit.MinCleanAge {
		return rec.State, false
	}
	if rec.RequestCount < crit.MinCleanRequests {
		return rec.State, false
	}
	if rec.RiskScore > crit.MaxEstablishmentRisk {
		return rec.State, false
	}

	if rec.State == StateNew {
		rec.State = StateProbation
		rec.Revision++
		return rec.State, false
	}

	rec.State = StateEstablished
	rec.Revision++
	return rec.State, true
}