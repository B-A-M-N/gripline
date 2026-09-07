package lane

import (
	"errors"
	"time"
)

// This file holds the PURE lane mutation reducers (P0.10): deterministic
// functions over an explicit record set, clock, and limits — no shared state,
// no map iteration, no I/O. The in-memory Store executes them under its mutex;
// the durable statebolt repository executes them inside one bbolt write
// transaction. Both repositories therefore run IDENTICAL security semantics,
// and a restart reproduces the same decisions, because there is exactly one
// implementation of each mutation to diverge from.

// ErrTooManyLanes is returned when a credential already holds the max lanes.
var ErrTooManyLanes = errors.New("lane: too many lanes for credential")

// ErrLaneConflict is returned when a create would overwrite an existing lane
// row. An overwrite here is a state-reset attack (§24): distinct feature sets
// deriving the same caller-chosen id would replace a BLOCKED/SUSPICIOUS lane
// with a fresh NEW record — laundering its history and evading the explosion
// limit. Failing closed is the only safe answer.
var ErrLaneConflict = errors.New("lane: lane id collision with different features")

// MutationResult is the outcome of one pure lane-set mutation. Upsert carries
// a COPY of the mutated/created record; Deletes names records removed by
// retention; Created distinguishes creation from mutation.
type MutationResult struct {
	Upsert  *LaneRecord
	Deletes []string
	Created bool
}

// EffectiveSecurityHysteresis resolves the hysteresis for lane risk→status
// transitions: an explicit override (the compiled policy, P0.13) wins; a valid
// configured base is next; conservative defaults last. Shared by both
// repositories so a policy override behaves identically on memory and Bolt.
func EffectiveSecurityHysteresis(override, base SecurityHysteresis) SecurityHysteresis {
	if override.SuspectThresh > 0 && override.BlockThresh > 0 {
		return override
	}
	if base.SuspectThresh > 0 && base.BlockThresh > 0 {
		return base
	}
	return DefaultSecurityHysteresis()
}

// RetentionDecision reports whether a lane SURVIVES idle retention at now
// (P0.23): ordinary NEW/PROBATION lanes are cache (expire at the configured
// idle bound); ESTABLISHED lanes live 4x longer; SUSPICIOUS lanes are security
// history (16x); BLOCKED lanes are tombstones that NEVER expire through this
// path — only an explicit operator lifecycle action may remove them. A
// non-positive idleExpiration retains everything.
func RetentionDecision(rec *LaneRecord, idleExpiration time.Duration, now time.Time) bool {
	if idleExpiration <= 0 {
		return true
	}
	if rec.LastSeenAt.After(now.Add(-idleExpiration)) {
		return true
	}
	if rec.Security.Status == LaneBlocked {
		return true // tombstone (P0.23)
	}
	retained := idleExpiration
	switch {
	case rec.Security.Status == LaneSuspicious:
		retained *= 16 // security history outlives the cache bound
	case rec.State == StateEstablished:
		retained *= 4 // continuity for established lanes
	}
	return rec.LastSeenAt.After(now.Add(-retained))
}

// TrackActiveDay advances the distinct-active-days counter (§29).
func TrackActiveDay(r *LaneRecord, now time.Time) {
	day := now.Format("2006-01-02")
	if r.LastActiveDay == day {
		return
	}
	r.LastActiveDay = day
	r.ActiveDays++
}

// applyCleanCounters increments the authorized-clean counters for now.
func applyCleanCounters(r *LaneRecord, now time.Time) {
	r.AuthorizedCleanRequests++
	day := now.Format("2006-01-02")
	if r.LastCleanActiveDay != day {
		r.LastCleanActiveDay = day
		r.CleanActiveDays++
	}
	TrackActiveDay(r, now)
}

// ApplyBorrowOrCreate is the PURE core of BorrowOrCreate (P0.9/§26, P0.21,
// P0.22, §28): given the credential's current records (in any order), the
// owning credential id, a candidate lane id + feature vector, the
// classification context, and the effective limits, it selects/mutates/creates
// the lane and decides retention deletes. Deterministic: candidates tie-break
// on (similarity desc, lane id asc). records are mutated in place for existing
// lanes; a created lane is returned only in the result (Upsert), never aliased
// into records.
func ApplyBorrowOrCreate(records []*LaneRecord, credID, newLaneID string, cand Features, ctx ClassificationContext, limits Limits, now time.Time) (MutationResult, error) {
	res := MutationResult{}
	th := ctx.Thresholds
	// P0.21: a zero/unset context revision means "the current universe".
	if ctx.Revision < 1 {
		ctx.Revision = currentClassificationRevision
	}

	// Retention first (per-credential, before the limit decision) so a lane
	// that should have expired cannot wedge creation (§28).
	kept := records[:0:0]
	for _, rec := range records {
		if RetentionDecision(rec, limits.LaneIdleExpiration, now) {
			kept = append(kept, rec)
		} else {
			res.Deletes = append(res.Deletes, rec.LaneID)
		}
	}
	records = kept

	// Exact-manifestation reuse (P0.1): the candidate re-presents the identical
	// vector its lane ID was derived from under the current schema — reuse its
	// OWN lane, whatever its state, without granting established-lane trust. A
	// same-ID record with a DIFFERENT vector or an old schema is the §24
	// state-reset collision and fails closed; a schema-stale record is never
	// silently compared (P0.22).
	for _, rec := range records {
		if rec.LaneID != newLaneID {
			continue
		}
		if rec.FeatSchema == featSchemaVersion && rec.ClassificationRevision == ctx.Revision && sameFeatures(rec.Features, cand) {
			rec.LastSeenAt = now
			rec.RequestCount++
			rec.Revision++
			TrackActiveDay(rec, now)
			c := *rec
			res.Upsert = &c
			return res, nil
		}
		return res, ErrLaneConflict
	}

	// Deterministic best-match selection over schema+revision-current rows.
	bestSim := -1.0
	var best *LaneRecord
	for _, rec := range records {
		if rec.FeatSchema != featSchemaVersion || rec.ClassificationRevision != ctx.Revision {
			continue
		}
		if sim := Similarity(cand, rec.Features); sim > bestSim {
			bestSim = sim
			best = rec
		} else if sim == bestSim && best != nil && rec.LaneID < best.LaneID {
			best = rec
		}
	}

	// Anti-laundering gate (P0.9): a Match requires BOTH enough renormalized
	// similarity AND enough comparable feature mass. A floor of 0 fails closed.
	isMatch := best != nil && th.classify(bestSim) == ClassMatch
	if isMatch && th.MinComparableWeight > 0 {
		isMatch = ComparableWeight(cand, best.Features) >= th.MinComparableWeight
	} else if best != nil {
		isMatch = false
	}
	if best != nil && isMatch {
		best.LastSeenAt = now
		best.RequestCount++
		best.Revision++
		TrackActiveDay(best, now)
		c := *best
		res.Upsert = &c
		return res, nil
	}

	// New lane: explosion protection (§28) — active and provisional lanes both
	// bounded.
	if len(records) >= limits.MaxActiveLanesPerCredential {
		return res, ErrTooManyLanes
	}
	if limits.MaxProvisionalLanes > 0 {
		provisional := 0
		for _, rec := range records {
			if rec.State == StateNew || rec.State == StateProbation {
				provisional++
			}
		}
		if provisional >= limits.MaxProvisionalLanes {
			return res, ErrTooManyLanes
		}
	}
	rec := &LaneRecord{
		LaneID:       newLaneID,
		CredentialID: credID,
		State:        StateNew,
		FirstSeenAt:  now,
		LastSeenAt:   now,
		Features:     cand, // full vector persisted (P0.8)
		FeatSchema:   featSchemaVersion,
		// P0.21: persist the classification universe the row was created under.
		ClassificationRevision: ctx.Revision,
		RequestCount:           1,
		CleanSince:             now, // the clean window starts at lane creation (P0.42)
		Revision:               1,
	}
	TrackActiveDay(rec, now)
	res.Upsert = rec
	res.Created = true
	return res, nil
}

// ApplyRiskObservation is the PURE core of ObserveRisk (P0.7): one risk score
// observation drives the lane's security dimension. Elevation invalidates the
// clean window (P0.42); recovery to NORMAL restarts it and epochs the clean
// counters (P0.24). Mutates rec in place.
func ApplyRiskObservation(rec *LaneRecord, riskScore int, hy SecurityHysteresis, now time.Time) {
	before := rec.Security.Status
	rec.RiskScore = riskScore
	rec.Security = ReduceLaneSecurity(hy, rec.Security, riskScore, now)
	if rec.Security.Status != LaneNormal && before == LaneNormal {
		// P0.42: elevation invalidates the contiguous clean window.
		rec.CleanSince = time.Time{}
	}
	if rec.Security.Status == LaneNormal && before != LaneNormal {
		// P0.24: recovery restarts the clean window and epochs baseline
		// progress — promotion criteria must be re-earned in the new window.
		rec.CleanSince = now
		rec.AuthorizedCleanRequests = 0
		rec.CleanActiveDays = 0
		rec.LastCleanActiveDay = ""
	}
	rec.Revision++
}

// ApplyCleanAuthorizedAndPromote is the PURE core of
// RecordCleanAuthorizedAndPromote (P0.25): ONE authoritative mutation — clean
// counters, then promotion if eligible — bumping Revision exactly once.
// Returns whether a promotion occurred. Mutates rec in place.
func ApplyCleanAuthorizedAndPromote(rec *LaneRecord, riskScore int, crit PromotionCriteria, now time.Time) bool {
	rec.RiskScore = riskScore
	applyCleanCounters(rec, now)

	promoted := false
	switch rec.State {
	case StateNew, StateProbation:
		if newState, ok := PromoteIfEligible(rec, crit, now); ok {
			rec.State = newState
			promoted = true
		}
	}
	rec.Revision++
	return promoted
}

// ApplyCleanAuthorized is the PURE counter-only mutation (no promotion attempt)
// used by legacy RecordCleanAuthorized. Mutates rec in place, bumps Revision.
func ApplyCleanAuthorized(rec *LaneRecord, now time.Time) {
	applyCleanCounters(rec, now)
	rec.Revision++
}

// ApplyUnblock is the PURE operator lifecycle mutation for exiting a BLOCKED
// lane (P0.7/§36): validates the precondition (the lane must be BLOCKED —
// clearing a lane that never earned a block would let a FORCE action launder
// state), resets the security dimension to NORMAL, and re-seeds the contiguous
// clean window (P0.42) so promotion criteria restart from the operator's
// clearing, NOT from the pre-abuse quiet period. Mutates rec in place.
// Returns the pre-transition security status for the audit entry.
func ApplyUnblock(rec *LaneRecord, now time.Time) (SecurityStatus, error) {
	if rec.Security.Status != LaneBlocked {
		return rec.Security.Status, ErrActionInvalid
	}
	before := rec.Security.Status
	rec.Security.Status = LaneNormal
	rec.CleanSince = now
	rec.Security.SuspectStreak = 0
	rec.Security.ClearSince = time.Time{}
	rec.Security.RiskScore = 0
	rec.Revision++
	return before, nil
}
