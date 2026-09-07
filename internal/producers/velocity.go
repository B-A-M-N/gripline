package producers

import (
	"sync"
	"time"
)

// absoluteCostFloorMicrounits is the minimum spend (in integer micro-units of a
// currency unit) a single completion must exceed — beyond the 4x multiple — for
// COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR to fire. The evidence code
// NAME claims an absolute floor; the detector must implement it. A zero cost can
// never spike; a tiny-cost account's "4x" would otherwise flag a $0.0001 → $0.02
// blip that is nothing in absolute terms.
const absoluteCostFloorMicrounits = 50_000 // 0.05 in microunits

// ResourceVelocityProducer detects resource-velocity abuse: concurrency,
// token velocity, and cost velocity exceeding a multiple of the per-subject
// baseline. It maintains an exponential moving average per subject and emits
// a signal when the current value exceeds the threshold multiple.
//
// Baseline scope follows the ACCUSED scope (P0.8/P0.11): a signal that later
// lands on a LANE (CONCURRENCY_*, TOKEN_VELOCITY_*) must be judged against that
// lane's OWN baseline, not a shared per-credential one — otherwise one abusive
// lane inflates the norm every other lane is judged against. COST_VELOCITY_*
// is SCOPE_CREDENTIAL, so cost uses the credential baseline.
type ResourceVelocityProducer struct {
	mu          sync.Mutex
	now         func() time.Time
	alpha       float64 // EMA smoothing factor
	cooldown    time.Duration
	maxSubjects int

	// concurrencyBaseline tracks per-lane concurrency EMA (ScopeLane).
	concurrencyBaseline map[string]*baseline
	// tokenBaseline tracks per-lane token EMA (ScopeLane).
	tokenBaseline map[string]*baseline
	// costBaseline tracks per-credential cost EMA (ScopeCredential).
	costBaseline map[string]*baseline
}

// NewResourceVelocityProducer builds a ResourceVelocityProducer.
func NewResourceVelocityProducer(now func() time.Time) *ResourceVelocityProducer {
	if now == nil {
		now = time.Now
	}
	return &ResourceVelocityProducer{
		now:                 now,
		alpha:               0.3,
		cooldown:            defaultCooldown,
		maxSubjects:         defaultMaxSubjects,
		concurrencyBaseline: make(map[string]*baseline),
		tokenBaseline:       make(map[string]*baseline),
		costBaseline:        make(map[string]*baseline),
	}
}

// laneSubject returns the baseline key for a LANE-scoped signal: the lane id
// when present, else the credential id. It never returns "" — an empty key would
// pool ALL no-lane traffic into one shared baseline, polluting every
// credential's norm. A credential-keyed fallback is a conservative,
// still-per-scope-owner bound for the (edge) no-lane admission.
func laneSubject(subjects SubjectContext) string {
	if subjects.LaneID != "" {
		return subjects.LaneID
	}
	return subjects.CredentialID
}

// ObserveAdmission checks concurrency against the baseline at admission time.
// Concurrency is a LANE-scoped quantity (CONCURRENCY_OVER_* → ScopeLane), so it
// is measured per lane.
func (p *ResourceVelocityProducer) ObserveAdmission(behavior AdmissionBehavior) []Signal {
	if behavior.Subjects.CredentialID == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	var signals []Signal
	subject := laneSubject(behavior.Subjects)
	now := p.now()

	if behavior.Concurrency > 0 {
		if sig := p.checkVelocity(p.concurrencyBaseline, subject+":conc", float64(behavior.Concurrency), now, "CONCURRENCY_OVER_4X_BASELINE", "CONCURRENCY_OVER_10X_BASELINE"); sig != "" {
			signals = append(signals, Signal{Code: sig})
		}
	}

	return signals
}

// ObserveCompletion checks token and cost velocity against the baseline.
// Token velocity is LANE-scoped (TOKEN_VELOCITY_* → ScopeLane); cost velocity
// is CREDENTIAL-scoped (COST_VELOCITY_* → ScopeCredential).
func (p *ResourceVelocityProducer) ObserveCompletion(behavior CompletionBehavior) []Signal {
	if behavior.Subjects.CredentialID == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	var signals []Signal
	lane := laneSubject(behavior.Subjects)
	cred := behavior.Subjects.CredentialID
	now := p.now()

	// Token velocity — per lane.
	if behavior.Actual.Combined > 0 {
		if sig := p.checkVelocity(p.tokenBaseline, lane+":tok", float64(behavior.Actual.Combined), now, "TOKEN_VELOCITY_OVER_4X_BASELINE", "TOKEN_VELOCITY_OVER_10X_BASELINE"); sig != "" {
			signals = append(signals, Signal{Code: sig})
		}
	}

	// Cost velocity — per credential. EVERY positive cost observation updates
	// the baseline (a sub-floor norm must still be LEARNED, or a later spike
	// becomes "baseline observation #1" instead of a spike against an
	// established low-cost norm — P0.10-fix). The absolute floor gates
	// EMISSION only: the evidence name
	// COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR requires BOTH the
	// 4x multiple AND the floor, so a sub-floor 4x blip still never emits.
	if behavior.Actual.Cost > 0 {
		if sig := p.checkVelocity(p.costBaseline, cred+":cost", float64(behavior.Actual.Cost), now, "COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR", ""); sig != "" && behavior.Actual.Cost >= absoluteCostFloorMicrounits {
			signals = append(signals, Signal{Code: sig})
		}
	}

	return signals
}

// checkVelocity updates the baseline and returns the appropriate signal code
// (or empty if no threshold crossed). Compares against the PREVIOUS baseline
// so a spike is measured against the established norm, not a diluted average.
func (p *ResourceVelocityProducer) checkVelocity(m map[string]*baseline, key string, value float64, now time.Time, code4x string, code10x string) string {
	b := m[key]
	if b == nil {
		if len(m) >= p.maxSubjects {
			evictColdestBaseline(m)
		}
		b = &baseline{}
		m[key] = b
	}
	b.count++
	b.lastSeen = now

	// Need a baseline established before comparing (at least 2 prior observations).
	if b.count < 3 || b.ema <= 0 {
		// Update EMA after comparison.
		if b.count == 1 {
			b.ema = value
		} else {
			b.ema = p.alpha*value + (1-p.alpha)*b.ema
		}
		return ""
	}

	emitted := ""
	// Check higher threshold first (only if code10x is provided).
	if code10x != "" && value >= b.ema*10 {
		if b.lastEmit.IsZero() || now.Sub(b.lastEmit) >= p.cooldown {
			b.lastEmit = now
			emitted = code10x
		}
	} else if value >= b.ema*4 {
		if b.lastEmit.IsZero() || now.Sub(b.lastEmit) >= p.cooldown {
			b.lastEmit = now
			emitted = code4x
		}
	}

	// Update EMA after comparison.
	b.ema = p.alpha*value + (1-p.alpha)*b.ema

	return emitted
}
