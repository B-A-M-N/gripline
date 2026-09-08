package producers

import (
	"context"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/adaptive"
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
	distributed adaptive.Store
	stateMu     sync.Mutex
	stateErr    error

	// concurrencyBaseline tracks per-lane concurrency EMA (ScopeLane).
	concurrencyBaseline map[string]*baseline
	// tokenBaseline tracks per-lane token EMA (ScopeLane).
	tokenBaseline map[string]*baseline
	// costBaseline tracks per-credential cost EMA (ScopeCredential).
	costBaseline map[string]*baseline
}

// NewDistributedResourceVelocityProducer uses authority-owned baseline rows
// so completion observations from different nodes share one EMA.
func NewDistributedResourceVelocityProducer(now func() time.Time, store adaptive.Store) *ResourceVelocityProducer {
	p := NewResourceVelocityProducer(now)
	p.distributed = store
	return p
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
	return p.ObserveAdmissionContext(context.Background(), behavior)
}

func (p *ResourceVelocityProducer) ObserveAdmissionContext(ctx context.Context, behavior AdmissionBehavior) []Signal {
	if p.distributed != nil {
		if behavior.Subjects.CredentialID == "" || behavior.Concurrency <= 0 {
			return nil
		}
		signal, err := p.distributed.ObserveBaseline(ctx, adaptive.BaselineObservation{
			Detector: "resource_velocity", Subject: laneSubject(behavior.Subjects), Metric: "concurrency",
			Value: float64(behavior.Concurrency), Alpha: p.alpha, Cooldown: p.cooldown,
			Threshold4: 4, Threshold10: 10, Code4: "CONCURRENCY_OVER_4X_BASELINE",
			Code10: "CONCURRENCY_OVER_10X_BASELINE", ConcurrencyRamp: true,
		})
		p.stateMu.Lock()
		p.stateErr = err
		p.stateMu.Unlock()
		if err != nil || signal == "" {
			return nil
		}
		return []Signal{{Code: signal}}
	}
	return p.observeAdmissionLocal(behavior)
}

func (p *ResourceVelocityProducer) observeAdmissionLocal(behavior AdmissionBehavior) []Signal {
	if behavior.Subjects.CredentialID == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	var signals []Signal
	subject := laneSubject(behavior.Subjects)
	now := p.now()

	if behavior.Concurrency > 0 {
		if sig := p.checkConcurrencyVelocity(subject+":conc", float64(behavior.Concurrency), now); sig != "" {
			signals = append(signals, Signal{Code: sig})
		}
	}

	return signals
}

// checkConcurrencyVelocity deliberately learns only from observations that
// remain near the established baseline. A real concurrent burst is observed
// as a ramp (1, 2, 3, ...), and feeding each in-flight value into the EMA can
// otherwise make the detector normalize the attack before it reaches a
// threshold. Token and cost baselines continue to use checkVelocity because
// their completion values have different learning characteristics.
func (p *ResourceVelocityProducer) checkConcurrencyVelocity(key string, value float64, now time.Time) string {
	b := p.concurrencyBaseline[key]
	if b == nil {
		if len(p.concurrencyBaseline) >= p.maxSubjects {
			evictColdestBaseline(p.concurrencyBaseline)
		}
		b = &baseline{}
		p.concurrencyBaseline[key] = b
	}
	b.count++
	b.lastSeen = now
	if b.count < 3 || b.ema <= 0 {
		if b.count == 1 {
			b.ema = value
		} else {
			b.ema = p.alpha*value + (1-p.alpha)*b.ema
		}
		return ""
	}

	emitted := ""
	if value >= b.ema*10 {
		if b.lastEmit.IsZero() || now.Sub(b.lastEmit) >= p.cooldown {
			b.lastEmit = now
			emitted = "CONCURRENCY_OVER_10X_BASELINE"
		}
	} else if value >= b.ema*4 {
		if b.lastEmit.IsZero() || now.Sub(b.lastEmit) >= p.cooldown {
			b.lastEmit = now
			emitted = "CONCURRENCY_OVER_4X_BASELINE"
		}
	}

	// Do not let an elevated in-flight ramp redefine the normal level. A
	// return to near-baseline traffic resumes ordinary EMA learning.
	if value < b.ema*2 {
		b.ema = p.alpha*value + (1-p.alpha)*b.ema
	}
	return emitted
}

// ObserveCompletion checks token and cost velocity against the baseline.
// Token velocity is LANE-scoped (TOKEN_VELOCITY_* → ScopeLane); cost velocity
// is CREDENTIAL-scoped (COST_VELOCITY_* → ScopeCredential).
func (p *ResourceVelocityProducer) ObserveCompletion(behavior CompletionBehavior) []Signal {
	return p.ObserveCompletionContext(context.Background(), behavior)
}

func (p *ResourceVelocityProducer) ObserveCompletionContext(ctx context.Context, behavior CompletionBehavior) []Signal {
	if p.distributed != nil {
		return p.observeCompletionDistributed(ctx, behavior)
	}
	return p.observeCompletionLocal(behavior)
}

func (p *ResourceVelocityProducer) observeCompletionLocal(behavior CompletionBehavior) []Signal {
	if behavior.Subjects.CredentialID == "" || !behavior.Success {
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

func (p *ResourceVelocityProducer) observeCompletionDistributed(ctx context.Context, behavior CompletionBehavior) []Signal {
	if behavior.Subjects.CredentialID == "" || !behavior.Success {
		return nil
	}
	var signals []Signal
	var observedErr error
	observe := func(subject, metric string, value float64, code4, code10 string, floor float64) {
		if value <= 0 {
			return
		}
		signal, err := p.distributed.ObserveBaseline(ctx, adaptive.BaselineObservation{
			Detector: "resource_velocity", Subject: subject, Metric: metric, Value: value,
			Alpha: p.alpha, Cooldown: p.cooldown, Threshold4: 4, Threshold10: 10,
			Code4: code4, Code10: code10, AbsoluteFloor: floor,
		})
		if err != nil {
			observedErr = err
			return
		}
		if signal != "" {
			signals = append(signals, Signal{Code: signal})
		}
	}
	lane := laneSubject(behavior.Subjects)
	observe(lane, "token", float64(behavior.Actual.Combined), "TOKEN_VELOCITY_OVER_4X_BASELINE", "TOKEN_VELOCITY_OVER_10X_BASELINE", 0)
	observe(behavior.Subjects.CredentialID, "cost", float64(behavior.Actual.Cost), "COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR", "", absoluteCostFloorMicrounits)
	p.stateMu.Lock()
	p.stateErr = observedErr
	p.stateMu.Unlock()
	return signals
}

func (p *ResourceVelocityProducer) PersistenceError() error {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.stateErr
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
