package producers

import (
	"testing"
	"time"
)

// TestResourceVelocityProducerLearnsSubFloorBaseline proves the P0.10-fix: the
// absolute cost floor gates EMISSION, never baseline LEARNING. A subject whose
// normal spend sits below the floor establishes a low-cost baseline; a later
// spend that is both >4x that norm AND above the floor must fire. Under the
// old behavior the sub-floor observations never seeded the baseline, so the
// spike became "baseline observation #1" and the detector missed exactly the
// attack it exists for.
func TestResourceVelocityProducerLearnsSubFloorBaseline(t *testing.T) {
	base := time.Now()
	p := NewResourceVelocityProducer(func() time.Time { return base })

	// Establish the norm below the absolute floor: 4 observations at 1,000
	// microunits ($0.001) — well under the 50,000 floor.
	for i := 0; i < 4; i++ {
		sigs := p.ObserveCompletion(CompletionBehavior{
			Subjects: SubjectContext{CredentialID: "cred_low"},
			Actual:   UsageEstimate{Cost: 1_000},
			Success:  true,
		})
		if len(sigs) != 0 {
			t.Fatalf("normal sub-floor cost %d must not emit: %v", i, sigs)
		}
	}

	// Spike: 1,000,000 microunits ($1.00) = 1000x the established norm and far
	// above the absolute floor. MUST fire.
	sigs := p.ObserveCompletion(CompletionBehavior{
		Subjects: SubjectContext{CredentialID: "cred_low"},
		Actual:   UsageEstimate{Cost: 1_000_000},
		Success:  true,
	})
	if len(sigs) == 0 || sigs[0].Code != "COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR" {
		t.Fatalf("spike over learned low-cost norm must fire COST_VELOCITY; got %v", sigs)
	}
}

func TestResourceVelocityConcurrencyRampDoesNotNormalizeBurst(t *testing.T) {
	base := time.Now()
	p := NewResourceVelocityProducer(func() time.Time { return base })
	const subject = "cred_ramp"
	for i := 0; i < 3; i++ {
		p.ObserveAdmission(AdmissionBehavior{Subjects: SubjectContext{CredentialID: subject}, Concurrency: 1})
	}
	// A real in-flight burst is observed as a ramp because each admission sees
	// the reservations that won the race before it. Elevated values must not
	// rewrite the normal baseline before the ramp reaches the 4x rule.
	for _, concurrency := range []int{1, 2, 3} {
		if sigs := p.ObserveAdmission(AdmissionBehavior{Subjects: SubjectContext{CredentialID: subject}, Concurrency: concurrency}); len(sigs) != 0 {
			t.Fatalf("ramp value %d emitted early: %v", concurrency, sigs)
		}
	}
	sigs := p.ObserveAdmission(AdmissionBehavior{Subjects: SubjectContext{CredentialID: subject}, Concurrency: 4})
	if len(sigs) != 1 || sigs[0].Code != "CONCURRENCY_OVER_4X_BASELINE" {
		t.Fatalf("ramp must expose 4x concurrency signal, got %v", sigs)
	}
}

// TestResourceVelocityProducerFloorStillGatesEmission keeps the original
// guarantee: a sub-floor spike (4x the baseline but tiny in absolute terms)
// must NOT emit — both predicates in the evidence name must hold.
func TestResourceVelocityProducerFloorStillGatesEmission(t *testing.T) {
	base := time.Now()
	p := NewResourceVelocityProducer(func() time.Time { return base })

	for i := 0; i < 4; i++ {
		p.ObserveCompletion(CompletionBehavior{
			Subjects: SubjectContext{CredentialID: "cred_floor"},
			Actual:   UsageEstimate{Cost: 1_000},
			Success:  true,
		})
	}
	// 8x the norm but below the floor: no emission.
	sigs := p.ObserveCompletion(CompletionBehavior{
		Subjects: SubjectContext{CredentialID: "cred_floor"},
		Actual:   UsageEstimate{Cost: 8_000},
		Success:  true,
	})
	if len(sigs) != 0 {
		t.Fatalf("sub-floor 4x blip must not emit; got %v", sigs)
	}
}

// TestResourceVelocityProducerSubFloorSpikesDoNotEmitCoastline proves that
// baseline learning from sub-floor values does not weaken the norm: repeated
// sub-floor values never emit, and after the spike the EMA has absorbed it so
// the next normal value stays quiet (cooldown aside, the multiple no longer
// holds).
func TestResourceVelocityProducerSubFloorSpikesDoNotEmitCoastline(t *testing.T) {
	base := time.Now()
	p := NewResourceVelocityProducer(func() time.Time { return base })
	const cred = "cred_coast"

	for i := 0; i < 4; i++ {
		p.ObserveCompletion(CompletionBehavior{
			Subjects: SubjectContext{CredentialID: cred},
			Actual:   UsageEstimate{Cost: 1_000},
			Success:  true,
		})
	}
	// Sub-floor 3x values: quiet, but they DO update the baseline.
	for i := 0; i < 3; i++ {
		sigs := p.ObserveCompletion(CompletionBehavior{
			Subjects: SubjectContext{CredentialID: cred},
			Actual:   UsageEstimate{Cost: 3_000},
			Success:  true,
		})
		if len(sigs) != 0 {
			t.Fatalf("3x sub-floor values must never emit; got %v", sigs)
		}
	}
	// Baseline has drifted up toward ~2,600; 4x of that exceeds the floor, but
	// 4,000 is well under 4x: quiet.
	sigs := p.ObserveCompletion(CompletionBehavior{
		Subjects: SubjectContext{CredentialID: cred},
		Actual:   UsageEstimate{Cost: 4_000},
		Success:  true,
	})
	if len(sigs) != 0 {
		t.Fatalf("within-norm value after drift must not emit; got %v", sigs)
	}
}

func TestResourceVelocityProducerFailedCompletionsDoNotLearnCleanBaseline(t *testing.T) {
	p := NewResourceVelocityProducer(time.Now)
	subjects := SubjectContext{CredentialID: "cred_failed"}
	for i := 0; i < 4; i++ {
		p.ObserveCompletion(CompletionBehavior{
			Subjects: subjects,
			Actual:   UsageEstimate{Combined: 1_000_000, Cost: 1_000_000},
			Success:  false,
		})
	}
	for i := 0; i < 3; i++ {
		p.ObserveCompletion(CompletionBehavior{
			Subjects: subjects,
			Actual:   UsageEstimate{Combined: 100, Cost: 100},
			Success:  true,
		})
	}
	got := p.ObserveCompletion(CompletionBehavior{
		Subjects: subjects,
		Actual:   UsageEstimate{Combined: 1_000, Cost: 1_000},
		Success:  true,
	})
	if len(got) != 1 || got[0].Code != "TOKEN_VELOCITY_OVER_10X_BASELINE" {
		t.Fatalf("failed completions contaminated clean baseline: %v", got)
	}
}
