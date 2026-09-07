package producers

import (
	"testing"
	"time"
)

func TestSourceNoveltyProducerEmitsNewASN(t *testing.T) {
	base := time.Now()
	p := NewSourceNoveltyProducer(func() time.Time { return base })

	beh := AdmissionBehavior{
		Subjects: SubjectContext{CredentialID: "cred_1"},
		Features: Features{NetworkASN: "AS100", NetworkType: "residential"},
	}

	// First observation: no signal (establishing baseline).
	sigs := p.ObserveAdmission(beh)
	if len(sigs) != 0 {
		t.Fatalf("first observation should not emit, got %v", sigs)
	}

	// Second observation with different ASN: NEW_ASN signal.
	beh.Features.NetworkASN = "AS200"
	sigs = p.ObserveAdmission(beh)
	if len(sigs) != 1 || sigs[0].Code != "NEW_ASN" {
		t.Fatalf("expected NEW_ASN signal, got %v", sigs)
	}
}

func TestSourceNoveltyProducerHostingASN(t *testing.T) {
	base := time.Now()
	p := NewSourceNoveltyProducer(func() time.Time { return base })

	beh := AdmissionBehavior{
		Subjects: SubjectContext{CredentialID: "cred_1"},
		Features: Features{NetworkASN: "AS5000", NetworkType: "hosting"},
	}

	sigs := p.ObserveAdmission(beh)
	if len(sigs) != 0 {
		t.Fatalf("first observation should not emit, got %v", sigs)
	}

	beh.Features.NetworkASN = "AS6000"
	sigs = p.ObserveAdmission(beh)
	haveNewASN := false
	haveHosting := false
	for _, s := range sigs {
		if s.Code == "NEW_ASN" {
			haveNewASN = true
		}
		if s.Code == "NEW_HOSTING_ASN" {
			haveHosting = true
		}
	}
	if !haveNewASN || !haveHosting {
		t.Fatalf("expected NEW_ASN and NEW_HOSTING_ASN, got %v", sigs)
	}
}

func TestResourceVelocityProducerOver10x(t *testing.T) {
	base := time.Now()
	p := NewResourceVelocityProducer(func() time.Time { return base })

	// Establish baseline: 5 observations at concurrency=2.
	for i := 0; i < 5; i++ {
		p.ObserveAdmission(AdmissionBehavior{
			Subjects:    SubjectContext{CredentialID: "cred_1"},
			Concurrency: 2,
		})
	}

	// Spike to 25 (12.5x baseline): should emit CONCURRENCY_OVER_10X_BASELINE.
	sigs := p.ObserveAdmission(AdmissionBehavior{
		Subjects:    SubjectContext{CredentialID: "cred_1"},
		Concurrency: 25,
	})
	if len(sigs) != 1 || sigs[0].Code != "CONCURRENCY_OVER_10X_BASELINE" {
		t.Fatalf("expected CONCURRENCY_OVER_10X_BASELINE, got %v", sigs)
	}
}

func TestResourceVelocityProducerTokenVelocity(t *testing.T) {
	base := time.Now()
	p := NewResourceVelocityProducer(func() time.Time { return base })

	// Establish baseline: 5 completions at 100 tokens.
	for i := 0; i < 5; i++ {
		p.ObserveCompletion(CompletionBehavior{
			Subjects: SubjectContext{CredentialID: "cred_1"},
			Actual:   UsageEstimate{Combined: 100},
		})
	}

	// Spike to 1000 tokens (10x).
	sigs := p.ObserveCompletion(CompletionBehavior{
		Subjects: SubjectContext{CredentialID: "cred_1"},
		Actual:   UsageEstimate{Combined: 1000},
	})
	if len(sigs) != 1 || sigs[0].Code != "TOKEN_VELOCITY_OVER_10X_BASELINE" {
		t.Fatalf("expected TOKEN_VELOCITY_OVER_10X_BASELINE, got %v", sigs)
	}
}

// TestResourceVelocityProducerLaneIsolation proves the #11 scope fix: an
// abusive lane's spike must NOT inflate the baseline another lane is judged
// against. Each lane keys its own concurrency/token baseline.
func TestResourceVelocityProducerLaneIsolation(t *testing.T) {
	base := time.Now()
	p := NewResourceVelocityProducer(func() time.Time { return base })

	// Two lanes under the SAME credential. Establish a high-noise baseline on
	// lane_a only.
	for i := 0; i < 6; i++ {
		p.ObserveAdmission(AdmissionBehavior{
			Subjects:    SubjectContext{CredentialID: "cred_1", LaneID: "lane_a"},
			Concurrency: 50,
		})
	}
	// lane_a is quiet now (low activity). A modest 5-concurrency blip on lane_a
	// must NOT be flagged just because lane_a's baseline is 50 (it would be a
	// DECREASE). Set lane_a's norm high and confirm no false 4x.
	sigs := p.ObserveAdmission(AdmissionBehavior{
		Subjects:    SubjectContext{CredentialID: "cred_1", LaneID: "lane_a"},
		Concurrency: 5,
	})
	if len(sigs) != 0 {
		t.Fatalf("lane_a below its own baseline must not emit, got %v", sigs)
	}

	// Now a fresh lane_b with its own low baseline: a 50-concurrency spike is
	// 10x ITS OWN norm and must fire, INDEPENDENT of lane_a's inflated 50-norm.
	for i := 0; i < 4; i++ {
		p.ObserveAdmission(AdmissionBehavior{
			Subjects:    SubjectContext{CredentialID: "cred_1", LaneID: "lane_b"},
			Concurrency: 2,
		})
	}
	sigs = p.ObserveAdmission(AdmissionBehavior{
		Subjects:    SubjectContext{CredentialID: "cred_1", LaneID: "lane_b"},
		Concurrency: 25,
	})
	found := false
	for _, s := range sigs {
		if s.Code == "CONCURRENCY_OVER_10X_BASELINE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("lane_b low-norm spike must be flagged despite lane_a's high norm; got %v", sigs)
	}
}

// TestResourceVelocityProducerCostAbsoluteFloor proves the #11 fix: the
// COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR evidence name claims an
// absolute floor, and the detector must implement it. A sub-floor spend that is
// nonetheless 4x the baseline must NOT emit.
func TestResourceVelocityProducerCostAbsoluteFloor(t *testing.T) {
	base := time.Now()
	p := NewResourceVelocityProducer(func() time.Time { return base })

	// Establish a near-zero cost baseline (3 prior observations at 1 micro-unit).
	for i := 0; i < 4; i++ {
		p.ObserveCompletion(CompletionBehavior{
			Subjects: SubjectContext{CredentialID: "cred_1"},
			Actual:   UsageEstimate{Cost: 1},
		})
	}
	// 8 micro-units is 8x the baseline but far below the absolute floor: must NOT
	// emit — the CODE name would be a lie.
	sigs := p.ObserveCompletion(CompletionBehavior{
		Subjects: SubjectContext{CredentialID: "cred_1"},
		Actual:   UsageEstimate{Cost: 8},
	})
	if len(sigs) != 0 {
		t.Fatalf("sub-floor 4x blip must NOT emit COST_VELOCITY (floor not met); got %v", sigs)
	}
}

func TestEnumerationProducerRapidEndpoints(t *testing.T) {
	base := time.Now()
	p := NewEnumerationProducer(func() time.Time { return base })

	endpoints := []string{"/v1/chat", "/v1/embeddings", "/v1/moderations", "/v1/models", "/v1/completions", "/v1/edits"}
	var signals []Signal
	for _, ep := range endpoints {
		s := p.ObserveAdmission(AdmissionBehavior{
			Subjects:       SubjectContext{CredentialID: "cred_1"},
			EndpointFamily: ep,
		})
		signals = append(signals, s...)
	}

	found := false
	for _, s := range signals {
		if s.Code == "RAPID_ENDPOINT_OR_MODEL_ENUMERATION" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected RAPID_ENDPOINT_OR_MODEL_ENUMERATION signal, got %v", signals)
	}
}

func TestProducersAreBounded(t *testing.T) {
	base := time.Now()
	p := NewSourceNoveltyProducer(func() time.Time { return base })

	for i := 0; i < defaultMaxSubjects+100; i++ {
		p.ObserveAdmission(AdmissionBehavior{
			Subjects: SubjectContext{CredentialID: "cred_" + string(rune('A'+i%26)) + string(rune('0'+i/26))},
			Features: Features{NetworkASN: "AS" + string(rune(i))},
		})
	}

	p.mu.Lock()
	count := len(p.credASN)
	p.mu.Unlock()
	if count > defaultMaxSubjects+10 {
		t.Fatalf("producer state grew unbounded: %d subjects (cap %d)", count, defaultMaxSubjects)
	}
}
