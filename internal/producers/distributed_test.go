package producers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/adaptive"
)

type sharedAdaptiveStore struct {
	mu        sync.Mutex
	windows   map[string]map[string]struct{}
	baselines map[string]adaptiveBaseline
}

type adaptiveBaseline struct {
	ema   float64
	count int
}

func (s *sharedAdaptiveStore) ObserveWindow(_ context.Context, obs adaptive.WindowObservation) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.windows == nil {
		s.windows = make(map[string]map[string]struct{})
	}
	key := obs.Detector + "\x00" + obs.Subject
	if s.windows[key] == nil {
		s.windows[key] = make(map[string]struct{})
	}
	_, existed := s.windows[key][obs.Key]
	s.windows[key][obs.Key] = struct{}{}
	return !existed && len(s.windows[key]) > obs.Threshold, nil
}

func (s *sharedAdaptiveStore) ObserveBaseline(_ context.Context, obs adaptive.BaselineObservation) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.baselines == nil {
		s.baselines = make(map[string]adaptiveBaseline)
	}
	key := obs.Detector + "\x00" + obs.Subject + "\x00" + obs.Metric
	b := s.baselines[key]
	b.count++
	signal := ""
	if b.count >= 3 && b.ema > 0 {
		if obs.Code10 != "" && obs.Value >= b.ema*obs.Threshold10 {
			signal = obs.Code10
		} else if obs.Code4 != "" && obs.Value >= b.ema*obs.Threshold4 {
			signal = obs.Code4
		}
	}
	if b.count == 1 {
		b.ema = obs.Value
	} else if !obs.ConcurrencyRamp || b.ema == 0 || obs.Value < b.ema*2 {
		b.ema = obs.Alpha*obs.Value + (1-obs.Alpha)*b.ema
	}
	s.baselines[key] = b
	return signal, nil
}

func TestDistributedSourceNoveltyAggregatesAcrossNodes(t *testing.T) {
	store := &sharedAdaptiveStore{}
	nodeA := NewDistributedSourceNoveltyProducer(time.Now, store)
	nodeB := NewDistributedSourceNoveltyProducer(time.Now, store)
	base := AdmissionBehavior{Subjects: SubjectContext{CredentialID: "cred-1"}}
	if got := nodeA.ObserveAdmissionContext(context.Background(), func() AdmissionBehavior {
		base.Subjects.SourceID = "source-a"
		return base
	}()); len(got) != 0 {
		t.Fatalf("first source observation emitted %v", got)
	}
	base.Subjects.SourceID = "source-b"
	got := nodeB.ObserveAdmissionContext(context.Background(), base)
	if len(got) != 1 || got[0].Code != "NEW_SOURCE" {
		t.Fatalf("second node did not observe the shared novelty window: %v", got)
	}
}

func TestDistributedVelocityAggregatesAcrossNodes(t *testing.T) {
	store := &sharedAdaptiveStore{}
	nodeA := NewDistributedResourceVelocityProducer(time.Now, store)
	nodeB := NewDistributedResourceVelocityProducer(time.Now, store)
	subjects := SubjectContext{CredentialID: "cred-1", LaneID: "lane-1"}
	for i := 0; i < 3; i++ {
		producer := nodeA
		if i%2 == 1 {
			producer = nodeB
		}
		if got := producer.ObserveCompletionContext(context.Background(), CompletionBehavior{
			Subjects: subjects, Actual: UsageEstimate{Combined: 100}, Success: true,
		}); len(got) != 0 {
			t.Fatalf("baseline observation %d emitted %v", i, got)
		}
	}
	got := nodeB.ObserveCompletionContext(context.Background(), CompletionBehavior{
		Subjects: subjects, Actual: UsageEstimate{Combined: 1_000}, Success: true,
	})
	if len(got) != 1 || got[0].Code != "TOKEN_VELOCITY_OVER_10X_BASELINE" {
		t.Fatalf("fourth cross-node observation did not cross shared baseline: %v", got)
	}
}
