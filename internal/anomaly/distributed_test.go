package anomaly

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/adaptive"
)

type sharedWindowStore struct {
	mu  sync.Mutex
	set map[string]map[string]struct{}
}

func (s *sharedWindowStore) ObserveWindow(_ context.Context, obs adaptive.WindowObservation) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set == nil {
		s.set = make(map[string]map[string]struct{})
	}
	key := obs.Detector + "\x00" + obs.Subject
	if s.set[key] == nil {
		s.set[key] = make(map[string]struct{})
	}
	_, existed := s.set[key][obs.Key]
	s.set[key][obs.Key] = struct{}{}
	return !existed && len(s.set[key]) > obs.Threshold, nil
}

func (s *sharedWindowStore) ObserveBaseline(context.Context, adaptive.BaselineObservation) (string, error) {
	return "", nil
}

func TestDistributedSprayAggregatesAcrossNodes(t *testing.T) {
	store := &sharedWindowStore{}
	nodeA := NewDistributedDetector(nil, DefaultThresholds(), store)
	nodeB := NewDistributedDetector(nil, DefaultThresholds(), store)
	for i := 0; i < 4; i++ {
		producer := nodeA
		if i%2 == 1 {
			producer = nodeB
		}
		if got := producer.ObserveContext(context.Background(), "source-1", "credential-"+string(rune('a'+i)), "AS1", time.Time{}); len(got) != 0 {
			t.Fatalf("spray baseline observation %d emitted %v", i, got)
		}
	}
	got := nodeB.ObserveContext(context.Background(), "source-1", "credential-e", "AS1", time.Time{})
	if len(got) != 1 || got[0].Code != "SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS" {
		t.Fatalf("fifth cross-node credential did not cross shared spray window: %v", got)
	}
}
