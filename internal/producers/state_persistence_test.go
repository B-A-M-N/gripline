package producers

import (
	"testing"
	"time"
)

type memoryDetectorStateStore struct {
	data map[string][]byte
}

func (s *memoryDetectorStateStore) LoadDetectorState(name string) ([]byte, bool, error) {
	data, ok := s.data[name]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), data...), true, nil
}

func (s *memoryDetectorStateStore) SaveDetectorState(name string, data []byte) error {
	if s.data == nil {
		s.data = make(map[string][]byte)
	}
	s.data[name] = append([]byte(nil), data...)
	return nil
}

func TestPersistentProducerRestoresVelocityBaselineAcrossRestart(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	store := &memoryDetectorStateStore{}
	subjects := SubjectContext{CredentialID: "credential-1"}

	first := NewResourceVelocityProducer(func() time.Time { return base })
	persistedFirst, err := NewPersistentProducer(first, first, store, "resource_velocity")
	if err != nil {
		t.Fatalf("create first persistent producer: %v", err)
	}
	for i := 0; i < 4; i++ {
		if signals := persistedFirst.ObserveCompletion(CompletionBehavior{
			Subjects: subjects,
			Actual:   UsageEstimate{Combined: 100},
		}); len(signals) != 0 {
			t.Fatalf("baseline observation %d emitted signals: %v", i, signals)
		}
	}

	second := NewResourceVelocityProducer(func() time.Time { return base })
	persistedSecond, err := NewPersistentProducer(second, second, store, "resource_velocity")
	if err != nil {
		t.Fatalf("create restarted persistent producer: %v", err)
	}
	signals := persistedSecond.ObserveCompletion(CompletionBehavior{
		Subjects: subjects,
		Actual:   UsageEstimate{Combined: 1_000},
	})
	if len(signals) != 1 || signals[0].Code != "TOKEN_VELOCITY_OVER_10X_BASELINE" {
		t.Fatalf("restarted producer did not restore baseline: %v", signals)
	}
}
