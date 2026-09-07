package producers

import (
	"sync"
	"time"
)

// EnumerationProducer detects rapid endpoint/model enumeration: a client
// hitting many distinct endpoint or model families in a short window,
// indicating reconnaissance or model-extraction behavior.
type EnumerationProducer struct {
	mu          sync.Mutex
	now         func() time.Time
	window      time.Duration
	cooldown    time.Duration
	maxSubjects int
	threshold   int // distinct endpoints before signal

	credEndpoint map[string]*windowKey
}

// NewEnumerationProducer builds an EnumerationProducer.
func NewEnumerationProducer(now func() time.Time) *EnumerationProducer {
	if now == nil {
		now = time.Now
	}
	return &EnumerationProducer{
		now:          now,
		window:       5 * time.Minute,
		cooldown:     defaultCooldown,
		maxSubjects:  defaultMaxSubjects,
		threshold:    5,
		credEndpoint: make(map[string]*windowKey),
	}
}

// ObserveAdmission records one request's endpoint behavior and returns an enumeration
// signal when the distinct-endpoint threshold is crossed.
func (p *EnumerationProducer) ObserveAdmission(behavior AdmissionBehavior) []Signal {
	if behavior.Subjects.CredentialID == "" || behavior.EndpointFamily == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if observeWindow(p.credEndpoint, behavior.Subjects.CredentialID, behavior.EndpointFamily, p.threshold, p.window, p.cooldown, p.now(), p.maxSubjects) {
		return []Signal{{Code: "RAPID_ENDPOINT_OR_MODEL_ENUMERATION"}}
	}
	return nil
}

// ObserveCompletion is a no-op for enumeration (admission-time only).
func (p *EnumerationProducer) ObserveCompletion(behavior CompletionBehavior) []Signal {
	return nil
}
