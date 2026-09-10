package producers

import (
	"context"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/adaptive"
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
	distributed adaptive.Store
	windowGate  distributedObservationGate
	stateMu     sync.Mutex
	stateErr    error

	credEndpoint map[string]*windowKey
}

// NewDistributedEnumerationProducer uses a keyed PostgreSQL window rather
// than a process-local snapshot.
func NewDistributedEnumerationProducer(now func() time.Time, store adaptive.Store) *EnumerationProducer {
	p := NewEnumerationProducer(now)
	p.distributed = store
	return p
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
	return p.ObserveAdmissionContext(context.Background(), behavior)
}

func (p *EnumerationProducer) ObserveAdmissionContext(ctx context.Context, behavior AdmissionBehavior) []Signal {
	if p.distributed != nil {
		if behavior.Subjects.CredentialID == "" || behavior.EndpointFamily == "" {
			return nil
		}
		if !p.windowGate.allow("enumeration", behavior.Subjects.CredentialID, behavior.EndpointFamily, p.now()) {
			return nil
		}
		emitted, err := p.distributed.ObserveWindow(ctx, adaptive.WindowObservation{
			Detector: "enumeration", Subject: behavior.Subjects.CredentialID,
			Key: behavior.EndpointFamily, Threshold: p.threshold, Window: p.window,
			Cooldown: p.cooldown, MaxSubjects: p.maxSubjects, MaxKeys: 256,
		})
		p.stateMu.Lock()
		p.stateErr = err
		p.stateMu.Unlock()
		if err != nil {
			return nil
		}
		if emitted {
			return []Signal{{Code: "RAPID_ENDPOINT_OR_MODEL_ENUMERATION"}}
		}
		return nil
	}
	return p.observeAdmissionLocal(behavior)
}

func (p *EnumerationProducer) observeAdmissionLocal(behavior AdmissionBehavior) []Signal {
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

func (p *EnumerationProducer) ObserveCompletionContext(context.Context, CompletionBehavior) []Signal {
	return nil
}

func (p *EnumerationProducer) PersistenceError() error {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.stateErr
}

// RecoverPersistence clears a transient distributed-observation error after
// the shared authority has become healthy again. See SourceNoveltyProducer's
// recovery probe for why readiness must be able to perform this check.
func (p *EnumerationProducer) RecoverPersistence(ctx context.Context) error {
	err := recoverAdaptivePersistence(ctx, p.distributed)
	p.stateMu.Lock()
	p.stateErr = err
	p.stateMu.Unlock()
	return err
}
