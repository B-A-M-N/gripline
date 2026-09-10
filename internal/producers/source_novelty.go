package producers

import (
	"context"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/adaptive"
)

// SourceNoveltyProducer detects source-discontinuity novelty: a credential
// appearing from a new keyed source pseudonym, ASN, hosting ASN, or region
// class. The source pseudonym is useful even when no ASN database is deployed;
// it is a continuity signal, not proof that a source is malicious.
type SourceNoveltyProducer struct {
	mu          sync.Mutex
	now         func() time.Time
	window      time.Duration
	cooldown    time.Duration
	maxSubjects int
	distributed adaptive.Store
	windowGate  distributedObservationGate
	stateMu     sync.Mutex
	stateErr    error

	// credASN tracks distinct ASNs per credential.
	credASN map[string]*windowKey
	// credRegion tracks distinct regions per credential.
	credRegion map[string]*windowKey
	// credSource tracks keyed source pseudonyms per credential.
	credSource map[string]*windowKey
}

// NewDistributedSourceNoveltyProducer uses keyed authority rows instead of a
// process-local snapshot. The local maps remain initialized for compatibility,
// but are not consulted when distributed is set.
func NewDistributedSourceNoveltyProducer(now func() time.Time, store adaptive.Store) *SourceNoveltyProducer {
	p := NewSourceNoveltyProducer(now)
	p.distributed = store
	return p
}

// NewSourceNoveltyProducer builds a SourceNoveltyProducer.
func NewSourceNoveltyProducer(now func() time.Time) *SourceNoveltyProducer {
	if now == nil {
		now = time.Now
	}
	return &SourceNoveltyProducer{
		now:         now,
		window:      10 * time.Minute,
		cooldown:    defaultCooldown,
		maxSubjects: defaultMaxSubjects,
		credASN:     make(map[string]*windowKey),
		credRegion:  make(map[string]*windowKey),
		credSource:  make(map[string]*windowKey),
	}
}

// ObserveAdmission records one request's source behavior and returns any novelty signals.
func (p *SourceNoveltyProducer) ObserveAdmission(behavior AdmissionBehavior) []Signal {
	return p.ObserveAdmissionContext(context.Background(), behavior)
}

func (p *SourceNoveltyProducer) ObserveAdmissionContext(ctx context.Context, behavior AdmissionBehavior) []Signal {
	if p.distributed != nil {
		return p.observeAdmissionDistributed(ctx, behavior)
	}
	return p.observeAdmissionLocal(behavior)
}

func (p *SourceNoveltyProducer) observeAdmissionLocal(behavior AdmissionBehavior) []Signal {
	if behavior.Subjects.CredentialID == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	var signals []Signal
	subject := behavior.Subjects.CredentialID

	if behavior.Subjects.SourceID != "" {
		if observeWindow(p.credSource, subject, behavior.Subjects.SourceID, 1, p.window, p.cooldown, now, p.maxSubjects) {
			signals = append(signals, Signal{Code: "NEW_SOURCE"})
		}
	}

	if behavior.Features.NetworkASN != "" {
		if observeWindow(p.credASN, subject, behavior.Features.NetworkASN, 1, p.window, p.cooldown, now, p.maxSubjects) {
			signals = append(signals, Signal{Code: "NEW_ASN"})
		}
	}

	if behavior.Features.NetworkASN != "" && behavior.Features.NetworkType == "hosting" {
		if observeWindow(p.credASN, subject+":hosting", behavior.Features.NetworkASN, 1, p.window, p.cooldown, now, p.maxSubjects) {
			signals = append(signals, Signal{Code: "NEW_HOSTING_ASN"})
		}
	}

	if behavior.Features.RegionClass != "" {
		if observeWindow(p.credRegion, subject, behavior.Features.RegionClass, 1, p.window, p.cooldown, now, p.maxSubjects) {
			signals = append(signals, Signal{Code: "NEW_COUNTRY"})
		}
	}

	return signals
}

func (p *SourceNoveltyProducer) observeAdmissionDistributed(ctx context.Context, behavior AdmissionBehavior) []Signal {
	if behavior.Subjects.CredentialID == "" {
		return nil
	}
	subject := behavior.Subjects.CredentialID
	now := p.now()
	var signals []Signal
	var observedErr error
	observe := func(detector, key string, threshold int, code string) {
		if key == "" {
			return
		}
		if !p.windowGate.allow(detector, subject, key, now) {
			return
		}
		emitted, err := p.distributed.ObserveWindow(ctx, adaptive.WindowObservation{
			Detector: detector, Subject: subject, Key: key, Threshold: threshold,
			Window: p.window, Cooldown: p.cooldown, MaxSubjects: p.maxSubjects, MaxKeys: 256,
		})
		if err != nil {
			observedErr = err
			return
		}
		if emitted {
			signals = append(signals, Signal{Code: code})
		}
	}
	observe("source_novelty_source", behavior.Subjects.SourceID, 1, "NEW_SOURCE")
	observe("source_novelty_asn", behavior.Features.NetworkASN, 1, "NEW_ASN")
	if behavior.Features.NetworkASN != "" && behavior.Features.NetworkType == "hosting" {
		observe("source_novelty_hosting_asn", behavior.Features.NetworkASN, 1, "NEW_HOSTING_ASN")
	}
	observe("source_novelty_region", behavior.Features.RegionClass, 1, "NEW_COUNTRY")
	p.stateMu.Lock()
	p.stateErr = observedErr
	p.stateMu.Unlock()
	return signals
}

// ObserveCompletion is a no-op for source novelty (admission-time only).
func (p *SourceNoveltyProducer) ObserveCompletion(behavior CompletionBehavior) []Signal {
	return nil
}

func (p *SourceNoveltyProducer) ObserveCompletionContext(context.Context, CompletionBehavior) []Signal {
	return nil
}

func (p *SourceNoveltyProducer) PersistenceError() error {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.stateErr
}

// RecoverPersistence clears a transient distributed-observation error after
// the shared authority has become healthy again. Without this probe, a node
// that records one database outage remains unready forever: its load balancer
// removes it before another admission can retry the observation.
func (p *SourceNoveltyProducer) RecoverPersistence(ctx context.Context) error {
	err := recoverAdaptivePersistence(ctx, p.distributed)
	p.stateMu.Lock()
	p.stateErr = err
	p.stateMu.Unlock()
	return err
}

func recoverAdaptivePersistence(ctx context.Context, store adaptive.Store) error {
	if store == nil {
		return nil
	}
	if ready, ok := store.(interface{ Ready(context.Context) error }); ok {
		return ready.Ready(ctx)
	}
	return nil
}
