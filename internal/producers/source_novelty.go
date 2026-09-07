package producers

import (
	"sync"
	"time"
)

// SourceNoveltyProducer detects source-discontinuity novelty: a credential
// appearing from a new ASN, hosting ASN, or region class. It tracks the
// distinct ASNs/regions seen per credential within a sliding window and emits
// a signal when a new one is observed after the baseline set is established.
type SourceNoveltyProducer struct {
	mu          sync.Mutex
	now         func() time.Time
	window      time.Duration
	cooldown    time.Duration
	maxSubjects int

	// credASN tracks distinct ASNs per credential.
	credASN map[string]*windowKey
	// credRegion tracks distinct regions per credential.
	credRegion map[string]*windowKey
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
	}
}

// ObserveAdmission records one request's source behavior and returns any novelty signals.
func (p *SourceNoveltyProducer) ObserveAdmission(behavior AdmissionBehavior) []Signal {
	if behavior.Subjects.CredentialID == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	var signals []Signal
	subject := behavior.Subjects.CredentialID

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

// ObserveCompletion is a no-op for source novelty (admission-time only).
func (p *SourceNoveltyProducer) ObserveCompletion(behavior CompletionBehavior) []Signal {
	return nil
}
