package producers

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// StateStore is the narrow persistence seam for bounded detector checkpoints.
// The durable state authority owns the transaction; producers only serialize
// their bounded observations.
type StateStore interface {
	LoadDetectorState(name string) ([]byte, bool, error)
	SaveDetectorState(name string, data []byte) error
}

// StateSnapshotter is implemented by stateful producers.
type StateSnapshotter interface {
	SnapshotState() ([]byte, error)
	RestoreState([]byte) error
}

const producerStateVersion = 1

type windowState struct {
	Keys     map[string]time.Time `json:"keys"`
	LastSeen time.Time            `json:"last_seen"`
	LastEmit time.Time            `json:"last_emit"`
}

func snapshotWindows(src map[string]*windowKey) map[string]windowState {
	out := make(map[string]windowState, len(src))
	for subject, state := range src {
		keys := make(map[string]time.Time, len(state.keys))
		for key, at := range state.keys {
			keys[key] = at
		}
		out[subject] = windowState{Keys: keys, LastSeen: state.lastSeen, LastEmit: state.lastEmit}
	}
	return out
}

func restoreWindows(dst map[string]*windowKey, src map[string]windowState) error {
	if len(src) > defaultMaxSubjects {
		return errors.New("producers: snapshot exceeds subject bound")
	}
	for subject, state := range src {
		if len(state.Keys) > defaultMaxSubjects {
			return fmt.Errorf("producers: snapshot subject %q exceeds key bound", subject)
		}
		keys := make(map[string]time.Time, len(state.Keys))
		for key, at := range state.Keys {
			keys[key] = at
		}
		dst[subject] = &windowKey{keys: keys, lastSeen: state.LastSeen, lastEmit: state.LastEmit}
	}
	return nil
}

type sourceNoveltyState struct {
	Version int                    `json:"version"`
	ASN     map[string]windowState `json:"asn"`
	Region  map[string]windowState `json:"region"`
	Source  map[string]windowState `json:"source"`
}

func (p *SourceNoveltyProducer) SnapshotState() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return json.Marshal(sourceNoveltyState{Version: producerStateVersion, ASN: snapshotWindows(p.credASN), Region: snapshotWindows(p.credRegion), Source: snapshotWindows(p.credSource)})
}

func (p *SourceNoveltyProducer) RestoreState(data []byte) error {
	var state sourceNoveltyState
	if err := json.Unmarshal(data, &state); err != nil || state.Version != producerStateVersion {
		return errors.New("producers: invalid source novelty snapshot")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := restoreWindows(p.credASN, state.ASN); err != nil {
		return err
	}
	if err := restoreWindows(p.credRegion, state.Region); err != nil {
		return err
	}
	return restoreWindows(p.credSource, state.Source)
}

type enumerationState struct {
	Version  int                    `json:"version"`
	Endpoint map[string]windowState `json:"endpoint"`
}

func (p *EnumerationProducer) SnapshotState() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return json.Marshal(enumerationState{Version: producerStateVersion, Endpoint: snapshotWindows(p.credEndpoint)})
}

func (p *EnumerationProducer) RestoreState(data []byte) error {
	var state enumerationState
	if err := json.Unmarshal(data, &state); err != nil || state.Version != producerStateVersion {
		return errors.New("producers: invalid enumeration snapshot")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return restoreWindows(p.credEndpoint, state.Endpoint)
}

type baselineState struct {
	EMA      float64   `json:"ema"`
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
	LastEmit time.Time `json:"last_emit"`
}

func snapshotBaselines(src map[string]*baseline) map[string]baselineState {
	out := make(map[string]baselineState, len(src))
	for key, state := range src {
		out[key] = baselineState{EMA: state.ema, Count: state.count, LastSeen: state.lastSeen, LastEmit: state.lastEmit}
	}
	return out
}

func restoreBaselines(dst map[string]*baseline, src map[string]baselineState) error {
	if len(src) > defaultMaxSubjects {
		return errors.New("producers: snapshot exceeds baseline bound")
	}
	for key, state := range src {
		if state.EMA < 0 || state.Count < 0 {
			return fmt.Errorf("producers: invalid baseline %q", key)
		}
		dst[key] = &baseline{ema: state.EMA, count: state.Count, lastSeen: state.LastSeen, lastEmit: state.LastEmit}
	}
	return nil
}

type velocityState struct {
	Version     int                      `json:"version"`
	Concurrency map[string]baselineState `json:"concurrency"`
	Token       map[string]baselineState `json:"token"`
	Cost        map[string]baselineState `json:"cost"`
}

func (p *ResourceVelocityProducer) SnapshotState() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return json.Marshal(velocityState{Version: producerStateVersion, Concurrency: snapshotBaselines(p.concurrencyBaseline), Token: snapshotBaselines(p.tokenBaseline), Cost: snapshotBaselines(p.costBaseline)})
}

func (p *ResourceVelocityProducer) RestoreState(data []byte) error {
	var state velocityState
	if err := json.Unmarshal(data, &state); err != nil || state.Version != producerStateVersion {
		return errors.New("producers: invalid velocity snapshot")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := restoreBaselines(p.concurrencyBaseline, state.Concurrency); err != nil {
		return err
	}
	if err := restoreBaselines(p.tokenBaseline, state.Token); err != nil {
		return err
	}
	return restoreBaselines(p.costBaseline, state.Cost)
}

// PersistentProducer restores a producer at startup and checkpoints its
// bounded state after each observation. Checkpoint failure is retained for
// operational reporting but never turns an already-authorized request into a
// different authorization result.
type PersistentProducer struct {
	producer Producer
	snapshot StateSnapshotter
	store    StateStore
	name     string
	mu       sync.Mutex
	err      error
}

func NewPersistentProducer(producer Producer, snapshot StateSnapshotter, store StateStore, name string) (*PersistentProducer, error) {
	if producer == nil || snapshot == nil || store == nil || name == "" {
		return nil, errors.New("producers: persistent producer requires producer, snapshot, store, and name")
	}
	data, found, err := store.LoadDetectorState(name)
	if err != nil {
		return nil, fmt.Errorf("producers: load %s: %w", name, err)
	}
	if found {
		if err := snapshot.RestoreState(data); err != nil {
			return nil, fmt.Errorf("producers: restore %s: %w", name, err)
		}
	}
	return &PersistentProducer{producer: producer, snapshot: snapshot, store: store, name: name}, nil
}

func (p *PersistentProducer) ObserveAdmission(b AdmissionBehavior) []Signal {
	out := p.producer.ObserveAdmission(b)
	p.persist()
	return out
}

func (p *PersistentProducer) ObserveCompletion(b CompletionBehavior) []Signal {
	out := p.producer.ObserveCompletion(b)
	p.persist()
	return out
}

func (p *PersistentProducer) persist() {
	data, err := p.snapshot.SnapshotState()
	if err == nil {
		err = p.store.SaveDetectorState(p.name, data)
	}
	if err != nil {
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
	}
}

// PersistenceError returns the latest checkpoint error, if any.
func (p *PersistentProducer) PersistenceError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}
