package producers

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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

const detectorCheckpointInterval = 500 * time.Millisecond

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
// bounded state asynchronously. Observations only mutate the in-memory bounded
// detector and mark it dirty; the periodic worker coalesces many observations
// into one serialized state snapshot and one durable transaction. A threshold
// crossing forces an immediate checkpoint so newly detected abuse is not left
// solely in memory. Checkpoint failure is retained for operational reporting
// and retried by later flushes.
type PersistentProducer struct {
	producer  Producer
	snapshot  StateSnapshotter
	store     StateStore
	name      string
	mu        sync.Mutex // protects err
	err       error
	dirty     atomic.Bool
	flushMu   sync.Mutex
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
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
	p := &PersistentProducer{
		producer: producer,
		snapshot: snapshot,
		store:    store,
		name:     name,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go p.checkpointLoop()
	return p, nil
}

func (p *PersistentProducer) ObserveAdmission(b AdmissionBehavior) []Signal {
	out := p.producer.ObserveAdmission(b)
	p.markDirty()
	if len(out) > 0 {
		_ = p.Flush()
	}
	return out
}

func (p *PersistentProducer) ObserveCompletion(b CompletionBehavior) []Signal {
	out := p.producer.ObserveCompletion(b)
	p.markDirty()
	if len(out) > 0 {
		_ = p.Flush()
	}
	return out
}

func (p *PersistentProducer) markDirty() {
	p.dirty.Store(true)
}

func (p *PersistentProducer) checkpointLoop() {
	ticker := time.NewTicker(detectorCheckpointInterval)
	defer ticker.Stop()
	defer close(p.done)
	for {
		select {
		case <-ticker.C:
			_ = p.Flush()
		case <-p.stop:
			return
		}
	}
}

// Flush checkpoints dirty state synchronously. It is intended for threshold
// crossings, graceful shutdown, and tests that need a restart boundary.
func (p *PersistentProducer) Flush() error {
	if p == nil {
		return errors.New("producers: nil persistent producer")
	}
	p.flushMu.Lock()
	defer p.flushMu.Unlock()
	if !p.dirty.Swap(false) {
		return p.PersistenceError()
	}
	data, err := p.snapshot.SnapshotState()
	if err == nil {
		err = p.store.SaveDetectorState(p.name, data)
	}
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
	if err != nil {
		p.dirty.Store(true)
	}
	return err
}

// Close stops the checkpoint worker and performs one final synchronous flush.
func (p *PersistentProducer) Close() error {
	if p == nil {
		return nil
	}
	var err error
	p.closeOnce.Do(func() {
		close(p.stop)
		<-p.done
		err = p.Flush()
	})
	return err
}

// PersistenceError returns the latest checkpoint error, if any.
func (p *PersistentProducer) PersistenceError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}
