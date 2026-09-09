package anomaly

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// StateStore is the narrow persistence seam for spray-detector checkpoints.
type StateStore interface {
	LoadDetectorState(name string) ([]byte, bool, error)
	SaveDetectorState(name string, data []byte) error
}

const detectorStateVersion = 1

const detectorCheckpointInterval = 500 * time.Millisecond

type winState struct {
	Keys     map[string]time.Time `json:"keys"`
	LastSeen time.Time            `json:"last_seen"`
	LastEmit map[string]time.Time `json:"last_emit"`
}

type detectorState struct {
	Version    int                 `json:"version"`
	CredASN    map[string]winState `json:"credential_asn"`
	SourceCred map[string]winState `json:"source_credential"`
	Invalid    map[string]winState `json:"source_invalid"`
}

func (d *Detector) snapshotLocked() ([]byte, error) {
	return json.Marshal(detectorState{
		Version: detectorStateVersion, CredASN: snapshotWinSets(d.credAsn),
		SourceCred: snapshotWinSets(d.srcCred), Invalid: snapshotWinSets(d.srcInvalid),
	})
}

func snapshotWinSets(src map[string]*winSet) map[string]winState {
	out := make(map[string]winState, len(src))
	for subject, state := range src {
		keys := make(map[string]time.Time, len(state.keys))
		for key, at := range state.keys {
			keys[key] = at
		}
		emits := make(map[string]time.Time, len(state.lastEmit))
		for code, at := range state.lastEmit {
			emits[code] = at
		}
		out[subject] = winState{Keys: keys, LastSeen: state.lastSeen, LastEmit: emits}
	}
	return out
}

func restoreWinSets(dst map[string]*winSet, src map[string]winState, maxSubjects, maxKeys int) error {
	if len(src) > maxSubjects {
		return errors.New("anomaly: snapshot exceeds subject bound")
	}
	for subject, state := range src {
		if len(state.Keys) > maxKeys {
			return fmt.Errorf("anomaly: snapshot subject %q exceeds key bound", subject)
		}
		keys := make(map[string]time.Time, len(state.Keys))
		for key, at := range state.Keys {
			keys[key] = at
		}
		emits := make(map[string]time.Time, len(state.LastEmit))
		for code, at := range state.LastEmit {
			emits[code] = at
		}
		dst[subject] = &winSet{keys: keys, lastSeen: state.LastSeen, lastEmit: emits}
	}
	return nil
}

// SnapshotState returns a bounded JSON checkpoint of the detector's sliding
// windows. Raw credentials are never part of detector state; callers pass only
// source pseudonyms, credential IDs, and keyed candidate tags.
func (d *Detector) SnapshotState() ([]byte, error) {
	if d == nil {
		return nil, errors.New("anomaly: nil detector")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.snapshotLocked()
}

// RestoreState loads a checkpoint after validating its version and cardinality.
func (d *Detector) RestoreState(data []byte) error {
	var state detectorState
	if err := json.Unmarshal(data, &state); err != nil || state.Version != detectorStateVersion {
		return errors.New("anomaly: invalid detector snapshot")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := restoreWinSets(d.credAsn, state.CredASN, d.th.MaxSubjects, d.th.MaxKeysPerSubject); err != nil {
		return err
	}
	if err := restoreWinSets(d.srcCred, state.SourceCred, d.th.MaxSubjects, d.th.MaxKeysPerSubject); err != nil {
		return err
	}
	return restoreWinSets(d.srcInvalid, state.Invalid, d.th.MaxSubjects, d.th.MaxKeysPerSubject)
}

// NewPersistentDetector restores and checkpoints one detector through the
// durable state authority.
func NewPersistentDetector(now func() time.Time, th Thresholds, store StateStore, name string) (*Detector, error) {
	if store == nil || name == "" {
		return nil, errors.New("anomaly: persistent detector requires store and name")
	}
	d := NewDetector(now, th)
	data, found, err := store.LoadDetectorState(name)
	if err != nil {
		return nil, fmt.Errorf("anomaly: load %s: %w", name, err)
	}
	if found {
		if err := d.RestoreState(data); err != nil {
			return nil, fmt.Errorf("anomaly: restore %s: %w", name, err)
		}
	}
	d.store, d.stateName = store, name
	d.checkpointStop = make(chan struct{})
	d.checkpointDone = make(chan struct{})
	go d.checkpointLoop()
	return d, nil
}

func (d *Detector) persistLocked() {
	if d.store != nil {
		d.dirty.Store(true)
	}
}

// checkpointLoop coalesces detector observations into bounded periodic
// checkpoints. The detector's mutex protects in-memory windows; the separate
// flush mutex prevents two durable snapshots from racing.
func (d *Detector) checkpointLoop() {
	ticker := time.NewTicker(detectorCheckpointInterval)
	defer ticker.Stop()
	defer close(d.checkpointDone)
	for {
		select {
		case <-ticker.C:
			_ = d.Flush()
		case <-d.checkpointStop:
			return
		}
	}
}

// Flush checkpoints dirty state synchronously. It is used for threshold
// crossings, controlled shutdown, and restart-boundary tests.
func (d *Detector) Flush() error {
	if d == nil {
		return errors.New("anomaly: nil detector")
	}
	d.flushMu.Lock()
	defer d.flushMu.Unlock()
	if d.store == nil || !d.dirty.Swap(false) {
		return d.PersistenceError()
	}
	data, err := d.SnapshotState()
	if err == nil {
		err = d.store.SaveDetectorState(d.stateName, data)
	}
	d.mu.Lock()
	d.stateErr = err
	d.mu.Unlock()
	if err != nil {
		d.dirty.Store(true)
	}
	return err
}

// Close stops the checkpoint worker and performs one final synchronous flush.
func (d *Detector) Close() error {
	if d == nil || d.store == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		close(d.checkpointStop)
		<-d.checkpointDone
	})
	return d.Flush()
}

// PersistenceError reports the latest checkpoint failure, if any.
func (d *Detector) PersistenceError() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stateErr
}

// RecoverPersistence clears a transient distributed-observation error after
// the shared authority has become healthy again. Readiness must be able to do
// this probe because an unready node may not receive another admission that
// would otherwise retry the observation.
func (d *Detector) RecoverPersistence(ctx context.Context) error {
	if d == nil || d.distributed == nil {
		return nil
	}
	var err error
	if ready, ok := d.distributed.(interface{ Ready(context.Context) error }); ok {
		err = ready.Ready(ctx)
	}
	d.mu.Lock()
	d.stateErr = err
	d.mu.Unlock()
	return err
}
