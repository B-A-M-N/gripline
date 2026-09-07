package anomaly

import (
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
	return d, nil
}

func (d *Detector) persistLocked() {
	if d.store == nil {
		return
	}
	data, err := d.snapshotLocked()
	if err == nil {
		err = d.store.SaveDetectorState(d.stateName, data)
	}
	if err != nil {
		d.stateErr = err
	}
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
