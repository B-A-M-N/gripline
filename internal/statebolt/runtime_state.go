package statebolt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	bolt "go.etcd.io/bbolt"
)

const detectorStateSchemaVersion = 1
const maxDetectorStateBytes = 4 << 20

type persistedDetectorState struct {
	SchemaVersion int             `json:"schema_version"`
	Data          json.RawMessage `json:"data"`
}

// LoadDetectorState reads one bounded detector checkpoint. The API is generic
// so the anomaly and producer packages can persist their private state without
// coupling the state authority to their implementations.
func (s *Store) LoadDetectorState(name string) ([]byte, bool, error) {
	if err := validateDetectorStateName(name); err != nil {
		return nil, false, err
	}
	var out []byte
	var found bool
	err := s.view(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketDetectorState).Get([]byte(name))
		if value == nil {
			return nil
		}
		var state persistedDetectorState
		if err := json.Unmarshal(value, &state); err != nil || state.SchemaVersion != detectorStateSchemaVersion || len(state.Data) > maxDetectorStateBytes {
			return errors.New("statebolt: corrupt detector state")
		}
		out = append([]byte(nil), state.Data...)
		found = true
		return nil
	})
	return out, found, err
}

// SaveDetectorState atomically replaces one bounded detector checkpoint.
func (s *Store) SaveDetectorState(name string, data []byte) error {
	if err := validateDetectorStateName(name); err != nil {
		return err
	}
	if len(data) > maxDetectorStateBytes {
		return fmt.Errorf("statebolt: detector state %q exceeds %d bytes", name, maxDetectorStateBytes)
	}
	env, err := json.Marshal(persistedDetectorState{SchemaVersion: detectorStateSchemaVersion, Data: data})
	if err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDetectorState).Put([]byte(name), env)
	})
}

func validateDetectorStateName(name string) error {
	if strings.TrimSpace(name) == "" || len(name) > 128 || bytes.IndexByte([]byte(name), 0) >= 0 {
		return errors.New("statebolt: invalid detector state name")
	}
	return nil
}
