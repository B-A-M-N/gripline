package statebolt

// Policy lifecycle state is kept in the same bbolt authority as credentials,
// lanes, evidence, posture, and operator audit. In particular, an active
// manifest and its transition event are committed by one transaction; a
// restart therefore cannot observe a policy activation without its audit row.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/policy"
)

const policyStateSchemaVersion = 1

type persistedPolicyManifest struct {
	SchemaVersion int             `json:"schema_version"`
	Manifest      policy.Manifest `json:"manifest"`
}

type persistedPolicyEvent struct {
	SchemaVersion int          `json:"schema_version"`
	Event         policy.Event `json:"event"`
}

// LoadPolicyManifest returns the durable lifecycle marker. A fresh database
// returns an empty manifest so Manager can seed its configured initial policy.
func (s *Store) LoadPolicyManifest() (policy.Manifest, error) {
	var out policy.Manifest
	err := s.view(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketPolicyManifest).Get(keyPolicyManifest)
		if value == nil {
			return nil
		}
		var record persistedPolicyManifest
		if err := json.Unmarshal(value, &record); err != nil || record.SchemaVersion != policyStateSchemaVersion {
			return errors.New("statebolt: corrupt policy manifest")
		}
		if record.Manifest.ActivationEpoch == 0 {
			record.Manifest.ActivationEpoch = 1
		}
		if err := validatePolicyManifest(record.Manifest); err != nil {
			return err
		}
		out = record.Manifest
		return nil
	})
	return out, err
}

// PersistPolicyManifest stores the initial lifecycle marker. Transitioning
// manifests should use PersistPolicyTransition so the event is atomic with it.
func (s *Store) PersistPolicyManifest(manifest policy.Manifest) error {
	if manifest.ActivationEpoch == 0 {
		manifest.ActivationEpoch = 1
	}
	if err := validatePolicyManifest(manifest); err != nil {
		return err
	}
	data, err := json.Marshal(persistedPolicyManifest{SchemaVersion: policyStateSchemaVersion, Manifest: manifest})
	if err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPolicyManifest).Put(keyPolicyManifest, data)
	})
}

// PersistPolicyArtifact stores the exact validated policy bytes referenced by
// a lifecycle manifest. Artifacts are immutable content-addressed records.
func (s *Store) PersistPolicyArtifact(compiled *policy.CompiledPolicy) error {
	if compiled == nil {
		return errors.New("statebolt: policy artifact required")
	}
	digest, err := policy.Digest(&compiled.Policy)
	if err != nil {
		return err
	}
	data, err := json.Marshal(&compiled.Policy)
	if err != nil {
		return err
	}
	ref := policy.PolicyRef{ID: compiled.ID, Revision: compiled.Revision, Digest: digest}
	if err := validatePolicyRef(ref); err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPolicyArtifacts).Put(policyArtifactKey(ref), data)
	})
}

// LoadPolicyArtifact restores and revalidates an immutable artifact referenced
// by a durable manifest.
func (s *Store) LoadPolicyArtifact(ref policy.PolicyRef) (*policy.CompiledPolicy, error) {
	if err := validatePolicyRef(ref); err != nil {
		return nil, err
	}
	var data []byte
	err := s.view(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketPolicyArtifacts).Get(policyArtifactKey(ref))
		if value == nil {
			return fmt.Errorf("statebolt: policy artifact %s/%d not found", ref.ID, ref.Revision)
		}
		data = append([]byte(nil), value...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	var raw policy.Policy
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("statebolt: decode policy artifact: %w", err)
	}
	compiled, err := policy.Compile(&raw)
	if err != nil {
		return nil, fmt.Errorf("statebolt: compile policy artifact: %w", err)
	}
	digest, err := policy.Digest(&compiled.Policy)
	if err != nil || compiled.ID != ref.ID || compiled.Revision != ref.Revision || digest != ref.Digest {
		return nil, errors.New("statebolt: policy artifact does not match manifest reference")
	}
	return compiled, nil
}

// PersistPolicyTransition commits the manifest and its lifecycle audit event
// in one bbolt transaction. The old active pointer may not move backwards
// except for an explicitly named rollback event, and an equal revision may
// not change its digest.
func (s *Store) PersistPolicyTransition(manifest policy.Manifest, event policy.Event) error {
	if manifest.ActivationEpoch == 0 {
		manifest.ActivationEpoch = 1
	}
	if err := validatePolicyManifest(manifest); err != nil {
		return err
	}
	validTarget := manifest.Active
	if event.Action == "prepare" {
		if manifest.Candidate == nil {
			return errors.New("statebolt: policy prepare transition requires a candidate")
		}
		validTarget = *manifest.Candidate
	}
	if strings.TrimSpace(event.Action) == "" || event.ToRevision != validTarget.Revision || event.PolicyID != validTarget.ID {
		return errors.New("statebolt: invalid policy transition event")
	}
	data, err := json.Marshal(persistedPolicyManifest{SchemaVersion: policyStateSchemaVersion, Manifest: manifest})
	if err != nil {
		return err
	}
	eventData, err := json.Marshal(persistedPolicyEvent{SchemaVersion: policyStateSchemaVersion, Event: event})
	if err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error {
		manifestBucket := tx.Bucket(bucketPolicyManifest)
		if previous := manifestBucket.Get(keyPolicyManifest); previous != nil {
			var old persistedPolicyManifest
			if err := json.Unmarshal(previous, &old); err != nil || old.SchemaVersion != policyStateSchemaVersion {
				return errors.New("statebolt: corrupt previous policy manifest")
			}
			if old.Manifest.ActivationEpoch == 0 {
				old.Manifest.ActivationEpoch = 1
			}
			if event.FromRevision != old.Manifest.Active.Revision {
				return fmt.Errorf("statebolt: stale policy transition from revision %d; active is %d", event.FromRevision, old.Manifest.Active.Revision)
			}
			if event.FromEpoch != 0 && event.FromEpoch != old.Manifest.ActivationEpoch {
				return fmt.Errorf("statebolt: stale policy transition from epoch %d; active is %d", event.FromEpoch, old.Manifest.ActivationEpoch)
			}
			epochAware := event.FromEpoch != 0 || event.ToEpoch != 0
			if event.Action == "prepare" {
				if old.Manifest.Candidate != nil {
					return errors.New("statebolt: another policy candidate is already prepared")
				}
				if epochAware && manifest.ActivationEpoch != old.Manifest.ActivationEpoch {
					return errors.New("statebolt: prepare changes policy activation epoch")
				}
			} else if epochAware && manifest.ActivationEpoch != old.Manifest.ActivationEpoch+1 {
				return errors.New("statebolt: policy activation epoch is not monotonic")
			}
			if event.ToEpoch != 0 && event.ToEpoch != manifest.ActivationEpoch {
				return fmt.Errorf("statebolt: transition event epoch %d does not match manifest epoch %d", event.ToEpoch, manifest.ActivationEpoch)
			}
			if epochAware && event.Action == "activate" && (old.Manifest.Candidate == nil || old.Manifest.Candidate.Revision != event.ToRevision || old.Manifest.Candidate.ID != event.PolicyID) {
				return errors.New("statebolt: activation does not match the shared candidate")
			}
			if event.Action != "rollback" && old.Manifest.Active.Revision > manifest.Active.Revision {
				return errors.New("statebolt: policy transition moves active revision backwards")
			}
			if old.Manifest.Active.Revision == manifest.Active.Revision && old.Manifest.Active.Digest != manifest.Active.Digest {
				return errors.New("statebolt: policy transition changes active digest at the same revision")
			}
		}
		if err := manifestBucket.Put(keyPolicyManifest, data); err != nil {
			return err
		}
		return appendPolicyEventTx(tx, eventData)
	})
}

// ListPolicyAudit returns lifecycle events in durable sequence order.
func (s *Store) ListPolicyAudit(after uint64, limit int) ([]policy.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var out []policy.Event
	err := s.view(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(bucketPolicyAudit).Cursor()
		for key, value := cursor.First(); key != nil && len(out) < limit; key, value = cursor.Next() {
			if string(key) == string(keyPolicySequence) {
				continue
			}
			seq := btoi(key)
			if seq <= after {
				continue
			}
			var record persistedPolicyEvent
			if err := json.Unmarshal(value, &record); err != nil || record.SchemaVersion != policyStateSchemaVersion {
				return errors.New("statebolt: corrupt policy audit event")
			}
			out = append(out, record.Event)
		}
		return nil
	})
	return out, err
}

func appendPolicyEventTx(tx *bolt.Tx, data []byte) error {
	bucket := tx.Bucket(bucketPolicyAudit)
	sequence := btoi(bucket.Get(keyPolicySequence)) + 1
	if err := bucket.Put(itob(sequence), data); err != nil {
		return err
	}
	return bucket.Put(keyPolicySequence, itob(sequence))
}

func policyArtifactKey(ref policy.PolicyRef) []byte {
	return []byte(strconv.Itoa(ref.Revision) + "/" + ref.Digest)
}

func validatePolicyManifest(manifest policy.Manifest) error {
	if manifest.SchemaVersion != 1 {
		return errors.New("statebolt: invalid policy manifest schema")
	}
	if manifest.ActivationEpoch == 0 {
		return errors.New("statebolt: invalid policy activation epoch")
	}
	if err := validatePolicyRef(manifest.Active); err != nil {
		return fmt.Errorf("statebolt: active policy: %w", err)
	}
	if manifest.Candidate != nil {
		if err := validatePolicyRef(*manifest.Candidate); err != nil {
			return fmt.Errorf("statebolt: candidate policy: %w", err)
		}
	}
	if manifest.Previous != nil {
		if err := validatePolicyRef(*manifest.Previous); err != nil {
			return fmt.Errorf("statebolt: previous policy: %w", err)
		}
	}
	return nil
}

func validatePolicyRef(ref policy.PolicyRef) error {
	if strings.TrimSpace(ref.ID) == "" || ref.Revision < 1 || len(ref.Digest) != 64 {
		return errors.New("invalid policy reference")
	}
	return nil
}
