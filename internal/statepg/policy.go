package statepg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/jackc/pgx/v5"
)

const policyManifestSchemaVersion = 1

func validatePolicyRef(ref policy.PolicyRef) error {
	if strings.TrimSpace(ref.ID) == "" || ref.Revision < 1 || len(ref.Digest) != 64 {
		return errors.New("statepg: invalid policy reference")
	}
	return nil
}

func validatePolicyManifest(manifest policy.Manifest) error {
	if manifest.SchemaVersion != policyManifestSchemaVersion {
		return errors.New("statepg: invalid policy manifest schema")
	}
	if manifest.ActivationEpoch == 0 {
		return errors.New("statepg: invalid policy activation epoch")
	}
	if err := validatePolicyRef(manifest.Active); err != nil {
		return fmt.Errorf("active policy: %w", err)
	}
	if manifest.Candidate != nil {
		if err := validatePolicyRef(*manifest.Candidate); err != nil {
			return fmt.Errorf("candidate policy: %w", err)
		}
	}
	if manifest.Previous != nil {
		if err := validatePolicyRef(*manifest.Previous); err != nil {
			return fmt.Errorf("previous policy: %w", err)
		}
	}
	return nil
}

func (s *Store) LoadPolicyManifest() (policy.Manifest, error) {
	return s.LoadPolicyManifestContext(context.Background())
}

func (s *Store) LoadPolicyManifestContext(ctx context.Context) (policy.Manifest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var out policy.Manifest
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT manifest FROM gripline_policy_manifest WHERE singleton=TRUE`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, mapDBError(err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("statepg: decode policy manifest: %w", err)
	}
	if out.ActivationEpoch == 0 {
		// Manifests written before activation epochs are treated as epoch 1;
		// lifecycle writes thereafter must carry the field explicitly.
		out.ActivationEpoch = 1
	}
	return out, validatePolicyManifest(out)
}

func (s *Store) PersistPolicyManifest(manifest policy.Manifest) error {
	return s.PersistPolicyManifestContext(context.Background(), manifest)
}

func (s *Store) PersistPolicyManifestContext(ctx context.Context, manifest policy.Manifest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if manifest.ActivationEpoch == 0 {
		manifest.ActivationEpoch = 1
	}
	if err := validatePolicyManifest(manifest); err != nil {
		return err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO gripline_policy_manifest (singleton, manifest, updated_at)
		VALUES (TRUE,$1,$2) ON CONFLICT (singleton) DO UPDATE SET manifest=EXCLUDED.manifest, updated_at=EXCLUDED.updated_at`, raw, manifest.UpdatedAt.UTC())
	return mapDBError(err)
}

// InitializePolicyManifest publishes the first cluster policy with
// create-only semantics. A normal lifecycle persistence operation must never
// be used here: two nodes can boot concurrently with different local policy
// files, and neither is allowed to overwrite the winner.
func (s *Store) InitializePolicyManifest(manifest policy.Manifest) error {
	return s.InitializePolicyManifestContext(context.Background(), manifest)
}

func (s *Store) InitializePolicyManifestContext(ctx context.Context, manifest policy.Manifest) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if manifest.ActivationEpoch == 0 {
		manifest.ActivationEpoch = 1
	}
	if err := validatePolicyManifest(manifest); err != nil {
		return err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO gripline_policy_manifest (singleton, manifest, updated_at)
		VALUES (TRUE,$1,$2) ON CONFLICT (singleton) DO NOTHING`, raw, manifest.UpdatedAt.UTC())
	return mapDBError(err)
}

func (s *Store) PersistPolicyArtifact(compiled *policy.CompiledPolicy) error {
	return s.PersistPolicyArtifactContext(context.Background(), compiled)
}

func (s *Store) PersistPolicyArtifactContext(ctx context.Context, compiled *policy.CompiledPolicy) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if compiled == nil {
		return errors.New("statepg: policy artifact required")
	}
	digest, err := policy.Digest(&compiled.Policy)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(&compiled.Policy)
	if err != nil {
		return err
	}
	if err := validatePolicyRef(policy.PolicyRef{ID: compiled.ID, Revision: compiled.Revision, Digest: digest}); err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO gripline_policy_artifacts (policy_id, revision, digest, artifact)
		VALUES ($1,$2,$3,$4) ON CONFLICT (policy_id, revision, digest) DO NOTHING`, compiled.ID, compiled.Revision, digest, raw)
	return mapDBError(err)
}

func (s *Store) LoadPolicyArtifact(ref policy.PolicyRef) (*policy.CompiledPolicy, error) {
	return s.LoadPolicyArtifactContext(context.Background(), ref)
}

func (s *Store) LoadPolicyArtifactContext(ctx context.Context, ref policy.PolicyRef) (*policy.CompiledPolicy, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validatePolicyRef(ref); err != nil {
		return nil, err
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT artifact FROM gripline_policy_artifacts WHERE policy_id=$1 AND revision=$2 AND digest=$3`, ref.ID, ref.Revision, ref.Digest).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("statepg: policy artifact %s/%d not found", ref.ID, ref.Revision)
	}
	if err != nil {
		return nil, mapDBError(err)
	}
	var rawPolicy policy.Policy
	if err := json.Unmarshal(raw, &rawPolicy); err != nil {
		return nil, fmt.Errorf("statepg: decode policy artifact: %w", err)
	}
	compiled, err := policy.Compile(&rawPolicy)
	if err != nil {
		return nil, fmt.Errorf("statepg: compile policy artifact: %w", err)
	}
	digest, err := policy.Digest(&compiled.Policy)
	if err != nil || compiled.ID != ref.ID || compiled.Revision != ref.Revision || digest != ref.Digest {
		return nil, errors.New("statepg: policy artifact does not match manifest reference")
	}
	return compiled, nil
}

func (s *Store) PersistPolicyTransition(manifest policy.Manifest, event policy.Event) error {
	return s.PersistPolicyTransitionContext(context.Background(), manifest, event)
}

func (s *Store) PersistPolicyTransitionContext(ctx context.Context, manifest policy.Manifest, event policy.Event) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validatePolicyManifest(manifest); err != nil {
		return err
	}
	validTarget := manifest.Active
	if event.Action == "prepare" {
		if manifest.Candidate == nil {
			return errors.New("statepg: policy prepare requires a candidate")
		}
		validTarget = *manifest.Candidate
	}
	if strings.TrimSpace(event.Action) == "" || event.ToRevision != validTarget.Revision || event.PolicyID != validTarget.ID {
		return errors.New("statepg: invalid policy transition event")
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	rawEvent, err := json.Marshal(event)
	if err != nil {
		return err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return mapDBError(err)
	}
	defer tx.Rollback(ctx)
	var previousRaw []byte
	err = tx.QueryRow(ctx, `SELECT manifest FROM gripline_policy_manifest WHERE singleton=TRUE FOR UPDATE`).Scan(&previousRaw)
	if err == nil {
		var previous policy.Manifest
		if json.Unmarshal(previousRaw, &previous) != nil {
			return errors.New("statepg: corrupt previous policy manifest")
		}
		if previous.ActivationEpoch == 0 {
			previous.ActivationEpoch = 1
		}
		if validatePolicyManifest(previous) != nil {
			return errors.New("statepg: corrupt previous policy manifest")
		}
		if event.FromRevision != previous.Active.Revision {
			return fmt.Errorf("statepg: stale policy transition from revision %d; active is %d", event.FromRevision, previous.Active.Revision)
		}
		if event.FromEpoch != 0 && event.FromEpoch != previous.ActivationEpoch {
			return fmt.Errorf("statepg: stale policy transition from epoch %d; active is %d", event.FromEpoch, previous.ActivationEpoch)
		}
		epochAware := event.FromEpoch != 0 || event.ToEpoch != 0
		switch event.Action {
		case "prepare":
			if previous.Candidate != nil {
				return errors.New("statepg: another policy candidate is already prepared")
			}
		case "activate":
			if epochAware && (previous.Candidate == nil || previous.Candidate.Revision != event.ToRevision || previous.Candidate.ID != event.PolicyID) {
				return errors.New("statepg: activation does not match the shared candidate")
			}
		}
		if epochAware {
			if event.Action == "prepare" {
				if manifest.ActivationEpoch != previous.ActivationEpoch {
					return errors.New("statepg: prepare changes policy activation epoch")
				}
			} else if manifest.ActivationEpoch != previous.ActivationEpoch+1 {
				return errors.New("statepg: policy activation epoch is not monotonic")
			}
		}
		if event.ToEpoch != 0 && event.ToEpoch != manifest.ActivationEpoch {
			return fmt.Errorf("statepg: transition event epoch %d does not match manifest epoch %d", event.ToEpoch, manifest.ActivationEpoch)
		}
		if event.Action != "rollback" && previous.Active.Revision > manifest.Active.Revision {
			return errors.New("statepg: policy transition moves active revision backwards")
		}
		if previous.Active.Revision == manifest.Active.Revision && previous.Active.Digest != manifest.Active.Digest {
			return errors.New("statepg: policy transition changes active digest at same revision")
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return mapDBError(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_policy_manifest (singleton, manifest, updated_at) VALUES (TRUE,$1,$2)
		ON CONFLICT (singleton) DO UPDATE SET manifest=EXCLUDED.manifest, updated_at=EXCLUDED.updated_at`, rawManifest, manifest.UpdatedAt.UTC()); err != nil {
		return mapDBError(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_policy_audit (event) VALUES ($1)`, rawEvent); err != nil {
		return mapDBError(err)
	}
	return mapDBError(tx.Commit(ctx))
}

func (s *Store) ListPolicyAudit(after uint64, limit int) ([]policy.Event, error) {
	return s.ListPolicyAuditContext(context.Background(), after, limit)
}

func (s *Store) ListPolicyAuditContext(ctx context.Context, after uint64, limit int) ([]policy.Event, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT event FROM gripline_policy_audit WHERE sequence > $1 ORDER BY sequence LIMIT $2`, after, limit)
	if err != nil {
		return nil, mapDBError(err)
	}
	defer rows.Close()
	var out []policy.Event
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, mapDBError(err)
		}
		var event policy.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return nil, errors.New("statepg: corrupt policy audit event")
		}
		out = append(out, event)
	}
	return out, mapDBError(rows.Err())
}
