package statepg

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/jackc/pgx/v5"
)

func evidenceSubject(sk evidence.SubjectKey) (string, string, error) {
	if sk.ID == "" {
		return "", "", errors.New("statepg: empty evidence subject")
	}
	return sk.Scope.String(), sk.ID, nil
}

func loadEvidenceSubject(ctx context.Context, tx pgx.Tx, sk evidence.SubjectKey, lock bool) ([]evidence.Evidence, error) {
	scope, id, err := evidenceSubject(sk)
	if err != nil {
		return nil, err
	}
	query := `SELECT item FROM gripline_evidence WHERE scope=$1 AND subject_id=$2 ORDER BY evidence_id`
	if lock {
		query += ` FOR UPDATE`
	}
	rows, err := tx.Query(ctx, query, scope, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []evidence.Evidence
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var item evidence.Evidence
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, errors.New("statepg: corrupt evidence record")
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Append atomically merges a batch per subject using the same bounded
// compaction semantics as the resident and Bolt authorities.
func (s *Store) Append(items ...evidence.Evidence) error {
	return s.AppendContext(context.Background(), items...)
}

func (s *Store) AppendContext(ctx context.Context, items ...evidence.Evidence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, item := range items {
		if err := evidence.ValidateForStore(item); err != nil {
			return err
		}
	}
	if len(items) == 0 {
		return nil
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	bySubject := make(map[evidence.SubjectKey][]evidence.Evidence)
	for _, item := range items {
		key := evidence.SubjectKey{Scope: item.Scope, ID: item.SubjectID}
		bySubject[key] = append(bySubject[key], item)
	}
	for subject, incoming := range bySubject {
		existing, err := loadEvidenceSubject(ctx, tx, subject, true)
		if err != nil {
			return err
		}
		merged := evidence.MergeSubject(existing, incoming, s.now())
		scope, id, err := evidenceSubject(subject)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM gripline_evidence WHERE scope=$1 AND subject_id=$2`, scope, id); err != nil {
			return err
		}
		for _, item := range merged {
			raw, err := json.Marshal(item)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO gripline_evidence (scope, subject_id, evidence_id, item) VALUES ($1,$2,$3,$4)`, scope, id, item.EvidenceID, raw); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) Snapshot(subjects []evidence.SubjectKey, now time.Time) ([]evidence.Evidence, error) {
	return s.SnapshotContext(context.Background(), subjects, now)
}

func (s *Store) SnapshotContext(ctx context.Context, subjects []evidence.SubjectKey, now time.Time) ([]evidence.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []evidence.Evidence
	for _, subject := range subjects {
		scope, id, err := evidenceSubject(subject)
		if err != nil {
			return nil, err
		}
		rows, err := s.pool.Query(ctx, `SELECT item FROM gripline_evidence WHERE scope=$1 AND subject_id=$2 ORDER BY evidence_id`, scope, id)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return nil, err
			}
			var item evidence.Evidence
			if err := json.Unmarshal(raw, &item); err != nil {
				rows.Close()
				return nil, errors.New("statepg: corrupt evidence record")
			}
			if item.Valid(now) {
				out = append(out, item)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

func (s *Store) Prune(subjects []evidence.SubjectKey, now time.Time) (int, error) {
	return s.PruneContext(context.Background(), subjects, now)
}

func (s *Store) PruneContext(ctx context.Context, subjects []evidence.SubjectKey, now time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	pruned := 0
	for _, subject := range subjects {
		items, err := loadEvidenceSubject(ctx, tx, subject, true)
		if err != nil {
			return 0, err
		}
		scope, id, err := evidenceSubject(subject)
		if err != nil {
			return 0, err
		}
		for _, item := range items {
			if !item.Valid(now) {
				if _, err := tx.Exec(ctx, `DELETE FROM gripline_evidence WHERE scope=$1 AND subject_id=$2 AND evidence_id=$3`, scope, id, item.EvidenceID); err != nil {
					return 0, err
				}
				pruned++
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return pruned, nil
}

var _ evidence.Store = (*Store)(nil)
var _ evidence.ContextStore = (*Store)(nil)
