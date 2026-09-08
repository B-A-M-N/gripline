package statepg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
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
	return withTransactionRetry(ctx, "evidence append", func() error {
		return s.appendContextOnce(ctx, items)
	})
}

func (s *Store) appendContextOnce(ctx context.Context, items []evidence.Evidence) error {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, false); err != nil {
		return err
	}
	authorityNow, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	bySubject := make(map[evidence.SubjectKey][]evidence.Evidence)
	for _, item := range items {
		key := evidence.SubjectKey{Scope: item.Scope, ID: item.SubjectID}
		bySubject[key] = append(bySubject[key], item)
	}
	subjects := make([]evidence.SubjectKey, 0, len(bySubject))
	for subject := range bySubject {
		subjects = append(subjects, subject)
	}
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i].Scope != subjects[j].Scope {
			return subjects[i].Scope < subjects[j].Scope
		}
		return subjects[i].ID < subjects[j].ID
	})
	for _, subject := range subjects {
		incoming := bySubject[subject]
		if err := s.lockEvidenceGuard(ctx, tx, subject, authorityNow); err != nil {
			return err
		}
		existing, err := loadEvidenceSubject(ctx, tx, subject, true)
		if err != nil {
			return err
		}
		merged := evidence.MergeSubject(existing, incoming, authorityNow)
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
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
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
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var pruned int
	var lastErr error
	for attempt := 0; attempt < maxTransactionAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		pruned, lastErr = s.pruneContextOnce(ctx, subjects, now)
		if lastErr == nil || !retryableTransactionError(lastErr) {
			return pruned, lastErr
		}
	}
	return 0, fmt.Errorf("statepg: evidence prune remained conflicted after retries: %w", lastErr)
}

func (s *Store) pruneContextOnce(ctx context.Context, subjects []evidence.SubjectKey, _ time.Time) (int, error) {
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if err := s.requireNodeOwnership(ctx, tx, true); err != nil {
		return 0, err
	}
	authorityNow, err := dbNow(ctx, tx)
	if err != nil {
		return 0, err
	}
	pruned := 0
	orderedSubjects := append([]evidence.SubjectKey(nil), subjects...)
	sort.Slice(orderedSubjects, func(i, j int) bool {
		if orderedSubjects[i].Scope != orderedSubjects[j].Scope {
			return orderedSubjects[i].Scope < orderedSubjects[j].Scope
		}
		return orderedSubjects[i].ID < orderedSubjects[j].ID
	})
	for _, subject := range orderedSubjects {
		if err := s.lockEvidenceGuard(ctx, tx, subject, authorityNow); err != nil {
			return 0, err
		}
		items, err := loadEvidenceSubject(ctx, tx, subject, true)
		if err != nil {
			return 0, err
		}
		scope, id, err := evidenceSubject(subject)
		if err != nil {
			return 0, err
		}
		for _, item := range items {
			if !item.Valid(authorityNow) {
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

// lockEvidenceGuard gives a first-write subject a durable row to lock. A
// FOR UPDATE on gripline_evidence cannot serialize two transactions when the
// subject has no evidence row yet.
func (s *Store) lockEvidenceGuard(ctx context.Context, tx pgx.Tx, subject evidence.SubjectKey, now time.Time) error {
	scope, id, err := evidenceSubject(subject)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_evidence_guards (scope, subject_id, created_at)
		VALUES ($1,$2,$3) ON CONFLICT (scope, subject_id) DO NOTHING`, scope, id, now.UTC()); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT scope, subject_id FROM gripline_evidence_guards
		WHERE scope=$1 AND subject_id=$2 FOR UPDATE`, scope, id)
	return err
}

var _ evidence.Store = (*Store)(nil)
var _ evidence.ContextStore = (*Store)(nil)
