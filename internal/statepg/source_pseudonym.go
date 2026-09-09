package statepg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// SourcePseudonymAlias is one locally-derived source alias. Generation is
// persisted separately so retirement can reason about retained aliases without
// parsing identity strings in every consumer.
type SourcePseudonymAlias struct {
	Alias      string
	Generation int
}

// ResolveOrRegisterSource atomically resolves every loaded alias for one raw
// source to a stable canonical identity. A miss registers the explicitly active
// alias as the canonical identity and records all other loaded aliases as
// alternate mappings, so rotation preserves evidence and adaptive history.
func (s *Store) ResolveOrRegisterSource(ctx context.Context, candidates []SourcePseudonymAlias, active SourcePseudonymAlias) (string, error) {
	if s == nil || s.pool == nil {
		return "", errors.New("statepg: authority is unavailable")
	}
	if strings.TrimSpace(active.Alias) == "" || active.Generation < 1 {
		return "", errors.New("statepg: active source alias is required")
	}
	aliases := make([]SourcePseudonymAlias, 0, len(candidates)+1)
	seen := make(map[string]struct{}, len(candidates)+1)
	allCandidates := make([]SourcePseudonymAlias, 0, len(candidates)+1)
	allCandidates = append(allCandidates, candidates...)
	allCandidates = append(allCandidates, active)
	for _, candidate := range allCandidates {
		if strings.TrimSpace(candidate.Alias) == "" || candidate.Generation < 1 {
			return "", fmt.Errorf("statepg: invalid source alias candidate")
		}
		if _, ok := seen[candidate.Alias]; ok {
			continue
		}
		seen[candidate.Alias] = struct{}{}
		aliases = append(aliases, candidate)
	}
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	var canonical string
	err := s.withTransactionRetry(ctx, "source alias resolution", func() error {
		tx, err := begin(ctx, s.pool)
		if err != nil {
			return mapDBError(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, active.Alias); err != nil {
			return mapDBError(err)
		}
		values := make([]string, 0, len(aliases))
		for _, candidate := range aliases {
			values = append(values, candidate.Alias)
		}
		err = tx.QueryRow(ctx, `SELECT canonical_source_id
			FROM gripline_source_aliases
			WHERE alias = ANY($1::text[])
			ORDER BY generation, alias
			LIMIT 1 FOR UPDATE`, values).Scan(&canonical)
		if errors.Is(err, pgx.ErrNoRows) {
			canonical = active.Alias
		} else if err != nil {
			return mapDBError(err)
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		for _, candidate := range aliases {
			if _, err := tx.Exec(ctx, `INSERT INTO gripline_source_aliases
				(canonical_source_id, alias, generation, created_at, last_seen_at)
				VALUES ($1,$2,$3,$4,$4) ON CONFLICT (alias) DO NOTHING`,
				canonical, candidate.Alias, candidate.Generation, now); err != nil {
				return mapDBError(err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE gripline_source_aliases
			SET last_seen_at=$2 WHERE canonical_source_id=$1 AND alias = ANY($3::text[])`, canonical, now, values); err != nil {
			return mapDBError(err)
		}
		return mapDBError(tx.Commit(ctx))
	})
	if err != nil {
		return "", err
	}
	return canonical, nil
}

// ResolveExistingSourcePseudonym returns the oldest loaded pseudonym
// candidate that already owns a shared source scope. It never stores raw
// network identity: candidates are keyed HMAC outputs. A new active key can
// therefore find a source first seen under an older key and continue using the
// same scope ID across every node.
func (s *Store) ResolveExistingSourcePseudonym(ctx context.Context, candidates []string) (string, error) {
	if s == nil || s.pool == nil {
		return "", errors.New("statepg: authority is unavailable")
	}
	if len(candidates) == 0 {
		return "", nil
	}
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT alias FROM gripline_source_aliases
		WHERE alias = ANY($1::text[])`, candidates)
	if err != nil {
		// Compatibility with an authority created before the alias table was
		// introduced; normal serving paths use ResolveOrRegisterSource after
		// schema migration, but this keeps the read-only seam fail-closed.
		rows, err = s.pool.Query(ctx, `SELECT scope_id FROM gripline_resource_source_scopes
			WHERE scope_id = ANY($1::text[])`, candidates)
		if err != nil {
			return "", mapDBError(err)
		}
	}
	defer rows.Close()
	found := make(map[string]struct{}, len(candidates))
	for rows.Next() {
		var scopeID string
		if err := rows.Scan(&scopeID); err != nil {
			return "", mapDBError(err)
		}
		found[scopeID] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return "", mapDBError(err)
	}
	for _, candidate := range candidates {
		if _, ok := found[candidate]; ok {
			return candidate, nil
		}
	}
	return "", nil
}

var _ interface {
	ResolveExistingSourcePseudonym(context.Context, []string) (string, error)
} = (*Store)(nil)
