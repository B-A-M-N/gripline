package statepg

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	sourceAliasTouchInterval = time.Minute
	sourceAliasTouchTimeout  = 500 * time.Millisecond
)

// SourcePseudonymAlias is one locally-derived source alias. Generation is
// persisted separately so retirement can reason about retained aliases without
// parsing identity strings in every consumer.
type SourcePseudonymAlias struct {
	Alias      string
	Generation int
}

// ErrSourceAliasConflict means that the loaded aliases for one source are
// already owned by more than one canonical source identity. Resolving such a
// set would silently merge unrelated source scopes, so callers must fail
// closed and leave the rows untouched.
var ErrSourceAliasConflict = errors.New("statepg: source alias conflict")

// ResolveOrRegisterSource atomically resolves every loaded alias for one raw
// source to a stable canonical identity. A miss registers the explicitly active
// alias as the canonical identity and records all other loaded aliases as
// alternate mappings, so rotation preserves evidence and adaptive history.
func (s *Store) ResolveOrRegisterSource(ctx context.Context, candidates []SourcePseudonymAlias, active SourcePseudonymAlias) (canonical string, err error) {
	started := time.Now()
	registered := false
	defer func() {
		if s != nil {
			s.metrics.sourceAliasAttempts.Add(1)
			s.metrics.sourceAliasResolutionLatencyNanos.Add(time.Since(started).Nanoseconds())
			if registered {
				s.metrics.sourceAliasRegistrations.Add(1)
			}
			if errors.Is(err, ErrSourceAliasConflict) {
				s.metrics.sourceAliasConflicts.Add(1)
			}
			if err != nil {
				s.metrics.sourceAliasFailures.Add(1)
			}
		}
	}()
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
	values := make([]string, 0, len(aliases))
	for _, candidate := range aliases {
		values = append(values, candidate.Alias)
	}
	var complete bool
	canonical, complete, err = s.resolveSourceAliasesReadOnly(ctx, values)
	if err != nil {
		return "", err
	}
	if canonical != "" && complete {
		s.maybeTouchSourceAliases(values)
		return canonical, nil
	}

	canonical, registered, err = s.registerSourceAliases(ctx, aliases, active.Alias)
	if err != nil {
		return "", err
	}
	return canonical, nil
}

func (s *Store) resolveSourceAliasesReadOnly(ctx context.Context, aliases []string) (string, bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT alias, canonical_source_id
		FROM gripline_source_aliases WHERE alias = ANY($1::text[])`, aliases)
	if err != nil {
		return "", false, mapDBError(err)
	}
	defer rows.Close()
	canonicalIDs := make(map[string]struct{}, 1)
	foundAliases := make(map[string]struct{}, len(aliases))
	for rows.Next() {
		var alias string
		var canonical string
		if err := rows.Scan(&alias, &canonical); err != nil {
			return "", false, mapDBError(err)
		}
		foundAliases[alias] = struct{}{}
		canonicalIDs[canonical] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return "", false, mapDBError(err)
	}
	if len(canonicalIDs) > 1 {
		return "", false, ErrSourceAliasConflict
	}
	for canonical := range canonicalIDs {
		return canonical, len(foundAliases) == len(aliases), nil
	}
	return "", false, nil
}

func (s *Store) registerSourceAliases(ctx context.Context, aliases []SourcePseudonymAlias, active string) (canonical string, registered bool, err error) {
	values := make([]string, 0, len(aliases))
	for _, candidate := range aliases {
		values = append(values, candidate.Alias)
	}
	lockValues := append([]string(nil), values...)
	sort.Strings(lockValues)
	err = s.withTransactionRetry(ctx, "source alias registration", func() error {
		tx, err := begin(ctx, s.pool)
		if err != nil {
			return mapDBError(err)
		}
		defer tx.Rollback(ctx)
		for _, alias := range lockValues {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, alias); err != nil {
				return mapDBError(err)
			}
		}
		rows, err := tx.Query(ctx, `SELECT alias, canonical_source_id
			FROM gripline_source_aliases
			WHERE alias = ANY($1::text[]) FOR UPDATE`, values)
		if err != nil {
			return mapDBError(err)
		}
		found := make(map[string]struct{}, 1)
		existingAliases := make(map[string]struct{}, len(values))
		for rows.Next() {
			var alias, owner string
			if err := rows.Scan(&alias, &owner); err != nil {
				rows.Close()
				return mapDBError(err)
			}
			existingAliases[alias] = struct{}{}
			found[owner] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return mapDBError(err)
		}
		rows.Close()
		if len(found) > 1 {
			return ErrSourceAliasConflict
		}
		if len(found) == 0 {
			canonical = active
		} else {
			for owner := range found {
				canonical = owner
			}
		}
		inserted := false
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		for _, candidate := range aliases {
			if _, ok := existingAliases[candidate.Alias]; !ok {
				inserted = true
			}
			if _, err := tx.Exec(ctx, `INSERT INTO gripline_source_aliases
				(canonical_source_id, alias, generation, created_at, last_seen_at)
				VALUES ($1,$2,$3,$4,$4) ON CONFLICT (alias) DO NOTHING`,
				canonical, candidate.Alias, candidate.Generation, now); err != nil {
				return mapDBError(err)
			}
		}
		if err := mapDBError(tx.Commit(ctx)); err != nil {
			return err
		}
		registered = registered || inserted
		return nil
	})
	return canonical, registered, err
}

// maybeTouchSourceAliases keeps alias recency useful without putting a write,
// row lock, or touch failure on the request's authority path. Each alias is
// claimed at most once per interval per Store; the detached update is
// intentionally best effort because recency is analytics/retention metadata,
// not an inference correctness condition.
func (s *Store) maybeTouchSourceAliases(aliases []string) {
	if s == nil || s.pool == nil || len(aliases) == 0 {
		return
	}
	claimed := s.claimSourceAliasTouch(aliases, time.Now())
	if len(claimed) == 0 {
		return
	}
	go func() {
		touchCtx, cancel := context.WithTimeout(context.Background(), sourceAliasTouchTimeout)
		defer cancel()
		_, _ = s.pool.Exec(touchCtx, `UPDATE gripline_source_aliases
			SET last_seen_at=CURRENT_TIMESTAMP
			WHERE alias = ANY($1::text[])
			  AND last_seen_at < CURRENT_TIMESTAMP - INTERVAL '30 seconds'`, claimed)
	}()
}

func (s *Store) claimSourceAliasTouch(aliases []string, now time.Time) []string {
	s.sourceAliasTouchMu.Lock()
	defer s.sourceAliasTouchMu.Unlock()
	if s.sourceAliasLastTouch == nil {
		s.sourceAliasLastTouch = make(map[string]time.Time)
	}
	claimed := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		last := s.sourceAliasLastTouch[alias]
		if !last.IsZero() && now.Sub(last) < sourceAliasTouchInterval {
			continue
		}
		s.sourceAliasLastTouch[alias] = now
		claimed = append(claimed, alias)
	}
	// Keep the in-memory throttle bounded if a process observes many sources.
	if len(s.sourceAliasLastTouch) > 8192 {
		for alias, last := range s.sourceAliasLastTouch {
			if now.Sub(last) >= sourceAliasTouchInterval {
				delete(s.sourceAliasLastTouch, alias)
			}
		}
		for alias := range s.sourceAliasLastTouch {
			if len(s.sourceAliasLastTouch) <= 4096 {
				break
			}
			delete(s.sourceAliasLastTouch, alias)
		}
	}
	return claimed
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
