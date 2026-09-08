package statepg

import (
	"context"
	"errors"
)

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
	rows, err := s.pool.Query(ctx, `SELECT scope_id FROM gripline_resource_source_scopes
		WHERE scope_id = ANY($1::text[])`, candidates)
	if err != nil {
		return "", mapDBError(err)
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
