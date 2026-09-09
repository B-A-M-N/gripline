// Package replay contains shared replay authorities used by reference
// qualification backends. The public verify package stays dependency-free;
// this package is the PostgreSQL-backed deployment adapter.
package replay

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/B-A-M-N/gripline/verify"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresGuard records a namespaced assertion claim in a shared authority.
// The primary key makes concurrent claims across independent verifier
// processes atomic. Schema ownership belongs to the explicit migration
// command; serving processes only verify the schema and perform DML.
type PostgresGuard struct {
	pool *pgxpool.Pool
}

// OpenPostgresGuard connects to an already-migrated shared replay table.
func OpenPostgresGuard(ctx context.Context, dsn string) (*PostgresGuard, error) {
	ctx = nonNilContext(ctx)
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("replay: empty PostgreSQL DSN")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	guard := &PostgresGuard{pool: pool}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := guard.checkSchema(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return guard, nil
}

// MigratePostgresGuard applies the repository-owned replay schema. It is
// intentionally separate from OpenPostgresGuard so a serving role never needs
// CREATE/ALTER privileges.
func MigratePostgresGuard(ctx context.Context, dsn string) error {
	ctx = nonNilContext(ctx)
	if strings.TrimSpace(dsn) == "" {
		return errors.New("replay: empty PostgreSQL DSN")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	return (&PostgresGuard{pool: pool}).ensureSchema(ctx)
}

func (g *PostgresGuard) checkSchema(ctx context.Context) error {
	ctx = nonNilContext(ctx)
	var table string
	if err := g.pool.QueryRow(ctx, `SELECT to_regclass('public.gripline_replay_claims')`).Scan(&table); err != nil {
		return err
	}
	if table == "" {
		return errors.New("replay: schema is not migrated")
	}
	var index string
	if err := g.pool.QueryRow(ctx, `SELECT to_regclass('public.gripline_replay_claims_expiry_idx')`).Scan(&index); err != nil {
		return err
	}
	if index == "" {
		return errors.New("replay: expiry index is not migrated")
	}
	return nil
}

func (g *PostgresGuard) ensureSchema(ctx context.Context) error {
	tx, err := g.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('gripline_replay_schema', 0))`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS gripline_replay_claims (
		claim_key BYTEA PRIMARY KEY,
		expires_at TIMESTAMPTZ NOT NULL
);
	CREATE INDEX IF NOT EXISTS gripline_replay_claims_expiry_idx
		ON gripline_replay_claims (expires_at);`); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Close releases the shared pool.
func (g *PostgresGuard) Close() {
	if g != nil && g.pool != nil {
		g.pool.Close()
	}
}

// Accept atomically claims one issuer/audience/JTI namespace until expiry.
func (g *PostgresGuard) Accept(ctx context.Context, claim verify.ReplayClaim) (bool, error) {
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if g == nil || g.pool == nil || strings.TrimSpace(claim.Issuer) == "" || strings.TrimSpace(claim.Audience) == "" || strings.TrimSpace(claim.JTI) == "" || claim.ExpiresAt.IsZero() {
		return false, errors.New("replay: unavailable")
	}
	if !time.Now().Before(claim.ExpiresAt) {
		return false, errors.New("replay: claim expired")
	}
	key := claimKey(claim)
	var inserted int
	err := g.pool.QueryRow(ctx, `INSERT INTO gripline_replay_claims (claim_key, expires_at)
		SELECT $1, $2
		WHERE $2 > CURRENT_TIMESTAMP
		ON CONFLICT (claim_key) DO UPDATE
		SET expires_at = EXCLUDED.expires_at
		WHERE gripline_replay_claims.expires_at <= CURRENT_TIMESTAMP
		RETURNING 1`, key, claim.ExpiresAt.UTC()).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return inserted == 1, nil
}

// CleanupExpired removes at most limit rows. It is deliberately separate from
// Accept so request admission never performs an unbounded table-wide delete.
func (g *PostgresGuard) CleanupExpired(ctx context.Context, limit int) (int64, error) {
	ctx = nonNilContext(ctx)
	if g == nil || g.pool == nil {
		return 0, errors.New("replay: unavailable")
	}
	if limit <= 0 {
		return 0, errors.New("replay: cleanup limit must be positive")
	}
	tag, err := g.pool.Exec(ctx, `WITH expired AS (
		SELECT claim_key FROM gripline_replay_claims
		WHERE expires_at <= CURRENT_TIMESTAMP
		ORDER BY expires_at
		LIMIT $1
	)
	DELETE FROM gripline_replay_claims c USING expired
	WHERE c.claim_key = expired.claim_key`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func claimKey(claim verify.ReplayClaim) []byte {
	sum := sha256.Sum256([]byte(strings.Join([]string{claim.Issuer, claim.Audience, claim.JTI}, "\x00")))
	return sum[:]
}
