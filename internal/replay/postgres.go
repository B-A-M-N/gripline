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
// processes atomic; expired rows are indexed and removed before insertion.
type PostgresGuard struct {
	pool *pgxpool.Pool
}

// OpenPostgresGuard connects to and initializes the shared replay table.
func OpenPostgresGuard(ctx context.Context, dsn string) (*PostgresGuard, error) {
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
	if err := guard.ensureSchema(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return guard, nil
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
	if _, err := g.pool.Exec(ctx, `DELETE FROM gripline_replay_claims WHERE expires_at <= CURRENT_TIMESTAMP`); err != nil {
		return false, err
	}
	var inserted int
	err := g.pool.QueryRow(ctx, `INSERT INTO gripline_replay_claims (claim_key, expires_at)
		VALUES ($1,$2) ON CONFLICT (claim_key) DO NOTHING RETURNING 1`, key, claim.ExpiresAt.UTC()).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return inserted == 1, nil
}

func claimKey(claim verify.ReplayClaim) []byte {
	sum := sha256.Sum256([]byte(strings.Join([]string{claim.Issuer, claim.Audience, claim.JTI}, "\x00")))
	return sum[:]
}
