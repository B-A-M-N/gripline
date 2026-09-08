// Package statepg provides the clustered PostgreSQL authority for Gripline.
//
// It is deliberately separate from statebolt: bbolt remains the explicit
// single-process backend, while this package owns rows in a shared database
// and uses PostgreSQL transactions/row locks for cross-process coordination.
// Security decisions never fall back from this authority to a local cache.
package statepg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options configures a PostgreSQL authority. DSN must come from a secret
// reference or environment expansion; it is never persisted by this package.
type Options struct {
	DSN      string
	MaxConns int32
	MinConns int32
	Now      func() time.Time
}

// Store is the shared transactional authority. Credential, lane, and evidence
// methods are split across files but use this same pool and transaction model.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

const currentSchemaVersion = 1

var ErrMigrationRequired = errors.New("statepg: database schema requires migration")
var ErrDSNRequired = errors.New("statepg: DSN required")

// Open connects to PostgreSQL, verifies liveness, and creates the authority
// schema idempotently. Schema creation is intentionally explicit at boot so a
// partially migrated cluster cannot silently serve with missing state.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.DSN == "" {
		return nil, ErrDSNRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	config, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("statepg: parse DSN: %w", err)
	}
	if opts.MaxConns > 0 {
		config.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		config.MinConns = opts.MinConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("statepg: connect: %w", err)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Store{pool: pool, now: opts.Now}
	if err := s.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := s.ensureSchema(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the shared connection pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Ping is the readiness probe for the shared authority.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("statepg: authority is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.pool.Ping(ctx); err != nil {
		return mapDBError(err)
	}
	return nil
}

func (s *Store) ensureSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS gripline_schema (singleton BOOLEAN PRIMARY KEY, version INTEGER NOT NULL)`,
		`INSERT INTO gripline_schema (singleton, version) VALUES (TRUE, 1) ON CONFLICT (singleton) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS gripline_credentials (
			credential_id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			verifier BYTEA NOT NULL,
			verifier_version INTEGER NOT NULL,
			pepper_version INTEGER NOT NULL,
			status INTEGER NOT NULL,
			security JSONB NOT NULL,
			policy_id TEXT NOT NULL,
			plan_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ,
			rotated_at TIMESTAMPTZ,
			last_seen_at TIMESTAMPTZ,
			revision BIGINT NOT NULL,
			UNIQUE (pepper_version, verifier)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_credential_transitions (
			id BIGSERIAL PRIMARY KEY,
			at TIMESTAMPTZ NOT NULL,
			request_id TEXT NOT NULL,
			credential_id TEXT NOT NULL,
			before_status INTEGER NOT NULL,
			after_status INTEGER NOT NULL,
			risk_score INTEGER NOT NULL,
			revision BIGINT NOT NULL,
			policy_revision INTEGER NOT NULL,
			evidence_codes JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_lanes (
			credential_id TEXT NOT NULL,
			lane_id TEXT NOT NULL,
			record JSONB NOT NULL,
			PRIMARY KEY (credential_id, lane_id)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_evidence (
			scope TEXT NOT NULL,
			subject_id TEXT NOT NULL,
			evidence_id TEXT NOT NULL,
			item JSONB NOT NULL,
			PRIMARY KEY (scope, subject_id, evidence_id)
		)`,
		`CREATE INDEX IF NOT EXISTS gripline_evidence_subject_idx ON gripline_evidence (scope, subject_id)`,
	}
	for _, statement := range statements {
		if _, err := s.pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("statepg: ensure schema: %w", mapDBError(err))
		}
	}
	var version int
	if err := s.pool.QueryRow(ctx, `SELECT version FROM gripline_schema WHERE singleton=TRUE`).Scan(&version); err != nil {
		return fmt.Errorf("statepg: read schema version: %w", err)
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("%w: found %d, supported %d", ErrMigrationRequired, version, currentSchemaVersion)
	}
	return nil
}

func begin(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
}

func mapDBError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return err
}

func zeroTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
