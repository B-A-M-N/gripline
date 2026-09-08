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
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options configures a PostgreSQL authority. DSN must come from a secret
// reference or environment expansion; it is never persisted by this package.
type Options struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	Now             func() time.Time
	NodeID          string
	LeaseTTL        time.Duration
	RenewEvery      time.Duration
	MaxSourceScopes int
}

// Store is the shared transactional authority. Credential, lane, and evidence
// methods are split across files but use this same pool and transaction model.
type Store struct {
	pool            *pgxpool.Pool
	now             func() time.Time
	nodeID          string
	instanceID      string
	nodeEpoch       int64
	fenced          atomic.Bool
	leaseTTL        time.Duration
	maxSourceScopes int
	leaseStop       chan struct{}
	leaseDone       chan struct{}
	membershipStop  chan struct{}
	membershipDone  chan struct{}
}

// Schema version 1 is the original clustered-authority layout. Version 2
// adds request-correlated resource leases, credential transition receipts,
// and the shared audit/state tables now used by the runtime. Version 3 binds
// a request id to its resource payload. Version 4 adds node-instance fencing
// to membership and resource leases. Keep the marker versioned even though
// the DDL below is idempotent: CREATE TABLE IF NOT EXISTS cannot add columns
// to an already initialized database.
const currentSchemaVersion = 4

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
	if opts.LeaseTTL <= 0 {
		opts.LeaseTTL = 30 * time.Second
	}
	if opts.MaxSourceScopes <= 0 {
		opts.MaxSourceScopes = 4096
	}
	if opts.RenewEvery <= 0 || opts.RenewEvery >= opts.LeaseTTL/2 {
		opts.RenewEvery = opts.LeaseTTL / 3
	}
	s := &Store{pool: pool, now: opts.Now, nodeID: opts.NodeID, leaseTTL: opts.LeaseTTL, maxSourceScopes: opts.MaxSourceScopes,
		leaseStop: make(chan struct{}), leaseDone: make(chan struct{})}
	if err := s.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := s.ensureSchema(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if s.nodeID != "" {
		if err := s.registerNode(ctx); err != nil {
			pool.Close()
			return nil, err
		}
		s.membershipStop = make(chan struct{})
		s.membershipDone = make(chan struct{})
		go s.membershipHeartbeat()
	}
	go s.leaseReaper()
	return s, nil
}

// Close releases the shared connection pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		if s.membershipStop != nil {
			select {
			case <-s.membershipStop:
			default:
				close(s.membershipStop)
				<-s.membershipDone
			}
		}
		if s.nodeID != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.markNodeStopped(ctx)
			cancel()
		}
		select {
		case <-s.leaseStop:
		default:
			close(s.leaseStop)
			<-s.leaseDone
		}
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("statepg: begin schema migration: %w", mapDBError(err))
	}
	defer tx.Rollback(ctx)
	// All nodes take the same advisory lock while applying idempotent DDL and
	// checking the schema marker. This keeps rolling starts from observing a
	// half-created authority schema.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('gripline-authority-schema'))`); err != nil {
		return fmt.Errorf("statepg: schema lock: %w", mapDBError(err))
	}
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
		`CREATE TABLE IF NOT EXISTS gripline_security_transitions (
			sequence BIGSERIAL PRIMARY KEY,
			at TIMESTAMPTZ NOT NULL,
			kind TEXT NOT NULL,
			request_id TEXT NOT NULL,
			credential_id TEXT NOT NULL,
			lane_id TEXT NOT NULL,
			before_state TEXT NOT NULL,
			after_state TEXT NOT NULL,
			risk_score INTEGER NOT NULL,
			revision BIGINT NOT NULL,
			policy_revision INTEGER NOT NULL,
			evidence_codes JSONB NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS gripline_security_transitions_cursor_idx ON gripline_security_transitions (sequence)`,
		`CREATE TABLE IF NOT EXISTS gripline_lanes (
			credential_id TEXT NOT NULL,
			lane_id TEXT NOT NULL,
			record JSONB NOT NULL,
			PRIMARY KEY (credential_id, lane_id)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_lane_guards (
			credential_id TEXT PRIMARY KEY,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_lane_operator_audit (
			id BIGSERIAL PRIMARY KEY,
			at TIMESTAMPTZ NOT NULL,
			credential_id TEXT NOT NULL,
			lane_id TEXT NOT NULL,
			actor TEXT NOT NULL,
			action INTEGER NOT NULL,
			before_state TEXT NOT NULL,
			after_state TEXT NOT NULL,
			revision BIGINT NOT NULL,
			reason TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_operator_posture (
			singleton BOOLEAN PRIMARY KEY,
			posture INTEGER NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_operator_audit (
			sequence BIGSERIAL PRIMARY KEY,
			at TIMESTAMPTZ NOT NULL,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT NOT NULL,
			reason TEXT NOT NULL,
			posture TEXT NOT NULL,
			committed BOOLEAN NOT NULL,
			detail TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_admission_audit (
			sequence BIGSERIAL PRIMARY KEY,
			at TIMESTAMPTZ NOT NULL,
			request_id TEXT NOT NULL,
			credential_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			lane_id TEXT NOT NULL,
			posture TEXT NOT NULL,
			authorized BOOLEAN NOT NULL,
			reason TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_policy_manifest (
			singleton BOOLEAN PRIMARY KEY,
			manifest JSONB NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_policy_artifacts (
			policy_id TEXT NOT NULL,
			revision INTEGER NOT NULL,
			digest TEXT NOT NULL,
			artifact JSONB NOT NULL,
			PRIMARY KEY (policy_id, revision, digest)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_policy_audit (
			sequence BIGSERIAL PRIMARY KEY,
			event JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_adaptive_state (
			name TEXT PRIMARY KEY,
			data BYTEA NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_resource_buckets (
			scope INTEGER NOT NULL,
			scope_id TEXT NOT NULL,
			dimension INTEGER NOT NULL,
			capacity DOUBLE PRECISION NOT NULL,
			refill_per DOUBLE PRECISION NOT NULL,
			refill_in_ns BIGINT NOT NULL,
			available DOUBLE PRECISION NOT NULL,
			concurrency_used INTEGER NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (scope, scope_id, dimension)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_resource_source_scopes (
			scope_id TEXT PRIMARY KEY,
			last_used_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_resource_leases (
			lease_id TEXT PRIMARY KEY,
			request_id TEXT NOT NULL UNIQUE,
			request_fingerprint TEXT NOT NULL DEFAULT '',
			node_id TEXT NOT NULL,
			node_epoch BIGINT NOT NULL DEFAULT 0,
			state TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			forwarded_at TIMESTAMPTZ,
			settled_at TIMESTAMPTZ,
			released_at TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS gripline_resource_leases_expiry_idx ON gripline_resource_leases (state, expires_at)`,
		`CREATE TABLE IF NOT EXISTS gripline_resource_holds (
			lease_id TEXT NOT NULL REFERENCES gripline_resource_leases(lease_id),
			scope INTEGER NOT NULL,
			scope_id TEXT NOT NULL,
			dimension INTEGER NOT NULL,
			amount DOUBLE PRECISION NOT NULL,
			settled BOOLEAN NOT NULL DEFAULT FALSE,
			PRIMARY KEY (lease_id, scope, scope_id, dimension)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_credential_receipts (
			request_id TEXT NOT NULL,
			credential_id TEXT NOT NULL,
			changed BOOLEAN NOT NULL,
			before_record JSONB NOT NULL,
			after_record JSONB NOT NULL,
			PRIMARY KEY (request_id, credential_id)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_membership (
			node_id TEXT PRIMARY KEY,
			instance_id TEXT NOT NULL DEFAULT '',
			node_epoch BIGINT NOT NULL DEFAULT 0,
			protocol_version INTEGER NOT NULL,
			schema_version INTEGER NOT NULL,
			state TEXT NOT NULL,
			last_seen_at TIMESTAMPTZ NOT NULL,
			drain_until TIMESTAMPTZ
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
		if _, err := tx.Exec(ctx, statement); err != nil {
			return fmt.Errorf("statepg: ensure schema: %w", mapDBError(err))
		}
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT version FROM gripline_schema WHERE singleton=TRUE`).Scan(&version); err != nil {
		return fmt.Errorf("statepg: read schema version: %w", err)
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("%w: found %d, supported %d", ErrMigrationRequired, version, currentSchemaVersion)
	}
	if version < 1 {
		return fmt.Errorf("%w: unsupported schema version %d", ErrMigrationRequired, version)
	}
	if version == 1 {
		// The first PostgreSQL prototype stored automatic credential transitions
		// in a credential-specific table. Preserve those rows in the unified,
		// cursor-readable transition stream before advancing the marker.
		if _, err := tx.Exec(ctx, `DO $$
			BEGIN
				IF to_regclass('public.gripline_credential_transitions') IS NOT NULL THEN
					INSERT INTO gripline_security_transitions
						(at, kind, request_id, credential_id, lane_id, before_state, after_state,
						 risk_score, revision, policy_revision, evidence_codes)
					SELECT at, 'credential_status', request_id, credential_id, '',
						CASE before_status
							WHEN 0 THEN 'NORMAL' WHEN 1 THEN 'WATCH' WHEN 2 THEN 'CONSTRAINED'
							WHEN 3 THEN 'QUARANTINED' WHEN 4 THEN 'REVOKED' ELSE 'UNKNOWN' END,
						CASE after_status
							WHEN 0 THEN 'NORMAL' WHEN 1 THEN 'WATCH' WHEN 2 THEN 'CONSTRAINED'
							WHEN 3 THEN 'QUARANTINED' WHEN 4 THEN 'REVOKED' ELSE 'UNKNOWN' END,
						risk_score, revision, policy_revision, evidence_codes
					FROM gripline_credential_transitions;
				END IF;
			END
			$$`); err != nil {
			return fmt.Errorf("statepg: migrate credential transitions: %w", mapDBError(err))
		}
		// Older version-1 databases predate request_id on resource leases. Fill
		// it from the already-unique lease id, then enforce the new invariant.
		for _, statement := range []string{
			`ALTER TABLE gripline_resource_leases ADD COLUMN IF NOT EXISTS request_id TEXT`,
			`UPDATE gripline_resource_leases SET request_id=lease_id WHERE request_id IS NULL OR request_id=''`,
			`ALTER TABLE gripline_resource_leases ALTER COLUMN request_id SET NOT NULL`,
			`CREATE UNIQUE INDEX IF NOT EXISTS gripline_resource_leases_request_id_idx ON gripline_resource_leases (request_id)`,
		} {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return fmt.Errorf("statepg: migrate resource leases: %w", mapDBError(err))
			}
		}
		version = 2
	}
	if version == 2 {
		if _, err := tx.Exec(ctx, `ALTER TABLE gripline_resource_leases ADD COLUMN IF NOT EXISTS request_fingerprint TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("statepg: migrate resource request fingerprint: %w", mapDBError(err))
		}
		version = 3
	}
	if version == 3 {
		for _, statement := range []string{
			`ALTER TABLE gripline_membership ADD COLUMN IF NOT EXISTS instance_id TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE gripline_membership ADD COLUMN IF NOT EXISTS node_epoch BIGINT NOT NULL DEFAULT 0`,
			`ALTER TABLE gripline_resource_leases ADD COLUMN IF NOT EXISTS node_epoch BIGINT NOT NULL DEFAULT 0`,
		} {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return fmt.Errorf("statepg: migrate node fencing: %w", mapDBError(err))
			}
		}
		version = 4
	}
	if version != currentSchemaVersion {
		return fmt.Errorf("%w: unsupported migration state %d", ErrMigrationRequired, version)
	}
	if _, err := tx.Exec(ctx, `UPDATE gripline_schema SET version=$1 WHERE singleton=TRUE`, currentSchemaVersion); err != nil {
		return fmt.Errorf("statepg: record schema version: %w", mapDBError(err))
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("statepg: commit schema migration: %w", mapDBError(err))
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
