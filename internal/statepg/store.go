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
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	SourceScopeIdle time.Duration
	ConnectTimeout  time.Duration
	// OperationTimeout is reserved for callers that need a store-owned
	// default around remote operations. The request context remains the
	// authoritative upper bound when one is supplied.
	OperationTimeout time.Duration
	// Migrate grants this process permission to create or alter the authority
	// schema. Serving nodes must leave it false and only verify compatibility;
	// the dedicated migration command sets it true.
	Migrate bool
}

// Store is the shared transactional authority. Credential, lane, and evidence
// methods are split across files but use this same pool and transaction model.
type Store struct {
	pool             *pgxpool.Pool
	now              func() time.Time
	nodeID           string
	instanceID       string
	nodeEpoch        int64
	fenced           atomic.Bool
	leaseTTL         time.Duration
	maxSourceScopes  int
	sourceScopeIdle  time.Duration
	operationTimeout time.Duration
	leaseStop        chan struct{}
	leaseDone        chan struct{}
	membershipStop   chan struct{}
	membershipDone   chan struct{}
	cryptoReady      atomic.Bool
	cryptoObserved   atomic.Value // cryptoObservation
}

// Schema version 1 is the original clustered-authority layout. Version 2
// adds request-correlated resource leases, credential transition receipts,
// and the shared audit/state tables now used by the runtime. Version 3 binds
// a request id to its resource payload. Version 4 adds node-instance fencing
// to membership and resource leases. Version 5 adds keyed adaptive windows
// and baselines. Version 6 adds the cluster crypto identity record. Version 7
// adds durable control-operation claims. Version 8 adds evidence subject
// guards for deterministic first-write locking. Version 9 adds staged
// cluster-crypto generations and per-node capability acknowledgements. Version
// 10 adds per-node policy observations used as an activation barrier. Keep
// the marker versioned even though the DDL below is idempotent: CREATE TABLE
// IF NOT EXISTS cannot add columns to an already initialized database.
const currentSchemaVersion = 10

const maxTransactionAttempts = 3

const transactionRetryBaseDelay = 5 * time.Millisecond

var ErrMigrationRequired = errors.New("statepg: database schema requires migration")
var ErrDSNRequired = errors.New("statepg: DSN required")
var ErrInsecureTransport = errors.New("statepg: remote PostgreSQL requires authenticated TLS")

// SupportedSchemaVersion is the schema marker expected by serving nodes.
func SupportedSchemaVersion() int { return currentSchemaVersion }

// Open connects to PostgreSQL, verifies liveness, and either applies the
// authority schema (when Migrate is true) or verifies that an already-applied
// schema is compatible. Serving nodes must use the latter mode so their
// database role does not need DDL privileges.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.DSN == "" {
		return nil, ErrDSNRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 10 * time.Second
	}
	connectCtx, cancel := context.WithTimeout(ctx, opts.ConnectTimeout)
	defer cancel()
	config, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("statepg: parse DSN: %w", err)
	}
	if err := validateTransport(config); err != nil {
		return nil, err
	}
	// pgx uses this value for connections opened after the initial pool
	// creation too. Bounding only NewWithConfig would still allow a later
	// reconnect to block beyond the deployment's connection budget.
	config.ConnConfig.ConnectTimeout = opts.ConnectTimeout
	if opts.MaxConns > 0 {
		config.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		config.MinConns = opts.MinConns
	}
	pool, err := pgxpool.NewWithConfig(connectCtx, config)
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
	if opts.SourceScopeIdle <= 0 {
		opts.SourceScopeIdle = 10 * time.Minute
	}
	if opts.RenewEvery <= 0 || opts.RenewEvery >= opts.LeaseTTL/2 {
		opts.RenewEvery = opts.LeaseTTL / 3
	}
	if opts.OperationTimeout <= 0 {
		opts.OperationTimeout = 2 * time.Second
	}
	s := &Store{pool: pool, now: opts.Now, nodeID: opts.NodeID, leaseTTL: opts.LeaseTTL, maxSourceScopes: opts.MaxSourceScopes, sourceScopeIdle: opts.SourceScopeIdle, operationTimeout: opts.OperationTimeout,
		leaseStop: make(chan struct{}), leaseDone: make(chan struct{})}
	if err := s.Ping(connectCtx); err != nil {
		pool.Close()
		return nil, err
	}
	if opts.Migrate {
		if err := s.ensureSchema(connectCtx); err != nil {
			pool.Close()
			return nil, err
		}
	} else if err := CheckSchemaCompatibility(connectCtx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	if s.nodeID != "" {
		if err := s.registerNode(connectCtx); err != nil {
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

// operationContext gives every ordinary store operation a finite authority
// budget. A caller deadline remains authoritative because WithTimeout uses
// the earlier of the two deadlines. Background maintenance uses its own
// explicit contexts and does not rely on this helper.
func (s *Store) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.operationTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, s.operationTimeout)
}

// SchemaStatus is the read-only result used by migration planning and
// operator status. A missing marker is represented without mutating the
// database.
type SchemaStatus struct {
	Present          bool
	Version          int
	SupportedVersion int
}

// InspectSchema reads the schema marker without taking the migration lock or
// executing DDL. It is safe to run with the serving runtime database role.
func InspectSchema(ctx context.Context, opts Options) (SchemaStatus, error) {
	status := SchemaStatus{SupportedVersion: currentSchemaVersion}
	if opts.DSN == "" {
		return status, ErrDSNRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 10 * time.Second
	}
	connectCtx, cancel := context.WithTimeout(ctx, opts.ConnectTimeout)
	defer cancel()
	config, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		return status, fmt.Errorf("statepg: parse DSN: %w", err)
	}
	if err := validateTransport(config); err != nil {
		return status, err
	}
	config.ConnConfig.ConnectTimeout = opts.ConnectTimeout
	if opts.MaxConns > 0 {
		config.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		config.MinConns = opts.MinConns
	}
	pool, err := pgxpool.NewWithConfig(connectCtx, config)
	if err != nil {
		return status, fmt.Errorf("statepg: connect: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(connectCtx); err != nil {
		return status, mapDBError(err)
	}
	var version int
	err = pool.QueryRow(connectCtx, `SELECT version FROM gripline_schema WHERE singleton=TRUE`).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return status, nil
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return status, nil
		}
		return status, mapDBError(err)
	}
	status.Present = true
	status.Version = version
	return status, nil
}

// validateTransport rejects the libpq/pgx default "prefer" mode for remote
// authorities because its fallback can silently downgrade to plaintext. A
// local Unix socket or loopback connection is an explicit local deployment
// boundary; every other host must use a TLS configuration that authenticates
// the server (verify-full, or verify-ca with a peer-verification callback).
func validateTransport(config *pgxpool.Config) error {
	if config == nil {
		return errors.New("statepg: nil PostgreSQL connection config")
	}
	configs := []*pgconn.Config{{
		Host:      config.ConnConfig.Host,
		Port:      config.ConnConfig.Port,
		TLSConfig: config.ConnConfig.TLSConfig,
	}}
	for _, fallback := range config.ConnConfig.Fallbacks {
		configs = append(configs, &pgconn.Config{Host: fallback.Host, Port: fallback.Port, TLSConfig: fallback.TLSConfig})
	}
	for _, candidate := range configs {
		if candidate == nil {
			continue
		}
		network, _ := pgconn.NetworkAddress(candidate.Host, candidate.Port)
		if network == "unix" || isLoopbackDatabaseHost(candidate.Host) {
			continue
		}
		if candidate.TLSConfig == nil || (candidate.TLSConfig.InsecureSkipVerify && candidate.TLSConfig.VerifyPeerCertificate == nil) {
			return fmt.Errorf("%w: host %q", ErrInsecureTransport, candidate.Host)
		}
	}
	return nil
}

func isLoopbackDatabaseHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CheckSchemaCompatibility verifies that a serving node can use the
// authority layout without changing it. It deliberately rejects both older
// and newer markers; an explicit migration/upgrade procedure must establish
// compatibility before the node becomes ready.
func CheckSchemaCompatibility(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return ErrMigrationRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var version int
	err := pool.QueryRow(ctx, `SELECT version FROM gripline_schema WHERE singleton=TRUE`).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: schema marker is missing", ErrMigrationRequired)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return fmt.Errorf("%w: schema is not initialized", ErrMigrationRequired)
		}
		return mapDBError(err)
	}
	if version != currentSchemaVersion {
		return fmt.Errorf("%w: found %d, supported %d", ErrMigrationRequired, version, currentSchemaVersion)
	}
	return nil
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
		`CREATE TABLE IF NOT EXISTS gripline_control_operations (
			operation_id TEXT PRIMARY KEY,
			action TEXT NOT NULL,
			payload_fingerprint TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
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
		`CREATE TABLE IF NOT EXISTS gripline_adaptive_window_subjects (
			detector TEXT NOT NULL,
			subject TEXT NOT NULL,
			last_seen_at TIMESTAMPTZ NOT NULL,
			last_emit_at TIMESTAMPTZ,
			PRIMARY KEY (detector, subject)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_adaptive_window_keys (
			detector TEXT NOT NULL,
			subject TEXT NOT NULL,
			observation_key TEXT NOT NULL,
			observed_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (detector, subject, observation_key),
			FOREIGN KEY (detector, subject) REFERENCES gripline_adaptive_window_subjects(detector, subject) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS gripline_adaptive_window_keys_expiry_idx ON gripline_adaptive_window_keys (detector, observed_at)`,
		`CREATE TABLE IF NOT EXISTS gripline_adaptive_baselines (
			detector TEXT NOT NULL,
			subject TEXT NOT NULL,
			metric TEXT NOT NULL,
			ema DOUBLE PRECISION NOT NULL,
			sample_count BIGINT NOT NULL,
			last_seen_at TIMESTAMPTZ NOT NULL,
			last_emit_at TIMESTAMPTZ,
			PRIMARY KEY (detector, subject, metric)
		)`,
		`CREATE INDEX IF NOT EXISTS gripline_adaptive_window_subjects_seen_idx ON gripline_adaptive_window_subjects (detector, last_seen_at)`,
		`CREATE INDEX IF NOT EXISTS gripline_adaptive_baselines_seen_idx ON gripline_adaptive_baselines (detector, last_seen_at)`,
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
		`CREATE TABLE IF NOT EXISTS gripline_cluster_crypto (
			singleton BOOLEAN PRIMARY KEY,
			signer_active_kid INTEGER NOT NULL,
			signer_fingerprint TEXT NOT NULL,
			signer_active_fingerprint TEXT NOT NULL DEFAULT '',
			pepper_active_version INTEGER NOT NULL,
			pepper_fingerprint TEXT NOT NULL,
			pepper_active_fingerprint TEXT NOT NULL DEFAULT '',
			pseudonym_version INTEGER NOT NULL,
			pseudonym_fingerprint TEXT NOT NULL,
			pseudonym_active_fingerprint TEXT NOT NULL DEFAULT '',
			generation_epoch BIGINT NOT NULL DEFAULT 1,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`ALTER TABLE gripline_cluster_crypto ADD COLUMN IF NOT EXISTS generation_epoch BIGINT NOT NULL DEFAULT 1`,
		`ALTER TABLE gripline_cluster_crypto ADD COLUMN IF NOT EXISTS signer_active_fingerprint TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE gripline_cluster_crypto ADD COLUMN IF NOT EXISTS pepper_active_fingerprint TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE gripline_cluster_crypto ADD COLUMN IF NOT EXISTS pseudonym_active_fingerprint TEXT NOT NULL DEFAULT ''`,
		`CREATE TABLE IF NOT EXISTS gripline_cluster_crypto_generations (
			kind TEXT NOT NULL,
			generation INTEGER NOT NULL,
			fingerprint TEXT NOT NULL,
			state TEXT NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (kind, generation)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_cluster_crypto_acks (
			node_id TEXT NOT NULL,
			node_epoch BIGINT NOT NULL,
			kind TEXT NOT NULL,
			generation INTEGER NOT NULL,
			fingerprint TEXT NOT NULL,
			acknowledged_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (node_id, node_epoch, kind, generation)
		)`,
		`CREATE TABLE IF NOT EXISTS gripline_policy_node_state (
			node_id TEXT NOT NULL,
			node_epoch BIGINT NOT NULL,
			observed_policy_epoch BIGINT NOT NULL,
			observed_policy_id TEXT NOT NULL,
			observed_policy_revision INTEGER NOT NULL,
			observed_policy_digest TEXT NOT NULL,
			candidate_policy_id TEXT NOT NULL DEFAULT '',
			candidate_policy_revision INTEGER NOT NULL DEFAULT 0,
			candidate_policy_digest TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (node_id, node_epoch)
		)`,
		`CREATE INDEX IF NOT EXISTS gripline_policy_node_state_updated_idx ON gripline_policy_node_state (updated_at)`,
		`CREATE TABLE IF NOT EXISTS gripline_evidence (
			scope TEXT NOT NULL,
			subject_id TEXT NOT NULL,
			evidence_id TEXT NOT NULL,
			item JSONB NOT NULL,
			PRIMARY KEY (scope, subject_id, evidence_id)
		)`,
		`CREATE INDEX IF NOT EXISTS gripline_evidence_subject_idx ON gripline_evidence (scope, subject_id)`,
		`CREATE TABLE IF NOT EXISTS gripline_evidence_guards (
			scope TEXT NOT NULL,
			subject_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (scope, subject_id)
		)`,
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
	if version == 4 {
		// Version 5's keyed adaptive tables are created by the idempotent DDL
		// above; advancing the marker is sufficient for existing databases.
		version = 5
	}
	if version == 5 {
		// Version 6's cluster crypto identity table is created by the idempotent
		// DDL above; advancing the marker is sufficient for existing databases.
		version = 6
	}
	if version == 6 {
		// Version 7's control-operation claim table is created by the idempotent
		// DDL above; advancing the marker is sufficient for existing databases.
		version = 7
	}
	if version == 7 {
		// Version 8's evidence subject guard table is created by the idempotent
		// DDL above; advancing the marker is sufficient for existing databases.
		version = 8
	}
	if version == 8 {
		// Version 9's staged crypto capability tables and generation epoch
		// column are created by the idempotent DDL above.
		version = 9
	}
	if version == 9 {
		// Version 10's policy observation table is created by the idempotent
		// DDL above; advancing the marker is sufficient for existing databases.
		version = 10
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

// withTransactionRetry is the shared bounded retry primitive for serializable
// authority reducers. Domain errors are returned immediately; only PostgreSQL
// serialization failures and deadlocks are retried by the callback's error
// classification.
func withTransactionRetry(ctx context.Context, operation string, fn func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	for attempt := 0; attempt < maxTransactionAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = fn()
		if lastErr == nil || !retryableTransactionError(lastErr) {
			return lastErr
		}
		if attempt+1 < maxTransactionAttempts {
			if err := waitTransactionRetry(ctx, attempt); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("statepg: %s remained conflicted after retries: %w", operation, lastErr)
}

// waitTransactionRetry backs off only between retryable database conflicts.
// The small time-derived jitter prevents a group of replicas that collided on
// the same serializable transaction from immediately colliding again, while
// the context-aware timer keeps retry sleep inside the caller's deadline.
func waitTransactionRetry(ctx context.Context, attempt int) error {
	delay := transactionRetryBaseDelay << attempt
	jitterWindow := delay / 2
	if jitterWindow > 0 {
		jitter := time.Duration(time.Now().UnixNano() % int64(jitterWindow))
		delay += jitter
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
