// Package statebolt is the single transactional persistence authority for a
// single-node Gripline deployment (P0.10/P0.18). It replaces ad-hoc Gob files
// with one bbolt database: credentials (+verifier index + security state),
// lanes, evidence, operator audit, and operator posture all live behind one
// write path, so a state mutation and its operator-audit record commit or fail
// together (P0.18) and a restart restores the same durable posture (P0.10).
//
// The store does NOT reimplement security semantics: it satisfies the existing
// credential.Registry / credential.SecurityStateRepository /
// credential.VerifierLookup and lane.Repository contracts and reuses the pure,
// resident transition helpers (credential.ReduceTransition,
// lane.ReduceLaneSecurity, ...). All persisted rows use versioned JSON
// envelopes (never bare current-struct Gob), so future schema changes are
// explicit and migratable.
package statebolt

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/lane"
)

// Bucket names (§schema). meta holds a schema marker; each logical bucket holds
// one record type. All values are versioned JSON envelopes.
var (
	bucketMeta          = []byte("meta")
	bucketCredentials   = []byte("credentials")
	bucketCredVerifier  = []byte("credential_verifiers") // "pepVer/verifierB64" -> credentialID
	bucketLanes         = []byte("lanes")                // "credID/laneID" -> lane record
	bucketEvidence      = []byte("evidence")             // subjectKey/id -> evidence
	bucketOperatorAudit = []byte("operator_audit")       // seq -> OperatorRecord
	bucketSecurityAudit = []byte("security_audit")       // seq -> SecurityTransitionRecord
	bucketOperatorState = []byte("operator_state")       // "posture" -> Posture
	bucketDetectorState = []byte("detector_state")       // bounded detector snapshots
	keySchemaVersion    = []byte("schema_version")
	keyPosture          = []byte("posture")
	keyAuditSequence    = []byte("audit_sequence")
	keySecuritySequence = []byte("security_sequence")
)

const currentSchemaVersion = 2

// ErrMigrationRequired is returned when a database carries a schema version
// newer than this build or cannot be migrated safely.
var ErrMigrationRequired = errors.New("statebolt: database schema version requires migration or is unsupported")

type schemaMigration struct {
	From  int
	To    int
	Apply func(*bolt.Tx) error
}

var schemaMigrations = []schemaMigration{
	{From: 1, To: 2, Apply: func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketDetectorState)
		return err
	}},
}

// Options configures opening a state database.
type Options struct {
	// Now is the clock used for timestamps (tests).
	Now func() time.Time
}

// Store is one bbolt-backed state authority. It is safe for concurrent use;
// bbolt serializes writers. It satisfies credential.Registry, lane.Repository,
// and evidence.Store.
type Store struct {
	db                 *bolt.DB
	now                func() time.Time
	lastSeenMu         sync.Mutex
	lastSeen           map[string]time.Time
	lastSeenInterval   time.Duration
	evidenceSweepMu    sync.Mutex
	evidenceSweepAfter []byte
	evidenceSweepStats EvidenceSweepStats
	// mu guards the small policy-side knobs below (they are written once at
	// terminator construction, read on every lane admission).
	mu sync.RWMutex
	// securityOverride carries the compiled policy's lane security hysteresis
	// (P0.13); zero means defaults.
	securityOverride lane.SecurityHysteresis
	// laneLimitsFn provides the lane explosion limits (policy-compiled). Nil
	// uses lane.DefaultLimits.
	laneLimitsFn func() lane.Limits
	txMu         sync.Mutex
	txCount      uint64
	txErrors     uint64
	txNanos      uint64
}

// TransactionStats is a low-cardinality view of bbolt activity. Latency is
// aggregate nanoseconds, not a per-request or per-credential label.
type TransactionStats struct {
	Transactions      uint64
	TransactionErrors uint64
	TransactionNanos  uint64
}

func (s *Store) recordTransaction(start time.Time, err error) {
	s.txMu.Lock()
	s.txCount++
	s.txNanos += uint64(time.Since(start))
	if err != nil {
		s.txErrors++
	}
	s.txMu.Unlock()
}

func (s *Store) update(fn func(*bolt.Tx) error) error {
	start := time.Now()
	err := s.db.Update(fn)
	s.recordTransaction(start, err)
	return err
}

func (s *Store) view(fn func(*bolt.Tx) error) error {
	start := time.Now()
	err := s.db.View(fn)
	s.recordTransaction(start, err)
	return err
}

// TransactionStats reports aggregate durable-state transaction activity.
func (s *Store) TransactionStats() TransactionStats {
	if s == nil {
		return TransactionStats{}
	}
	s.txMu.Lock()
	defer s.txMu.Unlock()
	return TransactionStats{Transactions: s.txCount, TransactionErrors: s.txErrors, TransactionNanos: s.txNanos}
}

// SetLaneLimits wires the lane explosion-limits provider (the runtime compiles
// it from policy). Must be called before serving traffic.
func (s *Store) SetLaneLimits(fn func() lane.Limits) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.laneLimitsFn = fn
}

// Open opens (creating if needed) the database at path and guarantees the
// bucket schema exists.
func Open(path string, opts Options) (*Store, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if path == "" {
		return nil, errors.New("statebolt: empty database path")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("statebolt: create dir: %w", err)
		}
	}
	if err := validateStateFile(path, true); err != nil {
		return nil, err
	}
	// 0600: the DB holds verifiers (public material) and operator audit but its
	// on-disk access must still be restricted by default (defense in depth).
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("statebolt: open %s: %w", path, err)
	}
	s := &Store{db: db, now: opts.Now, lastSeen: make(map[string]time.Time), lastSeenInterval: time.Minute}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func validateStateFile(path string, allowMissing bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("statebolt: inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("statebolt: database %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("statebolt: database %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("statebolt: database %s permissions %04o are too broad; require 0600", path, info.Mode().Perm())
	}
	return nil
}

// init creates the schema buckets and stamps/validates the schema version.
func (s *Store) init() error {
	var existingVersion int
	if err := s.view(func(tx *bolt.Tx) error {
		if meta := tx.Bucket(bucketMeta); meta != nil && meta.Get(keySchemaVersion) != nil {
			existingVersion = btoi(meta.Get(keySchemaVersion))
		}
		return nil
	}); err != nil {
		return err
	}
	if existingVersion > 0 && existingVersion < currentSchemaVersion {
		backupPath := fmt.Sprintf("%s.pre-migration-v%d", s.db.Path(), existingVersion)
		if err := s.view(func(tx *bolt.Tx) error { return tx.CopyFile(backupPath, 0o600) }); err != nil {
			return fmt.Errorf("statebolt: pre-migration backup: %w", err)
		}
	}
	return s.update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			bucketMeta, bucketCredentials, bucketCredVerifier, bucketLanes,
			bucketEvidence, bucketOperatorAudit, bucketSecurityAudit, bucketOperatorState, bucketDetectorState,
		} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("statebolt: create bucket %s: %w", b, err)
			}
		}
		meta := tx.Bucket(bucketMeta)
		v := meta.Get(keySchemaVersion)
		if v == nil {
			return meta.Put(keySchemaVersion, itob(currentSchemaVersion))
		}
		got := btoi(v)
		if got > currentSchemaVersion || got < 1 {
			return fmt.Errorf("statebolt: database schema %d, supported through %d: %w", got, currentSchemaVersion, ErrMigrationRequired)
		}
		for got < currentSchemaVersion {
			migrated := false
			for _, migration := range schemaMigrations {
				if migration.From != got {
					continue
				}
				if err := migration.Apply(tx); err != nil {
					return fmt.Errorf("statebolt: migrate schema %d to %d: %w", migration.From, migration.To, err)
				}
				got = migration.To
				migrated = true
				break
			}
			if !migrated {
				return fmt.Errorf("statebolt: no migration path from schema %d: %w", got, ErrMigrationRequired)
			}
		}
		return meta.Put(keySchemaVersion, itob(currentSchemaVersion))
	})
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping proves the database answers reads (P1-24 readiness probe). It performs
// a trivial read transaction — cheap, lock-free against writers (bbolt MVCC).
func (s *Store) Ping() error {
	return s.view(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketMeta) == nil {
			return errors.New("statebolt: meta bucket missing")
		}
		return nil
	})
}

// DBPath returns the on-disk path (diagnostics).
func (s *Store) DBPath() string { return s.db.Path() }

// --- low-level helpers ---

// itob encodes a uint64 as an 8-byte big-endian key (used for the audit
// sequence so lexicographic order == chronological order).
func itob(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

func btoi(b []byte) int {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return int(v)
}
