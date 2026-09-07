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
	bucketOperatorState = []byte("operator_state")       // "posture" -> Posture
	keySchemaVersion    = []byte("schema_version")
	keyPosture          = []byte("posture")
	keyAuditSequence    = []byte("audit_sequence")
)

const currentSchemaVersion = 1

// ErrMigrationRequired is returned when a database carries a schema version
// other than the one this build understands (P1.22). Until real migration
// machinery exists, an OLDER schema must fail closed too — silently accepting
// it would make the "versioned/migratable" claim a lie the first time the
// schema actually changes.
var ErrMigrationRequired = errors.New("statebolt: database schema version requires migration (unsupported for this build)")

// Options configures opening a state database.
type Options struct {
	// Now is the clock used for timestamps (tests).
	Now func() time.Time
}

// Store is one bbolt-backed state authority. It is safe for concurrent use;
// bbolt serializes writers. It satisfies credential.Registry, lane.Repository,
// and evidence.Store.
type Store struct {
	db  *bolt.DB
	now func() time.Time
	// mu guards the small policy-side knobs below (they are written once at
	// terminator construction, read on every lane admission).
	mu sync.RWMutex
	// securityOverride carries the compiled policy's lane security hysteresis
	// (P0.13); zero means defaults.
	securityOverride lane.SecurityHysteresis
	// laneLimitsFn provides the lane explosion limits (policy-compiled). Nil
	// uses lane.DefaultLimits.
	laneLimitsFn func() lane.Limits
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
	// 0600: the DB holds verifiers (public material) and operator audit but its
	// on-disk access must still be restricted by default (defense in depth).
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("statebolt: open %s: %w", path, err)
	}
	s := &Store{db: db, now: opts.Now}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// init creates the schema buckets and stamps/validates the schema version.
func (s *Store) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			bucketMeta, bucketCredentials, bucketCredVerifier, bucketLanes,
			bucketEvidence, bucketOperatorAudit, bucketOperatorState,
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
		// P1.22: until explicit migrations exist, ONLY the exact current schema
		// is acceptable — an older database fails closed with
		// ErrMigrationRequired rather than being silently read with semantics
		// it was not written under.
		got := btoi(v)
		if got != currentSchemaVersion {
			return fmt.Errorf("statebolt: database schema %d, supported %d: %w", got, currentSchemaVersion, ErrMigrationRequired)
		}
		return nil
	})
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping proves the database answers reads (P1-24 readiness probe). It performs
// a trivial read transaction — cheap, lock-free against writers (bbolt MVCC).
func (s *Store) Ping() error {
	return s.db.View(func(tx *bolt.Tx) error {
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
