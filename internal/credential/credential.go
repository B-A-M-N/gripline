// Package credential models the operational credential: the keyed verifier
// derivation, the persisted CredentialRecord (which stores a verifier, never
// the raw key — INV-1), the credential status state machine with hysteresis,
// and the Registry lookup interface.
//
// High-entropy API keys use this design. Pepper rotation supports multiple
// active verifier versions during migration. The pepper key material must live
// in a separate secret store (HSM / KMS) and is never persisted here.
package credential

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/B-A-M-N/gripline/internal/secret"
)

// RevokedError indicates authentication was attempted for a revoked credential.
var RevokedError = errors.New("credential: revoked")

// UnknownError indicates the presented credential did not match any record.
var UnknownError = errors.New("credential: unknown")

// Status is the credential lifecycle state (§30 of the spec).
type Status int

const (
	StatusNormal Status = iota
	StatusWatch
	StatusConstrained
	StatusQuarantined
	StatusRevoked
)

func (s Status) String() string {
	switch s {
	case StatusNormal:
		return "NORMAL"
	case StatusWatch:
		return "WATCH"
	case StatusConstrained:
		return "CONSTRAINED"
	case StatusQuarantined:
		return "QUARANTINED"
	case StatusRevoked:
		return "REVOKED"
	default:
		return "UNKNOWN"
	}
}

// IsActive reports whether a credential in this status may still authenticate.
// REVOKED never authenticates (INV-13). QUARANTINED denies but is a
// reversible lifecycle state distinct from REVOKED.
func (s Status) IsActive() bool {
	return s != StatusRevoked
}

// CredentialRecord is the persisted operational row. The verifier, not the raw
// key, is stored (INV-1, T3).
type CredentialRecord struct {
	CredentialID string
	AccountID    string
	// Verifier is HMAC-SHA256(pepper, raw) — never the raw key.
	Verifier        []byte
	VerifierVersion int // verifier algorithm version
	PepperVersion   int // active pepper key version used to derive Verifier
	Status          Status
	// Security is the persisted hysteresis state (P0.5): the durable, reproducible
	// record of risk observations that drive status transitions. It lives on the
	// credential row so restart and replication do not erase escalation history.
	Security SecurityState
	PolicyID string
	PlanID   string
	CreatedAt time.Time
	ExpiresAt time.Time
	RotatedAt time.Time
	LastSeenAt time.Time
	Revision  int // monotonic; echoed as cred_rev in internal assertions
}

// Credential is the resolved authentication outcome handed to the terminator.
// It never carries the raw secret.
type Credential struct {
	CredentialID string
	AccountID    string
	PolicyID     string
	PlanID       string
	Status       Status
	Revision     int
}

// CredentialExpiredError indicates the record's ExpiresAt has passed (§75).
var CredentialExpiredError = errors.New("credential: expired")

// Authenticatable reports whether a record in its current state may attempt
// authentication: not revoked (INV-13), not quarantined (§30 — requests from a
// quarantined credential are denied), and not expired (§75). Presentation of a
// quarantined credential must fail authentication BEFORE any policy lookup, so
// it cannot bypass credential-level policy (INV-6).
func (rec *CredentialRecord) Authenticatable(now time.Time) error {
	if rec == nil {
		return UnknownError
	}
	switch rec.Status {
	case StatusRevoked:
		return RevokedError
	case StatusQuarantined:
		return CredentialQuarantinedError
	}
	// Expiry is inclusive-invalid: a credential is expired AT its expiration
	// instant (now == ExpiresAt fails), matching assertion/evidence semantics
	// (P0.21/P0.14).
	if !rec.ExpiresAt.IsZero() && !now.Before(rec.ExpiresAt) {
		return CredentialExpiredError
	}
	return nil
}

// CredentialQuarantinedError indicates authentication was attempted for a
// quarantined credential (§30: requests from the affected scope are denied).
var CredentialQuarantinedError = errors.New("credential: quarantined")

// supportedVerifierVersion is the only verifier algorithm this build accepts.
// Unknown algorithm versions fail closed (P0.18).
const supportedVerifierVersion = 1

// Validate reports whether a record is structurally sound enough to persist or
// authenticate (P0.17/P0.18). It refuses malformed records rather than letting
// them occupy storage: empty id, no verifier, an unknown verifier algorithm,
// revision < 1, or an impossible createdAt.
func (rec *CredentialRecord) Validate() error {
	if rec == nil {
		return errors.New("credential: nil record")
	}
	if rec.CredentialID == "" {
		return errors.New("credential: empty credential id")
	}
	if len(rec.Verifier) == 0 {
		return errors.New("credential: record has no verifier")
	}
	// Version 0 is the legacy "unversioned" marker used by pre-P0.18 persisted
	// records; version 1 is the modern HMAC-SHA256 verifier. Any other explicit
	// version is an unknown algorithm and fails closed (P0.18).
	if rec.VerifierVersion != 0 && rec.VerifierVersion != supportedVerifierVersion {
		return fmt.Errorf("credential: unsupported verifier algorithm version %d (fail closed, P0.18)", rec.VerifierVersion)
	}
	if rec.Revision < 1 {
		return errors.New("credential: revision must be >= 1")
	}
	if !rec.CreatedAt.IsZero() && rec.CreatedAt.After(time.Now()) {
		return errors.New("credential: createdAt in the future")
	}
	return nil
}

// Verifier derives the stored verifier for a raw secret under a pepper key set.
// The returned digest is what a CredentialStore persists and what lookup
// compares against, sealed within the secret boundary.
func Verifier(secret *secret.SealedSecret, key *PepperKey) []byte {
	return secret.DigestHMAC(key.Key)
}

// PepperKey is one active pepper version's key material. Key lives in the
// secret store; the struct is a handle. It deliberately carries key bytes only
// so NewPepperRing can ingest them at construction — and it implements an
// active redaction surface (P0.15) so that if the config struct is ever
// formatted, logged, or %#v'd, it emits "<redacted>" instead of the key bytes.
// The ring copies the bytes at ingestion and this construction-time handle is
// not retained.
type PepperKey struct {
	Version int
	Key     []byte
}

// Format implements fmt.Formatter and always redacts (P0.15): no flag, verb,
// or width combination may reach the key bytes.
func (k PepperKey) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, "<redacted>")
}

// String implements fmt.Stringer (%s/%v).
func (k PepperKey) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer (%#v).
func (k PepperKey) GoString() string { return "<redacted>" }

var (
	_ fmt.Formatter  = PepperKey{}
	_ fmt.Stringer   = PepperKey{}
	_ fmt.GoStringer = PepperKey{}
)

// PepperRing holds the active pepper versions for rotation (§16). Lookup must
// accept the version recorded on each stored verifier even after rotation
// introduces a newer one.
type PepperRing struct {
	active map[int][]byte
	now    func() time.Time
}

// Format implements fmt.Formatter and always redacts (P0.16). VALUE receiver:
// a struct copy of a PepperRing must redact identically — the ring holds live
// pepper key material (map[int][]byte), and a copy of a pointer-receiver
// formatter type falls back to struct formatting, exposing the map.
func (r PepperRing) Format(f fmt.State, verb rune) { fmt.Fprint(f, "<redacted>") }

// String implements fmt.Stringer (value receiver, P0.16).
func (r PepperRing) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer (%#v; value receiver, P0.16).
func (r PepperRing) GoString() string { return "<redacted>" }

var (
	_ fmt.Formatter  = PepperRing{}
	_ fmt.Stringer   = PepperRing{}
	_ fmt.GoStringer = PepperRing{}
)

// NewPepperRing builds a ring from one or more versions. A later version is
// "active" for new verifiers; all versions remain valid for comparison.
// Versions with empty key material or negative version numbers are refused:
// an HMAC under an empty key is publicly computable, which would make stored
// verifiers enumerable — the failure INV-1 exists to prevent. Key material is
// COPIED on ingestion, so later mutation of the caller's slice cannot alter
// live keys. A ring built from only invalid versions errors rather than
// failing open.
func NewPepperRing(versions ...*PepperKey) (*PepperRing, error) {
	r := &PepperRing{active: make(map[int][]byte, len(versions)), now: time.Now}
	for _, v := range versions {
		if v == nil {
			continue
		}
		if v.Version < 0 {
			return nil, fmt.Errorf("credential: negative pepper version %d", v.Version)
		}
		if len(v.Key) == 0 {
			return nil, fmt.Errorf("credential: pepper version %d has empty key", v.Version)
		}
		if _, dup := r.active[v.Version]; dup {
			return nil, fmt.Errorf("credential: duplicate pepper version %d", v.Version)
		}
		r.active[v.Version] = append([]byte(nil), v.Key...)
	}
	if len(r.active) == 0 {
		return nil, fmt.Errorf("credential: pepper ring requires at least one keyed version")
	}
	return r, nil
}

// MustPepperRing is NewPepperRing with a panic on invalid configuration. For
// process-startup wiring where an unusable pepper ring is a deployment error,
// not a runtime condition to handle (fail closed at boot).
func MustPepperRing(versions ...*PepperKey) *PepperRing {
	r, err := NewPepperRing(versions...)
	if err != nil {
		panic(err)
	}
	return r
}

// WithClock injects a clock (tests).
func (r *PepperRing) WithClock(now func() time.Time) *PepperRing {
	if now != nil {
		r.now = now
	}
	return r
}

// Get returns a COPY of the key material for a version, or false if unknown.
// Returning the internal slice would let a caller mutate the live pepper ring
// (P0.16); callers that only need a verifier should use DeriveVerifier instead
// so key bytes never leave the ring.
func (r *PepperRing) Get(version int) ([]byte, bool) {
	k, ok := r.active[version]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), k...), true
}

// DeriveVerifier folds a sealed secret under the pepper key for a version,
// returning the verifier digest. The pepper key bytes never leave the ring
// (P0.16): the caller hands in the sealed secret and gets back only the one-way
// digest that a registry persists. Returns nil if the secret or key is unusable
// (matches SealedSecret.DigestHMAC fail-closed behavior).
func (r *PepperRing) DeriveVerifier(presented *secret.SealedSecret, version int) []byte {
	k, ok := r.active[version]
	if !ok || len(k) == 0 {
		return nil
	}
	return presented.DigestHMAC(k)
}

// DeriveAllActiveVerifiers folds a sealed secret under every active pepper
// version, returning a map version->verifier digest. Used at lookup time to
// test presentation across the rotation window without extracting key bytes.
func (r *PepperRing) DeriveAllActiveVerifiers(presented *secret.SealedSecret) map[int][]byte {
	out := make(map[int][]byte, len(r.active))
	for v, k := range r.active {
		if len(k) == 0 {
			continue
		}
		out[v] = presented.DigestHMAC(k)
	}
	return out
}

// Latest returns the highest configured version.
func (r *PepperRing) Latest() int {
	best := -1
	for v := range r.active {
		if v > best {
			best = v
		}
	}
	return best
}

// Versions returns the configured versions in ascending order. Authentication
// iterates THIS list (never the 0..latest integer range, which is pathological
// for sparse/high version numbers).
func (r *PepperRing) Versions() []int {
	out := make([]int, 0, len(r.active))
	for v := range r.active {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// Validate checks a presented secret against a stored record: it derives the
// verifier with the pepper version recorded on the record and compares
// constant-time. Revoked and expired credentials fail (INV-13 + §75).
func (r *PepperRing) Validate(presented *secret.SealedSecret, rec *CredentialRecord) (*Credential, error) {
	if rec == nil || presented == nil || presented.Zeroed() {
		return nil, UnknownError
	}
	if err := rec.Authenticatable(r.now()); err != nil {
		return nil, err
	}
	key, ok := r.Get(rec.PepperVersion)
	if !ok {
		return nil, fmt.Errorf("credential: no pepper for version %d", rec.PepperVersion)
	}
	derived := presented.DigestHMAC(key)
	if !hmac.Equal(derived, rec.Verifier) {
		return nil, UnknownError
	}
	return &Credential{
		CredentialID: rec.CredentialID,
		AccountID:    rec.AccountID,
		PolicyID:     rec.PolicyID,
		PlanID:       rec.PlanID,
		Status:       rec.Status,
		Revision:     rec.Revision,
	}, nil
}

// --- Credential status state machine with hysteresis (spec §31) -------------

// Hysteresis holds the risk thresholds and dwell requirements governing
// credential-state transitions. All values are policy-controlled.
type Hysteresis struct {
	WatchThresh           int           // risk >= this for >=2 obs → WATCH
	ConstrainedThresh     int           // risk >= this → CONSTRAINED
	QuarantineThresh      int           // risk >= this → QUARANTINED
	ConstrainedDownThresh int           // risk < this for dwell → CONSTRAINED→WATCH
	WatchDownThresh       int           // risk < this for dwell → WATCH→NORMAL
	ConstrainedDwell      time.Duration // WATCH→CONSTRAINED→WATCH dwell
	WatchDwell            time.Duration // WATCH→NORMAL dwell
	WatchObs              int           // qualifying observations to enter WATCH
	// MaxAutomaticStatus is the ceiling on AUTOMATIC escalation (P0.14). Zero
	// means no ceiling (QUARANTINE reachable). Gate H: while automatic
	// quarantine is policy-disabled, the terminator sets this to CONSTRAINED so
	// a hot observation escalates normally up to CONSTRAINED but never commits
	// an operator-unvalidated QUARANTINED status. The REAL score always flows
	// into the machine — the old code mutilated the score to Constrained-1,
	// which could never cross the CONSTRAINED threshold, so high-risk
	// credentials stuck at WATCH forever and recorded a falsified risk history.
	// The reducer decides states; policy gating decides which transitions are
	// permitted.
	MaxAutomaticStatus Status
}

// DefaultHysteresis returns the spec §31 example defaults.
func DefaultHysteresis() Hysteresis {
	return Hysteresis{
		WatchThresh:           30,
		ConstrainedThresh:     55,
		QuarantineThresh:      80,
		ConstrainedDownThresh: 40,
		WatchDownThresh:       20,
		ConstrainedDwell:      15 * time.Minute,
		WatchDwell:            30 * time.Minute,
		WatchObs:              2,
	}
}

// obs is a single risk observation retaining state needed for dwell checks.
type obs struct {
	score int
	at    time.Time
}

// StateMachine tracks credential status across risk observations with
// hysteresis so transitions do not flap at score boundaries.
type StateMachine struct {
	hy  Hysteresis
	now func() time.Time
	// current/below tracking
	status Status
	score  int
	// WATCH entry needs watchObs qualifying observations.
	watchStreak   int
	belowSince    time.Time // time score last crossed below the down-threshold
	lastScoreTime time.Time
}

// NewStateMachine initializes a state machine in NORMAL.
func NewStateMachine(hy Hysteresis, now func() time.Time) *StateMachine {
	no := now
	if no == nil {
		no = time.Now
	}
	return &StateMachine{hy: hy, status: StatusNormal, now: no, belowSince: time.Time{}}
}

// Status returns the current credential status.
func (m *StateMachine) Status() Status { return m.status }

// SetStatus sets the machine's status to a specific value (seed from persisted
// state). It does not affect hysteresis metadata like belowSince — that
// metadata is process-local until retrained through observations.
func (m *StateMachine) SetStatus(s Status) { m.status = s }

// Score returns the current risk score.
func (m *StateMachine) Score() int { return m.score }

// Observe feeds a new risk observation for the credential and returns the new
// status. Transitions follow the spec §31 defaults governed by Hysteresis.
func (m *StateMachine) Observe(score int) Status {
	now := m.now()
	m.score = clamp01(score)

	// Direct escalation: a score at or above the quarantine threshold escalates
	// immediately from any active state (spec §36: MANUAL_CONFIRMED_COMPROMISE
	// = 100 quarantines; a low-confidence novelty signal must never). This
	// honors the quarantine boundary without waiting through the ladder.
	if m.status != StatusQuarantined && m.status != StatusRevoked && m.score >= m.hy.QuarantineThresh {
		m.status = StatusQuarantined
		m.belowSince = time.Time{}
		m.lastScoreTime = now
		return m.status
	}

	switch m.status {
	case StatusNormal:
		if m.score >= m.hy.WatchThresh {
			m.watchStreak++
			if m.watchStreak >= m.hy.WatchObs {
				m.status = StatusWatch
				m.belowSince = time.Time{}
			}
		} else {
			m.watchStreak = 0
		}

	case StatusWatch:
		if m.score >= m.hy.ConstrainedThresh {
			m.status = StatusConstrained
			m.belowSince = time.Time{}
		} else if m.score < m.hy.WatchDownThresh {
			if m.belowSince.IsZero() {
				m.belowSince = now
			} else if now.Sub(m.belowSince) >= m.hy.WatchDwell {
				m.status = StatusNormal
				m.watchStreak = 0
				m.belowSince = time.Time{}
			}
		} else {
			m.belowSince = time.Time{}
		}

	case StatusConstrained:
		if m.score >= m.hy.QuarantineThresh {
			m.status = StatusQuarantined
			m.belowSince = time.Time{}
		} else if m.score < m.hy.ConstrainedDownThresh {
			if m.belowSince.IsZero() {
				m.belowSince = now
			} else if now.Sub(m.belowSince) >= m.hy.ConstrainedDwell {
				m.status = StatusWatch
				m.belowSince = time.Time{}
			}
		} else {
			m.belowSince = time.Time{}
		}

	case StatusQuarantined:
		// Quarantine requires explicit lifecycle action to exit (no automatic
		// recovery from high-risk quarantine).

	case StatusRevoked:
		// Revoked is terminal until explicit lifecycle action.
	}

	m.lastScoreTime = now
	return m.status
}

func clamp01(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// IsAuthenticatable reports whether the machine's status permits authentication.
// It must answer identically to CredentialRecord.Authenticatable (§30): a
// quarantined credential is denied at authentication, not only revoked.
func (m *StateMachine) IsAuthenticatable() bool {
	return m.status != StatusRevoked && m.status != StatusQuarantined
}
