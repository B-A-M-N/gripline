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
	"time"

	"github.com/freeinference/gripline/internal/secret"
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
	PolicyID        string
	PlanID          string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RotatedAt       time.Time
	LastSeenAt      time.Time
	Revision        int // monotonic; echoed as cred_rev in internal assertions
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
	if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
		return CredentialExpiredError
	}
	return nil
}

// CredentialQuarantinedError indicates authentication was attempted for a
// quarantined credential (§30: requests from the affected scope are denied).
var CredentialQuarantinedError = errors.New("credential: quarantined")

// Verifier derives the stored verifier for a raw secret under a pepper key set.
// The returned digest is what a CredentialStore persists and what lookup
// compares against, sealed within the secret boundary.
func Verifier(secret *secret.SealedSecret, key *PepperKey) []byte {
	return secret.DigestHMAC(key.Key)
}

// PepperKey is one active pepper version's key material. Key lives in the
// secret store; the struct is a handle.
type PepperKey struct {
	Version int
	Key     []byte
}

// PepperRing holds the active pepper versions for rotation (§16). Lookup must
// accept the version recorded on each stored verifier even after rotation
// introduces a newer one.
type PepperRing struct {
	active map[int][]byte
	now    func() time.Time
}

// NewPepperRing builds a ring from one or more versions. A later version is
// "active" for new verifiers; all versions remain valid for comparison.
func NewPepperRing(versions ...*PepperKey) *PepperRing {
	r := &PepperRing{active: make(map[int][]byte, len(versions)), now: time.Now}
	for _, v := range versions {
		if v != nil {
			r.active[v.Version] = v.Key
		}
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

// Get returns the key for a version, or false if unknown.
func (r *PepperRing) Get(version int) ([]byte, bool) {
	k, ok := r.active[version]
	return k, ok
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
func (m *StateMachine) IsAuthenticatable() bool {
	return m.status != StatusRevoked
}
