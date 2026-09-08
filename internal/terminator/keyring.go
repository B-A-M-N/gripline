package terminator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// keyringPersist is the on-disk representation of a Keyring (BETA-10).
// It carries the active private key AND all retained public keys so a
// restart recovers signing authority without key rotation.
type keyringPersist struct {
	ActiveKid       int                      `json:"active_kid"` // P0.14: persist kid for rotation correctness
	Active          string                   `json:"active"`     // base64-encoded private key
	Verifiers       map[int]string           `json:"verifiers"`  // kid -> base64-encoded public key
	Next            int                      `json:"next"`
	Candidate       *keyringCandidatePersist `json:"candidate,omitempty"`
	RotationPhase   string                   `json:"rotation_phase"`
	RotationAt      time.Time                `json:"rotation_at,omitempty"`
	RotationHistory []RotationEvent          `json:"rotation_history,omitempty"`
}

type keyringCandidatePersist struct {
	Kid     int    `json:"kid"`
	Private string `json:"private"`
}

// Save writes the keyring's active private key and all retained public keys
// to path with restricted permissions (0600). This is the persistence seam
// for BETA-10: a restart can recover its signing authority without a
// rotation event.
func (k *Keyring) Save(path string) error {
	if path == "" {
		return nil
	}
	if err := validateKeyringFile(path, true); err != nil {
		return err
	}
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	return saveKeyringLocked(path, k.st.active, k.st.next, k.st.verifiers, k.st.pending, k.st.rotationHistory)
}

func saveKeyringLocked(path string, active *Signer, next int, verifiers map[int][]byte, pending *Signer, history []RotationEvent) error {
	persist := keyringPersist{
		ActiveKid:       active.Kid(),
		Active:          base64.StdEncoding.EncodeToString([]byte(active.Private())),
		Next:            next,
		Verifiers:       make(map[int]string, len(verifiers)),
		RotationHistory: append([]RotationEvent(nil), history...),
	}
	persist.RotationPhase = "active"
	if pending != nil {
		persist.RotationPhase = "prepared"
		persist.RotationAt = time.Now().UTC()
	}
	for kid, pub := range verifiers {
		persist.Verifiers[kid] = base64.StdEncoding.EncodeToString(pub)
	}
	if pending != nil {
		persist.Candidate = &keyringCandidatePersist{Kid: pending.Kid(), Private: base64.StdEncoding.EncodeToString([]byte(pending.Private()))}
	}

	data, err := json.Marshal(persist)
	if err != nil {
		return err
	}
	dirPath := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dirPath, ".gripline-keyring-*")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	f := tmpFile
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	if err := dir.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}

// RotateAndSave is the legacy one-step rotation primitive. New production
// integrations should use PrepareRotation followed by ActivatePrepared so a
// backend can accept the candidate public key before the signer activates it.
func (k *Keyring) RotateAndSave(path string) (int, error) {
	if path == "" {
		return 0, errors.New("terminator: keyring path required for live rotation")
	}
	if err := validateKeyringFile(path, true); err != nil {
		return 0, err
	}
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	if k.st.pending != nil {
		return 0, errors.New("terminator: signing rotation already prepared")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 0, fmt.Errorf("terminator: rotate keyring: %w", err)
	}
	kid := k.st.next
	candidate := &Signer{priv: priv, Version: kid}
	verifiers := make(map[int][]byte, len(k.st.verifiers)+1)
	for oldKid, pub := range k.st.verifiers {
		verifiers[oldKid] = append([]byte(nil), pub...)
	}
	verifiers[kid] = []byte(candidate.Public())
	event := RotationEvent{Phase: "activated", KID: kid, At: k.st.now().UTC()}
	history := appendRotationHistory(k.st.rotationHistory, event)
	if err := saveKeyringLocked(path, candidate, kid+1, verifiers, nil, history); err != nil {
		return 0, fmt.Errorf("terminator: persist rotated keyring: %w", err)
	}
	k.st.verifiers, k.st.active, k.st.next, k.st.rotationHistory = verifiers, candidate, kid+1, history
	return kid, nil
}

// RotationCandidate is the public portion of a persisted-but-not-yet-active
// signing generation. Publish this key to the backend verifier and confirm it
// can validate a canary assertion before calling ActivatePrepared.
type RotationCandidate struct {
	KID       int
	PublicKey []byte
}

// RotationEvent is the auditable lifecycle record emitted by the safe live
// rotation methods. The event contains no private key material.
type RotationEvent struct {
	Phase string    `json:"phase"` // prepared, activated, retired
	KID   int       `json:"kid"`
	At    time.Time `json:"at"`
}

// RotationAudit is called after each durable lifecycle transition. A provider
// should connect it to the same append-only operator audit authority used for
// policy changes; a failed audit leaves the durable key phase intact and must
// be investigated before proceeding.
type RotationAudit func(RotationEvent) error

// PrepareRotation creates and durably records a candidate while leaving the
// current signer active. The candidate public key is included by PublicKeys,
// so a subsequent keys export can publish it during the overlap phase.
func (k *Keyring) PrepareRotation(path string) (*RotationCandidate, error) {
	return k.PrepareRotationWithAudit(path, nil)
}

// PrepareRotationWithAudit is PrepareRotation with an explicit lifecycle
// audit hook.
func (k *Keyring) PrepareRotationWithAudit(path string, audit RotationAudit) (*RotationCandidate, error) {
	if path == "" {
		return nil, errors.New("terminator: keyring path required for rotation preparation")
	}
	if err := validateKeyringFile(path, true); err != nil {
		return nil, err
	}
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	if k.st.pending != nil {
		return nil, errors.New("terminator: signing rotation already prepared")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("terminator: prepare key rotation: %w", err)
	}
	kid := k.st.next
	candidate := &Signer{priv: priv, Version: kid}
	verifiers := clonePublicKeys(k.st.verifiers)
	verifiers[kid] = []byte(candidate.Public())
	event := RotationEvent{Phase: "prepared", KID: kid, At: k.st.now().UTC()}
	history := appendRotationHistory(k.st.rotationHistory, event)
	if err := saveKeyringLocked(path, k.st.active, kid+1, verifiers, candidate, history); err != nil {
		return nil, fmt.Errorf("terminator: persist prepared key rotation: %w", err)
	}
	k.st.verifiers, k.st.next, k.st.pending, k.st.rotationHistory = verifiers, kid+1, candidate, history
	if audit != nil {
		if err := audit(event); err != nil {
			return nil, fmt.Errorf("terminator: audit prepared signing key %d: %w", kid, err)
		}
	}
	return &RotationCandidate{KID: kid, PublicKey: append([]byte(nil), verifiers[kid]...)}, nil
}

// ActivatePrepared verifies backend acceptance of a candidate, then durably
// activates it. A failed verifier callback leaves the old signer active and
// the prepared candidate available for retry. The callback runs without the
// keyring lock and receives only a copy of the public key.
func (k *Keyring) ActivatePrepared(path string, kid int, backendAccepted func([]byte) error) error {
	return k.ActivatePreparedWithAudit(path, kid, backendAccepted, nil)
}

// ActivatePreparedWithAudit requires backend acceptance before activation and
// records the transition through an explicit audit hook.
func (k *Keyring) ActivatePreparedWithAudit(path string, kid int, backendAccepted func([]byte) error, audit RotationAudit) error {
	if path == "" {
		return errors.New("terminator: keyring path required for rotation activation")
	}
	if backendAccepted == nil {
		return errors.New("terminator: backend acceptance check required before key activation")
	}
	if err := validateKeyringFile(path, true); err != nil {
		return err
	}
	k.st.mu.Lock()
	pending := k.st.pending
	if pending == nil || pending.Kid() != kid {
		k.st.mu.Unlock()
		return fmt.Errorf("terminator: prepared signing key %d not found", kid)
	}
	publicKey := append([]byte(nil), pending.Public()...)
	k.st.mu.Unlock()
	if err := backendAccepted(publicKey); err != nil {
		return fmt.Errorf("terminator: backend rejected signing key %d: %w", kid, err)
	}

	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	if k.st.pending == nil || k.st.pending.Kid() != kid {
		return fmt.Errorf("terminator: prepared signing key %d changed during activation", kid)
	}
	event := RotationEvent{Phase: "activated", KID: kid, At: k.st.now().UTC()}
	history := appendRotationHistory(k.st.rotationHistory, event)
	if err := saveKeyringLocked(path, k.st.pending, k.st.next, k.st.verifiers, nil, history); err != nil {
		return fmt.Errorf("terminator: persist activated key %d: %w", kid, err)
	}
	k.st.active, k.st.pending, k.st.rotationHistory = k.st.pending, nil, history
	if audit != nil {
		if err := audit(event); err != nil {
			return fmt.Errorf("terminator: audit activated signing key %d: %w", kid, err)
		}
	}
	return nil
}

// Retire removes an old public generation after the deployment has waited
// longer than the maximum assertion TTL plus clock-skew allowance. It cannot
// remove the active or prepared generation and persists the change atomically.
func (k *Keyring) Retire(path string, kid int) error {
	return k.RetireAfter(path, kid, time.Time{})
}

// RetireAfter removes an old generation only after notBefore. Callers should
// set notBefore to now + max assertion TTL + allowed clock skew. The zero time
// keeps Retire source-compatible for low-level maintenance tools; providers'
// live rotation code should always use this method with an explicit horizon.
func (k *Keyring) RetireAfter(path string, kid int, notBefore time.Time) error {
	return k.retireAfter(path, kid, notBefore, nil)
}

// RetireAfterWithAudit is RetireAfter with an explicit lifecycle audit hook.
func (k *Keyring) RetireAfterWithAudit(path string, kid int, notBefore time.Time, audit RotationAudit) error {
	return k.retireAfter(path, kid, notBefore, audit)
}

func (k *Keyring) retireAfter(path string, kid int, notBefore time.Time, audit RotationAudit) error {
	if path == "" {
		return errors.New("terminator: keyring path required for key retirement")
	}
	if err := validateKeyringFile(path, true); err != nil {
		return err
	}
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	if !notBefore.IsZero() && k.st.now().Before(notBefore) {
		return fmt.Errorf("terminator: cannot retire signing key %d before %s", kid, notBefore.UTC().Format(time.RFC3339))
	}
	if kid == k.st.active.Kid() || (k.st.pending != nil && kid == k.st.pending.Kid()) {
		return fmt.Errorf("terminator: cannot retire active or prepared key %d", kid)
	}
	if _, ok := k.st.verifiers[kid]; !ok {
		return fmt.Errorf("terminator: signing key %d not found", kid)
	}
	verifiers := clonePublicKeys(k.st.verifiers)
	delete(verifiers, kid)
	event := RotationEvent{Phase: "retired", KID: kid, At: k.st.now().UTC()}
	history := appendRotationHistory(k.st.rotationHistory, event)
	if err := saveKeyringLocked(path, k.st.active, k.st.next, verifiers, k.st.pending, history); err != nil {
		return fmt.Errorf("terminator: persist retired key %d: %w", kid, err)
	}
	k.st.verifiers, k.st.rotationHistory = verifiers, history
	if audit != nil {
		if err := audit(event); err != nil {
			return fmt.Errorf("terminator: audit retired signing key %d: %w", kid, err)
		}
	}
	return nil
}

func clonePublicKeys(src map[int][]byte) map[int][]byte {
	out := make(map[int][]byte, len(src))
	for kid, pub := range src {
		out[kid] = append([]byte(nil), pub...)
	}
	return out
}

func appendRotationHistory(history []RotationEvent, event RotationEvent) []RotationEvent {
	out := append([]RotationEvent(nil), history...)
	return append(out, event)
}

// LoadKeyring reads a keyring from a file with load-or-create semantics: a
// missing file generates a fresh keyring and persists it. This is the RUNTIME
// path. Read-only consumers (export, inspection, migration tools) must use
// LoadExistingKeyring instead — a command named "export" must never mint a
// new signing identity as a side effect (P0.17).
func LoadKeyring(path string) (*Keyring, error) {
	return LoadOrCreateKeyring(path)
}

// LoadOrCreateKeyring is the explicit load-or-create runtime loader.
func LoadOrCreateKeyring(path string) (*Keyring, error) {
	if path == "" {
		return NewKeyring()
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := prepareKeyringDir(dir); err != nil {
			return nil, err
		}
	}

	_, err := os.Lstat(path)
	switch {
	case err == nil:
		// File exists: load below.
	case errors.Is(err, os.ErrNotExist):
		// File doesn't exist: generate fresh and save.
		kr, err := NewKeyring()
		if err != nil {
			return nil, err
		}
		if err := kr.Save(path); err != nil {
			return nil, err
		}
		return kr, nil
	default:
		// Some other stat error (permissions, etc.): don't silently generate.
		return nil, err
	}

	return loadKeyringFile(path)
}

// LoadExistingKeyring loads a keyring that MUST already exist (P0.17): a
// missing file is an error, never a new signing identity. Read-only consumers
// — key export, inspection, operator tooling — must use this path so a typo'd
// or unset signer path cannot silently mutate the trust root. "" is rejected
// rather than falling back to an ephemeral identity.
func LoadExistingKeyring(path string) (*Keyring, error) {
	if path == "" {
		return nil, errors.New("terminator: keyring path required for read-only load")
	}
	if err := validateKeyringFile(path, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("terminator: keyring %s does not exist (read-only load refuses to create a signing identity)", path)
		}
		return nil, err
	}
	return loadKeyringFile(path)
}

// loadKeyringFile reads and validates an existing keyring file without any
// create/write behavior.
func loadKeyringFile(path string) (*Keyring, error) {
	if err := validateKeyringFile(path, false); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p keyringPersist
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	k := &Keyring{st: &keyringState{
		verifiers:       make(map[int][]byte, len(p.Verifiers)),
		next:            p.Next,
		now:             time.Now,
		rotationHistory: append([]RotationEvent(nil), p.RotationHistory...),
	}}
	priv, err := base64.StdEncoding.DecodeString(p.Active)
	if err != nil {
		return nil, err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("terminator: invalid persisted private key size %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	k.st.active = &Signer{priv: ed25519.PrivateKey(priv), Version: p.ActiveKid}
	if p.ActiveKid < 1 {
		return nil, fmt.Errorf("terminator: persisted active_kid %d invalid (must be >= 1)", p.ActiveKid)
	}
	if p.Next <= p.ActiveKid {
		return nil, fmt.Errorf("terminator: persisted next kid %d must exceed active_kid %d", p.Next, p.ActiveKid)
	}
	if len(p.Verifiers) == 0 {
		return nil, fmt.Errorf("terminator: persisted keyring has no verifier keys")
	}
	if _, ok := p.Verifiers[p.ActiveKid]; !ok {
		return nil, fmt.Errorf("terminator: persisted verifier table lacks the active kid %d", p.ActiveKid)
	}
	activePriv := ed25519.PrivateKey(priv)
	activePub, ok := activePriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("terminator: active key is not Ed25519")
	}
	if len(activePub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("terminator: active public key size %d, want %d", len(activePub), ed25519.PublicKeySize)
	}
	wantActive := p.Verifiers[p.ActiveKid]
	gotActive, err := base64.StdEncoding.DecodeString(wantActive)
	if err != nil || !bytes.Equal(gotActive, activePub) {
		return nil, fmt.Errorf("terminator: active private key's public component does not match persisted verifier %d (corrupt keyring)", p.ActiveKid)
	}
	for kid, pubB64 := range p.Verifiers {
		pub, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil {
			return nil, err
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("terminator: verifier key %d size %d, want %d", kid, len(pub), ed25519.PublicKeySize)
		}
		k.st.verifiers[kid] = pub
	}
	if p.Candidate != nil {
		if p.RotationPhase != "prepared" {
			return nil, fmt.Errorf("terminator: persisted candidate requires prepared rotation phase")
		}
		if p.Candidate.Kid <= p.ActiveKid {
			return nil, fmt.Errorf("terminator: persisted candidate kid %d is not newer than active kid %d", p.Candidate.Kid, p.ActiveKid)
		}
		candidatePriv, err := base64.StdEncoding.DecodeString(p.Candidate.Private)
		if err != nil || len(candidatePriv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("terminator: invalid persisted candidate private key")
		}
		candidate := &Signer{priv: ed25519.PrivateKey(candidatePriv), Version: p.Candidate.Kid}
		candidatePub := candidate.Public()
		persistedPub, ok := k.st.verifiers[p.Candidate.Kid]
		if !ok || !bytes.Equal(persistedPub, candidatePub) {
			return nil, fmt.Errorf("terminator: persisted candidate public key does not match candidate private key")
		}
		if p.Next <= p.Candidate.Kid {
			return nil, fmt.Errorf("terminator: persisted next kid %d must exceed candidate kid %d", p.Next, p.Candidate.Kid)
		}
		k.st.pending = candidate
	} else if p.RotationPhase != "" && p.RotationPhase != "active" {
		return nil, fmt.Errorf("terminator: unknown persisted rotation phase %q", p.RotationPhase)
	}
	for _, event := range p.RotationHistory {
		if event.KID < 1 || (event.Phase != "prepared" && event.Phase != "activated" && event.Phase != "retired") || event.At.IsZero() {
			return nil, fmt.Errorf("terminator: invalid persisted rotation history event")
		}
	}
	return k, nil
}

// validateKeyringFile rejects symlinks, special files, and group/world
// readable key material before any read or overwrite. The create path allows
// a missing file; callers then generate it through the exclusive temp-file
// commit in Save.
func validateKeyringFile(path string, allowMissing bool) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := validateKeyringDir(dir); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("terminator: keyring %s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("terminator: keyring %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("terminator: keyring %s permissions %04o are too broad; require 0600", path, info.Mode().Perm())
	}
	return nil
}

func prepareKeyringDir(path string) error {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	return validateKeyringDir(path)
}

func validateKeyringDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("terminator: keyring parent %s must be a real directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 && !keyringDirOwnedByProcess(info) {
		return fmt.Errorf("terminator: keyring parent %s permissions %04o are writable by group/other", path, info.Mode().Perm())
	}
	return nil
}

func keyringDirOwnedByProcess(info os.FileInfo) bool {
	if info.Mode().Perm()&0o002 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid() && int(stat.Gid) == os.Getgid()
}

// Keyring is a rotating set of assertion signers (generations), mirroring the
// PepperRing rotation model (§21, P0.59/P0.60). It is the signer-side half of
// the internal trust boundary: it holds the ACTIVE private key for new
// assertions AND all still-valid public keys so a rotated credential's already-
// issued (short-lived, ≤30s) assertions stay verifiable during the overlap.
//
// Rotation property (P0.59): after Rotate(), new assertions carry a higher kid,
// but assertions issued under the previous generation remain valid for parsing
// while their TTL is live. The verifier side keeps the prior public keys.
//
// Concurrency: rotation and issuance both take the lock; a Mid-flight issue
// after a Rotate uses the CURRENT active key at that instant, so a single token
// never mixes generations.
type Keyring struct {
	st *keyringState // shared state: copies of the handle stay the SAME keyring
}

// keyringState holds the keyring's actual contents behind one lock. It exists
// so the exported Keyring can carry value-receiver redaction methods (P0.16)
// without copying a sync.Mutex (go vet lock-by-value): the exported struct is
// a thin handle, and copy := *kr yields another handle over the same state —
// same behavior as before for use, redacting correctly for formatting.
type keyringState struct {
	mu              sync.Mutex
	active          *Signer          // current signing generation (highest kid)
	pending         *Signer          // prepared generation awaiting backend acceptance
	verifiers       map[int][]byte   // kid -> public key (all retained generations)
	next            int              // next kid to assign
	now             func() time.Time // clock (tests)
	rotationHistory []RotationEvent
}

// Format implements fmt.Formatter and always redacts (P0.16 defense in
// depth). VALUE receiver so a struct copy (copy := *kr) redacts identically
// rather than fall back to struct formatting that would expose the active
// private signer. (The verifier map is public material, but the signer is not.)
func (k Keyring) Format(f fmt.State, verb rune) { fmt.Fprint(f, "<redacted>") }

// String implements fmt.Stringer (value receiver, P0.16).
func (k Keyring) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer (%#v; value receiver, P0.16).
func (k Keyring) GoString() string { return "<redacted>" }

// NewKeyring seeds a keyring with an initial generation (kid 1), freshly
// generated. The verifier map starts with generation 1's public key.
func NewKeyring() (*Keyring, error) {
	s, err := GenerateSigner()
	if err != nil {
		return nil, err
	}
	k := &Keyring{st: &keyringState{
		verifiers: make(map[int][]byte),
		next:      2,
		now:       time.Now,
	}}
	k.st.active = s
	k.st.verifiers[s.Kid()] = []byte(s.Public())
	return k, nil
}

// WithClock injects a clock for tests.
func (k *Keyring) WithClock(now func() time.Time) *Keyring {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	if now != nil {
		k.st.now = now
	}
	return k
}

// Issue is the AssertionSigner interface: it signs with the current active
// generation. The verifier selects the matching public key by the token's kid.
func (k *Keyring) Issue(c Claims, ttl time.Duration) (*Assertion, error) {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	if k.st.active == nil {
		return nil, errors.New("terminator: keyring has no active signer")
	}
	return k.st.active.Issue(c, ttl)
}

// ActiveKid reports the current signing generation.
func (k *Keyring) ActiveKid() int {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	return k.st.active.Kid()
}

// Rotate advances the keyring to a NEW random generation with kid = previous+1,
// retaining every prior public key so outstanding short-lived assertions remain
// verifiable (P0.59). Returns the new kid.
func (k *Keyring) Rotate() (int, error) {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	if k.st.pending != nil {
		return 0, errors.New("terminator: signing rotation already prepared")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 0, fmt.Errorf("terminator: rotate keyring: %w", err)
	}
	kid := k.st.next
	k.st.next++
	s := &Signer{priv: priv, Version: kid}
	k.st.verifiers[kid] = []byte(s.Public())
	k.st.active = s
	return kid, nil
}

// Public looks up the public key for a generation (verifier side). kid 0
// resolves to generation 1 for backward-compatible tokens issued without a kid.
// Returns a copy so the caller cannot mutate the keyring.
func (k *Keyring) Public(kid int) ([]byte, bool) {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	if kid == 0 {
		kid = 1
	}
	b, ok := k.st.verifiers[kid]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), b...), true
}

// VerificationKeySource publishes the public verification material for backend
// verification (P0.15). Signing and public-key publication are conceptually
// separate: a remote signer/HSM may hold the private key while the runtime
// publishes the corresponding public material to backends.
type VerificationKeySource interface {
	ActiveKid() int
	PublicKeys() map[int]ed25519.PublicKey
}

// PublicKeys returns a copy of all retained generation public keys (P0.15).
func (k *Keyring) PublicKeys() map[int]ed25519.PublicKey {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	out := make(map[int]ed25519.PublicKey, len(k.st.verifiers))
	for kid, pub := range k.st.verifiers {
		out[kid] = append(ed25519.PublicKey(nil), pub...)
	}
	return out
}

// PublicKeysetFingerprint returns a stable digest of every retained public
// signer generation. It is cluster identity metadata only; no private key is
// included. Equal active kids with unequal fingerprints indicate a
// misprovisioned signing authority.
func (k *Keyring) PublicKeysetFingerprint() string {
	if k == nil {
		return ""
	}
	keys := k.PublicKeys()
	kids := make([]int, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	sort.Ints(kids)
	h := sha256.New()
	for _, kid := range kids {
		_, _ = h.Write([]byte(strconv.Itoa(kid)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(keys[kid])
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PublishVerifier builds the VERIFIER-side keyring (P0.17): a
// VerifierKeyring holding PUBLIC keys only, connected to this signer by key
// publication. This is the deployment hands to private backends —
// never the SignerKeyring itself, whose possession implies signing authority.
func (k *Keyring) PublishVerifier() *VerifierKeyring {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	vk := newVerifierKeyring()
	for kid, pub := range k.st.verifiers {
		vk.st.verifiers[kid] = append([]byte(nil), pub...)
	}
	if k.st.now != nil {
		vk.st.now = k.st.now
	}
	return vk
}

// Verify validates an encoded assertion by selecting the generation's public
// key from the token's kid then running the standard signature/audience/TTL
// checks. It FAILS CLOSED if the kid is unknown — a token signed by a generation
// the verifier has not yet accepted is rejected, never accepted by guessing.
//
// Prefer publishing a VerifierKeyring (PublishVerifier) for verifiers (P0.17);
// this method remains for single-process deployments where the signer and
// verifier are the same trust domain.
func (k *Keyring) Verify(encoded, audience string, now time.Time) (*Claims, error) {
	if now.IsZero() {
		k.st.mu.Lock()
		now = k.st.now()
		k.st.mu.Unlock()
	}
	kid, err := extractKid(encoded)
	if err != nil {
		return nil, err
	}
	if kid == 0 {
		kid = 1
	}
	pub, ok := k.Public(kid)
	if !ok {
		return nil, fmt.Errorf("terminator: no public key for assertion kid %d (rotation not yet propagated)", kid)
	}
	return ParseAndVerify(encoded, ed25519.PublicKey(pub), audience, now)
}

// VerifierKeyring is the verification-only half of the rotation keyring
// (P0.17): it holds PUBLIC keys for every retained generation and can never
// sign. This is what a private backend receives — the old shape handed the
// backend the full *Keyring (active private signer + Issue + Rotate), giving
// the verifying side the authority to mint its own assertions and defeating
// the issuer/verifier isolation the boundary exists for.
//
// Publication model: the signer side publishes generations into the verifier
// (Publish, below); the two objects are independently constructed and share no
// private material. Tests wire them together exactly that way.
type VerifierKeyring struct {
	st *verifierKeyringState
}

type verifierKeyringState struct {
	mu        sync.Mutex
	verifiers map[int][]byte // kid -> public key
	now       func() time.Time
}

// Format/String/GoString: value receivers, always redact (P0.16 parity — the
// contents are public material, but a consistent redaction surface means
// nothing downstream can distinguish secret-bearing types by their formatting).
func (k VerifierKeyring) Format(f fmt.State, verb rune) { fmt.Fprint(f, "<redacted>") }
func (k VerifierKeyring) String() string                { return "<redacted>" }
func (k VerifierKeyring) GoString() string              { return "<redacted>" }

func newVerifierKeyring() *VerifierKeyring {
	return &VerifierKeyring{st: &verifierKeyringState{
		verifiers: make(map[int][]byte),
		now:       time.Now,
	}}
}

// NewVerifierKeyring builds an EMPTY verifier keyring (publication model:
// generations arrive via Publish). For a fixed single-key verifier without
// rotation, use NewBackendVerifier(pub, audience) instead.
func NewVerifierKeyring() *VerifierKeyring { return newVerifierKeyring() }

// WithClock injects a clock for tests.
func (k *VerifierKeyring) WithClock(now func() time.Time) *VerifierKeyring {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	if now != nil {
		k.st.now = now
	}
	return k
}

// Publish installs (or replaces) the public key for one generation. This is
// the rotation-propagation seam: the operator/publisher pushes each new
// signer generation's public key to verifiers, and unknown generations fail
// closed until publication lands.
func (k *VerifierKeyring) Publish(kid int, pub ed25519.PublicKey) {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	k.st.verifiers[kid] = append([]byte(nil), pub...)
}

// Retire drops a generation's public key (rotation cleanup: once every
// outstanding ≤30s assertion of a generation is expired, its public key can
// be removed).
func (k *VerifierKeyring) Retire(kid int) {
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	delete(k.st.verifiers, kid)
}

// Verify validates an encoded assertion against the published generation keys.
// Fails closed on an unknown kid — publication lag denies, never downgrades.
func (k *VerifierKeyring) Verify(encoded, audience string, now time.Time) (*Claims, error) {
	if now.IsZero() {
		k.st.mu.Lock()
		now = k.st.now()
		k.st.mu.Unlock()
	}
	kid, err := extractKid(encoded)
	if err != nil {
		return nil, err
	}
	if kid == 0 {
		kid = 1
	}
	k.st.mu.Lock()
	pub, ok := k.st.verifiers[kid]
	k.st.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("terminator: no public key for assertion kid %d (rotation not yet published)", kid)
	}
	return ParseAndVerify(encoded, ed25519.PublicKey(append([]byte(nil), pub...)), audience, now)
}

// extractKid decodes just the payload's kid claim to route verification to the
// right key. The returned kid is NOT trusted for authorization — the full
// ParseAndVerify signature check still gates acceptance.
func extractKid(encoded string) (int, error) {
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 || parts[0] != assertionWireVersion {
		return 0, ErrBadAssertion
	}
	payloadB64 := parts[1]
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return 0, ErrBadAssertion
	}
	var probe struct {
		KeyID int `json:"kid"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return 0, ErrBadAssertion
	}
	return probe.KeyID, nil
}
