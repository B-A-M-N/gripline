package terminator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// keyringPersist is the on-disk representation of a Keyring (BETA-10).
// It carries the active private key AND all retained public keys so a
// restart recovers signing authority without key rotation.
type keyringPersist struct {
	ActiveKid int            `json:"active_kid"` // P0.14: persist kid for rotation correctness
	Active    string         `json:"active"`     // base64-encoded private key
	Verifiers map[int]string `json:"verifiers"`  // kid -> base64-encoded public key
	Next      int            `json:"next"`
}

// Save writes the keyring's active private key and all retained public keys
// to path with restricted permissions (0600). This is the persistence seam
// for BETA-10: a restart can recover its signing authority without a
// rotation event.
func (k *Keyring) Save(path string) error {
	if path == "" {
		return nil
	}
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
	return saveKeyringLocked(path, k.st.active, k.st.next, k.st.verifiers)
}

func saveKeyringLocked(path string, active *Signer, next int, verifiers map[int][]byte) error {
	persist := keyringPersist{
		ActiveKid: active.Kid(),
		Active:    base64.StdEncoding.EncodeToString([]byte(active.Private())),
		Next:      next,
		Verifiers: make(map[int]string, len(verifiers)),
	}
	for kid, pub := range verifiers {
		persist.Verifiers[kid] = base64.StdEncoding.EncodeToString(pub)
	}

	data, err := json.Marshal(persist)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RotateAndSave atomically persists a candidate generation before publishing
// it as active. A failed write leaves the current signer untouched, so a live
// process can never publish a key that a restart would forget.
func (k *Keyring) RotateAndSave(path string) (int, error) {
	if path == "" {
		return 0, errors.New("terminator: keyring path required for live rotation")
	}
	k.st.mu.Lock()
	defer k.st.mu.Unlock()
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
	if err := saveKeyringLocked(path, candidate, kid+1, verifiers); err != nil {
		return 0, fmt.Errorf("terminator: persist rotated keyring: %w", err)
	}
	k.st.verifiers, k.st.active, k.st.next = verifiers, candidate, kid+1
	return kid, nil
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
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
	}

	_, err := os.Stat(path)
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
	if _, err := os.Stat(path); err != nil {
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p keyringPersist
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	k := &Keyring{st: &keyringState{
		verifiers: make(map[int][]byte, len(p.Verifiers)),
		next:      p.Next,
		now:       time.Now,
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
	return k, nil
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
	mu        sync.Mutex
	active    *Signer          // current signing generation (highest kid)
	verifiers map[int][]byte   // kid -> public key (all retained generations)
	next      int              // next kid to assign
	now       func() time.Time // clock (tests)
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
	dot := strings.IndexByte(encoded, '.')
	if dot < 0 {
		return 0, ErrBadAssertion
	}
	payloadB64 := encoded[:dot]
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
