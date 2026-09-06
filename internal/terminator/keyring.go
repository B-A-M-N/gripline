package terminator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

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

// Verify validates an encoded assertion by selecting the generation's public
// key from the token's kid then running the standard signature/audience/TTL
// checks. It FAILS CLOSED if the kid is unknown — a token signed by a generation
// the verifier has not yet accepted is rejected, never accepted by guessing.
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