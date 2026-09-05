package proxy

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"time"

	"github.com/B-A-M-N/gripline/internal/terminator"
)

// BackendVerifier is the private-backend half of the trust boundary (INV-10,
// INV-11). It validates the internal assertion the proxy injects and resolves
// the authenticated principal, so the backend can authorize WITHOUT ever seeing
// the raw external credential. This is the "accepted by a private backend
// without the external credential crossing the boundary" gate.
//
// It accepts a Keyring so the private backend follows the proxy's signer
// rotation (§21, P0.59): each assertion names its generation (kid) and the
// verifier selects that generation's public key, so rotated tokens remain
// acceptable during the overlap and unknown generations fail closed.
type BackendVerifier struct {
	// keyring, when set, is the rotation-aware verifier path (P0.59).
	keyring *terminator.Keyring
	// pub is the fixed single-key path (back-compat), used when keyring is nil.
	pub      ed25519.PublicKey
	audience string
	now      func() time.Time
}

// NewBackendVerifier configures a verifier with a FIXED internal signer's
// public key and the exact audience the proxy issues to (INV-11 binding). Use
// NewBackendVerifierKeyring for rotation.
func NewBackendVerifier(pub ed25519.PublicKey, audience string) *BackendVerifier {
	return &BackendVerifier{pub: pub, audience: audience}
}

// NewBackendVerifierKeyring configures a verifier that follows the signer's
// rotation (P0.59): the public key is selected per-assertion by its kid.
func NewBackendVerifierKeyring(keyring *terminator.Keyring, audience string) *BackendVerifier {
	return &BackendVerifier{keyring: keyring, audience: audience}
}

// WithClock injects a clock for tests.
func (b *BackendVerifier) WithClock(now func() time.Time) *BackendVerifier {
	if now != nil {
		b.now = now
	}
	return b
}

// Verify extracts and validates the internal assertion from r and returns the
// authenticated claims. It fails closed on any of: missing assertion, bad
// signature, wrong audience (INV-11), expired/too-long TTL (INV-10/IP-reuse),
// unknown signing generation (P0.59), or a forged/invalid carrier. It never
// touches the external secret headers.
func (b *BackendVerifier) Verify(r *http.Request) (*terminator.Claims, error) {
	vals := r.Header.Values(assertionHeader)
	if len(vals) == 0 {
		return nil, fmt.Errorf("backend: missing internal assertion (INV-11)")
	}
	if len(vals) > 1 {
		return nil, fmt.Errorf("backend: duplicate internal assertion")
	}
	now := time.Now()
	if b.now != nil {
		now = b.now()
	}
	var (
		claims *terminator.Claims
		err    error
	)
	if b.keyring != nil {
		claims, err = b.keyring.Verify(vals[0], b.audience, now)
	} else {
		claims, err = terminator.ParseAndVerify(vals[0], b.pub, b.audience, now)
	}
	if err != nil {
		return nil, fmt.Errorf("backend: assertion rejected: %w", err)
	}
	return claims, nil
}