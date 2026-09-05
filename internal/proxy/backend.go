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
type BackendVerifier struct {
	pub      ed25519.PublicKey
	audience string
	now      func() time.Time
}

// NewBackendVerifier configures a verifier with the internal signer's public
// key and the exact audience the proxy issues to (INV-11 binding). now may be
// nil (defaults to time.Now).
func NewBackendVerifier(pub ed25519.PublicKey, audience string) *BackendVerifier {
	return &BackendVerifier{pub: pub, audience: audience}
}

// Verify extracts and validates the internal assertion from r and returns the
// authenticated claims. It fails closed on any of: missing assertion, bad
// signature, wrong audience (INV-11), expired/too-long TTL (INV-10/IP-reuse),
// or a forged/invalid carrier. It never touches the external secret headers.
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
	claims, err := terminator.ParseAndVerify(vals[0], b.pub, b.audience, now)
	if err != nil {
		return nil, fmt.Errorf("backend: assertion rejected: %w", err)
	}
	return claims, nil
}