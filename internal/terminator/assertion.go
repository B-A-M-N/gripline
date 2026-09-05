// Package terminator orchestrates the credential-termination admission flow
// (spec §53) and issues the short-lived, audience-bound internal assertion that
// authenticates toward protected services (spec §20-21, INV-10, INV-11). No raw
// external secret ever leaves this boundary into the assertion or downstream.
package terminator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AssertionSigner is the seam the terminator uses to mint internal identity.
// Indirected as an interface so production deployments can isolate the real
// signer (HSM-backed, remote signer service) and rotation behind it (§21), and
// so admission-failure paths are exercisable in tests.
type AssertionSigner interface {
	Issue(c Claims, ttl time.Duration) (*Assertion, error)
}

// Signer holds the Ed25519 key used to sign internal assertions. In production
// the signer is isolated from the Internet-facing parser and keys support
// rotation (§21).
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner creates a signer from an Ed25519 private key. Use GenerateSigner
// for a fresh key. The key size is validated (ed25519.PrivateKeySize) so a
// truncated or mis-typed key fails loudly at construction instead of at
// signing time.
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("terminator: invalid ed25519 private key size %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &Signer{priv: priv}, nil
}

// GenerateSigner produces a new random Ed25519 key.
func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("terminator: generate signer: %w", err)
	}
	return &Signer{priv: priv}, nil
}

// Public returns the public key (for configuring verifiers). The public key is
// not secret; the private key is.
func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// Format implements fmt.Formatter and always redacts (P0.15/P0.31): formatting a
// Signer must never reach the private key bytes.
func (s *Signer) Format(f fmt.State, verb rune) { fmt.Fprint(f, "<redacted>") }

// String implements fmt.Stringer.
func (s *Signer) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer (%#v).
func (s *Signer) GoString() string { return "<redacted>" }

var (
	_ fmt.Formatter  = (*Signer)(nil)
	_ fmt.Stringer   = (*Signer)(nil)
	_ fmt.GoStringer = (*Signer)(nil)
)

// Claims is the internal-identity payload (§20).
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"` // account id
	CredID    string   `json:"cid"` // credential id
	LaneID    string   `json:"ctx"` // lane context
	Audience  string   `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	JTI       string   `json:"jti"` // unique per-request id
	PolicyRev int      `json:"policy_rev"`
	CredRev   int      `json:"cred_rev"`
	Scope     []string `json:"scope"`
}

// Assertion is a signed, self-contained internal identity. It is a short-lived
// internal bearer capability, not a reusable external credential — but it is
// still sensitive: formatting it must never reconstruct the wire token (P0.31).
type Assertion struct {
	raw       []byte // canonical JSON to sign; never the raw secret
	signature []byte
	claims    Claims
}

// Format implements fmt.Formatter and always redacts (P0.31): generic logging
// of an Assertion must not leak the wire token or its signature.
func (a *Assertion) Format(f fmt.State, verb rune) { fmt.Fprint(f, "<redacted>") }

// String implements fmt.Stringer.
func (a *Assertion) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer (%#v).
func (a *Assertion) GoString() string { return "<redacted>" }

var (
	_ fmt.Formatter  = (*Assertion)(nil)
	_ fmt.Stringer   = (*Assertion)(nil)
	_ fmt.GoStringer = (*Assertion)(nil)
)

// Issue builds and signs an internal assertion with the configured TTL and
// audience. jti must be a unique request id. iat/exp are wall-clock bounded.
func (s *Signer) Issue(c Claims, ttl time.Duration) (*Assertion, error) {
	// INV-10 / P0.28: internal assertions are hard-capped at 30s. The signer
	// refuses a longer lifetime even if policy is somehow misconfigured upward.
	if ttl <= 0 || ttl > maxAssertionTTLSeconds*time.Second {
		return nil, fmt.Errorf("terminator: TTL out of bounds (INV-10): %v", ttl)
	}
	now := time.Now()
	c.Issuer = "gripline"
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(ttl).Unix()
	if c.JTI == "" {
		return nil, fmt.Errorf("terminator: jti (request id) required")
	}
	if c.Audience == "" {
		return nil, fmt.Errorf("terminator: audience required (INV-11)")
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("terminator: marshal claims: %w", err)
	}
	sig := ed25519.Sign(s.priv, payload)
	return &Assertion{raw: payload, signature: sig, claims: c}, nil
}

// Claims decodes the payload JSON without exposing more than the claim set.
func (a *Assertion) Claims() Claims { return a.claims }

// Encode returns the wire format: base64url(payload).base64url(sig).
func (a *Assertion) Encode() string {
	return base64.RawURLEncoding.EncodeToString(a.raw) + "." + base64.RawURLEncoding.EncodeToString(a.signature)
}

// ParseAndVerify validates an encoded assertion against a public key, the
// expected audience, and a sanity window. It rejects expired (INV-10) and
// wrong-audience (INV-11) assertions.
func ParseAndVerify(encoded string, pub ed25519.PublicKey, expectedAudience string, now time.Time) (*Claims, error) {
	dot := strings.IndexByte(encoded, '.')
	if dot < 0 {
		return nil, ErrBadAssertion
	}
	payloadB64, sigB64 := encoded[:dot], encoded[dot+1:]
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrBadAssertion
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrBadAssertion
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, ErrBadSignature
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrBadAssertion
	}
	if c.Issuer != assertionIssuer {
		return nil, ErrWrongIssuer
	}
	if c.Audience != expectedAudience {
		return nil, ErrWrongAudience
	}
	// exp is inclusive-invalid: an assertion is expired AT its expiry second
	// (now == exp fails), matching standard JWT semantics.
	if now.Unix() >= c.ExpiresAt {
		return nil, ErrExpired
	}
	if now.Unix() < c.IssuedAt-5 { // allow small clock skew; never future-mint
		return nil, ErrNotYetValid
	}
	// Defensive bound: a signed assertion claiming a lifetime beyond the
	// maximum supported TTL is rejected even if correctly signed — protects
	// against signer-key misuse minting long-lived identities.
	if c.ExpiresAt-c.IssuedAt > maxAssertionTTLSeconds {
		return nil, ErrTTLTooLong
	}
	if c.CredID == "" || c.JTI == "" {
		return nil, ErrBadAssertion
	}
	return &c, nil
}

// assertionIssuer is the only issuer internal verifiers accept.
const assertionIssuer = "gripline"

// maxAssertionTTLSeconds is the defensive upper bound on accepted assertion
// lifetimes (INV-10, P0.28): the stated invariant is ≤30s, so both Issue and
// ParseAndVerify hard-cap here.
const maxAssertionTTLSeconds = 30

// Errors returned by assertion verification.
var (
	ErrBadAssertion  = errors.New("terminator: bad assertion format")
	ErrBadSignature  = errors.New("terminator: bad signature")
	ErrWrongIssuer   = errors.New("terminator: wrong issuer")
	ErrWrongAudience = errors.New("terminator: wrong audience (INV-11)")
	ErrExpired       = errors.New("terminator: assertion expired (INV-10)")
	ErrNotYetValid   = errors.New("terminator: assertion not yet valid")
	ErrTTLTooLong    = errors.New("terminator: assertion TTL exceeds bound (INV-10)")
)
