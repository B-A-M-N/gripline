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

// Signer holds the Ed25519 key used to sign internal assertions. In production
// the signer is isolated from the Internet-facing parser and keys support
// rotation (§21).
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner creates a signer from an Ed25519 private key. Use GenerateSigner
// for a fresh key.
func NewSigner(priv ed25519.PrivateKey) *Signer {
	return &Signer{priv: priv}
}

// GenerateSigner produces a new random Ed25519 key.
func GenerateSigner() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("terminator: generate signer: %w", err)
	}
	_ = pub
	return &Signer{priv: priv}, nil
}

// Public returns the public key (for configuring verifiers).
func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

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

// Assertion is a signed, self-contained internal identity.
type Assertion struct {
	raw       []byte // canonical JSON to sign; never the raw secret
	signature []byte
	claims    Claims
}

// Issue builds and signs an internal assertion with the configured TTL and
// audience. jti must be a unique request id. iat/exp are wall-clock bounded.
func (s *Signer) Issue(c Claims, ttl time.Duration) (*Assertion, error) {
	if ttl <= 0 || ttl > 60*time.Second {
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
	if c.Audience != expectedAudience {
		return nil, ErrWrongAudience
	}
	if now.Unix() > c.ExpiresAt {
		return nil, ErrExpired
	}
	if now.Unix() < c.IssuedAt-5 { // allow small clock skew; never future-mint
		return nil, ErrNotYetValid
	}
	if c.CredID == "" {
		return nil, ErrBadAssertion
	}
	return &c, nil
}

// Errors returned by assertion verification.
var (
	ErrBadAssertion  = errors.New("terminator: bad assertion format")
	ErrBadSignature  = errors.New("terminator: bad signature")
	ErrWrongAudience = errors.New("terminator: wrong audience (INV-11)")
	ErrExpired       = errors.New("terminator: assertion expired (INV-10)")
	ErrNotYetValid   = errors.New("terminator: assertion not yet valid")
)