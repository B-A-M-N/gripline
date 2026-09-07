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
// rotation (§21, P0.59).
//
// Version is the signer's generation (kid), stamped into every assertion it
// issues so a rotating verifier keyring can select the right public key during
// the rotation overlap window (P0.59/P0.60). A signer created with the default
// zero version issues version-1 assertions (backward compatible).
type Signer struct {
	priv    ed25519.PrivateKey
	Version int
}

// Private returns a COPY of the private key for serialization (BETA-10).
// The caller cannot mutate the live signer through the returned slice.
func (s *Signer) Private() ed25519.PrivateKey {
	return append(ed25519.PrivateKey(nil), s.priv...)
}

// NewSigner creates a signer from an Ed25519 private key. Use GenerateSigner
// for a fresh key. The key size is validated (ed25519.PrivateKeySize) so a
// truncated or mis-typed key fails loudly at construction instead of at
// signing time. A zero Version is normalized to 1.
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("terminator: invalid ed25519 private key size %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &Signer{priv: priv, Version: 1}, nil
}

// GenerateSigner produces a new random Ed25519 key at version 1.
func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("terminator: generate signer: %w", err)
	}
	return &Signer{priv: priv, Version: 1}, nil
}

// Kid returns the signer's generation (its assertion key id).
func (s *Signer) Kid() int {
	if s == nil || s.Version < 1 {
		return 1
	}
	return s.Version
}

// Public returns the public key (for configuring verifiers). The public key is
// not secret; the private key is.
func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// Format implements fmt.Formatter and always redacts (P0.15/P0.31): formatting a
// Signer must never reach the private key bytes. VALUE receivers (P0.15): a
// copy of a Signer (copy := *signer) must redact identically — pointer
// receivers only cover the original, and a copy falls back to struct
// formatting, exposing priv.
func (s Signer) Format(f fmt.State, verb rune) { fmt.Fprint(f, "<redacted>") }

// String implements fmt.Stringer (value receiver, P0.15).
func (s Signer) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer (%#v; value receiver, P0.15).
func (s Signer) GoString() string { return "<redacted>" }

var (
	_ fmt.Formatter  = Signer{}
	_ fmt.Stringer   = Signer{}
	_ fmt.GoStringer = Signer{}
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
	// KeyID is the signer generation (kid). The verifier selects its public key
	// by this id, enabling key rotation with overlap (P0.59).
	KeyID int `json:"kid"`
}

// Assertion is a signed, self-contained internal identity. It is a short-lived
// internal bearer capability, not a reusable external credential — but it is
// still sensitive: formatting it must never reconstruct the wire token (P0.31).
type Assertion struct {
	raw       []byte // canonical JSON to sign; never the raw secret
	signature []byte
	claims    Claims
}

// Format implements fmt.Formatter and always redacts (P0.31/P0.15): generic
// logging of an Assertion must not leak the wire token or its signature. VALUE
// receivers so a struct copy redacts identically to the original.
func (a Assertion) Format(f fmt.State, verb rune) { fmt.Fprint(f, "<redacted>") }

// String implements fmt.Stringer (value receiver, P0.15).
func (a Assertion) String() string { return "<redacted>" }

// GoString implements fmt.GoStringer (%#v; value receiver, P0.15).
func (a Assertion) GoString() string { return "<redacted>" }

var (
	_ fmt.Formatter  = Assertion{}
	_ fmt.Stringer   = Assertion{}
	_ fmt.GoStringer = Assertion{}
)

// Issue builds and signs an internal assertion with the configured TTL and
// audience. jti must be a unique request id. iat/exp are wall-clock bounded.
//
// P0.18: the signer enforces the same claim strictness the verifier applies —
// a signer must never mint an assertion a conforming verifier would reject
// (relying on every caller to populate claims correctly is how malformed-but-
// signed authority gets into the wild).
func (s *Signer) Issue(c Claims, ttl time.Duration) (*Assertion, error) {
	// INV-10 / P0.28: internal assertions are hard-capped at 30s. The signer
	// refuses a longer lifetime even if policy is somehow misconfigured upward.
	if ttl <= 0 || ttl > maxAssertionTTLSeconds*time.Second {
		return nil, fmt.Errorf("terminator: TTL out of bounds (INV-10): %v", ttl)
	}
	if c.JTI == "" {
		return nil, fmt.Errorf("terminator: jti (request id) required")
	}
	if c.Audience == "" {
		return nil, fmt.Errorf("terminator: audience required (INV-11)")
	}
	if c.Subject == "" {
		return nil, fmt.Errorf("terminator: subject required (P0.18)")
	}
	if c.CredID == "" {
		return nil, fmt.Errorf("terminator: credential id required (P0.18)")
	}
	if len(c.Scope) == 0 || len(c.Scope) > maxAssertionScopes {
		return nil, fmt.Errorf("terminator: scope required, bounded at %d (P0.18)", maxAssertionScopes)
	}
	for _, sc := range c.Scope {
		if !validAssertionScope(sc) {
			return nil, fmt.Errorf("terminator: scope %q not allowlisted (P0.18)", sc)
		}
	}
	if c.PolicyRev < 1 {
		return nil, fmt.Errorf("terminator: policy_rev must be > 0 (P0.18)")
	}
	if c.CredRev < 1 {
		return nil, fmt.Errorf("terminator: cred_rev must be > 0 (P0.18)")
	}
	// LaneID is required when the scope set demands lane context (P0.18).
	if requiresLaneScope(c.Scope) && c.LaneID == "" {
		return nil, fmt.Errorf("terminator: lane scope requires LaneID (P0.18)")
	}
	now := time.Now()
	c.Issuer = assertionIssuer
	c.IssuedAt = now.Unix()
	c.ExpiresAt = now.Add(ttl).Unix()
	// Stamp the signer's generation so the verifier selects the right key during
	// rotation (P0.59). A zero/absent key id stays 0 for backward compat; the
	// verifier keyring treats 0 as version 1.
	c.KeyID = s.Kid()
	payload, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("terminator: marshal claims: %w", err)
	}
	if len(payload) > maxAssertionPayloadBytes {
		return nil, fmt.Errorf("terminator: assertion payload %d exceeds bound %d (P0.18)", len(payload), maxAssertionPayloadBytes)
	}
	sig := ed25519.Sign(s.priv, payload)
	return &Assertion{raw: payload, signature: sig, claims: c}, nil
}

// maxAssertionScopes bounds the scope claim's cardinality (P0.18).
const maxAssertionScopes = 8

// maxAssertionPayloadBytes bounds the encoded assertion size (P0.18): a signed
// but bloated authority is still a DoS surface on every verifying hop.
const maxAssertionPayloadBytes = 4096

// validAssertionScope allowlists scope values (P0.18): an arbitrary scope
// string must never acquire meaning by sneaking through. "inference" is the
// data-plane workload scope the terminator mints; REQUEST/LANE/CREDENTIAL/
// ACCOUNT are the principal scope names.
func validAssertionScope(s string) bool {
	switch s {
	case "inference", "REQUEST", "LANE", "CREDENTIAL", "ACCOUNT":
		return true
	}
	return false
}

// requiresLaneScope reports whether the scope set demands lane context.
func requiresLaneScope(scopes []string) bool {
	for _, s := range scopes {
		if s == "LANE" {
			return true
		}
	}
	return false
}

// Claims decodes the payload JSON without exposing more than the claim set.
func (a *Assertion) Claims() Claims { return a.claims }

// Encode returns the versioned wire format: v1.base64url(payload).base64url(sig).
func (a *Assertion) Encode() string {
	return assertionWireVersion + "." + base64.RawURLEncoding.EncodeToString(a.raw) + "." + base64.RawURLEncoding.EncodeToString(a.signature)
}

// ParseAndVerify validates an encoded assertion against a public key, the
// expected audience, and a sanity window. It rejects expired (INV-10) and
// wrong-audience (INV-11) assertions.
//
// P0.18 strictness: a malformed-but-correctly-signed authority must fail.
// Beyond signature/TTL/audience this requires a nonempty expected audience,
// Subject, CredentialID, JTI, a valid kid, PolicyRev/CredRev > 0, a bounded
// allowlisted scope set (LaneID required when lane scope is present), and a
// bounded encoded size.
func ParseAndVerify(encoded string, pub ed25519.PublicKey, expectedAudience string, now time.Time) (*Claims, error) {
	if expectedAudience == "" {
		// A verifier that forgot its audience binding accepts any audience —
		// the INV-11 hole. Fail closed at the verifier, not the caller.
		return nil, ErrWrongAudience
	}
	if len(encoded) > maxEncodedAssertionBytes {
		return nil, ErrBadAssertion
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 || parts[0] != assertionWireVersion || parts[1] == "" || parts[2] == "" {
		return nil, ErrBadAssertion
	}
	payloadB64, sigB64 := parts[1], parts[2]
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrBadAssertion
	}
	if len(payload) > maxAssertionPayloadBytes {
		return nil, ErrBadAssertion
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrBadAssertion
	}
	if len(sig) != ed25519.SignatureSize {
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
	if c.ExpiresAt <= c.IssuedAt {
		return nil, ErrBadAssertion
	}
	if c.Subject == "" || c.CredID == "" || c.JTI == "" {
		return nil, ErrBadAssertion
	}
	if c.PolicyRev < 1 || c.CredRev < 1 {
		return nil, ErrBadAssertion
	}
	if len(c.Scope) == 0 || len(c.Scope) > maxAssertionScopes {
		return nil, ErrBadAssertion
	}
	for _, sc := range c.Scope {
		if !validAssertionScope(sc) {
			return nil, ErrBadAssertion
		}
	}
	if requiresLaneScope(c.Scope) && c.LaneID == "" {
		return nil, ErrBadAssertion
	}
	return &c, nil
}

// maxEncodedAssertionBytes bounds the total encoded assertion (P0.18).
const maxEncodedAssertionBytes = 8192

// assertionIssuer is the only issuer internal verifiers accept.
const assertionIssuer = "gripline"

const assertionWireVersion = "v1"

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
