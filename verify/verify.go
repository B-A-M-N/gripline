// Package verify is Gripline's supported provider-facing backend verifier.
//
// It intentionally depends only on the Go standard library. A protected
// service can import this package without importing Gripline's internal
// terminator, signer, policy, or credential implementation. The key-set
// loader consumes the JSON emitted by `gripline keys export`; only public
// Ed25519 verification keys enter this package.
package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// AssertionHeader is the single trusted-hop carrier.
	AssertionHeader = "X-Gripline-Assertion"
	// AssertionWireVersion is the frozen version prefix for assertion tokens.
	AssertionWireVersion = "v1"
	issuer               = "gripline"
	maxTTLSeconds        = 30
	maxScopes            = 8
	maxPayloadBytes      = 4096
	maxTokenBytes        = 8192
)

// Claims is the authenticated, non-secret principal passed to the provider.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	CredID    string   `json:"cid"`
	LaneID    string   `json:"ctx"`
	Audience  string   `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	JTI       string   `json:"jti"`
	PolicyRev int      `json:"policy_rev"`
	CredRev   int      `json:"cred_rev"`
	Scope     []string `json:"scope"`
	KeyID     int      `json:"kid"`
}

// KeyMaterial is one public key entry from `gripline keys export`.
type KeyMaterial struct {
	KID         int    `json:"kid"`
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// KeySet is the public verification material published to a provider backend.
type KeySet struct {
	Keys        []KeyMaterial `json:"keys"`
	ActiveKID   int           `json:"active_kid"`
	GeneratedAt string        `json:"generated_at,omitempty"`
}

// LoadKeySet validates a bounded JSON key publication. Duplicate KIDs, bad
// algorithms, invalid key sizes, and a missing active key are rejected.
func LoadKeySet(r io.Reader) (*KeySet, error) {
	if r == nil {
		return nil, errors.New("gripline verify: nil key-set reader")
	}
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read key set: %w", err)
	}
	var set KeySet
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("parse key set: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("parse key set: trailing JSON value")
	}
	if err := set.validate(); err != nil {
		return nil, err
	}
	return &set, nil
}

// NewKeySet constructs public key material from an in-memory publication.
func NewKeySet(keys map[int]ed25519.PublicKey, activeKID int) (*KeySet, error) {
	set := &KeySet{ActiveKID: activeKID, Keys: make([]KeyMaterial, 0, len(keys))}
	for kid, pub := range keys {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %d: invalid Ed25519 public key size", kid)
		}
		sum := sha256.Sum256(pub)
		set.Keys = append(set.Keys, KeyMaterial{
			KID: kid, Algorithm: "Ed25519",
			PublicKey:   base64.StdEncoding.EncodeToString(pub),
			Fingerprint: base64.StdEncoding.EncodeToString(sum[:8]),
		})
	}
	if err := set.validate(); err != nil {
		return nil, err
	}
	return set, nil
}

func (s *KeySet) validate() error {
	if s == nil || len(s.Keys) == 0 {
		return errors.New("gripline verify: key set is empty")
	}
	seen := make(map[int]struct{}, len(s.Keys))
	for _, key := range s.Keys {
		if key.KID < 1 {
			return fmt.Errorf("gripline verify: key id must be positive")
		}
		if _, ok := seen[key.KID]; ok {
			return fmt.Errorf("gripline verify: duplicate key id %d", key.KID)
		}
		seen[key.KID] = struct{}{}
		if key.Algorithm != "Ed25519" {
			return fmt.Errorf("gripline verify: key %d uses unsupported algorithm %q", key.KID, key.Algorithm)
		}
		pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("gripline verify: key %d has invalid public key", key.KID)
		}
		if key.Fingerprint != "" {
			sum := sha256.Sum256(pub)
			want := base64.StdEncoding.EncodeToString(sum[:8])
			if key.Fingerprint != want {
				return fmt.Errorf("gripline verify: key %d fingerprint mismatch", key.KID)
			}
		}
	}
	if s.ActiveKID > 0 {
		if _, ok := seen[s.ActiveKID]; !ok {
			return fmt.Errorf("gripline verify: active key %d is not published", s.ActiveKID)
		}
	}
	return nil
}

// RevisionSource is an optional authoritative freshness check for sensitive
// provider endpoints.
type RevisionSource interface {
	CredentialRevision(credentialID string) (int, bool)
}

// TransportTrust proves the request arrived over the provider's trusted
// private transport. It must inspect connection identity, not application
// headers.
type TransportTrust interface {
	Trusted(*http.Request) bool
}

// Verifier validates the short-lived assertion and provides middleware for a
// protected HTTP handler.
type Verifier struct {
	keys         map[int]ed25519.PublicKey
	audience     string
	now          func() time.Time
	revisions    RevisionSource
	minPolicyRev int
	transport    TransportTrust
}

// New constructs a verifier bound to one exact audience.
func New(set *KeySet, audience string) (*Verifier, error) {
	if set == nil {
		return nil, errors.New("gripline verify: key set required")
	}
	if err := set.validate(); err != nil {
		return nil, err
	}
	if audience == "" {
		return nil, ErrWrongAudience
	}
	v := &Verifier{keys: make(map[int]ed25519.PublicKey, len(set.Keys)), audience: audience, now: time.Now}
	for _, key := range set.Keys {
		pub, _ := base64.StdEncoding.DecodeString(key.PublicKey)
		v.keys[key.KID] = append(ed25519.PublicKey(nil), pub...)
	}
	return v, nil
}

func (v *Verifier) WithClock(now func() time.Time) *Verifier {
	if now != nil {
		v.now = now
	}
	return v
}

func (v *Verifier) WithRevisionChecks(src RevisionSource, minPolicyRev int) *Verifier {
	v.revisions, v.minPolicyRev = src, minPolicyRev
	return v
}

func (v *Verifier) RequireTransportTrust(trust TransportTrust) *Verifier {
	v.transport = trust
	return v
}

// Verify authenticates an assertion without mutating the request.
func (v *Verifier) Verify(r *http.Request) (*Claims, error) {
	if v == nil || r == nil {
		return nil, ErrBadAssertion
	}
	if v.transport != nil && !v.transport.Trusted(r) {
		return nil, ErrUntrustedTransport
	}
	values := r.Header.Values(AssertionHeader)
	if len(values) == 0 {
		return nil, ErrMissingAssertion
	}
	if len(values) != 1 {
		return nil, ErrDuplicateAssertion
	}
	return v.verifyEncoded(values[0])
}

// VerifyAndStrip authenticates the request and removes the assertion only
// after successful verification. The returned Claims are the replacement
// principal representation for downstream code.
func (v *Verifier) VerifyAndStrip(r *http.Request) (*Claims, error) {
	claims, err := v.Verify(r)
	if err != nil {
		return nil, err
	}
	r.Header.Del(AssertionHeader)
	return claims, nil
}

type claimsContextKey struct{}

// Middleware verifies and strips the assertion before invoking next.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := v.VerifyAndStrip(r)
		if err != nil {
			http.Error(w, "assertion required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsContextKey{}, claims)))
	})
}

// ClaimsFromContext returns the principal installed by Middleware.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*Claims)
	return claims, ok
}

func (v *Verifier) verifyEncoded(encoded string) (*Claims, error) {
	if encoded == "" || len(encoded) > maxTokenBytes {
		return nil, ErrBadAssertion
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 || parts[0] != AssertionWireVersion || parts[1] == "" || parts[2] == "" {
		return nil, ErrBadAssertion
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) == 0 || len(payload) > maxPayloadBytes {
		return nil, ErrBadAssertion
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrBadAssertion
	}
	var envelope struct {
		KeyID int `json:"kid"`
	}
	if err := rejectDuplicateKeys(payload); err != nil || json.Unmarshal(payload, &envelope) != nil || envelope.KeyID < 1 {
		return nil, ErrBadAssertion
	}
	pub, ok := v.keys[envelope.KeyID]
	if !ok {
		return nil, ErrUnknownKey
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, ErrBadSignature
	}
	var c Claims
	if err := decodeClaims(payload, &c); err != nil {
		return nil, ErrBadAssertion
	}
	if c.Issuer != issuer {
		return nil, ErrWrongIssuer
	}
	if c.Audience != v.audience {
		return nil, ErrWrongAudience
	}
	if c.KeyID != envelope.KeyID || c.Subject == "" || c.CredID == "" || c.JTI == "" || c.IssuedAt <= 0 || c.ExpiresAt <= 0 {
		return nil, ErrBadAssertion
	}
	if len(c.Scope) == 0 || len(c.Scope) > maxScopes {
		return nil, ErrBadAssertion
	}
	seenScope := make(map[string]struct{}, len(c.Scope))
	for _, scope := range c.Scope {
		if _, exists := seenScope[scope]; exists || !validScope(scope) {
			return nil, ErrBadAssertion
		}
		seenScope[scope] = struct{}{}
	}
	if requiresLane(c.Scope) && c.LaneID == "" {
		return nil, ErrBadAssertion
	}
	if c.PolicyRev < 1 || c.CredRev < 1 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > maxTTLSeconds {
		return nil, ErrBadAssertion
	}
	now := v.now()
	if now.Unix() >= c.ExpiresAt {
		return nil, ErrExpired
	}
	if now.Unix() < c.IssuedAt-5 {
		return nil, ErrNotYetValid
	}
	if v.revisions != nil {
		current, exists := v.revisions.CredentialRevision(c.CredID)
		if !exists || current != c.CredRev {
			return nil, ErrStaleCredentialRevision
		}
		if c.PolicyRev < v.minPolicyRev {
			return nil, ErrStalePolicyRevision
		}
	}
	return &c, nil
}

func decodeClaims(payload []byte, dst any) error {
	if err := rejectDuplicateKeys(payload); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func rejectDuplicateKeys(payload []byte) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	start, ok := tok.(json.Delim)
	if !ok || start != '{' {
		return errors.New("claims must be an object")
	}
	seen := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("claim key must be a string")
		}
		if _, exists := seen[key]; exists {
			return errors.New("duplicate claim")
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

func validScope(s string) bool {
	switch s {
	case "inference", "REQUEST", "LANE", "CREDENTIAL", "ACCOUNT":
		return true
	default:
		return false
	}
}

func requiresLane(scopes []string) bool {
	for _, s := range scopes {
		if s == "LANE" {
			return true
		}
	}
	return false
}

var (
	ErrMissingAssertion        = errors.New("gripline verify: missing assertion")
	ErrDuplicateAssertion      = errors.New("gripline verify: duplicate assertion")
	ErrBadAssertion            = errors.New("gripline verify: bad assertion")
	ErrBadSignature            = errors.New("gripline verify: bad signature")
	ErrUnknownKey              = errors.New("gripline verify: unknown signing key")
	ErrWrongIssuer             = errors.New("gripline verify: wrong issuer")
	ErrWrongAudience           = errors.New("gripline verify: wrong audience")
	ErrExpired                 = errors.New("gripline verify: assertion expired")
	ErrNotYetValid             = errors.New("gripline verify: assertion not yet valid")
	ErrStaleCredentialRevision = errors.New("gripline verify: stale credential revision")
	ErrStalePolicyRevision     = errors.New("gripline verify: stale policy revision")
	ErrUntrustedTransport      = errors.New("gripline verify: untrusted transport")
)
