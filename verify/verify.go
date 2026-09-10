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
	"container/heap"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/protocollimits"
)

const (
	// AssertionHeader is the single trusted-hop carrier.
	AssertionHeader = "X-Gripline-Assertion"
	// AssertionWireVersion is the frozen version prefix for assertion tokens.
	AssertionWireVersion = "v1"
	issuer               = "gripline"
	maxScopes            = 8
	maxPayloadBytes      = 4096
	maxTokenBytes        = 8192
)

// Claims is the authenticated, non-secret principal passed to the provider.
type Claims struct {
	Issuer      string   `json:"iss"`
	Subject     string   `json:"sub"`
	CredID      string   `json:"cid"`
	LaneID      string   `json:"ctx"`
	Audience    string   `json:"aud"`
	IssuedAt    int64    `json:"iat"`
	ExpiresAt   int64    `json:"exp"`
	JTI         string   `json:"jti"`
	PolicyRev   int      `json:"policy_rev"`
	PolicyEpoch uint64   `json:"policy_epoch,omitempty"`
	CredRev     int      `json:"cred_rev"`
	Scope       []string `json:"scope"`
	KeyID       int      `json:"kid"`
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

// ContextRevisionSource is the context-aware form of RevisionSource. When
// configured, the verifier uses it so an authority lookup cannot outlive the
// request being authenticated.
type ContextRevisionSource interface {
	CredentialRevisionContext(context.Context, string) (int, error)
}

// PolicyEpochSource supplies the current activation epoch from the policy
// authority. A verifier configured with this source rejects assertions from a
// prior activation, including assertions whose policy revision is lower but
// whose artifact is otherwise known-good after a rollback.
type PolicyEpochSource interface {
	PolicyEpoch() (uint64, bool)
}

// ContextPolicyEpochSource is the context-aware form of PolicyEpochSource.
type ContextPolicyEpochSource interface {
	PolicyEpochContext(context.Context) (uint64, error)
}

// TransportTrust proves the request arrived over the provider's trusted
// private transport. It must inspect connection identity, not application
// headers.
type TransportTrust interface {
	Trusted(*http.Request) bool
}

// ReplayGuard is an optional, atomic assertion-use record. Accept must return
// true exactly once for a JTI until expiresAt. A distributed backend should
// implement this against its shared authority; a local guard only protects
// one verifier instance.
type ReplayGuard interface {
	Accept(context.Context, ReplayClaim) (bool, error)
}

// ReplayClaim gives a shared replay authority an explicit namespace. A JTI is
// only unique within its issuer/audience domain; keeping those fields in the
// public contract prevents cross-service collisions in one shared store.
type ReplayClaim struct {
	Issuer    string
	Audience  string
	JTI       string
	ExpiresAt time.Time
}

// MemoryReplayGuard is a bounded single-process replay guard. It fails closed
// when its live table is full rather than evicting unexpired JTIs. Use a
// shared ReplayGuard for active/active backend instances.
type MemoryReplayGuard struct {
	mu       sync.Mutex
	max      int
	now      func() time.Time
	entries  map[string]time.Time
	expiries replayExpiryHeap
}

type replayExpiry struct {
	key     string
	expires time.Time
}

type replayExpiryHeap []replayExpiry

func (h replayExpiryHeap) Len() int           { return len(h) }
func (h replayExpiryHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h replayExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *replayExpiryHeap) Push(x any)        { *h = append(*h, x.(replayExpiry)) }
func (h *replayExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// NewMemoryReplayGuard constructs a bounded local replay guard. A non-positive
// capacity selects a conservative 100,000-entry default.
func NewMemoryReplayGuard(maxEntries int) *MemoryReplayGuard {
	if maxEntries <= 0 {
		maxEntries = 100000
	}
	return &MemoryReplayGuard{max: maxEntries, now: time.Now, entries: make(map[string]time.Time, maxEntries)}
}

// Accept atomically claims a namespaced JTI until expiry. Expired claims are
// removed from a min-heap, so cleanup is proportional to claims that actually
// expired rather than to the full live table on every request.
func (g *MemoryReplayGuard) Accept(ctx context.Context, claim ReplayClaim) (bool, error) {
	if err := contextErr(ctx); err != nil {
		return false, err
	}
	if g == nil || strings.TrimSpace(claim.Issuer) == "" || strings.TrimSpace(claim.Audience) == "" || strings.TrimSpace(claim.JTI) == "" || claim.ExpiresAt.IsZero() {
		return false, ErrReplayGuardUnavailable
	}
	now := g.now()
	if !now.Before(claim.ExpiresAt) {
		return false, ErrReplayGuardUnavailable
	}
	key := replayKey(claim)
	g.mu.Lock()
	defer g.mu.Unlock()
	for len(g.expiries) > 0 && !now.Before(g.expiries[0].expires) {
		item := heap.Pop(&g.expiries).(replayExpiry)
		if expiry, exists := g.entries[item.key]; exists && !now.Before(expiry) {
			delete(g.entries, item.key)
		}
	}
	if _, exists := g.entries[key]; exists {
		return false, nil
	}
	if len(g.entries) >= g.max {
		return false, ErrReplayGuardCapacity
	}
	g.entries[key] = claim.ExpiresAt
	heap.Push(&g.expiries, replayExpiry{key: key, expires: claim.ExpiresAt})
	return true, nil
}

func replayKey(claim ReplayClaim) string {
	data := strings.Join([]string{claim.Issuer, claim.Audience, claim.JTI}, "\x00")
	sum := sha256.Sum256([]byte(data))
	return string(sum[:])
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

// MTLSOptions describes the provider-side service identities accepted on the
// trusted hop. At least one exact SPIFFE ID or DNS name must be configured;
// accepting any client certificate would turn mTLS into encryption-only.
type MTLSOptions struct {
	AllowedSPIFFEIDs []string
	AllowedDNSNames  []string
}

type mtlsTrust struct {
	spiffe map[string]struct{}
	dns    map[string]struct{}
}

// RequireMTLS returns a concrete TransportTrust implementation for HTTP
// servers using verified client certificates. It checks the TLS connection's
// verified peer identity, never application headers. Use a different
// certificate identity for verifier-management traffic than for inference.
func RequireMTLS(opts MTLSOptions) TransportTrust {
	t := &mtlsTrust{spiffe: make(map[string]struct{}), dns: make(map[string]struct{})}
	for _, id := range opts.AllowedSPIFFEIDs {
		if id = strings.TrimSpace(id); id != "" {
			t.spiffe[id] = struct{}{}
		}
	}
	for _, name := range opts.AllowedDNSNames {
		if name = strings.TrimSpace(name); name != "" {
			t.dns[name] = struct{}{}
		}
	}
	return t
}

func (t *mtlsTrust) Trusted(r *http.Request) bool {
	if t == nil || r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return false
	}
	for _, uri := range r.TLS.PeerCertificates[0].URIs {
		if _, ok := t.spiffe[uri.String()]; ok {
			return true
		}
	}
	for _, name := range r.TLS.PeerCertificates[0].DNSNames {
		if _, ok := t.dns[name]; ok {
			return true
		}
	}
	return false
}

// Verifier validates the short-lived assertion and provides middleware for a
// protected HTTP handler.
type Verifier struct {
	mu                  sync.RWMutex
	keys                map[int]ed25519.PublicKey
	audience            string
	now                 func() time.Time
	revisions           RevisionSource
	contextRevisions    ContextRevisionSource
	minPolicyRev        int
	policyEpochs        PolicyEpochSource
	contextPolicyEpochs ContextPolicyEpochSource
	minPolicyEpoch      uint64
	transport           TransportTrust
	replay              ReplayGuard
}

// ProductionOptions is the fail-closed constructor contract for a backend
// that is claiming production readiness. New remains available for narrowly
// scoped compatibility fixtures; production code should use this constructor
// so transport trust, distributed replay, and authority freshness cannot be
// accidentally left opt-in.
type ProductionOptions struct {
	KeySet   *KeySet
	Audience string

	Transport TransportTrust
	Replay    ReplayGuard

	CredentialRevisions        RevisionSource
	ContextCredentialRevisions ContextRevisionSource
	MinPolicyRevision          int
	PolicyEpochs               PolicyEpochSource
	ContextPolicyEpochs        ContextPolicyEpochSource
	MinPolicyEpoch             uint64
}

// PublishKey installs one public signer generation for the verifier overlap
// window. A backend control plane may call this only after authenticating its
// operator/runtime transport; the caller can then verify a candidate canary
// before Gripline makes the generation authoritative. Re-publishing the exact
// same key is idempotent, while a KID collision with different material fails
// closed.
func (v *Verifier) PublishKey(kid int, pub ed25519.PublicKey) error {
	if v == nil || kid < 1 || len(pub) != ed25519.PublicKeySize {
		return errors.New("gripline verify: invalid public key publication")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if existing, ok := v.keys[kid]; ok {
		if !bytes.Equal(existing, pub) {
			return fmt.Errorf("gripline verify: key %d already published with different material", kid)
		}
		return nil
	}
	v.keys[kid] = append(ed25519.PublicKey(nil), pub...)
	return nil
}

// RetireKey removes one previously published generation after the caller has
// enforced its assertion-overlap horizon. The fingerprint check prevents a
// control-plane request for one generation from deleting a different key
// after a misconfiguration or KID reuse. Repeating retirement is idempotent.
func (v *Verifier) RetireKey(kid int, fingerprint string) error {
	if v == nil || kid < 1 || strings.TrimSpace(fingerprint) == "" {
		return errors.New("gripline verify: invalid public key retirement")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	pub, ok := v.keys[kid]
	if !ok {
		return nil
	}
	sum := sha256.Sum256(pub)
	if hex.EncodeToString(sum[:]) != fingerprint {
		return fmt.Errorf("gripline verify: key %d fingerprint mismatch during retirement", kid)
	}
	delete(v.keys, kid)
	return nil
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

// NewProduction constructs a verifier with the minimum non-optional
// production controls enabled: an exact audience, transport trust, an atomic
// replay authority, credential revision freshness, and policy activation
// epoch freshness. This prevents a backend from silently shipping the
// signature-only verifier posture.
func NewProduction(opts ProductionOptions) (*Verifier, error) {
	if opts.KeySet == nil {
		return nil, errors.New("gripline verify: production key set required")
	}
	if strings.TrimSpace(opts.Audience) == "" {
		return nil, errors.New("gripline verify: production audience required")
	}
	if opts.Transport == nil {
		return nil, errors.New("gripline verify: production transport trust required")
	}
	if opts.Replay == nil {
		return nil, errors.New("gripline verify: production replay guard required")
	}
	if opts.CredentialRevisions == nil && opts.ContextCredentialRevisions == nil {
		return nil, errors.New("gripline verify: production credential revision source required")
	}
	if opts.PolicyEpochs == nil && opts.ContextPolicyEpochs == nil {
		return nil, errors.New("gripline verify: production policy epoch source required")
	}
	v, err := New(opts.KeySet, opts.Audience)
	if err != nil {
		return nil, err
	}
	v.RequireTransportTrust(opts.Transport).WithReplayGuard(opts.Replay)
	if opts.ContextCredentialRevisions != nil {
		v.WithContextRevisionChecks(opts.ContextCredentialRevisions, opts.MinPolicyRevision)
	} else {
		v.WithRevisionChecks(opts.CredentialRevisions, opts.MinPolicyRevision)
	}
	if opts.ContextPolicyEpochs != nil {
		v.WithContextPolicyEpochChecks(opts.ContextPolicyEpochs, opts.MinPolicyEpoch)
	} else {
		v.WithPolicyEpochChecks(opts.PolicyEpochs, opts.MinPolicyEpoch)
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
	v.contextRevisions = nil
	if contextSource, ok := src.(ContextRevisionSource); ok {
		v.contextRevisions = contextSource
	}
	return v
}

// WithContextRevisionChecks is the primary API for distributed authorities
// that only expose cancellable freshness lookups. It avoids requiring such an
// authority to implement the legacy context-free interface as well.
func (v *Verifier) WithContextRevisionChecks(src ContextRevisionSource, minPolicyRev int) *Verifier {
	v.contextRevisions, v.revisions, v.minPolicyRev = src, nil, minPolicyRev
	return v
}

// WithPolicyEpochChecks enables exact activation-epoch freshness checks. The
// source is optional; when nil, minEpoch still provides a lower-bound check.
func (v *Verifier) WithPolicyEpochChecks(src PolicyEpochSource, minEpoch uint64) *Verifier {
	v.policyEpochs, v.minPolicyEpoch = src, minEpoch
	v.contextPolicyEpochs = nil
	if contextSource, ok := src.(ContextPolicyEpochSource); ok {
		v.contextPolicyEpochs = contextSource
	}
	return v
}

// WithContextPolicyEpochChecks is the cancellable counterpart to
// WithPolicyEpochChecks for distributed policy authorities.
func (v *Verifier) WithContextPolicyEpochChecks(src ContextPolicyEpochSource, minEpoch uint64) *Verifier {
	v.contextPolicyEpochs, v.policyEpochs, v.minPolicyEpoch = src, nil, minEpoch
	return v
}

func (v *Verifier) RequireTransportTrust(trust TransportTrust) *Verifier {
	v.transport = trust
	return v
}

// WithReplayGuard enables atomic JTI claims after signature, freshness, and
// transport checks succeed. It is opt-in for compatibility with bearer-style
// deployments; sensitive backends should configure a local or shared guard.
func (v *Verifier) WithReplayGuard(guard ReplayGuard) *Verifier {
	v.replay = guard
	return v
}

// Verify authenticates an assertion without mutating the request.
func (v *Verifier) Verify(r *http.Request) (*Claims, error) {
	return v.VerifyContext(context.Background(), r)
}

// VerifyContext authenticates an assertion while carrying ctx into
// authoritative freshness lookups.
func (v *Verifier) VerifyContext(ctx context.Context, r *http.Request) (*Claims, error) {
	if v == nil || r == nil {
		return nil, ErrBadAssertion
	}
	if ctx == nil {
		ctx = context.Background()
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
	return v.verifyEncodedContext(ctx, values[0])
}

// VerifyAndStrip authenticates the request and removes the assertion only
// after successful verification. The returned Claims are the replacement
// principal representation for downstream code.
func (v *Verifier) VerifyAndStrip(r *http.Request) (*Claims, error) {
	return v.VerifyAndStripContext(context.Background(), r)
}

// VerifyAndStripContext authenticates and strips an assertion using ctx for
// authoritative freshness lookups.
func (v *Verifier) VerifyAndStripContext(ctx context.Context, r *http.Request) (*Claims, error) {
	claims, err := v.VerifyContext(ctx, r)
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
		claims, err := v.VerifyAndStripContext(r.Context(), r)
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

func (v *Verifier) verifyEncodedContext(ctx context.Context, encoded string) (*Claims, error) {
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
	v.mu.RLock()
	pub, ok := v.keys[envelope.KeyID]
	pub = append(ed25519.PublicKey(nil), pub...)
	v.mu.RUnlock()
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
	if c.PolicyRev < 1 || c.CredRev < 1 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(protocollimits.MaxAssertionTTL/time.Second) {
		return nil, ErrBadAssertion
	}
	now := v.now()
	if now.Unix() >= c.ExpiresAt {
		return nil, ErrExpired
	}
	if now.Unix() < c.IssuedAt-int64(protocollimits.AssertionClockSkew/time.Second) {
		return nil, ErrNotYetValid
	}
	if v.contextRevisions != nil || v.revisions != nil {
		if v.contextRevisions != nil {
			current, err := v.contextRevisions.CredentialRevisionContext(ctx, c.CredID)
			if err != nil {
				return nil, ErrCredentialRevisionUnavailable
			}
			if current != c.CredRev {
				return nil, ErrStaleCredentialRevision
			}
		} else {
			current, exists := v.revisions.CredentialRevision(c.CredID)
			if !exists || current != c.CredRev {
				return nil, ErrStaleCredentialRevision
			}
		}
		if c.PolicyRev < v.minPolicyRev {
			return nil, ErrStalePolicyRevision
		}
	}
	if v.contextPolicyEpochs != nil || v.policyEpochs != nil || v.minPolicyEpoch > 0 {
		if c.PolicyEpoch == 0 || c.PolicyEpoch < v.minPolicyEpoch {
			return nil, ErrStalePolicyEpoch
		}
		if v.contextPolicyEpochs != nil || v.policyEpochs != nil {
			var current uint64
			var err error
			if v.contextPolicyEpochs != nil {
				current, err = v.contextPolicyEpochs.PolicyEpochContext(ctx)
			} else {
				var exists bool
				current, exists = v.policyEpochs.PolicyEpoch()
				if !exists {
					err = ErrPolicyEpochUnavailable
				}
			}
			if err != nil {
				return nil, ErrPolicyEpochUnavailable
			}
			if current == 0 || c.PolicyEpoch != current {
				return nil, ErrStalePolicyEpoch
			}
		}
	}
	if v.replay != nil {
		accepted, err := v.replay.Accept(ctx, ReplayClaim{
			Issuer: c.Issuer, Audience: c.Audience, JTI: c.JTI,
			ExpiresAt: time.Unix(c.ExpiresAt, 0),
		})
		if err != nil {
			return nil, ErrReplayGuardUnavailable
		}
		if !accepted {
			return nil, ErrReplayDetected
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
	ErrMissingAssertion              = errors.New("gripline verify: missing assertion")
	ErrDuplicateAssertion            = errors.New("gripline verify: duplicate assertion")
	ErrBadAssertion                  = errors.New("gripline verify: bad assertion")
	ErrBadSignature                  = errors.New("gripline verify: bad signature")
	ErrUnknownKey                    = errors.New("gripline verify: unknown signing key")
	ErrWrongIssuer                   = errors.New("gripline verify: wrong issuer")
	ErrWrongAudience                 = errors.New("gripline verify: wrong audience")
	ErrExpired                       = errors.New("gripline verify: assertion expired")
	ErrNotYetValid                   = errors.New("gripline verify: assertion not yet valid")
	ErrStaleCredentialRevision       = errors.New("gripline verify: stale credential revision")
	ErrCredentialRevisionUnavailable = errors.New("gripline verify: credential revision unavailable")
	ErrStalePolicyRevision           = errors.New("gripline verify: stale policy revision")
	ErrStalePolicyEpoch              = errors.New("gripline verify: stale policy activation epoch")
	ErrPolicyEpochUnavailable        = errors.New("gripline verify: policy activation epoch unavailable")
	ErrUntrustedTransport            = errors.New("gripline verify: untrusted transport")
	ErrReplayDetected                = errors.New("gripline verify: assertion replay detected")
	ErrReplayGuardUnavailable        = errors.New("gripline verify: replay guard unavailable")
	ErrReplayGuardCapacity           = errors.New("gripline verify: replay guard capacity exhausted")
)
