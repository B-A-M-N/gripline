package proxy

import (
	"context"
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
// P0.17: it accepts PUBLIC verification material only — a fixed public key or
// a *terminator.VerifierKeyring. The old shape accepted *terminator.Keyring,
// whose possession implies signing authority (Issue/Rotate): a verifier that
// can mint its own assertions defeats the issuer/verifier isolation.
type BackendVerifier struct {
	// keyring, when set, is the rotation-aware verifier path (P0.59) over
	// published public keys only (P0.17).
	keyring *terminator.VerifierKeyring
	// pub is the fixed single-key path (back-compat), used when keyring is nil.
	pub      ed25519.PublicKey
	audience string
	now      func() time.Time

	// Revision freshness (P0.19): optional AUTHORITATIVE revision checks for
	// sensitive backends. An assertion cryptographically valid but minted
	// before a credential revision bump (revocation, status change, key
	// rotation) is rejected when rev is set and the assertion's CredRev is
	// stale; minPolicyRev rejects assertions minted under an older policy
	// revision. Stateless TTL-only verifiers leave both zero (their service
	// class: TTL is the freshness bound — ≤30s INV-10).
	rev            RevisionSource
	contextRev     ContextRevisionSource
	minPolicyRev   int
	policyEpochs   PolicyEpochSource
	contextEpochs  ContextPolicyEpochSource
	minPolicyEpoch uint64
	// transport is the P0.53 gate: required network/service identity, proven
	// below the assertion. Nil = not enforced (tests, non-sensitive hop).
	transport TransportIdentity
}

// RevisionSource is the authoritative revision lookup a sensitive backend
// supplies (P0.19). CredentialRevision must return the CURRENT revision of a
// credential; a lookup failure fails CLOSED (unknown freshness is stale).
type RevisionSource interface {
	CredentialRevision(credID string) (int, bool)
}

// ContextRevisionSource is the request-aware form of RevisionSource. It lets
// a distributed backend authority stop an in-flight lookup when the request
// is canceled.
type ContextRevisionSource interface {
	CredentialRevisionContext(context.Context, string) (int, error)
}

// PolicyEpochSource supplies the exact active policy activation epoch. Unlike
// a policy revision, this remains fresh across rollback to an older artifact.
type PolicyEpochSource interface {
	PolicyEpoch() (uint64, bool)
}

// ContextPolicyEpochSource is the request-aware form of PolicyEpochSource.
type ContextPolicyEpochSource interface {
	PolicyEpochContext(context.Context) (uint64, error)
}

// WithRevisionChecks enables P0.19 enforcement: assertions whose cred_rev is
// behind the authoritative current revision, or whose policy_rev is below
// minPolicyRev, are rejected even while cryptographically valid. High-value
// operations set this; stateless TTL-only services do not.
func (b *BackendVerifier) WithRevisionChecks(src RevisionSource, minPolicyRev int) *BackendVerifier {
	b.rev = src
	b.minPolicyRev = minPolicyRev
	b.contextRev = nil
	if contextSource, ok := src.(ContextRevisionSource); ok {
		b.contextRev = contextSource
	}
	return b
}

// WithContextRevisionChecks is the cancellable freshness API for distributed
// backends whose authority intentionally has no context-free lookup method.
func (b *BackendVerifier) WithContextRevisionChecks(src ContextRevisionSource, minPolicyRev int) *BackendVerifier {
	b.contextRev, b.rev = src, nil
	b.minPolicyRev = minPolicyRev
	return b
}

// WithPolicyEpochChecks enables exact activation-epoch checks for sensitive
// backend routes. A nil source still permits a lower-bound-only check.
func (b *BackendVerifier) WithPolicyEpochChecks(src PolicyEpochSource, minEpoch uint64) *BackendVerifier {
	b.policyEpochs = src
	b.minPolicyEpoch = minEpoch
	b.contextEpochs = nil
	if contextSource, ok := src.(ContextPolicyEpochSource); ok {
		b.contextEpochs = contextSource
	}
	return b
}

// WithContextPolicyEpochChecks is the cancellable counterpart to
// WithPolicyEpochChecks.
func (b *BackendVerifier) WithContextPolicyEpochChecks(src ContextPolicyEpochSource, minEpoch uint64) *BackendVerifier {
	b.contextEpochs, b.policyEpochs = src, nil
	b.minPolicyEpoch = minEpoch
	return b
}

// NewBackendVerifier configures a verifier with a FIXED internal signer's
// public key and the exact audience the proxy issues to (INV-11 binding). Use
// NewBackendVerifierKeyring for rotation.
func NewBackendVerifier(pub ed25519.PublicKey, audience string) *BackendVerifier {
	return &BackendVerifier{pub: pub, audience: audience}
}

// NewBackendVerifierKeyring configures a verifier that follows the signer's
// rotation (P0.59) via PUBLISHED public keys only (P0.17): the key is selected
// per-assertion by its kid.
func NewBackendVerifierKeyring(keyring *terminator.VerifierKeyring, audience string) *BackendVerifier {
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
// unknown signing generation (P0.59), stale credential/policy revision (P0.19,
// when revision checks are enabled), or a forged/invalid carrier. It never
// touches the external secret headers.
func (b *BackendVerifier) Verify(r *http.Request) (*terminator.Claims, error) {
	return b.VerifyContext(context.Background(), r)
}

// VerifyContext is Verify with request context propagated to authoritative
// freshness lookups.
func (b *BackendVerifier) VerifyContext(ctx context.Context, r *http.Request) (*terminator.Claims, error) {
	if r == nil {
		return nil, fmt.Errorf("backend: nil request")
	}
	if ctx == nil {
		ctx = context.Background()
	}
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
	// P0.53: transport identity is checked BEFORE the assertion — a valid
	// assertion over an untrusted connection is still an untrusted request.
	if b.transport != nil && !b.transport.Trusted(r) {
		return nil, fmt.Errorf("backend: transport identity not trusted (P0.53)")
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
	// P0.19: authoritative revision freshness for sensitive backends. The
	// lookup failing is stale-by-unknown → deny (fail closed).
	if b.contextRev != nil || b.rev != nil {
		var cur int
		var ok bool
		if b.contextRev != nil {
			value, lookupErr := b.contextRev.CredentialRevisionContext(ctx, claims.CredID)
			cur, ok = value, lookupErr == nil
		} else {
			cur, ok = b.rev.CredentialRevision(claims.CredID)
		}
		if !ok || cur != claims.CredRev {
			return nil, fmt.Errorf("backend: assertion cred_rev %d stale (current %v) (P0.19)", claims.CredRev, cur)
		}
		if claims.PolicyRev < b.minPolicyRev {
			return nil, fmt.Errorf("backend: assertion policy_rev %d below minimum %d (P0.19)", claims.PolicyRev, b.minPolicyRev)
		}
	}
	if b.contextEpochs != nil || b.policyEpochs != nil || b.minPolicyEpoch > 0 {
		if claims.PolicyEpoch == 0 || claims.PolicyEpoch < b.minPolicyEpoch {
			return nil, fmt.Errorf("backend: assertion policy epoch %d is stale (P0.19)", claims.PolicyEpoch)
		}
		if b.contextEpochs != nil || b.policyEpochs != nil {
			var current uint64
			var ok bool
			if b.contextEpochs != nil {
				value, lookupErr := b.contextEpochs.PolicyEpochContext(ctx)
				current, ok = value, lookupErr == nil
			} else {
				current, ok = b.policyEpochs.PolicyEpoch()
			}
			if !ok || current == 0 || claims.PolicyEpoch != current {
				return nil, fmt.Errorf("backend: assertion policy epoch %d stale (current %v) (P0.19)", claims.PolicyEpoch, current)
			}
		}
	}
	return claims, nil
}

// StripAssertion removes the assertion header from a request AFTER successful
// verification (P0.52): the short-lived bearer must not become a new internal
// credential that is forwarded to further services or logged downstream. The
// verified Claims are the trusted principal representation; the token itself
// has served its one purpose.
func (b *BackendVerifier) StripAssertion(r *http.Request) {
	r.Header.Del(assertionHeader)
}

// TransportIdentity is the P0.53 seam: the network/service identity of the
// caller, proven BELOW the assertion (mTLS client certificate, private-link
// peer, etc.). An assertion verifier is request authentication, not transport
// trust: production private backends require BOTH, and a verifier built with
// RequireTransportIdentity denies requests that arrive without the expected
// peer identity — regardless of a valid assertion.
type TransportIdentity interface {
	// Trusted reports whether the request arrived over an authenticated,
	// expected transport connection (e.g. mTLS with an allow-listed service
	// certificate). It receives the *http.Request to read TLS connection
	// state; it must never read application headers (client-assertable).
	Trusted(r *http.Request) bool
}

// RequireTransportIdentity gates verification on transport identity (P0.53):
// with this set, Verify rejects any request whose transport identity is not
// trusted BEFORE the assertion is even examined. Deployment path must prove
// the transport half; the deployment wires the implementation (TLS peer
// certificate inspection at the edge of the private network).
func (b *BackendVerifier) RequireTransportIdentity(ti TransportIdentity) *BackendVerifier {
	b.transport = ti
	return b
}
