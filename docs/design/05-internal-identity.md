# 05 — Internal Identity & Assertions

Gripline authenticates toward protected services with internal provider-controlled
identity: transport identity (mTLS / private path) plus a **short-lived signed
assertion** carrying the principal and authorization scope.

## 1. Claims

```json
{
  "iss": "gripline",
  "sub": "account_217",
  "cid": "cred_83ab",
  "ctx": "lane_29c",
  "aud": "fi-inference",
  "iat": 1788581000,
  "exp": 1788581030,
  "jti": "req_0193...",
  "policy_rev": 42,
  "cred_rev": 11,
  "scope": ["inference"]
}
```

## 2. Properties (binding)

- **Short-lived** — maximum recommended lifetime 30s (INV-10). Shorter allowed.
- **Audience-bound** — verifier rejects wrong `aud` (INV-11).
- **Not reusable credentials** — assertions never become user credentials.
- **Signed** with Ed25519 (or ES256). Signer isolated from the Internet-facing
  parser. Keys support rotation; verifiers accept only explicitly configured
  algorithms — no algorithm negotiation from untrusted requests.

## 3. Internal header namespace

Reserved headers: `Gripline-Principal`, `Gripline-Assertion`,
`Gripline-Context`, `Gripline-Request-ID` (or FI equivalents like
`X-FI-Internal-Auth`). Every externally supplied instance is **stripped at
ingress** and only Gripline may recreate them (INV-12).

## 4. Assertion verification

`internal/terminator` contains an `AssertionVerifier`: checks signature against
configured public key(s), `exp`/`iat` window, `aud`, `iss`, and enables stale
`cred_rev` rejection by sensitive services. Expired and wrong-audience
assertions never validate (spec §104 property list).

## 5. Sender-constrained mode (HARDENED, future)

Optional DPoP-style proof of possession (RFC 9449) / mTLS certificate-bound
credentials (RFC 8705) / platform-backed keys. The long-lived key becomes a
bootstrap credential; API requests carry a proof binding method, target URI,
issued-at, proof id, and public key. Replay state is bounded; already-accepted
proof ids inside the replay window are rejected. Compatibility mode remains
bearer-compatible and cannot provide full cryptographic replay prevention.