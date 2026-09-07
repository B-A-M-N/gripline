# 07 — Deployment, Failure Semantics, Integration

## 1. Modes → implementation phases

See `00-overview.md §4` for mode semantics. Deployment phases (§102):

```
Phase 0 Inventory      (no enforcement — credential ingress/gravity map)
Phase 1 Shadow         lanes/velocity/source + hypothetical evidence (OBSERVE)
Phase 2 Hygiene        secret-safe telemetry, immutable-header stripping, auth-failure controls
Phase 3 Termination    external auth authority → Gripline; zero external creds downstream
Phase 4 Hard limits    revocation, account/credential limits, spray controls, hard concurrency
Phase 5 Lane control   WATCH / CONSTRAINED, lane scope preferred
Phase 6 Auto quarantine  only after validated shadow results
Phase 7 Hardened auth  sender-constrained (DPoP / mTLS / platform keys)
```

## 2. Consistency requirements

- **Strong:** credential revocation, hard concurrency admission, hard spend
  admission where promised, emergency block state.
- **Eventual OK:** analytics, baseline updates, historical investigation,
  low-severity evidence propagation.
- Never treat eventually-consistent state as authoritative for a hard limit
  (§77).

## 3. Multi-node & hot keys

Active/active data-plane nodes, stateless w.r.t. durable config, shared state
for hard limits. A single hot credential must not destabilize global state — no
one centralized mutex per request; leases/tokens are sharded/atomic per scope
(§78–79). Load testing must cover one-credential-high-concurrency and lane
explosion.

## 4. Dependency failure semantics

| Dependency down | Behavior |
|---|---|
| Credential registry | short authenticated local cache (≤60s) for recently verified; unknown fail closed |
| Risk store | `DEGRADED_STATIC`; never disable hard limits |
| Resource state | bounded local emergency limits; never unlimited |
| Policy service | last validated policy |
| Analytics | proxy continues; buffer events within strict bounds |
| Internal signer | **fail closed** for new upstream authorization (alternate hot signer → HA) |

Control-plane dependency degradation must not silently weaken the data plane
(§61): data-plane admission remains fail-closed and loads only
authenticated+versioned+validated policy. A configured admin listener is part
of the process lifecycle, so listener construction or serve failure is
reported and the supervisor drains both servers.

## 5. FreeInference integration

Limited to: make Gripline authoritative for external auth; accept Gripline
internal identity; prevent direct backend access; remove original-key
dependencies downstream (§90). MUST NOT require changes to model serving,
inference scheduling, model selection, ordinary streaming, prompt contents, or
client SDK behavior.

```
Internet → Cloudflare → Gripline → mTLS/private → FI internal API
                                                    (principal, credential_id, scope, NO user API key)
                                                        → router / provider / models
```

Integration levels: L1 separable auth middleware
(`authenticate()`→`validate_gripline_identity()`); L2 small internal-auth
adapter; L3 one-time refactor where FI distributes original-key validation. In
every case the fundamental change is `backend trusts user key` →
`backend trusts Gripline`.

## 6. Cloudflare

Origin access must prevent bypass around Cloudflare and forged
`CF-Connecting-IP`; only authenticated trusted ingress contributes trusted
source identity (T10, INV-4). Cloudflare is an ingress integration, **not** a
security dependency of the architecture — Gripline works without it.

## 7. Trusted ingress

Terminates TLS or trusts authenticated edge; enforces max header/body sizes;
rejects malformed HTTP; prevents request smuggling; normalizes duplicate
headers; establishes **provenanced** source metadata

```
TRUSTED_EDGE | DERIVED | UNTRUSTED
```

— only TRUSTED_EDGE/DERIVED influence identity-sensitive policy — assigns a
unique request id, and strips reserved internal headers (INV-12).
