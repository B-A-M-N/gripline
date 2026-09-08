# 07 — Deployment, Failure Semantics, Integration

## 1. Modes → implementation phases (target architecture)

The phases below describe the desired deployment progression, not a claim that
every phase is delivered by this repository. The stock binary is a single-node
`TERMINATE` + `ENFORCE` runtime with durable bbolt containment state and
process-local resource windows.

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

## 2. Consistency requirements (supported v1 versus target)

- **Strong in one authority:** credential revocation, hard concurrency
  admission, configured request/token/cost reservations, and emergency block
  state. Token/cost budgets require a configured usage adapter; the stock
  adapter reserves the configured maximum request body and output allowance
  before execution, then settles against structured response usage.
- **Eventual OK:** analytics, baseline updates, historical investigation,
  low-severity evidence propagation.
- Never treat eventually-consistent state as authoritative for a hard limit
  (§77).

## 3. Multi-node & hot keys (future deployment boundary)

Active/active data-plane nodes, stateless w.r.t. durable config, shared state
for hard limits. A single hot credential must not destabilize global state — no
one centralized mutex per request; leases/tokens are sharded/atomic per scope
(§78–79). Load testing must cover one-credential-high-concurrency and lane
explosion. The current Governor removes the process-wide admission lock and
proves per-object atomicity, but it is not a cross-node lease service.

## 4. Dependency failure semantics

The table below is the target multi-service contract. Entries marked **target**
are not silently claimed by the stock single-node binary; the executable
behavior is the final sentence in each row.

| Dependency down | Behavior |
|---|---|
| Credential registry | **target:** short authenticated local cache (≤60s); v1 fails closed on registry errors |
| Risk store | `DEGRADED_STATIC`; never disable hard limits |
| Resource state | **target:** bounded distributed fallback; v1 governor is process-local and never unlimited |
| Policy service | **target:** last validated policy; v1 uses the durable local manifest and signed artifact |
| Analytics | proxy continues; bounded queue drops are counted |
| Internal signer | **target:** alternate hot signer; v1 fails closed for new upstream authorization |

Control-plane dependency degradation must not silently weaken the data plane
(§61): data-plane admission remains fail-closed and loads only
authenticated+versioned+validated policy. A configured admin listener is part
of the process lifecycle, so listener construction or serve failure is
reported and the supervisor drains both servers.

The private admin listener exposes authenticated low-cardinality metrics at
`GET /admin/metrics` (`audit.read`). It reports admission/denial classes,
degraded decisions, resource/policy denials, bounded spool utilization,
backend failures/status classes, active streams, bbolt transaction counts and
latency, source-table saturation/overflow, detector drops, telemetry sink
failures, global evidence-sweep counters, and active policy revision/signer
identity. No request, credential, policy ID, signer KID, or source value is a
metric label.

## 5. Single-node boundary

This release has one authoritative bbolt file per runtime. Credential, lane,
evidence, policy lifecycle, posture, audit, detector state, recovery manifests,
and signer publication are restart-safe within that node. Resource buckets and in-flight
leases are process-local and reset on restart; do not deploy multiple active
nodes and call the resource limits globally enforced until a shared lease,
reservation-TTL, replication, and leader/ownership protocol has been added.

## 6. FreeInference integration

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
`backend trusts Gripline`. A deployment gate must also deny direct raw-key
requests at the backend; proxy configuration alone is not that gate.

## 7. Cloudflare

Origin access must prevent bypass around Cloudflare and forged
`CF-Connecting-IP`; only authenticated trusted ingress contributes trusted
source identity (T10, INV-4). Cloudflare is an ingress integration, **not** a
security dependency of the architecture — Gripline works without it.

## 8. Trusted ingress

Terminates TLS or trusts authenticated edge; enforces max header/body sizes;
rejects malformed HTTP; prevents request smuggling; normalizes duplicate
headers; establishes **provenanced** source metadata

```
TRUSTED_EDGE | DERIVED | UNTRUSTED
```

— only TRUSTED_EDGE/DERIVED influence identity-sensitive policy — assigns a
unique request id, and strips reserved internal headers (INV-12).
