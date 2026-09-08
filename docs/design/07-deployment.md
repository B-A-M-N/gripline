# 07 — Deployment, Failure Semantics, Integration

## 1. Deployment modes and implementation phases

Gripline supports two authority topologies. Both expose the same
`TERMINATE` + `ENFORCE` data-plane contract; the authority choice determines
whether durable state is local to one process or shared by active/active nodes.

| Topology | Durable authority | Resource behavior | Suitable deployment |
|---|---|---|---|
| `standalone` / bbolt | One local transactional bbolt file | Process-local buckets and leases; restart resets in-flight resource state | One gateway process or deliberately isolated development |
| `clustered` / PostgreSQL | Shared credentials, lanes, evidence, policy, posture, audit, adaptive rows, crypto generations, membership, buckets, and leases | PostgreSQL-authoritative reservations with TTL, renewal, fencing, and conservative settlement | Multiple active/active gateways behind a load balancer |

PostgreSQL HA, backups/PITR, TLS certificates, operator-token delivery, and the
private network perimeter remain deployment responsibilities. A clustered node
must not be advertised as ready unless it owns its membership epoch, can read
the active policy and shared posture, has matching crypto generations, and can
reach the resource authority.

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

- **Strong in one authority:** credential revocation, hard concurrency
  admission, configured request/token/cost reservations, and emergency block
  state. Token/cost budgets require a configured usage adapter; the stock
  adapter reserves the configured maximum request body and output allowance
  before execution, then settles against structured response usage.
- **Eventual OK:** analytics, baseline updates, historical investigation,
  low-severity evidence propagation.
- Never treat eventually-consistent state as authoritative for a hard limit
  (§77).

## 3. Cluster topology, fencing, and rollout

The supported clustered shape is:

```text
                         ┌─ Gripline A ─┐──── inference identity ────> private inference listener
client ─ load balancer ──┼─ Gripline B ─┤
                         └─ Gripline C ─┘──── control identity ───────> private verifier-management listener
                                  │
                           PostgreSQL authority
```

Each process needs a unique configured `authority.node_id`. PostgreSQL assigns
an instance identity and fencing epoch at registration. Heartbeats are scoped
to that epoch; a replaced or paused process loses ownership and must stop
serving. Resource leases carry the same epoch, so a stale process cannot renew,
settle, or release capacity owned by its replacement. `/readyz` is the load
balancer contract: route only to nodes returning 200.

Before starting serving nodes on a new or upgraded database, run:

```bash
gripline migrate plan --config /etc/gripline/config.json
gripline migrate apply --config /etc/gripline/config.json
```

Serving nodes use `Migrate=false` and only check schema compatibility. Do not
give the Internet-facing runtime database role DDL privileges. v1 uses an
enforced stop-the-world upgrade contract: `migrate apply` refuses while a
recently-live `ready` or `draining` membership row exists. Stop or drain every
old node, apply the migration, then start the new binary. A future
expand/contract release may replace this with an explicit protocol/schema
compatibility range.

Crypto rotation is also a cluster operation: stage identical signer/pepper/
pseudonym material, make every live node acknowledge the exact fingerprint,
activate through the authenticated control plane, and wait for every node to
reconcile before relying on the new generation. Signer activation requires a
backend canary acceptance; retirement waits for the assertion TTL plus clock
skew and verifies that old pepper credentials/source scopes are gone.

Verifier-management traffic is a separate trust boundary from inference
traffic. Configure `backend.verifier_control.url` with a dedicated control
certificate identity (or a dedicated control token only for a loopback control
sidecar/test fixture). Do not multiplex the endpoint onto a listener that
accepts the inference client identity. The public data plane rejects the
configured control path even when an operator accidentally includes it in its
endpoint list.

## 4. Dependency failure semantics

| Dependency down | Behavior |
|---|---|
| Credential registry | Clustered and standalone admission fails closed on registry errors; no stale credential cache is used for security decisions |
| Risk store | `DEGRADED_STATIC`; never disable hard limits |
| Resource state | Clustered PostgreSQL outage makes readiness unhealthy and new protected traffic fails closed; standalone keeps its process-local authority |
| Policy service | Clustered nodes require the shared active manifest/artifact; policy read/reconcile failure makes the node unready |
| Analytics | proxy continues; bounded queue drops are counted |
| Internal signer | New upstream authorization fails closed when signing is unavailable |

Control-plane dependency degradation must not silently weaken the data plane
(§61): data-plane admission remains fail-closed and loads only
authenticated+versioned+validated policy. A configured admin listener is part
of the process lifecycle, so listener construction or serve failure is
reported and the supervisor drains both servers.

The private admin listener exposes authenticated low-cardinality metrics at
`GET /admin/metrics` (`audit.read`). In clustered mode, use the PostgreSQL
authority status and node metrics for pool waits, transaction/retry failures,
reservation/lease state, policy lag, crypto-generation acknowledgements, and
fencing. No request, credential, policy ID, signer KID, or source value is a
metric label.

## 5. Resource and lease semantics

In PostgreSQL mode, reservation and release use one canonical scope/key lock
order and database-authoritative time. A lease is:

```text
reserve → RESERVED → mark forwarded → FORWARDED → settle/release → SETTLED/RELEASED
```

An abandoned `RESERVED` lease refunds its estimate. A `FORWARDED` lease with no
trusted settlement consumes at least its estimate and releases only
concurrency; it never mints budget back after uncertain backend execution.
Deadlock/serialization retries are bounded by the request context. In bbolt
mode, the same API is backed by the local governor and in-flight leases are
lost on process restart.

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
