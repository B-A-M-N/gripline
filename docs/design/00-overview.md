# Gripline — Design Overview

**Status:** Engineering design, derived from the Gripline specification (v0.1.0).
**Implementation language:** Go (rationale in §Language below).
**Security posture:** deterministic, provider-agnostic credential containment.

---

## 1. What Gripline is

Gripline is a transparent API security boundary placed in front of an inference
provider (initial target FreeInference.org). It:

1. **Terminates** reusable external credentials at the first provider-controlled
   trust boundary — the raw secret never propagates into the provider stack.
2. **Reconstructs** request authority from an authenticated internal principal,
   current security state (lanes, evidence, risk), resource state, and versioned
   policy — never from "credential is present" alone.
3. **Isolates** suspicious manifestations of a credential into independently
   enforceable **security lanes**, so a compromised lane can be constrained
   without disabling legitimate lanes.
4. **Enforces hard resource limits** (concurrency and request bursts in the
   stock runtime; token/cost velocity when a provider usage adapter is wired)
   independent of adaptive scoring.
5. **Authenticates** toward the backend using short-lived, audience-bound,
   signed internal assertions — never the user's credential.

The single architectural rule:

> **External credentials MUST NOT become internal credentials.**

---

## 2. Why this is the correct lens

For most API providers, a reusable credential currently functions as *both*
proof of identity and proof of authority. Gripline separates those.

| Concept | Before Gripline | After Gripline |
|---|---|---|
| Credential | `API_KEY → valid? → authority` | `API_KEY → authentication claim → Principal` |
| Downstream exposure | Key propagates through router/adapters/workers | Key exists only inside the Credential Terminator |
| Suspicious use | binary: credential trusted or disabled | lane-scoped: constrain only the bad manifestation |
| Compute loss | bounded only by user quota | bounded by independent hard resource controls |

This turns a stolen credential from *portable unconditional authority* into *a
portable authentication claim whose usable authority is continuously bounded by
the provider* (§116 of the spec).

---

## 3. Scope boundaries

Build / own:

```
credential termination
+ principal reconstruction
+ lane security state
+ resource authorization
+ deterministic enforcement
+ internal identity
```

Explicitly out of scope (components or adjacent controls, not a substitute):

```
IP anomaly scoring · API rate limiting · WAF rules
behavioral fraud detection · header redaction
```

These refer to edge/provider controls, not Gripline's internal resource
governor or invalid-auth pre-auth guard. They may be used as inputs/adjacent
controls but are not Gripline by themselves; their absence remains a release
qualification concern for deployments that need those protections.

### Non-goals

Gripline does not replace WAFs, DDoS mitigation, SIEM, identity providers,
anti-bot signup, model moderation, or prompt-injection defenses. It does not
prevent a reusable bearer credential from being stolen. It addresses:

```
where credentials can propagate
+ how stolen credentials can be exploited
+ how quickly misuse consumes resources
+ how precisely suspicious contexts can be isolated
```

---

## 4. Deployment modes

| Mode | What's active | Default posture |
|---|---|---|
| `OBSERVE` | classify, evidence, lanes, shadow actions | no adaptive blocking; legacy auth path unchanged |
| `HYGIENE` | redact credentials from telemetry, strip spoofable headers, auth-failure controls | original auth may remain |
| `TERMINATE` | Gripline authoritative for external auth; discard raw credential | full containment invariants mandatory |
| `ENFORCE` | + resource enforcement, source controls, lane constraints, WATCH/CONSTRAINED | hard limits live |
| `QUARANTINE` | automated lane/credential quarantine after shadow validation | gated by validation |
| `HARDENED` | optional proof-of-possession (DPoP / mTLS-bound) | opt-in for clients |

The implementation supports `TERMINATE` + `ENFORCE` in two authority
topologies:

| Topology | Authority and guarantees |
|---|---|
| `standalone` / bbolt | One durable local credential/lane/evidence/policy/posture/audit authority; resource buckets and in-flight leases are process-local and reset on restart. |
| `clustered` / PostgreSQL | Active/active nodes share credentials, lanes, evidence, policy, posture/audit, adaptive state, resource buckets/leases, membership/fencing, and crypto-generation state. PostgreSQL outage makes nodes unready and admission fails closed. |

Clustered nodes require a shared PostgreSQL authority, unique `node_id` values,
an already-compatible schema, identical staged cryptographic generations, and
a private verifier backend. PostgreSQL HA, backup/PITR, TLS, and the network
perimeter remain deployment responsibilities. See `07-deployment.md` for
migration, fencing, rotation, and failure procedures.

---

## 5. Backend trust requirement

Transparent *client* compatibility and zero *backend* integration differ
(§6). Credential termination requires a downstream trust relationship that can
replace the user's credential:

- **Mode A** — backend trusts authenticated requests from Gripline.
- **Mode B** — backend accepts a Gripline service identity.
- **Mode C** — trusted infrastructure auth adapter validates Gripline assertions then forwards.

If the backend fundamentally needs the original credential, full termination is
impossible until that relationship changes. Gripline must not claim otherwise.

---

## 6. Language choice

The spec (§83) recommends Rust or Go, preferring Rust where stronger
memory safety and explicit secret-lifetime control justify the complexity.

**Chosen: Go.** Rationale:

- A mature, dependency-free streaming-HTTP proxy story in the stdlib
  (`net/http`, `httputil.ReverseProxy`, SSE pass-through).
- Productive model for the breadth here (deterministic state machines, policy,
  storage adapters, control-plane tooling).
- The two security-critical behavior requirements — "raw secret never
  serializes" and "raw secret is zeroed" — are both enforceable in Go:
  a sealed `[]byte` container whose API forbids `fmt`/`Display`/serialization,
  plus explicit `Zero()` on use. These are *behavioral* contracts, and the
  property tests (§code) lock them in.
- Fast-initialization, single-binary deploys align with §78 active/active
  data-plane nodes.

Where the spec genuinely requires defensive memory hygiene beyond Go's cost
(core routing in a narrow `secret` package), the boundary is kept tiny.

---

## 7. Dependency policy

The **security core** is dependency-free: it uses only the Go standard library
(`crypto/hmac`, `crypto/sha256`, `crypto/ed25519`, `encoding/*`, `sync`,
`time`). This keeps the raw-secret handling component's dependency tree
minimal (§82) and the `go.mod` reproducible.

Adapter packages (provider, storage, observability) may add dependencies
later and must not leak into the core.

---

## 8. Canonical request path

```
client ── HTTP ──► Trusted Ingress
                     │ strip reserved headers · normalize · assign request_id
                     ▼
                  Credential Terminator
                     │ extract secret · verify · resolve principal · discard secret
                     ▼
                  Principal (account_id, credential_id, policy, plan, state, revision)
                     │
                     ▼
                  Lane Classifier → lane_id, lane_state
                     │
                     ▼
                  Evidence Engine (synchronous) → evidence[]
                     │
                     ▼
                  Resource Controller → hard limits, leases, reservations
                     │
                     ▼
                  Policy + Risk evaluation → AuthorizedContext
                     │
                     ▼
                  Internal Identity Issuer → short-lived signed assertion (≤30s, aud-bound)
                     │
                     ▼
                  Streaming Proxy → backend
```

Downstream carries **only** internal identity. The user's reusable credential
is absent (§121 test: a captured post-boundary request must contain no external
credential).

---

## 9. Module boundary

Per spec §84. Implemented as Go packages under `internal/`:

```
internal/secret        sealed secret container (zeroize, non-formatting, non-serializing)
internal/credential    verifier derivation + CredentialRecord + credential state machine
internal/pseudonym     keyed HMAC pseudonymization (source_id, invalid-cred fingerprints)
internal/principal     Principal, AuthorizedContext, PrincipalResolver
internal/lane          lane model, features, classification, state machine, promotion
internal/evidence      Evidence record model, families, correlation, TTL
internal/risk          deterministic risk evaluation (bounded families, 0..100)
internal/policy        versioned policy model, integrity, enforcement precedence
internal/resource      token buckets, concurrency leases, reservations, velocity
internal/terminator    the admission orchestration (fast-path flow) + internal identity issuer
```

Provider-specific behavior (OpenAI/Anthropic/Generic/FI adapters) lives behind
adapter interfaces and MUST NOT leak into `lane`, `evidence`, `risk`,
`policy`, or `resource`.

---

## 10. Document index

- `01-containment.md` — the credential terminator, secret lifecycle, invariants.
- `02-lanes.md` — security lanes, features, classification, states, promotion.
- `03-evidence-risk.md` — evidence model, families, correlation, deterministic risk.
- `04-policy-resource.md` — policy, enforcement precedence, hard limits, leases.
- `05-internal-identity.md` — internal identity, assertions, signing.
- `06-observability.md` — telemetry, pseudonymization, retention, audit.
- `07-deployment.md` — modes, failure semantics, multi-node, FreeInference integration.
- `08-testing.md` — unit/property/fuzz/integration and the acceptance gates.

See `README.md` at the repo root for the implementation status checklist.
