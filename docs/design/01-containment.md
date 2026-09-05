# 01 — Credential Containment

The non-negotiable half of Gripline. Everything else (lanes, risk, resources)
limits damage when a credential is misused; containment is what stops the raw
secret from living *inside the provider's architecture at all*.

> **External credentials MUST NOT become internal credentials.**

## 1. The boundary

```
PUBLIC INTERNET
      │
      ▼
CDN / EDGE
      │
      ▼  ┌────────────────────────────┐
Gripline │  Credential Terminator     │  ← only place a raw secret may exist
         │  (bounded memory, poisoned │
         │   after use, tiny API)     │
         └───────────┬────────────────┘
                     │  INTERNAL IDENTITY ONLY  ↓
                     ▼
         PRIVATE API NETWORK (router, services, provider, workers)
```

After termination, the external API key MUST NOT exist in:

```
router memory · provider adapters · model workers · service logs
distributed traces · analytics events · billing workers · background queues
error reports · internal HTTP headers
```

except within explicitly bounded memory owned by the Credential Terminator
*during* authentication.

## 2. Terminator processing order

```
request arrives
  → extract credential into a bounded secret container
  → derive credential verifier (HMAC-SHA256, keyed by pepper version)
  → lookup credential (never the raw value in storage)
  → validate state / revision
  → resolve credential_id + account_id
  → zero/drop raw secret representation   ← INSTRUCTIONAL
  → emit Principal (no secret)
```

## 3. SealedSecret — the raw-secret type

The secret SHALL be exposed only through a container that by its API:

- **prohibits accidental formatting** — no `String()`, `Format`, `%v` leakage;
- **prohibits debug output and serialization** — no `MarshalJSON`/`MarshalBinary`;
- **zeroes memory on destruction** — explicit `Zero()` before returning to a pool, plus `defer Zero()` on the active path;
- **exposes only the verifier operation** needed for authentication.

Enforced in `internal/secret` with a `SealedSecret` wrapper over an owned
`[]byte`, plus property tests that assert a zeroed secret reads back all-zero
and that formatting/serialization are excluded at the type level.

## 4. Credential extraction (ambigacity fails)

Adapted carriers: `Authorization: Bearer`, `x-api-key`, `api-key`,
provider-specific secret headers. Ambiguity MUST fail:

- two `Authorization` headers;
- Bearer + conflicting `x-api-key`;
- malformed Bearer syntax;
- oversized credential.

Default policy for equivalent duplicate carriers: **reject**.

Credential extraction must occur before ordinary middleware; secret-bearing
headers are removed/replaced in the internal request representation immediately
after extraction. We may expose `credential_id=cred_83ab…`, never
`credential=sk-…`.

## 5. Credential verifiers

For high-entropy generated API keys:

```
verifier = HMAC-SHA256(pepper_version, raw_credential)
```

The operational database stores the **verifier**, not the credential (INV-1,
T3 defense). Required HMAC key isolation: the verifier key lives in a separate
secret manager (HSM / KMS / sealed store / root-only runtime secret), and the
abuse-detection HMAC key (§45) is a *distinct* key.

Pepper rotation must support multiple active versions during migration.

**Low-entropy user-chosen secrets:** out of scope for the core API-key design.
If ever supported, HMAC lookup alone is not equivalent to password hashing;
they require Argon2id + salted verification with a separate lookup identifier.

## 6. Credential record & state machine

Stored fields: `credential_id, account_id, verifier, verifier_version,
pepper_version, status, policy_id, plan_id, created_at, expires_at, rotated_at,
last_seen_at, revision`.

`status` ∈ `NORMAL | WATCH | CONSTRAINED | QUARANTINED | REVOKED`. Transitions
are governed by risk scores with hysteresis (see `03-evidence-risk.md`). A
`REVOKED` credential never authenticates (INV-13).

## 7. Invariants (binding in TERMINATE mode)

Each maps to a test:

| # | Invariant | Enforcement |
|---|---|---|
| INV-1 | raw credentials never persisted | verifier-only storage; property test on store |
| INV-2 | never in logs/traces/metrics/events/panics | SealedSecret + no `String()`; no secret type reaches telemetry |
| INV-3 | never leave the termination boundary | `Principal` carries no secret; captured downstream request has none |
| INV-4 | untrusted forwarding metadata never influences security | provenance-gated source metadata |
| INV-5 | protected backends not publicly reachable around Gripline | deployment/network; Gate B |
| INV-6 | successful verification alone must not bypass policy | admission flow applies state/lane/resource policy after auth |
| INV-7 | every risk-state transition auditable | audit event on every transition |
| INV-8 | suspicious traffic must not retrain baselines | baseline-update gating (§42) |
| INV-9 | analytics failure must not disable hard quotas | resource enforcement independent of risk store |
| INV-10 | internal assertions short-lived (≤30s) | issuer enforces TTL; verifier rejects expiry |
| INV-11 | assertions audience-bound | verifier enforces `aud` |
| INV-12 | external internal-auth headers never survive ingress | strip reserved headers before processing |
| INV-13 | revoked credential never authenticates | auth consults status; property test |
| INV-14 | state/policy downgrade requires explicit authorized action | control-plane gating + audit |
| INV-15 | concurrent resource accounting never negative | atomic leases/tokens; property test |
| INV-16 | lane constraint must not silently widen to credential scope | enforcement-scope narrowing rule |

## 8. Credential rotation & revision

Planned overlap supported (`old: active, new: active` in a bounded migration
window, then `old: revoked`). Confirmed-theft rotation disables overlap unless
explicitly required. Every credential keeps a monotonic `revision`, echoed into
internal assertions as `cred_rev` so sensitive internal services can reject
assertions minted under stale credential state.

## 9. Final test

Capture a successfully authorized request immediately after the Gripline trust
boundary. If it contains the user's reusable external credential, containment
is not active. If it contains only internal principal + short-lived internal
authorization + bounded request authority, the central architecture works.
(Gate A / Gate G.)