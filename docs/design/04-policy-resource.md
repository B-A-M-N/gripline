# 04 — Policy & Resource Authorization

## 1. Versioned policy

Resource windows are process-local and volatile in the beta. They reset when
the process restarts; durable credential, lane, evidence, audit, and posture
state do not. Multi-node shared leases and window persistence are target
architecture and are not claimed by this implementation.

All policy is versioned (`id` + monotonically increasing `revision`). The
`policy.Manager` prepare/activate lifecycle validates candidates, persists an
active manifest before swapping the immutable snapshot, retains known-good
revisions for explicit audited rollback, and rejects replayed revisions. The
data plane still requires the deployment to authenticate policy artifacts
(signature/KMS verification is an integration seam) before loading them.

```go
type Policy struct {
    ID        string
    Revision  int
    Risk      RiskThresholds  // watch/constrained/quarantine
    Limits    Limits          // per-scope concurrency, request-rate, velocity multipliers
    Learning  Learning        // maximum_risk, allow_new_lanes, allow_suspicious_lanes
    Privacy   Privacy         // prompt/completion retention
    Identity  Identity        // internal identity max_ttl_seconds
    // scope-keyed overrides (date: plan, constrained: lane, ...)
}
```

## 2. Enforcement precedence

Denial is resolved highest-priority-first; a more permissive lower-level rule
MUST NOT override a higher-priority denial (§58):

```
1. revoked credential
2. explicit emergency block
3. source-level hard security block
4. account hard limits
5. credential hard limits
6. lane hard limits
7. risk-state restrictions
8. normal policy
```

## 3. Emergency modes

`NORMAL | DEGRADED_STATIC | EMERGENCY_LOCKDOWN`.

- `DEGRADED_STATIC`: credential auth active, static hard quotas active,
  baseline/adaptive promotion paused, cached established lanes may continue.
- `EMERGENCY_LOCKDOWN`: operator incident mode — deny new lanes, restrict
  expensive models, reduce concurrency, disable source classes, quarantine
  credentials, restrict admin APIs.

Failure semantics (§60): credential-registry outage → short authenticated local
cache (≤60s) for recently verified, unknown fail closed; risk-store outage →
`DEGRADED_STATIC`, never disable hard limits; resource-state outage → bounded
local emergency limits, never unlimited; analytics outage → proxy continues,
buffer events within strict bounds; **internal-signer outage → fail closed**.
INV-9: analytics failure never disables hard quotas.

## 4. Resource dimensions & scopes

Dimensions: `requests, concurrency, input tokens, output tokens, combined
tokens, cost`. Scopes: `SOURCE, LANE, CREDENTIAL, ACCOUNT, GLOBAL`. Hard limits
remain active even if adaptive risk evaluation is unavailable.

## 5. Token buckets

Buckets (source-auth, lane-request, credential-request, credential-token,
credential-cost, account-cost) carry `capacity, refill_rate, balance,
revision`. Updates are **atomic** where concurrent authorizations could
oversubscribe limits.

## 6. Concurrency leases

Concurrency is represented with atomic leases carrying TTLs:

```
admission → lease acquired → upstream active → {completion | client-cancel |
upstream-error | lease-timeout} → lease released
```

Lease TTL exceeds expected request duration or supports safe renewal tied to a
valid active request; orphaned leases expire so a crash never permanently
consumes concurrency (§48–49). **INV-15: concurrency accounting never becomes
negative** — the lease holder owns a slot and releases at most once
(idempotent release).

## 7. Reservation accounting

Where exact usage is unknown at admission:

```
estimate → reserve → execute → observe actual → reconcile
```

Accounting distinguishes `estimated / reserved / settled`, so settling can
never mint allowance (§104 property: resource settlement cannot mint
allowance) and provider tokenization stays behind adapters (§51).
