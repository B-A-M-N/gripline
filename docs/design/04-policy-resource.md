# 04 — Policy & Resource Authorization

## 1. Versioned policy

Resource behavior follows the selected authority topology. In standalone/bbolt
mode, buckets and in-flight leases are process-local and reset on restart. In
clustered/PostgreSQL mode, credentials, lanes, evidence, policy, posture,
adaptive rows, and resource buckets/leases are shared and durable. PostgreSQL
uses TTL leases, node-instance fencing, database time, canonical row-lock
ordering, bounded transaction retries, and conservative settlement semantics.
The stock `usage.mode=none` configuration still meters requests only; token and
cost dimensions become active only when a provider usage adapter is configured.

All policy is versioned (`id` + monotonically increasing `revision`). The
`policy.Manager` prepare/activate lifecycle validates candidates, persists an
active manifest before swapping the immutable snapshot, retains known-good
revisions for explicit audited rollback, and rejects replayed revisions.
The stock composition root authenticates configured policy artifacts with a
version-1 Ed25519 signature and rejects unsigned files. A KMS/HSM-backed
verifier may replace that local public-key seam without changing the data
plane contract.

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

Failure semantics (§60) are fail-closed for security authority failures:
credential/authority errors deny admission, policy or posture cannot be read as
an implicit allow, and signer failure denies new upstream authorization.
Analytics may continue through a bounded queue. In clustered mode a PostgreSQL
outage makes nodes unready and prevents new protected traffic from reaching the
backend; recovery requires a successful shared-authority and policy/crypto
reconciliation.
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

Concurrency is represented with atomic leases carrying TTLs. In PostgreSQL mode
the lease row includes the owning node instance epoch and all scope rows are
locked in canonical order:

```
admission → lease acquired → upstream active → {completion | client-cancel |
upstream-error | lease-timeout} → lease released
```

The PostgreSQL reaper expires orphaned leases; a process crash therefore cannot
permanently strand capacity. A forwarded-but-unsettled lease consumes its
reserved estimate rather than refunding uncertain work. In bbolt mode the
in-process lease holder releases at most once and process exit resets
in-flight state. **INV-15: concurrency accounting never becomes negative**.

## 7. Reservation accounting

Where exact usage is unknown at admission, the stock provider adapter reserves
the configured maximum body and output allowance before execution; adapters
with a stronger bounded request parser may provide a tighter estimate:

```
estimate → reserve → execute → observe actual → reconcile
```

Accounting distinguishes `estimated / reserved / settled`, so settling can
never mint allowance (§104 property: resource settlement cannot mint
allowance) and provider tokenization stays behind adapters (§51).
