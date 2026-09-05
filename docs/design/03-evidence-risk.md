# 03 — Evidence & Deterministic Risk

Production authorization is **deterministic** (§G7, §38). No LLM, neural
classifier, or probabilistic generative model sits in the authorization path.
Offline analysis may help operators author policy, but recommendations only
affect authorization as explicit versioned policy.

## 1. Evidence model

```go
type Evidence struct {
    Code            string   // e.g. NEW_HOSTING_ASN
    Family          Family   // source/resource/novelty/abuse/operator
    Scope           Scope    // request/source/lane/credential/account/global
    SubjectID       string
    Score           int      // contribution to family sum
    Severity        int
    Confidence      int      // 0..100
    CorrelationGroup string  // same root observation → bounded reducer
    CreatedAt       time.Time
    ExpiresAt       time.Time // explicit lifetime (TTL)
    PolicyRevision  int
}
```

Every evidence event and enforcement action declares a **scope**. The engine
chooses the **narrowest defensible scope** (§32) — e.g. a new hosting lane +
abnormal concurrency normally produces `LANE`, not `ACCOUNT`, and a lane
constraint never silently widens to credential scope without policy (INV-16).

## 2. Risk families (bounded, no accidental double-counting)

```go
SOURCE_DISCONTINUITY  max 35
RESOURCE_VELOCITY     max 35
CLIENT_NOVELTY        max 20
ABUSE_CORRELATION     max 40
OPERATOR_IOC          max 100

risk = min(100, source + resource + novelty + abuse + operator)
```

**Correlation:** signals from the same root observation are not blindly
additive; within a correlation group use `max` (or another bounded reducer)
rather than naive sum (§35).

## 3. Example evidence defaults (initial, policy-tunable)

```
NEW_ASN +10 · NEW_HOSTING_ASN +15 · NEW_COUNTRY +15
SIMULTANEOUS_ESTABLISHED_LANE_FROM_UNRELATED_ASN +20
MORE_THAN_3_UNRELATED_ASNS_IN_10_MIN +30
CONCURRENCY_OVER_4X_BASELINE +20 · CONCURRENCY_OVER_10X_BASELINE +30
TOKEN_VELOCITY_OVER_4X_BASELINE +15 · TOKEN_VELOCITY_OVER_10X_BASELINE +25
COST_VELOCITY_OVER_4X_BASELINE_AND_ABSOLUTE_FLOOR +20
RAPID_ENDPOINT_OR_MODEL_ENUMERATION +10..20
SOURCE_ATTEMPTING_MANY_UNRELATED_CREDENTIALS +30..40
MANUAL_CONFIRMED_COMPROMISE 100
```

A low-confidence novelty signal must NOT independently quarantine a credential.

## 4. Evidence TTL

Every evidence has an explicit lifetime (new-ASN: hours; concurrency spike:
minutes; spray: minutes–hours; manual compromise: until revoked). Expired
evidence stops influencing risk unless transformed into another persistent
state — risk cannot permanently accumulate from unrelated historical anomalies
(§37).

## 5. State hysteresis (no flapping)

```
NORMAL → WATCH         risk ≥ 30 for ≥ 2 qualifying observations
WATCH → CONSTRAINED    risk ≥ 55
CONSTRAINED → QUARANTINED  risk ≥ 80
CONSTRAINED → WATCH    risk < 40 for 15 min
WATCH → NORMAL         risk < 20 for 30 min
```

All thresholds and dwell times are policy-controlled (in `internal/policy`).
Every risk-state transition is audited (INV-7).

## 6. Credential state machine

`NORMAL | WATCH | CONSTRAINED | QUARANTINED | REVOKED`, driven by the effective
scope's risk. `REVOKED` never authenticates (INV-13).

## 7. Baselines & change detection

Bounded online statistics: EWMA at 1m / 15m / 1h / 24h scales, decayed
counters, token buckets, CUSUM-style change detection for persistent rate/token/
spend/concurrency/auth-failure shifts. Network only; no neural baseline model.
Baseline updates are gated per §42 / INV-8 (see `02-lanes.md` §5).