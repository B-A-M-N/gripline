# 02 — Security Lanes

A **lane** is one observed manifestation of a credential. A credential MAY
legitimately have several lanes (Claude Code on a residential network, CI, a
VPS automation job). Lane-scoped enforcement is what makes adaptive credential
containment *operationally viable*: a provider must not be forced to choose
between "ignore suspicious activity" and "break every legitimate workload"
(§117).

## 1. Lane states

```
NEW → PROBATION → ESTABLISHED
        │             │
        └── SUSPICIOUS ── BLOCKED
```

| State | Meaning |
|---|---|
| `NEW` | recently observed; novelty alone is not malicious |
| `PROBATION` | enough continuity to distinguish, not enough to seed baselines |
| `ESTABLISHED` | clean history satisfies promotion criteria |
| `SUSPICIOUS` | evidence this lane may be compromise/abusive reuse |
| `BLOCKED` | requests from this lane denied |

## 2. Features

Lanes derive from **metadata**, not exact device fingerprints. Candidate
features: network ASN, network type, coarse geographic region, IP prefix class,
client family, SDK family, HTTP version, trusted TLS characteristics, endpoint
families, model families, request-size geometry, estimated input/output-token
geometry, request-interval distribution, concurrency pattern, streaming
behavior, request duration, cache metadata.

**Prompt text and completion text MUST NOT be required** (§G10).
**Missing features MUST NOT be interpreted as match or mismatch without policy**
(weights renormalize over available comparable features, §27).

## 3. Classification

Deterministic for `(feature vector, lane state, policy revision)`.

```
similarity = w_network·net_sim + w_client·client_sim + w_workload·workload_sim + w_temporal·temporal_sim

similarity ≥ 0.80           → candidate existing lane
0.55 ≤ similarity < 0.80    → related context / candidate new lane
similarity < 0.55           → novel lane
```

Thresholds are policy defaults, not constants.

## 4. Explosion protection

The beta enforces the policy-owned maximum active lanes per credential,
maximum provisional lanes, idle expiration, and hard `ErrTooManyLanes`
admission failure. It does not claim a creation-rate limiter or an overflow
security context: those are future controls, not hidden behavior. The resident
and Bolt repositories apply the same bounded reducer and retention rules.

## 5. Promotion & baselines

A lane becomes `ESTABLISHED` only after: minimum clean age, minimum clean
requests, minimum clean active periods, risk below establishment threshold, and
no active high-confidence abuse evidence. New lanes MUST NOT immediately alter
long-term global baselines. Baseline updates gate on
`credential_state == NORMAL && lane_state == ESTABLISHED && risk < threshold &&
no excluded evidence`, with bounded update magnitude and excluded suspicious/
blocked/incident windows (§42, INV-8).

## 6. Lane record

```
lane_id · credential_id · state · first_seen_at · last_seen_at
network_class · region_class · client_family · request_count
risk_score · establishment_score · revision
```
