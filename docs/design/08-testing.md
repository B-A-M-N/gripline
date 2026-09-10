# 08 — Testing & Acceptance

Product goal: deterministic authorization with bounded state. The test story is
therefore as much a correctness contract as a validation exercise.

## 1. Unit tests

Every credential format / parsing failure, evidence rule, risk-family reducer,
state transition (lane + credential), hysteresis, rate limiter, resource
reservation, concurrency operation, assertion verifier, policy-precedence rule,
and lane-lifecycle transition (spec §103).

## 2. Property tests

High-value properties that must hold under generated inputs (spec §104):

```text
raw credentials never serialize
risk always remains 0..100
revoked credentials never authenticate
expired assertions never validate
wrong-audience assertions never validate
untrusted internal headers never survive
concurrency never becomes negative
resource settlement cannot mint allowance
lane-scoped action cannot silently widen scope
policy revision cannot decrease without explicit rollback
```

Each maps to a test in `internal/*` (e.g. `secret` non-serialization,
`risk` bounds, `resource` lease idempotency, `terminator` assertion verify).
Coverage: table-driven adversarial cases + fuzz (`go test -fuzz`) on the
header/credential parsers.

## 3. Integration & chaos

Required flows (§106): valid/invalid/revoked credential, streaming &
non-streaming, large context, long inference, client & upstream disconnect,
retry, parallel, new lane, VPN/CI/VPS transitions, credential spraying,
resale simulation, resource drain, and each dependency outage (risk store,
credential DB, policy, gateway restart, signer failure) with **expected
behavior specified before the test** (§109).

The repository includes executable release checks. `scripts/release-harness.sh`
builds separate gateway, assertion-fixture, and public-verifier backend
processes, then proves direct raw-key denial, malformed/forged/wrong
audience/issuer/KID/revision assertions, query/body fidelity, chunked input,
gzip, SSE completion, provider statuses and `Retry-After`, oversized bodies,
upstream dial failure, idle-stream cutting, client cancellation, connection
reuse, persistent restart, and exact-credential canary absence. The compiled
release backend now runs behind a private-CA mTLS connection and requires the
exact inference client identity before assertion verification. The separate
repository-owned qualification lab supplies the production-shaped
network-isolation and official SDK proof.
`scripts/chaos-smoke.sh`
adds executable state/keyring/backend/spool/telemetry failure seams and runs
the release harness again. `scripts/cluster-harness.sh` runs three active/active
gateways against PostgreSQL and proves shared concurrency, revocation,
posture, policy, crypto rotation, source continuity, fencing, killed-node
recovery, backend cancellation, and PostgreSQL outage/recovery. CI and release
jobs require the PostgreSQL outage segment; local runs may skip it only when no
PostgreSQL service container is available.
The same harness has two deliberately separate load modes. `security-load`
keeps production-like hard limits and asserts caps, denials, and fairness;
`capacity-load` uses only disposable fixture ceilings and a persistent Go
client pool. The latter runs through `bash scripts/qualification/capacity.sh`
and reports status distribution, total/successful RPS, p50/p95/p99 latency,
PostgreSQL pool wait, transaction retries, and transaction latency. Its
reference gate permits at most 1.5 recovered serializable retries per request
and no deadlock retries; callers can tighten that bound for a deployment-
specific benchmark. Neither is an operator-specific capacity claim.

The qualification suite records `workers` for the security soak and
`capacity_workers` independently. The reference suite defaults the capacity
gate to 16 persistent clients with a 2-second PostgreSQL authority-operation
budget; `--capacity-workers` may be raised for an explicit stress profile
without silently changing the release gate's workload. The disposable
capacity fixture raises concurrency ceilings and disables request-rate gauges
so the reference measures active/active admission headroom rather than a
shared quota-bucket exhaustion test.

The security harness runs a configurable short sustained load phase
(`GRIPLINE_CLUSTER_HARNESS_LOAD_SECONDS` and
`GRIPLINE_CLUSTER_HARNESS_LOAD_WORKERS`, with the optional
`GRIPLINE_CLUSTER_HARNESS_LOAD_P95_LIMIT_MS`) through the load balancer and
records sample count, throughput, p50, and successful-request p95 latency.
This is a pool/serialization regression gate. The repository-owned
`scripts/qualification/soak.sh` composes the local HA database, runs the
three-node workload, continuously checks replica/security invariants, bounded
active leases/holds/source scopes and retention, and records each node's RSS,
goroutine, and heap samples; it can run the 24-72 hour reference soak.
The soak uses compressed historical retention only for its disposable fixture;
live coordination state keeps a longer window, and the explicit maintenance
tool exercises retention under traffic. Operator-specific capacity remains a
separate deployment layer.
The release harness also invokes `scripts/security-http-harness.sh`, which
writes raw HTTP/1.1 framing and header cases to a TCP socket and checks that
parser ambiguity never creates more than one backend request or leaks a
client-controlled carrier. `scripts/qualification/http2.sh` starts the real
TLS listener with local PKI and executes the HTTP/2 cases with `nghttp`, the
repository cancellation/recovery client, and `h2load`. Both protocol clients
run from the pinned Debian fixture (`nghttp2-client=1.52.0-1+deb12u2` from
Debian Snapshot `20240929T143658Z`) in a
host-networked container; no ambient host package is part of the certified
gate. It also checks bounded oversized-header rejection and authenticated
HTTP/2 error metrics.
`scripts/security-http2-harness.sh` remains the URL-driven operator
deployment check. `scripts/fuzz-smoke.sh` runs short parser fuzzing in
PR/security CI and a longer scheduled budget.

## 4. Acceptance gates (§111)

- **Gate A** — full test telemetry contains zero raw credentials.
- **Gate B** — direct public access to the protected backend fails.
- **Gate C** — supported clients operate unchanged. The repository-owned SDK
  lab exercises the official OpenAI/Anthropic Python and TypeScript clients
  against a provider-shaped local backend; operator accounts and model quotas
  remain deployment evidence. Cases include streaming, non-streaming,
  cancellation bounds, and usage settlement.
- **Gate D** — no material streaming-semantic regression.
- **Gate E** — every enforcement action reproducible from explicit state+policy.
- **Gate F** — adaptive failure neither creates unlimited access nor kills the service.
- **Gate G** — packet/request/trace/process verification: no external credential downstream.
- **Gate H** — automatic quarantine disabled until shadow validation.
- **Gate I** — lane-scoped compromise does not disable established legitimate lanes.
- **Gate J** — three-node PostgreSQL concurrency/resource accounting,
  cross-node state propagation, crypto rollout, fencing, and authority outage
  recovery pass through `scripts/cluster-harness.sh`.

## 5. Performance & security gates (§112, §108)

β pHs target: p95 added < 2ms, p99 < 5ms; 0 credential-bearing logs; 0 direct
backend public paths; 100% deterministic authorization; 0 unsupported streaming body
mutation. The durable benchmark reports p50/p95/p99 and throughput for the
state-backed proxy path; clustered qualification must separately measure
PostgreSQL arbitration, pool waits, lock contention, and three-node p95/p99.
Security tests currently cover log-injection, malformed/duplicate Authorization,
header-map sanitation, forged forwarding headers, forged Gripline headers,
direct backend bypass, short-lived bearer/proof semantics, resource &
concurrency races, baseline poisoning, lane explosion, source rotation,
rotation race, policy rollback, and assertion algorithm/audience/expiry
bypass. The reference qualification lab (`scripts/qualification/`) now owns
HTTP/2 connection-load, official SDK compatibility, mTLS/network isolation,
PostgreSQL HA/PITR, shared replay, and long-duration soak evidence. Cloud
network policy, managed database behavior, issued PKI, and provider account
capacity remain operator-specific deployment work.
