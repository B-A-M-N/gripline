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
reuse, persistent restart, and exact-credential canary absence. The harness is
not a production network-isolation or third-party SDK proof. `scripts/chaos-smoke.sh`
adds executable state/keyring/backend/spool/telemetry failure seams and runs
the release harness again. `scripts/cluster-harness.sh` runs three active/active
gateways against PostgreSQL and proves shared concurrency, revocation,
posture, policy, crypto rotation, source continuity, fencing, killed-node
recovery, backend cancellation, and PostgreSQL outage/recovery. CI and release
jobs require the PostgreSQL outage segment; local runs may skip it only when no
PostgreSQL service container is available.

## 4. Acceptance gates (§111)

- **Gate A** — full test telemetry contains zero raw credentials.
- **Gate B** — direct public access to the protected backend fails.
- **Gate C** — supported clients operate unchanged (generic HTTP is exercised
  here; OpenAI/Anthropic SDKs, Claude Code, and Codex require hosting-side
  connector evidence), including streaming, non-streaming, large context, tool
  calls, parallel, cancellation, retry, and long-lived requests.
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
Security tests cover log-injection, malformed/duplicate Authorization, header
smuggling, forged forwarding headers, forged Gripline headers, direct backend
bypass, bearer/proof replay, resource & concurrency races, baseline poisoning,
lane explosion, source rotation, rotation race, policy rollback, assertion
algorithm/audience/expiry bypass, and timing analysis.
