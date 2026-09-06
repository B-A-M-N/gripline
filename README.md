# Gripline

Provider-agnostic **credential containment and authorization gateway** for API
infrastructure. Terminates reusable external credentials at the provider trust
boundary, reconstructs authority from scoped internal identity and current
security state, constrains suspicious contexts via security lanes, and enforces
hard resource limits — transparently to legacy clients.

External credentials stop at the line. Authority continues across it. That line
is Gripline.

---

## Design

Engineering design documents live in [`docs/design/`](docs/design/), derived
from the Gripline specification (v0.1.0):

- [`00-overview.md`](docs/design/00-overview.md) — what it is, scope, modes, language choice, module boundary.
- [`01-containment.md`](docs/design/01-containment.md) — credential terminator, secret lifecycle, invariants.
- [`02-lanes.md`](docs/design/02-lanes.md) — security lanes, features, classification, states.
- [`03-evidence-risk.md`](docs/design/03-evidence-risk.md) — evidence model, families, deterministic risk.
- [`04-policy-resource.md`](docs/design/04-policy-resource.md) — policy, precedence, hard limits, leases.
- [`05-internal-identity.md`](docs/design/05-internal-identity.md) — internal identity + assertions.
- [`06-observability.md`](docs/design/06-observability.md) — telemetry, pseudonymization, retention, audit.
- [`07-deployment.md`](docs/design/07-deployment.md) — modes, failure semantics, multi-node, FI integration.
- [`08-testing.md`](docs/design/08-testing.md) — test strategy + acceptance gates.

## Status

**Phase:** implementation of the deterministic security core (§99) with a
deployable single-node gateway (`cmd/gripline`). NOT production-stable: the
known-gaps section below is the binding list.

`✅` = implemented + tested · `◇` = partially / sketched · `⬜` = not yet

The smallest release worthy of the Gripline name:

1. ✅ credential terminator — `internal/terminator`, `internal/secret`
2. ✅ credential-safe handling — `SealedSecret` forbids formatting/serialization
3. ✅ internal principal — `internal/principal`
4. ✅ internal signed identity — Ed25519, ≤30s TTL, audience-bound (`internal/terminator`)
5. ✅ private backend enforcement (terminate-and-forward proxy + backend verifier,
   optional revision-freshness + transport-identity checks at sensitive backends)
6. ✅ hard per-credential concurrency (atomic leases, INV-15; multi-scope governor)
7. ◇ hard resource velocity — typed multi-scope governor + token buckets with
   reserve-estimate/settle-actuals (`internal/resource`); enforcement is REAL for
   deployments that supply a provider `UsageEstimator`, but the shipped default
   (`NoUsage`) accounts requests only — token/cost dimensions stay inert until a
   provider adapter feeds estimates/actuals
8. ✅ source key-spray detection — pseudonym fingerprints + invalid-credential
   spray signals (`internal/anomaly`, `internal/secret.SprayPseudonym`)
9. ✅ lane tracking — `internal/lane` (classification, trust/security axes,
   explosion protection, retention classes)
10. ✅ deterministic shadow evidence — `internal/evidence` + `internal/risk` (fuzzed 0..100)
11. ✅ audit trail — authenticated control plane with durable append-only operator
    audit (`internal/control`), atomic state+audit lane lifecycle (P0.49), and
    internal decision traces for denials (`internal/observability`, P0.50/P0.51)
12. ✅ adaptive-state failure semantics — DEGRADED never fails open (P0.1)
13. ✅ source-spray anomaly detector, bounded under one-shot-subject floods
    (`internal/anomaly`, P0.30–P0.32)
14. ◇ acceptance-gate COMPONENT tests (`internal/gates`, spec §111) — in-process
    component approximations of gates A–J, honestly named (`...Component`).
    These are NOT the gates: gate-level evidence (multi-node resource proofs,
    network isolation, cross-process replay, external telemetry canary) requires
    the external release harness, which does not exist yet. Passing this package
    must never be reported as "gates A–J green".
15. ✅ shadow-first auto-quarantine — `Risk.EnableAutomaticQuarantine=false` default;
    request-level denial still fires, persisted quarantine stays operator-set
16. ✅ deployable executable — `cmd/gripline` + `internal/config`: boot-validated
    TLS posture, fixed backend, bounded timeouts/headers/bodies, graceful drain,
    readiness/liveness, optional authenticated admin listener

### Implemented packages

```
internal/secret        SealedSecret: opaque state pointer, active redaction of every fmt verb
                       (Format/String/GoString), no serializers, zeroize-on-Zero shared across
                       struct copies (INV-2; canary-tested incl. log/panic/error paths)
internal/credential    HMAC-SHA256 pepper verifier (keys copied on ingestion, empty keys refused),
                       CredentialRecord, status machine + hysteresis, registry with rotation-safe
                       verifier indexes + defensive re-check (INV-1,13)
internal/pseudonym     keyed HMAC source/fingerprint IDs (fail-closed construction, key copies,
                       negative versions refused), rotation (key distinct from verifier pepper)
internal/principal     Principal / AuthorizedContext (no secret field)
internal/lane          lane states NEW/PROBATION/ESTABLISHED/SUSPICIOUS/BLOCKED, full-vector
                       similarity classifier with schema revision, deterministic tie-breaking,
                       bounded store (insert-only rows, evict-before-limit, provisional cap), promotion
internal/evidence      bounded risk families, correlation groups, TTL≤0 = unbounded,
                       trusted Mint() from versioned rule table (unknown codes rejected)
internal/risk          deterministic 0..100 evaluation (family caps, correlation bounded per
                       subject+scope); fuzzed
internal/policy        versioned + validated policy (threshold ladder checked), enforcement
                       precedence (§58), TTL bound (INV-10)
internal/resource      atomic token buckets with all-or-nothing Reservations, concurrency leases
                       with shared release state (copy-safe, INV-15; race-tested)
internal/terminator    admission flow (§53): extract → strip secret+internal headers → authenticate →
                       policy binding → lane → evidence → risk → policy resolver → hard limit →
                       internal identity; policy snapshot at New; explicit TERMINATE/ENFORCE modes;
                       128-bit random request ids; Ed25519 keyring with overlap rotation
internal/resource      multi-scope governor: SOURCE/LANE/CREDENTIAL/ACCOUNT/global all-or-nothing
                       provisioning; token buckets + atomic concurrency leases (INV-15)
internal/lane/control  operator unblock lifecycle + audit entries (P0.35/P0.42)
internal/control       operator control plane: posture switch + authenticated RBAC service + durable
                       append-only operator audit (P0.47); in-memory plane is the admission-side buffer
internal/anomaly       source-spray signal detector (ASN/credential/invalid-key spray), bounded state
                       + emit cooldown; signals resolve through Mint at the current policy revision
internal/proxy         terminate-and-forward data plane: strip reserved headers (INV-12), re-inject
                       signed assertion on the trusted hop, stream unchanged (INV-1/10/11)
internal/observability DecisionRecord per admission (§97) projected from the internal DecisionTrace
                       (P0.50): denied decisions carry principal, lane, and policy revision (P0.51)
internal/gates         component invariant tests for the §111 gate properties (honestly named
                       `...Component`) — NOT the acceptance gates; external release harness pending
```

Verified with `go vet ./...` clean and `go test -race ./...` (all packages)
green, plus fuzz runs on the risk-bounds invariant and credential extraction,
and the §112 latency budget (p95 ≈ 0.5ms &lt; 2ms target).

### Known gaps (audit honesty)

These are known-unfinished parts of the admission pipeline, stated here so
no invariant is claimed beyond what the implementation establishes:

- **Admission-state integration (P0.10):** the credential `StateMachine`,
  lane promotion, and persistent evidence accumulation are wired into the
  live admission path (`Admit`). Evidence persists across requests; credential
  risk and lane risk are computed independently; CONSTRAINED credentials
  receive restricted concurrency caps; lanes promote through
  NEW→PROBATION→ESTABLISHED. However, WATCH/CONSTRAINED limit selection
  uses the credential status (persisted), not the live state-machine
  observation — so an immediate downgrade from a single high-risk request
  requires the CAS path to succeed first. Velocity/source-spray signals are
  collected as evidence and drive risk/scope enforcement through the evidence
  pipeline; the gap is limit-selection timing only.
- **Policy immutability:** the terminator enforces a compiled deep-copy
  snapshot (`policy.Compile`, tested against post-construction mutation of
  every reference-bearing field), but a POLICY MANAGER — authenticated/signed
  artifact load, monotonic revision enforcement, last-known-good, explicit
  authorized rollback — is not built yet.
- **In-process state:** the credential registry, lane store, evidence store,
  resource governor, and control plane are in-process. Durable backends
  (PostgreSQL registry, shared resource leases, replicated lane/security
  state) substitute behind the seams but are not implemented — a single
  replica's BLOCKED lane is not yet blocked on every replica.
- **Single-process resources:** the concurrency pool and token buckets prove
  the atomic accounting invariants in-process. Cross-node leases, reservation
  TTLs, and orphan recovery need a shared backend (see `07-deployment.md`).
- **Streaming equivalence is gate-tested, not SDK-proven:** the proxy streams
  generic HTTP + SSE pass-through with per-chunk flush and is gate-tested for
  both byte fidelity AND incremental chunk arrival (a buffering proxy fails the
  timing gate). The real third-party SDK matrix (OpenAI/Anthropic Python-TS,
  Claude Code, Codex) is not run in this repo; connector-level equivalence is
  verified in the hosting integration.
- **Provider adapters are stubbed:** real ASN/region attribution, trusted-edge
  RealIP (`SourceResolver`), and usage estimation (`UsageEstimator`) are
  seams with deterministic defaults (`HeaderFeatures`, `NoSource`, `NoUsage`);
  a hosting provider must wire its adapters. Non-supplied features are treated
  as unknown (never falsely matched); without a UsageEstimator, token/cost
  resource dimensions stay inert (item 7).
- **Acceptance gates are components, not gates:** `internal/gates` proves
  in-process approximations of the §111 properties under honest names. The
  external release harness — telemetry canary sweeps, network-isolation
  proofs, cross-process decision replay, multi-node resource accounting —
  does not exist. Do not certify release from this repo's tests alone.

## Invariants

The security invariants INV-1..INV-16 (§11 of the spec) are binding
requirements when TERMINATE mode is active. Each is enumerated as an
implementation requirement in [`01-containment.md`](docs/design/01-containment.md)
and checked by property tests in the `internal/` packages.

## Layout

```
internal/secret        sealed secret container (the raw-secret boundary)
internal/credential    verifier + CredentialRecord + credential state machine
internal/pseudonym     keyed HMAC pseudonymization
internal/principal     Principal / AuthorizedContext
internal/lane          security lanes
internal/evidence      evidence model
internal/risk          deterministic risk evaluation
internal/policy        versioned policy
internal/resource      token buckets / concurrency leases / velocity
internal/terminator    admission flow + internal identity issuance
```

Language: **Go** (stdlib-only security core). See
[`00-overview.md` §6](docs/design/00-overview.md) for rationale.

## Security claim

Gripline does **not** prevent credentials from being stolen. Its defensible
claim:

> Gripline terminates reusable external credentials at the provider trust
> boundary, reduces the systems in which those credentials can be exposed,
> reconstructs authorization from scoped internal identity and current security
> state, detects substantial evidence of credential misuse, and constrains
> suspicious contexts and resource consumption while preserving legacy API
> clients.

For hardened clients it can additionally use sender-constrained authentication.