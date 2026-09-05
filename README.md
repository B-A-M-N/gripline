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

**Phase:** early implementation — the deterministic security core of the MVP
(§99) is implemented and tested. Provider adapters, the streaming proxy layer,
and the control plane remain.

`✅` = implemented + tested · `◇` = partially / sketched · `⬜` = not yet

The smallest release worthy of the Gripline name:

1. ✅ credential terminator — `internal/terminator`, `internal/secret`
2. ✅ credential-safe handling — `SealedSecret` forbids formatting/serialization
3. ✅ internal principal — `internal/principal`
4. ✅ internal signed identity — Ed25519, ≤30s TTL, audience-bound (`internal/terminator`)
5. ✅ private backend enforcement (terminate-and-forward proxy + backend verifier)
6. ✅ hard per-credential concurrency (atomic leases, INV-15; multi-scope governor)
7. ✅ hard resource velocity — multi-scope governor + token buckets (`internal/resource`)
8. ✅ source key-spray detection — pseudonym fingerprints + source-spray minter
9. ✅ lane tracking — `internal/lane` (classification, states, explosion protection)
10. ✅ deterministic shadow evidence — `internal/evidence` + `internal/risk` (fuzzed 0..100)
11. ✅ audit trail — operator control plane (`internal/control`) + decision records
    (`internal/observability`)
12. ✅ adaptive-state failure semantics — DEGRADED never fails open (P0.1)
13. ✅ source-spray anomaly detector (`internal/anomaly`)
14. ✅ acceptance gates A–J (`internal/gates`, spec §111) — all green
15. ✅ shadow-first auto-quarantine — `Risk.EnableAutomaticQuarantine=false` default
    (Gate H); request-level denial still fires, persisted quarantine stays operator-set

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
internal/control       operator control plane: emergency lockdown posture + bounded audit trail
internal/anomaly       source-spray minter (credential ASN-spray + source credential-spray) via Mint
internal/proxy         terminate-and-forward data plane: strip reserved headers (INV-12), re-inject
                       signed assertion on the trusted hop, stream unchanged (INV-1/10/11)
internal/observability DecisionRecord per admission (§97): safe, machine-readable explanation
internal/gates         executable acceptance gates A–J (spec §111) — each fails the build on
                       release-contract regression
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
  requires the CAS path to succeed first. Velocity/source-spray signals
  are collected as evidence but not yet used as dynamic gates.
- **Policy immutability:** the terminator enforces a deep-value SNAPSHOT of
  the policy taken at construction (post-`New` mutation of the caller's
  `*policy.Policy` cannot alter enforcement, tested), but a compiled/
  immutable policy type with authenticated load, monotonic revision
  enforcement, and explicit rollback authorization is not built yet.
- **Single-process resources:** the concurrency pool and token buckets prove
  the atomic accounting invariants in-process. Cross-node leases, reservation
  TTLs, and orphan recovery need a shared backend (see `07-deployment.md`).
- **Streaming equivalence is gate-tested, not SDK-proven:** the proxy streams
  generic HTTP + SSE pass-through unchanged (Gate C/D), but the real third-party
  SDK matrix (OpenAI/Anthropic Python-TS, Claude Code, Codex) is not run in
  this repo. Gate C enforces the generic-HTTP contract; connector-level
  equivalence is verified in the hosting integration, not here.
- **Provider adapters are stubbed:** real ASN/region attribution and
  trusted-edge RealIP are `FeatureResolver` seams with deterministic defaults
  (`HeaderFeatures`); a hosting provider must wire its adapter. Non-supplied
  features are treated as unknown (never falsely matched).

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