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
5. ⬜ private backend enforcement (proxy + network)
6. ✅ hard per-credential concurrency (atomic leases, INV-15)
7. ◇ hard resource velocity — token buckets present; velocity adapters pending
8. ◇ source key-spray detection — pseudonym fingerprints present; source state pending
9. ✅ lane tracking — `internal/lane` (classification, states, explosion protection)
10. ✅ deterministic shadow evidence — `internal/evidence` + `internal/risk` (fuzzed 0..100)
11. ⬜ audit trail (control-plane mutations)

### Implemented packages

```
internal/secret        SealedSecret: zeroize on Zero, no String/Format/Marshaler (INV-1,2)
internal/credential    HMAC-SHA256 pepper verifier, CredentialRecord, status machine + hysteresis, registry (INV-1,13)
internal/pseudonym     keyed HMAC source/fingerprint IDs, rotation (key distinct from verifier pepper)
internal/principal     Principal / AuthorizedContext (no secret field)
internal/lane          lane states NEW/PROBATION/ESTABLISHED/SUSPICIOUS/BLOCKED, similarity classifier, bounded store, promotion
internal/evidence      bounded risk families, correlation groups, TTL
internal/risk          deterministic 0..100 evaluation (family caps, correlated max-reduction); fuzzed
internal/policy        versioned policy, enforcement precedence (§58), TTL bound (INV-10)
internal/resource      atomic token buckets + concurrency leases (INV-15; race-tested)
internal/terminator    admission flow (§53): extract → authenticate → lane → evidence → risk → hard limit → internal identity
```

61 `test`/`Fuzz` functions. Verified with `go test -race ./...` and fuzz runs on
the risk-bounds invariant and the credential-extraction parser.

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