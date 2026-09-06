# Gripline — Hostile-Review P0 Verdict Audit (Full)

Durable source of truth for the numbered P0 findings from the external hostile
production review. Every row is a verdict grounded in committed code, confirmed
by re-reading the actual implementation (not inferred from summaries). This is
the on-repo ground truth for "All P0s now": a finding is only RESOLVED when the
verdict links to the committed symbol that satisfies it, and only CLOSED once
that code is committed on `main`.

Legend:
- RESOLVED — the invariant is implemented and enforced in committed code.
- PARTIAL — the safety property holds but a named surface is known-incomplete;
  the missing piece is called out.
- OPEN — a confirmed defect not yet closed.
- NOT GROUNDED — no code/test/comment in the tree references this finding
  number; i.e. the finding text has no committed representation to verify.

Last verified against `main` @ 55df52a. Full suite green: `go test -race ./...`
across all 15 packages.

---

## Adaptive state + durable state semantics (P0.1–P0.6)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.1 | RESOLVED (telemetry caveat) | Snapshot failure → `AdaptiveDegraded`; state-machine commit is gated behind `AdaptiveAvailable`, so the outage is never observed as clean history that downgrades CONSTRAINED/WATCH→NORMAL. `observability/decision.go` sets `Degraded` so `RiskAfter` is not mistaken for a fresh score. Caveat: a failed credential snapshot reports `CredentialRisk=0` (guarded by the `Degraded` flag). |
| P0.2 | RESOLVED | `terminator.New()` rejects `ModeEnforce` with no evidence store; `ModeTerminate` (and empty) may omit adaptive state. |
| P0.3 | RESOLVED | Synchronous current-request evidence combined with historical snapshot via `dedupAppend` keyed on `EvidenceID`; store also dedups on `Append`. |
| P0.4 | RESOLVED | `synchronousEvidence` → `evidence.Mint`; every security field from the versioned rule table (rejects unknown codes), table now from compiled policy (P0.11). |
| P0.5/P0.6 | RESOLVED | `ObserveAndCommit` load→reduce→CAS→commit atomically under lock, revision bumped exactly once, rejects QUARANTINED/REVOKED transitions, `TransitionConflict` on CAS miss — never fuses local + stale persisted state. |

## Lane enforcement + policy versioning (P0.7–P0.11)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.7 | RESOLVED | `ObserveRisk` atomically updates the lane security dimension; BLOCKED → deny (`lane_restricted`/`ErrorLaneBlocked`), SUSPICIOUS → constrained limits. |
| P0.8 | RESOLVED | `LaneRecord.Features` persists the complete normalized classification vector + `FeatSchema`; test proves full vectors distinguish lanes. |
| P0.9 | RESOLVED | `ComparableWeight` + `MinComparableWeight=0.70`; MATCH requires renormalized similarity AND comparable mass ≥ floor; zero floor fails closed. **Closed by commit a457117.** |
| P0.10 | PARTIAL | DEGRADED is not permanently latched (each request re-snapshots); a single-request `TransitionConflict` re-reads but does not re-apply the observation (comment says "bounded retry once" but only implements the re-read half). README documents it. |
| P0.11 | RESOLVED | `policy.Policy.{EvidenceRules, Classification}` carried on the compiled revision; terminator mints NEW_LANE and classifies lanes from `t.pol.*`, not package globals; `IsValid` fails closed on empty/degenerate. **Closed by commit 0509894.** |

## Evidence integrity + secret hygiene (P0.12–P0.22)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.12 | RESOLVED | `Evidence.NonEvictable` marks FamilyOperatorIOC + zero-ExpiresAt critical; `compactLocked` skips them and fails safe (keeps all) if nothing evictable. `TestM1CriticalEvidenceNotEvictedByFlood`. |
| P0.13 | RESOLVED | `Append` validates the whole batch under one lock before storing anything (atomic gate → `ErrInvalidEvidence`); per-subject bound `maxEvidencePerSubject=2048`; empty-subject pruned. `TestAppendAtomicBatchRejectsPartial`. |
| P0.14 | RESOLVED | `Evidence.Valid` rejects `!now.Before(ExpiresAt)` — inclusive-invalid at the boundary; `purgeExpiredLocked` + `Snapshot`/`Prune` reuse it. `TestExpiryIsInclusiveInvalidAtBoundary`. |
| P0.15 | PARTIAL | Terminator sync evidence uses a CSPRNG id (`t.rand`, 128-bit). BUT `evidence.Mint` stamps a predictable `ev_<UnixNano>` id and `anomaly.Detector.Observe` does not override it; `Append` accepts any non-empty id with no entropy check, and dedup is per-subject so the same id under two subjects double-counts in `risk.Evaluate`. |
| P0.16 | RESOLVED | `PepperRing.Get` returns a copy; key bytes never leave the ring; ring copies on ingestion. |
| P0.17 | RESOLVED | `CredentialRecord.Validate` rejects empty id/verifier, unknown verifier version, invalid revision, future CreatedAt; `Insert` clones verifier bytes. |
| P0.18 | RESOLVED | Unknown verifier algorithm fails closed (`Validate` rejects VerifierVersion ∉ {0,1}). |
| P0.19 | RESOLVED | `Evidence` carries only codes/ids/scores; all producers pass subject IDs, never the sealed secret; `Outcome.Evidence` is codes only. |
| P0.20 | RESOLVED | Lookup returns typed `ErrNotFound` vs `ErrUnavailable`/`ErrTimeout`/`ErrCorrupt`; admission degrades fail-safe on them. |
| P0.21 | RESOLVED | `CredentialRecord.Authenticatable` uses `!now.Before(ExpiresAt)` — inclusive-invalid, matching evidence/assertion semantics. |
| P0.22 | RESOLVED | `Registry.TouchLastSeen` documented no-op-capable; `markLastSeen` fire-and-forget; `SecurityState.LastStateChangeAt` is a dedicated field. |

## Resource auth + settlement (P0.23–P0.27)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.23 | RESOLVED | `Governor.Provision` holds the lock across both rounds, rolls back every partial hold on failure (deferred release loop). `TestGovernorAllOrNothingAcrossScopes`. |
| P0.24 | RESOLVED | Denying scope named via `ScopeLimitError{Scope}` at both failure points; rollback releases upstream holds. |
| P0.25 | RESOLVED | `resourceScopeReason`/`resourceScopeErr` map SOURCE→source_restricted, LANE→lane_restricted, CREDENTIAL→credential_restricted, ACCOUNT→rate_limit. `TestM3MultiscopeDeniesWhenScopeSaturated`. |
| P0.26 | RESOLVED | `ConcurrencyPool` mutex-guarded balance; `AcquireN` decrements only when `balance >= n`; never negative (INV-15). `TestConcurrencyNeverNegative`. |
| P0.27 | RESOLVED | `Reserve` all-or-nothing; `Settle`/`Cancel` idempotent + mutually exclusive via shared `reservationState`; `Cancel` refunds exactly its own amount clamped ≥0; `MultiReservation.Release` cancels unsettled. `TestGovernorTokenSettleConsumesCancelRefunds`. |

## Identity trust boundary + source (P0.28–P0.38)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.28 | RESOLVED | Assertion TTL hard-capped ≤30s: policy `IsValid`, `MaxIdentityTTLSeconds` clamp, `Signer.Issue` refusal, `ParseAndVerify` defensive reject. `TestM1AssertionTTLCappedAt30s`. |
| P0.29 | NOT GROUNDED | No code/tag references P0.29; audience-binding behavior present via `BackendVerifier.Verify` (INV-11) but not labeled P0.29. |
| P0.30 | RESOLVED | Quarantined denial → `CredentialQuarantinedError` + `credential_restricted` (not Revoked); `safeReason` maps error classes to safe strings; proxy `writeDenial` maps reasons→status. |
| P0.31 | RESOLVED | `Signer`/`Assertion` Format/String/GoString all emit `<redacted>`. `TestM1KeyStructFormatRedacts`. |
| P0.32–P0.34 | NOT GROUNDED | No P0.32/33/34 references in the tree. |
| P0.35 | RESOLVED | `ControlPlane.RecordAdmission` + `SetEmergency` write a bounded audit trail; lane operator actions write `AuditEntry`. `TestControlPlaneAuditTrailRecordsDecisions`. |
| P0.36 | NOT GROUNDED | No P0.36 reference in code. |
| P0.37 | RESOLVED | Pseudonym version prefix `v<N>.<b64>` routes stores by key version; `Verify` accepts every active version. pseudonym_test. |
| P0.38 | RESOLVED | `Key.Format/String/GoString` redact. pseudonym_test. |

## Policy + lane lifecycle (P0.39–P0.48)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.39 | RESOLVED | `ControlPlane.SetEmergency`; lane `Unblock` requires BLOCKED precondition, fails closed otherwise. control_test + lane/control_test. |
| P0.40 | RESOLVED | Lockdown denies NEW lanes (`emergency_lockdown`) while authoritative risk observation still runs. `TestControlPlaneEmergencyLockdownDeniesNewLanes`. |
| P0.41 | RESOLVED | Lockdown gate keys on `laneNew` only; established lanes continue. Same test. |
| P0.42 | RESOLVED | `CleanSince` seeded at creation, zeroed on security elevation, re-seeded on operator unblock, used (not FirstSeenAt) in `PromoteIfEligible`. `TestCleanSinceResetOnElevation`. |
| P0.43 | RESOLVED | `PromoteIfEligible` returns early when `Security.Status != Normal`; `AllowSuspicious` deprecated/no-effect; SUSPICIOUS forced to constrained limits. lane/security_test. |
| P0.44 | RESOLVED | `ObserveAndCommit` bumps `Revision++` exactly once on status change, not on NoChange; `UpdateStatusCAS` likewise. m1_test. |
| P0.45 | PARTIAL | Evidence is minted with a `PolicyRevision` and assertions embed `PolicyRev`, but enforcement never compares evidence's revision against the compiled policy, and the lane id ignores the revision — stale-revision evidence is silently evaluated under the new policy. Mixing `t.pol.Revision` into `shortTag` (or filtering evidence by revision) would close it. |
| P0.46/P0.47 | NOT GROUNDED | No code references P0.46/P0.47. |
| P0.48 | PARTIAL | Clean counters advance only on authorized requests (INV-8, `RecordCleanAuthorizedAndPromote` only in the authorized path; promotion gated behind `AdaptiveAvailable`). Caveat: in DEGRADED posture the counters still advance (promotion itself is the gated action) — a conditional INV-8 reading. |

## Architecture / control plane / gateway (P0.49–P0.57)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.49–P0.57 | NOT GROUNDED | No code, test, or comment references P0.49 through P0.57; highest numbered P0 in the tree is P0.69. These findings' text cannot be verified against committed code until their requirement text is reconciled with the repo. |

## Backend + production state + proof (P0.58–P0.69)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.58 | ABSENT | Durable credential store backend: only `MemoryRegistry` exists; no Postgres/SQLite/FS backend. |
| P0.59 | RESOLVED | Signer key rotation / overlap: `terminator.Keyring` `Rotate()` + retained old-generation public keys; `TestDataPlaneBackendFollowsSignerRotation`. |
| P0.60 | PARTIAL | Assertion key overlap exists via Keyring, but no HSM/remote signer or automated key-management lifecycle. |
| P0.61 | ABSENT | Multi-node / leader election: resource governor is a single-process `sync.Mutex`; no etcd/Consul/Raft. |
| P0.62 | ABSENT | Shared leases with TTL across nodes: leases are in-process; no distributed store/TTL. |
| P0.63 | ABSENT | Lane-store restart recovery: `map[string]map[string]*LaneRecord` in-memory only; no persistence layer. |
| P0.64 | ABSENT | Evidence-store restart recovery: `memoryStore` only; no WAL/disk/remote. |
| P0.65 | PARTIAL | Credential `SecurityState` designed durable, but only `MemoryRegistry`; `StateMachine` hysteresis (`watchStreak`, `belowSince`, `lastScoreTime`) is explicitly process-local. |
| P0.66 | ABSENT | No WAL / journal / durable append path. |
| P0.67 | RESOLVED | Source-spray anomaly detector: `anomaly.Detector` wired via `Dependencies.Spray`; `internal/anomaly/spray.go` + `m6_test.go`. |
| P0.68 | ABSENT | Dependency chaos / failure-injection harness: docs mention it (`docs/design/08-testing.md`) but no implementation; Gate F hand-codes one `failingStore`, not a harness. |
| P0.69 | RESOLVED | Acceptance gates A–J: all 10 present and asserted in `internal/gates/gates_test.go`; §112 perf gate in `internal/terminator/bench_test.go`. |

---

## Executable acceptance / proof surface (Gate A–J, §112, e2e)

| Gate | Proof | Status |
|------|-------|--------|
| A | No raw credential in telemetry/formatting | committed |
| B | Direct backend access (none/forged assertion) fails 401 | committed |
| C | Generic client / non-credential request operates unchanged | committed |
| D | Streaming response unmodified | committed |
| E | Enforcement reproducible (reducer → WATCH) | committed |
| F | Adaptive failure: quarantined stays denied during evidence outage (no fail-open) | committed |
| G | No external credential downstream + forged reserved header stripped (INV-12) | committed |
| H | Automatic quarantine disabled until shadow validation (fail-closed) | committed |
| I | Lane-scoped compromise blocks one lane, established continues | committed |
| J | Concurrent accounting: peak simultaneous holders ≤ cap | committed (flake fixed) |
| §112 | Admission latency p95 < 5ms / p99 < 20ms (liberal, de-flaked) | committed |
| e2e | Lane-restricted decision through real proxy → private backend, no secret crossing | committed (55df52a) |

## Production classification

**Hardened security-core prototype / pre-beta data-plane library.** The core
deterministic authorization engine, the proxy trust boundary, all 10 acceptance
gates, the source-spray detector, signer rotation, the control plane, and the
observability decision record are committed and race-tested. It is NOT
production-stable because all state is in-memory and lost on restart; there is
no standalone gateway process; no multi-node lease coordination; no durable
backend / WAL / metrics pipeline; no chaos harness; no KMS/HSM-backed keys or
TLS.

## Production gaps (not P0 defects; architecture recommendations)

1. **Gateway process** — no `cmd/`, no `main.go`, no socket listener; the
   library is in-memory-test-only. Required before production traffic.
2. **Durable stores** — lane/evidence/credential/lease state is in-memory and
   lost on restart (P0.58/P0.63–66); no WAL/durable append.
3. **Multi-node coordination + TTL leases** — `resource.Governor` is a
   single-process mutex; no leader election or shared lease store (P0.61/62).
4. **Dependency chaos / failure-injection harness** — only Gate F hand-codes one
   evidence outage; no systematic harness (P0.68).
5. **Metrics / telemetry pipeline** — decision records + control-plane audit only;
   no Prometheus/OTel sink.
6. **KMS/HSM key management + TLS** — pepper keys are `[]byte` in config;
   assertion signer is in-memory Ed25519; no HSM/KMS/mTLS.
7. **Source-identity attribution (M4 seam)** — `proxy.HeaderFeatures` cannot
   resolve trusted ASN/region. The e2e gate injects a resolver; a real provider
   adapter is the flagged M4 default.

## Open / partial work queue (ordered by what blocks the e2e goal)

1. P0.15 — give `evidence.Mint` a CSPRNG id (or an injectable idgen); reject
   low-entropy ids in `validate`.
2. P0.48/P0.10 — gate clean-counter increments on adaptive status; implement the
   single-request conflict re-observe.
3. P0.45 — mix `t.pol.Revision` into `shortTag` (or filter evidence by revision)
   so a policy change forces re-classification per §26.
4. Durable stores + gateway process (P0.58/63/64/61/62) — before production.