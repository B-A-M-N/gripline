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
| P0.12 | RESOLVED | `Evidence.NonEvictable` marks FamilyOperatorIOC + zero-ExpiresAt critical; shared `evidence.CompactSubject` skips them and fails safe (keeps all) if nothing evictable. `TestM1CriticalEvidenceNotEvictedByFlood`. |
| P0.13 | RESOLVED | Every backend validates the whole batch before mutation, merges by subject, deduplicates IDs, and priority-compacts at `MaxEvidencePerSubject=2048`; invalid batches return `ErrInvalidEvidence`. `TestAppendAtomicBatchRejectsPartial` plus the durable/Bolt cap tests. |
| P0.14 | RESOLVED | `Evidence.Valid` rejects `!now.Before(ExpiresAt)` — inclusive-invalid at the boundary; all `Snapshot`/`Prune` implementations reuse the same evaluation rule. `TestExpiryIsInclusiveInvalidAtBoundary`. |
| P0.15 | RESOLVED | `evidence.Mint` stamps a CSPRNG id; `MintID` accepts an explicit idgen (nil fails closed); terminator + spray detector all produce uniform, unpredictable `ev_...` ids. **Closed by commit 5b644ee.** |
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
| P0.45 | PARTIAL | Evidence-revision filtering CLOSED (`policyRevisionFilter` drops stale-revision evidence from the authoritative feed; **commit 1685b35**). Lane-id part remains open: `shortTag` still hashes features only, so a policy change does not re-key lane identity (a fresh lane per §26 re-classification); documented follow-up. |
| P0.46/P0.47 | NOT GROUNDED | No code references P0.46/P0.47. |
| P0.48 | PARTIAL | Clean counters advance only on authorized requests (INV-8, `RecordCleanAuthorizedAndPromote` only in the authorized path; promotion gated behind `AdaptiveAvailable`). Caveat: in DEGRADED posture the counters still advance (promotion itself is the gated action) — a conditional INV-8 reading. |

## Architecture / control plane / gateway (P0.49–P0.57)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.49–P0.57 | NOT GROUNDED | No code, test, or comment references P0.49 through P0.57; highest numbered P0 in the tree is P0.69. These findings' text cannot be verified against committed code until their requirement text is reconciled with the repo. |

## Backend + production state + proof (P0.58–P0.69)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.58 | RESOLVED (single-node beta) | `internal/statebolt` is the durable credential authority. Multi-node replication remains deliberately out of scope. |
| P0.59 | RESOLVED | Signer key rotation / overlap: `terminator.Keyring` `Rotate()` + retained old-generation public keys; `TestDataPlaneBackendFollowsSignerRotation`. |
| P0.60 | PARTIAL | Assertion key overlap exists via Keyring, but no HSM/remote signer or automated key-management lifecycle. |
| P0.61 | ABSENT | Multi-node / leader election: resource governor is a single-process `sync.Mutex`; no etcd/Consul/Raft. |
| P0.62 | ABSENT | Shared leases with TTL across nodes: leases are in-process; no distributed store/TTL. |
| P0.63 | RESOLVED (single-node beta) | `statebolt.Store` implements `lane.Repository`; full lane records and security state survive restart. The resident lane store remains the explicit ephemeral implementation. |
| P0.64 | RESOLVED (single-node beta) | `statebolt.Store` implements `evidence.Store`; evidence survives restart. The legacy Gob store is compatibility-only and is not a production authority. |
| P0.65 | PARTIAL | Credential `SecurityState` and its authoritative transitions are durable in `statebolt`; process-local governor buckets and adapters remain volatile by design. |
| P0.66 | RESOLVED (single-node beta) | bbolt supplies the transactional append path for the beta authority; external WAL/replication and multi-node recovery remain out of scope. |
| P0.67 | RESOLVED | Source-spray anomaly detector: `anomaly.Detector` wired via `Dependencies.Spray`; `internal/anomaly/spray.go` + `m6_test.go`. |
| P0.68 | ABSENT | Dependency chaos / failure-injection harness: docs mention it (`docs/design/08-testing.md`) but no implementation; Gate F hand-codes one `failingStore`, not a harness. |
| P0.69 | PARTIAL (honest scope) | `internal/gates` contains component proofs for A–J and the latency test covers §112; the external release harness, network isolation, cross-process replay, and multi-node proofs remain pending. |

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

> **NOTE (public-beta re-review pass):** the classification and gap list below
> predate the deployable gateway and the transactional state authority. See
> the "Public-beta re-review close-out" section at the bottom for what is now
> true.

**Hardened security-core prototype / pre-beta data-plane library.** The core
deterministic authorization engine, the proxy trust boundary, all 10 acceptance
gates, the source-spray detector, signer rotation, the control plane, and the
observability decision record are committed and race-tested. At the time of
writing all state was in-memory and lost on restart; there was no standalone
gateway process; no multi-node lease coordination; no durable backend / WAL /
metrics pipeline; no chaos harness; no KMS/HSM-backed keys or TLS.

## Production gaps (not P0 defects; architecture recommendations)

> **Status updates from the public-beta close-out:** (1) RESOLVED —
> `cmd/gripline` is the deployable executable with boot-validated config.
> (2) LARGELY RESOLVED — credentials, lanes, evidence, operator audit, and
> posture are durable in one transactional bbolt database
> (`internal/statebolt`); restart containment is acceptance-proven. (3) STILL
> OPEN (deliberately out of beta scope) — multi-node coordination/TTL leases,
> chaos harness, metrics pipeline, KMS/HSM. (4) PARTIAL — source-identity
> attribution remains the provider-adapter seam.

## Open / partial work queue (ordered by what blocks the e2e goal)

1. ~~P0.15~~ CLOSED — CSPRNG evidence ids (commit 5b644ee).
2. ~~P0.45 evidence-revision filter~~ CLOSED — stale-revision evidence dropped
   from the authoritative state machine (commit 1685b35); lane-id re-keying
   per §26 remains a separate follow-up.
3. P0.48/P0.10 — gate clean-counter increments on adaptive status; implement the
   single-request conflict re-observe.
4. Durable stores + gateway process (P0.58/63/64/61/62) — before production.
---

## Public-beta re-review close-out (2026-09)

The second external review ("Gripline Public-Beta Re-review", 35 findings,
5-phase fix order) was implemented in full. Summary of what each phase changed
and how it is proven:

**Phase 1 — immediate correctness defects**
- Body spooler limit bypass/truncation + temp-file leak: `proxy.spoolBody` reads
  exactly `maxBytes+1` (overflow-safe), flags `tooLarge`, and cleanup is the
  body's own idempotent `Close` (every path). Proven: `TestSpoolBodyLimitBoundaries`,
  `TestSpoolBodyTooLargeNotForwardable`, `TestSpoolBodyTempFileCleanedOnNormalClose`,
  `TestSpoolBodyChunkedEndToEnd`, `TestSpoolBodyTempFilesDoNotLeakEndToEnd`.
- bbolt transaction error swallowing: every `statebolt` mutation returns
  transaction failures from the callback (bbolt rolls back). Proven by the
  statebolt suite + restart acceptance.
- Cost-velocity baseline: EMA learns sub-floor baselines; the absolute floor
  gates emission only. `producers/velocity_baseline_test.go`.
- Source-resolution failure now fails closed (503), never silently degrades to
  "no source". `proxy/source_resolution_test.go`.

**Phase 2 — single-node security authority**
- `internal/statebolt` implements `lane.Repository` and `evidence.Store` over
  the SAME pure mutation reducers as the memory store (semantic drift is
  structurally impossible: both call `lane.ApplyBorrowOrCreate` et al).
- One bbolt database is the credential + lane + evidence + operator-audit +
  posture authority; split Bolt/Gob configuration is a boot error. A state-backed
  `paths.audit_log` mirror is also rejected, so there is one audit authority.
- `control.MutationStore`: revoke / unblock / posture commit mutation + audit
  row in one transaction. Bolt is the sole audit authority when state-backed;
  JSONL remains only for explicitly ephemeral admin mode.
- Persistent state is mandatory unless `deployment.allow_ephemeral_state=true`.
- Restart containment acceptance: `TestAcceptanceRestartContainment`.
- Data race in the lane memory store fixed (returned records are copies).

**Phase 3 — live inference lifecycle**
- `UsageProvider.Begin → UsageSession{ObserveChunk, Finish}`: settlement
  charges the final streamed usage envelope; the meter sees every chunk
  without buffering or retaining content. `proxy/usage_test.go`.
- `DecisionObserver` surfaces completion-evidence persistence failures.
  `proxy/observer_test.go`.
- Streaming timeouts: `server.stream_write_idle_timeout` re-arms per chunk and
  the idle reader cuts a STALLED upstream; live SSE runs indefinitely.
  `TestAcceptanceRealStreaming`, `TestAcceptanceStalledStreamCut`.
- Split backend timeouts (dial / TLS handshake / response headers).

**Phase 4 — deployment fail-closed**
- Negative header/body/idle limits rejected; `admin.allow_public` REMOVED
  (private admin bind is unconditional); `tls.terminate_tls_upstream` requires
  a loopback/private bind; pepper + pseudonym keys must be base64 >= 32 bytes
  and distinct; `/readyz` probes the state authority (`Runtime.Ready`); run()
  propagates Close errors.

**Phase 5 — operator/release usability**
- `gripline credential list|revoke`, `gripline lane list|unblock`, `gripline audit
  list|export`, and `gripline status` use the running private admin listener by
  default; `--offline` is explicit stopped-database maintenance. They use the
  authorization + atomic mutation/audit seams and never touch raw secrets.
- bbolt is a direct dependency; CI: go-version-file, vet, staticcheck, build,
  race, gates, executable acceptance, gofmt.
- Release assets: LICENSE (Apache-2.0), SECURITY.md, CHANGELOG.md,
  deploy/config.example.json (validated by `gripline status`), deploy/Dockerfile
  (distroless, explicit UID 65532, image build verified); `.dockerignore` is
  present and staticcheck is pinned to v0.7.0.

**Verification at close-out:** `go vet ./...`, `staticcheck`, `go build ./...`,
`go test -race ./...` (all packages) green; executable acceptance suite green;
Docker image builds.
