# Gripline — Hostile-Review P0 Verdict Audit (Full)

Durable source of truth for the numbered P0 findings from the external hostile
production review. Every row is a verdict grounded in the current release-
candidate tree, confirmed by re-reading the actual implementation (not inferred
from summaries). This is the on-repo ground truth for the review close-out: a
finding is only RESOLVED when the verdict links to the symbol and proof that
satisfy it. Known beta boundaries are recorded as scope decisions, not hidden
capability claims.

Legend:
- RESOLVED — the invariant is implemented and enforced in the current tree.
- PARTIAL — the safety property holds but a named surface is known-incomplete;
  the missing piece is called out.
- OPEN — a confirmed defect not yet closed.
- NOT GROUNDED — no code/test/comment in the tree references this finding
  number; i.e. the finding text has no repository representation to verify.

Last verified against the release-candidate worktree on 2026-09-08. The
historical public-beta close-out below is retained for traceability, but the
current clustered-authority addendum at the end supersedes any older
single-node/out-of-scope wording.

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
| P0.10 | RESOLVED | DEGRADED is evaluated per request and a `TransitionConflict` performs one bounded authoritative re-read/re-observe attempt; failures preserve the stricter persisted state. |
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
| P0.45 | RESOLVED | Active evidence remains active across policy revisions until TTL expiry, and `laneTag` includes feature-schema plus classification-universe revisions so classification changes re-key the lane universe. |
| P0.46/P0.47 | NOT GROUNDED | No code references P0.46/P0.47. |
| P0.48 | RESOLVED | Clean baseline credit is deferred to successful proxy completion and the `BaselineToken` is ineligible in `AdaptiveDegraded`; denied, failed, and degraded requests do not advance trust counters. |

## Architecture / control plane / gateway (P0.49–P0.57)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.49–P0.57 | NOT GROUNDED | No code, test, or comment references P0.49 through P0.57; highest numbered P0 in the tree is P0.69. These findings' text cannot be verified against committed code until their requirement text is reconciled with the repo. |

## Backend + production state + proof (P0.58–P0.69)

| # | Verdict | Evidence |
|---|---------|----------|
| P0.58 | RESOLVED (standalone and clustered) | `internal/statebolt` is the standalone durable authority; `internal/statepg` is the shared PostgreSQL authority for clustered nodes. |
| P0.59 | RESOLVED (live clustered lifecycle) | `PrepareRotationWithAudit`, authenticated `/admin/crypto/activate` and `/admin/crypto/retire`, backend canary acceptance, shared generation barriers, and TTL/skew retirement are wired through the stock runtime and CLI. |
| P0.60 | PARTIAL | Assertion key overlap exists via Keyring, but no HSM/remote signer or automated key-management lifecycle. |
| P0.61 | RESOLVED (PostgreSQL active/active) | `statepg` provides shared row-locked resource buckets, leases, TTL expiry, node-epoch fencing, bounded retries, and the three-node cluster harness; active/active operation does not require a leader election service. |
| P0.62 | RESOLVED (PostgreSQL active/active) | Resource reservations carry request IDs, node epochs, forwarded/settled lifecycle, renewal, conservative expiry, and idempotent replay semantics in PostgreSQL. |
| P0.63 | RESOLVED (standalone and clustered) | bbolt and PostgreSQL both implement the lane authority; the resident lane store remains the explicit ephemeral implementation. |
| P0.64 | RESOLVED (standalone and clustered) | bbolt and PostgreSQL both implement the evidence authority; the legacy Gob store is compatibility-only and not a production authority. |
| P0.65 | RESOLVED (standalone and clustered) | Credential/lane/evidence/security state and resource accounting use the selected durable authority; only standalone in-flight leases are process-local. |
| P0.66 | RESOLVED for supported authorities | bbolt supplies standalone transactional durability and PostgreSQL supplies shared transactional durability; PostgreSQL WAL/replication/PITR remain infrastructure responsibilities. |
| P0.67 | RESOLVED | Source-spray anomaly detector: `anomaly.Detector` wired via `Dependencies.Spray`; `internal/anomaly/spray.go` + `m6_test.go`. |
| P0.68 | RESOLVED (single-node and clustered harnesses) | `scripts/chaos-smoke.sh` covers local failure seams and `scripts/cluster-harness.sh` covers three-node PostgreSQL state, fencing, crypto rollout, authority outage/recovery, and killed-node behavior. Environment-specific network isolation and third-party SDK evidence remain deployment gates. |
| P0.69 | RESOLVED (release and cluster proof) | The compiled release harness proves the single-node gateway/backend path; the PostgreSQL cluster harness proves active/active resource and authority invariants. Network isolation and provider SDKs remain hosting evidence. |

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
| J | Three-node PostgreSQL accounting: peak simultaneous holders ≤ shared cap, propagation, fencing, and authority recovery | committed in `scripts/cluster-harness.sh` |
| §112 | Admission latency p95 < 5ms / p99 < 20ms (liberal, de-flaked) | committed |
| e2e | Lane-restricted decision through real proxy → private backend, no secret crossing | committed (55df52a) |

## Production classification

> **NOTE (public-beta re-review pass):** the classification and gap list below
> predate the deployable gateway and the transactional state authority. See
> the "Public-beta re-review close-out" section at the bottom for what is now
> true.

**Production candidate with two supported topologies.** The deterministic
authorization engine, proxy trust boundary, durable bbolt authority,
PostgreSQL active/active authority, source-spray detector, operator control
plane, crypto lifecycle, and causal demo are implemented and tested. The
repository includes single-node release/chaos and three-node PostgreSQL
harnesses. Stable-release qualification still requires hosted provenance,
production network-perimeter verification, PostgreSQL HA/PITR evidence, and a
provider SDK/usage integration matrix.

## Production gaps (not P0 defects; architecture recommendations)

> **Status updates from the public-beta close-out:** (1) RESOLVED —
> `cmd/gripline` is the deployable executable with boot-validated config.
> (2) LARGELY RESOLVED — credentials, lanes, evidence, operator audit, and
> posture are durable in one transactional bbolt database
> (`internal/statebolt`); restart containment is acceptance-proven. (3) STILL
> OUT OF BETA SCOPE — multi-node coordination/TTL leases, network-isolation
> proof, SDK matrix, metrics export integration, and KMS/HSM. (4) PARTIAL —
> source-identity
> attribution remains the provider-adapter seam.

## Open / partial work queue (ordered by what blocks the e2e goal)

1. Release provenance — push the exact audited tree, pass hosted CI, cut a
   stable tag, and retain checksum/signature/build-provenance evidence.
2. Deployment evidence — PostgreSQL HA/PITR, network isolation, external
   telemetry, and provider SDK/usage semantics remain hosting gates.
3. Provider adapters — `usage.mode=none` is request/concurrency accounting
   only; production integrations must supply authoritative token/cost usage and
   source metadata for their provider.
---

## Public-beta re-review close-out (2026-09)

The current release-candidate tree addresses the second external review
("Gripline Public-Beta Re-review", 35 findings, 5-phase fix order). The
remaining partial/absent items are explicit beta limitations above, not hidden
claims. The ten release blockers and their current status are:

| Review item | Current status and evidence |
|---|---|
| P0-1 typed hard-resource denials | **RESOLVED.** `ScopeLimitError` survives `Terminator` into `Outcome.DenialErr`; HTTP maps typed hard-limit denials to 429 and preserves typed `Retry-After`. `TestM3TypedScopeDenialsPreserveHardLimitCause` covers SOURCE, ACCOUNT, CREDENTIAL, LANE, and GLOBAL. |
| P0-2 body-spool ordering | **RESOLVED.** Full source/classification/evidence/state/resource admission runs before unknown-length spooling; denied traffic does not spool, oversized admitted bodies cancel without backend or baseline credit, and chunked bodies forward exactly. `internal/proxy/spool_test.go` plus acceptance coverage. |
| P0-3 stock demo signal | **RESOLVED.** The demo uses only `SourceNovelty`, `ResourceVelocity`, and `Enumeration` producers and contains no `DEMO_*` signal, manual evidence append, or manual lane mutation. A real concurrent HTTP burst exposes stock `CONCURRENCY_OVER_4X_BASELINE`; the web and headless proofs require the real evidence and transition. |
| P0-4/P0-5 credential provisioning | **RESOLVED.** `terminator.ValidateExternalCredential` is shared by ingress, bootstrap, and live CLI; live add validates the config but never stats/opens the server-owned state file. |
| P0-6 admin bearer transport | **RESOLVED.** Plaintext admin binds accept numeric loopback only; LAN/private/public binds are rejected and remote access is documented through SSH or a TLS wrapper. |
| P0-7 live signer rotation | **RESOLVED at the lifecycle seam; route out of beta.** `PrepareRotationWithAudit` persists a prepared candidate, public publication is explicit, `ActivatePreparedWithAudit` requires backend acceptance before activation, and `RetireAfterWithAudit` enforces the TTL/skew horizon. The admin route remains out of beta and is not claimed as shipped. |
| P0-8 key durability | **RESOLVED.** Keyring replacement writes 0600 temporary state, fsyncs file, renames, fsyncs the parent directory, and cleans up failed temporary writes. |
| P0-9 strict config | **RESOLVED.** Config decoding disallows unknown fields at every nesting level and rejects trailing JSON values. |
| P0-10 cryptographic buffer hygiene | **RESOLVED (best effort).** Key comparisons use decoded bytes and temporary pepper, pseudonym, verifier, and secret buffers are wiped on owned exit paths; Go string/header copies remain outside the mutable-buffer guarantee. |
| P0-11 release publication | **RESOLVED in workflow.** Release tags run the full vet/tidy/diff/staticcheck/build/test/race/gate/acceptance/gofmt/demo/container checks, publish human and SHA image tags with normalized GHCR naming, embed version metadata, ship demo binaries, and smoke-test the pushed human tag. |

P1 close-out is also wired: `audit security list|export` exposes automatic
transition history; transition rows carry request, policy, and evidence
provenance; the bounded observer reports telemetry drops while running; the
quick start starts only after config/secrets are prepared and readiness is
verified; demo browser controls have `httptest` coverage; and the release
workflow declares the demo binaries as assets.

Summary of the implementation phases and their proof follows:

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

**Verification at close-out (2026-09-07):** `go test ./...`, `go vet ./...`,
`staticcheck ./...`, `go build ./...`, `go mod tidy -diff`, `git diff --check`,
and the `gofmt` gate are green. `go test -race ./...` is green across all
packages. Gate A–J component proofs, observability proofs, and the §112
admission-latency proof are green (p95 ≈ 0.41ms, p99 ≈ 0.57ms); the
executable acceptance suite and headless causal demo are green. The release
container builds and `deploy/container-smoke.sh` passes persistence, readiness,
SIGTERM, and restart checks.

Final re-verification after the numbered audit changes also passed
govulncheck (No vulnerabilities found), bash syntax checks, scripts/chaos-smoke.sh,
the compiled release-harness.sh including backend capture canary, read-only
state/signer/spool probes and SIGKILL restart, and the durable state-backed
proxy percentile test (p50 41.8ms, p95 48.2ms, p99 67.8ms, 1,434 req/s on
this host). The explicit admission-latency gate measured p95 397.6µs and p99
738.1µs; the container smoke passed with a nonroot UID, TLS, persistence, and
restart.

## Numbered production-review completion audit (1–38)

This matrix is the requirement-by-requirement close-out for the production
review supplied on 2026-09-07. “Scope-closed” means the review requirement is
handled by an explicit single-node or beta boundary and the repository does
not claim the excluded deployment capability.

| # | Verdict | Evidence |
|---|---|---|
| 1 | VERIFIED | go.mod requires Go 1.25.13; CI/release assert the exact toolchain and run govulncheck. |
| 2 | VERIFIED | Public adapter/usage and adapter/ingress contracts plus external compile tests. |
| 3 | VERIFIED | Stock ingress resolves trusted canonical source metadata through the configured ASN/network/region CIDR adapter. |
| 4 | VERIFIED | Source novelty emits independent NEW_SOURCE evidence; it does not derive continuity solely from ASN. |
| 5 | VERIFIED | Producer, anomaly, credential, lane, evidence, posture, and audit state are persistent; restart tests prove detector baseline restoration. |
| 6 | VERIFIED | policy.Manager validates, prepares, persists, activates, restores crash-phase candidates, and performs explicit audited rollback. |
| 7 | SCOPE-CLOSED | One immutable policy snapshot is selected per process; PlanID is required metadata and multi-plan resolution is explicitly not shipped. |
| 8 | VERIFIED | Bounded OpenAI/Anthropic usage adapters are wired; request reservation precedes execution and actual usage settles after completion. |
| 9 | VERIFIED by topology | Standalone buckets are process-lifetime; clustered PostgreSQL buckets/leases are shared, TTL-bound, fenced, and acceptance-tested. |
| 10 | VERIFIED | Governor uses metadata locking only; independent pools/buckets are acquired without a process-wide admission mutex. |
| 11 | VERIFIED | Zero MaxSourceScopes resolves to a conservative bound and is covered by runtime status and governor tests. |
| 12 | VERIFIED | Idle source scopes are evicted; non-evictable saturation folds identities into bounded hashed overflow scopes with metrics. |
| 13 | VERIFIED | Idle lane/resource state has explicit removal and refuses eviction while leases, reservations, or debt remain. |
| 14 | VERIFIED | Global evidence sweep, expiry metrics, bounded compaction, and durable sweep cursor are implemented in statebolt. |
| 15 | VERIFIED | Persistent runtime config resolves zero spool limits to bounded 64 MiB/64-file defaults. |
| 16 | VERIFIED | External secret carriers are stripped before source, feature, usage, or backend processing; owned mutable copies are zeroed. |
| 17 | VERIFIED | Pepper keys are copied only inside the ring, never persisted, versioned records support overlap/migration, and old versions remain explicit. |
| 18 | VERIFIED | Pseudonym keys are versioned with overlap and highest-version issuance; key material is distinct from verifier peppers. |
| 19 | VERIFIED at live lifecycle | Signer prepare/persist/public-publish/backend-accept/activate/TTL-skew-retire phases are durable, audited, exposed through the authenticated admin/CLI lifecycle, and covered by cluster harness assertions. |
| 20 | VERIFIED | Keyring, policy, lifecycle, manifest, and state files reject links/special files/broad permissions; writes use restricted temp files, fsync, rename, and directory sync. |
| 21 | VERIFIED | Recovery manifests bind database hash/schema to policy ID/revision/digest, signer public fingerprints, and required pepper/pseudonym versions; restore refuses an active target. |
| 22 | VERIFIED | Ordered statebolt migrations create pre-migration backups, run transactionally, validate schema post-open, and expose backup/restore tooling. |
| 23 | VERIFIED | The compiled backend fixture and demo use the public verify key-set acceptance path, not the private signer. |
| 24 | VERIFIED | Wire format is versioned v1 with immutable payload/signature vectors in verify/testdata. |
| 25 | VERIFIED for claimed surface | Compiled release harness uses separate gateway/backend processes and real TCP HTTP cases for direct denial, forged claims, revision freshness, query/gzip/chunked/SSE/oversized/cancel/restart/status behavior; third-party SDKs remain hosting-side evidence. |
| 26 | VERIFIED | Exact harness credential is scanned across generated config, provision output, logs, backend captures, telemetry, audit, and artifacts before release proof passes. |
| 27 | VERIFIED for repository fault matrix | Chaos smoke covers local failures; the three-node PostgreSQL harness covers authority outage/recovery, fencing, killed-node leases, backend cancellation, and shared-state faults. ENOSPC/network-namespace and production HA remain hosting gates. |
| 28 | VERIFIED | Durable state-backed proxy benchmark reports p50/p95/p99 and throughput under concurrent request pressure. |
| 29 | VERIFIED | Admin metrics expose low-cardinality admission, denial, degraded, resource scope/dimension, source saturation/eviction, spool, evidence, bbolt, stream, backend, telemetry, policy, and signer counters. |
| 30 | VERIFIED | status reports active durable policy ID/revision/digest, actual signer KID state, resource persistence boundary, source bound, spool limits, and pepper/pseudonym versions. |
| 31 | VERIFIED | CredentialRecord validation requires PlanID; CLI help and live provisioning use the same contract. |
| 32 | VERIFIED | Generic policy naming is the default and the legacy provider alias remains accepted for compatibility. |
| 33 | VERIFIED | CI/release pin action SHAs and tool versions, fail on toolchain/vulnerability/static checks, publish checksums, cosign signatures, SBOM/provenance, and attestations. |
| 34 | VERIFIED | README and design docs describe standalone/bbolt and clustered/PostgreSQL authority modes, crypto rollout, fencing, migration, leases, and deployment boundaries. |
| 35 | VERIFIED | README and value visual distinguish implemented clustered authority from remaining hosted SDK, perimeter, HA, and provenance qualification. |
| 36 | VERIFIED | The causal demo uses the configured ingress/network adapter and a separate public verify-backed protected backend; headless proof is executable. |
| 37 | VERIFIED as deployment gate | Backend integration docs require private reachability/mTLS and raw-key denial; the release harness directly proves the backend rejects raw credentials. |
| 38 | VERIFIED | README, design docs, status, benchmark, and audit state both topology boundaries and the distinct standalone versus PostgreSQL resource semantics. |

## Current clustered-authority addendum (2026-09-08)

This addendum supersedes older beta-era statements in this file. The current
tree contains a real active/active PostgreSQL authority, not just an interface
stub:

- `internal/statepg` owns shared credentials, lanes, evidence, posture/audit,
  policy observations, adaptive rows, resource buckets/leases, membership and
  instance fencing, and staged crypto generations.
- `scripts/cluster-harness.sh` runs three gateways against PostgreSQL and is
  required by CI/release. It proves shared concurrency, revocation, lockdown,
  policy activation/rollback, signer activation and retirement, stale-assertion
  rejection, killed-node cancellation, and PostgreSQL outage/recovery.
- `gripline migrate plan|apply`, `cluster status`, and `crypto
  status|activate|retire|signer-prepare` are the operational surfaces for the
  shared authority. Serving nodes do not run migrations automatically.
- `deploy/config.postgres.example.json` is the reference clustered topology;
  local `paths.state`, `paths.evidence`, and `paths.audit_log` are deliberately
  absent because PostgreSQL is the authority.

The production-stable verdict remains **NO-GO until hosted release
qualification completes**. The remaining evidence is outside what this local
tree can prove: exact-commit hosted CI/release provenance, PostgreSQL HA/PITR
and failover operations, production network isolation/mTLS, and the provider
SDK plus authoritative token/cost usage matrix. `usage.mode=none` intentionally
enforces requests/concurrency only.
