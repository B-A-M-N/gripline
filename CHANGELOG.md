# Changelog

All notable changes to Gripline are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Release qualification

- Long qualification workflows now set explicit 24-hour/72-hour job budgets;
  manifest provenance attestation runs in a downstream job with fresh GitHub
  credentials after the long soak.

### Public-beta hardening (re-review pass)

This release closes the findings of the pre-beta re-review. The theme: the
safe deployment must be the default, and every authority the security story
depends on must be real.

#### Added

- **Single transactional state authority** (`internal/statebolt`): credentials,
  lanes, evidence, operator audit, and operator posture now live in ONE bbolt
  database behind one write path. Lane and evidence repositories execute the
  same pure mutation reducers as the in-memory backends, so resident and
  durable semantics cannot drift.
- **Restart containment**: credential CONSTRAINED/REVOKED, lane
  SUSPICIOUS/BLOCKED (with full records), evidence, emergency posture, and the
  signer identity all survive a process restart — proven by an executable
  acceptance test (`TestAcceptanceRestartContainment`).
- **Transactional operator mutations** (`control.MutationStore`): credential
  revoke, lane unblock, and emergency posture each commit their mutation and
  audit row in ONE database transaction.
- **Streaming usage metering** (`proxy.UsageProvider`/`UsageSession`): the
  provider adapter observes every streamed body chunk and settles actual
  token/cost usage from the final response envelope at end-of-stream —
  completion accounting no longer has to guess from headers.
- **Completion observer** (`proxy.DecisionObserver`): completion-evidence
  persistence failures are surfaced as operational telemetry instead of being
  discarded.
- **Streaming timeout semantics**: `server.stream_write_idle_timeout` re-arms
  the write deadline per forwarded chunk and cuts a STALLED upstream stream
  (an idle bound), while long-lived live SSE streams run indefinitely. Split
  backend timeouts (`dial_timeout`, `tls_handshake_timeout`,
  `response_header_timeout`) bound each upstream phase.
- **Operator CLI** (`gripline credential list|revoke`, `gripline lane
  list|unblock`, `gripline status`): lifecycle actions through the same
  authorization + atomic mutation/audit seams as the admin HTTP surface, never
  touching raw credential secrets.
- **Real readiness probe** (`Runtime.Ready` behind `/readyz`): the state
  authority must answer a probe read; a failed probe is a 503, not a 200 that
  lies.
- **Secret-material hardening**: `GRIPLINE_PEPPER_V1` and
  `ingress.pseudonym_key` must be base64 and decode to >= 32 bytes; the two
  keys must differ (key separation).
- Release assets: LICENSE (Apache-2.0), SECURITY.md, this changelog,
  `deploy/config.example.json`, `deploy/Dockerfile`.

#### Changed

- **Persistent state is the required default** (`deployment.allow_ephemeral_state`,
  default false): boot FAILS without `paths.state` and `paths.signer_keyring`
  unless development mode is explicitly declared.
- **Bolt is the single evidence authority**: configuring `paths.evidence`
  together with `paths.state` is a boot error — no silent split authority.
- **Bolt is the authoritative operator audit** when state-backed; the JSONL
  file is an optional post-commit mirror.
- **bbolt is a direct dependency** in `go.mod`; CI runs staticcheck, builds,
  the executable acceptance suite, and a gofmt check, and takes its Go version
  from `go.mod`.

#### Removed

- **`admin.allow_public`**: the control plane must bind loopback or a private
  interface. There is no override.
- **Cleartext public listeners**: `tls.terminate_tls_upstream` (plain HTTP on
  the public listener) now REQUIRES a loopback/private bind.
- **`UsageEstimator.Actual`**: replaced by the streaming `UsageSession`
  contract (see Added).
- Negative `max_header_bytes` / `max_body_bytes` / `stream_write_idle_timeout`
  values are rejected at config load.

#### Fixed

- Chunked/unknown-length request bodies larger than `max_body_bytes` are
  rejected with 413 (previously they could be truncated and forwarded).
- Spooled request-body temp files no longer leak: cleanup is part of the
  body's own `Close`, on every path.
- bbolt transaction errors are no longer swallowed: every mutation returns
  transaction failures so bbolt rolls back (no partially committed security
  writes).
- The lane memory store returns copies of lane records (no escaped internal
  pointers across concurrent admissions).
- Source-resolution failures fail the request closed (503) instead of
  silently degrading to "no source".
- Cost-velocity detection learns sub-floor baselines instead of failing to
  build them.

## [0.1.0] and earlier

See the repository history and `docs/design/` for the design documents and
the milestone-by-milestone build-up (terminator, lanes, evidence, policy,
resource governor, internal identity, observability, deployment).
