# Security Release Criteria

Gripline has three qualification layers. The first two are repository-owned;
the third is specific to the operator's deployment.

```yaml
repository_status: layer_1_worktree_passed_pending_exact_release_record
reference_lab_status: repository-owned_smoke_and_long_soak_required_on_exact_sha
operator_deployment_status: separate_per_deployment
production_qualification_status: pending_exact_release_record
production_stable: false
production_stable_rule: layers_1_and_2_pass_on_exact_release_sha
```

## Layer 1 — code correctness

These gates must pass on the exact release commit. The current worktree has
passed the Go test/race/vet and unexcluded gosec gates; hosted release
execution remains the authoritative exact-SHA record:

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `staticcheck ./...`
- `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...`
- `go run github.com/securego/gosec/v2/cmd/gosec@v2.22.8 -quiet ./...`
- `GRIPLINE_FUZZ_TIME=2s bash scripts/fuzz-smoke.sh`
- `bash scripts/release-harness.sh`
- `bash scripts/chaos-smoke.sh`
- PostgreSQL integration and `bash scripts/cluster-harness.sh`
- exact commit check: `git rev-parse HEAD == GITHUB_SHA`

The workflow must retain the commit, tool versions, test output, vulnerability
result, and artifact provenance. Gosec has no global exclusions; intentional
exceptions are line-local and documented in `GOSEC-BASELINE.md`.

## Layer 2 — repository reference production lab

These are reproducible local qualification gates, not placeholders for hosted
infrastructure. The qualification workflow runs the short functional set; the
release workflow runs the full reference suite and gates publication on a
24-hour self-hosted reference soak on the exact tagged SHA.
The scheduled/manual qualification record must additionally retain the long
soak evidence:

| Control | Owned entrypoint | Evidence required |
|---|---|---|
| PostgreSQL primary/replica promotion and rejoin | `bash scripts/qualification/ha.sh` | Replica promotion, preserved policy/crypto state, failed-node rejoin |
| Base-backup/WAL PITR | `bash scripts/qualification/pitr.sh` | Target-time restore returns the pre-mutation security state |
| Network isolation and mTLS | `bash scripts/qualification/perimeter.sh` and `bash scripts/qualification/clustered-perimeter.sh` | Public attacker cannot reach private backend/control/PostgreSQL; standalone and clustered gateway identities succeed |
| Official SDK behavior | `bash scripts/qualification/sdk.sh` | OpenAI and Anthropic Python/TypeScript streaming and non-streaming usage, tools, large input, retry/429, 5xx, cancellation, reuse, and parallel calls |
| Direct TLS/HTTP2 | `bash scripts/qualification/http2.sh` | ALPN, stream/header bounds, CONTINUATION, cancellation/recovery, error metrics, and `h2load` evidence |
| Shared replay | `bash scripts/qualification/replay.sh` | Two independent processes produce exactly one winner for one claim |
| Long-running active/active behavior | `bash scripts/qualification/soak.sh --duration 24h` | Replica/policy continuity, bounded active leases/holds/source scopes, retention checks, RSS/goroutine/heap snapshots, outage recovery, post-soak promotion |
| Reference capacity behavior | `bash scripts/qualification/capacity.sh --duration 30s` | Persistent-client load, status distribution, p50/p95/p99, PostgreSQL pool wait, transaction retries, and transaction latency |
| Source-churn qualification | `bash scripts/qualification/source-churn.sh` | Invalid-source spray remains read-only and backend-isolated; authenticated first-seen sources bind, source scopes overflow within bounds, pseudonym rotation preserves cardinality, and stale aliases are reclaimed |

The lab uses disposable containers, generated keys, and local
provider-shaped fixtures; it requires no provider account. Each suite run emits
sanitized per-gate JSON plus `manifest.json` and `manifest.sha256` under the
qualification result directory. By default each run is written under a
commit/run-specific directory; CI may provide an explicit artifact directory.
The manifest records the exact commit,
fixture image digests, tool versions, and gate outcomes; release publication
verifies that manifest before building artifacts and attests it.
The qualification workflow's manual `soak_duration` input accepts `24h` or
`72h` for the long reference record; only short smoke runs use a GitHub-hosted
runner.

## Layer 3 — operator-specific deployment validation

These checks remain necessary before a particular deployment is called
production-ready, but they do not block the generic software production-stable
claim once Layers 1 and 2 pass:

- operator AWS/Kubernetes/VPC/network-policy reachability and edge DDoS controls;
- managed PostgreSQL product failover, backup/PITR, TLS, and restore evidence;
- issued production PKI, secret delivery, KMS/HSM, and key rotation;
- provider account/model quotas, authoritative token/cost settlement, and
  provider-owned object/property authorization;
- operator observability, alerting, retention, incident response, and capacity.

The release record must label these as `operator_deployment_status`, not as
missing Gripline implementation. Backend object/property authorization,
volumetric DDoS, and host/key compromise remain explicit boundary controls.
