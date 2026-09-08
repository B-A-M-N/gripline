#!/usr/bin/env bash
set -euo pipefail

# Start two independent verifier-like processes against one PostgreSQL replay
# authority and race the same namespaced claim. Exactly one process may win.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$repo_dir/scripts/qualification/fixtures/replay"
project="gripline-replay-${$}"
work_dir="$(mktemp -d)"
pids=()
keep="${GRIPLINE_QUALIFICATION_KEEP:-0}"
cleanup() {
	for pid in "${pids[@]}"; do kill "$pid" >/dev/null 2>&1 || true; done
	for pid in "${pids[@]}"; do wait "$pid" >/dev/null 2>&1 || true; done
	if [[ "$keep" != 1 ]]; then docker compose -p "$project" -f "$fixture_dir/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true; else echo "replay lab retained: $project" >&2; fi
	rm -rf "$work_dir"
}
trap cleanup EXIT
command -v docker >/dev/null || { echo "replay qualification: docker is required" >&2; exit 2; }
docker compose version >/dev/null || { echo "replay qualification: docker compose is required" >&2; exit 2; }
command -v go >/dev/null || { echo "replay qualification: go is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "replay qualification: curl is required" >&2; exit 2; }
compose=(docker compose -p "$project" -f "$fixture_dir/compose.yaml")
"${compose[@]}" up -d >/dev/null
for _ in $(seq 1 60); do
	if "${compose[@]}" exec -T postgres pg_isready -U gripline -d gripline >/dev/null 2>&1; then break; fi
	sleep 1
done
dsn="postgres://gripline:gripline@127.0.0.1:${GRIPLINE_REPLAY_POSTGRES_PORT:-25436}/gripline?sslmode=disable"
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/replay" ./cmd/gripline-test-replay
"$work_dir/replay" -listen 127.0.0.1:19601 -dsn "$dsn" >"$work_dir/a.log" 2>&1 & pids+=("$!")
"$work_dir/replay" -listen 127.0.0.1:19602 -dsn "$dsn" >"$work_dir/b.log" 2>&1 & pids+=("$!")
for port in 19601 19602; do
	for _ in $(seq 1 40); do
		if curl -fsS "http://127.0.0.1:${port}/readyz" >/dev/null 2>&1; then break; fi
		sleep 0.2
	done
	if ! curl -fsS "http://127.0.0.1:${port}/readyz" >/dev/null; then
		cat "$work_dir/a.log" "$work_dir/b.log" >&2
		exit 1
	fi
done
expires="$(date -u -d '+60 seconds' '+%Y-%m-%dT%H:%M:%SZ')"
payload="{\"issuer\":\"gripline\",\"audience\":\"qualification\",\"jti\":\"process-race-$$\",\"expires_at\":\"${expires}\"}"
claim_pids=()
for port in 19601 19602; do
	curl -sS -o "$work_dir/${port}.json" -w '%{http_code}' -X POST "http://127.0.0.1:${port}/claim" -H 'Content-Type: application/json' -d "$payload" >"$work_dir/${port}.status" &
	claim_pids+=("$!")
done
for pid in "${claim_pids[@]}"; do wait "$pid"; done
accepted="$(rg -l '"accepted":true' "$work_dir"/*.json | wc -l)"
[[ "$accepted" == 1 ]] || { echo "replay qualification: accepted=$accepted, want exactly one" >&2; exit 1; }
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" GRIPLINE_REPLAY_POSTGRES_DSN="$dsn" go test ./internal/replay -run TestPostgresReplayGuardParallelAcrossInstances -count=1
echo "replay qualification: two independent processes and parallel PostgreSQL claims produced exactly one winner"
