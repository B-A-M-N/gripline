#!/usr/bin/env bash
set -euo pipefail

# Capacity is deliberately separate from the security soak: it uses the same
# repository-owned HA database and three-node harness, but omits the outage
# handoff so rate-limit/security recovery state cannot distort throughput.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_dir/scripts/qualification/assertions.sh"
fixture_dir="$repo_dir/scripts/qualification/fixtures/postgres-ha"
source "$fixture_dir/ports.sh"
project="gripline-capacity-${$}"
work_dir="$(mktemp -d)"
writer_pid=""
capacity_evidence="${GRIPLINE_CLUSTER_HARNESS_CAPACITY_EVIDENCE_FILE:-$work_dir/capacity-load-telemetry.json}"
export GRIPLINE_CLUSTER_HARNESS_CAPACITY_EVIDENCE_FILE="$capacity_evidence"
duration="${GRIPLINE_CAPACITY_LOAD_DURATION:-30s}"
workers="${GRIPLINE_CAPACITY_LOAD_WORKERS:-16}"
while [[ $# -gt 0 ]]; do
	case "$1" in
		--duration) duration=${2:?--duration requires a value}; shift 2 ;;
		--workers) workers=${2:?--workers requires a value}; shift 2 ;;
		*) echo "capacity qualification: unknown argument $1" >&2; exit 2 ;;
	esac
done
cleanup() {
	if [[ -n "$writer_pid" ]]; then kill -TERM "$writer_pid" >/dev/null 2>&1 || true; wait "$writer_pid" >/dev/null 2>&1 || true; fi
	docker compose -p "$project" -f "$fixture_dir/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	rm -rf "$work_dir"
}
trap cleanup EXIT
command -v docker >/dev/null || { echo "capacity qualification: docker is required" >&2; exit 2; }
docker compose version >/dev/null || { echo "capacity qualification: docker compose is required" >&2; exit 2; }
command -v go >/dev/null || { echo "capacity qualification: go is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "capacity qualification: python3 is required" >&2; exit 2; }
configure_ha_ports
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/pg-writer" ./cmd/gripline-test-pg-writer
compose=(docker compose -p "$project" -f "$fixture_dir/compose.yaml")
"${compose[@]}" up -d >/dev/null
[[ "$GRIPLINE_HA_PRIMARY_PORT" =~ ^[0-9]+$ && "$GRIPLINE_HA_REPLICA_PORT" =~ ^[0-9]+$ ]] || {
	echo "capacity qualification: compose did not publish numeric PostgreSQL ports" >&2
	exit 1
}
for _ in $(seq 1 90); do
	if "${compose[@]}" exec -T primary pg_isready -U gripline -d gripline >/dev/null 2>&1 && "${compose[@]}" exec -T replica pg_isready -U gripline -d gripline >/dev/null 2>&1; then break; fi
	sleep 1
done
writer_port="${GRIPLINE_HA_WRITER_PORT:-$(pick_free_port 26434 27434)}"
export GRIPLINE_HA_WRITER_PORT="$writer_port"
dsn="postgres://gripline:gripline@127.0.0.1:${writer_port}/gripline?sslmode=disable"
"$work_dir/pg-writer" -listen "127.0.0.1:${writer_port}" \
	-backend-dsn "postgres://gripline:gripline@127.0.0.1:${GRIPLINE_HA_PRIMARY_PORT:-25432}/gripline?sslmode=disable" \
	-backend-dsn "postgres://gripline:gripline@127.0.0.1:${GRIPLINE_HA_REPLICA_PORT:-25433}/gripline?sslmode=disable" \
	>"$work_dir/pg-writer.log" 2>&1 &
writer_pid=$!
case "$duration" in
	*[smh]) load_duration="${duration%[smh]}"; unit="${duration: -1}" ;;
	*) echo "capacity qualification: duration must end in s, m, or h" >&2; exit 2 ;;
esac
case "$unit" in
	s) load_seconds=$load_duration ;;
	m) load_seconds=$((load_duration * 60)) ;;
	h) load_seconds=$((load_duration * 3600)) ;;
esac
# The three-node serializable authority can legitimately retry a hot shared
# source/lane row once or twice while still returning every request
# successfully. Keep the bound strict at 1.5 retries/request; callers may
# tighten it for a dedicated deployment benchmark.
GRIPLINE_CLUSTER_HARNESS_LOAD_MODE=capacity \
GRIPLINE_CLUSTER_HARNESS_LOAD_SECONDS="$load_seconds" \
GRIPLINE_CLUSTER_HARNESS_LOAD_WORKERS="$workers" \
GRIPLINE_CLUSTER_HARNESS_MAX_CONNS="${GRIPLINE_CAPACITY_MAX_CONNS:-16}" \
GRIPLINE_CLUSTER_HARNESS_OPERATION_TIMEOUT="2s" \
GRIPLINE_CLUSTER_HARNESS_LOAD_TIMEOUT="${GRIPLINE_CAPACITY_LOAD_TIMEOUT:-30s}" \
GRIPLINE_CAPACITY_MIN_SUCCESS_RPS="${GRIPLINE_CAPACITY_MIN_SUCCESS_RPS:-10}" \
GRIPLINE_CAPACITY_MAX_P95_MS="${GRIPLINE_CAPACITY_MAX_P95_MS:-5000}" \
GRIPLINE_CAPACITY_MAX_P99_MS="${GRIPLINE_CAPACITY_MAX_P99_MS:-8000}" \
GRIPLINE_CAPACITY_MAX_RETRIES_PER_1000="${GRIPLINE_CAPACITY_MAX_RETRIES_PER_1000:-1500}" \
GRIPLINE_CAPACITY_MAX_DEADLOCKS="${GRIPLINE_CAPACITY_MAX_DEADLOCKS:-0}" \
GRIPLINE_CLUSTER_HARNESS_SKIP_OUTAGE=1 \
GRIPLINE_CLUSTER_HARNESS_SKIP_KILLED_NODE=1 \
GRIPLINE_CLUSTER_HARNESS_REQUIRE_DB_OUTAGE=0 \
GRIPLINE_TEST_POSTGRES_DSN="$dsn" \
bash "$repo_dir/scripts/cluster-harness.sh"
if [[ -z "$capacity_evidence" || ! -s "$capacity_evidence" ]]; then
	echo "capacity qualification: structured capacity evidence is missing" >&2
	exit 1
fi
capacity_measurements="$(python3 - "$capacity_evidence" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
required = (
    "authority_operation_timeout_ms", "total", "successful", "success_ratio",
    "successful_rps", "source_resolution_failures", "authority_timeouts",
    "transaction_retries", "deadlocks",
)
for name in required:
    if name not in value or isinstance(value[name], bool) or not isinstance(value[name], (int, float)):
        raise SystemExit(f"capacity evidence measurement is missing or invalid: {name}")
measurements = {
    "authority_operation_timeout_ms": value["authority_operation_timeout_ms"],
    "total_requests": value["total"],
    "successful_requests": value["successful"],
    "success_ratio": value["success_ratio"],
    "successful_rps": value["successful_rps"],
    "p50_ms": value["latency"]["successful"]["p50_ms"],
    "p95_ms": value["latency"]["successful"]["p95_ms"],
    "p99_ms": value["latency"]["successful"]["p99_ms"],
    "source_resolution_failures": value["source_resolution_failures"],
    "authority_timeouts": value["authority_timeouts"],
    "transaction_retries": value["transaction_retries"],
    "deadlocks": value["deadlocks"],
}
print(json.dumps(measurements, separators=(",", ":")))
PY
)"
emit_qualification_assertions \
	'{"load_completed":true,"concurrency_bound_enforced":true,"resource_state_bounded":true}' \
	"$(python3 - "$capacity_measurements" "$load_seconds" "$workers" <<'PY'
import json
import sys
measurements = json.loads(sys.argv[1])
measurements["duration_seconds"] = int(sys.argv[2])
measurements["workers"] = int(sys.argv[3])
print(json.dumps(measurements, separators=(",", ":")))
PY
)"
