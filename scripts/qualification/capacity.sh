#!/usr/bin/env bash
set -euo pipefail

# Capacity is deliberately separate from the security soak: it uses the same
# repository-owned HA database and three-node harness, but omits the outage
# handoff so rate-limit/security recovery state cannot distort throughput.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$repo_dir/scripts/qualification/fixtures/postgres-ha"
project="gripline-capacity-${$}"
work_dir="$(mktemp -d)"
writer_pid=""
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
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/pg-writer" ./cmd/gripline-test-pg-writer
compose=(docker compose -p "$project" -f "$fixture_dir/compose.yaml")
"${compose[@]}" up -d >/dev/null
export GRIPLINE_HA_PRIMARY_PORT="${GRIPLINE_HA_PRIMARY_PORT:-$(${compose[*]} port primary 5432 | head -1 | awk -F: '{print $NF}')}"
export GRIPLINE_HA_REPLICA_PORT="${GRIPLINE_HA_REPLICA_PORT:-$(${compose[*]} port replica 5432 | head -1 | awk -F: '{print $NF}')}"
[[ "$GRIPLINE_HA_PRIMARY_PORT" =~ ^[0-9]+$ && "$GRIPLINE_HA_REPLICA_PORT" =~ ^[0-9]+$ ]] || {
	echo "capacity qualification: compose did not publish numeric PostgreSQL ports" >&2
	exit 1
}
for _ in $(seq 1 90); do
	if "${compose[@]}" exec -T primary pg_isready -U gripline -d gripline >/dev/null 2>&1 && "${compose[@]}" exec -T replica pg_isready -U gripline -d gripline >/dev/null 2>&1; then break; fi
	sleep 1
done
writer_port=$((25434 + ($$ % 100)))
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
GRIPLINE_CLUSTER_HARNESS_LOAD_MODE=capacity \
GRIPLINE_CLUSTER_HARNESS_LOAD_SECONDS="$load_seconds" \
GRIPLINE_CLUSTER_HARNESS_LOAD_WORKERS="$workers" \
GRIPLINE_CLUSTER_HARNESS_SKIP_OUTAGE=1 \
GRIPLINE_CLUSTER_HARNESS_SKIP_KILLED_NODE=1 \
GRIPLINE_CLUSTER_HARNESS_REQUIRE_DB_OUTAGE=0 \
GRIPLINE_TEST_POSTGRES_DSN="$dsn" \
bash "$repo_dir/scripts/cluster-harness.sh"
