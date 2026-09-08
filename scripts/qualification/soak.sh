#!/usr/bin/env bash
set -euo pipefail

# Self-contained active/active soak: local HA PostgreSQL, three compiled
# Gripline nodes, a process-level load balancer, continuous replica/state
# checks, and a promotion after the load phase.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$repo_dir/scripts/qualification/fixtures/postgres-ha"
project="gripline-soak-${$}"
work_dir="$(mktemp -d)"
monitor_pid=""
harness_pid=""
harness_artifact="$work_dir/harness.env"
snapshot_file="$work_dir/soak.tsv"
duration_text="5m"
workers="${GRIPLINE_CLUSTER_SOAK_WORKERS:-24}"
while [[ $# -gt 0 ]]; do
	case "$1" in
		--duration) duration_text=${2:?--duration requires a value}; shift 2 ;;
		--workers) workers=${2:?--workers requires a value}; shift 2 ;;
		-h|--help) echo 'usage: soak.sh [--duration 24h|72h|300s] [--workers N]'; exit 0 ;;
		*) echo "soak qualification: unknown argument $1" >&2; exit 2 ;;
	esac
done
case "$duration_text" in
	*[smh]) amount="${duration_text%[smh]}"; unit="${duration_text: -1}" ;;
	*) echo "soak qualification: duration must end in s, m, or h" >&2; exit 2 ;;
esac
[[ "$amount" =~ ^[1-9][0-9]*$ ]] || { echo "soak qualification: duration must be positive" >&2; exit 2; }
case "$unit" in s) duration=$amount ;; m) duration=$((amount * 60)) ;; h) duration=$((amount * 3600)) ;; esac
[[ "$workers" =~ ^[1-9][0-9]*$ ]] || { echo "soak qualification: workers must be positive" >&2; exit 2; }
cleanup() {
	if [[ -n "$harness_pid" ]]; then kill -TERM "$harness_pid" >/dev/null 2>&1 || true; wait "$harness_pid" >/dev/null 2>&1 || true; fi
	if [[ -n "$monitor_pid" ]]; then kill "$monitor_pid" >/dev/null 2>&1 || true; wait "$monitor_pid" >/dev/null 2>&1 || true; fi
	docker compose -p "$project" -f "$fixture_dir/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	rm -rf "$work_dir"
}
trap cleanup EXIT
command -v docker >/dev/null || { echo "soak qualification: docker is required" >&2; exit 2; }
docker compose version >/dev/null || { echo "soak qualification: docker compose is required" >&2; exit 2; }
command -v go >/dev/null || { echo "soak qualification: go is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "soak qualification: curl is required" >&2; exit 2; }
compose=(docker compose -p "$project" -f "$fixture_dir/compose.yaml")
"${compose[@]}" up -d >/dev/null
for _ in $(seq 1 90); do
	if "${compose[@]}" exec -T primary pg_isready -U gripline -d gripline >/dev/null 2>&1 && "${compose[@]}" exec -T replica pg_isready -U gripline -d gripline >/dev/null 2>&1; then break; fi
	sleep 1
done
monitor_failure="$work_dir/monitor.failure"
monitor() {
	while [[ -z "$harness_pid" ]] || kill -0 "$harness_pid" >/dev/null 2>&1; do
		if ! "${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc 'SELECT pg_is_in_recovery()' 2>/dev/null | rg -qx t; then echo replica-not-in-recovery >"$monitor_failure"; return 1; fi
		schema="$("${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='gripline_policy_manifest')" 2>/dev/null || true)"
		if [[ "$schema" != t ]]; then sleep 5; continue; fi
		if ! "${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc 'SELECT singleton FROM gripline_policy_manifest WHERE singleton=TRUE' 2>/dev/null | rg -qx t; then echo replica-policy-missing >"$monitor_failure"; return 1; fi
		if [[ -s "$harness_artifact" ]]; then
			base="$(awk -F= '$1 == "base" {print $2}' "$harness_artifact")"
			token="$(awk -F= '$1 == "operator_token" {print $2}' "$harness_artifact")"
			for node in a b c; do
				case "$node" in
					a) admin_port=$((base + 20)); pid="$(awk -F= '$1 == "node_a_pid" {print $2}' "$harness_artifact")" ;;
					b) admin_port=$((base + 21)); pid="$(awk -F= '$1 == "node_b_pid" {print $2}' "$harness_artifact")" ;;
					c) admin_port=$((base + 22)); pid="$(awk -F= '$1 == "node_c_pid" {print $2}' "$harness_artifact")" ;;
				esac
				if [[ -z "$pid" || ! -r "/proc/$pid/status" ]]; then continue; fi
				metrics="$(curl -fsS "http://127.0.0.1:${admin_port}/admin/metrics" -H "Authorization: Bearer ${token}" 2>/dev/null || true)"
				if [[ -z "$metrics" ]]; then continue; fi
				metric() { printf '%s\n' "$metrics" | awk -v name="gripline_$1" '$1 == name {print $2}'; }
				goroutines="$(metric runtime_goroutines)"
				heap="$(metric runtime_heap_alloc_bytes)"
				scopes="$(metric resource_source_scopes)"
				active="$(metric resource_active_leases)"
				rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")"
				if [[ ! "$goroutines" =~ ^[0-9]+$ || ! "$heap" =~ ^[0-9]+$ || ! "$scopes" =~ ^[0-9]+$ || ! "$active" =~ ^[0-9]+$ || ! "$rss" =~ ^[0-9]+$ ]]; then
					continue
				fi
				if (( scopes > 4096 || active > 5 )); then echo "resource-bounds-${node}" >"$monitor_failure"; return 1; fi
				printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$node" "$rss" "$goroutines" "$heap" "$scopes" "$active" >>"$snapshot_file"
			done
			retention="$("${compose[@]}" exec -T primary psql -U gripline -d gripline -X -Atqc "SELECT (SELECT count(*) FROM gripline_resource_leases WHERE state IN ('reserved','forwarded')) || '|' || (SELECT count(*) FROM gripline_resource_holds h JOIN gripline_resource_leases l ON l.lease_id=h.lease_id WHERE l.state IN ('reserved','forwarded')) || '|' || (SELECT count(*) FROM gripline_evidence)" 2>/dev/null || true)"
			if [[ "$retention" =~ ^([0-9]+)\|([0-9]+)\|([0-9]+)$ ]]; then
				if (( BASH_REMATCH[1] > 5 || BASH_REMATCH[2] > 64 || BASH_REMATCH[3] > 100000 )); then echo "retention-bounds" >"$monitor_failure"; return 1; fi
			fi
		fi
		sleep 5
	done
}
monitor &
monitor_pid=$!
dsn="postgres://gripline:gripline@127.0.0.1:${GRIPLINE_HA_PRIMARY_PORT:-25432}/gripline?sslmode=disable"
GRIPLINE_CLUSTER_HARNESS_ARTIFACT_FILE="$harness_artifact" GRIPLINE_TEST_POSTGRES_DSN="$dsn" GRIPLINE_TEST_POSTGRES_CONTAINER="${project}-primary-1" GRIPLINE_CLUSTER_HARNESS_REQUIRE_DB_OUTAGE=1 GRIPLINE_CLUSTER_HARNESS_LOAD_SECONDS="$duration" GRIPLINE_CLUSTER_HARNESS_LOAD_WORKERS="$workers" bash "$repo_dir/scripts/cluster-harness.sh" >"$work_dir/harness.log" 2>&1 &
harness_pid=$!
for _ in $(seq 1 120); do
	if [[ -s "$harness_artifact" ]]; then break; fi
	if ! kill -0 "$harness_pid" >/dev/null 2>&1; then cat "$work_dir/harness.log" >&2; exit 1; fi
	sleep 0.25
done
[[ -s "$harness_artifact" ]] || { echo "soak qualification: cluster harness did not publish its runtime fixture" >&2; cat "$work_dir/harness.log" >&2; exit 1; }
if ! wait "$harness_pid"; then cat "$work_dir/harness.log" >&2; exit 1; fi
harness_pid=""
if [[ -f "$monitor_failure" ]]; then echo "soak qualification: invariant monitor failed: $(<"$monitor_failure")" >&2; exit 1; fi
kill "$monitor_pid" >/dev/null 2>&1 || true
wait "$monitor_pid" >/dev/null 2>&1 || true
monitor_pid=""
[[ -s "$snapshot_file" ]] || { echo "soak qualification: no process/resource snapshots captured" >&2; exit 1; }
for node in a b c; do
	[[ "$(awk -F '\t' -v want="$node" '$2 == want {n++} END {print n+0}' "$snapshot_file")" -gt 0 ]] || { echo "soak qualification: no complete runtime snapshot for node $node" >&2; exit 1; }
done
max_rss="$(awk -F '\t' 'BEGIN {m=0} {if ($3 > m) m=$3} END {print m+0}' "$snapshot_file")"
max_goroutines="$(awk -F '\t' 'BEGIN {m=0} {if ($4 > m) m=$4} END {print m+0}' "$snapshot_file")"
max_heap="$(awk -F '\t' 'BEGIN {m=0} {if ($5 > m) m=$5} END {print m+0}' "$snapshot_file")"
printf 'soak qualification: snapshots=%s max_rss_kb=%s max_goroutines=%s max_heap_bytes=%s\n' "$(wc -l <"$snapshot_file")" "$max_rss" "$max_goroutines" "$max_heap"
"${compose[@]}" stop primary >/dev/null
"${compose[@]}" exec -T replica gosu postgres pg_ctl promote -D /var/lib/postgresql/data >/dev/null
for _ in $(seq 1 60); do
	if "${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc 'SELECT pg_is_in_recovery()' 2>/dev/null | rg -qx f; then break; fi
	sleep 1
done
"${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc 'SELECT pg_is_in_recovery()' | rg -qx f
"${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc 'SELECT singleton FROM gripline_policy_manifest WHERE singleton=TRUE' | rg -qx t
echo "soak qualification: ${duration_text} self-contained cluster soak, invariant monitoring, outage recovery, and post-soak promotion passed"
