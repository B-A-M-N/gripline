#!/usr/bin/env bash
set -euo pipefail

# Self-contained active/active soak: local HA PostgreSQL, three compiled
# Gripline nodes, a process-level load balancer, continuous replica/state
# checks, and a promotion after the load phase.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$repo_dir/scripts/qualification/fixtures/postgres-ha"
source "$fixture_dir/ports.sh"
project="gripline-soak-${$}"
work_dir="$(mktemp -d)"
monitor_pid=""
harness_pid=""
writer_pid=""
harness_artifact="$work_dir/harness.env"
snapshot_file="$work_dir/soak.tsv"
relation_file="$work_dir/relations.tsv"
maintenance_file="$work_dir/maintenance.tsv"
maintenance_metrics_file="$work_dir/maintenance-metrics.tsv"
row_file="$work_dir/rows.tsv"
maintenance_bin="$work_dir/maintenance"
external_maintenance_interval="${GRIPLINE_SOAK_EXTERNAL_MAINTENANCE_INTERVAL:-60}"
duration_text="5m"
workers="${GRIPLINE_CLUSTER_SOAK_WORKERS:-24}"
load_mode="${GRIPLINE_CLUSTER_SOAK_LOAD_MODE:-security}"
handoff_timeout="${GRIPLINE_SOAK_HANDOFF_TIMEOUT:-600}"
while [[ $# -gt 0 ]]; do
	case "$1" in
		--duration) duration_text=${2:?--duration requires a value}; shift 2 ;;
		--workers) workers=${2:?--workers requires a value}; shift 2 ;;
		--load-mode) load_mode=${2:?--load-mode requires a value}; shift 2 ;;
		-h|--help) echo 'usage: soak.sh [--duration 24h|72h|300s] [--workers N] [--load-mode security|capacity]'; exit 0 ;;
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
[[ "$load_mode" == security || "$load_mode" == capacity ]] || { echo "soak qualification: load mode must be security or capacity" >&2; exit 2; }
[[ "$external_maintenance_interval" =~ ^[1-9][0-9]*$ ]] || { echo "soak qualification: external maintenance interval must be positive" >&2; exit 2; }
[[ "$handoff_timeout" =~ ^[1-9][0-9]*$ ]] || { echo "soak qualification: handoff timeout must be positive" >&2; exit 2; }
cleanup() {
	if [[ -n "$harness_pid" ]]; then kill -TERM "$harness_pid" >/dev/null 2>&1 || true; wait "$harness_pid" >/dev/null 2>&1 || true; fi
	if [[ -n "$monitor_pid" ]]; then kill "$monitor_pid" >/dev/null 2>&1 || true; wait "$monitor_pid" >/dev/null 2>&1 || true; fi
	if [[ -n "$writer_pid" ]]; then kill "$writer_pid" >/dev/null 2>&1 || true; wait "$writer_pid" >/dev/null 2>&1 || true; fi
	docker compose -p "$project" -f "$fixture_dir/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
	if [[ "${GRIPLINE_QUALIFICATION_KEEP:-0}" == "1" ]]; then
		echo "soak qualification diagnostics retained: $work_dir" >&2
	else
		rm -rf "$work_dir"
	fi
}
trap cleanup EXIT
command -v docker >/dev/null || { echo "soak qualification: docker is required" >&2; exit 2; }
docker compose version >/dev/null || { echo "soak qualification: docker compose is required" >&2; exit 2; }
command -v go >/dev/null || { echo "soak qualification: go is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "soak qualification: curl is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "soak qualification: python3 is required" >&2; exit 2; }
configure_ha_ports
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$maintenance_bin" ./cmd/gripline-test-pg-maintenance
writer_bin="$work_dir/pg-writer"
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$writer_bin" ./cmd/gripline-test-pg-writer
compose=(docker compose -p "$project" -f "$fixture_dir/compose.yaml")
"${compose[@]}" up -d >/dev/null
[[ "$GRIPLINE_HA_PRIMARY_PORT" =~ ^[0-9]+$ && "$GRIPLINE_HA_REPLICA_PORT" =~ ^[0-9]+$ ]] || {
	echo "soak qualification: compose did not publish numeric PostgreSQL ports" >&2
	exit 1
}
for _ in $(seq 1 90); do
	if "${compose[@]}" exec -T primary pg_isready -U gripline -d gripline >/dev/null 2>&1 && "${compose[@]}" exec -T replica pg_isready -U gripline -d gripline >/dev/null 2>&1; then break; fi
	sleep 1
done
monitor_failure="$work_dir/monitor.failure"
promotion_file="$work_dir/promotion.expected"
pause_file="$work_dir/harness.pause"
release_file="$work_dir/harness.release"
writer_port=$((25434 + ($$ % 100)))
dsn="postgres://gripline:gripline@127.0.0.1:${writer_port}/gripline?sslmode=disable"
"$writer_bin" -listen "127.0.0.1:${writer_port}" \
	-backend-dsn "postgres://gripline:gripline@127.0.0.1:${GRIPLINE_HA_PRIMARY_PORT:-25432}/gripline?sslmode=disable" \
	-backend-dsn "postgres://gripline:gripline@127.0.0.1:${GRIPLINE_HA_REPLICA_PORT:-25433}/gripline?sslmode=disable" \
	>"$work_dir/pg-writer.log" 2>&1 &
writer_pid=$!
table_counts() {
	"${compose[@]}" exec -T primary psql -U gripline -d gripline -X -Atqc "
		SELECT 'gripline_credentials=' || count(*) FROM gripline_credentials
		UNION ALL SELECT 'gripline_security_transitions=' || count(*) FROM gripline_security_transitions
		UNION ALL SELECT 'gripline_lanes=' || count(*) FROM gripline_lanes
		UNION ALL SELECT 'gripline_lane_operator_audit=' || count(*) FROM gripline_lane_operator_audit
		UNION ALL SELECT 'gripline_operator_audit=' || count(*) FROM gripline_operator_audit
		UNION ALL SELECT 'gripline_control_operations=' || count(*) FROM gripline_control_operations
		UNION ALL SELECT 'gripline_admission_audit=' || count(*) FROM gripline_admission_audit
		UNION ALL SELECT 'gripline_policy_artifacts=' || count(*) FROM gripline_policy_artifacts
		UNION ALL SELECT 'gripline_policy_audit=' || count(*) FROM gripline_policy_audit
		UNION ALL SELECT 'gripline_adaptive_state=' || count(*) FROM gripline_adaptive_state
		UNION ALL SELECT 'gripline_adaptive_window_subjects=' || count(*) FROM gripline_adaptive_window_subjects
		UNION ALL SELECT 'gripline_adaptive_window_keys=' || count(*) FROM gripline_adaptive_window_keys
		UNION ALL SELECT 'gripline_adaptive_baselines=' || count(*) FROM gripline_adaptive_baselines
		UNION ALL SELECT 'gripline_resource_buckets=' || count(*) FROM gripline_resource_buckets
		UNION ALL SELECT 'gripline_resource_source_scopes=' || count(*) FROM gripline_resource_source_scopes
		UNION ALL SELECT 'gripline_resource_leases=' || count(*) FROM gripline_resource_leases
		UNION ALL SELECT 'gripline_resource_holds=' || count(*) FROM gripline_resource_holds
		UNION ALL SELECT 'gripline_credential_receipts=' || count(*) FROM gripline_credential_receipts
		UNION ALL SELECT 'gripline_membership=' || count(*) FROM gripline_membership
		UNION ALL SELECT 'gripline_cluster_crypto_generations=' || count(*) FROM gripline_cluster_crypto_generations
		UNION ALL SELECT 'gripline_cluster_crypto_acks=' || count(*) FROM gripline_cluster_crypto_acks
		UNION ALL SELECT 'gripline_policy_node_state=' || count(*) FROM gripline_policy_node_state
		UNION ALL SELECT 'gripline_evidence=' || count(*) FROM gripline_evidence
		UNION ALL SELECT 'gripline_evidence_guards=' || count(*) FROM gripline_evidence_guards" | tr '\n' ';'
}
monitor() {
	last_maintenance=0
	while [[ -z "$harness_pid" ]] || kill -0 "$harness_pid" >/dev/null 2>&1; do
		if [[ ! -f "$promotion_file" ]] && ! "${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc 'SELECT pg_is_in_recovery()' 2>/dev/null | rg -qx t; then echo replica-not-in-recovery >"$monitor_failure"; return 1; fi
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
				maintenance_runs="$(metric postgres_maintenance_runs_total)"
				maintenance_deleted="$(metric postgres_maintenance_rows_deleted_total)"
				maintenance_backlog="$(metric postgres_maintenance_backlog_estimate)"
				maintenance_duration="$(metric postgres_maintenance_last_duration_seconds)"
				maintenance_errors="$(metric postgres_maintenance_errors_total)"
				rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status")"
				if [[ ! "$goroutines" =~ ^[0-9]+$ || ! "$heap" =~ ^[0-9]+$ || ! "$scopes" =~ ^[0-9]+$ || ! "$active" =~ ^[0-9]+$ || ! "$rss" =~ ^[0-9]+$ ]]; then
					continue
				fi
				maintenance_runs="${maintenance_runs:-0}"
				maintenance_deleted="${maintenance_deleted:-0}"
				maintenance_backlog="${maintenance_backlog:-0}"
				maintenance_duration="${maintenance_duration:-0}"
				maintenance_errors="${maintenance_errors:-0}"
				if (( scopes > 4096 || active > 5 )); then echo "resource-bounds-${node}" >"$monitor_failure"; return 1; fi
				printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$node" "$rss" "$goroutines" "$heap" "$scopes" "$active" >>"$snapshot_file"
				printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "$node" "$maintenance_runs" "$maintenance_deleted" "$maintenance_backlog" "$maintenance_duration" "$maintenance_errors" >>"$maintenance_metrics_file"
			done
			retention="$("${compose[@]}" exec -T primary psql -U gripline -d gripline -X -Atqc "SELECT (SELECT count(*) FROM gripline_resource_leases WHERE state IN ('reserved','forwarded')) || '|' || (SELECT count(*) FROM gripline_resource_holds h JOIN gripline_resource_leases l ON l.lease_id=h.lease_id WHERE l.state IN ('reserved','forwarded')) || '|' || (SELECT count(*) FROM gripline_evidence)" 2>/dev/null || true)"
			if [[ "$retention" =~ ^([0-9]+)\|([0-9]+)\|([0-9]+)$ ]]; then
				if (( BASH_REMATCH[1] > 5 || BASH_REMATCH[2] > 64 || BASH_REMATCH[3] > 100000 )); then echo "retention-bounds" >"$monitor_failure"; return 1; fi
			fi
			now="$(date +%s)"
			rows="$(table_counts 2>/dev/null || true)"
			[[ -n "$rows" ]] && printf '%s\t%s\n' "$now" "$rows" >>"$row_file"
			if (( now >= last_maintenance + external_maintenance_interval )) && [[ ! -f "$promotion_file" ]]; then
				before="$rows"
				maintenance_start="$now"
				maintenance_json="$($maintenance_bin -dsn "$dsn" -batch-size 256 -history-retention "${GRIPLINE_SOAK_RETENTION_WINDOW:-1m}" 2>/dev/null)" || { echo maintenance-failed >"$monitor_failure"; return 1; }
				"${compose[@]}" exec -T primary psql -U gripline -d gripline -X -v ON_ERROR_STOP=1 -c 'VACUUM (ANALYZE)' >/dev/null 2>&1 || { echo vacuum-failed >"$monitor_failure"; return 1; }
				after="$(table_counts 2>/dev/null || true)"
				printf '%s\t%s\t%s\t%s\t%s\n' "$now" "$(( $(date +%s) - maintenance_start ))" "$before" "$after" "$maintenance_json" >>"$maintenance_file"
				last_maintenance=$now
			fi
			relation_bytes="$("${compose[@]}" exec -T primary psql -U gripline -d gripline -X -Atqc "SELECT COALESCE(SUM(pg_total_relation_size(relid)),0) FROM pg_stat_user_tables WHERE relname LIKE 'gripline_%'" 2>/dev/null || true)"
			if [[ "$relation_bytes" =~ ^[0-9]+$ ]]; then
				printf '%s\t%s\n' "$now" "$relation_bytes" >>"$relation_file"
				if (( relation_bytes > ${GRIPLINE_SOAK_MAX_TERMINAL_BYTES:-67108864} )); then echo terminal-relation-size >"$monitor_failure"; return 1; fi
			fi
		fi
		sleep 5
	done
}
wait_replica_caught_up() {
	local primary_lsn=""
	for _ in $(seq 1 "${GRIPLINE_SOAK_REPLICATION_WAIT_ATTEMPTS:-120}"); do
		primary_lsn="$("${compose[@]}" exec -T primary psql -U gripline -d gripline -X -Atqc 'SELECT pg_current_wal_flush_lsn()' 2>/dev/null || true)"
		if [[ "$primary_lsn" =~ ^[0-9A-Fa-f]+/[0-9A-Fa-f]+$ ]] &&
			"${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc "SELECT pg_last_wal_replay_lsn() >= '${primary_lsn}'::pg_lsn" 2>/dev/null | rg -qx t; then
			return 0
		fi
		sleep 0.5
	done
	echo "soak qualification: replica did not catch up to primary WAL position ${primary_lsn}" >&2
	return 1
}
monitor &
monitor_pid=$!
GRIPLINE_LOG_READINESS_FAILURES=1 GRIPLINE_CLUSTER_HARNESS_COMPRESSED_RETENTION=1 GRIPLINE_CLUSTER_HARNESS_RETENTION_WINDOW="${GRIPLINE_SOAK_RETENTION_WINDOW:-1m}" GRIPLINE_CLUSTER_HARNESS_ARTIFACT_FILE="$harness_artifact" GRIPLINE_CLUSTER_HARNESS_PAUSE_FILE="$pause_file" GRIPLINE_CLUSTER_HARNESS_RELEASE_FILE="$release_file" GRIPLINE_CLUSTER_WRITER_LOG="$work_dir/pg-writer.log" GRIPLINE_CLUSTER_HARNESS_KEEP="${GRIPLINE_QUALIFICATION_KEEP:-0}" GRIPLINE_TEST_POSTGRES_DSN="$dsn" GRIPLINE_TEST_POSTGRES_CONTAINER="${project}-primary-1" GRIPLINE_CLUSTER_HARNESS_REQUIRE_DB_OUTAGE=1 GRIPLINE_CLUSTER_HARNESS_LOAD_MODE="$load_mode" GRIPLINE_CLUSTER_HARNESS_LOAD_SECONDS="$duration" GRIPLINE_CLUSTER_HARNESS_LOAD_WORKERS="$workers" bash "$repo_dir/scripts/cluster-harness.sh" >"$work_dir/harness.log" 2>&1 &
harness_pid=$!
for _ in $(seq 1 120); do
	if [[ -s "$harness_artifact" ]]; then break; fi
	if ! kill -0 "$harness_pid" >/dev/null 2>&1; then cat "$work_dir/harness.log" >&2; exit 1; fi
	sleep 0.25
done
[[ -s "$harness_artifact" ]] || { echo "soak qualification: cluster harness did not publish its runtime fixture" >&2; cat "$work_dir/harness.log" >&2; exit 1; }

for _ in $(seq 1 $((handoff_timeout * 4))); do
	[[ -f "$pause_file" ]] && break
	if ! kill -0 "$harness_pid" >/dev/null 2>&1; then cat "$work_dir/harness.log" >&2; exit 1; fi
	sleep 0.25
done
[[ -f "$pause_file" ]] || { echo "soak qualification: live cluster did not reach failover handoff" >&2; exit 1; }
if [[ -f "$monitor_failure" ]]; then echo "soak qualification: invariant monitor failed: $(<"$monitor_failure")" >&2; exit 1; fi
[[ -s "$snapshot_file" ]] || { echo "soak qualification: no process/resource snapshots captured" >&2; exit 1; }
for node in a b c; do
	[[ "$(awk -F '\t' -v want="$node" '$2 == want {n++} END {print n+0}' "$snapshot_file")" -gt 0 ]] || { echo "soak qualification: no complete runtime snapshot for node $node" >&2; exit 1; }
done
max_rss="$(awk -F '\t' 'BEGIN {m=0} {if ($3 > m) m=$3} END {print m+0}' "$snapshot_file")"
max_goroutines="$(awk -F '\t' 'BEGIN {m=0} {if ($4 > m) m=$4} END {print m+0}' "$snapshot_file")"
max_heap="$(awk -F '\t' 'BEGIN {m=0} {if ($5 > m) m=$5} END {print m+0}' "$snapshot_file")"
printf 'soak qualification: snapshots=%s max_rss_kb=%s max_goroutines=%s max_heap_bytes=%s\n' "$(wc -l <"$snapshot_file")" "$max_rss" "$max_goroutines" "$max_heap"
if (( duration >= 120 )) && [[ ! -s "$maintenance_file" ]]; then
	echo "soak qualification: long soak did not execute scheduled maintenance" >&2
	exit 1
fi
maintenance_metric_samples="$(wc -l <"$maintenance_metrics_file" 2>/dev/null || echo 0)"
maintenance_max_deleted="$(awk -F '\t' 'BEGIN {m=0} {if ($4+0 > m) m=$4+0} END {print m+0}' "$maintenance_metrics_file" 2>/dev/null || echo 0)"
external_maintenance_samples="$(wc -l <"$maintenance_file" 2>/dev/null || echo 0)"
external_maintenance_max_deleted="$(rg -o '"RowsDeleted":[0-9]+' "$maintenance_file" 2>/dev/null | awk -F: 'BEGIN {m=0} {if ($2+0 > m) m=$2+0} END {print m+0}' || echo 0)"
if (( external_maintenance_max_deleted > maintenance_max_deleted )); then maintenance_max_deleted=$external_maintenance_max_deleted; fi
maintenance_max_errors="$(awk -F '\t' 'BEGIN {m=0} {if ($7+0 > m) m=$7+0} END {print m+0}' "$maintenance_metrics_file" 2>/dev/null || echo 0)"
if (( duration >= 120 )); then
	if (( maintenance_metric_samples + external_maintenance_samples < 1 )); then
		echo "soak qualification: compressed-retention maintenance emitted no metrics" >&2
		exit 1
	fi
	if (( maintenance_max_deleted < 1 )); then
		echo "soak qualification: compressed-retention fixture deleted no expired rows" >&2
		exit 1
	fi
	if (( maintenance_max_errors > 0 )); then
		echo "soak qualification: maintenance reported ${maintenance_max_errors} errors" >&2
		exit 1
	fi
fi
for node in a b c; do
	read -r rss_start rss_end <<<"$(awk -F '\t' -v want="$node" '$2 == want {if (!first) first=$3; last=$3} END {print first+0, last+0}' "$snapshot_file")"
	if (( rss_end > rss_start + ${GRIPLINE_SOAK_MAX_RSS_GROWTH_KB:-131072} )); then
		echo "soak qualification: RSS trend grew beyond bound for node $node" >&2
		exit 1
	fi
done
base="$(awk -F= '$1 == "base" {print $2}' "$harness_artifact")"
request_secret="$(awk -F= '$1 == "request_secret" {print $2}' "$harness_artifact")"
wait_replica_caught_up
promotion_started_ms="$(date +%s%3N)"
touch "$promotion_file"
"${compose[@]}" stop primary >/dev/null
"${compose[@]}" exec -T replica gosu postgres pg_ctl promote -D /var/lib/postgresql/data >/dev/null
for _ in $(seq 1 60); do
	if "${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc 'SELECT pg_is_in_recovery()' 2>/dev/null | rg -qx f; then break; fi
	sleep 1
done
"${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc 'SELECT pg_is_in_recovery()' | rg -qx f
"${compose[@]}" exec -T replica psql -U gripline -d gripline -X -Atqc 'SELECT singleton FROM gripline_policy_manifest WHERE singleton=TRUE' | rg -qx t
for port in $((base + 10)) $((base + 11)); do
	ready_response="$work_dir/post-promotion-ready-${port}.json"
	ready_status=000
	for _ in $(seq 1 90); do
		ready_status="$(curl -sS -o "$ready_response" -w '%{http_code}' "http://127.0.0.1:${port}/readyz" 2>/dev/null || true)"
		if [[ "$ready_status" == 200 ]]; then break; fi
		sleep 1
	done
	if [[ "$ready_status" != 200 ]]; then
		echo "soak qualification: post-promotion readiness failed on port ${port} (status ${ready_status})" >&2
		cat "$ready_response" >&2 || true
		cat "$work_dir/pg-writer.log" >&2 || true
		exit 1
	fi
	data_response="$work_dir/post-promotion-${port}.json"
	data_status=000
	for _ in $(seq 1 90); do
		data_status="$(curl -sS -o "$data_response" -w '%{http_code}' -X POST "http://127.0.0.1:${port}/v1/messages" -H "Authorization: Bearer ${request_secret}" -d '{}' 2>/dev/null || true)"
		if [[ "$data_status" == 200 ]]; then break; fi
		sleep 1
	done
	if [[ "$data_status" != 200 ]]; then
		echo "soak qualification: post-promotion data request failed on port ${port} (status ${data_status})" >&2
		cat "$data_response" >&2 || true
		cat "$work_dir/pg-writer.log" >&2 || true
		exit 1
	fi
done
promotion_recovery_ms="$(( $(date +%s%3N) - promotion_started_ms ))"
touch "$release_file"
if ! wait "$harness_pid"; then cat "$work_dir/harness.log" >&2; exit 1; fi
harness_pid=""
kill "$monitor_pid" >/dev/null 2>&1 || true
wait "$monitor_pid" >/dev/null 2>&1 || true
monitor_pid=""
if [[ -n "${GRIPLINE_SOAK_EVIDENCE_FILE:-}" ]]; then
	relation_max="$(awk '{if ($2 > m) m=$2} END {print m+0}' "$relation_file" 2>/dev/null || true)"
	retention_first="$(awk -F '\t' 'NR == 1 {print $2; exit}' "$row_file" 2>/dev/null || true)"
	retention_final="$(awk -F '\t' 'END {print $2}' "$row_file" 2>/dev/null || true)"
	maintenance_max_duration="$(awk -F '\t' 'BEGIN {m=0} {if ($6+0 > m) m=$6+0} END {printf "%.6f", m+0}' "$maintenance_metrics_file" 2>/dev/null || echo 0)"
	maintenance_p95_duration="$(awk -F '\t' '{print $6+0}' "$maintenance_metrics_file" 2>/dev/null | sort -n | awk -v n="$(wc -l <"$maintenance_metrics_file" 2>/dev/null || echo 0)" 'NR == int((n * 95 + 99) / 100) {printf "%.6f", $1; exit}')"
	retention_first="${retention_first//\"/}"
	retention_final="${retention_final//\"/}"
	cat >"$GRIPLINE_SOAK_EVIDENCE_FILE" <<EOF
{
  "qualification": "reference-production-soak",
  "status": "passed",
  "commit": "$(git rev-parse HEAD)",
  "duration_seconds": ${duration},
	"workers": ${workers},
	"load_mode": "${load_mode}",
  "snapshots": $(wc -l <"$snapshot_file"),
  "max_rss_kb": ${max_rss},
	"max_goroutines": ${max_goroutines},
	"max_heap_bytes": ${max_heap},
	"maintenance_samples": $((maintenance_metric_samples + external_maintenance_samples)),
	"maintenance_rows_deleted_max": ${maintenance_max_deleted},
	"maintenance_max_duration_seconds": ${maintenance_max_duration:-0},
	"maintenance_p95_duration_seconds": ${maintenance_p95_duration:-0},
	"maintenance_errors_max": ${maintenance_max_errors},
	"retention_row_samples": $(wc -l <"$row_file" 2>/dev/null || echo 0),
	"retention_rows_first": "${retention_first}",
	"retention_rows_final": "${retention_final}",
		"maintenance_failures": 0,
	  "max_terminal_relation_bytes": ${relation_max:-0},
	  "post_promotion_recovery_ms": ${promotion_recovery_ms},
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
fi
echo "soak qualification: ${duration_text} self-contained cluster soak, invariant monitoring, outage recovery, live-node promotion traffic, and post-soak promotion passed"
