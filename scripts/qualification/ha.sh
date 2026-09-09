#!/usr/bin/env bash
set -euo pipefail

# Repository-owned PostgreSQL streaming-replication qualification. This is a
# reference lab: the replica is built with pg_basebackup, the primary is
# stopped, the replica is promoted, and the failed node is re-seeded as a
# standby from the promoted authority.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$repo_dir/scripts/qualification/fixtures/postgres-ha"
source "$fixture_dir/ports.sh"
project="gripline-ha-${$}"
work_dir="$(mktemp -d)"
live_pids=()
keep="${GRIPLINE_QUALIFICATION_KEEP:-0}"
phase="fixture-start"
compose=()
diagnose_failure() {
	local rc=$?
	if (( rc != 0 )); then
		echo "HA lab failure: phase=${phase} rc=${rc}" >&2
		"${compose[@]}" ps >&2 2>/dev/null || true
		"${compose[@]}" logs --no-color --tail=120 >&2 2>/dev/null || true
		if [[ -f "$work_dir/live-gripline.log" ]]; then
			echo "HA lab live Gripline log:" >&2
			tail -120 "$work_dir/live-gripline.log" >&2 || true
		fi
		if [[ "$keep" == 1 ]]; then
			echo "HA lab diagnostics retained: $work_dir" >&2
		fi
	fi
}
cleanup() {
	for pid in "${live_pids[@]}"; do kill -TERM "$pid" >/dev/null 2>&1 || true; done
	for pid in "${live_pids[@]}"; do wait "$pid" >/dev/null 2>&1 || true; done
	if [[ "$keep" == 1 ]]; then
		echo "HA lab retained: docker compose -p $project -f $fixture_dir/compose.yaml" >&2
		echo "HA lab diagnostics retained: $work_dir" >&2
	else
		docker compose -p "$project" -f "$fixture_dir/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
		rm -rf "$work_dir"
	fi
}
trap diagnose_failure ERR
trap cleanup EXIT

command -v docker >/dev/null || { echo "ha qualification: docker is required" >&2; exit 2; }
docker compose version >/dev/null || { echo "ha qualification: docker compose is required" >&2; exit 2; }
command -v go >/dev/null || { echo "ha qualification: go is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "ha qualification: openssl is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "ha qualification: python3 is required" >&2; exit 2; }
configure_ha_ports

compose=(docker compose -p "$project" -f "$fixture_dir/compose.yaml")

"${compose[@]}" up -d
[[ "$GRIPLINE_HA_PRIMARY_PORT" =~ ^[0-9]+$ && "$GRIPLINE_HA_REPLICA_PORT" =~ ^[0-9]+$ ]] || {
	echo "ha qualification: compose did not publish numeric PostgreSQL ports" >&2
	exit 1
}
phase="replica-catchup"
for _ in $(seq 1 90); do
	if "${compose[@]}" exec -T primary pg_isready -U gripline -d gripline >/dev/null 2>&1 && \
		"${compose[@]}" exec -T replica pg_isready -U gripline -d gripline >/dev/null 2>&1; then
		break
	fi
	sleep 2
done
"${compose[@]}" exec -T primary pg_isready -U gripline -d gripline >/dev/null
"${compose[@]}" exec -T replica pg_isready -U gripline -d gripline >/dev/null

dsn="postgres://gripline:gripline@127.0.0.1:${GRIPLINE_HA_PRIMARY_PORT:-25432}/gripline?sslmode=disable"
pepper_one="$(openssl rand -base64 32 | tr -d '\n')"
pepper_two="$(openssl rand -base64 32 | tr -d '\n')"
pseudonym_one="$(openssl rand -base64 32 | tr -d '\n')"
pseudonym_two="$(openssl rand -base64 32 | tr -d '\n')"
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go run ./cmd/gripline-test-cluster-setup \
	-reset-dsn "$dsn" \
	-keyring "$work_dir/keyring.json" \
	-policy "$work_dir/policy.json" \
	-verifier "$work_dir/verifier.key" \
	-seed-reference-state \
	-pepper-one "$pepper_one" -pepper-two "$pepper_two" \
	-pseudonym-one "$pseudonym_one" -pseudonym-two "$pseudonym_two"

sql() {
	local service=$1 query=$2
	"${compose[@]}" exec -T "$service" psql -U gripline -d gripline -X -v ON_ERROR_STOP=1 -Atqc "$query"
}

[[ "$(sql primary 'SELECT pg_is_in_recovery()')" == f ]] || { echo "ha qualification: primary is not writable" >&2; exit 1; }
[[ "$(sql replica 'SELECT pg_is_in_recovery()')" == t ]] || { echo "ha qualification: replica is not in recovery" >&2; exit 1; }
for table in gripline_policy_manifest gripline_cluster_crypto gripline_credentials; do
	[[ "$(sql primary "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='${table}')")" == t ]] || {
		echo "ha qualification: missing security table $table" >&2
		exit 1
	}
done

for _ in $(seq 1 60); do
	if [[ "$(sql replica 'SELECT COUNT(*) FROM gripline_cluster_crypto' 2>/dev/null || true)" -ge 1 && "$(sql replica 'SELECT singleton FROM gripline_policy_manifest WHERE singleton=TRUE' 2>/dev/null || true)" == t ]]; then
		break
	fi
	sleep 1
done
[[ "$(sql replica 'SELECT COUNT(*) FROM gripline_cluster_crypto')" -ge 1 ]] || { echo "ha qualification: replica did not catch up security state" >&2; exit 1; }

state_fingerprint() {
	local service=$1
	sql "$service" "SELECT concat_ws('|',
		(SELECT manifest->'active'->>'id' FROM gripline_policy_manifest WHERE singleton=TRUE),
		(SELECT manifest->'active'->>'revision' FROM gripline_policy_manifest WHERE singleton=TRUE),
		(SELECT manifest->'active'->>'digest' FROM gripline_policy_manifest WHERE singleton=TRUE),
		(SELECT manifest->>'activation_epoch' FROM gripline_policy_manifest WHERE singleton=TRUE),
		(SELECT signer_active_kid || ':' || signer_fingerprint || ':' || pepper_active_version || ':' || pepper_fingerprint || ':' || pseudonym_version || ':' || pseudonym_fingerprint || ':' || generation_epoch FROM gripline_cluster_crypto WHERE singleton=TRUE),
		(SELECT count(*) FROM gripline_credentials WHERE status=0),
		(SELECT count(*) FROM gripline_credentials WHERE status=4),
		(SELECT count(*) FROM gripline_lanes WHERE credential_id='qualification-active'),
		(SELECT count(*) FROM gripline_evidence WHERE subject_id='qualification-active'),
		(SELECT count(*) FROM gripline_control_operations WHERE operation_id='qualification-seed-operation'),
		(SELECT count(*) FROM gripline_credential_receipts WHERE request_id='qualification-seed-request'),
		(SELECT count(*) FROM gripline_resource_leases WHERE lease_id='qualification-seed-lease' AND state='reserved'),
		(SELECT count(*) FROM gripline_resource_holds WHERE lease_id='qualification-seed-lease'),
		(SELECT concurrency_used FROM gripline_resource_buckets WHERE scope=2 AND scope_id='qualification-active' AND dimension=1),
		(SELECT count(*) FROM gripline_policy_artifacts WHERE policy_id='gripline-default-v1' AND revision=1),
		(SELECT count(*) FROM gripline_cluster_crypto_generations),
		(SELECT count(*) FROM gripline_operator_audit WHERE target='qualification-active'),
		(SELECT count(*) FROM gripline_admission_audit WHERE request_id='qualification-seed-request'))"
}

expected_state="$(state_fingerprint primary)"
[[ "$expected_state" == *"|1|1|1|1|1|1|1|1|1|1|5|1|1"* ]] || {
	echo "ha qualification: reference state seed is incomplete: $expected_state" >&2
	exit 1
}
[[ "$(sql primary 'SELECT posture FROM gripline_operator_posture WHERE singleton=TRUE')" == 0 ]] || {
	echo "ha qualification: reference state seed has non-clear operator posture" >&2
	exit 1
}
for _ in $(seq 1 60); do
	if [[ "$(state_fingerprint replica 2>/dev/null || true)" == "$expected_state" ]]; then
		break
	fi
	sleep 1
done
[[ "$(state_fingerprint replica)" == "$expected_state" ]] || {
	echo "ha qualification: replica did not preserve complete reference state" >&2
	exit 1
}

phase="live-build"
# Start a real Gripline node against a repository-owned writer endpoint. The
# writer endpoint probes both PostgreSQL instances and only routes to the
# non-recovery authority, so the server process survives a primary kill while
# its shared-authority connection is re-established through the same address.
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/gripline" ./cmd/gripline
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/pg-writer" ./cmd/gripline-test-pg-writer
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/backend" ./cmd/gripline-test-backend
phase="live-start"
writer_port="${GRIPLINE_HA_WRITER_PORT:-$(pick_free_port 26434 27434)}"
export GRIPLINE_HA_WRITER_PORT="$writer_port"
live_port="$(pick_free_port 25600 25700)"
live_backend_port="$(pick_free_port 25700 25800)"
live_admin_port="$(pick_free_port 25800 25900)"
live_secret="ha-live-qualification-secret-0123456789abcdef"
live_operator="ha-live-qualification-operator-0123456789abcdef"
live_config="$work_dir/live-config.json"
writer_dsn="postgres://gripline:gripline@127.0.0.1:${writer_port}/gripline?sslmode=disable"
cat >"$live_config" <<EOF
{
  "listen": "127.0.0.1:${live_port}",
  "tls": {"terminate_tls_upstream": true},
  "backend": {"url": "http://127.0.0.1:${live_backend_port}", "trust_mode": "private_network", "timeout": "5s", "allowed_endpoints": [{"method":"POST","path":"/v1/messages"}]},
  "server": {"read_timeout":"10s","write_timeout":"10s","idle_timeout":"10s","read_header_timeout":"5s"},
  "identity": {"audience":"ha-live-qualification"},
  "secrets": {"pepper_versions":{"1":"${pepper_one}","2":"${pepper_two}"}},
  "ingress": {"pseudonym_keys":{"1":"${pseudonym_one}","2":"${pseudonym_two}"}},
  "admin": {"listen":"127.0.0.1:${live_admin_port}","operator_tokens":{"${live_operator}":"harness:credential.lifecycle,posture.control,crypto.lifecycle,cluster.read,audit.read"}},
  "paths": {"signer_keyring":"${work_dir}/keyring.json"},
  "policy": {"file":"${work_dir}/policy.json","verifier_key_file":"${work_dir}/verifier.key"},
  "authority": {"backend":"postgres","dsn_env":"GRIPLINE_HA_WRITER_DSN","node_id":"ha-live-node","lease_ttl":"5s","renew_every":"1s","connect_timeout":"3s","operation_timeout":"1s","max_conns":4,"min_conns":1},
  "deployment": {"allow_ephemeral_state":false}
}
EOF
"$work_dir/pg-writer" -listen "127.0.0.1:${writer_port}" \
	-backend-dsn "postgres://gripline:gripline@127.0.0.1:${GRIPLINE_HA_PRIMARY_PORT:-25432}/gripline?sslmode=disable" \
	-backend-dsn "postgres://gripline:gripline@127.0.0.1:${GRIPLINE_HA_REPLICA_PORT:-25433}/gripline?sslmode=disable" \
	>"$work_dir/pg-writer.log" 2>&1 & live_pids+=("$!")
GRIPLINE_HA_WRITER_DSN="$writer_dsn" "$work_dir/gripline" keys export --config "$live_config" >"$work_dir/live-keys.json"
"$work_dir/backend" -listen "127.0.0.1:${live_backend_port}" -keys "$work_dir/live-keys.json" -audience ha-live-qualification >"$work_dir/live-backend.log" 2>&1 & live_pids+=("$!")
GRIPLINE_HA_WRITER_DSN="$writer_dsn" "$work_dir/gripline" -config "$live_config" >"$work_dir/live-gripline.log" 2>&1 & live_pids+=("$!")
for _ in $(seq 1 60); do
	if curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${live_port}/readyz" 2>/dev/null | rg -qx 200; then break; fi
	sleep 0.25
done
curl -fsS "http://127.0.0.1:${live_port}/readyz" >/dev/null
printf '%s\n' "$live_secret" | GRIPLINE_OPERATOR_TOKEN="$live_operator" "$work_dir/gripline" credential add --config "$live_config" --id ha-live-credential --account ha-live --policy gripline-default-v1 --plan ha-live --reason "HA reference qualification" --operation-id "ha-live-credential-add-${$}" --secret-stdin >/dev/null
curl -fsS -X POST "http://127.0.0.1:${live_port}/v1/messages" -H "Authorization: Bearer ${live_secret}" -H 'Content-Type: application/json' --data '{}' >/dev/null
live_expected_state="$(state_fingerprint primary)"
for _ in $(seq 1 60); do
	if [[ "$(state_fingerprint replica 2>/dev/null || true)" == "$live_expected_state" ]]; then break; fi
	sleep 1
done
[[ "$(state_fingerprint replica)" == "$live_expected_state" ]] || {
	echo "ha qualification: live Gripline state did not replicate before failover" >&2
	exit 1
}

echo "ha qualification: stopping primary and promoting replica"
	phase="failover"
ambiguous_operation="ha-unknown-commit-${$}"
ambiguous_reason="HA unknown-commit posture mutation"
ambiguous_url="http://127.0.0.1:${live_admin_port}/admin/posture"
curl -sS --max-time 3 -o "$work_dir/ambiguous-first.json" -X POST "$ambiguous_url" \
	-H "Authorization: Bearer ${live_operator}" -H "Idempotency-Key: ${ambiguous_operation}" \
	-H 'Content-Type: application/json' --data "{\"on\":true,\"reason\":\"${ambiguous_reason}\"}" & ambiguous_pid=$!
sleep 0.02
"${compose[@]}" stop primary >/dev/null
"${compose[@]}" exec -T replica gosu postgres pg_ctl promote -D /var/lib/postgresql/data >/dev/null
for _ in $(seq 1 60); do
	if [[ "$(sql replica 'SELECT pg_is_in_recovery()' 2>/dev/null || true)" == f ]]; then
		break
	fi
	sleep 1
done
[[ "$(sql replica 'SELECT pg_is_in_recovery()')" == f ]] || { echo "ha qualification: replica did not promote" >&2; exit 1; }
[[ "$(state_fingerprint replica)" == "$live_expected_state" ]] || {
	echo "ha qualification: promoted authority lost reference security state" >&2
	exit 1
}
wait "$ambiguous_pid" >/dev/null 2>&1 || true
ambiguous_status=000
for _ in $(seq 1 90); do
	ambiguous_status="$(curl -sS --max-time 3 -o "$work_dir/ambiguous-retry.json" -w '%{http_code}' -X POST "$ambiguous_url" \
		-H "Authorization: Bearer ${live_operator}" -H "Idempotency-Key: ${ambiguous_operation}" \
		-H 'Content-Type: application/json' --data "{\"on\":true,\"reason\":\"${ambiguous_reason}\"}" 2>/dev/null || true)"
	if [[ "$ambiguous_status" == 200 ]]; then break; fi
	sleep 1
done
[[ "$ambiguous_status" == 200 ]] || { echo "ha qualification: idempotent retry after failover did not complete (status ${ambiguous_status})" >&2; exit 1; }
[[ "$(sql replica "SELECT COUNT(*) FROM gripline_control_operations WHERE operation_id='${ambiguous_operation}'")" == 1 ]] || {
	echo "ha qualification: unknown-commit retry created more than one operation receipt" >&2
	exit 1
}
curl -fsS --max-time 3 -X POST "$ambiguous_url" \
	-H "Authorization: Bearer ${live_operator}" -H "Idempotency-Key: ha-unknown-commit-clear-${$}" \
	-H 'Content-Type: application/json' --data '{"on":false,"reason":"HA unknown-commit posture clear"}' >/dev/null
[[ "$(sql replica 'SELECT posture FROM gripline_operator_posture WHERE singleton=TRUE')" == 0 ]] || {
	echo "ha qualification: posture mutation did not converge after failover" >&2
	exit 1
}
final_expected_state="$(state_fingerprint replica)"
for _ in $(seq 1 90); do
	if curl -fsS "http://127.0.0.1:${live_port}/readyz" >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
kill -0 "${live_pids[2]}"
curl -fsS "http://127.0.0.1:${live_port}/readyz" >/dev/null
curl -fsS -X POST "http://127.0.0.1:${live_port}/v1/messages" -H "Authorization: Bearer ${live_secret}" -H 'Content-Type: application/json' --data '{}' >/dev/null
echo "ha qualification: live Gripline node recovered through stable writer endpoint"

# Rejoin the failed node from the promoted authority. pg_basebackup -R writes
# standby.signal and primary_conninfo, proving the node came back as a
# follower instead of silently forking a second authority.
phase="rejoin"
"${compose[@]}" run --rm --no-deps --entrypoint bash primary -ceu \
	'rm -rf -- /var/lib/postgresql/data/*; PGPASSWORD=gripline pg_basebackup -h replica -U replicator -D /var/lib/postgresql/data -Fp -Xs -P -R; chown -R postgres:postgres /var/lib/postgresql/data; chmod 0700 /var/lib/postgresql/data' \
	>/dev/null
"${compose[@]}" up -d primary >/dev/null
for _ in $(seq 1 60); do
	if [[ "$(sql primary 'SELECT pg_is_in_recovery()' 2>/dev/null || true)" == t ]]; then
		break
	fi
	sleep 1
done
[[ "$(sql primary 'SELECT pg_is_in_recovery()')" == t ]] || { echo "ha qualification: failed node did not rejoin as standby" >&2; exit 1; }
[[ "$(state_fingerprint primary)" == "$final_expected_state" ]] || {
	echo "ha qualification: rejoined standby lost complete reference state" >&2
	exit 1
}
echo "ha qualification: primary/replica promotion, security-state preservation, and rejoin passed"
