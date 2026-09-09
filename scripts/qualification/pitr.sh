#!/usr/bin/env bash
set -euo pipefail

# Repository-owned PITR exercise. The base backup is taken before a policy
# mutation, WAL is archived by the local PostgreSQL container, and a restore
# target before that mutation must recover the earlier policy/security state.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$repo_dir/scripts/qualification/fixtures/pitr"
source "$repo_dir/scripts/qualification/fixtures/postgres-ha/ports.sh"
project="gripline-pitr-${$}"
pitr_port="${GRIPLINE_PITR_PORT:-$(pick_free_port 26434 27434)}"
restore_port="${GRIPLINE_PITR_RESTORE_PORT:-$(pick_free_port "$((pitr_port + 1))" 27434)}"
export GRIPLINE_PITR_PORT="$pitr_port" GRIPLINE_PITR_RESTORE_PORT="$restore_port"
cleanup() {
	rm -rf "${work_dir:-}"
	docker compose -p "$project" -f "$fixture_dir/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "pitr qualification: docker is required" >&2; exit 2; }
docker compose version >/dev/null || { echo "pitr qualification: docker compose is required" >&2; exit 2; }
command -v go >/dev/null || { echo "pitr qualification: go is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "pitr qualification: curl is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "pitr qualification: openssl is required" >&2; exit 2; }
compose=(docker compose -p "$project" -f "$fixture_dir/compose.yaml")
work_dir="$(mktemp -d)"

"${compose[@]}" up -d db >/dev/null
for _ in $(seq 1 60); do
	if "${compose[@]}" exec -T db pg_isready -U gripline -d gripline >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
"${compose[@]}" exec -T db pg_isready -U gripline -d gripline >/dev/null
"${compose[@]}" exec -T -u root db chown postgres:postgres /archive /backup
dsn="postgres://gripline:gripline@127.0.0.1:${pitr_port}/gripline?sslmode=disable"
pepper_one="$(openssl rand -base64 32 | tr -d '\n')"
pepper_two="$(openssl rand -base64 32 | tr -d '\n')"
pseudonym_one="$(openssl rand -base64 32 | tr -d '\n')"
pseudonym_two="$(openssl rand -base64 32 | tr -d '\n')"
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go run ./cmd/gripline-test-cluster-setup \
	-reset-dsn "$dsn" -keyring "$work_dir/keyring.json" -policy "$work_dir/policy.json" -verifier "$work_dir/verifier.key" \
	-seed-reference-state \
	-pepper-one "$pepper_one" -pepper-two "$pepper_two" \
	-pseudonym-one "$pseudonym_one" -pseudonym-two "$pseudonym_two"

sql() {
	"${compose[@]}" exec -T db psql -U gripline -d gripline -X -v ON_ERROR_STOP=1 -Atqc "$1"
}

state_fingerprint() {
	sql "SELECT concat_ws('|',
		(SELECT manifest->'active'->>'id' FROM gripline_policy_manifest WHERE singleton=TRUE),
		(SELECT manifest->'active'->>'revision' FROM gripline_policy_manifest WHERE singleton=TRUE),
		(SELECT manifest->'active'->>'digest' FROM gripline_policy_manifest WHERE singleton=TRUE),
		(SELECT manifest->>'activation_epoch' FROM gripline_policy_manifest WHERE singleton=TRUE),
		(SELECT signer_active_kid || ':' || signer_fingerprint || ':' || pepper_active_version || ':' || pepper_fingerprint || ':' || pseudonym_version || ':' || pseudonym_fingerprint || ':' || generation_epoch FROM gripline_cluster_crypto WHERE singleton=TRUE),
		(SELECT count(*) FROM gripline_credentials WHERE status=0),
		(SELECT count(*) FROM gripline_credentials WHERE status=4),
		(SELECT count(*) FROM gripline_lanes WHERE credential_id='qualification-active'),
		(SELECT count(*) FROM gripline_evidence WHERE subject_id='qualification-active'),
		(SELECT posture FROM gripline_operator_posture WHERE singleton=TRUE),
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

expected_state="$(state_fingerprint)"
[[ "$expected_state" == *"|1|1|1|1|0|1|1|1|1|1|1|5|1|1"* ]] || {
	echo "pitr qualification: reference state seed is incomplete: $expected_state" >&2
	exit 1
}

"${compose[@]}" exec -T db bash -ceu \
	'rm -rf /backup/base; mkdir -p /backup/base; pg_basebackup -h 127.0.0.1 -U gripline -D /backup/base -Fp -Xs -P' >/dev/null
target="$(sql "SELECT to_char(clock_timestamp() + interval '3 seconds', 'YYYY-MM-DD HH24:MI:SS.USOF')")"
sleep 4
sql "UPDATE gripline_policy_manifest SET manifest=jsonb_set(manifest, '{activation_epoch}', '2'::jsonb), updated_at=CURRENT_TIMESTAMP WHERE singleton=TRUE"
sql "UPDATE gripline_credentials SET status=1, revision=2, security=jsonb_set(security, '{risk_score}', '20'::jsonb) WHERE credential_id='qualification-active'"
sql "UPDATE gripline_operator_posture SET posture=1, updated_at=CURRENT_TIMESTAMP WHERE singleton=TRUE"
sql "INSERT INTO gripline_control_operations (operation_id, action, payload_fingerprint, created_at) VALUES ('qualification-post-backup-operation','qualification.post-backup','post-backup-payload',CURRENT_TIMESTAMP)"
sql 'SELECT pg_switch_wal()' >/dev/null
sql 'SELECT pg_switch_wal()' >/dev/null
for _ in $(seq 1 30); do
	if "${compose[@]}" exec -T db bash -ceu 'find /archive -type f -not -name "*.history" -print -quit | grep -q .' >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
"${compose[@]}" exec -T db bash -ceu 'find /archive -type f -not -name "*.history" -print -quit | grep -q .'

"${compose[@]}" stop db >/dev/null
GRIPLINE_PITR_TARGET_TIME="$target" "${compose[@]}" --profile restore up -d restore >/dev/null
for _ in $(seq 1 90); do
	if "${compose[@]}" exec -T restore pg_isready -U gripline -d gripline >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
"${compose[@]}" exec -T restore pg_isready -U gripline -d gripline >/dev/null
restored_state="$("${compose[@]}" exec -T restore psql -U gripline -d gripline -X -v ON_ERROR_STOP=1 -Atqc "SELECT concat_ws('|',
	(SELECT manifest->'active'->>'id' FROM gripline_policy_manifest WHERE singleton=TRUE),
	(SELECT manifest->'active'->>'revision' FROM gripline_policy_manifest WHERE singleton=TRUE),
	(SELECT manifest->'active'->>'digest' FROM gripline_policy_manifest WHERE singleton=TRUE),
	(SELECT manifest->>'activation_epoch' FROM gripline_policy_manifest WHERE singleton=TRUE),
	(SELECT signer_active_kid || ':' || signer_fingerprint || ':' || pepper_active_version || ':' || pepper_fingerprint || ':' || pseudonym_version || ':' || pseudonym_fingerprint || ':' || generation_epoch FROM gripline_cluster_crypto WHERE singleton=TRUE),
	(SELECT count(*) FROM gripline_credentials WHERE status=0),
	(SELECT count(*) FROM gripline_credentials WHERE status=4),
	(SELECT count(*) FROM gripline_lanes WHERE credential_id='qualification-active'),
	(SELECT count(*) FROM gripline_evidence WHERE subject_id='qualification-active'),
	(SELECT posture FROM gripline_operator_posture WHERE singleton=TRUE),
	(SELECT count(*) FROM gripline_control_operations WHERE operation_id='qualification-seed-operation'),
	(SELECT count(*) FROM gripline_credential_receipts WHERE request_id='qualification-seed-request'),
	(SELECT count(*) FROM gripline_resource_leases WHERE lease_id='qualification-seed-lease' AND state='reserved'),
	(SELECT count(*) FROM gripline_resource_holds WHERE lease_id='qualification-seed-lease'),
	(SELECT concurrency_used FROM gripline_resource_buckets WHERE scope=2 AND scope_id='qualification-active' AND dimension=1),
	(SELECT count(*) FROM gripline_policy_artifacts WHERE policy_id='gripline-default-v1' AND revision=1),
	(SELECT count(*) FROM gripline_cluster_crypto_generations),
	(SELECT count(*) FROM gripline_operator_audit WHERE target='qualification-active'),
	(SELECT count(*) FROM gripline_admission_audit WHERE request_id='qualification-seed-request'))")"
[[ "$restored_state" == "$expected_state" ]] || {
	echo "pitr qualification: restored state differs from pre-mutation state" >&2
	echo "  before:  $expected_state" >&2
	echo "  restore: $restored_state" >&2
	exit 1
}
[[ "$("${compose[@]}" exec -T restore psql -U gripline -d gripline -X -v ON_ERROR_STOP=1 -Atqc "SELECT COUNT(*) FROM gripline_control_operations WHERE operation_id='qualification-post-backup-operation'")" == 0 ]] || {
	echo "pitr qualification: post-backup control operation survived target restore" >&2
	exit 1
}
# Start the real clustered server against the restored authority and exercise
# the fail-closed readiness contract with repository-owned broken fixtures.
# Missing local signer/pepper/pseudonym/policy material is a boot failure; a
# missing schema marker is a serving-authority failure. None may become ready.
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/gripline" ./cmd/gripline
restore_dsn="postgres://gripline:gripline@127.0.0.1:${restore_port}/gripline?sslmode=disable"
pepper_json="{\"1\":\"${pepper_one}\",\"2\":\"${pepper_two}\"}"
pseudonym_json="{\"1\":\"${pseudonym_one}\",\"2\":\"${pseudonym_two}\"}"

write_readiness_config() {
	local name=$1
	local signer_path="$work_dir/keyring.json"
	local policy_path="$work_dir/policy.json"
	local configured_peppers="$pepper_json"
	local configured_pseudonyms="$pseudonym_json"
	case "$name" in
		baseline) ;;
		missing-signer) signer_path="$work_dir/missing-keyring.json" ;;
		missing-pepper) configured_peppers="{\"2\":\"${pepper_two}\"}" ;;
		missing-pseudonym) configured_pseudonyms="{}" ;;
		missing-policy) policy_path="$work_dir/missing-policy.json" ;;
		missing-schema) ;;
		*) echo "pitr qualification: unknown readiness case $name" >&2; return 2 ;;
	esac
	cat >"$work_dir/config-${name}.json" <<EOF
{
  "listen": "127.0.0.1:$((25500 + ${#name}))",
  "tls": {"terminate_tls_upstream": true},
  "backend": {"url": "http://127.0.0.1:1", "trust_mode": "private_network", "timeout": "2s", "allowed_endpoints": [{"method": "POST", "path": "/v1/messages"}]},
  "server": {"read_timeout": "5s", "write_timeout": "5s", "idle_timeout": "5s", "read_header_timeout": "2s"},
  "identity": {"audience": "pitr-readiness"},
  "secrets": {"pepper_versions": ${configured_peppers}},
  "ingress": {"pseudonym_keys": ${configured_pseudonyms}},
  "paths": {"signer_keyring": "${signer_path}"},
  "policy": {"file": "${policy_path}", "verifier_key_file": "${work_dir}/verifier.key"},
  "authority": {"backend": "postgres", "dsn_env": "GRIPLINE_PITR_READY_DSN", "node_id": "pitr-${name}", "lease_ttl": "5s", "renew_every": "1s", "connect_timeout": "3s", "operation_timeout": "1s", "max_conns": 4, "min_conns": 1},
  "deployment": {"allow_ephemeral_state": false}
}
EOF
}

assert_ready() {
	local name=$1
	local port=$((25500 + ${#name}))
	local pid
	GRIPLINE_PITR_READY_DSN="$restore_dsn" "$work_dir/gripline" -config "$work_dir/config-${name}.json" >"$work_dir/${name}.log" 2>&1 &
	pid=$!
	for _ in $(seq 1 40); do
		if [[ "$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/readyz" 2>/dev/null || true)" == 200 ]]; then
			kill -TERM "$pid" >/dev/null 2>&1 || true
			wait "$pid" >/dev/null 2>&1 || true
			return 0
		fi
		if ! kill -0 "$pid" >/dev/null 2>&1; then
			break
		fi
		sleep 0.25
	done
	kill -TERM "$pid" >/dev/null 2>&1 || true
	wait "$pid" >/dev/null 2>&1 || true
	echo "pitr qualification: readiness baseline did not become ready" >&2
	cat "$work_dir/${name}.log" >&2
	return 1
}

assert_not_ready() {
	local name=$1
	local port=$((25500 + ${#name}))
	local pid
	local observed=0
	GRIPLINE_PITR_READY_DSN="$restore_dsn" "$work_dir/gripline" -config "$work_dir/config-${name}.json" >"$work_dir/${name}.log" 2>&1 &
	pid=$!
	for _ in $(seq 1 40); do
		case "$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/readyz" 2>/dev/null || true)" in
			200) echo "pitr qualification: ${name} unexpectedly became ready" >&2; observed=2; break ;;
			503) observed=1; break ;;
		esac
		if ! kill -0 "$pid" >/dev/null 2>&1; then
			observed=1
			break
		fi
		sleep 0.25
	done
	kill -TERM "$pid" >/dev/null 2>&1 || true
	wait "$pid" >/dev/null 2>&1 || true
	if [[ "$observed" != 1 ]]; then
		cat "$work_dir/${name}.log" >&2
		return 1
	fi
	echo "pitr qualification: ${name} failed closed"
}

write_readiness_config baseline
assert_ready baseline
for readiness_case in missing-signer missing-pepper missing-pseudonym missing-policy; do
	write_readiness_config "$readiness_case"
	assert_not_ready "$readiness_case"
done
write_readiness_config missing-schema
"${compose[@]}" exec -T restore psql -U gripline -d gripline -X -v ON_ERROR_STOP=1 -c 'DROP TABLE gripline_schema' >/dev/null
assert_not_ready missing-schema

echo "pitr qualification: base backup, WAL archive, target-time restore, complete security-state validation, and fail-closed readiness cases passed"
