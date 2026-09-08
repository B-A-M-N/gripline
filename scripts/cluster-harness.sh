#!/usr/bin/env bash
set -euo pipefail

# Multi-process PostgreSQL acceptance gate. The database is supplied by CI (or
# GRIPLINE_TEST_POSTGRES_DSN); three separately running gateways receive only
# shared authority state, and every client request enters through the compiled
# round-robin load balancer.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness_dir="$(mktemp -d)"
pids=()
cleanup() {
	for pid in "${pids[@]}"; do
		kill -TERM "$pid" >/dev/null 2>&1 || true
	done
	for pid in "${pids[@]}"; do
		wait "$pid" >/dev/null 2>&1 || true
	done
	if [[ "${GRIPLINE_CLUSTER_HARNESS_KEEP:-0}" == "1" ]]; then
		echo "cluster harness artifacts: $harness_dir" >&2
	else
		rm -rf "$harness_dir"
	fi
}
trap cleanup EXIT

cd "$repo_dir"
dsn="${GRIPLINE_TEST_POSTGRES_DSN:-postgres://gripline:gripline@127.0.0.1:5432/gripline?sslmode=disable}"
base=$((19000 + ($$ % 800) * 10))
lb_port=$base
backend_port=$((base + 1))
audience="gripline-cluster-harness"
operator_token="operator-cluster-harness-0123456789abcdef0123456789"
secret_one="cluster-secret-one-0123456789"
secret_two="cluster-secret-two-0123456789"
pepper_b64="$(openssl rand -base64 32 | tr -d '\n')"
policy_epoch_file="$harness_dir/policy-epoch"
printf '1\n' >"$policy_epoch_file"

go build -trimpath -o "$harness_dir/gripline" ./cmd/gripline
go build -trimpath -o "$harness_dir/backend" ./cmd/gripline-test-backend
go build -trimpath -o "$harness_dir/lb" ./cmd/gripline-test-lb
go build -trimpath -o "$harness_dir/setup" ./cmd/gripline-test-cluster-setup

"$harness_dir/setup" \
	-reset-dsn "$dsn" \
	-keyring "$harness_dir/keyring.json" \
	-policy "$harness_dir/policy.json" \
	-candidate "$harness_dir/candidate.json" \
	-verifier "$harness_dir/policy-verifier.key"

export GRIPLINE_CLUSTER_DSN="$dsn"
for node in a b c; do
	case "$node" in
		a) node_port=$((base + 10)); admin_port=$((base + 20));;
		b) node_port=$((base + 11)); admin_port=$((base + 21));;
		c) node_port=$((base + 12)); admin_port=$((base + 22));;
	esac
	cat >"$harness_dir/config-${node}.json" <<EOF
{
  "listen": "127.0.0.1:${node_port}",
  "tls": {"terminate_tls_upstream": true},
  "backend": {"url": "http://127.0.0.1:${backend_port}", "verifier_control_url": "http://127.0.0.1:${backend_port}/v1/verifier/rotate", "timeout": "5s"},
  "server": {
    "read_timeout": "10s", "write_timeout": "10s", "idle_timeout": "10s",
    "read_header_timeout": "5s", "stream_write_idle_timeout": "1s", "max_body_bytes": 1048576,
    "spool_dir": "${harness_dir}/spool-${node}", "spool_max_bytes": 1048576, "spool_max_files": 8
  },
  "identity": {"audience": "${audience}"},
  "secrets": {"pepper_versions": {"1": "${pepper_b64}"}},
  "admin": {"listen": "127.0.0.1:${admin_port}", "operator_tokens": {"${operator_token}": "harness:posture.control,credential.lifecycle,lane.lifecycle,policy.install,audit.read,cluster.read,crypto.lifecycle"}},
  "paths": {"signer_keyring": "${harness_dir}/keyring.json"},
  "policy": {"file": "${harness_dir}/policy.json", "verifier_key_file": "${harness_dir}/policy-verifier.key"},
  "authority": {
    "backend": "postgres", "dsn_env": "GRIPLINE_CLUSTER_DSN", "node_id": "cluster-${node}",
    "lease_ttl": "10s", "renew_every": "2s", "connect_timeout": "10s", "operation_timeout": "2s",
    "max_conns": 8, "min_conns": 1
  },
  "deployment": {"allow_ephemeral_state": false}
}
EOF
done

# Prepare one sealed candidate while the cluster is stopped. Every node uses
# this identical keyring, so the authority can compare one signer fingerprint
# across all live acknowledgements.
"$harness_dir/gripline" crypto signer-prepare --config "$harness_dir/config-a.json" --offline >"$harness_dir/signer-prepare.log"
signer_fingerprint="$(awk -F'fingerprint=' '/fingerprint=/{split($2, fields, ";"); print fields[1]; exit}' "$harness_dir/signer-prepare.log")"
if [[ -z "$signer_fingerprint" ]]; then
	echo "cluster harness: signer preparation did not produce a fingerprint" >&2
	exit 1
fi

for node in a b c; do
	"$harness_dir/gripline" -config "$harness_dir/config-${node}.json" >"$harness_dir/gripline-${node}.log" 2>&1 &
	pids+=("$!")
done

"$harness_dir/gripline" keys export --config "$harness_dir/config-a.json" >"$harness_dir/keys.json"
"$harness_dir/backend" \
	-listen "127.0.0.1:${backend_port}" \
	-keys "$harness_dir/keys.json" \
	-audience "$audience" \
	-work-delay 2s \
	-verifier-control "/v1/verifier/rotate" \
	-active "$harness_dir/backend-active" \
	-peak "$harness_dir/backend-peak" \
	-policy-epoch-file "$policy_epoch_file" \
	-assertion-path "$harness_dir/latest-assertion" \
	-capture "$harness_dir/backend-capture.log" >"$harness_dir/backend.log" 2>&1 &
pids+=("$!")

"$harness_dir/lb" \
	-listen "127.0.0.1:${lb_port}" \
	-backend "http://127.0.0.1:$((base + 10))" \
	-backend "http://127.0.0.1:$((base + 11))" \
	-backend "http://127.0.0.1:$((base + 12))" >"$harness_dir/lb.log" 2>&1 &
pids+=("$!")

wait_status() {
	local url=$1 expected=${2:-200}
	for _ in $(seq 1 120); do
		if [[ "$(curl -sS -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)" == "$expected" ]]; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

for node in a b c; do
	case "$node" in
		a) node_port=$((base + 10));;
		b) node_port=$((base + 11));;
		c) node_port=$((base + 12));;
	esac
	if ! wait_status "http://127.0.0.1:${node_port}/readyz"; then
		cat "$harness_dir/gripline-${node}.log" >&2
		exit 1
	fi
done
wait_status "http://127.0.0.1:${lb_port}/readyz"
wait_status "http://127.0.0.1:${backend_port}/healthz" 401

provision() {
	local id=$1 secret=$2
	printf '%s\n' "$secret" | GRIPLINE_OPERATOR_TOKEN="$operator_token" \
	"$harness_dir/gripline" credential add --config "$harness_dir/config-a.json" \
		--id "$id" --account "${id}-account" --policy gripline-default-v1 \
		--plan cluster-plan --reason "cluster harness seed" --operation-id "cluster-add-${id}" --secret-stdin \
		>"$harness_dir/provision-${id}.log" 2>&1
}
provision cluster-credential-one "$secret_one"
provision cluster-credential-two "$secret_two"

# Capture an assertion signed by the original key before rotation. Retirement
# below must make this assertion unverifiable at the backend after its TTL
# overlap has explicitly elapsed.
pre_rotation_assertion="$(curl -fsS "http://127.0.0.1:${lb_port}/v1/messages" -H "Authorization: Bearer ${secret_two}")"
printf '%s\n' "$pre_rotation_assertion" | rg -q '"policy_revision":1'
old_assertion="$(<"$harness_dir/latest-assertion")"
test -n "$old_assertion"

# Read the initial generation fingerprint before activating its replacement.
crypto_status_before="$(curl -fsS "http://127.0.0.1:$((base + 20))/admin/crypto" -H "Authorization: Bearer ${operator_token}")"
old_signer_fingerprint="$(printf '%s' "$crypto_status_before" | sed -n 's/.*"kind":"signer","generation":1,"fingerprint":"\([^"]*\)".*/\1/p')"
if [[ -z "$old_signer_fingerprint" ]]; then
	echo "cluster harness: initial signer fingerprint unavailable" >&2
	exit 1
fi

# Signer activation requires the backend to publish the candidate and verify a
# candidate-signed canary before the shared authority changes active KID.
signer_activation_code="$(curl -sS -o "$harness_dir/signer-activation-body" -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/crypto/activate" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-signer-activate' \
	--data "{\"kind\":\"signer\",\"generation\":2,\"fingerprint\":\"${signer_fingerprint}\",\"reason\":\"cluster signer canary\"}")"
if [[ "$signer_activation_code" != "200" ]]; then
	cat "$harness_dir/signer-activation-body" >&2
	exit 1
fi
for port in $((base + 10)) $((base + 11)) $((base + 12)); do
	wait_status "http://127.0.0.1:${port}/readyz"
done

retire_not_before="$(date -u -d '1 second ago' '+%Y-%m-%dT%H:%M:%SZ')"
retire_code="$(curl -sS -o "$harness_dir/signer-retirement-body" -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/crypto/retire" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-signer-retire-old' \
	--data "{\"kind\":\"signer\",\"generation\":1,\"fingerprint\":\"${old_signer_fingerprint}\",\"not_before\":\"${retire_not_before}\",\"reason\":\"cluster signer overlap expired\"}")"
if [[ "$retire_code" != "200" ]]; then
	cat "$harness_dir/signer-retirement-body" >&2
	exit 1
fi
for port in $((base + 10)) $((base + 11)) $((base + 12)); do
	wait_status "http://127.0.0.1:${port}/readyz"
done
old_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${backend_port}/v1/messages" -H "X-Gripline-Assertion: ${old_assertion}")"
test "$old_code" = 401

curl_data_code() {
	local url=$1 secret=$2
	curl -sS -o /dev/null -w '%{http_code}' "$url" -H "Authorization: Bearer ${secret}" 2>/dev/null || true
}

# Global concurrency cap is five. Fifteen requests enter via the LB and the
# backend's independently tracked active-work peak must never exceed five.
mkdir -p "$harness_dir/codes"
work_pids=()
for i in $(seq 1 15); do
	curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${lb_port}/v1/work" \
		-H "Authorization: Bearer ${secret_one}" >"$harness_dir/codes/${i}" 2>/dev/null &
	work_pids+=("$!")
done
for pid in "${work_pids[@]}"; do
	wait "$pid" || true
done
peak="$(cat "$harness_dir/backend-peak")"
if [[ "$peak" -gt 5 ]]; then
	echo "cluster harness: backend peak ${peak} exceeded global cap 5" >&2
	exit 1
fi
if [[ "$(awk '$1 == 200 {n++} END {print n+0}' "$harness_dir/codes"/*)" -lt 1 ]]; then
	echo "cluster harness: no work request completed through the LB" >&2
	exit 1
fi

# A revoke committed through A must deny on the other two authorities.
missing_operation_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/credentials/revoke" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	--data '{"credential_id":"cluster-credential-one","reason":"missing operation id"}')"
test "$missing_operation_code" = 400
revoke_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/credentials/revoke" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-revoke-one' \
	--data '{"credential_id":"cluster-credential-one","reason":"cluster revoke"}')"
test "$revoke_code" = 200
replay_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 21))/admin/credentials/revoke" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-revoke-one' \
	--data '{"credential_id":"cluster-credential-one","reason":"cluster revoke"}')"
test "$replay_code" = 200
conflict_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 22))/admin/credentials/revoke" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-revoke-one' \
	--data '{"credential_id":"cluster-credential-one","reason":"different operation payload"}')"
test "$conflict_code" = 409
test "$(curl_data_code "http://127.0.0.1:$((base + 11))/v1/messages" "$secret_one")" != 200
test "$(curl_data_code "http://127.0.0.1:$((base + 12))/v1/messages" "$secret_one")" != 200

# Lockdown committed through B must be observed by A, B, and C.
lockdown_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 21))/admin/posture" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-lockdown' \
	--data '{"on":true,"reason":"cluster lockdown"}')"
test "$lockdown_code" = 200
for port in $((base + 10)) $((base + 11)) $((base + 12)); do
	test "$(curl_data_code "http://127.0.0.1:${port}/v1/messages" "$secret_two")" != 200
done
unlock_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/posture" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-unlock' \
	--data '{"on":false,"reason":"cluster harness continues"}')"
test "$unlock_code" = 200

# Policy activation and rollback through A must propagate to B and C via the
# watcher; each node's backend-visible assertion revision is checked directly.
candidate="$(<"$harness_dir/candidate.json")"
old_response="$(curl -fsS "http://127.0.0.1:${lb_port}/v1/messages" -H "Authorization: Bearer ${secret_two}")"
printf '%s\n' "$old_response" | rg -q '"policy_revision":1'
printf '%s\n' "$old_response" | rg -q '"policy_epoch":1'
prepare_payload="$(printf '{"artifact":%s,"reason":"cluster policy canary"}' "$candidate")"
prepare_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/policy/prepare" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	--data "$prepare_payload")"
test "$prepare_code" = 200
activate_code=400
for _ in $(seq 1 120); do
	activate_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/policy/activate" \
		-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
		--data '{"reason":"cluster policy canary"}')"
	if [[ "$activate_code" == "200" ]]; then
		break
	fi
	sleep 0.1
done
test "$activate_code" = 200
printf '2\n' >"$policy_epoch_file"
for port in $((base + 10)) $((base + 11)) $((base + 12)); do
	for _ in $(seq 1 50); do
		if curl -fsS "http://127.0.0.1:${port}/v1/messages" -H "Authorization: Bearer ${secret_two}" 2>/dev/null | rg -q '"policy_revision":2' && \
			curl -fsS "http://127.0.0.1:${port}/v1/messages" -H "Authorization: Bearer ${secret_two}" 2>/dev/null | rg -q '"policy_epoch":2'; then
			break
		fi
		sleep 0.1
	done
	curl -fsS "http://127.0.0.1:${port}/v1/messages" -H "Authorization: Bearer ${secret_two}" | rg -q '"policy_revision":2'
	curl -fsS "http://127.0.0.1:${port}/v1/messages" -H "Authorization: Bearer ${secret_two}" | rg -q '"policy_epoch":2'
done
rollback_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/policy/rollback" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	--data '{"revision":1,"reason":"cluster rollback canary"}')"
test "$rollback_code" = 200
printf '3\n' >"$policy_epoch_file"
for port in $((base + 10)) $((base + 11)) $((base + 12)); do
	for _ in $(seq 1 50); do
		if curl -fsS "http://127.0.0.1:${port}/v1/messages" -H "Authorization: Bearer ${secret_two}" 2>/dev/null | rg -q '"policy_revision":1' && \
			curl -fsS "http://127.0.0.1:${port}/v1/messages" -H "Authorization: Bearer ${secret_two}" 2>/dev/null | rg -q '"policy_epoch":3'; then
			break
		fi
		sleep 0.1
	done
	curl -fsS "http://127.0.0.1:${port}/v1/messages" -H "Authorization: Bearer ${secret_two}" | rg -q '"policy_revision":1'
	curl -fsS "http://127.0.0.1:${port}/v1/messages" -H "Authorization: Bearer ${secret_two}" | rg -q '"policy_epoch":3'
done
# A killed replica with in-flight work must cancel the upstream request. The
# fixture's active-work counter measures backend work, not merely proxy
# sockets; this proves the concurrency cap is released only after cancellation
# reaches the actual backend operation.
printf '0\n' >"$harness_dir/backend-active"
curl -sS -o /dev/null "http://127.0.0.1:$((base + 12))/v1/work" \
	-H "Authorization: Bearer ${secret_two}" >"$harness_dir/killed-request.log" 2>&1 &
killed_request_pid=$!
for _ in $(seq 1 50); do
	if [[ -f "$harness_dir/backend-active" && "$(<"$harness_dir/backend-active")" -ge 1 ]]; then
		break
	fi
	sleep 0.1
done
if [[ ! -f "$harness_dir/backend-active" || "$(<"$harness_dir/backend-active")" -lt 1 ]]; then
	echo "cluster harness: in-flight backend work did not start before node kill" >&2
	cat "$harness_dir/killed-request.log" >&2 || true
	exit 1
fi
kill -KILL "${pids[2]}" >/dev/null 2>&1 || true
wait "${pids[2]}" >/dev/null 2>&1 || true
wait "$killed_request_pid" >/dev/null 2>&1 || true
for _ in $(seq 1 50); do
	if [[ "$(<"$harness_dir/backend-active")" -eq 0 ]]; then
		break
	fi
	sleep 0.1
done
if [[ "$(<"$harness_dir/backend-active")" -ne 0 ]]; then
	echo "cluster harness: backend work survived killed proxy" >&2
	exit 1
fi
# A killed replica is absent from readiness and cannot mint a lease. The
# remaining two nodes continue to enforce the same five-slot authority.
if curl -sS "http://127.0.0.1:$((base + 12))/readyz" >/dev/null 2>&1; then
	echo "cluster harness: killed node remained reachable" >&2
	exit 1
fi

echo "cluster harness: three-node PostgreSQL invariants passed"
