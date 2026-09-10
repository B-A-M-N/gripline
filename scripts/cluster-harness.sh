#!/usr/bin/env bash
set -euo pipefail

diagnose_failure() {
	local rc=$?
	echo "cluster harness failed: line=${BASH_LINENO[0]:-0} command=${BASH_COMMAND@Q} rc=${rc}" >&2
}
trap diagnose_failure ERR

# Multi-process PostgreSQL acceptance gate. The database is supplied by CI (or
# GRIPLINE_TEST_POSTGRES_DSN); three separately running gateways receive only
# shared authority state, and every client request enters through the compiled
# round-robin load balancer. The inference and verifier-control backends are
# separate processes/listeners so the lifecycle proof cannot accidentally rely
# on a multiplexed data-plane identity.

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
pick_cluster_base() {
	python3 - <<'PY'
import socket

offsets = (0, 1, 2, 10, 11, 12, 20, 21, 22)
for base in range(19000, 27000, 10):
    sockets = []
    try:
        for offset in offsets:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", base + offset))
            sockets.append(sock)
    except OSError:
        for sock in sockets:
            sock.close()
        continue
    for sock in sockets:
        sock.close()
    print(base)
    raise SystemExit(0)
raise SystemExit("no free cluster harness listener range")
PY
}

base="$(pick_cluster_base)"
lb_port=$base
backend_port=$((base + 1))
control_backend_port=$((base + 2))
audience="gripline-cluster-harness"
operator_token="operator-cluster-harness-0123456789abcdef0123456789"
secret_one="cluster-secret-one-0123456789"
secret_two="cluster-secret-two-0123456789"
secret_three="cluster-secret-three-0123456789"
secret_four="cluster-secret-four-0123456789"
lease_ttl="${GRIPLINE_CLUSTER_HARNESS_LEASE_TTL:-30s}"
renew_every="${GRIPLINE_CLUSTER_HARNESS_RENEW_EVERY:-5s}"
load_mode="${GRIPLINE_CLUSTER_HARNESS_LOAD_MODE:-security}"
if [[ "$load_mode" != security && "$load_mode" != capacity ]]; then
	echo "cluster harness: load mode must be security or capacity" >&2
	exit 2
fi
pepper_one_b64="$(openssl rand -base64 32 | tr -d '\n')"
pepper_two_b64="$(openssl rand -base64 32 | tr -d '\n')"
pseudonym_one_b64="$(openssl rand -base64 32 | tr -d '\n')"
pseudonym_two_b64="$(openssl rand -base64 32 | tr -d '\n')"
policy_epoch_file="$harness_dir/policy-epoch"
printf '1\n' >"$policy_epoch_file"
maintenance_config=""
if [[ "${GRIPLINE_CLUSTER_HARNESS_COMPRESSED_RETENTION:-0}" == "1" ]]; then
	retention_window="${GRIPLINE_CLUSTER_HARNESS_RETENTION_WINDOW:-1m}"
	maintenance_interval="${GRIPLINE_CLUSTER_HARNESS_MAINTENANCE_INTERVAL:-1h}"
	maintenance_config=", \"maintenance\": {\"interval\":\"${maintenance_interval}\",\"batch_size\":256,\"max_batches_per_pass\":64,\"max_rows_per_pass\":4096,\"max_runtime_per_pass\":\"5s\",\"evidence_grace\":\"0s\",\"released_lease_retention\":\"${retention_window}\",\"credential_receipt_retention\":\"${retention_window}\",\"control_operation_retention\":\"${retention_window}\",\"admission_audit_retention\":\"${retention_window}\",\"security_transition_retention\":\"${retention_window}\",\"operator_audit_retention\":\"${retention_window}\",\"policy_audit_retention\":\"${retention_window}\",\"membership_retention\":\"1h\",\"adaptive_retention\":\"1h\",\"evidence_guard_retention\":\"${retention_window}\",\"lane_operator_audit_retention\":\"${retention_window}\",\"policy_node_state_retention\":\"1h\",\"cluster_crypto_ack_retention\":\"1h\"}"
fi
max_conns="${GRIPLINE_CLUSTER_HARNESS_MAX_CONNS:-8}"
operation_timeout="${GRIPLINE_CLUSTER_HARNESS_OPERATION_TIMEOUT:-2s}"
load_timeout="${GRIPLINE_CLUSTER_HARNESS_LOAD_TIMEOUT:-10s}"
load_user_agent="${GRIPLINE_CLUSTER_HARNESS_LOAD_USER_AGENT:-gripline-qualification-load/1}"
ingress_extra=""
if [[ "$load_mode" == capacity ]]; then
	# The disposable load balancer is the only trusted proxy in this fixture.
	# Capacity workers bind distinct loopback addresses so the source-scoped
	# authority rows measure independent clients instead of one artificial hot
	# source bucket. Same-source contention remains covered by statepg tests.
	ingress_extra=', "trusted_proxies": ["127.0.0.1/32"]'
fi

write_artifact() {
	if [[ -n "${GRIPLINE_CLUSTER_HARNESS_ARTIFACT_FILE:-}" ]]; then
		cat >"$GRIPLINE_CLUSTER_HARNESS_ARTIFACT_FILE" <<EOF
base=${base}
lb_port=${lb_port}
node_a_port=$((base + 10))
node_b_port=$((base + 11))
node_c_port=$((base + 12))
admin_a_port=$((base + 20))
admin_b_port=$((base + 21))
admin_c_port=$((base + 22))
node_a_pid=${pids[0]:-}
node_b_pid=${pids[1]:-}
node_c_pid=${pids[2]:-}
operator_token=${operator_token}
request_secret=${secret_four}
EOF
	fi
}

ca_key="$harness_dir/backend-ca.key"
ca_cert="$harness_dir/backend-ca.pem"
backend_key="$harness_dir/backend-server.key"
backend_csr="$harness_dir/backend-server.csr"
backend_cert="$harness_dir/backend-server.pem"
inference_client_key="$harness_dir/inference-client.key"
inference_client_csr="$harness_dir/inference-client.csr"
inference_client_cert="$harness_dir/inference-client.pem"
control_client_key="$harness_dir/verifier-control-client.key"
control_client_csr="$harness_dir/verifier-control-client.csr"
control_client_cert="$harness_dir/verifier-control-client.pem"

# The cluster fixture uses distinct verified client identities for inference
# and verifier management. Both listeners trust the private CA, but each
# verifier accepts only its own exact DNS identity.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout "$ca_key" -out "$ca_cert" -subj "/CN=Gripline cluster harness CA" \
	>/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
	-keyout "$backend_key" -out "$backend_csr" -subj "/CN=backend.internal" \
	-addext "subjectAltName=DNS:backend.internal,DNS:control.internal" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 -copy_extensions copy \
	-in "$backend_csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
	-out "$backend_cert" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
	-keyout "$inference_client_key" -out "$inference_client_csr" -subj "/CN=gripline-inference.internal" \
	-addext "subjectAltName=DNS:gripline-inference.internal" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 -copy_extensions copy \
	-in "$inference_client_csr" -CA "$ca_cert" -CAkey "$ca_key" -CAserial "$harness_dir/backend-ca.srl" \
	-out "$inference_client_cert" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
	-keyout "$control_client_key" -out "$control_client_csr" -subj "/CN=gripline-verifier-control.internal" \
	-addext "subjectAltName=DNS:gripline-verifier-control.internal" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 -copy_extensions copy \
	-in "$control_client_csr" -CA "$ca_cert" -CAkey "$ca_key" -CAserial "$harness_dir/backend-ca.srl" \
	-out "$control_client_cert" >/dev/null 2>&1

go build -trimpath -o "$harness_dir/gripline" ./cmd/gripline
go build -trimpath -o "$harness_dir/backend" ./cmd/gripline-test-backend
go build -trimpath -o "$harness_dir/lb" ./cmd/gripline-test-lb
go build -trimpath -o "$harness_dir/setup" ./cmd/gripline-test-cluster-setup
go build -trimpath -o "$harness_dir/load" ./cmd/gripline-test-load

setup_args=(
	-reset-dsn "$dsn"
	-keyring "$harness_dir/keyring.json"
	-policy "$harness_dir/policy.json"
	-candidate "$harness_dir/candidate.json"
	-verifier "$harness_dir/policy-verifier.key"
	-pepper-one "$pepper_one_b64" -pepper-two "$pepper_two_b64"
	-pseudonym-one "$pseudonym_one_b64" -pseudonym-two "$pseudonym_two_b64"
)
if [[ "$load_mode" == capacity ]]; then
	setup_args+=(-capacity-mode)
fi
if [[ "${GRIPLINE_CLUSTER_HARNESS_COMPRESSED_RETENTION:-0}" == "1" ]]; then
	setup_args+=(-seed-maintenance-fixture)
fi
"$harness_dir/setup" "${setup_args[@]}"

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
	"backend": {
	    "url": "https://127.0.0.1:${backend_port}",
	    "trust_mode": "mtls",
	    "tls": {"ca_file": "${ca_cert}", "client_cert_file": "${inference_client_cert}", "client_key_file": "${inference_client_key}", "server_name": "backend.internal", "min_version": "1.2"},
	    "verifier_control": {"url": "https://127.0.0.1:${control_backend_port}/v1/verifier/rotate", "ca_file": "${ca_cert}", "client_cert_file": "${control_client_cert}", "client_key_file": "${control_client_key}", "server_name": "control.internal", "min_version": "1.2"},
    "timeout": "5s",
    "allowed_endpoints": [
      {"method": "POST", "path": "/v1/messages"},
      {"method": "GET", "path": "/v1/work"}
    ]
  },
  "server": {
    "read_timeout": "10s", "write_timeout": "10s", "idle_timeout": "10s",
    "read_header_timeout": "5s", "stream_write_idle_timeout": "1s", "max_body_bytes": 1048576,
    "spool_dir": "${harness_dir}/spool-${node}", "spool_max_bytes": 1048576, "spool_max_files": 8
  },
  "identity": {"audience": "${audience}"},
  "secrets": {"pepper_versions": {"1": "${pepper_one_b64}", "2": "${pepper_two_b64}"}},
	"ingress": {"pseudonym_keys": {"1": "${pseudonym_one_b64}", "2": "${pseudonym_two_b64}"}${ingress_extra}},
  "admin": {"listen": "127.0.0.1:${admin_port}", "operator_tokens": {"${operator_token}": "harness:posture.control,credential.lifecycle,lane.lifecycle,policy.read,policy.install,audit.read,cluster.read,crypto.lifecycle"}},
  "paths": {"signer_keyring": "${harness_dir}/keyring.json"},
  "policy": {"file": "${harness_dir}/policy.json", "verifier_key_file": "${harness_dir}/policy-verifier.key"},
  "authority": {
    "backend": "postgres", "dsn_env": "GRIPLINE_CLUSTER_DSN", "node_id": "cluster-${node}",
	    "lease_ttl": "${lease_ttl}", "renew_every": "${renew_every}", "connect_timeout": "10s", "operation_timeout": "${operation_timeout}",
	    "max_conns": ${max_conns}, "min_conns": 1${maintenance_config}
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
"$harness_dir/gripline" serve --config "$harness_dir/config-${node}.json" >"$harness_dir/gripline-${node}.log" 2>&1 &
	pids+=("$!")
done
write_artifact

"$harness_dir/gripline" keys export --config "$harness_dir/config-a.json" >"$harness_dir/keys.json"
"$harness_dir/backend" \
	-listen "127.0.0.1:${backend_port}" \
	-tls-cert "$backend_cert" -tls-key "$backend_key" -client-ca "$ca_cert" \
	-require-client-dns "gripline-inference.internal" \
	-keys "$harness_dir/keys.json" \
	-audience "$audience" \
	-work-delay "$([[ "$load_mode" == capacity ]] && echo 10ms || echo 2s)" \
	-active "$harness_dir/backend-active" \
	-peak "$harness_dir/backend-peak" \
	-policy-epoch-file "$policy_epoch_file" \
	-assertion-path "$harness_dir/latest-assertion" \
	-capture "$harness_dir/backend-capture.log" >"$harness_dir/backend.log" 2>&1 &
pids+=("$!")

# Verifier-management is a distinct listener and process. It receives only the
# dedicated verifier-control mTLS identity and never serves inference traffic.
"$harness_dir/backend" \
	-listen "127.0.0.1:${control_backend_port}" \
	-tls-cert "$backend_cert" -tls-key "$backend_key" -client-ca "$ca_cert" \
	-require-client-dns "gripline-verifier-control.internal" \
	-keys "$harness_dir/keys.json" \
	-audience "$audience" \
	-verifier-control "/v1/verifier/rotate" \
	-control-only \
	>"$harness_dir/verifier-control-backend.log" 2>&1 &
pids+=("$!")

"$harness_dir/lb" \
	-listen "127.0.0.1:${lb_port}" \
	-backend "http://127.0.0.1:$((base + 10))" \
	-backend "http://127.0.0.1:$((base + 11))" \
	-backend "http://127.0.0.1:$((base + 12))" >"$harness_dir/lb.log" 2>&1 &
pids+=("$!")

wait_status() {
	local url=$1 expected=${2:-200}
	for _ in $(seq 1 "${GRIPLINE_CLUSTER_HARNESS_READY_ATTEMPTS:-1800}"); do
		if [[ "$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)" == "$expected" ]]; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

backend_curl() {
	curl --cacert "$ca_cert" --cert "$inference_client_cert" --key "$inference_client_key" \
		--resolve "backend.internal:${backend_port}:127.0.0.1" "$@"
}

control_curl() {
	curl --cacert "$ca_cert" --cert "$control_client_cert" --key "$control_client_key" \
		--resolve "control.internal:${control_backend_port}:127.0.0.1" "$@"
}

inference_control_curl() {
	curl --cacert "$ca_cert" --cert "$inference_client_cert" --key "$inference_client_key" \
		--resolve "control.internal:${control_backend_port}:127.0.0.1" "$@"
}

control_data_curl() {
	curl --cacert "$ca_cert" --cert "$control_client_cert" --key "$control_client_key" \
		--resolve "backend.internal:${backend_port}:127.0.0.1" "$@"
}

load_seconds="${GRIPLINE_CLUSTER_HARNESS_LOAD_SECONDS:-5}"
load_workers="${GRIPLINE_CLUSTER_HARNESS_LOAD_WORKERS:-12}"
load_p95_limit_ms="${GRIPLINE_CLUSTER_HARNESS_LOAD_P95_LIMIT_MS:-5000}"
capacity_min_success_ratio="${GRIPLINE_CLUSTER_HARNESS_CAPACITY_MIN_SUCCESS_RATIO:-0.99}"
if ! [[ "$load_seconds" =~ ^[0-9]+$ && "$load_workers" =~ ^[1-9][0-9]*$ && "$load_p95_limit_ms" =~ ^[1-9][0-9]*$ ]]; then
	echo "cluster harness: load seconds/workers/p95 limit must be non-negative/positive integers" >&2
	exit 2
fi
load_p95_limit_ns=$((load_p95_limit_ms * 1000000))

wait_backend() {
	for _ in $(seq 1 120); do
		if [[ "$(backend_curl -sS -o /dev/null -w '%{http_code}' "https://backend.internal:${backend_port}/healthz" 2>/dev/null || true)" == "401" ]]; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

wait_control_backend() {
	for _ in $(seq 1 120); do
		if [[ "$(control_curl -sS -o /dev/null -w '%{http_code}' "https://control.internal:${control_backend_port}/healthz" 2>/dev/null || true)" == "401" ]]; then
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
wait_backend
wait_control_backend

provision() {
	local id=$1 secret=$2
	printf '%s\n' "$secret" | GRIPLINE_OPERATOR_TOKEN="$operator_token" \
	"$harness_dir/gripline" credential add --config "$harness_dir/config-a.json" \
		--id "$id" --account "${id}-account" --policy gripline-default-v1 \
		--plan cluster-plan --reason "cluster harness seed" --operation-id "cluster-add-${id}" --secret-stdin \
		>"$harness_dir/provision-${id}.log" 2>&1 || {
			echo "cluster harness: provisioning ${id} failed" >&2
			cat "$harness_dir/provision-${id}.log" >&2
			return 1
		}
}
provision cluster-credential-one "$secret_one"
provision cluster-credential-two "$secret_two"

# The public data plane must not expose the verifier-management path, and the
# backend must reject a direct unauthenticated control mutation before parsing
# its payload. The inference identity is valid for the data listener but must
# also be rejected by the verifier-management listener. The later crypto
# activation calls the same path with the dedicated control identity.
external_control_code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/verifier/rotate" -H "Authorization: Bearer ${secret_one}" -d '{}')"
test "$external_control_code" = 404
no_cert_control_code="$(curl --cacert "$ca_cert" --resolve "control.internal:${control_backend_port}:127.0.0.1" -sS -o /dev/null -w '%{http_code}' -X POST "https://control.internal:${control_backend_port}/v1/verifier/rotate" -d '{}' 2>/dev/null || true)"
test "$no_cert_control_code" = 000
direct_control_code="$(inference_control_curl -sS -o /dev/null -w '%{http_code}' -X POST "https://control.internal:${control_backend_port}/v1/verifier/rotate" -d '{}' 2>/dev/null || true)"
test "$direct_control_code" = 403
control_data_code="$(control_curl -sS -o /dev/null -w '%{http_code}' -X POST "https://control.internal:${control_backend_port}/v1/messages" -d '{}')"
test "$control_data_code" = 404
control_to_data_code="$(control_data_curl -sS -o /dev/null -w '%{http_code}' -X POST "https://backend.internal:${backend_port}/v1/messages" -d '{}' 2>/dev/null || true)"
test "$control_to_data_code" = 403

# Capture an assertion signed by the original key before rotation. Retirement
# below must make this assertion unverifiable at the backend after its TTL
# overlap has explicitly elapsed.
pre_rotation_assertion="$(curl -fsS -X POST "http://127.0.0.1:${lb_port}/v1/messages" -H "Authorization: Bearer ${secret_two}" -d '{}')"
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
retire_code=409
for _ in $(seq 1 "${GRIPLINE_CLUSTER_HARNESS_RETIRE_ATTEMPTS:-120}"); do
	retire_code="$(curl -sS -o "$harness_dir/signer-retirement-body" -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/crypto/retire" \
		-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
		-H 'Idempotency-Key: cluster-signer-retire-old' \
		--data "{\"kind\":\"signer\",\"generation\":1,\"fingerprint\":\"${old_signer_fingerprint}\",\"not_before\":\"${retire_not_before}\",\"reason\":\"cluster signer overlap expired\"}")"
	if [[ "$retire_code" == "200" ]]; then
		break
	fi
	if [[ "$retire_code" != "409" ]] || ! rg -q '"safe_after"' "$harness_dir/signer-retirement-body"; then
		cat "$harness_dir/signer-retirement-body" >&2
		exit 1
	fi
	retire_safe_after="$(sed -n 's/.*"safe_after":"\([^"]*\)".*/\1/p' "$harness_dir/signer-retirement-body")"
	retire_safe_after_epoch="$(date -u -d "$retire_safe_after" '+%s' 2>/dev/null || true)"
	if [[ ! "$retire_safe_after_epoch" =~ ^[0-9]+$ ]]; then
		cat "$harness_dir/signer-retirement-body" >&2
		exit 1
	fi
	retire_wait=$((retire_safe_after_epoch - $(date -u '+%s') + 1))
	if (( retire_wait > 0 )); then
		sleep "$retire_wait"
	else
		sleep 0.1
	fi
done
if [[ "$retire_code" != "200" ]]; then
	cat "$harness_dir/signer-retirement-body" >&2
	exit 1
fi
for port in $((base + 10)) $((base + 11)) $((base + 12)); do
	wait_status "http://127.0.0.1:${port}/readyz"
done
old_code="$(backend_curl -sS -o /dev/null -w '%{http_code}' "https://backend.internal:${backend_port}/v1/messages" -H "X-Gripline-Assertion: ${old_assertion}")"
test "$old_code" = 401

curl_data_code() {
	local url=$1 secret=$2
	curl -sS -o /dev/null -w '%{http_code}' -X POST "$url" -H "Authorization: Bearer ${secret}" -d '{}' 2>/dev/null || true
}

wait_data_denied() {
	local url=$1 secret=$2
	for _ in $(seq 1 60); do
		if [[ "$(curl_data_code "$url" "$secret")" != "200" ]]; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

wait_assertion_policy() {
	local port=$1 secret=$2 revision=$3 epoch=$4
	local response="$harness_dir/policy-${port}-${revision}-${epoch}.json" status=000
	for _ in $(seq 1 "${GRIPLINE_CLUSTER_HARNESS_POLICY_ATTEMPTS:-120}"); do
		status="$(curl -sS -o "$response" -w '%{http_code}' -X POST "http://127.0.0.1:${port}/v1/messages" \
			-H "Authorization: Bearer ${secret}" -d '{}' 2>/dev/null || true)"
		if [[ "$status" == 200 ]] &&
			rg -q '"policy_revision":'"${revision}" "$response" &&
			rg -q '"policy_epoch":'"${epoch}" "$response"; then
			return 0
		fi
		# A node can briefly forward the request while its policy/verifier
		# watcher is converging. The reference backend's exact response is a
		# bounded transient; invalid credentials and every other 401 remain
		# terminal failures.
		if [[ "$status" == 401 ]] && ! rg -qx 'assertion required' "$response"; then
			echo "cluster harness: policy ${revision}/${epoch} returned an unexpected 401 on port ${port}" >&2
			cat "$response" >&2 || true
			return 1
		fi
		if [[ "$status" != 401 && "$status" != 429 && "$status" != 503 && "$status" != 000 && "$status" != 200 ]]; then
			echo "cluster harness: policy ${revision}/${epoch} convergence returned unexpected status ${status} on port ${port}" >&2
			cat "$response" >&2 || true
			return 1
		fi
		sleep 0.1
	done
	echo "cluster harness: policy ${revision}/${epoch} did not converge on port ${port} (last status ${status})" >&2
	cat "$response" >&2 || true
	return 1
}

crypto_fingerprint() {
	local status=$1 kind=$2 generation=$3
	printf '%s' "$status" | sed -n "s/.*\"kind\":\"${kind}\",\"generation\":${generation},\"fingerprint\":\"\([^\"]*\)\".*/\1/p"
}

activate_crypto_generation() {
	local kind=$1 generation=$2 fingerprint=$3 operation_id=$4 node_admin_port=$5
	local body="$harness_dir/${kind}-${generation}-activation-body"
	local code
	code="$(curl -sS -o "$body" -w '%{http_code}' "http://127.0.0.1:${node_admin_port}/admin/crypto/activate" \
		-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
		-H "Idempotency-Key: ${operation_id}" \
		--data "{\"kind\":\"${kind}\",\"generation\":${generation},\"fingerprint\":\"${fingerprint}\",\"reason\":\"cluster ${kind} generation ${generation}\"}")"
	if [[ "$code" != "200" ]]; then
		cat "$body" >&2
		exit 1
	fi
	for port in $((base + 20)) $((base + 21)) $((base + 22)); do
		for _ in $(seq 1 60); do
			status="$(curl -sS "http://127.0.0.1:${port}/admin/crypto" -H "Authorization: Bearer ${operator_token}" 2>/dev/null || true)"
			if printf '%s' "$status" | rg -q "\"${kind}_active_(version|kid)\":${generation}"; then
				break
			fi
			sleep 0.1
		done
		printf '%s' "$status" | rg -q "\"${kind}_active_(version|kid)\":${generation}"
	done
	# The shared generation becoming visible is not sufficient: every node
	# withdraws readiness while it applies the local material and re-acknowledges
	# the new epoch. Wait for that serving invariant before sending data-plane
	# traffic, otherwise this harness races the deliberately fail-closed rollout.
	for port in $((base + 10)) $((base + 11)) $((base + 12)); do
		wait_status "http://127.0.0.1:${port}/readyz"
	done
}

# Pepper activation changes the generation used for newly provisioned
# credentials. Existing v1 records remain usable while the shared authority
# directs all new records to v2, regardless of which node handles the add.
crypto_status_after_signer="$(curl -fsS "http://127.0.0.1:$((base + 20))/admin/crypto" -H "Authorization: Bearer ${operator_token}")"
pepper_two_fingerprint="$(crypto_fingerprint "$crypto_status_after_signer" pepper 2)"
pseudonym_two_fingerprint="$(crypto_fingerprint "$crypto_status_after_signer" pseudonym 2)"
if [[ -z "$pepper_two_fingerprint" || -z "$pseudonym_two_fingerprint" ]]; then
	echo "cluster harness: staged pepper/pseudonym fingerprints unavailable" >&2
	exit 1
fi
activate_crypto_generation pepper 2 "$pepper_two_fingerprint" cluster-pepper-activate $((base + 21))
pepper_replay_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 22))/admin/crypto/activate" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-pepper-activate' \
	--data "{\"kind\":\"pepper\",\"generation\":2,\"fingerprint\":\"${pepper_two_fingerprint}\",\"reason\":\"cluster pepper generation 2\"}")"
test "$pepper_replay_code" = 200
provision cluster-credential-three "$secret_three"
pepper_counts="$(curl -fsS "http://127.0.0.1:$((base + 22))/admin/credentials/pepper-status" -H "Authorization: Bearer ${operator_token}")"
printf '%s' "$pepper_counts" | rg -q '"1":2'
printf '%s' "$pepper_counts" | rg -q '"2":1'
test "$(curl_data_code "http://127.0.0.1:$((base + 12))/v1/messages" "$secret_three")" = 200

# Pseudonym activation must preserve the source scope minted under v1. The
# shared alias lookup makes all three nodes select that existing v1 scope
# after v2 becomes active, so rotation does not reset source quotas or
# novelty history.
source_scopes_before="$(curl -fsS "http://127.0.0.1:$((base + 20))/admin/metrics" -H "Authorization: Bearer ${operator_token}" | sed -n 's/^gripline_resource_source_scopes \([0-9][0-9]*\)$/\1/p')"
if [[ -z "$source_scopes_before" || "$source_scopes_before" -lt 1 ]]; then
	echo "cluster harness: no shared source scope was created before pseudonym rotation" >&2
	exit 1
fi
activate_crypto_generation pseudonym 2 "$pseudonym_two_fingerprint" cluster-pseudonym-activate $((base + 22))
for port in $((base + 10)) $((base + 11)) $((base + 12)); do
	test "$(curl_data_code "http://127.0.0.1:${port}/v1/messages" "$secret_three")" = 200
done
source_scopes_after="$(curl -fsS "http://127.0.0.1:$((base + 21))/admin/metrics" -H "Authorization: Bearer ${operator_token}" | sed -n 's/^gripline_resource_source_scopes \([0-9][0-9]*\)$/\1/p')"
test "$source_scopes_after" = "$source_scopes_before"

# Global concurrency cap is five. Fifteen requests enter via the LB and the
# backend's independently tracked active-work peak must never exceed five.
mkdir -p "$harness_dir/codes"
work_pids=()
for i in $(seq 1 15); do
	curl -sS -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:${lb_port}/v1/work" \
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
# Keep one status per file. Without the newline, concurrent curl outputs such
# as 503403200 become one awk field and a successful request is miscounted.
if [[ "$(awk '$1 == 200 {n++} END {print n+0}' "$harness_dir/codes"/*)" -lt 1 ]]; then
	echo "cluster harness: no work request completed through the LB" >&2
	exit 1
fi

# A revoke committed through A must deny on the other two authorities.
provision cluster-credential-four "$secret_four"
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

# Lockdown committed through B must be observed by A, B, and C. Use the
# freshly provisioned credential: emergency lockdown intentionally denies new
# lanes, while an already-established lane may continue serving according to
# the documented posture contract.
lockdown_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 21))/admin/posture" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-lockdown' \
	--data '{"on":true,"reason":"cluster lockdown"}')"
test "$lockdown_code" = 200
for port in $((base + 10)) $((base + 11)) $((base + 12)); do
	wait_data_denied "http://127.0.0.1:${port}/v1/messages" "$secret_four"
done
unlock_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/posture" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-unlock' \
	--data '{"on":false,"reason":"cluster harness continues"}')"
test "$unlock_code" = 200

# Policy activation and rollback through A must propagate to B and C via the
# watcher; each node's backend-visible assertion revision is checked directly.
candidate="$(<"$harness_dir/candidate.json")"
old_response_file="$harness_dir/old-response.json"
old_response_code=000
for _ in $(seq 1 240); do
old_response_code="$(curl -sS -o "$old_response_file" -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/messages" -H "Authorization: Bearer ${secret_four}" -d '{}' 2>/dev/null || true)"
	if [[ "$old_response_code" == 200 ]]; then break; fi
	sleep 0.5
done
if [[ "$old_response_code" != 200 ]]; then
	echo "cluster harness: fresh lifecycle credential never received a successful response (last status ${old_response_code})" >&2
	cat "$old_response_file" >&2 || true
	exit 1
fi
old_response="$(<"$old_response_file")"
printf '%s\n' "$old_response" | rg -q '"policy_revision":1'
printf '%s\n' "$old_response" | rg -q '"policy_epoch":1'
prepare_payload="$(printf '{"artifact":%s,"reason":"cluster policy canary"}' "$candidate")"
missing_policy_operation_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/policy/prepare" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	--data "$prepare_payload")"
test "$missing_policy_operation_code" = 400
prepare_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/policy/prepare" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-policy-prepare' \
	--data "$prepare_payload")"
test "$prepare_code" = 200
activate_code=400
for _ in $(seq 1 120); do
	activate_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/policy/activate" \
		-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
		-H 'Idempotency-Key: cluster-policy-activate' \
		--data '{"reason":"cluster policy canary"}')"
	if [[ "$activate_code" == "200" ]]; then
		break
	fi
	sleep 0.1
done
test "$activate_code" = 200
printf '2\n' >"$policy_epoch_file"
	for port in $((base + 10)) $((base + 11)) $((base + 12)); do
		wait_assertion_policy "$port" "$secret_four" 2 2
	done
rollback_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/policy/rollback" \
	-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
	-H 'Idempotency-Key: cluster-policy-rollback' \
	--data '{"revision":1,"reason":"cluster rollback canary"}')"
test "$rollback_code" = 200
printf '3\n' >"$policy_epoch_file"
	for port in $((base + 10)) $((base + 11)) $((base + 12)); do
		wait_assertion_policy "$port" "$secret_four" 1 3
	done

# Run load only after deterministic lifecycle checks have converged. Security
# mode intentionally exercises hard limits. Capacity mode raises only the
# disposable fixture's ceilings and uses persistent clients so its measurements
# describe actual gateway/PostgreSQL behavior rather than curl process churn.
if [[ "$load_seconds" -gt 0 ]]; then
	load_dir="$harness_dir/cluster-load"
	mkdir -p "$load_dir"
	if [[ "$load_mode" == security ]]; then
		load_end_epoch=$(( $(date +%s) + load_seconds ))
		load_secrets=("$secret_two" "$secret_three" "$secret_four")
		load_worker() {
			local worker=$1 result_file="$load_dir/worker-${1}.tsv"
			local secret_index=$(( (worker - 1) % ${#load_secrets[@]} ))
			local load_secret="${load_secrets[$secret_index]}"
			local started ended code
			: >"$result_file"
			while [[ "$(date +%s)" -lt "$load_end_epoch" ]]; do
				started="$(date +%s%N)"
				code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
					-H "Authorization: Bearer ${load_secret}" -d '{}' 2>/dev/null || true)"
				ended="$(date +%s%N)"
				printf '%s\t%s\n' "${code:-000}" "$((ended - started))" >>"$result_file"
			done
		}
		load_pids=()
		for worker in $(seq 1 "$load_workers"); do
			load_worker "$worker" &
			load_pids+=("$!")
		done
		for pid in "${load_pids[@]}"; do
			wait "$pid" || true
		done
		cat "$load_dir"/*.tsv >"$load_dir/results.tsv"
		load_samples="$(wc -l <"$load_dir/results.tsv")"
		if [[ "$load_samples" -lt 1 ]]; then
			echo "cluster harness: security load produced no samples" >&2
			exit 1
		fi
		load_successes="$(awk -F '\t' '$1 == 200 {n++} END {print n+0}' "$load_dir/results.tsv")"
		awk -F '\t' '$1 == 200 {print $2}' "$load_dir/results.tsv" | sort -n >"$load_dir/success-latencies.ns"
		success_count="$(wc -l <"$load_dir/success-latencies.ns")"
		if [[ "$load_successes" -lt 1 ]]; then
			echo "cluster harness: security load had no successful requests" >&2
			exit 1
		fi
		load_p50_ns="$(awk -v n="$success_count" 'NR == int((n * 50 + 99) / 100) {print; exit}' "$load_dir/success-latencies.ns")"
		load_p95_ns="$(awk -v n="$success_count" 'NR == int((n * 95 + 99) / 100) {print; exit}' "$load_dir/success-latencies.ns")"
		load_success_rate="$(awk -v successes="$load_successes" -v seconds="$load_seconds" 'BEGIN {printf "%.2f", successes / seconds}')"
		printf 'cluster harness: security load samples=%s successes=%s success_per_sec=%s p50_ns=%s p95_ns=%s workers=%s seconds=%s\n' \
			"$load_samples" "$load_successes" "$load_success_rate" "$load_p50_ns" "$load_p95_ns" "$load_workers" "$load_seconds"
		if [[ "$load_p95_ns" -gt "$load_p95_limit_ns" ]]; then
			echo "cluster harness: security-load p95 ${load_p95_ns}ns exceeded ${load_p95_limit_ms}ms limit" >&2
			exit 1
		fi
	else
		capacity_secrets=()
		for worker in $(seq 1 "$load_workers"); do
			capacity_id="cluster-capacity-$(printf '%02d' "$worker")"
			capacity_secret="cluster-capacity-secret-$(printf '%02d' "$worker")-0123456789abcdef"
			provision "$capacity_id" "$capacity_secret"
			capacity_secrets+=("$capacity_secret")
		done
		capacity_secret_list="$(IFS=,; printf '%s' "${capacity_secrets[*]}")"
		# Seed the exact feature vector used by the persistent load clients. The
		# normal lifecycle probes use curl, while the capacity driver intentionally
		# identifies itself as a stable qualification client; prewarming avoids
		# turning throughput measurement into a new-lane/security-classification
		# test.
		for worker in "${!capacity_secrets[@]}"; do
			secret="${capacity_secrets[$worker]}"
			source_address="127.0.0.$((worker + 2))"
			curl -fsS -o /dev/null -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
				--interface "$source_address" \
				-H "Authorization: Bearer ${secret}" -H "User-Agent: ${load_user_agent}" -d '{}'
		done
		for node in a b c; do
			case "$node" in
				a) admin_port=$((base + 20));;
				b) admin_port=$((base + 21));;
				c) admin_port=$((base + 22));;
			esac
			curl -fsS "http://127.0.0.1:${admin_port}/admin/metrics" -H "Authorization: Bearer ${operator_token}" >"$load_dir/metrics-before-${node}.prom"
		done
		load_args=(
			-url "http://127.0.0.1:${lb_port}/v1/messages"
			-secrets "$capacity_secret_list"
			-duration "${load_seconds}s"
			-workers "$load_workers"
			-timeout "$load_timeout"
			-user-agent "$load_user_agent"
			-local-address-prefix "127.0.0."
		)
		"$harness_dir/load" "${load_args[@]}" >"$load_dir/capacity.json"
		for node in a b c; do
			case "$node" in
				a) admin_port=$((base + 20));;
				b) admin_port=$((base + 21));;
				c) admin_port=$((base + 22));;
			esac
			curl -fsS "http://127.0.0.1:${admin_port}/admin/metrics" -H "Authorization: Bearer ${operator_token}" >"$load_dir/metrics-after-${node}.prom"
		done
		metric_value() { awk -v key="gripline_$1" '$1 == key {print $2; exit}' "$2"; }
		fleet_metric_delta() {
			local metric=$1 total=0 before after
			for node in a b c; do
				before="$(metric_value "$metric" "$load_dir/metrics-before-${node}.prom")"
				after="$(metric_value "$metric" "$load_dir/metrics-after-${node}.prom")"
				total="$(awk -v total="$total" -v before="${before:-0}" -v after="${after:-0}" 'BEGIN {printf "%.6f", total + (after+0) - (before+0)}')"
			done
			printf '%s' "$total"
		}
		serialization_retries="$(fleet_metric_delta postgres_serialization_retries_total)"
		deadlock_retries="$(fleet_metric_delta postgres_deadlock_retries_total)"
		transaction_retries="$(awk -v serialization="$serialization_retries" -v deadlock="$deadlock_retries" 'BEGIN {printf "%.0f", serialization + deadlock}')"
		authority_timeouts="$(fleet_metric_delta postgres_authority_timeouts_total)"
		source_alias_resolutions="$(fleet_metric_delta postgres_source_alias_resolutions_total)"
		source_alias_registrations="$(fleet_metric_delta postgres_source_alias_registrations_total)"
		source_alias_conflicts="$(fleet_metric_delta postgres_source_alias_conflicts_total)"
		source_alias_failures="$(fleet_metric_delta postgres_source_alias_resolution_failures_total)"
		source_alias_latency="$(fleet_metric_delta postgres_source_alias_resolution_seconds_total)"
		adaptive_window_retries="$(fleet_metric_delta postgres_transaction_retries_adaptive_window_total)"
		adaptive_baseline_retries="$(fleet_metric_delta postgres_transaction_retries_adaptive_baseline_total)"
		lane_borrow_retries="$(fleet_metric_delta postgres_transaction_retries_lane_borrow_total)"
		lane_risk_retries="$(fleet_metric_delta postgres_transaction_retries_lane_risk_total)"
		credential_retries="$(fleet_metric_delta postgres_transaction_retries_credential_total)"
		resource_retries="$(fleet_metric_delta postgres_transaction_retries_resource_total)"
		other_retries="$(fleet_metric_delta postgres_transaction_retries_other_total)"
		cat >"$load_dir/postgres-metrics.json" <<EOF
{
  "serialization_retries": ${serialization_retries},
  "deadlock_retries": ${deadlock_retries},
  "transaction_retries": ${transaction_retries},
  "authority_timeouts": ${authority_timeouts},
  "source_alias_resolutions": ${source_alias_resolutions},
  "source_alias_registrations": ${source_alias_registrations},
  "source_alias_conflicts": ${source_alias_conflicts},
  "source_alias_failures": ${source_alias_failures},
  "source_alias_resolution_seconds": ${source_alias_latency},
  "operation_retries": {
    "adaptive_window": ${adaptive_window_retries},
    "adaptive_baseline": ${adaptive_baseline_retries},
    "lane_borrow": ${lane_borrow_retries},
    "lane_risk": ${lane_risk_retries},
    "credential": ${credential_retries},
    "resource": ${resource_retries},
    "other": ${other_retries}
  }
}
EOF
		python3 - "$load_dir/capacity.json" "$load_dir/postgres-metrics.json" "$operation_timeout" <<'PY'
import json
import re
import sys

load_path, postgres_path, timeout_text = sys.argv[1:]
with open(load_path, encoding="utf-8") as stream:
    load = json.load(stream)
with open(postgres_path, encoding="utf-8") as stream:
    postgres = json.load(stream)
match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", timeout_text)
if not match:
    raise SystemExit(f"unsupported operation timeout {timeout_text!r}")
value = float(match.group(1))
scale = {"ms": 1, "s": 1000, "m": 60000, "h": 3600000}[match.group(2)]
load["authority_operation_timeout_ms"] = int(value * scale)
load["source_resolution_failures"] = int(float(postgres.get("source_alias_failures", 0)))
load["authority_timeouts"] = int(float(postgres.get("authority_timeouts", 0)))
load["transaction_retries"] = int(float(postgres.get("transaction_retries", 0)))
load["deadlocks"] = int(float(postgres.get("deadlock_retries", 0)))
load["source_alias_resolution_seconds"] = float(postgres.get("source_alias_resolution_seconds", 0.0))
with open(load_path, "w", encoding="utf-8") as stream:
    json.dump(load, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
		printf 'cluster harness: capacity load metrics=%s pg_pool_wait_seconds=%s transaction_retries=%s transaction_latency_seconds=%s\n' \
			"$(cat "$load_dir/capacity.json")" \
			"$(fleet_metric_delta postgres_pool_empty_acquire_wait_seconds)" \
			"$transaction_retries" \
			"$(fleet_metric_delta postgres_transaction_latency_seconds_total)"
		capacity_validation_rc=0
		python3 "$repo_dir/scripts/qualification/validate-capacity.py" "$load_dir/capacity.json" "$capacity_min_success_ratio" "$load_dir/postgres-metrics.json" || capacity_validation_rc=$?
		if [[ -n "${GRIPLINE_CLUSTER_HARNESS_CAPACITY_EVIDENCE_FILE:-}" ]]; then
			install -D -m 0600 "$load_dir/capacity.json" "$GRIPLINE_CLUSTER_HARNESS_CAPACITY_EVIDENCE_FILE"
		fi
		if (( capacity_validation_rc != 0 )); then
			exit "$capacity_validation_rc"
		fi
	fi
fi

# The shared authority is a fail-closed dependency. CI supplies the PostgreSQL
# service container; local runs may omit it when Docker is unavailable, but the
# CI/release jobs set REQUIRE_DB_OUTAGE so this cannot silently become optional
# in the release gate.
postgres_container="${GRIPLINE_TEST_POSTGRES_CONTAINER:-}"
if [[ "${GRIPLINE_CLUSTER_HARNESS_SKIP_OUTAGE:-0}" != "1" && -z "$postgres_container" ]] && command -v docker >/dev/null 2>&1; then
	postgres_container="$(docker ps --filter 'ancestor=postgres:16' --format '{{.ID}}' | head -n 1 || true)"
fi
if [[ -z "$postgres_container" ]]; then
	if [[ "${GRIPLINE_CLUSTER_HARNESS_REQUIRE_DB_OUTAGE:-0}" == "1" ]]; then
		echo "cluster harness: PostgreSQL container is required for outage acceptance" >&2
		exit 1
	fi
	echo "cluster harness: PostgreSQL outage acceptance skipped (set GRIPLINE_TEST_POSTGRES_CONTAINER or run with a postgres:16 container)" >&2
else
	backend_capture_before=0
	if [[ -f "$harness_dir/backend-capture.log" ]]; then
		backend_capture_before="$(wc -l <"$harness_dir/backend-capture.log")"
	fi
	if [[ -n "${GRIPLINE_CLUSTER_HARNESS_OUTAGE_MARKER_FILE:-}" ]]; then
		printf '%s\n' "$(date +%s)" >"$GRIPLINE_CLUSTER_HARNESS_OUTAGE_MARKER_FILE"
	fi
	docker stop "$postgres_container" >/dev/null
	for port in $((base + 10)) $((base + 11)) $((base + 12)); do
		for _ in $(seq 1 60); do
			status="$(curl --max-time 2 -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/readyz" 2>/dev/null || true)"
			if [[ "$status" != "200" ]]; then
				break
			fi
			sleep 0.1
		done
		test "$status" != "200"
		test "$(curl_data_code "http://127.0.0.1:${port}/v1/messages" "$secret_two")" != "200"
	done
	backend_capture_after=0
	if [[ -f "$harness_dir/backend-capture.log" ]]; then
		backend_capture_after="$(wc -l <"$harness_dir/backend-capture.log")"
	fi
	if [[ "$backend_capture_after" != "$backend_capture_before" ]]; then
		echo "cluster harness: protected traffic reached backend while PostgreSQL was unavailable" >&2
		exit 1
	fi
	docker start "$postgres_container" >/dev/null
	for port in $((base + 10)) $((base + 11)) $((base + 12)); do
		if ! wait_status "http://127.0.0.1:${port}/readyz"; then
			echo "cluster harness: node on port ${port} did not recover after PostgreSQL restart" >&2
			for node in a b c; do cat "$harness_dir/gripline-${node}.log" >&2 2>/dev/null || true; done
			cat "${GRIPLINE_CLUSTER_WRITER_LOG:-/dev/null}" >&2 2>/dev/null || true
			exit 1
		fi
	done
	wait_status "http://127.0.0.1:${lb_port}/readyz"
fi

# A killed replica with in-flight work must cancel the upstream request. The
# fixture's active-work counter measures backend work, not merely proxy
# sockets; this proves the concurrency cap is released only after cancellation
# reaches the actual backend operation.
if [[ "${GRIPLINE_CLUSTER_HARNESS_SKIP_KILLED_NODE:-0}" != "1" ]]; then
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
fi

# A long-soak coordinator can hold the complete live cluster here, promote its
# PostgreSQL replica, and send protected traffic through the still-running
# Gripline nodes before allowing this harness to exit. This keeps failover
# qualification attached to real gateway processes rather than a DB-only test.
if [[ -n "${GRIPLINE_CLUSTER_HARNESS_PAUSE_FILE:-}" ]]; then
	touch "$GRIPLINE_CLUSTER_HARNESS_PAUSE_FILE"
	while [[ ! -f "${GRIPLINE_CLUSTER_HARNESS_RELEASE_FILE:-}" ]]; do
		sleep 1
	done
fi

echo "cluster harness: three-node PostgreSQL invariants passed"
