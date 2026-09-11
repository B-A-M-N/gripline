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
for command in curl docker go openssl psql python3 grep awk sed tr; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "cluster harness: required command not found: $command" >&2
		exit 2
	}
done
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
source_alias_retention="${GRIPLINE_CLUSTER_HARNESS_SOURCE_ALIAS_RETENTION:-${GRIPLINE_CLUSTER_HARNESS_RETENTION_WINDOW:-1m}}"
if [[ "${GRIPLINE_CLUSTER_HARNESS_COMPRESSED_RETENTION:-0}" == "1" ]]; then
	retention_window="${GRIPLINE_CLUSTER_HARNESS_RETENTION_WINDOW:-1m}"
	maintenance_interval="${GRIPLINE_CLUSTER_HARNESS_MAINTENANCE_INTERVAL:-1h}"
	maintenance_config=", \"maintenance\": {\"interval\":\"${maintenance_interval}\",\"batch_size\":256,\"max_batches_per_pass\":64,\"max_rows_per_pass\":4096,\"max_runtime_per_pass\":\"5s\",\"evidence_grace\":\"0s\",\"released_lease_retention\":\"${retention_window}\",\"credential_receipt_retention\":\"${retention_window}\",\"control_operation_retention\":\"${retention_window}\",\"admission_audit_retention\":\"${retention_window}\",\"security_transition_retention\":\"${retention_window}\",\"operator_audit_retention\":\"${retention_window}\",\"policy_audit_retention\":\"${retention_window}\",\"membership_retention\":\"1h\",\"adaptive_retention\":\"1h\",\"evidence_guard_retention\":\"${retention_window}\",\"lane_operator_audit_retention\":\"${retention_window}\",\"policy_node_state_retention\":\"1h\",\"cluster_crypto_ack_retention\":\"1h\",\"source_alias_retention\":\"${source_alias_retention}\"}"
fi
max_conns="${GRIPLINE_CLUSTER_HARNESS_MAX_CONNS:-8}"
operation_timeout="${GRIPLINE_CLUSTER_HARNESS_OPERATION_TIMEOUT:-2s}"
load_timeout="${GRIPLINE_CLUSTER_HARNESS_LOAD_TIMEOUT:-10s}"
load_user_agent="${GRIPLINE_CLUSTER_HARNESS_LOAD_USER_AGENT:-gripline-qualification-load/1}"
backend_work_delay="${GRIPLINE_CLUSTER_HARNESS_WORK_DELAY:-2s}"
source_churn_enabled="${GRIPLINE_CLUSTER_HARNESS_SOURCE_CHURN:-0}"
source_scope_limit="${GRIPLINE_CLUSTER_HARNESS_SOURCE_SCOPE_LIMIT:-4096}"
source_alias_identity_limit="${GRIPLINE_CLUSTER_HARNESS_MAX_SOURCE_ALIAS_IDENTITIES:-4096}"
resource_denial_mode="${GRIPLINE_CLUSTER_HARNESS_RESOURCE_DENIAL:-0}"
preauth_max_sources="${GRIPLINE_CLUSTER_HARNESS_PREAUTH_MAX_SOURCES:-10000}"
maintenance_bin="${GRIPLINE_CLUSTER_HARNESS_MAINTENANCE_BIN:-}"
source_churn_authenticated_sources=0
source_churn_secrets=()
ingress_extra=""
if [[ "$load_mode" == capacity ]]; then
	# The disposable load balancer is the only trusted proxy in this fixture.
	# Capacity workers bind distinct loopback addresses. Trust the complete
	# loopback range because the LB appends each worker's loopback peer to the
	# forwarding chain; otherwise that transport hop would replace the intended
	# qualification source identity. Same-source contention remains covered by
	# statepg tests.
	ingress_extra=', "trusted_proxies": ["127.0.0.0/8"]'
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
if [[ "$resource_denial_mode" == "1" ]]; then
	setup_args+=(-resource-denial-mode)
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
    "max_source_scopes": ${source_scope_limit}, "preauth_max_sources": ${preauth_max_sources},
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
	    "max_conns": ${max_conns}, "min_conns": 1, "max_source_alias_identities": ${source_alias_identity_limit}${maintenance_config}
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
	-work-delay "$backend_work_delay" \
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

if [[ "$source_churn_enabled" == "1" ]]; then
	if [[ "$load_mode" != capacity ]]; then
		echo "cluster harness: source churn requires capacity load mode" >&2
		exit 2
	fi
	command -v psql >/dev/null || { echo "cluster harness: psql is required for source churn" >&2; exit 2; }
	source_churn_invalid_sources="${GRIPLINE_CLUSTER_HARNESS_INVALID_SOURCES:-10000}"
	source_churn_authenticated_sources="${GRIPLINE_CLUSTER_HARNESS_AUTHENTICATED_SOURCES:-16}"
	source_churn_workers="${GRIPLINE_CLUSTER_HARNESS_SOURCE_CHURN_WORKERS:-32}"
	source_churn_adaptive_subject_bound="${GRIPLINE_CLUSTER_HARNESS_ADAPTIVE_MAX_SUBJECTS:-65536}"
	source_churn_adaptive_key_bound="${GRIPLINE_CLUSTER_HARNESS_ADAPTIVE_MAX_KEYS:-256}"
	if ! [[ "$source_churn_invalid_sources" =~ ^[1-9][0-9]*$ && "$source_churn_authenticated_sources" =~ ^[1-9][0-9]*$ && "$source_churn_workers" =~ ^[1-9][0-9]*$ && "$source_scope_limit" =~ ^[1-9][0-9]*$ && "$source_alias_identity_limit" =~ ^[1-9][0-9]*$ && "$preauth_max_sources" =~ ^[1-9][0-9]*$ && "$source_churn_adaptive_subject_bound" =~ ^[1-9][0-9]*$ && "$source_churn_adaptive_key_bound" =~ ^[1-9][0-9]*$ ]]; then
		echo "cluster harness: source churn bounds must be positive integers" >&2
		exit 2
	fi
	if (( source_alias_identity_limit < source_churn_authenticated_sources + 3 )); then
		echo "cluster harness: source alias identity bound must allow authenticated sources plus three churn fixtures" >&2
		exit 2
	fi
	for index in $(seq 0 $((source_churn_authenticated_sources - 1))); do
		source_churn_secret="source-churn-secret-${index}-0123456789"
		provision "source-churn-credential-${index}" "$source_churn_secret"
		source_churn_secrets+=("$source_churn_secret")
	done
	source_churn_revoked_secret="source-churn-revoked-secret-0123456789"
	provision source-churn-revoked-credential "$source_churn_revoked_secret"
	source_churn_overbound_secrets=()
	for index in 0 1; do
		source_churn_secret="source-churn-overbound-secret-${index}-0123456789"
		provision "source-churn-overbound-credential-${index}" "$source_churn_secret"
		source_churn_overbound_secrets+=("$source_churn_secret")
	done
	source_sql() { psql "$dsn" -X -Atqc "$1"; }
	source_metric_sum() {
		local metric=$1 total=0 port value
		for port in $((base + 20)) $((base + 21)) $((base + 22)); do
			value="$(curl -fsS "http://127.0.0.1:${port}/admin/metrics" -H "Authorization: Bearer ${operator_token}" | awk -v name="gripline_${metric}" '$1 == name {print $2; exit}')"
			total=$((total + ${value:-0}))
		done
		printf '%s\n' "$total"
	}
	source_metric_max() {
		local metric=$1 max=0 port value
		for port in $((base + 20)) $((base + 21)) $((base + 22)); do
			value="$(curl -fsS "http://127.0.0.1:${port}/admin/metrics" -H "Authorization: Bearer ${operator_token}" | awk -v name="gripline_${metric}" '$1 == name {print $2; exit}')"
			if [[ "${value:-0}" =~ ^[0-9]+$ ]] && (( value > max )); then max=$value; fi
		done
		printf '%s\n' "$max"
	}
	source_churn_aliases_before="$(source_sql 'SELECT COUNT(*) FROM gripline_source_aliases')"
	source_churn_backend_before=0
	if [[ -f "$harness_dir/backend-capture.log" ]]; then source_churn_backend_before="$(wc -l <"$harness_dir/backend-capture.log")"; fi
	source_churn_invalid_dir="$harness_dir/source-churn-invalid"
	mkdir -p "$source_churn_invalid_dir"
	source_churn_invalid_worker() {
		local worker=$1 file="$source_churn_invalid_dir/worker-$1.tsv" i octet2 octet3 octet4 ip code
		: >"$file"
		for ((i = worker; i < source_churn_invalid_sources; i += source_churn_workers)); do
			octet2=$(((i + 1) / 65536))
			octet3=$((((i + 1) / 256) % 256))
			octet4=$(((i + 1) % 256))
			ip="10.${octet2}.${octet3}.${octet4}"
			if code="$(curl --connect-timeout 2 --max-time 5 -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
				-H "X-Forwarded-For: ${ip}" -H "Authorization: Bearer invalid-source-churn-secret" -d '{}' 2>/dev/null)"; then
				code="${code:-000}"
			else
				code=000
			fi
			printf '%s\n' "$code" >>"$file"
		done
	}
	source_churn_invalid_pids=()
	for worker in $(seq 0 $((source_churn_workers - 1))); do
		source_churn_invalid_worker "$worker" &
		source_churn_invalid_pids+=("$!")
	done
	for pid in "${source_churn_invalid_pids[@]}"; do wait "$pid" || true; done
	source_churn_invalid_results="$harness_dir/source-churn-invalid.tsv"
	cat "$source_churn_invalid_dir"/*.tsv >"$source_churn_invalid_results"
	source_churn_invalid_requests_attempted="$source_churn_invalid_sources"
	source_churn_invalid_requests_completed="$(awk '$1 != 000 {n++} END {print n+0}' "$source_churn_invalid_results")"
	source_churn_invalid_401="$(awk '$1 == 401 {n++} END {print n+0}' "$source_churn_invalid_results")"
	source_churn_invalid_429="$(awk '$1 == 429 {n++} END {print n+0}' "$source_churn_invalid_results")"
	source_churn_invalid_transport_errors="$(awk '$1 == 000 {n++} END {print n+0}' "$source_churn_invalid_results")"
	source_churn_invalid_unexpected_statuses="$(awk '$1 != 000 && $1 != 401 && $1 != 429 {n++} END {print n+0}' "$source_churn_invalid_results")"
	source_churn_aliases_after_invalid="$(source_sql 'SELECT COUNT(*) FROM gripline_source_aliases')"
	source_churn_adaptive_subjects_after_invalid="$(source_sql 'SELECT COUNT(*) FROM gripline_adaptive_window_subjects')"
	source_churn_adaptive_keys_after_invalid="$(source_sql 'SELECT COUNT(*) FROM gripline_adaptive_window_keys')"
	source_churn_adaptive_baselines_after_invalid="$(source_sql 'SELECT COUNT(*) FROM gripline_adaptive_baselines')"
	source_churn_adaptive_rows_after_invalid=$((source_churn_adaptive_subjects_after_invalid + source_churn_adaptive_keys_after_invalid + source_churn_adaptive_baselines_after_invalid))
	source_churn_preauth_entries_peak="$(source_metric_max preauth_source_table_entries)"
	source_churn_backend_after_invalid=0
	if [[ -f "$harness_dir/backend-capture.log" ]]; then source_churn_backend_after_invalid="$(wc -l <"$harness_dir/backend-capture.log")"; fi
	source_churn_backend_hits_from_invalid=$((source_churn_backend_after_invalid - source_churn_backend_before))
	if [[ "$source_churn_invalid_requests_completed" != "$source_churn_invalid_requests_attempted" || "$source_churn_invalid_transport_errors" != 0 || "$source_churn_invalid_unexpected_statuses" != 0 || $((source_churn_invalid_401 + source_churn_invalid_429)) != "$source_churn_invalid_requests_completed" || "$source_churn_aliases_after_invalid" != "$source_churn_aliases_before" || "$source_churn_adaptive_subjects_after_invalid" -gt "$source_churn_adaptive_subject_bound" || "$source_churn_adaptive_keys_after_invalid" -gt $((source_churn_adaptive_subject_bound * source_churn_adaptive_key_bound)) || "$source_churn_adaptive_baselines_after_invalid" -gt "$source_churn_adaptive_subject_bound" || "$source_churn_backend_hits_from_invalid" != 0 ]]; then
		echo "cluster harness: invalid source churn violated read-only/isolated behavior" >&2
		exit 1
	fi

	source_churn_revoked_revoke_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/credentials/revoke" \
		-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
		-H 'Idempotency-Key: source-churn-revoke-known' \
		--data '{"credential_id":"source-churn-revoked-credential","reason":"source churn revoked-known proof"}')"
	if [[ "$source_churn_revoked_revoke_code" != 200 ]]; then
		echo "cluster harness: revoke-known source-churn fixture failed with ${source_churn_revoked_revoke_code}" >&2
		exit 1
	fi
	source_churn_revoked_aliases_before="$(source_sql 'SELECT COUNT(*) FROM gripline_source_aliases')"
	source_churn_revoked_requests=8
	source_churn_revoked_dir="$harness_dir/source-churn-revoked"
	mkdir -p "$source_churn_revoked_dir"
	for index in $(seq 1 "$source_churn_revoked_requests"); do
		if code="$(curl --connect-timeout 2 --max-time 5 -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
			-H "X-Forwarded-For: 13.0.0.${index}" -H "Authorization: Bearer ${source_churn_revoked_secret}" -d '{}' 2>/dev/null)"; then
			code="${code:-000}"
		else
			code=000
		fi
		printf '%s\n' "$code" >"$source_churn_revoked_dir/$index"
	done
	source_churn_revoked_completed="$(awk '$1 != 000 {n++} END {print n+0}' "$source_churn_revoked_dir"/*)"
	source_churn_revoked_401="$(awk '$1 == 401 {n++} END {print n+0}' "$source_churn_revoked_dir"/*)"
	source_churn_revoked_403="$(awk '$1 == 403 {n++} END {print n+0}' "$source_churn_revoked_dir"/*)"
	source_churn_revoked_transport_errors="$(awk '$1 == 000 {n++} END {print n+0}' "$source_churn_revoked_dir"/*)"
	source_churn_revoked_unexpected_statuses="$(awk '$1 != 000 && $1 != 401 && $1 != 403 {n++} END {print n+0}' "$source_churn_revoked_dir"/*)"
	source_churn_revoked_aliases_after="$(source_sql 'SELECT COUNT(*) FROM gripline_source_aliases')"
	if [[ "$source_churn_revoked_completed" != "$source_churn_revoked_requests" || $((source_churn_revoked_401 + source_churn_revoked_403)) != "$source_churn_revoked_requests" || "$source_churn_revoked_transport_errors" != 0 || "$source_churn_revoked_unexpected_statuses" != 0 || "$source_churn_revoked_aliases_after" != "$source_churn_revoked_aliases_before" ]]; then
		echo "cluster harness: revoked known-credential churn was not denied without alias binding" >&2
		exit 1
	fi

	source_churn_valid_dir="$harness_dir/source-churn-valid"
	mkdir -p "$source_churn_valid_dir"
	source_churn_valid_worker() {
		local index=$1 ip="11.0.0.$((index + 1))" code valid_secret="${source_churn_secrets[$index]}"
		code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
			-H "X-Forwarded-For: ${ip}" -H "Authorization: Bearer ${valid_secret}" -d '{}' 2>/dev/null || true)"
		printf '%s\n' "${code:-000}" >"$source_churn_valid_dir/$index"
	}
	source_churn_valid_pids=()
	for index in $(seq 0 $((source_churn_authenticated_sources - 1))); do
		source_churn_valid_worker "$index" &
		source_churn_valid_pids+=("$!")
	done
	for pid in "${source_churn_valid_pids[@]}"; do wait "$pid" || true; done
	source_churn_valid_successes="$(awk '$1 == 200 {n++} END {print n+0}' "$source_churn_valid_dir"/*)"
	source_churn_valid_failures="$(awk '$1 != 200 {n++} END {print n+0}' "$source_churn_valid_dir"/*)"
	source_churn_aliases_before_valid="$(source_sql 'SELECT COUNT(DISTINCT canonical_source_id) FROM gripline_source_aliases')"
	if [[ "$source_churn_valid_successes" != "$source_churn_authenticated_sources" || "$source_churn_valid_failures" != 0 || "$source_churn_aliases_before_valid" != "$source_churn_authenticated_sources" ]]; then
		echo "cluster harness: authenticated first-seen source churn did not register cleanly" >&2
		exit 1
	fi
	source_churn_resource_denied_dir="$harness_dir/source-churn-resource-denied"
	mkdir -p "$source_churn_resource_denied_dir"
	source_churn_resource_denied_worker() {
		local index=$1 code
		if code="$(curl --connect-timeout 2 --max-time 8 -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${lb_port}/v1/work" \
			-H 'X-Forwarded-For: 11.0.0.1' -H "Authorization: Bearer ${source_churn_secrets[0]}" 2>/dev/null)"; then
			code="${code:-000}"
		else
			code=000
		fi
		printf '%s\n' "$code" >"$source_churn_resource_denied_dir/$index"
	}
	source_churn_resource_denied_pids=()
	for index in 1 2; do
		source_churn_resource_denied_worker "$index" &
		source_churn_resource_denied_pids+=("$!")
	done
	for pid in "${source_churn_resource_denied_pids[@]}"; do wait "$pid" || true; done
	source_churn_resource_denied_attempted=2
	source_churn_resource_denied_completed="$(awk '$1 != 000 {n++} END {print n+0}' "$source_churn_resource_denied_dir"/*)"
	source_churn_resource_denied_authorized="$(awk '$1 == 200 {n++} END {print n+0}' "$source_churn_resource_denied_dir"/*)"
	source_churn_resource_denied_denials="$(awk '$1 == 429 {n++} END {print n+0}' "$source_churn_resource_denied_dir"/*)"
	source_churn_resource_denied_transport_errors="$(awk '$1 == 000 {n++} END {print n+0}' "$source_churn_resource_denied_dir"/*)"
	source_churn_resource_denied_unexpected_statuses="$(awk '$1 != 000 && $1 != 200 && $1 != 429 {n++} END {print n+0}' "$source_churn_resource_denied_dir"/*)"
	if [[ "$source_churn_resource_denied_completed" != "$source_churn_resource_denied_attempted" || "$source_churn_resource_denied_authorized" != 1 || "$source_churn_resource_denied_denials" != 1 || "$source_churn_resource_denied_transport_errors" != 0 || "$source_churn_resource_denied_unexpected_statuses" != 0 ]]; then
		echo "cluster harness: valid resource-denied source-churn proof did not produce one authorization and one denial" >&2
		exit 1
	fi
	source_churn_overflow_code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
		-H 'X-Forwarded-For: 12.0.0.1' -H "Authorization: Bearer ${secret_one}" -d '{}' 2>/dev/null || true)"
	source_churn_source_scopes_after_valid="$(source_sql "SELECT COUNT(*) FROM gripline_resource_source_scopes WHERE scope_id NOT LIKE '__source_overflow_%'")"
	source_churn_source_scopes_after_overflow="$(source_sql 'SELECT COUNT(*) FROM gripline_resource_source_scopes')"
	source_churn_source_overflows="$(source_sql "SELECT COUNT(DISTINCT scope_id) FROM gripline_resource_buckets WHERE scope=0 AND scope_id LIKE '__source_overflow_%'")"
	source_churn_source_aliases_created="$source_churn_aliases_before_valid"
	if [[ "$source_churn_overflow_code" != 200 || "$source_churn_source_scopes_after_valid" -gt "$source_scope_limit" || "$source_churn_source_overflows" -lt 1 ]]; then
		echo "cluster harness: source-scope overflow behavior failed" >&2
		exit 1
	fi
	stale_alias_before=0
	source_sql "INSERT INTO gripline_source_aliases (canonical_source_id, alias, generation, created_at, last_seen_at) VALUES ('source-churn-stale', 'source-churn-stale-v1', 1, CURRENT_TIMESTAMP - INTERVAL '8 days', CURRENT_TIMESTAMP - INTERVAL '8 days') ON CONFLICT (alias) DO NOTHING" >/dev/null
	# Keep the reference rows current while the alias itself is stale. This
	# prevents compressed retention from deleting the references before the
	# bound assertion; the rows are removed immediately after that assertion so
	# the later maintenance check still proves safe reclamation.
	source_sql "INSERT INTO gripline_adaptive_window_subjects (detector, subject, last_seen_at) VALUES ('source_novelty_source', 'source-churn-stale', CURRENT_TIMESTAMP) ON CONFLICT (detector, subject) DO NOTHING" >/dev/null
	source_sql "INSERT INTO gripline_adaptive_window_keys (detector, subject, observation_key, observed_at) VALUES ('source_novelty_source', 'source-churn-stale', 'source-churn-stale', CURRENT_TIMESTAMP) ON CONFLICT (detector, subject, observation_key) DO NOTHING" >/dev/null
	if [[ "$(source_sql "SELECT COUNT(*) FROM gripline_source_aliases WHERE alias='source-churn-stale-v1'")" == 1 ]]; then
		stale_alias_before=1
	fi
	source_churn_overbound_first_code="$(curl --connect-timeout 2 --max-time 5 -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
		-H 'X-Forwarded-For: 12.0.0.2' -H "Authorization: Bearer ${source_churn_overbound_secrets[0]}" -d '{}' 2>/dev/null || true)"
	if source_churn_overbound_code="$(curl --connect-timeout 2 --max-time 5 -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
		-H 'X-Forwarded-For: 12.0.0.3' -H "Authorization: Bearer ${source_churn_overbound_secrets[1]}" -d '{}' 2>/dev/null)"; then
		source_churn_overbound_code="${source_churn_overbound_code:-000}"
	else
		source_churn_overbound_code=000
	fi
	source_churn_authenticated_over_bound_requests=2
	source_churn_authenticated_over_bound_successes=0
	if [[ "$source_churn_overbound_first_code" == 200 ]]; then source_churn_authenticated_over_bound_successes=1; fi
	source_churn_authenticated_over_bound_denials=0
	if [[ "$source_churn_overbound_code" == 503 ]]; then source_churn_authenticated_over_bound_denials=1; fi
	source_churn_authenticated_over_bound_unexpected=0
	if [[ "$source_churn_overbound_code" != 503 ]]; then source_churn_authenticated_over_bound_unexpected=1; fi
	source_churn_source_alias_identities_after_over_bound="$(source_sql 'SELECT COUNT(DISTINCT canonical_source_id) FROM gripline_source_aliases')"
	source_churn_source_alias_rows_after_over_bound="$(source_sql 'SELECT COUNT(*) FROM gripline_source_aliases')"
	if [[ "$source_churn_overbound_first_code" != 200 || "$source_churn_overbound_code" != 503 || "$source_churn_authenticated_over_bound_unexpected" != 0 || "$source_churn_source_alias_identities_after_over_bound" -gt "$source_alias_identity_limit" ]]; then
		echo "cluster harness: authenticated source churn did not fail closed at the durable alias bound (first=${source_churn_overbound_first_code} second=${source_churn_overbound_code} identities=${source_churn_source_alias_identities_after_over_bound} rows=${source_churn_source_alias_rows_after_over_bound} bound=${source_alias_identity_limit})" >&2
		exit 1
	fi
	source_sql "DELETE FROM gripline_adaptive_window_keys WHERE detector='source_novelty_source' AND subject='source-churn-stale' AND observation_key='source-churn-stale'" >/dev/null
	source_sql "DELETE FROM gripline_adaptive_window_subjects WHERE detector='source_novelty_source' AND subject='source-churn-stale'" >/dev/null
fi

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
printf '%s\n' "$pre_rotation_assertion" | grep -q '"policy_revision":1'
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
	if [[ "$retire_code" != "409" ]] || ! grep -q '"safe_after"' "$harness_dir/signer-retirement-body"; then
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
			grep -q '"policy_revision":'"${revision}" "$response" &&
			grep -q '"policy_epoch":'"${epoch}" "$response"; then
			return 0
		fi
		# A node can briefly forward the request while its policy/verifier
		# watcher is converging. The reference backend's exact response is a
		# bounded transient; invalid credentials and every other 401 remain
		# terminal failures.
		if [[ "$status" == 401 ]] && ! grep -qx 'assertion required' "$response"; then
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
			if printf '%s' "$status" | grep -Eq "\"${kind}_active_(version|kid)\":${generation}"; then
				break
			fi
			sleep 0.1
		done
		printf '%s' "$status" | grep -Eq "\"${kind}_active_(version|kid)\":${generation}"
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
expected_pepper_one_count=2
	if [[ "$source_churn_enabled" == "1" ]]; then
		expected_pepper_one_count=$((expected_pepper_one_count + source_churn_authenticated_sources + 3))
	fi
printf '%s' "$pepper_counts" | grep -q "\"1\":${expected_pepper_one_count}"
printf '%s' "$pepper_counts" | grep -q '"2":1'
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

if [[ "$source_churn_enabled" == "1" ]]; then
	source_churn_rotation_dir="$harness_dir/source-churn-rotation"
	mkdir -p "$source_churn_rotation_dir"
	source_churn_rotation_worker() {
		local index=$1 ip="11.0.0.$((index + 1))" code rotation_secret="${source_churn_secrets[$index]}"
		code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
			-H "X-Forwarded-For: ${ip}" -H "Authorization: Bearer ${rotation_secret}" -d '{}' 2>/dev/null || true)"
		printf '%s\n' "${code:-000}" >"$source_churn_rotation_dir/$index"
	}
	source_churn_rotation_pids=()
	for index in $(seq 0 $((source_churn_authenticated_sources - 1))); do
		source_churn_rotation_worker "$index" &
		source_churn_rotation_pids+=("$!")
	done
	for pid in "${source_churn_rotation_pids[@]}"; do wait "$pid" || true; done
	source_churn_rotation_successes="$(awk '$1 == 200 {n++} END {print n+0}' "$source_churn_rotation_dir"/*)"
	source_churn_rotation_failures="$(awk '$1 != 200 {n++} END {print n+0}' "$source_churn_rotation_dir"/*)"
	source_churn_source_scopes_after_rotation="$(source_sql "SELECT COUNT(*) FROM gripline_resource_source_scopes WHERE scope_id NOT LIKE '__source_overflow_%'")"
	if [[ "$source_churn_rotation_successes" != "$source_churn_authenticated_sources" || "$source_churn_rotation_failures" != 0 || "$source_churn_source_scopes_after_rotation" != "$source_churn_source_scopes_after_valid" ]]; then
		echo "cluster harness: source alias rotation overlap lost canonical/resource continuity" >&2
		exit 1
	fi
	source_churn_stale_aliases_after=1
	for _ in $(seq 1 60); do
		if [[ -n "$maintenance_bin" ]]; then
			"$maintenance_bin" -dsn "$dsn" -batch-size 256 -history-retention "${GRIPLINE_CLUSTER_HARNESS_RETENTION_WINDOW:-1m}" -source-alias-retention "${GRIPLINE_CLUSTER_HARNESS_SOURCE_ALIAS_RETENTION:-${GRIPLINE_CLUSTER_HARNESS_RETENTION_WINDOW:-1m}}" >"$harness_dir/source-churn-maintenance.log" 2>&1 || {
				cat "$harness_dir/source-churn-maintenance.log" >&2
				exit 1
			}
		fi
		source_churn_stale_aliases_after="$(source_sql "SELECT COUNT(*) FROM gripline_source_aliases WHERE alias='source-churn-stale-v1'")"
		if [[ "$source_churn_stale_aliases_after" == 0 ]]; then break; fi
		sleep 1
	done
	if [[ "$source_churn_stale_aliases_after" != 0 ]]; then
		echo "cluster harness: source alias maintenance did not reclaim stale unreferenced identity" >&2
		exit 1
	fi
	source_churn_source_scopes_peak="$source_churn_source_scopes_after_overflow"
	if [[ "$source_churn_source_scopes_after_rotation" -gt "$source_churn_source_scopes_peak" ]]; then
		source_churn_source_scopes_peak="$source_churn_source_scopes_after_rotation"
	fi
	source_churn_source_resolution_failures_total="$(source_metric_sum postgres_source_alias_resolution_failures_total)"
	source_churn_expected_source_resolution_failures=1
	source_churn_resolution_failures=$((source_churn_source_resolution_failures_total - source_churn_expected_source_resolution_failures))
	source_churn_authority_timeouts="$(source_metric_sum postgres_authority_timeouts_total)"
	source_churn_source_alias_capacity_denials="$(source_metric_sum postgres_source_alias_capacity_denials_total)"
	source_churn_source_alias_saturations="$(source_metric_sum postgres_source_alias_saturations_total)"
	source_churn_source_alias_safe_evictions="$(source_metric_sum postgres_source_alias_safe_evictions_total)"
	if [[ -n "${GRIPLINE_CLUSTER_HARNESS_SOURCE_CHURN_EVIDENCE_FILE:-}" ]]; then
		cat >"$GRIPLINE_CLUSTER_HARNESS_SOURCE_CHURN_EVIDENCE_FILE" <<EOF
{
  "invalid_sources": ${source_churn_invalid_sources},
  "invalid_requests_attempted": ${source_churn_invalid_requests_attempted},
  "invalid_requests_completed": ${source_churn_invalid_requests_completed},
  "invalid_401": ${source_churn_invalid_401},
  "invalid_429": ${source_churn_invalid_429},
  "invalid_transport_errors": ${source_churn_invalid_transport_errors},
  "invalid_unexpected_statuses": ${source_churn_invalid_unexpected_statuses},
  "aliases_before": ${source_churn_aliases_before},
  "aliases_after_invalid": ${source_churn_aliases_after_invalid},
  "adaptive_rows_after_invalid": ${source_churn_adaptive_rows_after_invalid},
  "adaptive_subjects_after_invalid": ${source_churn_adaptive_subjects_after_invalid},
  "adaptive_keys_after_invalid": ${source_churn_adaptive_keys_after_invalid},
  "adaptive_baselines_after_invalid": ${source_churn_adaptive_baselines_after_invalid},
  "adaptive_subject_bound": ${source_churn_adaptive_subject_bound},
  "adaptive_key_bound": ${source_churn_adaptive_key_bound},
  "preauth_source_table_entries_peak": ${source_churn_preauth_entries_peak},
  "preauth_source_table_bound": ${preauth_max_sources},
  "backend_hits_from_invalid": ${source_churn_backend_hits_from_invalid},
  "revoked_requests_attempted": ${source_churn_revoked_requests},
  "revoked_requests_completed": ${source_churn_revoked_completed},
  "revoked_401": ${source_churn_revoked_401},
  "revoked_403": ${source_churn_revoked_403},
  "revoked_transport_errors": ${source_churn_revoked_transport_errors},
  "revoked_unexpected_statuses": ${source_churn_revoked_unexpected_statuses},
  "revoked_aliases_before": ${source_churn_revoked_aliases_before},
  "revoked_aliases_after": ${source_churn_revoked_aliases_after},
  "resource_denied_attempted": ${source_churn_resource_denied_attempted},
  "resource_denied_completed": ${source_churn_resource_denied_completed},
  "resource_denied_authorized": ${source_churn_resource_denied_authorized},
  "resource_denied_denials": ${source_churn_resource_denied_denials},
  "resource_denied_transport_errors": ${source_churn_resource_denied_transport_errors},
  "resource_denied_unexpected_statuses": ${source_churn_resource_denied_unexpected_statuses},
	"authenticated_aliases_created": ${source_churn_aliases_before_valid},
  "authenticated_source_requests": ${source_churn_valid_successes},
  "authenticated_source_failures": ${source_churn_valid_failures},
  "authenticated_over_bound_attempted": ${source_churn_authenticated_over_bound_requests},
  "authenticated_over_bound_successes": ${source_churn_authenticated_over_bound_successes},
  "authenticated_over_bound_denials": ${source_churn_authenticated_over_bound_denials},
  "source_alias_identity_bound": ${source_alias_identity_limit},
  "source_alias_identities_after_over_bound": ${source_churn_source_alias_identities_after_over_bound},
  "source_alias_rows_after_over_bound": ${source_churn_source_alias_rows_after_over_bound},
  "source_alias_capacity_denials": ${source_churn_source_alias_capacity_denials},
  "source_alias_saturations": ${source_churn_source_alias_saturations},
  "source_alias_safe_evictions": ${source_churn_source_alias_safe_evictions},
  "source_scope_bound": ${source_scope_limit},
  "source_scopes_peak": ${source_churn_source_scopes_peak},
  "source_scope_overflows": ${source_churn_source_overflows},
  "rotation_source_scopes_before": ${source_churn_source_scopes_after_valid},
  "rotation_source_scopes_after": ${source_churn_source_scopes_after_rotation},
  "stale_aliases_before_maintenance": ${stale_alias_before},
  "stale_aliases_after_maintenance": ${source_churn_stale_aliases_after},
  "source_resolution_failures": ${source_churn_resolution_failures},
  "authority_timeouts": ${source_churn_authority_timeouts}
}
EOF
	fi
fi

# Security mode's global concurrency cap is five. Fifteen requests enter via
# the LB and the backend's independently tracked active-work peak must never
# exceed five; capacity mode deliberately raises this fixture ceiling.
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
if [[ "$load_mode" == security && "$peak" -gt 5 ]]; then
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
printf '%s\n' "$old_response" | grep -q '"policy_revision":1'
printf '%s\n' "$old_response" | grep -q '"policy_epoch":1'
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
rollback_code=000
if [[ "$load_mode" == security || "$source_churn_enabled" != "1" ]]; then
	rollback_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/policy/rollback" \
		-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
		-H 'Idempotency-Key: cluster-policy-rollback' \
		--data '{"revision":1,"reason":"cluster rollback canary"}')"
	test "$rollback_code" = 200
	printf '3\n' >"$policy_epoch_file"
		for port in $((base + 10)) $((base + 11)) $((base + 12)); do
			wait_assertion_policy "$port" "$secret_four" 1 3
		done
fi

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
			capacity_source_headers=()
			if [[ "$source_churn_enabled" == "1" ]]; then
				capacity_source_headers=(-H "X-Forwarded-For: 11.0.0.$((worker + 1))")
			fi
			curl -fsS -o /dev/null -X POST "http://127.0.0.1:${lb_port}/v1/messages" \
				--interface "$source_address" \
				"${capacity_source_headers[@]}" \
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
		if [[ "$source_churn_enabled" == "1" ]]; then
			load_args+=( -forwarded-for-prefix "11.0.0." )
		fi
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
	if [[ "$source_churn_enabled" == "1" ]]; then
		# Source churn starts with a one-request fixture to prove a real
		# resource denial. The revision-2 canary is the high-ceiling capacity
		# policy, so capacity load runs only after that policy converges.
		rollback_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((base + 20))/admin/policy/rollback" \
			-H "Authorization: Bearer ${operator_token}" -H 'Content-Type: application/json' \
			-H 'Idempotency-Key: cluster-policy-rollback' \
			--data '{"revision":1,"reason":"cluster rollback canary"}')"
		test "$rollback_code" = 200
		printf '3\n' >"$policy_epoch_file"
		for port in $((base + 10)) $((base + 11)) $((base + 12)); do
			wait_assertion_policy "$port" "$secret_four" 1 3
		done
	fi
fi

# The shared authority is a fail-closed dependency. CI supplies the PostgreSQL
# service container; local runs may omit it when Docker is unavailable, but the
# CI/release jobs set REQUIRE_DB_OUTAGE so this cannot silently become optional
# in the release gate.
postgres_container="${GRIPLINE_TEST_POSTGRES_CONTAINER:-}"
if [[ "${GRIPLINE_CLUSTER_HARNESS_SKIP_OUTAGE:-0}" != "1" && -z "$postgres_container" ]] && command -v docker >/dev/null 2>&1; then
	# GitHub service containers and local fixtures may expose the same pinned
	# image as either postgres:16 or postgres:16@sha256:<digest>. Match the
	# running image reference directly so the required outage proof does not
	# silently depend on Docker's tag-only ancestor filter.
	postgres_container="$(docker ps --format '{{.ID}}\t{{.Image}}' | awk -F '\t' '$2 ~ /^postgres:16(@sha256:[0-9a-f]{64})?$/ {print $1; exit}' || true)"
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

# Readiness is a serving invariant, but the first post-outage authority lookup
# can still be completing while the node transitions back to READY. Converge a
# protected request on the node used by the cancellation probe before asking it
# to hold a long-running backend operation.
if [[ "${GRIPLINE_CLUSTER_HARNESS_SKIP_KILLED_NODE:-0}" != "1" ]]; then
	post_recovery_code=000
	for _ in $(seq 1 60); do
		post_recovery_code="$(curl_data_code "http://127.0.0.1:$((base + 12))/v1/messages" "$secret_two")"
		if [[ "$post_recovery_code" == "200" ]]; then
			break
		fi
		sleep 0.1
	done
	if [[ "$post_recovery_code" != "200" ]]; then
		echo "cluster harness: post-recovery protected request did not converge on killed-node target" >&2
		exit 1
	fi
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
