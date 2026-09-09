#!/usr/bin/env bash
set -euo pipefail

# Repository-owned exact-cost gate. A local provider-shaped backend emits the
# same bounded usage envelopes as the SDK lab; the real gateway settles them
# in exact mode without a provider account.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d)"
gateway_pid=""
backend_pid=""
cleanup() {
	if [[ -n "$gateway_pid" ]]; then kill -TERM "$gateway_pid" >/dev/null 2>&1 || true; wait "$gateway_pid" >/dev/null 2>&1 || true; fi
	if [[ -n "$backend_pid" ]]; then kill -TERM "$backend_pid" >/dev/null 2>&1 || true; wait "$backend_pid" >/dev/null 2>&1 || true; fi
	rm -rf "$work_dir"
}
trap cleanup EXIT

command -v go >/dev/null || { echo "exact-cost qualification: go is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "exact-cost qualification: python3 is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "exact-cost qualification: curl is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "exact-cost qualification: openssl is required" >&2; exit 2; }

base_port=$((19300 + ($$ % 300)))
backend_port=$((base_port + 8))
secret="exact-cost-qualification-secret-0123456789abcdef"
operator_token="exact-cost-qualification-operator-0123456789abcdef"
pepper="$(openssl rand -base64 32 | tr -d '\n')"

GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/gripline" ./cmd/gripline
GRIPLINE_LOCAL_BACKEND_PORT="$backend_port" python3 "$repo_dir/qualification/sdk/local_backend.py" >/dev/null 2>&1 &
backend_pid=$!
for _ in $(seq 1 60); do
	if curl -sS "http://127.0.0.1:${backend_port}/" >/dev/null 2>&1; then break; fi
	sleep 0.2
	done
start_gateway() {
	local mode=$1 allowed_json=$2
	gateway_port=$3
	admin_port=$4
	local config="$work_dir/config-${mode}.json"
	cat >"$config" <<EOF
{
  "listen": "127.0.0.1:${gateway_port}",
  "tls": {"terminate_tls_upstream": true},
  "backend": {"url": "http://127.0.0.1:${backend_port}", "trust_mode": "private_network", "timeout": "10s", "allowed_endpoints": ${allowed_json}},
  "server": {"read_timeout":"10s","write_timeout":"10s","idle_timeout":"10s","read_header_timeout":"5s"},
  "identity": {"audience":"exact-cost-qualification"},
  "secrets": {"pepper_versions":{"1":"${pepper}"}},
  "usage": {"mode":"${mode}","cost_mode":"exact","input_microunits_per_token":2,"output_microunits_per_token":3,"cache_read_microunits_per_token":5,"cache_creation_microunits_per_token":7,"cache_creation_5m_microunits_per_token":7,"cache_creation_1h_microunits_per_token":9,"default_output_tokens":2,"max_output_tokens":64},
  "admin": {"listen":"127.0.0.1:${admin_port}","operator_tokens":{"${operator_token}":"harness:credential.lifecycle,audit.read"}},
  "paths": {"state":"${work_dir}/state-${mode}.db","signer_keyring":"${work_dir}/keyring-${mode}.json"},
  "deployment": {"allow_ephemeral_state":false}
}
EOF
	"$work_dir/gripline" -config "$config" >"$work_dir/gateway-${mode}.log" 2>&1 &
	gateway_pid=$!
	for _ in $(seq 1 60); do
	if curl -fsS "http://127.0.0.1:${gateway_port}/readyz" >/dev/null 2>&1; then break; fi
	sleep 0.2
	done
	curl -fsS "http://127.0.0.1:${gateway_port}/readyz" >/dev/null || { cat "$work_dir/gateway-${mode}.log" >&2; exit 1; }
	printf '%s\n' "$secret" | GRIPLINE_OPERATOR_TOKEN="$operator_token" "$work_dir/gripline" credential add --config "$config" --id exact-cost --account exact-cost --policy gripline-default-v1 --plan exact-cost --reason "exact cost qualification" --secret-stdin >/dev/null
}

stop_gateway() {
	kill -TERM "$gateway_pid" >/dev/null 2>&1 || true
	wait "$gateway_pid" >/dev/null 2>&1 || true
	gateway_pid=""
}

metric() {
	awk -v name="gripline_$2" '$1 == name {print $2}' "$1"
}
run_case() {
	local name=$1 expected_cost=$2 expected_input=$3 expected_output=$4 expected_combined=$5 path=$6 payload=$7
	local before="$work_dir/${name}.before" after="$work_dir/${name}.after" body="$work_dir/${name}.body"
	curl -fsS "http://127.0.0.1:${admin_port}/admin/metrics" -H "Authorization: Bearer ${operator_token}" >"$before"
	curl --retry 5 --retry-delay 1 --retry-connrefused -fsS -o "$body" -X POST "http://127.0.0.1:${gateway_port}${path}" -H "Authorization: Bearer ${secret}" -H 'Content-Type: application/json' --data "$payload" || { cat "$work_dir/gateway-"*.log >&2; cat "$body" >&2 2>/dev/null || true; exit 1; }
	curl -fsS "http://127.0.0.1:${admin_port}/admin/metrics" -H "Authorization: Bearer ${operator_token}" >"$after"
	local field before_value after_value expected
	for field in usage_sessions_total usage_input_tokens_total usage_output_tokens_total usage_combined_tokens_total usage_cost_microunits_total usage_conservative_settlements_total; do
		before_value="$(metric "$before" "$field")"
		after_value="$(metric "$after" "$field")"
		[[ "$before_value" =~ ^[0-9]+$ && "$after_value" =~ ^[0-9]+$ ]] || { echo "exact-cost qualification: ${name} missing ${field}" >&2; exit 1; }
		case "$field" in
			usage_sessions_total) expected=1 ;;
			usage_input_tokens_total) expected=$expected_input ;;
			usage_output_tokens_total) expected=$expected_output ;;
			usage_combined_tokens_total) expected=$expected_combined ;;
			usage_cost_microunits_total) expected=$expected_cost ;;
			usage_conservative_settlements_total) expected=0 ;;
		esac
		[[ $((after_value - before_value)) -eq "$expected" ]] || { echo "exact-cost qualification: ${name} ${field} delta=$((after_value - before_value)) want=${expected}" >&2; cat "$body" >&2; exit 1; }
	done
}

start_gateway openai '[{"method":"POST","path":"/v1/chat/completions"},{"method":"POST","path":"/v1/responses"},{"method":"POST","path":"/v1/embeddings"}]' "$((base_port + 10))" "$((base_port + 11))"
run_case openai-chat 12 3 2 5 /v1/chat/completions '{"model":"local-qualification","messages":[{"role":"user","content":"hello"}]}'
run_case openai-embeddings 6 3 0 3 /v1/embeddings '{"model":"local-qualification","input":"hello"}'
stop_gateway

start_gateway anthropic '[{"method":"POST","path":"/v1/messages"}]' "$((base_port + 20))" "$((base_port + 21))"
run_case anthropic-messages 12 3 2 5 /v1/messages '{"model":"local-qualification","messages":[{"role":"user","content":"hello"}]}'

# 3*2 + 2*3 + 4*5 + 2*7 + 1*9 = 55 micro-units.
run_case anthropic-cache 55 10 2 12 /v1/messages '{"model":"local-qualification-cache","messages":[{"role":"user","content":"hello"}]}'
stop_gateway

echo "exact-cost qualification: OpenAI, Anthropic, cache dimensions, exact deltas, and zero conservative fallbacks passed"
