#!/usr/bin/env bash
set -euo pipefail

# Build a local provider-shaped backend, put the real Gripline gateway in
# front of it, install the official Python and TypeScript SDKs, and exercise
# both OpenAI and Anthropic paths without provider accounts.
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

command -v go >/dev/null || { echo "SDK qualification: go is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "SDK qualification: python3 is required" >&2; exit 2; }
command -v npm >/dev/null || { echo "SDK qualification: npm is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "SDK qualification: openssl is required" >&2; exit 2; }

base_port=$((19100 + ($$ % 400)))
backend_port=$((base_port + 8))
secret="sdk-qualification-secret-0123456789abcdef0123456789"
operator_token="sdk-qualification-operator-0123456789abcdef0123456789"
pepper="$(openssl rand -base64 32 | tr -d '\n')"

GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/gripline" ./cmd/gripline
GRIPLINE_LOCAL_BACKEND_PORT="$backend_port" python3 "$repo_dir/qualification/sdk/local_backend.py" >/dev/null 2>&1 &
backend_pid=$!

IFS=',' read -r -a providers <<<"${GRIPLINE_SDK_PROVIDERS:-openai,anthropic}"
venv="$work_dir/venv"
python3 -m venv "$venv"
"$venv/bin/pip" install --disable-pip-version-check -q -r "$repo_dir/qualification/sdk/python/requirements.lock"

ts_dir="$work_dir/typescript"
cp -R "$repo_dir/qualification/sdk/typescript" "$ts_dir"
npm ci --prefix "$ts_dir" --ignore-scripts --no-audit --no-fund --silent
for index in "${!providers[@]}"; do
	provider="${providers[$index]}"
	case "$provider" in
		openai)
			mode=openai
			allowed='{"method":"POST","path":"/v1/chat/completions"},{"method":"POST","path":"/v1/responses"},{"method":"POST","path":"/v1/embeddings"},{"method":"GET","path":"/v1/models"}'
			expected_usage='{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}'
			profiles=(chat responses embeddings models)
		;;
		anthropic)
			mode=anthropic
			allowed='{"method":"POST","path":"/v1/messages"}'
			expected_usage='{"input_tokens":3,"output_tokens":2}'
			profiles=(messages)
		;;
		*) echo "SDK qualification: unsupported provider $provider" >&2; exit 2 ;;
	esac
	gateway_port=$((base_port + index * 10))
	admin_port=$((gateway_port + 1))
	config="$work_dir/config-${provider}.json"
	cat >"$config" <<EOF
{
  "listen": "127.0.0.1:${gateway_port}",
  "tls": {"terminate_tls_upstream": true},
  "backend": {"url": "http://127.0.0.1:${backend_port}", "timeout": "10s", "allowed_endpoints": [${allowed}]},
  "server": {"read_timeout": "10s", "write_timeout": "10s", "idle_timeout": "10s", "read_header_timeout": "5s", "stream_write_idle_timeout": "2s", "max_body_bytes": 1048576, "spool_dir": "${work_dir}/spool-${provider}", "spool_max_bytes": 1048576, "spool_max_files": 8},
  "identity": {"audience": "sdk-qualification-${provider}"},
  "secrets": {"pepper_versions": {"1": "${pepper}"}},
	  "usage": {"mode": "${mode}", "cost_mode": "conservative", "input_microunits_per_token": 2, "output_microunits_per_token": 3, "cache_read_microunits_per_token": 5, "cache_creation_microunits_per_token": 7, "cache_creation_5m_microunits_per_token": 7, "cache_creation_1h_microunits_per_token": 9, "default_output_tokens": 2, "max_output_tokens": 64},
  "admin": {"listen": "127.0.0.1:${admin_port}", "operator_tokens": {"${operator_token}": "harness:credential.lifecycle,audit.read"}},
  "paths": {"state": "${work_dir}/state-${provider}.db", "signer_keyring": "${work_dir}/keyring-${provider}.json"},
  "deployment": {"allow_ephemeral_state": false}
}
EOF
	"$work_dir/gripline" -config "$config" >"$work_dir/gateway-${provider}.log" 2>&1 &
	gateway_pid=$!
	for _ in $(seq 1 60); do
		if curl -fsS "http://127.0.0.1:${gateway_port}/readyz" >/dev/null 2>&1; then break; fi
		sleep 0.2
	done
	curl -fsS "http://127.0.0.1:${gateway_port}/readyz" >/dev/null || { cat "$work_dir/gateway-${provider}.log" >&2; exit 1; }
	printf '%s\n' "$secret" | GRIPLINE_OPERATOR_TOKEN="$operator_token" "$work_dir/gripline" credential add --config "$config" --id sdk-qualification --account sdk-qualification --policy gripline-default-v1 --plan sdk-qualification --reason "reference SDK qualification" --secret-stdin >/dev/null
	sdk_env=(GRIPLINE_SDK_BASE_URL="http://127.0.0.1:${gateway_port}/v1" GRIPLINE_SDK_ANTHROPIC_BASE_URL="http://127.0.0.1:${gateway_port}" GRIPLINE_SDK_API_KEY="$secret" GRIPLINE_SDK_MODEL="local-qualification" GRIPLINE_SDK_EXPECT_USAGE=1 GRIPLINE_SDK_EXPECT_USAGE_JSON="$expected_usage" GRIPLINE_SDK_MAX_SECONDS=30)
	metric_value() { awk -v name="gripline_$2" '$1 == name {print $2}' "$1"; }
	run_sdk_case() {
		local label=$1 expect_input=$2 expect_output=$3
		shift 3
		local before="$work_dir/${provider}-${label}-before.metrics" after="$work_dir/${provider}-${label}-after.metrics"
		curl -fsS "http://127.0.0.1:${admin_port}/admin/metrics" -H "Authorization: Bearer ${operator_token}" >"$before"
		"$@"
		curl -fsS "http://127.0.0.1:${admin_port}/admin/metrics" -H "Authorization: Bearer ${operator_token}" >"$after"
		local sessions_before sessions_after input_before input_after output_before output_after
		sessions_before="$(metric_value "$before" usage_sessions_total)"; sessions_after="$(metric_value "$after" usage_sessions_total)"
		input_before="$(metric_value "$before" usage_input_tokens_total)"; input_after="$(metric_value "$after" usage_input_tokens_total)"
		output_before="$(metric_value "$before" usage_output_tokens_total)"; output_after="$(metric_value "$after" usage_output_tokens_total)"
		[[ "$sessions_before" =~ ^[0-9]+$ && "$sessions_after" =~ ^[0-9]+$ && $((sessions_after - sessions_before)) -ge 1 ]] || { echo "SDK qualification: ${label} did not create a settled per-case session" >&2; exit 1; }
		if (( expect_input > 0 )); then [[ $((input_after - input_before)) -ge expect_input ]] || { echo "SDK qualification: ${label} input delta was too small" >&2; exit 1; }; fi
		if (( expect_output > 0 )); then [[ $((output_after - output_before)) -ge expect_output ]] || { echo "SDK qualification: ${label} output delta was too small" >&2; exit 1; }; fi
	}
	for profile in "${profiles[@]}"; do
		case "$profile" in
			chat) profile_usage="$expected_usage"; streams=(0 1) ;;
			responses) profile_usage='{"input_tokens":3,"output_tokens":2,"total_tokens":5}'; streams=(0 1) ;;
			embeddings) profile_usage='{"prompt_tokens":3,"total_tokens":3}'; streams=(0) ;;
			models) profile_usage=''; streams=(0) ;;
			messages) profile_usage="$expected_usage"; streams=(0 1) ;;
			*) echo "SDK qualification: unsupported profile $profile" >&2; exit 2 ;;
		esac
		for stream in "${streams[@]}"; do
			profile_env=(GRIPLINE_SDK_PROFILE="$profile" GRIPLINE_SDK_STREAM="$stream" GRIPLINE_SDK_EXPECT_USAGE_JSON="$profile_usage")
			[[ "$profile" == models ]] && profile_env+=(GRIPLINE_SDK_EXPECT_USAGE=0) || profile_env+=(GRIPLINE_SDK_EXPECT_USAGE=1)
			expect_input=3; expect_output=2
			[[ "$profile" == models ]] && expect_input=0 && expect_output=0
			[[ "$profile" == embeddings ]] && expect_output=0
			run_sdk_case "profile-${profile}-py-${stream}" "$expect_input" "$expect_output" env "${sdk_env[@]}" "${profile_env[@]}" "$venv/bin/python" "$repo_dir/qualification/sdk/python/runner.py" "$provider"
			run_sdk_case "profile-${profile}-ts-${stream}" "$expect_input" "$expect_output" env "${sdk_env[@]}" "${profile_env[@]}" node "$ts_dir/runner.mjs" "$provider"
		done
	done
	# Failure and concurrency cases use the same pinned official clients. The
	# local backend selects the deterministic case by model suffix, so no
	# provider account or out-of-tree mock service is involved.
	for scenario in tool large retry connection parallel; do
		extra=(GRIPLINE_SDK_SCENARIO="$scenario" GRIPLINE_SDK_STREAM=0)
		case "$scenario" in
			connection) extra+=(GRIPLINE_SDK_REQUESTS=4) ;;
			parallel) extra+=(GRIPLINE_SDK_PARALLEL=4) ;;
		esac
		env "${sdk_env[@]}" "${extra[@]}" "$venv/bin/python" "$repo_dir/qualification/sdk/python/runner.py" "$provider"
		env "${sdk_env[@]}" "${extra[@]}" node "$ts_dir/runner.mjs" "$provider"
	done
	for scenario in server-error cancel; do
		failure_env=(GRIPLINE_SDK_SCENARIO="$scenario" GRIPLINE_SDK_STREAM=0)
		[[ "$scenario" == cancel ]] && failure_env+=(GRIPLINE_SDK_MAX_SECONDS=1)
		for language in python typescript; do
			failure_log="$work_dir/${provider}-${language}-${scenario}.log"
			if [[ "$language" == python ]]; then
				if env "${sdk_env[@]}" "${failure_env[@]}" "$venv/bin/python" "$repo_dir/qualification/sdk/python/runner.py" "$provider" >"$failure_log" 2>&1; then
					cat "$failure_log" >&2
					echo "SDK qualification: $provider Python $scenario unexpectedly succeeded" >&2
					exit 1
				fi
			else
				if env "${sdk_env[@]}" "${failure_env[@]}" node "$ts_dir/runner.mjs" "$provider" >"$failure_log" 2>&1; then
					cat "$failure_log" >&2
					echo "SDK qualification: $provider TypeScript $scenario unexpectedly succeeded" >&2
					exit 1
				fi
			fi
		done
	done
	metrics="$(curl -fsS "http://127.0.0.1:${admin_port}/admin/metrics" -H "Authorization: Bearer ${operator_token}")"
	metric() { printf '%s\n' "$metrics" | awk -v name="gripline_$1" '$1 == name {print $2}'; }
	echo "SDK qualification metrics ($provider): sessions=$(metric usage_sessions_total) input=$(metric usage_input_tokens_total) output=$(metric usage_output_tokens_total) combined=$(metric usage_combined_tokens_total) cost=$(metric usage_cost_microunits_total) backend4xx=$(metric backend_4xx_total) backend5xx=$(metric backend_5xx_total)"
	test "$(metric usage_sessions_total)" -ge 20
	test "$(metric usage_input_tokens_total)" -ge 78
	test "$(metric usage_output_tokens_total)" -ge 52
	test "$(metric usage_combined_tokens_total)" -ge 130
	test "$(metric usage_cost_microunits_total)" -ge 312
	test "$(metric backend_5xx_total)" -ge 2
	kill -TERM "$gateway_pid" >/dev/null 2>&1 || true
	wait "$gateway_pid" >/dev/null 2>&1 || true
	gateway_pid=""
done
echo "SDK qualification: official Python/TypeScript provider clients, tools, large input, retry/429, 5xx, cancellation, reuse, and parallel cases passed"
