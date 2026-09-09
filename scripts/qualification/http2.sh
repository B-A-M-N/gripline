#!/usr/bin/env bash
set -euo pipefail

# Start a real TLS-enabled Gripline process with a local provider-shaped
# backend, then run the protocol harness against the actual ALPN/HTTP2 stack.
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
for command_name in go openssl curl python3 nghttp; do
	command -v "$command_name" >/dev/null || { echo "HTTP2 qualification: $command_name is required" >&2; exit 2; }
done

gateway_port=$((19300 + ($$ % 500)))
backend_port=$((gateway_port + 1))
admin_port=$((gateway_port + 2))
secret="http2-qualification-secret-0123456789abcdef0123456789"
operator_token="http2-qualification-operator-0123456789abcdef0123456789"
pepper="$(openssl rand -base64 32 | tr -d '\n')"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=127.0.0.1' \
	-addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' -keyout "$work_dir/server.key" -out "$work_dir/server.pem" >/dev/null 2>&1

GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/gripline" ./cmd/gripline
GOCACHE="${GOCACHE:-/tmp/gripline-go-cache}" go build -trimpath -o "$work_dir/http2-client" ./cmd/gripline-test-http2
GRIPLINE_LOCAL_BACKEND_PORT="$backend_port" python3 "$repo_dir/qualification/sdk/local_backend.py" >/dev/null 2>&1 &
backend_pid=$!
cat >"$work_dir/config.json" <<EOF
{
  "listen": "127.0.0.1:${gateway_port}",
  "tls": {"cert_file": "${work_dir}/server.pem", "key_file": "${work_dir}/server.key", "min_version": "1.2"},
  "backend": {"url": "http://127.0.0.1:${backend_port}", "timeout": "10s", "allowed_endpoints": [{"method": "POST", "path": "/v1/messages"}]},
  "server": {"read_timeout": "10s", "write_timeout": "10s", "idle_timeout": "10s", "read_header_timeout": "5s", "stream_write_idle_timeout": "2s", "max_header_bytes": 65536, "max_body_bytes": 1048576, "http2_max_concurrent_streams": 64, "http2_header_table_bytes": 65536, "http2_max_read_frame_bytes": 1048576, "http2_max_upload_buffer_per_connection": 1048576, "http2_max_upload_buffer_per_stream": 65536, "spool_dir": "${work_dir}/spool", "spool_max_bytes": 1048576, "spool_max_files": 8},
  "identity": {"audience": "http2-qualification"},
  "secrets": {"pepper_versions": {"1": "${pepper}"}},
  "admin": {"listen": "127.0.0.1:${admin_port}", "operator_tokens": {"${operator_token}": "harness:credential.lifecycle,audit.read"}},
  "paths": {"state": "${work_dir}/state.db", "signer_keyring": "${work_dir}/keyring.json"},
  "deployment": {"allow_ephemeral_state": false}
}
EOF
"$work_dir/gripline" -config "$work_dir/config.json" >"$work_dir/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 60); do
	if curl --cacert "$work_dir/server.pem" -fsS "https://127.0.0.1:${gateway_port}/readyz" >/dev/null 2>&1; then break; fi
	sleep 0.2
done
curl --cacert "$work_dir/server.pem" -fsS "https://127.0.0.1:${gateway_port}/readyz" >/dev/null || { cat "$work_dir/gateway.log" >&2; exit 1; }
printf '%s\n' "$secret" | GRIPLINE_OPERATOR_TOKEN="$operator_token" "$work_dir/gripline" credential add --config "$work_dir/config.json" --id http2-qualification --account http2-qualification --policy gripline-default-v1 --plan http2-qualification --reason "reference HTTP2 qualification" --secret-stdin >/dev/null
GRIPLINE_H2_QUALIFICATION=1 GRIPLINE_H2_LOAD_REQUIRED="${GRIPLINE_H2_LOAD_REQUIRED:-1}" GRIPLINE_H2_EXPECT_MAX_STREAMS=64 GRIPLINE_H2_EXPECT_HEADER_TABLE=65536 bash "$repo_dir/scripts/security-http2-harness.sh" "https://127.0.0.1:${gateway_port}/v1/messages" "$secret" "$work_dir/server.pem"
"$work_dir/http2-client" -url "https://127.0.0.1:${gateway_port}/v1/messages" -ca "$work_dir/server.pem" -bearer "$secret"
metrics="$(curl -fsS "http://127.0.0.1:${admin_port}/admin/metrics" -H "Authorization: Bearer ${operator_token}")"
h2_errors="$(printf '%s\n' "$metrics" | awk '$1 == "gripline_http2_errors_total" {print $2}')"
[[ "$h2_errors" =~ ^[0-9]+$ ]] || { echo "HTTP2 qualification: missing HTTP/2 error metric" >&2; exit 1; }
if command -v h2load >/dev/null; then
	echo "HTTP2 qualification: direct TLS/ALPN, stream bounds, cancellation/recovery, header-table churn, CONTINUATION, error metrics, and h2load cases passed"
else
	echo "HTTP2 qualification: direct TLS/ALPN, stream bounds, cancellation/recovery, header-table churn, CONTINUATION, and error metrics passed; h2load deferred"
fi
