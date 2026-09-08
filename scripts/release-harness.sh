#!/usr/bin/env bash
set -euo pipefail

# Black-box release proof: build the gateway and a separate backend process,
# start both from files, export only public verifier keys, and send a real HTTP
# request through the compiled gateway. The backend fixture imports verify/ and
# rejects raw credential carriers, proving the deployed hop is the public
# acceptance path rather than an in-process test double.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness_dir="$(mktemp -d)"
gateway_pid=""
backend_pid=""
cleanup() {
	if [[ -n "$gateway_pid" ]]; then kill -TERM "$gateway_pid" >/dev/null 2>&1 || true; fi
	if [[ -n "$backend_pid" ]]; then kill -TERM "$backend_pid" >/dev/null 2>&1 || true; fi
	if [[ -n "$gateway_pid" ]]; then wait "$gateway_pid" >/dev/null 2>&1 || true; fi
	if [[ -n "$backend_pid" ]]; then wait "$backend_pid" >/dev/null 2>&1 || true; fi
	chmod 0600 "$harness_dir/state.db" "$harness_dir/keyring.json" >/dev/null 2>&1 || true
	chmod 0750 "$harness_dir/spool" >/dev/null 2>&1 || true
	rm -rf "$harness_dir"
}
trap cleanup EXIT

cd "$repo_dir"
gateway_port=$((18080 + ($$ % 500)))
backend_port=$((gateway_port + 1))
admin_port=$((gateway_port + 2))
audience="gripline-release-harness"
secret="harness-secret-1234567890"
operator_token="operator-harness-0123456789abcdef0123456789"
pepper_b64="$(openssl rand -base64 32 | tr -d '\n')"
ca_key="$harness_dir/backend-ca.key"
ca_cert="$harness_dir/backend-ca.pem"
backend_key="$harness_dir/backend-server.key"
backend_csr="$harness_dir/backend-server.csr"
backend_cert="$harness_dir/backend-server.pem"
client_key="$harness_dir/inference-client.key"
client_csr="$harness_dir/inference-client.csr"
client_cert="$harness_dir/inference-client.pem"

# The release fixture uses the same concrete transport-trust shape required by
# a production private backend: the gateway presents an inference client
# certificate, the backend verifies it against a private CA, and the public
# assertion verifier additionally requires the exact client DNS identity.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout "$ca_key" -out "$ca_cert" -subj "/CN=Gripline release harness CA" \
	>/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
	-keyout "$backend_key" -out "$backend_csr" -subj "/CN=backend.internal" \
	-addext "subjectAltName=DNS:backend.internal" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 -copy_extensions copy \
	-in "$backend_csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
	-out "$backend_cert" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
	-keyout "$client_key" -out "$client_csr" -subj "/CN=gripline-inference.internal" \
	-addext "subjectAltName=DNS:gripline-inference.internal" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 -copy_extensions copy \
	-in "$client_csr" -CA "$ca_cert" -CAkey "$ca_key" -CAserial "$harness_dir/backend-ca.srl" \
	-out "$client_cert" >/dev/null 2>&1

go build -trimpath -o "$harness_dir/gripline" ./cmd/gripline
go build -trimpath -o "$harness_dir/backend" ./cmd/gripline-test-backend
go build -trimpath -o "$harness_dir/assertion" ./cmd/gripline-test-assertion

cat > "$harness_dir/config.json" <<EOF
{
  "listen": "127.0.0.1:${gateway_port}",
  "tls": {"terminate_tls_upstream": true},
  "backend": {
    "url": "https://127.0.0.1:${backend_port}",
    "tls": {
      "ca_file": "${ca_cert}",
      "client_cert_file": "${client_cert}",
      "client_key_file": "${client_key}",
      "server_name": "backend.internal",
      "min_version": "1.2"
    },
    "timeout": "5s",
    "allowed_endpoints": [
      {"method": "POST", "path": "/v1/messages"},
      {"method": "GET", "path": "/v1/messages"},
      {"method": "POST", "path": "/v1/echo"},
      {"method": "GET", "path": "/v1/gzip"},
      {"method": "GET", "path": "/v1/stream"},
      {"method": "GET", "path": "/v1/status/429"},
      {"method": "GET", "path": "/v1/status/500"},
      {"method": "GET", "path": "/v1/slow"}
    ]
  },
  "server": {
    "read_timeout": "5s", "write_timeout": "5s", "idle_timeout": "5s",
    "read_header_timeout": "5s", "stream_write_idle_timeout": "1s", "max_body_bytes": 1048576,
    "spool_dir": "${harness_dir}/spool", "spool_max_bytes": 1048576,
    "spool_max_files": 8
  },
  "identity": {"audience": "${audience}"},
  "secrets": {"pepper_versions": {"1": "${pepper_b64}"}},
  "admin": {"listen": "127.0.0.1:${admin_port}", "operator_tokens": {"${operator_token}": "harness:credential.lifecycle,audit.read"}},
  "paths": {"state": "${harness_dir}/state.db", "signer_keyring": "${harness_dir}/keyring.json"},
  "deployment": {"allow_ephemeral_state": false}
}
EOF

"$harness_dir/gripline" -config "$harness_dir/config.json" >"$harness_dir/gateway.log" 2>&1 &
gateway_pid=$!

for _ in $(seq 1 50); do
	if curl -fsS "http://127.0.0.1:${gateway_port}/readyz" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
if ! curl -fsS "http://127.0.0.1:${gateway_port}/readyz" >/dev/null; then
	cat "$harness_dir/gateway.log" >&2
	exit 1
fi

wait_admin() {
	local admin_status=""
	for _ in $(seq 1 50); do
		admin_status="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${admin_port}/admin/metrics" 2>/dev/null || true)"
		if [[ "$admin_status" == "401" ]]; then return 0; fi
		sleep 0.1
	done
	return 1
}

wait_admin

if ! "$harness_dir/gripline" keys export --config "$harness_dir/config.json" >"$harness_dir/keys.json"; then
	cat "$harness_dir/gateway.log" >&2
	exit 1
fi
if rg -n 'private|seed|secret' "$harness_dir/keys.json"; then
	echo "release harness: key export contains private material" >&2
	exit 1
fi

# Provision the credential through the authenticated operator surface. The
# persistent fixture has no bootstrap-secret escape hatch; restart must reuse
# the state database rather than recreate authority from environment input.
if ! printf '%s\n' "$secret" | GRIPLINE_OPERATOR_TOKEN="$operator_token" \
	"$harness_dir/gripline" credential add --config "$harness_dir/config.json" \
	--id harness-credential --account harness-account --policy gripline-default-v1 \
	--plan harness-plan --reason "release harness seed" --secret-stdin \
	>"$harness_dir/provision.log" 2>&1; then
	# Preserve the actionable operator error without allowing a future CLI
	# diagnostic to echo a bearer or credential value into CI logs.
	sed -E 's/[A-Za-z0-9+\/_=-]{32,}/[redacted]/g' "$harness_dir/provision.log" >&2
	exit 1
fi

start_backend() {
	local log_name=$1
	shift
	"$harness_dir/backend" -listen "127.0.0.1:${backend_port}" \
		-tls-cert "$backend_cert" -tls-key "$backend_key" -client-ca "$ca_cert" \
		-require-client-dns "gripline-inference.internal" \
		-keys "$harness_dir/keys.json" -audience "$audience" "$@" \
		>"$harness_dir/${log_name}" 2>&1 &
	backend_pid=$!
}

start_backend backend.log -capture "$harness_dir/backend-capture.log"

backend_curl() {
	curl --cacert "$ca_cert" --cert "$client_cert" --key "$client_key" \
		--resolve "backend.internal:${backend_port}:127.0.0.1" "$@"
}

wait_backend() {
	local backend_ready=""
	for _ in $(seq 1 50); do
		backend_ready="$(backend_curl -sS -o /dev/null -w '%{http_code}' "https://backend.internal:${backend_port}/healthz" 2>/dev/null || true)"
		if [[ "$backend_ready" == "401" ]]; then return 0; fi
		sleep 0.1
	done
	return 1
}

wait_backend
direct_code="$(backend_curl -sS -o /dev/null -w '%{http_code}' "https://backend.internal:${backend_port}/v1/messages" -H "Authorization: Bearer ${secret}")"
test "$direct_code" = "403"

response="$(curl -fsS -X POST "http://127.0.0.1:${gateway_port}/v1/messages" \
	-H "Authorization: Bearer ${secret}" -H 'Content-Type: application/json' \
	--data '{"prompt":"hello"}')"
echo "$response" | rg -q '"authorized":true'
echo "$response" | rg -q '"credential_id":"harness-credential"'

# The compiled gateway is now exercised with raw HTTP/1.1 bytes, including
# ambiguous framing, malformed chunks, duplicate credentials, absolute-form
# targets, traversal, and reserved trailers. The backend capture counter must
# never show more than one request per parser input or any client carrier.
"$repo_dir/scripts/security-http-harness.sh" 127.0.0.1 "$gateway_port" \
	"$harness_dir/backend-capture.log" "$secret" "127.0.0.1:${backend_port}"

# Negative assertion matrix: a separate process creates malformed, forged,
# wrong-audience, and unknown-key assertions. The backend imports only the
# public verify package, so every altered authority is tested at the hop.
for mode in wrong-audience wrong-issuer wrong-kid forged; do
	bad_token="$($harness_dir/assertion -keyring "$harness_dir/keyring.json" -audience "$audience" -mode "$mode")"
	bad_code="$(backend_curl -sS -o /dev/null -w '%{http_code}' "https://backend.internal:${backend_port}/v1/messages" -H "X-Gripline-Assertion: ${bad_token}")"
	test "$bad_code" = "401"
done

# A provider backend can enforce an authoritative policy-revision floor.
kill -TERM "$backend_pid" >/dev/null 2>&1
wait "$backend_pid" >/dev/null 2>&1 || true
backend_pid=""
start_backend backend-revision.log -min-policy-rev 2 -capture "$harness_dir/backend-capture.log"
wait_backend
stale_token="$($harness_dir/assertion -keyring "$harness_dir/keyring.json" -audience "$audience" -mode wrong-revision)"
stale_code="$(backend_curl -sS -o /dev/null -w '%{http_code}' "https://backend.internal:${backend_port}/v1/messages" -H "X-Gripline-Assertion: ${stale_token}")"
test "$stale_code" = "401"
kill -TERM "$backend_pid" >/dev/null 2>&1
wait "$backend_pid" >/dev/null 2>&1 || true
backend_pid=""
start_backend backend.log -capture "$harness_dir/backend-capture.log"
wait_backend

# Query and body fidelity, compressed bytes, SSE/chunk forwarding, provider
# statuses, Retry-After propagation, and oversized-body rejection.
echo "$(curl -fsS -X POST "http://127.0.0.1:${gateway_port}/v1/echo?model=canary&x=1" \
	-H "Authorization: Bearer ${secret}" -H 'Content-Type: application/json' --data '{"prompt":"echo"}')" \
	| rg -q '"query":"model=canary&x=1"'
chunked_response="$(printf '%s' '{"prompt":"chunked"}' | curl -fsS --http1.1 -X POST "http://127.0.0.1:${gateway_port}/v1/echo" \
	-H "Authorization: Bearer ${secret}" -H 'Content-Type: application/json' \
	-H 'Transfer-Encoding: chunked' --data-binary @-)"
echo "$chunked_response" | rg -F -q '"body":"{\"prompt\":\"chunked\"}"'
gzip_file="$harness_dir/gzip.bin"
curl -fsS --raw -o "$gzip_file" "http://127.0.0.1:${gateway_port}/v1/gzip" -H "Authorization: Bearer ${secret}" -H 'Accept-Encoding: gzip'
gzip -dc "$gzip_file" | rg -q '^compressed-body-fidelity$'
curl -fsS --no-buffer "http://127.0.0.1:${gateway_port}/v1/stream" -H "Authorization: Bearer ${secret}" | rg -q 'data: \[DONE\]'
status429="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${gateway_port}/v1/status/429" -H "Authorization: Bearer ${secret}")"
test "$status429" = "429"
status429_headers="$(curl -sS -D - -o /dev/null "http://127.0.0.1:$gateway_port/v1/status/429" -H "Authorization: Bearer $secret")"
echo "$status429_headers" | rg -i -q '^retry-after: 3'
status500="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${gateway_port}/v1/status/500" -H "Authorization: Bearer ${secret}")"
test "$status500" = "502"
# A silent upstream is cut by the configured idle bound; a client-side cancel
# also releases the upstream request and the next request remains healthy.
idle_file="$harness_dir/idle.bin"
: >"$idle_file"
curl -sS --max-time 3 -o "$idle_file" "http://127.0.0.1:${gateway_port}/v1/slow" -H "Authorization: Bearer ${secret}" 2>/dev/null || true
test "$(wc -c <"$idle_file")" -lt 5
if curl -fsS --max-time 0.2 "http://127.0.0.1:${gateway_port}/v1/slow" -H "Authorization: Bearer ${secret}" >/dev/null 2>&1; then
	echo "release harness: client cancellation unexpectedly completed" >&2
	exit 1
fi
head -c 1048577 /dev/zero >"$harness_dir/oversized.bin"
oversized="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${gateway_port}/v1/messages" -H "Authorization: Bearer ${secret}" --data-binary "@$harness_dir/oversized.bin")"
test "$oversized" = "413"

# Backend dial failure is a fail-closed 502; after restart, a second request
# proves connection reuse and the authorization boundary still hold.
kill -TERM "$backend_pid" >/dev/null 2>&1
wait "$backend_pid" >/dev/null 2>&1 || true
backend_pid=""
down_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${gateway_port}/v1/messages" -H "Authorization: Bearer ${secret}")"
test "$down_code" = "502"
start_backend backend.log -capture "$harness_dir/backend-capture.log"
wait_backend
curl -fsS "http://127.0.0.1:${gateway_port}/v1/messages" -H "Authorization: Bearer ${secret}" | rg -q '"authorized":true'

# Kill the compiled gateway without its graceful drain, then restart with the
# same signer/config and persistent state. This verifies that credential,
# signer, policy, posture, and detector authorities are not recreated from
# process memory after SIGKILL.
kill -KILL "$gateway_pid" >/dev/null 2>&1
wait "$gateway_pid" >/dev/null 2>&1 || true
gateway_pid=""
"$harness_dir/gripline" -config "$harness_dir/config.json" >"$harness_dir/gateway-restart.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 50); do
	if curl -fsS "http://127.0.0.1:${gateway_port}/readyz" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
curl -fsS "http://127.0.0.1:${gateway_port}/v1/messages" -H "Authorization: Bearer ${secret}" | rg -q '"authorized":true'
# Filesystem fault probes: a persistent authority must fail closed when its
# state or signer becomes unreadable, while a read-only spool must reject the
# affected unknown-length request without reaching the backend.
kill -TERM "$gateway_pid" >/dev/null 2>&1
wait "$gateway_pid" >/dev/null 2>&1 || true
gateway_pid=""
chmod 0400 "$harness_dir/state.db"
"$harness_dir/gripline" -config "$harness_dir/config.json" >"$harness_dir/readonly-state.log" 2>&1 &
gateway_pid=$!
sleep 1
if curl -fsS "http://127.0.0.1:$gateway_port/readyz" >/dev/null 2>&1; then
	echo "release harness: read-only state unexpectedly served" >&2
	exit 1
fi
kill -TERM "$gateway_pid" >/dev/null 2>&1 || true
wait "$gateway_pid" >/dev/null 2>&1 || true
gateway_pid=""
chmod 0600 "$harness_dir/state.db"

chmod 000 "$harness_dir/keyring.json"
"$harness_dir/gripline" -config "$harness_dir/config.json" >"$harness_dir/readonly-signer.log" 2>&1 &
gateway_pid=$!
sleep 1
if curl -fsS "http://127.0.0.1:$gateway_port/readyz" >/dev/null 2>&1; then
	echo "release harness: unreadable signer unexpectedly served" >&2
	exit 1
fi
kill -TERM "$gateway_pid" >/dev/null 2>&1 || true
wait "$gateway_pid" >/dev/null 2>&1 || true
gateway_pid=""
chmod 0600 "$harness_dir/keyring.json"

chmod 0500 "$harness_dir/spool"
"$harness_dir/gripline" -config "$harness_dir/config.json" >"$harness_dir/readonly-spool.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 50); do
	if curl -fsS "http://127.0.0.1:$gateway_port/readyz" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
spool_fault_bytes=300000
spool_fault_response="$(
	exec 3<>"/dev/tcp/127.0.0.1/$gateway_port"
	printf 'POST /v1/echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n' "$secret" >&3
	printf '%x\r\n' "$spool_fault_bytes" >&3
	head -c "$spool_fault_bytes" /dev/zero >&3
	printf '\r\n0\r\n\r\n' >&3
	timeout 5 cat <&3
	exec 3>&-
)"
echo "$spool_fault_response" | head -n 1 | rg -q ' 400 '
chmod 0750 "$harness_dir/spool"

if rg -F -n "$secret" "$harness_dir"; then
	echo "release harness: canary credential appeared in a generated artifact" >&2
	exit 1
fi
echo "release harness: compiled gateway -> public-verifier backend passed"
