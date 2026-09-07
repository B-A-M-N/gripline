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
	rm -rf "$harness_dir"
}
trap cleanup EXIT

cd "$repo_dir"
gateway_port=$((18080 + ($$ % 500)))
backend_port=$((gateway_port + 1))
audience="gripline-release-harness"
secret="harness-secret-1234567890"
pepper_b64="$(openssl rand -base64 32 | tr -d '\n')"
pepper_hex="$(printf '%s' "$pepper_b64" | base64 -d | od -An -tx1 -v | tr -d ' \n')"
verifier_b64="$(printf '%s%s' 'gripline:secret:digest:v1' "$secret" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$pepper_hex" -binary | base64 -w0)"

go build -trimpath -o "$harness_dir/gripline" ./cmd/gripline
go build -trimpath -o "$harness_dir/backend" ./cmd/gripline-test-backend

cat > "$harness_dir/config.json" <<EOF
{
  "listen": "127.0.0.1:${gateway_port}",
  "tls": {"terminate_tls_upstream": true},
  "backend": {"url": "http://127.0.0.1:${backend_port}", "timeout": "5s"},
  "server": {
    "read_timeout": "5s", "write_timeout": "5s", "idle_timeout": "5s",
    "read_header_timeout": "5s", "max_body_bytes": 1048576,
    "spool_dir": "${harness_dir}/spool", "spool_max_bytes": 1048576,
    "spool_max_files": 8
  },
  "identity": {"audience": "${audience}"},
  "secrets": {"pepper_versions": {"1": "${pepper_b64}"}},
  "paths": {"signer_keyring": "${harness_dir}/keyring.json"},
  "deployment": {"allow_ephemeral_state": true}
}
EOF

cat > "$harness_dir/request.json" <<EOF
{"CredentialID":"harness-credential","AccountID":"harness-account","Verifier":"${verifier_b64}","VerifierVersion":1,"PepperVersion":1,"Status":0,"PolicyID":"gripline-default-v1","PlanID":"harness-plan","Revision":1}
EOF

GRIPLINE_BOOTSTRAP_CREDENTIAL="$(tr -d '\n' < "$harness_dir/request.json")" \
	GRIPLINE_PEPPER_V1="$pepper_b64" \
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

if ! "$harness_dir/gripline" keys export --config "$harness_dir/config.json" >"$harness_dir/keys.json"; then
	cat "$harness_dir/gateway.log" >&2
	exit 1
fi
if rg -n 'private|seed|secret' "$harness_dir/keys.json"; then
	echo "release harness: key export contains private material" >&2
	exit 1
fi

"$harness_dir/backend" -listen "127.0.0.1:${backend_port}" -keys "$harness_dir/keys.json" -audience "$audience" >"$harness_dir/backend.log" 2>&1 &
backend_pid=$!

backend_ready=""
for _ in $(seq 1 50); do
	backend_ready="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${backend_port}/healthz" 2>/dev/null || true)"
	if [[ "$backend_ready" == "401" ]]; then break; fi
	sleep 0.1
done
test "$backend_ready" = "401"
direct_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${backend_port}/v1/messages" -H "Authorization: Bearer ${secret}")"
test "$direct_code" = "403"

response="$(curl -fsS -X POST "http://127.0.0.1:${gateway_port}/v1/messages" \
	-H "Authorization: Bearer ${secret}" -H 'Content-Type: application/json' \
	--data '{"prompt":"hello"}')"
echo "$response" | rg -q '"authorized":true'
echo "$response" | rg -q '"credential_id":"harness-credential"'
if rg -F -n "$secret" "$harness_dir"; then
	echo "release harness: canary credential appeared in a generated artifact" >&2
	exit 1
fi
echo "release harness: compiled gateway -> public-verifier backend passed"
