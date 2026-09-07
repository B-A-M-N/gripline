#!/usr/bin/env bash
set -euo pipefail

image_name="${1:-gripline-ci}"
container_name="gripline-smoke-$$"
smoke_dir="$(mktemp -d)"
cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  rm -rf "$smoke_dir"
}
trap cleanup EXIT

mkdir -p "$smoke_dir/state" "$smoke_dir/tls"
chmod 0777 "$smoke_dir/state"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -keyout "$smoke_dir/tls/key.pem" \
  -out "$smoke_dir/tls/cert.pem" >/dev/null 2>&1
chmod 0644 "$smoke_dir/tls/key.pem" "$smoke_dir/tls/cert.pem"
pepper_value="$(openssl rand -base64 32 | tr -d '\n')"
cat > "$smoke_dir/config.json" <<EOF
{
  "listen": "0.0.0.0:18443",
  "tls": {"cert_file": "/etc/gripline/tls/cert.pem", "key_file": "/etc/gripline/tls/key.pem", "min_version": "1.2"},
  "backend": {"url": "http://127.0.0.1:1", "timeout": "5s"},
  "server": {"read_timeout": "5s", "write_timeout": "5s", "idle_timeout": "5s", "read_header_timeout": "5s", "spool_dir": "/tmp/gripline-spool"},
  "identity": {"audience": "smoke"},
  "paths": {"state": "/var/lib/gripline/state.db", "signer_keyring": "/var/lib/gripline/keyring.json"}
}
EOF

start_container() {
  docker run -d --name "$container_name" --read-only --user 65532:65532 \
    -e "GRIPLINE_PEPPER_V1=$pepper_value" \
    -p 127.0.0.1:18443:18443 \
    --tmpfs /tmp/gripline-spool:rw,noexec,nosuid,size=64m \
    -v "$smoke_dir/config.json:/etc/gripline/config.json:ro" \
    -v "$smoke_dir/tls:/etc/gripline/tls:ro" \
    -v "$smoke_dir/state:/var/lib/gripline" \
    "$image_name" >/dev/null
}

wait_ready() {
  for _ in $(seq 1 30); do
    if curl -ksSf https://127.0.0.1:18443/readyz >/dev/null; then return 0; fi
    sleep 1
  done
  docker logs "$container_name" >&2 || true
  return 1
}

start_container
wait_ready
test -s "$smoke_dir/state/state.db"
test -s "$smoke_dir/state/keyring.json"
docker kill --signal=TERM "$container_name" >/dev/null
docker wait "$container_name" >/dev/null
docker rm "$container_name" >/dev/null
start_container
wait_ready
test -s "$smoke_dir/state/state.db"
test -s "$smoke_dir/state/keyring.json"
echo "container smoke: persistent state/keyring, readiness, SIGTERM, restart passed"
