#!/usr/bin/env bash
set -euo pipefail

image_name="${1:-gripline-ci}"
container_name="gripline-smoke-$$"
insecure_container_name="${container_name}-insecure"
smoke_dir="$(mktemp -d)"
cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  docker rm -f "$insecure_container_name" >/dev/null 2>&1 || true
  docker run --rm -v "$smoke_dir:/smoke" golang:1.25.13-alpine \
    chown -R "$(id -u):$(id -g)" /smoke >/dev/null 2>&1 || true
  rm -rf "$smoke_dir"
}
trap cleanup EXIT

mkdir -p "$smoke_dir/state" "$smoke_dir/tls"
# The state directory is private to the non-root container user. Set its
# ownership through a helper image because the host runner may not have UID
# 65532 available. World/group-writable state is covered by the negative smoke
# below and must never be the positive release path.
chmod 0750 "$smoke_dir/state"
docker run --rm -v "$smoke_dir/state:/state" golang:1.25.13-alpine \
  chown -R 65532:65532 /state >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -keyout "$smoke_dir/tls/key.pem" \
  -out "$smoke_dir/tls/cert.pem" >/dev/null 2>&1
chmod 0600 "$smoke_dir/tls/key.pem"
chmod 0644 "$smoke_dir/tls/cert.pem"
# The container runs as UID 65532. Transfer ownership inside a disposable
# helper container so the private key can remain 0600 while the nonroot smoke
# process can read it from the bind mount.
docker run --rm -v "$smoke_dir/tls:/tls" golang:1.25.13-alpine \
  chown 65532:65532 /tls/key.pem /tls/cert.pem >/dev/null
pepper_value="$(openssl rand -base64 32 | tr -d '\n')"
cat > "$smoke_dir/config.json" <<EOF
{
  "listen": "0.0.0.0:18443",
  "tls": {"cert_file": "/etc/gripline/tls/cert.pem", "key_file": "/etc/gripline/tls/key.pem", "min_version": "1.2"},
  "backend": {"url": "http://127.0.0.1:1", "trust_mode": "private_network", "timeout": "5s"},
  "server": {"read_timeout": "5s", "write_timeout": "5s", "idle_timeout": "5s", "read_header_timeout": "5s", "spool_dir": "/tmp/gripline-spool"},
  "identity": {"audience": "smoke"},
  "paths": {"state": "/var/lib/gripline/state.db", "signer_keyring": "/var/lib/gripline/keyring.json"}
}
EOF

start_container() {
  docker run -d --name "$1" --read-only --user 65532:65532 \
    -e "GRIPLINE_PEPPER_V1=$pepper_value" \
    -p 127.0.0.1:18443:18443 \
    --tmpfs /tmp/gripline-spool:rw,noexec,nosuid,size=64m \
    -v "$smoke_dir/config.json:/etc/gripline/config.json:ro" \
    -v "$smoke_dir/tls:/etc/gripline/tls:ro" \
    -v "$smoke_dir/state:/var/lib/gripline" \
    "$image_name" >/dev/null
}

assert_state_files() {
  docker run --rm -v "$smoke_dir/state:/state:ro" golang:1.25.13-alpine \
    sh -c 'test -s /state/state.db && test -s /state/keyring.json' >/dev/null
}

wait_ready() {
  for _ in $(seq 1 30); do
    if curl -ksSf https://127.0.0.1:18443/readyz >/dev/null; then return 0; fi
    sleep 1
  done
  docker logs "$container_name" >&2 || true
  return 1
}

start_container "$container_name"
wait_ready
assert_state_files
docker kill --signal=TERM "$container_name" >/dev/null
docker wait "$container_name" >/dev/null
docker rm "$container_name" >/dev/null
start_container "$container_name"
wait_ready
assert_state_files
docker kill --signal=TERM "$container_name" >/dev/null
docker wait "$container_name" >/dev/null
docker rm "$container_name" >/dev/null

# Keep an explicit regression test for the filesystem invariant that caused a
# previous smoke failure. A deliberately insecure parent must fail closed.
docker run --rm -v "$smoke_dir/state:/state" golang:1.25.13-alpine \
  chmod 0777 /state >/dev/null
start_container "$insecure_container_name"
sleep 2
insecure_state="$(docker inspect -f '{{.State.Status}}' "$insecure_container_name")"
insecure_status="$(docker inspect -f '{{.State.ExitCode}}' "$insecure_container_name")"
if [[ "$insecure_state" == "running" || "$insecure_state" == "restarting" || "$insecure_status" == "0" ]]; then
  docker logs "$insecure_container_name" >&2 || true
  echo "container smoke: insecure state directory unexpectedly started (state=$insecure_state exit=$insecure_status)" >&2
  exit 1
fi
docker rm "$insecure_container_name" >/dev/null
echo "container smoke: persistent state/keyring, readiness, SIGTERM, restart, insecure-state rejection passed"
