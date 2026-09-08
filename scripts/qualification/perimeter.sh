#!/usr/bin/env bash
set -euo pipefail

# Repository-owned network-perimeter lab. Containers are placed on distinct
# public/private/control/database networks; the private service requires a
# client certificate signed by the lab CA, and only the gateway identity can
# reach it. This proves the reference topology without relying on a cloud VPC.

lab="gripline-perimeter-${$}"
work_dir="$(mktemp -d)"
networks=("${lab}-public" "${lab}-private" "${lab}-control" "${lab}-db")
containers=("${lab}-backend" "${lab}-admin" "${lab}-gateway" "${lab}-control" "${lab}-attacker" "${lab}-postgres" "${lab}-inference-client" "${lab}-control-client")
cleanup() {
	for container in "${containers[@]}"; do docker rm -f "$container" >/dev/null 2>&1 || true; done
	for network in "${networks[@]}"; do docker network rm "$network" >/dev/null 2>&1 || true; done
	rm -rf "$work_dir"
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "perimeter qualification: docker is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "perimeter qualification: openssl is required" >&2; exit 2; }

for network in "${networks[@]}"; do
	docker network create --internal "$network" >/dev/null
done
docker network rm "${lab}-public" >/dev/null
docker network create "${lab}-public" >/dev/null

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Gripline qualification CA" \
	-keyout "$work_dir/ca.key" -out "$work_dir/ca.pem" >/dev/null 2>&1
make_cert() {
	local name=$1 cn=$2
	openssl req -newkey rsa:2048 -nodes -subj "/CN=${cn}" -keyout "$work_dir/${name}.key" -out "$work_dir/${name}.csr" >/dev/null 2>&1
	openssl x509 -req -days 1 -sha256 -in "$work_dir/${name}.csr" -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca.key" \
		-CAcreateserial -out "$work_dir/${name}.pem" >/dev/null 2>&1
}
make_cert backend backend.internal
make_cert control-server control.internal
make_cert gateway gripline-gateway.internal
make_cert control gripline-control.internal
make_cert attacker untrusted-client.internal
chmod 0755 "$work_dir"
chmod 0644 "$work_dir"/*.pem
# The disposable curl/nginx containers run as non-root users; the lab deletes
# this directory on exit and uses one-day test identities only.
chmod 0644 "$work_dir"/*.key
cat >"$work_dir/backend.conf" <<'EOF'
events {}
http {
  server {
    listen 8443 ssl;
    ssl_certificate /tls/backend.pem;
    ssl_certificate_key /tls/backend.key;
    ssl_client_certificate /tls/ca.pem;
    ssl_verify_client on;
    if ($ssl_client_s_dn !~ "CN=gripline-gateway") { return 403; }
    if ($http_authorization != "") { return 403; }
    if ($http_x_gripline_assertion != "qualification-assertion") { return 403; }
    location / { return 200 "private-backend\n"; }
  }
}
EOF
cat >"$work_dir/control.conf" <<'EOF'
events {}
http {
  server {
    listen 8443 ssl;
    ssl_certificate /tls/control-server.pem;
    ssl_certificate_key /tls/control-server.key;
    ssl_client_certificate /tls/ca.pem;
    ssl_verify_client on;
    if ($ssl_client_s_dn !~ "CN=gripline-control") { return 403; }
    location / { return 200 "verifier-control\n"; }
  }
}
EOF
docker run -d --name "${lab}-backend" --network "${lab}-private" --network-alias backend.internal \
	-v "$work_dir/backend.conf:/etc/nginx/nginx.conf:ro" -v "$work_dir:/tls:ro" nginx:alpine >/dev/null
docker run -d --name "${lab}-admin" --network "${lab}-control" --network-alias admin.internal nginx:alpine >/dev/null
docker run -d --name "${lab}-gateway" --network "${lab}-public" \
	-v "$work_dir:/tls:ro" curlimages/curl:8.10.1 sleep 600 >/dev/null
docker network connect "${lab}-private" "${lab}-gateway"
docker run -d --name "${lab}-control" --network "${lab}-control" --network-alias control.internal \
	-v "$work_dir/control.conf:/etc/nginx/nginx.conf:ro" -v "$work_dir:/tls:ro" nginx:alpine >/dev/null
docker run -d --name "${lab}-attacker" --network "${lab}-public" \
	-v "$work_dir:/tls:ro" curlimages/curl:8.10.1 sleep 600 >/dev/null
docker run -d --name "${lab}-postgres" --network "${lab}-db" --network-alias postgres.internal \
	-e POSTGRES_PASSWORD=qualification postgres:16 >/dev/null
docker run -d --name "${lab}-inference-client" --network "${lab}-private" \
	-v "$work_dir:/tls:ro" curlimages/curl:8.10.1 sleep 600 >/dev/null
docker network connect "${lab}-control" "${lab}-inference-client"
docker run -d --name "${lab}-control-client" --network "${lab}-control" \
	-v "$work_dir:/tls:ro" curlimages/curl:8.10.1 sleep 600 >/dev/null
docker network connect "${lab}-private" "${lab}-control-client"

gateway_curl=(docker exec "${lab}-gateway" curl --fail --silent --show-error --connect-timeout 3 --cacert /tls/ca.pem --cert /tls/gateway.pem --key /tls/gateway.key)
inference_curl=(docker exec "${lab}-inference-client" curl --fail --silent --show-error --connect-timeout 3 --cacert /tls/ca.pem --cert /tls/gateway.pem --key /tls/gateway.key)
control_curl=(docker exec "${lab}-control-client" curl --fail --silent --show-error --connect-timeout 3 --cacert /tls/ca.pem --cert /tls/control.pem --key /tls/control.key)
attacker_curl=(docker exec "${lab}-attacker" curl --fail --silent --show-error --connect-timeout 2 --cacert /tls/ca.pem --cert /tls/attacker.pem --key /tls/attacker.key)
"${gateway_curl[@]}" -H 'X-Gripline-Assertion: qualification-assertion' https://backend.internal:8443/ | rg -qx private-backend
"${inference_curl[@]}" -H 'X-Gripline-Assertion: qualification-assertion' https://backend.internal:8443/ | rg -qx private-backend
if "${gateway_curl[@]}" -H 'Authorization: Bearer raw-external-credential' -H 'X-Gripline-Assertion: qualification-assertion' https://backend.internal:8443/ >/dev/null 2>&1; then
	echo "perimeter qualification: raw external credential reached the private backend" >&2
	exit 1
fi
if "${gateway_curl[@]}" -H 'X-Gripline-Assertion: forged-assertion' https://backend.internal:8443/ >/dev/null 2>&1; then
	echo "perimeter qualification: forged backend assertion reached the private backend" >&2
	exit 1
fi
"${control_curl[@]}" https://control.internal:8443/ | rg -qx verifier-control
if "${inference_curl[@]}" https://control.internal:8443/ >/dev/null 2>&1; then
	echo "perimeter qualification: inference identity reached verifier control" >&2
	exit 1
fi
if "${control_curl[@]}" -H 'X-Gripline-Assertion: qualification-assertion' https://backend.internal:8443/ >/dev/null 2>&1; then
	echo "perimeter qualification: control identity reached inference backend" >&2
	exit 1
fi
if "${attacker_curl[@]}" https://backend.internal:8443/ >/dev/null 2>&1; then
	echo "perimeter qualification: public attacker reached private backend" >&2
	exit 1
fi
if docker exec "${lab}-gateway" curl --fail --silent --connect-timeout 2 http://admin.internal/ >/dev/null 2>&1; then
	echo "perimeter qualification: data gateway reached control/admin network" >&2
	exit 1
fi
if docker exec "${lab}-attacker" curl --fail --silent --connect-timeout 2 --cacert /tls/ca.pem https://control.internal:8443/ >/dev/null 2>&1; then
	echo "perimeter qualification: public attacker reached verifier control" >&2
	exit 1
fi
if docker exec "${lab}-attacker" curl --fail --silent --connect-timeout 2 http://postgres.internal:5432/ >/dev/null 2>&1; then
	echo "perimeter qualification: public attacker reached PostgreSQL network" >&2
	exit 1
fi
echo "perimeter qualification: mTLS identity separation, raw-credential denial, public isolation, control isolation, and database isolation passed"
