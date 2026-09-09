pick_free_port() {
	local start=$1 end=$2
	python3 - "$start" "$end" <<'PY'
import socket
import sys

start, end = map(int, sys.argv[1:3])
for port in range(start, end):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        sock.close()
        continue
    sock.close()
    print(port)
    raise SystemExit(0)
raise SystemExit("no free PostgreSQL fixture port")
PY
}

configure_ha_ports() {
	if [[ -z "${GRIPLINE_HA_PRIMARY_PORT:-}" ]]; then
		GRIPLINE_HA_PRIMARY_PORT="$(pick_free_port 25432 26432)"
	fi
	if [[ -z "${GRIPLINE_HA_REPLICA_PORT:-}" ]]; then
		GRIPLINE_HA_REPLICA_PORT="$(pick_free_port "$((GRIPLINE_HA_PRIMARY_PORT + 1))" 26433)"
	fi
	export GRIPLINE_HA_PRIMARY_PORT GRIPLINE_HA_REPLICA_PORT
}
