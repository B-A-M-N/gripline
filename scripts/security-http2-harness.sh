#!/usr/bin/env bash
set -euo pipefail

# HTTP/2 deployment qualification. This intentionally requires a live TLS
# listener because the release fixture terminates TLS upstream and therefore
# cannot prove ALPN, SETTINGS, stream, or header-table behavior.
if [[ $# -lt 2 || $# -gt 3 ]]; then
	echo "usage: $0 HTTPS_GATEWAY_URL BEARER_SECRET [CA_FILE]" >&2
	exit 2
fi

gateway_url=$1
secret=$2
ca_file=${3:-}

if [[ "$gateway_url" != https://* ]]; then
	echo "security HTTP/2 harness: gateway URL must use https://" >&2
	exit 2
fi
if [[ "$gateway_url" == */v1/messages ]]; then
	h2load_url="$gateway_url"
else
	h2load_url="${gateway_url%/}/v1/messages"
fi
command -v nghttp >/dev/null || {
	echo "security HTTP/2 harness: nghttp is required" >&2
	exit 2
}
if [[ "${GRIPLINE_H2_INSECURE:-0}" == "1" && "${GRIPLINE_H2_QUALIFICATION:-0}" == "1" ]]; then
	echo "security HTTP/2 harness: insecure certificate bypass is forbidden for qualification" >&2
	exit 2
fi
if [[ -n "$ca_file" && ! -r "$ca_file" ]]; then
	echo "security HTTP/2 harness: CA_FILE is not readable: $ca_file" >&2
	exit 2
fi

scratch_dir="$(mktemp -d)"
trap 'rm -rf "$scratch_dir"' EXIT
payload="$scratch_dir/payload.json"
printf '%s' '{"prompt":"http2-qualification"}' >"$payload"

run_h2() {
	local name=$1
	shift
	local output="$scratch_dir/${name}.log"
	local -a nghttp_args=(-n -v -t 5)
	if [[ "${GRIPLINE_H2_INSECURE:-0}" == "1" ]]; then
		nghttp_args+=(-y)
	fi
	if [[ -n "$ca_file" ]]; then
		SSL_CERT_FILE="$ca_file" nghttp "${nghttp_args[@]}" \
			-H ":method: POST" \
			-H "authorization: Bearer ${secret}" \
			-H "content-type: application/json" \
			-d "$payload" \
			"$@" "$gateway_url" >"$output" 2>&1
	else
		nghttp "${nghttp_args[@]}" \
		-H ":method: POST" \
		-H "authorization: Bearer ${secret}" \
		-H "content-type: application/json" \
		-d "$payload" \
			"$@" "$gateway_url" >"$output" 2>&1
	fi
	if ! rg -q 'The negotiated protocol: h2' "$output"; then
		echo "security HTTP/2 harness: ${name} did not negotiate h2" >&2
		cat "$output" >&2
		exit 1
	fi
	if ! rg -q ':status: 2[0-9][0-9]' "$output"; then
		echo "security HTTP/2 harness: ${name} did not receive a successful response" >&2
		cat "$output" >&2
		exit 1
	fi
	if ! rg -q 'SETTINGS_MAX_CONCURRENT_STREAMS' "$output"; then
		echo "security HTTP/2 harness: ${name} did not expose server stream settings" >&2
		cat "$output" >&2
		exit 1
	fi
	if ! rg -q 'SETTINGS_HEADER_TABLE_SIZE' "$output"; then
		echo "security HTTP/2 harness: ${name} did not expose header-table settings" >&2
		cat "$output" >&2
		exit 1
	fi
	if [[ -n "${GRIPLINE_H2_EXPECT_HEADER_TABLE:-}" ]] && ! rg -q "SETTINGS_HEADER_TABLE_SIZE.*${GRIPLINE_H2_EXPECT_HEADER_TABLE}" "$output"; then
		echo "security HTTP/2 harness: ${name} advertised an unexpected header-table bound" >&2
		cat "$output" >&2
		exit 1
	fi
	if [[ -n "${GRIPLINE_H2_EXPECT_MAX_STREAMS:-}" ]] && ! rg -q "SETTINGS_MAX_CONCURRENT_STREAMS.*${GRIPLINE_H2_EXPECT_MAX_STREAMS}" "$output"; then
		echo "security HTTP/2 harness: ${name} advertised an unexpected stream bound" >&2
		cat "$output" >&2
		exit 1
	fi
}

# Repeated requests exercise the configured stream cap and connection reuse.
run_h2 stream-churn -m 16

# SETTINGS header-table changes and CONTINUATION framing exercise the bounded
# HPACK/decoder configuration on a real TLS/ALPN connection.
run_h2 settings-churn -c 4096 --encoder-header-table-size 4096 --continuation

# Exercise the bounded upload/flow-control path with tiny windows. The request
# must still complete rather than hanging or exhausting connection buffers.
run_h2 flow-control -w 8 -W 8 -b 1024

# A header block larger than the configured request-header budget must be
# rejected at the HTTP/2 boundary. We accept either an HTTP 4xx response or
# the protocol-level error emitted by the decoder.
oversized_header="$scratch_dir/oversized-header.txt"
head -c 90000 /dev/zero | tr '\0' 'x' >"$oversized_header"
oversized_value="$(<"$oversized_header")"
oversized_output="$scratch_dir/oversized-header.log"
set +e
if [[ -n "$ca_file" ]]; then
	SSL_CERT_FILE="$ca_file" nghttp -n -v -t 5 \
		-H ":method: POST" \
		-H "authorization: Bearer ${secret}" \
		-H "content-type: application/json" \
		-H "x-qualification-oversized: ${oversized_value}" \
		-d "$payload" "$gateway_url" >"$oversized_output" 2>&1
else
	nghttp -y -n -v -t 5 \
		-H ":method: POST" \
		-H "authorization: Bearer ${secret}" \
		-H "content-type: application/json" \
		-H "x-qualification-oversized: ${oversized_value}" \
		-d "$payload" "$gateway_url" >"$oversized_output" 2>&1
fi
oversized_status=$?
set -e
if ! rg -q 'The negotiated protocol: h2' "$oversized_output"; then
	echo "security HTTP/2 harness: oversized-header case did not negotiate h2" >&2
	cat "$oversized_output" >&2
	exit 1
fi
if ! rg -q ':status: 4[0-9][0-9]|PROTOCOL_ERROR|ENHANCE_YOUR_CALM|FRAME_SIZE_ERROR|length of the frame is invalid|Some requests were not processed' "$oversized_output"; then
	echo "security HTTP/2 harness: oversized-header case was not rejected (exit=${oversized_status})" >&2
	cat "$oversized_output" >&2
	exit 1
fi

if command -v h2load >/dev/null; then
	load_status=passed
	load_output="$scratch_dir/h2load.log"
	h2load -n 32 -c 16 -m 8 -t 5 \
		-H "authorization: Bearer ${secret}" \
		-H 'content-type: application/json' \
		-d "$payload" "$h2load_url" >"$load_output" 2>&1
	done_count="$(rg -o '[0-9]+ done' "$load_output" | awk '{print $1}' | tail -1)"
	succeeded_count="$(rg -o '[0-9]+ succeeded' "$load_output" | awk '{print $1}' | tail -1)"
	two_xx_count="$(rg -o '[0-9]+ 2xx' "$load_output" | awk '{print $1}' | tail -1)"
	error_count="$(rg -o '[0-9]+ errored' "$load_output" | awk '{print $1}' | tail -1)"
	timeout_count="$(rg -o '[0-9]+ timeout' "$load_output" | awk '{print $1}' | tail -1)"
	if [[ ! "$done_count" =~ ^[0-9]+$ || ! "$succeeded_count" =~ ^[0-9]+$ || ! "$two_xx_count" =~ ^[0-9]+$ || "$done_count" == 0 || "$succeeded_count" != "$done_count" || "$two_xx_count" != "$done_count" || "${error_count:-0}" != 0 || "${timeout_count:-0}" != 0 ]]; then
		echo "security HTTP/2 harness: h2load did not report successful responses" >&2
		cat "$load_output" >&2
		exit 1
	fi
elif [[ "${GRIPLINE_H2_LOAD_REQUIRED:-0}" == "1" ]]; then
	echo "security HTTP/2 harness: h2load is required but not installed" >&2
	exit 2
else
	load_status=skipped
fi

echo "security HTTP/2 harness: ALPN, stream churn, header-table cases passed; h2load=$load_status"
