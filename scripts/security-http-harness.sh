#!/usr/bin/env bash
set -euo pipefail

# Raw HTTP/1.1 parser qualification. The compiled release harness supplies a
# live gateway and an instrumented backend; this script deliberately bypasses
# curl/net/http clients and writes ambiguous bytes to a TCP socket.
if [[ $# -ne 5 ]]; then
	echo "usage: $0 GATEWAY_HOST GATEWAY_PORT BACKEND_CAPTURE SECRET EXPECTED_BACKEND_HOST" >&2
	exit 2
fi

gateway_host=$1
gateway_port=$2
capture_path=$3
secret=$4
expected_backend_host=$5
scratch_dir="$(mktemp -d)"
trap 'rm -rf "$scratch_dir"' EXIT

capture_count() {
	if [[ -f "$capture_path" ]]; then
		wc -l <"$capture_path"
	else
		echo 0
	fi
}

send_raw() {
	local request=$1 output=$2
	(
		exec 3<>"/dev/tcp/${gateway_host}/${gateway_port}" 2>/dev/null || exit 0
		printf '%s' "$request" >&3
		timeout 2 cat <&3 >"$output" || true
		exec 3>&-
	) || true
}

send_raw_sequence() {
	local request=$1 output=$2
	(
		exec 3<>"/dev/tcp/${gateway_host}/${gateway_port}" 2>/dev/null || exit 0
		printf '%s' "$request" >&3
		timeout 2 cat <&3 >"$output" || true
		exec 3>&-
	) || true
}

wait_for_quiescence() {
	local previous current stable=0
	previous="$(capture_count)"
	for _ in $(seq 1 60); do
		sleep 0.05
		current="$(capture_count)"
		if [[ "$current" == "$previous" ]]; then
			stable=$((stable + 1))
			if (( stable >= 10 )); then
				echo "$current"
				return 0
			fi
		else
			stable=0
			previous=$current
		fi
	done
	echo "$current"
	return 1
}

check_downstream() {
	local before=$1 after=$2 name=$3 max_delta=${4:-1}
	local delta=$((after - before))
	if (( delta > max_delta )); then
		echo "security HTTP harness: ${name} produced ${delta} backend requests" >&2
		exit 1
	fi
	if (( delta == 0 )); then
		return
	fi
	local recent="$scratch_dir/${name}.capture"
	tail -n "$delta" "$capture_path" >"$recent"
	if grep -F -q "$secret" "$recent" || grep -F -q 'attacker-assertion' "$recent"; then
		echo "security HTTP harness: ${name} leaked a client credential/assertion downstream" >&2
		exit 1
	fi
	if ! grep -F -q "host=${expected_backend_host}" "$recent"; then
		echo "security HTTP harness: ${name} reached an unexpected backend host" >&2
		exit 1
	fi
}

exercise() {
	local name=$1 request=$2 output="$scratch_dir/$1.response"
	local before after
	before="$(capture_count)"
	send_raw "$request" "$output"
	# The backend write is asynchronous with respect to the parser response.
	# Wait for a bounded period of unchanged capture state instead of assuming
	# the malicious secondary request arrives within one fixed sleep.
	after="$(wait_for_quiescence)" || {
		echo "security HTTP harness: ${name} did not reach backend quiescence" >&2
		exit 1
	}
	check_downstream "$before" "$after" "$name"
}

exercise_sequence() {
	local name=$1 request=$2 expected=$3 output="$scratch_dir/$1.response"
	local before after delta
	before="$(capture_count)"
	send_raw_sequence "$request" "$output"
	after="$(wait_for_quiescence)" || {
		echo "security HTTP harness: ${name} did not reach backend quiescence" >&2
		exit 1
	}
	delta=$((after - before))
	if (( delta != expected )); then
		echo "security HTTP harness: ${name} produced ${delta} backend requests, want ${expected}" >&2
		exit 1
	fi
	check_downstream "$before" "$after" "$name" "$expected"
}

exercise_sequence_at_most() {
	local name=$1 request=$2 max_delta=$3 output="$scratch_dir/$1.response"
	local before after delta
	before="$(capture_count)"
	send_raw_sequence "$request" "$output"
	after="$(wait_for_quiescence)" || {
		echo "security HTTP harness: ${name} did not reach backend quiescence" >&2
		exit 1
	}
	delta=$((after - before))
	if (( delta > max_delta )); then
		echo "security HTTP harness: ${name} produced ${delta} backend requests, max ${max_delta}" >&2
		exit 1
	fi
	check_downstream "$before" "$after" "$name" "$max_delta"
}

exercise duplicate_content_length $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx'
exercise content_length_transfer_encoding $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n'
exercise transfer_encoding_content_length $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\nConnection: close\r\n\r\n0\r\n\r\n'
exercise malformed_chunk_size $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nnot-a-chunk\r\nbody\r\n0\r\n\r\n'
exercise chunk_extension $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2;probe=one\r\n{}\r\n0\r\n\r\n'
exercise invalid_transfer_encoding $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n0\r\n\r\n'
exercise obs_fold $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nX-Folded: first\r\n\tcontinued\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
exercise control_character $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nX-Control: bad\x01value\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
exercise duplicate_authorization $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nAuthorization: Bearer second\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
exercise comma_folded_authorization $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$', Bearer second\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
exercise connection_authorization $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nConnection: Authorization\r\nAuthorization: Bearer '"$secret"$'\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
exercise encoded_traversal $'POST /v1/%2e%2e/private HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
exercise encoded_slash_traversal $'POST /v1/%2e%2e%2fprivate HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'

# Accepted requests are also checked: absolute-form targets and attacker Host
# values must still use the fixed backend origin, and reserved carriers must
# not survive the trusted hop.
exercise absolute_form $'POST http://attacker.example/v1/messages?probe=1 HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nConnection: X-Gripline-Assertion\r\nX-Gripline-Assertion: attacker-assertion\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
exercise reserved_trailer $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nTrailer: Authorization, X-Gripline-Assertion\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\n{}\r\n0\r\nAuthorization: Bearer '"$secret"$'\r\nX-Gripline-Assertion: attacker-assertion\r\n\r\n'

# Keep-alive is a separate parser state machine from one-shot close. Two valid
# requests must produce exactly two backend requests, while an ambiguous first
# request followed by a valid request must not create more than one downstream
# request through parser desynchronization.
exercise_sequence keepalive_valid $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}' 2
exercise_sequence_at_most keepalive_ambiguous_then_valid $'POST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nxPOST /v1/messages HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer '"$secret"$'\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}' 1

if [[ -f "$capture_path" ]] && grep -F -q "$secret" "$capture_path"; then
	echo "security HTTP harness: credential appeared in backend capture" >&2
	exit 1
fi
echo "security HTTP harness: raw HTTP/1.1 cases passed"
