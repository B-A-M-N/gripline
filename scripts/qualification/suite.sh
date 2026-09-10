#!/usr/bin/env bash
set -uo pipefail

# Run the repository-owned reference qualification gates and emit sanitized,
# immutable-source evidence. Gate logs are retained as bounded, sanitized
# artifacts and hashed into the manifest; result JSON never contains
# credentials, assertions, private keys, or DSNs.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
requested_result_dir="${GRIPLINE_QUALIFICATION_RESULT_DIR:-}"
keep="${GRIPLINE_QUALIFICATION_KEEP:-0}"
soak_duration="30s"
capacity_duration="30s"
workers="${GRIPLINE_CLUSTER_SOAK_WORKERS:-8}"
capacity_workers="${GRIPLINE_CAPACITY_WORKERS:-16}"
only_soak=0

while [[ $# -gt 0 ]]; do
	case "$1" in
		--soak-duration)
			soak_duration=${2:?--soak-duration requires a value}
			shift 2
			;;
		--capacity-duration)
			capacity_duration=${2:?--capacity-duration requires a value}
			shift 2
			;;
		--workers)
			workers=${2:?--workers requires a value}
			shift 2
			;;
		--capacity-workers)
			capacity_workers=${2:?--capacity-workers requires a value}
			shift 2
			;;
		--only-soak)
			only_soak=1
			shift
			;;
		*)
			echo "qualification suite: unknown argument $1" >&2
			exit 2
			;;
	esac
done

if ! [[ "$workers" =~ ^[1-9][0-9]*$ && "$capacity_workers" =~ ^[1-9][0-9]*$ ]]; then
	echo "qualification suite: workers and capacity-workers must be positive integers" >&2
	exit 2
fi

command -v git >/dev/null || { echo "qualification suite: git is required" >&2; exit 2; }
commit="$(git -C "$repo_dir" rev-parse HEAD)"
run_id="$(date -u '+%Y%m%dT%H%M%SZ')-${$}"
if [[ -n "$requested_result_dir" ]]; then
	result_dir="$requested_result_dir"
else
	result_dir="$repo_dir/qualification-results/${commit}/${run_id}"
fi
if [[ -n "$(git -C "$repo_dir" status --porcelain)" ]]; then
	echo "qualification suite: source tree must be clean for release evidence" >&2
	exit 2
fi
mkdir -p "$result_dir"
if [[ -n "$(find "$result_dir" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
	echo "qualification suite: result directory must be empty to prevent stale evidence" >&2
	exit 2
fi
work_dir="$(mktemp -d)"
denylist="$work_dir/evidence-denylist.txt"
: >"$denylist"
cleanup() {
	if [[ "$keep" == 1 ]]; then
		echo "qualification suite logs retained: $work_dir" >&2
	else
		rm -rf "$work_dir"
	fi
}
trap cleanup EXIT

declare -A status exit_code duration_seconds evidence_sha256 telemetry_sha256 log_sha256
overall=0

safe_version() {
	local value
	value="$($* 2>/dev/null | head -1 || true)"
	printf '%s' "$value" | tr -cd '[:alnum:]._ /:-' | cut -c1-128
}

json_escape() {
	printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

sanitize_log() {
	# Qualification fixtures use synthetic secrets, but retaining only a
	# bounded redacted transcript keeps evidence useful without making secret
	# hygiene depend on every fixture's logging style.
	head -c 1048576 "$1" | sed -E \
		-e 's#(Authorization: Bearer[[:space:]]+|([Pp]assword|[Ss]ecret|[Tt]oken|[Dd][Ss][Nn])[=:][[:space:]]*)[^[:space:]]+#\1<redacted>#g' \
		-e 's#(GRIPLINE_[A-Z0-9_]+=)[^[:space:]]+#\1<redacted>#g' \
		-e 's#(/tmp/)[^[:space:]]+#\1<redacted>#g'
}

run_gate() {
	local name=$1 script=$2
	shift 2
	local started ended started_epoch ended_epoch rc log
	local assertions_file="$work_dir/$name-assertions.json"
	started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	started_epoch="$(date +%s)"
	log="$work_dir/${name}.log"
	rc=0
	if [[ "$name" == "soak" ]]; then
		GRIPLINE_SOAK_EVIDENCE_FILE="$result_dir/soak-telemetry.json" GRIPLINE_QUALIFICATION_ASSERTIONS_FILE="$assertions_file" GRIPLINE_QUALIFICATION_DENYLIST_FILE="$denylist" bash "$repo_dir/scripts/qualification/${script}" "$@" >"$log" 2>&1 || rc=$?
	elif [[ "$name" == "capacity-load" ]]; then
		GRIPLINE_CLUSTER_HARNESS_CAPACITY_EVIDENCE_FILE="$result_dir/capacity-load-telemetry.json" GRIPLINE_QUALIFICATION_ASSERTIONS_FILE="$assertions_file" GRIPLINE_QUALIFICATION_DENYLIST_FILE="$denylist" bash "$repo_dir/scripts/qualification/${script}" "$@" >"$log" 2>&1 || rc=$?
	else
		GRIPLINE_QUALIFICATION_ASSERTIONS_FILE="$assertions_file" GRIPLINE_QUALIFICATION_DENYLIST_FILE="$denylist" bash "$repo_dir/scripts/qualification/${script}" "$@" >"$log" 2>&1 || rc=$?
	fi
	local assertions_json='{}' measurements_json='{}'
	if [[ -s "$assertions_file" ]]; then
		if ! assertions_json="$(python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert isinstance(value,dict) and isinstance(value.get("assertions"),dict); print(json.dumps(value["assertions"], separators=(",",":")))' "$assertions_file" 2>/dev/null)"; then
			echo "qualification suite: $name emitted invalid assertions" >&2
			rc=1
		else
			measurements_json="$(python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert isinstance(value,dict) and isinstance(value.get("measurements",{}),dict); print(json.dumps(value.get("measurements",{}), separators=(",",":")))' "$assertions_file" 2>/dev/null)" || { echo "qualification suite: $name emitted invalid measurements" >&2; rc=1; }
		fi
	elif [[ "$rc" == 0 ]]; then
		echo "qualification suite: $name completed without gate-specific assertions" >&2
		rc=1
	fi
	ended="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	ended_epoch="$(date +%s)"
	status[$name]=$([[ "$rc" == 0 ]] && echo pass || echo fail)
	exit_code[$name]=$rc
	duration_seconds[$name]=$((ended_epoch - started_epoch))
	local summary summary_json telemetry_file telemetry_hash sanitized_log_file
	summary="$( (rg -i 'qualification.*(passed|metrics|samples=)|cluster harness: capacity load metrics=' "$log" || true) | tail -5 | tr '\n' ' ' | tr -cd '[:print:]' | cut -c1-1200)"
	summary_json="$(json_escape "$summary")"
	sanitized_log_file="${name}-log.txt"
	sanitize_log "$log" >"$result_dir/$sanitized_log_file"
	log_sha256[$name]="$(sha256sum "$result_dir/$sanitized_log_file" | awk '{print $1}')"
	telemetry_file=""
	if [[ -f "$result_dir/${name}-telemetry.json" ]]; then telemetry_file="${name}-telemetry.json"; fi
	cat >"$result_dir/${name}.json" <<EOF
{
	  "schema": 2,
  "suite": "gripline-reference-qualification-v1",
  "gate": "${name}",
  "commit": "${commit}",
  "started_at": "${started}",
  "finished_at": "${ended}",
  "duration_seconds": ${duration_seconds[$name]},
  "result": "${status[$name]}",
  "exit_code": ${rc},
  "assertions": $assertions_json,
  "measurements": $measurements_json,
  "process": {
    "gate_process_completed": true,
    "exit_code_zero": $([[ "$rc" == 0 ]] && echo true || echo false)
  },
  "summary": "${summary_json}",
  "log": {"path": "${sanitized_log_file}", "sha256": "${log_sha256[$name]}"}$(if [[ -n "$telemetry_file" ]]; then printf ',\n  "telemetry": {"path": "%s", "sha256": "%s"}' "$telemetry_file" "$(sha256sum "$result_dir/$telemetry_file" | awk '{print $1}')"; fi)
}
EOF
	evidence_sha256[$name]="$(sha256sum "$result_dir/${name}.json" | awk '{print $1}')"
	telemetry_hash=""
	if [[ -n "$telemetry_file" ]]; then telemetry_hash="$(sha256sum "$result_dir/$telemetry_file" | awk '{print $1}')"; fi
	telemetry_sha256[$name]="$telemetry_hash"
	if [[ "$rc" != 0 ]]; then
		overall=1
		cat "$log" >&2
	fi
}

if [[ "$only_soak" == 0 ]]; then
	run_gate postgres-ha ha.sh
	run_gate postgres-pitr pitr.sh
	run_gate perimeter perimeter.sh
	run_gate clustered-perimeter clustered-perimeter.sh
	run_gate replay replay.sh
	run_gate http2 http2.sh
	run_gate sdk sdk.sh
	run_gate exact-cost exact-cost.sh
	run_gate source-churn source-churn.sh
fi
run_gate soak soak.sh --duration "$soak_duration" --workers "$workers"
if [[ "$only_soak" == 0 ]]; then
	run_gate capacity-load capacity.sh --duration "$capacity_duration" --workers "$capacity_workers"
fi

gate_status() {
	local key=$1
	printf '%s' "${status[$key]:-skipped}"
}

manifest_gates_json() {
	local key first=1
	local gate_list="postgres-ha postgres-pitr perimeter clustered-perimeter replay http2 sdk exact-cost source-churn soak capacity-load"
	if [[ "$only_soak" == 1 ]]; then
		gate_list="soak"
	fi
	for key in $gate_list; do
		if [[ "$first" == 0 ]]; then printf ',\n'; fi
		printf '    "%s": "%s"' "$key" "$(gate_status "$key")"
		first=0
	done
}

manifest_evidence_entry() {
	local key=$1
	local record_hash=${evidence_sha256[$key]:-}
	local telemetry_hash=${telemetry_sha256[$key]:-}
	local log_hash=${log_sha256[$key]:-}
	printf '    "%s": {"record": {"path": "%s.json", "sha256": "%s"}, "log": {"path": "%s-log.txt", "sha256": "%s"}' "$key" "$key" "$record_hash" "$key" "$log_hash"
	if [[ -n "$telemetry_hash" ]]; then
		printf ', "telemetry": {"path": "%s-telemetry.json", "sha256": "%s"}' "$key" "$telemetry_hash"
	fi
	printf '}'
}

manifest_evidence_json() {
	local key first=1
	for key in postgres-ha postgres-pitr perimeter clustered-perimeter replay http2 sdk exact-cost source-churn soak capacity-load; do
		if [[ "${status[$key]:-skipped}" == skipped ]]; then
			continue
		fi
		if [[ "$first" == 0 ]]; then printf ',\n'; fi
		manifest_evidence_entry "$key"
		first=0
	done
}

if ! python3 "$repo_dir/scripts/qualification/scan-evidence.py" "$result_dir" "$denylist"; then
	echo "qualification suite: evidence secret scan failed" >&2
	overall=1
fi

required_gates='["postgres-ha", "postgres-pitr", "perimeter", "clustered-perimeter", "replay", "http2", "sdk", "exact-cost", "source-churn", "soak", "capacity-load"]'
if [[ "$only_soak" == 1 ]]; then
	required_gates='["soak"]'
fi
# http2.sh wraps both protocol clients in the pinned repository-owned
# container; no host package or ambient load generator is part of the gate.
h2load_provenance="pinned Docker fixture: scripts/qualification/fixtures/http2/Dockerfile (nghttp2-client=1.52.0-1+deb12u2)"

cat >"$result_dir/manifest.json" <<EOF
{
  "schema": 2,
  "suite": "gripline-reference-qualification-v1",
  "commit": "${commit}",
  "result": "$([[ "$overall" == 0 ]] && echo pass || echo fail)",
  "generated_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "soak_duration": "${soak_duration}",
  "capacity_duration": "${capacity_duration}",
  "workers": ${workers},
  "capacity_workers": ${capacity_workers},
  "qualification_mode": "$([[ "$only_soak" == 1 ]] && echo only-soak || echo full)",
  "required_gates": ${required_gates},
  "gates": {
$(manifest_gates_json)
  },
  "fixture_images": {
    "postgres": "postgres:16@sha256:f1c3376c26f2609ab9f29f71f824103fe2fcd8ee0346485cb6122a4f93df6f94",
    "nginx": "nginx:alpine@sha256:72ba65eb42c10344912a84ff42408db7d34f2feb642204570ab8fc5ffd29f1d3",
    "curl": "curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b",
    "debian": "debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171",
    "h2load": "scripts/qualification/fixtures/http2/Dockerfile (nghttp2-client=1.52.0-1+deb12u2)"
  },
  "evidence": {
$(manifest_evidence_json)
  },
  "tool_versions": {
    "go": "$(safe_version go version)",
    "python": "$(safe_version python3 --version)",
    "node": "$(safe_version node --version)",
    "npm": "$(safe_version npm --version)",
    "docker": "$(safe_version docker version --format '{{.Server.Version}}')",
    "openssl": "$(safe_version openssl version)",
    "curl": "$(safe_version curl --version)",
    "nghttp": "$(json_escape "$h2load_provenance")",
    "h2load": "$(json_escape "$h2load_provenance")",
    "psql": "$(safe_version psql --version)",
    "kernel": "$(safe_version uname -sr)",
    "architecture": "$(safe_version uname -m)"
  }
}
EOF

if ! python3 "$repo_dir/scripts/qualification/scan-evidence.py" "$result_dir" "$denylist"; then
	echo "qualification suite: final evidence secret scan failed" >&2
	overall=1
fi

(cd "$result_dir" && sha256sum manifest.json >manifest.sha256)
if ! bash "$repo_dir/scripts/qualification/verify-manifest.sh" "$result_dir" "$commit"; then
	echo "qualification suite: manifest verification failed" >&2
	overall=1
fi
exit "$overall"
