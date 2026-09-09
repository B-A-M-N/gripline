#!/usr/bin/env bash
set -uo pipefail

# Run the repository-owned reference qualification gates and emit sanitized,
# immutable-source evidence. Gate logs stay in a temporary directory unless
# GRIPLINE_QUALIFICATION_KEEP=1; result JSON never contains credentials,
# assertions, private keys, or DSNs.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
result_dir="${GRIPLINE_QUALIFICATION_RESULT_DIR:-$repo_dir/qualification/results}"
keep="${GRIPLINE_QUALIFICATION_KEEP:-0}"
soak_duration="30s"
workers="${GRIPLINE_CLUSTER_SOAK_WORKERS:-8}"
only_soak=0

while [[ $# -gt 0 ]]; do
	case "$1" in
		--soak-duration)
			soak_duration=${2:?--soak-duration requires a value}
			shift 2
			;;
		--workers)
			workers=${2:?--workers requires a value}
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

command -v git >/dev/null || { echo "qualification suite: git is required" >&2; exit 2; }
commit="$(git -C "$repo_dir" rev-parse HEAD)"
if [[ -n "$(git -C "$repo_dir" status --porcelain)" ]]; then
	echo "qualification suite: source tree must be clean for release evidence" >&2
	exit 2
fi
mkdir -p "$result_dir"
work_dir="$(mktemp -d)"
cleanup() {
	if [[ "$keep" == 1 ]]; then
		echo "qualification suite logs retained: $work_dir" >&2
	else
		rm -rf "$work_dir"
	fi
}
trap cleanup EXIT

declare -A status exit_code duration_seconds output_sha256
overall=0

safe_version() {
	local value
	value="$($* 2>/dev/null | head -1 || true)"
	printf '%s' "$value" | tr -cd '[:alnum:]._ /:-' | cut -c1-128
}

run_gate() {
	local name=$1 script=$2
	shift 2
	local started ended started_epoch ended_epoch rc log
	started="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	started_epoch="$(date +%s)"
	log="$work_dir/${name}.log"
	rc=0
	if [[ "$name" == "soak" ]]; then
		GRIPLINE_SOAK_EVIDENCE_FILE="$result_dir/soak-telemetry.json" bash "$repo_dir/scripts/qualification/${script}" "$@" >"$log" 2>&1 || rc=$?
	else
		bash "$repo_dir/scripts/qualification/${script}" "$@" >"$log" 2>&1 || rc=$?
	fi
	ended="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	ended_epoch="$(date +%s)"
	status[$name]=$([[ "$rc" == 0 ]] && echo pass || echo fail)
	exit_code[$name]=$rc
	duration_seconds[$name]=$((ended_epoch - started_epoch))
	output_sha256[$name]="$(sha256sum "$log" | awk '{print $1}')"
	cat >"$result_dir/${name}.json" <<EOF
{
  "schema": 1,
  "suite": "gripline-reference-qualification-v1",
  "gate": "${name}",
  "commit": "${commit}",
  "started_at": "${started}",
  "finished_at": "${ended}",
  "duration_seconds": ${duration_seconds[$name]},
  "result": "${status[$name]}",
  "exit_code": ${rc},
  "output_sha256": "${output_sha256[$name]}"
}
EOF
	if [[ "$rc" != 0 ]]; then
		overall=1
		cat "$log" >&2
	fi
}

if [[ "$only_soak" == 0 ]]; then
	run_gate postgres-ha ha.sh
	run_gate postgres-pitr pitr.sh
	run_gate perimeter perimeter.sh
	run_gate replay replay.sh
	run_gate http2 http2.sh
	run_gate sdk sdk.sh
fi
run_gate soak soak.sh --duration "$soak_duration" --workers "$workers"

gate_status() {
	local key=$1
	printf '%s' "${status[$key]:-skipped}"
}

cat >"$result_dir/manifest.json" <<EOF
{
  "schema": 1,
  "suite": "gripline-reference-qualification-v1",
  "commit": "${commit}",
  "result": "$([[ "$overall" == 0 ]] && echo pass || echo fail)",
  "generated_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "soak_duration": "${soak_duration}",
  "workers": ${workers},
  "gates": {
    "postgres-ha": "$(gate_status postgres-ha)",
    "postgres-pitr": "$(gate_status postgres-pitr)",
    "perimeter": "$(gate_status perimeter)",
    "replay": "$(gate_status replay)",
    "http2": "$(gate_status http2)",
    "sdk": "$(gate_status sdk)",
    "soak": "$(gate_status soak)"
  },
  "fixture_images": {
    "postgres": "postgres:16@sha256:f1c3376c26f2609ab9f29f71f824103fe2fcd8ee0346485cb6122a4f93df6f94",
    "nginx": "nginx:alpine@sha256:72ba65eb42c10344912a84ff42408db7d34f2feb642204570ab8fc5ffd29f1d3",
    "curl": "curlimages/curl:8.10.1@sha256:d9b4541e214bcd85196d6e92e2753ac6d0ea699f0af5741f8c6cccbfcf00ef4b",
    "debian": "debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
  },
  "tool_versions": {
    "go": "$(safe_version go version)",
    "python": "$(safe_version python3 --version)",
    "node": "$(safe_version node --version)",
    "npm": "$(safe_version npm --version)",
    "docker": "$(safe_version docker version --format '{{.Server.Version}}')"
  }
}
EOF

(cd "$result_dir" && sha256sum manifest.json >manifest.sha256)
exit "$overall"
