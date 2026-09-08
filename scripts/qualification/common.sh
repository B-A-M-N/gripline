#!/usr/bin/env bash
set -euo pipefail

# Shared guardrails for deployment-shaped qualification entrypoints. These
# helpers deliberately do not turn missing infrastructure into a pass.

qualification_repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
qualification_result_dir="${GRIPLINE_QUALIFICATION_RESULT_DIR:-$qualification_repo_dir/qualification/results}"

require_command() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "qualification: required command not found: $1" >&2
		exit 2
	}
}

require_env() {
	local name=$1
	if [[ -z "${!name:-}" ]]; then
		echo "qualification: required environment variable is unset: $name" >&2
		exit 2
	fi
}

csv_items() {
	local value=$1 item
	while IFS= read -r item; do
		item="${item#"${item%%[![:space:]]*}"}"
		item="${item%"${item##*[![:space:]]}"}"
		[[ -n "$item" ]] && printf '%s\n' "$item"
	done < <(printf '%s\n' "$value" | tr ',' '\n')
}

qualification_mkdir_results() {
	mkdir -p "$qualification_result_dir"
}

qualification_stamp() {
	date -u '+%Y-%m-%dT%H:%M:%SZ'
}

qualification_note() {
	echo "qualification[$(qualification_stamp)]: $*"
}

qualification_fail() {
	echo "qualification: $*" >&2
	exit 1
}

qualification_repo() {
	cd "$qualification_repo_dir"
}
