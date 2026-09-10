#!/usr/bin/env bash

# Gate scripts call this only after their semantic checks have passed. The
# suite embeds the resulting proof object into the signed gate record.
emit_qualification_assertions() {
	local output_path="${GRIPLINE_QUALIFICATION_ASSERTIONS_FILE:-}"
	if [[ -z "$output_path" ]]; then
		return 0
	fi
	local assertions=${1:-"{}"}
	local measurements=${2:-"{}"}
	mkdir -p "$(dirname "$output_path")"
	printf '{"assertions":%s,"measurements":%s}\n' "$assertions" "$measurements" >"$output_path"
}

register_qualification_secret() {
	local denylist="${GRIPLINE_QUALIFICATION_DENYLIST_FILE:-}"
	if [[ -n "$denylist" && -n "${1:-}" ]]; then
		printf '%s\n' "$1" >>"$denylist"
	fi
}
