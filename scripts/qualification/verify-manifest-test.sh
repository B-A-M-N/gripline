#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$(mktemp -d)"
cleanup() { rm -rf "$fixture_dir"; }
trap cleanup EXIT

printf '{"schema":2,"commit":"fixture","gate":"soak","result":"pass","exit_code":0,"log":{"path":"soak-log.txt","sha256":"LOG_PLACEHOLDER"},"telemetry":{"path":"soak-telemetry.json","sha256":"TELEMETRY_PLACEHOLDER"}}\n' >"$fixture_dir/soak.json"
printf 'telemetry\n' >"$fixture_dir/soak-telemetry.json"
printf 'sanitized log\n' >"$fixture_dir/soak-log.txt"
telemetry_hash="$(sha256sum "$fixture_dir/soak-telemetry.json" | awk '{print $1}')"
log_hash="$(sha256sum "$fixture_dir/soak-log.txt" | awk '{print $1}')"
sed -i "s/LOG_PLACEHOLDER/$log_hash/" "$fixture_dir/soak.json"
sed -i "s/TELEMETRY_PLACEHOLDER/$telemetry_hash/" "$fixture_dir/soak.json"
record_hash="$(sha256sum "$fixture_dir/soak.json" | awk '{print $1}')"
cat >"$fixture_dir/manifest.json" <<EOF
{"schema":2,"commit":"fixture","result":"pass","required_gates":["soak"],"gates":{"soak":"pass"},"evidence":{"soak":{"record":{"path":"soak.json","sha256":"$record_hash"},"log":{"path":"soak-log.txt","sha256":"$log_hash"},"telemetry":{"path":"soak-telemetry.json","sha256":"$telemetry_hash"}}}}
EOF
(cd "$fixture_dir" && sha256sum manifest.json >manifest.sha256)
bash "$repo_dir/scripts/qualification/verify-manifest.sh" "$fixture_dir" fixture >/dev/null

expect_reject() {
	local label=$1
	if bash "$repo_dir/scripts/qualification/verify-manifest.sh" "$fixture_dir" fixture >/dev/null 2>&1; then
		echo "qualification manifest ${label} unexpectedly passed" >&2
		exit 1
	fi
}

printf 'tampered\n' >"$fixture_dir/soak-telemetry.json"
expect_reject telemetry-tamper
printf '{"tampered":true}\n' >"$fixture_dir/soak.json"
expect_reject record-tamper
sed -i 's/"gates":{"soak":"pass"}/"gates":{}/' "$fixture_dir/manifest.json"
expect_reject missing-required-gate
echo "qualification manifest: pass and telemetry/record/missing-gate tamper rejection passed"
