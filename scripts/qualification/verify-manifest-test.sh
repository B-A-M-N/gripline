#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$(mktemp -d)"
cleanup() { rm -rf "$fixture_dir"; }
trap cleanup EXIT

printf '{"schema":2,"commit":"fixture","gate":"soak","result":"pass","exit_code":0,"telemetry":{"path":"soak-telemetry.json","sha256":"PLACEHOLDER"}}\n' >"$fixture_dir/soak.json"
printf 'telemetry\n' >"$fixture_dir/soak-telemetry.json"
telemetry_hash="$(sha256sum "$fixture_dir/soak-telemetry.json" | awk '{print $1}')"
sed -i "s/PLACEHOLDER/$telemetry_hash/" "$fixture_dir/soak.json"
record_hash="$(sha256sum "$fixture_dir/soak.json" | awk '{print $1}')"
cat >"$fixture_dir/manifest.json" <<EOF
{"schema":2,"commit":"fixture","result":"pass","required_gates":["soak"],"gates":{"soak":"pass"},"evidence":{"soak":{"record":{"path":"soak.json","sha256":"$record_hash"},"telemetry":{"path":"soak-telemetry.json","sha256":"$telemetry_hash"}}}}
EOF
(cd "$fixture_dir" && sha256sum manifest.json >manifest.sha256)
bash "$repo_dir/scripts/qualification/verify-manifest.sh" "$fixture_dir" fixture >/dev/null
printf 'tampered\n' >"$fixture_dir/soak-telemetry.json"
if bash "$repo_dir/scripts/qualification/verify-manifest.sh" "$fixture_dir" fixture >/dev/null 2>&1; then
	echo "qualification manifest tamper test unexpectedly passed" >&2
	exit 1
fi
echo "qualification manifest: pass and tamper rejection passed"
