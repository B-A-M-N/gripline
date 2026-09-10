#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_dir="$(mktemp -d)"
cleanup() { rm -rf "$fixture_dir"; }
trap cleanup EXIT

write_fixture() {
	python3 - "$fixture_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
(root / "soak-telemetry.json").write_text("telemetry\n", encoding="utf-8")
(root / "soak-log.txt").write_text("sanitized log\n", encoding="utf-8")
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
record = {
    "schema": 2,
    "commit": "fixture",
    "gate": "soak",
    "result": "pass",
    "exit_code": 0,
    "assertions": {
        "cluster_ha_recovery": True,
        "runtime_bounds_held": True,
        "maintenance_succeeded": True,
        "promotion_traffic_succeeded": True,
        "database_outage_recovered": True,
    },
    "measurements": {"duration_seconds": 30, "workers": 2, "post_promotion_recovery_ms": 100},
    "log": {"path": "soak-log.txt", "sha256": digest(root / "soak-log.txt")},
    "telemetry": {"path": "soak-telemetry.json", "sha256": digest(root / "soak-telemetry.json")},
}
(root / "soak.json").write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")
manifest = {
    "schema": 2,
    "commit": "fixture",
    "result": "pass",
    "qualification_mode": "only-soak",
    "required_gates": ["soak"],
    "gates": {"soak": "pass"},
    "evidence": {"soak": {
        "record": {"path": "soak.json", "sha256": digest(root / "soak.json")},
        "log": record["log"],
        "telemetry": record["telemetry"],
    }},
}
(root / "manifest.json").write_text(json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8")
(root / "manifest.sha256").write_text(f"{digest(root / 'manifest.json')}  manifest.json\n", encoding="utf-8")
PY
}

refresh_hashes() {
	python3 - "$fixture_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
record_path = root / "soak.json"
record = json.loads(record_path.read_text(encoding="utf-8"))
record_path.write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")
manifest_path = root / "manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["evidence"]["soak"]["record"]["sha256"] = digest(record_path)
manifest_path.write_text(json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8")
(root / "manifest.sha256").write_text(f"{digest(manifest_path)}  manifest.json\n", encoding="utf-8")
PY
}

expect_reject() {
	local label=$1
	if bash "$repo_dir/scripts/qualification/verify-manifest.sh" "$fixture_dir" fixture >/dev/null 2>&1; then
		echo "qualification manifest ${label} unexpectedly passed" >&2
		exit 1
	fi
}

write_fixture
bash "$repo_dir/scripts/qualification/verify-manifest.sh" "$fixture_dir" fixture >/dev/null
printf 'tampered\n' >"$fixture_dir/soak-telemetry.json"
expect_reject telemetry-tamper

write_fixture
python3 - "$fixture_dir/soak.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["assertions"]["cluster_ha_recovery"] = False
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
refresh_hashes
expect_reject assertion-false

write_fixture
python3 - "$fixture_dir/soak.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
del value["assertions"]["maintenance_succeeded"]
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
refresh_hashes
expect_reject assertion-missing

write_fixture
python3 - "$fixture_dir/soak.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["measurements"]["workers"] = "2"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
refresh_hashes
expect_reject measurement-wrong-type

write_fixture
python3 - "$fixture_dir/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["required_gates"].append("unknown-gate")
value["gates"]["unknown-gate"] = "pass"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
refresh_hashes
expect_reject unknown-gate-schema

write_fixture
python3 - "$fixture_dir/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["gates"] = {}
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
refresh_hashes
expect_reject missing-required-gate

write_fixture
python3 - "$fixture_dir/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["gates"]["unexpected"] = "pass"
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
refresh_hashes
expect_reject extra-gate-material

write_fixture
python3 - "$fixture_dir/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["evidence"]["unexpected"] = {}
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
refresh_hashes
expect_reject extra-evidence-material

write_fixture
python3 - "$fixture_dir/manifest.json" <<'PY'
import json
import sys
path = sys.argv[1]
value = json.loads(open(path, encoding="utf-8").read())
value["required_gates"].append("soak")
open(path, "w", encoding="utf-8").write(json.dumps(value) + "\n")
PY
refresh_hashes
expect_reject duplicate-required-gate
echo "qualification manifest: semantic and hash tamper rejection passed"
