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

write_full_fixture() {
	python3 - "$fixture_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
required = [
    "postgres-ha", "postgres-pitr", "perimeter", "clustered-perimeter",
    "replay", "http2", "sdk", "exact-cost", "source-churn", "soak",
    "capacity-load",
]
assertions = {
    "postgres-ha": ["promotion_completed", "state_fingerprint_equal", "live_writer_continuity", "rejoin_state_preserved"],
    "postgres-pitr": ["target_point_restored", "recovered_state_fingerprint_equal", "baseline_ready", "missing_signer_fail_closed", "missing_pepper_fail_closed", "missing_pseudonym_fail_closed", "missing_policy_fail_closed", "missing_schema_fail_closed"],
    "perimeter": ["mtls_identity_separation", "raw_credential_denied", "public_isolation", "control_isolation", "database_isolation"],
    "clustered-perimeter": ["mtls_identity_separation", "raw_credential_denied", "public_isolation", "control_isolation", "database_isolation"],
    "replay": ["parallel_claim_single_winner", "independent_processes_used"],
    "http2": ["alpn_h2_negotiated", "stream_limit_enforced", "continuation_case_passed", "cancellation_recovered"],
    "sdk": ["python_provider_passed", "typescript_provider_passed", "retry_429_passed", "server_error_passed", "cancellation_passed", "connection_reuse_passed", "parallel_passed"],
    "exact-cost": ["openai_exact_deltas", "anthropic_exact_deltas", "cache_dimensions_exact", "zero_conservative_fallbacks"],
    "source-churn": ["invalid_source_misses_read_only", "preauth_state_bounded", "backend_isolated", "authenticated_sources_registered", "source_scope_overflow_bounded", "rotation_overlap_continuous", "stale_alias_maintenance_succeeded"],
    "soak": ["cluster_ha_recovery", "runtime_bounds_held", "maintenance_succeeded", "promotion_traffic_succeeded", "database_outage_recovered"],
    "capacity-load": ["load_completed", "concurrency_bound_enforced", "resource_state_bounded"],
}
measurements = {
    "postgres-ha": {"state_fingerprint_sha256": "a" * 64, "rejoin_role": "replica"},
    "postgres-pitr": {"target_point": "2026-01-01T00:00:00Z", "recovered_state_fingerprint_sha256": "b" * 64, "readiness_fail_closed_cases": 5},
    "perimeter": {"mode": "standalone"},
    "clustered-perimeter": {"mode": "clustered"},
    "replay": {"accepted_winners": 1},
    "http2": {"advertised_max_streams": 64, "http2_errors": 0, "h2load_version": "fixture"},
    "sdk": {"providers_tested": 2, "minimum_sessions_per_provider": 3},
    "exact-cost": {"verified_cases": 4, "conservative_settlements": 0},
    "source-churn": {
        "invalid_sources": 10000,
        "aliases_before": 0,
        "aliases_after_invalid": 0,
        "adaptive_rows_after_invalid": 0,
        "adaptive_subjects_after_invalid": 0,
        "adaptive_keys_after_invalid": 0,
        "adaptive_baselines_after_invalid": 0,
        "adaptive_subject_bound": 65536,
        "adaptive_key_bound": 256,
        "preauth_source_table_entries_peak": 64,
        "preauth_source_table_bound": 64,
        "backend_hits_from_invalid": 0,
        "authenticated_aliases_created": 16,
        "authenticated_source_requests": 16,
        "authenticated_source_failures": 0,
        "source_scope_bound": 16,
        "source_scopes_peak": 16,
        "source_scope_overflows": 1,
        "rotation_source_scopes_before": 16,
        "rotation_source_scopes_after": 16,
        "stale_aliases_before_maintenance": 1,
        "stale_aliases_after_maintenance": 0,
        "source_resolution_failures": 0,
        "authority_timeouts": 0,
    },
    "soak": {"duration_seconds": 30, "workers": 2, "post_promotion_recovery_ms": 100},
    "capacity-load": {
        "duration_seconds": 30, "workers": 16, "authority_operation_timeout_ms": 2000,
        "total_requests": 100, "successful_requests": 100, "success_ratio": 1.0,
        "successful_rps": 3.3, "p50_ms": 10.0, "p95_ms": 20.0, "p99_ms": 30.0,
        "source_resolution_failures": 0, "authority_timeouts": 0,
        "transaction_retries": 0, "deadlocks": 0,
    },
}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

evidence = {}
for gate in required:
    log_path = root / f"{gate}-log.txt"
    log_path.write_text("sanitized log\n", encoding="utf-8")
    log = {"path": log_path.name, "sha256": digest(log_path)}
    record = {
        "schema": 2, "commit": "fixture", "gate": gate, "result": "pass",
        "exit_code": 0,
        "assertions": {name: True for name in assertions[gate]},
        "measurements": measurements[gate], "log": log,
    }
    record_path = root / f"{gate}.json"
    record_path.write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")
    evidence[gate] = {"record": {"path": record_path.name, "sha256": digest(record_path)}, "log": log}

manifest = {
    "schema": 2, "commit": "fixture", "result": "pass", "qualification_mode": "full",
    "capacity_workers": 16, "required_gates": required,
    "gates": {gate: "pass" for gate in required}, "evidence": evidence,
}
manifest_path = root / "manifest.json"
manifest_path.write_text(json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8")
(root / "manifest.sha256").write_text(f"{digest(manifest_path)}  manifest.json\n", encoding="utf-8")
PY
}

mutate_source_churn_measurement() {
	local name=$1 value=$2
	python3 - "$fixture_dir" "$name" "$value" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
name, value = sys.argv[2:]
record_path = root / "source-churn.json"
record = json.loads(record_path.read_text(encoding="utf-8"))
record["measurements"][name] = int(value)
record_path.write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")
manifest_path = root / "manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["evidence"]["source-churn"]["record"]["sha256"] = hashlib.sha256(record_path.read_bytes()).hexdigest()
manifest_path.write_text(json.dumps(manifest, separators=(",", ":")) + "\n", encoding="utf-8")
(root / "manifest.sha256").write_text(
    f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  manifest.json\n",
    encoding="utf-8",
)
PY
}

write_full_fixture
bash "$repo_dir/scripts/qualification/verify-manifest.sh" "$fixture_dir" fixture >/dev/null
mutate_source_churn_measurement aliases_after_invalid 1
expect_reject source-churn-semantic-alias

write_full_fixture
mutate_source_churn_measurement source_scopes_peak 17
expect_reject source-churn-semantic-scope
echo "qualification manifest: semantic and hash tamper rejection passed"
