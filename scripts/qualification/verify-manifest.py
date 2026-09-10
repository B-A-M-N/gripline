#!/usr/bin/env python3
"""Verify repository-owned qualification evidence as a release gate."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


REQUIRED_ASSERTIONS = {
    "postgres-ha": ("promotion_completed", "state_fingerprint_equal", "live_writer_continuity", "rejoin_state_preserved"),
    "postgres-pitr": ("target_point_restored", "recovered_state_fingerprint_equal", "baseline_ready", "missing_signer_fail_closed", "missing_pepper_fail_closed", "missing_pseudonym_fail_closed", "missing_policy_fail_closed", "missing_schema_fail_closed"),
    "perimeter": ("mtls_identity_separation", "raw_credential_denied", "public_isolation", "control_isolation", "database_isolation"),
    "clustered-perimeter": ("mtls_identity_separation", "raw_credential_denied", "public_isolation", "control_isolation", "database_isolation"),
    "replay": ("parallel_claim_single_winner", "independent_processes_used"),
    "http2": ("alpn_h2_negotiated", "stream_limit_enforced", "continuation_case_passed", "cancellation_recovered"),
    "sdk": ("python_provider_passed", "typescript_provider_passed", "retry_429_passed", "server_error_passed", "cancellation_passed", "connection_reuse_passed", "parallel_passed"),
    "exact-cost": ("openai_exact_deltas", "anthropic_exact_deltas", "cache_dimensions_exact", "zero_conservative_fallbacks"),
    "source-churn": ("invalid_source_misses_read_only", "invalid_source_receipt_complete", "preauth_state_bounded", "backend_isolated", "authenticated_sources_registered", "source_scope_overflow_bounded", "rotation_overlap_continuous", "stale_alias_maintenance_succeeded"),
    "soak": ("cluster_ha_recovery", "runtime_bounds_held", "maintenance_succeeded", "promotion_traffic_succeeded", "database_outage_recovered"),
    "capacity-load": ("load_completed", "concurrency_bound_enforced", "resource_state_bounded"),
}

REQUIRED_MEASUREMENTS = {
    "postgres-ha": {"state_fingerprint_sha256": str, "rejoin_role": str},
    "postgres-pitr": {"target_point": str, "recovered_state_fingerprint_sha256": str, "readiness_fail_closed_cases": int},
    "perimeter": {"mode": str},
    "clustered-perimeter": {"mode": str},
    "replay": {"accepted_winners": int},
    "http2": {"advertised_max_streams": int, "http2_errors": int, "h2load_version": str},
    "sdk": {"providers_tested": int, "minimum_sessions_per_provider": int},
    "exact-cost": {"verified_cases": int, "conservative_settlements": int},
    "source-churn": {
        "invalid_sources": int,
        "invalid_requests_attempted": int,
        "invalid_requests_completed": int,
        "invalid_401": int,
        "invalid_429": int,
        "invalid_transport_errors": int,
        "invalid_unexpected_statuses": int,
        "aliases_before": int,
        "aliases_after_invalid": int,
        "adaptive_rows_after_invalid": int,
        "adaptive_subjects_after_invalid": int,
        "adaptive_keys_after_invalid": int,
        "adaptive_baselines_after_invalid": int,
        "adaptive_subject_bound": int,
        "adaptive_key_bound": int,
        "preauth_source_table_entries_peak": int,
        "preauth_source_table_bound": int,
        "backend_hits_from_invalid": int,
        "revoked_requests_attempted": int,
        "revoked_requests_completed": int,
        "revoked_401": int,
        "revoked_403": int,
        "revoked_transport_errors": int,
        "revoked_unexpected_statuses": int,
        "revoked_aliases_before": int,
        "revoked_aliases_after": int,
        "resource_denied_attempted": int,
        "resource_denied_completed": int,
        "resource_denied_authorized": int,
        "resource_denied_denials": int,
        "resource_denied_transport_errors": int,
        "resource_denied_unexpected_statuses": int,
        "authenticated_aliases_created": int,
        "authenticated_source_requests": int,
        "authenticated_source_failures": int,
        "authenticated_over_bound_attempted": int,
        "authenticated_over_bound_successes": int,
        "authenticated_over_bound_denials": int,
        "source_alias_identity_bound": int,
        "source_alias_identities_after_over_bound": int,
        "source_alias_rows_after_over_bound": int,
        "source_alias_capacity_denials": int,
        "source_alias_saturations": int,
        "source_alias_safe_evictions": int,
        "source_scope_bound": int,
        "source_scopes_peak": int,
        "source_scope_overflows": int,
        "rotation_source_scopes_before": int,
        "rotation_source_scopes_after": int,
        "stale_aliases_before_maintenance": int,
        "stale_aliases_after_maintenance": int,
        "source_resolution_failures": int,
        "authority_timeouts": int,
    },
    "soak": {"duration_seconds": int, "workers": int, "post_promotion_recovery_ms": int},
    "capacity-load": {
        "duration_seconds": int,
        "workers": int,
        "authority_operation_timeout_ms": int,
        "total_requests": int,
        "successful_requests": int,
        "success_ratio": (int, float),
        "successful_rps": (int, float),
        "p50_ms": (int, float),
        "p95_ms": (int, float),
        "p99_ms": (int, float),
        "source_resolution_failures": int,
        "authority_timeouts": int,
        "transaction_retries": int,
        "deadlocks": int,
    },
}


def fail(message: str) -> None:
    raise SystemExit(f"qualification manifest: {message}")


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: pathlib.Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path.name}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.name} must contain an object")
    return value


def verify_source_churn_measurements(measurements: dict) -> None:
    """Enforce the source-churn gate's security and boundedness contract."""
    if measurements["invalid_sources"] <= 0:
        fail("source-churn invalid source count must be positive")
    if measurements["invalid_requests_attempted"] != measurements["invalid_sources"] or measurements["invalid_requests_completed"] != measurements["invalid_requests_attempted"]:
        fail("source-churn invalid request receipt is incomplete")
    if measurements["invalid_transport_errors"] != 0 or measurements["invalid_unexpected_statuses"] != 0:
        fail("source-churn invalid request receipt contains transport errors or unexpected statuses")
    if measurements["invalid_requests_completed"] != measurements["invalid_401"] + measurements["invalid_429"]:
        fail("source-churn invalid request receipt contains a status outside the denial set")
    if measurements["aliases_before"] != 0 or measurements["aliases_after_invalid"] != 0:
        fail("source-churn invalid requests created durable aliases")
    if measurements["backend_hits_from_invalid"] != 0:
        fail("source-churn invalid requests reached the backend")
    if measurements["revoked_requests_completed"] != measurements["revoked_requests_attempted"] or measurements["revoked_401"] + measurements["revoked_403"] != measurements["revoked_requests_attempted"] or measurements["revoked_transport_errors"] != 0 or measurements["revoked_unexpected_statuses"] != 0 or measurements["revoked_aliases_before"] != measurements["revoked_aliases_after"]:
        fail("source-churn revoked known-credential requests were not denied without alias binding")
    if measurements["resource_denied_attempted"] != 2 or measurements["resource_denied_completed"] != 2 or measurements["resource_denied_authorized"] != 1 or measurements["resource_denied_denials"] != 1 or measurements["resource_denied_transport_errors"] != 0 or measurements["resource_denied_unexpected_statuses"] != 0:
        fail("source-churn valid resource-denied receipt is incomplete")

    if measurements["adaptive_rows_after_invalid"] != (
        measurements["adaptive_subjects_after_invalid"]
        + measurements["adaptive_keys_after_invalid"]
        + measurements["adaptive_baselines_after_invalid"]
    ):
        fail("source-churn adaptive row measurement is inconsistent")
    if measurements["adaptive_subject_bound"] != 65536 or measurements["adaptive_key_bound"] != 256:
        fail("source-churn adaptive bounds do not match the detector contract")
    if measurements["adaptive_subjects_after_invalid"] > measurements["adaptive_subject_bound"]:
        fail("source-churn adaptive subject bound was exceeded")
    if measurements["adaptive_keys_after_invalid"] > measurements["adaptive_subject_bound"] * measurements["adaptive_key_bound"]:
        fail("source-churn adaptive key bound was exceeded")
    if measurements["adaptive_baselines_after_invalid"] > measurements["adaptive_subject_bound"]:
        fail("source-churn adaptive baseline bound was exceeded")

    if measurements["preauth_source_table_bound"] <= 0:
        fail("source-churn pre-auth bound must be positive")
    if measurements["preauth_source_table_entries_peak"] > measurements["preauth_source_table_bound"] + 64:
        fail("source-churn pre-auth source bound was exceeded")

    if measurements["authenticated_source_requests"] <= 0:
        fail("source-churn authenticated source count must be positive")
    if measurements["authenticated_source_failures"] != 0:
        fail("source-churn authenticated source requests failed")
    if measurements["authenticated_aliases_created"] < measurements["authenticated_source_requests"]:
        fail("source-churn authenticated aliases are incomplete")
    if measurements["authenticated_over_bound_attempted"] != 2 or measurements["authenticated_over_bound_successes"] != 1 or measurements["authenticated_over_bound_denials"] != 1:
        fail("source-churn authenticated over-bound proof is incomplete")
    if measurements["source_alias_identity_bound"] < measurements["authenticated_source_requests"] + 3:
        fail("source-churn alias bound is smaller than its qualification fixture")
    if measurements["source_alias_identities_after_over_bound"] > measurements["source_alias_identity_bound"]:
        fail("source-churn canonical source identity cardinality exceeded its hard bound")
    if measurements["source_alias_capacity_denials"] < 1 or measurements["source_alias_saturations"] < 1 or measurements["source_alias_safe_evictions"] < 1:
        fail("source-churn source alias telemetry did not prove saturation, denial, and safe eviction")

    if measurements["source_scope_bound"] <= 0:
        fail("source-churn source-scope bound must be positive")
    if measurements["source_scopes_peak"] > measurements["source_scope_bound"]:
        fail("source-churn source-scope bound was exceeded")
    if measurements["source_scope_overflows"] < 1:
        fail("source-churn did not exercise source-scope overflow")
    if measurements["rotation_source_scopes_before"] != measurements["rotation_source_scopes_after"]:
        fail("source-churn rotation changed source-scope cardinality")

    if measurements["stale_aliases_before_maintenance"] != 1 or measurements["stale_aliases_after_maintenance"] != 0:
        fail("source-churn stale alias maintenance did not reclaim the expected identity")
    if measurements["source_resolution_failures"] != 0 or measurements["authority_timeouts"] != 0:
        fail("source-churn observed authority failures or timeouts")


def verify_hash(root: pathlib.Path, entry: dict, label: str) -> pathlib.Path:
    path_value = entry.get("path")
    expected = entry.get("sha256")
    if not isinstance(path_value, str) or not isinstance(expected, str) or len(expected) != 64:
        fail(f"{label} must contain path and sha256")
    path = (root / path_value).resolve()
    if root not in path.parents:
        fail(f"{label} escapes result directory")
    if not path.is_file():
        fail(f"{label} file is missing: {path_value}")
    actual = sha256(path)
    if actual != expected:
        fail(f"{label} hash mismatch: expected {expected}, got {actual}")
    return path


def main() -> None:
    if len(sys.argv) not in (2, 3):
        fail("usage: verify-manifest.py RESULT_DIR [EXPECTED_COMMIT]")
    root = pathlib.Path(sys.argv[1]).resolve()
    manifest_path = root / "manifest.json"
    manifest = load_json(manifest_path)
    if manifest.get("schema") != 2:
        fail("manifest schema must be 2")
    if manifest.get("result") != "pass":
        fail("manifest result is not pass")
    commit = manifest.get("commit")
    if not isinstance(commit, str) or not commit:
        fail("manifest commit is missing")
    if len(sys.argv) == 3 and commit != sys.argv[2]:
        fail(f"manifest commit {commit} does not match expected {sys.argv[2]}")
    gates = manifest.get("gates")
    required = manifest.get("required_gates")
    evidence = manifest.get("evidence")
    if not isinstance(gates, dict) or not isinstance(required, list) or not required:
        fail("required_gates and gates are required")
    if not isinstance(evidence, dict):
        fail("evidence object is required")

    mode = manifest.get("qualification_mode")
    expected_required = {
        "full": ("postgres-ha", "postgres-pitr", "perimeter", "clustered-perimeter", "replay", "http2", "sdk", "exact-cost", "source-churn", "soak", "capacity-load"),
        "only-soak": ("soak",),
    }.get(mode)
    if expected_required is None:
        fail(f"unknown qualification_mode: {mode}")
    if any(not isinstance(gate_name, str) for gate_name in required):
        fail("required gate names must be strings")
    if len(required) != len(set(required)):
        fail("required_gates contains duplicates")
    if required != list(expected_required):
        fail(f"required_gates does not match the {mode} gate contract")
    if set(gates) != set(expected_required):
        fail(f"gates does not match the {mode} gate contract")
    if set(evidence) != set(expected_required):
        fail(f"evidence does not match the {mode} gate contract")

    for gate_name in required:
        if not isinstance(gate_name, str):
            fail(f"required gate name is not a string: {gate_name}")
        if gate_name not in REQUIRED_ASSERTIONS:
            fail(f"unknown required gate schema: {gate_name}")
        if gates.get(gate_name) != "pass":
            fail(f"required gate did not pass: {gate_name}")
        entry = evidence.get(gate_name)
        if not isinstance(entry, dict):
            fail(f"missing evidence entry for {gate_name}")
        record_entry = entry.get("record")
        if not isinstance(record_entry, dict):
            fail(f"missing record hash for {gate_name}")
        record_path = verify_hash(root, record_entry, f"{gate_name}.record")
        record = load_json(record_path)
        if record.get("schema") != 2:
            fail(f"{gate_name} record schema must be 2")
        if record.get("commit") != commit or record.get("gate") != gate_name:
            fail(f"{gate_name} record identity does not match manifest")
        if record.get("result") != "pass" or record.get("exit_code") != 0:
            fail(f"{gate_name} record is not a passing result")
        assertions = record.get("assertions")
        if not isinstance(assertions, dict):
            fail(f"{gate_name} gate-specific assertions are required")
        for assertion in REQUIRED_ASSERTIONS.get(gate_name, ()):
            if assertions.get(assertion) is not True:
                fail(f"{gate_name} assertion is missing or unsatisfied: {assertion}")
        measurements = record.get("measurements")
        if not isinstance(measurements, dict):
            fail(f"{gate_name} measurements object is required")
        for measurement, expected_type in REQUIRED_MEASUREMENTS.get(gate_name, {}).items():
            value = measurements.get(measurement)
            if not isinstance(value, expected_type) or isinstance(value, bool):
                fail(f"{gate_name} measurement is missing or has the wrong type: {measurement}")
        if gate_name == "source-churn":
            verify_source_churn_measurements(measurements)
        if gate_name == "capacity-load":
            if measurements.get("workers") != manifest.get("capacity_workers"):
                fail("capacity-load worker measurement does not match manifest capacity_workers")
            if measurements.get("authority_operation_timeout_ms") != 2000:
                fail("capacity-load authority timeout must be the 2000ms reference budget")

        record_log = record.get("log")
        manifest_log = entry.get("log")
        if not isinstance(manifest_log, dict) or not isinstance(record_log, dict):
            fail(f"{gate_name} sanitized log metadata is required")
        if manifest_log != record_log:
            fail(f"{gate_name} log metadata differs between record and manifest")
        verify_hash(root, manifest_log, f"{gate_name}.log")

        record_telemetry = record.get("telemetry")
        manifest_telemetry = entry.get("telemetry")
        if manifest_telemetry is not None:
            if not isinstance(manifest_telemetry, dict) or not isinstance(record_telemetry, dict):
                fail(f"{gate_name} telemetry metadata is incomplete")
            if manifest_telemetry != record_telemetry:
                fail(f"{gate_name} telemetry metadata differs between record and manifest")
            verify_hash(root, manifest_telemetry, f"{gate_name}.telemetry")
        elif record_telemetry is not None:
            fail(f"{gate_name} record declares telemetry absent from manifest")

    manifest_hash = root / "manifest.sha256"
    if not manifest_hash.is_file():
        fail("manifest.sha256 is missing")
    line = manifest_hash.read_text(encoding="utf-8").strip().split()
    if len(line) < 2 or line[1] != "manifest.json" or line[0] != sha256(manifest_path):
        fail("manifest.sha256 does not match manifest.json")
    print(f"qualification manifest: verified {len(required)} required gate(s) for {commit}")


if __name__ == "__main__":
    main()
