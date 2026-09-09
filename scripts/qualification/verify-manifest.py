#!/usr/bin/env python3
"""Verify repository-owned qualification evidence as a release gate."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


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

    for gate_name in required:
        if not isinstance(gate_name, str) or gates.get(gate_name) != "pass":
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
