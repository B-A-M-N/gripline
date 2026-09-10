#!/usr/bin/env python3
"""Reject credential, connection, and key material in qualification artifacts."""

from __future__ import annotations

import json
import pathlib
import re
import sys


PRIVATE_KEY = re.compile(rb"-----BEGIN [^-\r\n]*PRIVATE KEY-----")
DSN = re.compile(rb"postgres(?:ql)?://[^\s:@/]+:[^\s@]+@", re.IGNORECASE)
BEARER = re.compile(rb"Authorization:\s*Bearer\s+(?!<redacted>)[^\s]+", re.IGNORECASE)
REDACTED = {"", "<redacted>", "redacted", "[redacted]", "null"}
SENSITIVE_KEYS = {
    "token",
    "secret",
    "password",
    "dsn",
    "private_key",
    "privatekey",
    "api_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "credential_secret",
    "credential_value",
    "raw_credential",
    "authorization",
    "bearer",
}


def fail(message: str) -> None:
    raise SystemExit(f"qualification evidence scan: {message}")


def inspect_json(value: object, path: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in SENSITIVE_KEYS:
                if not isinstance(item, str) or item.strip().lower() not in REDACTED:
                    fail(f"sensitive JSON field {path}.{key} is not redacted")
            inspect_json(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            inspect_json(item, f"{path}[{index}]")


def main() -> None:
    if len(sys.argv) not in (2, 3):
        fail("usage: scan-evidence.py RESULT_DIR [DENYLIST]")
    root = pathlib.Path(sys.argv[1]).resolve()
    if not root.is_dir():
        fail(f"result directory is missing: {root}")
    denylist: list[bytes] = []
    if len(sys.argv) == 3:
        denylist_path = pathlib.Path(sys.argv[2]).resolve()
        if denylist_path.exists():
            denylist = [line.strip().encode() for line in denylist_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for literal in denylist:
            if literal in data:
                fail(f"denylisted fixture secret found in {path.relative_to(root)}")
        if PRIVATE_KEY.search(data):
            fail(f"private key material found in {path.relative_to(root)}")
        if DSN.search(data):
            fail(f"credential-bearing PostgreSQL DSN found in {path.relative_to(root)}")
        if BEARER.search(data):
            fail(f"unredacted bearer credential found in {path.relative_to(root)}")
        if path.suffix.lower() == ".json":
            try:
                inspect_json(json.loads(data.decode("utf-8")), str(path.relative_to(root)))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                fail(f"cannot inspect JSON artifact {path.name}: {exc}")
    print(f"qualification evidence scan: clean ({root})")


if __name__ == "__main__":
    main()
