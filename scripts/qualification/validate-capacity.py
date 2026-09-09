#!/usr/bin/env python3
"""Apply strict, machine-readable acceptance criteria to a load result."""

from __future__ import annotations

import json
import sys


def main() -> int:
    path, minimum_text = sys.argv[1:]
    minimum = float(minimum_text)
    with open(path, encoding="utf-8") as stream:
        result = json.load(stream)

    counts = {
        str(key): int(value)
        for key, value in result.get("status_counts", {}).items()
    }
    total = int(result.get("total", 0))
    successful = int(result.get("successful", 0))
    if total <= 0:
        raise SystemExit("capacity load produced no requests")

    ratio = successful / total
    request_errors = counts.get("request_error", 0)
    response_errors = counts.get("response_error", 0)
    status_5xx = sum(
        value
        for key, value in counts.items()
        if key.isdigit() and 500 <= int(key) <= 599
    )
    unexpected_4xx = sum(
        value
        for key, value in counts.items()
        if key.isdigit() and 400 <= int(key) <= 499
    )
    unexpected_statuses = {
        key: value
        for key, value in counts.items()
        if not (key.isdigit() and 200 <= int(key) <= 299)
    }
    failures = []
    if ratio < minimum:
        failures.append(f"success ratio {ratio:.6f} < {minimum:.6f}")
    if request_errors:
        failures.append(f"request_error={request_errors}")
    if response_errors:
        failures.append(f"response_error={response_errors}")
    if status_5xx:
        failures.append(f"5xx={status_5xx}")
    if unexpected_4xx:
        failures.append(f"unexpected_4xx={unexpected_4xx}")
    if unexpected_statuses:
        failures.append(f"unexpected_statuses={unexpected_statuses}")
    latency = result.get("latency", {})
    if not latency.get("all") or not latency.get("successful"):
        failures.append("structured latency is incomplete")
    if failures:
        raise SystemExit("capacity qualification failed: " + "; ".join(failures))

    print(
        f"capacity qualification: total={total} successful={successful} "
        f"ratio={ratio:.6f} statuses={counts}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
