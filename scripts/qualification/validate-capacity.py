#!/usr/bin/env python3
"""Apply strict, machine-readable acceptance criteria to a load result."""

from __future__ import annotations

import json
import os
import sys


def threshold(name: str, default: float) -> float:
    value = os.environ.get(name, "")
    return default if value == "" else float(value)


def main() -> int:
    args = sys.argv[1:]
    if len(args) not in (2, 3):
        raise SystemExit("usage: validate-capacity.py RESULT MIN_RATIO [POSTGRES_METRICS]")
    path, minimum_text = args[:2]
    minimum = float(minimum_text)
    with open(path, encoding="utf-8") as stream:
        result = json.load(stream)
    postgres = {}
    if len(args) == 3:
        with open(args[2], encoding="utf-8") as stream:
            postgres = json.load(stream)
        result["postgres"] = postgres

    min_success_rps = threshold("GRIPLINE_CAPACITY_MIN_SUCCESS_RPS", 10.0)
    max_p95_ms = threshold("GRIPLINE_CAPACITY_MAX_P95_MS", 5000.0)
    max_p99_ms = threshold("GRIPLINE_CAPACITY_MAX_P99_MS", 8000.0)
    max_retries_per_1000 = threshold("GRIPLINE_CAPACITY_MAX_RETRIES_PER_1000", 1500.0)
    max_deadlocks = threshold("GRIPLINE_CAPACITY_MAX_DEADLOCKS", 0.0)

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
    if result.get("successful_rps", 0.0) < min_success_rps:
        failures.append(
            f"successful RPS {result.get('successful_rps', 0.0):.6f} < {min_success_rps:.6f}"
        )
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
    source_resolution_failures = int(result.get("source_resolution_failures", 0))
    authority_timeouts = int(result.get("authority_timeouts", 0))
    if source_resolution_failures:
        failures.append(f"source resolution failures={source_resolution_failures}")
    if authority_timeouts:
        failures.append(f"authority timeouts={authority_timeouts}")
    latency = result.get("latency", {})
    if not latency.get("all") or not latency.get("successful"):
        failures.append("structured latency is incomplete")
    successful_latency = latency.get("successful", {})
    p95_ms = float(successful_latency.get("p95_ms", 0.0))
    p99_ms = float(successful_latency.get("p99_ms", 0.0))
    if p95_ms > max_p95_ms:
        failures.append(f"successful p95 {p95_ms:.3f}ms > {max_p95_ms:.3f}ms")
    if p99_ms > max_p99_ms:
        failures.append(f"successful p99 {p99_ms:.3f}ms > {max_p99_ms:.3f}ms")
    if postgres:
        serialization_retries = float(postgres.get("serialization_retries", 0))
        deadlock_retries = float(postgres.get("deadlock_retries", 0))
        retries_per_1000 = (serialization_retries + deadlock_retries) / total * 1000
        if retries_per_1000 > max_retries_per_1000:
            failures.append(
                f"transaction retries/1000 {retries_per_1000:.3f} > {max_retries_per_1000:.3f}"
            )
        if deadlock_retries > max_deadlocks:
            failures.append(f"deadlock retries {deadlock_retries:.0f} > {max_deadlocks:.0f}")
        result["qualification"] = {
            "min_success_rps": min_success_rps,
            "max_successful_p95_ms": max_p95_ms,
            "max_successful_p99_ms": max_p99_ms,
            "max_transaction_retries_per_1000": max_retries_per_1000,
            "max_deadlocks": max_deadlocks,
            "transaction_retries_per_1000": retries_per_1000,
            "source_resolution_failures": source_resolution_failures,
            "authority_timeouts": authority_timeouts,
        }
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    if failures:
        raise SystemExit("capacity qualification failed: " + "; ".join(failures))

    print(
        f"capacity qualification: total={total} successful={successful} "
        f"ratio={ratio:.6f} successful_rps={result.get('successful_rps', 0.0):.6f} "
        f"p95_ms={p95_ms:.3f} p99_ms={p99_ms:.3f} statuses={counts}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
