#!/usr/bin/env python3
"""Small, credential-free-by-default vendor SDK qualification runner."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
import signal
import sys
from typing import Any


class QualificationTimeout(RuntimeError):
    pass


def timeout_handler(_signum: int, _frame: Any) -> None:
    raise QualificationTimeout("SDK call exceeded GRIPLINE_SDK_MAX_SECONDS")


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise SystemExit(f"qualification: {name} is required")
    return value


def numeric_usage(usage: Any) -> dict[str, int]:
    if usage is None:
        return {}
    if hasattr(usage, "model_dump"):
        raw = usage.model_dump()
    elif hasattr(usage, "__dict__"):
        raw = vars(usage)
    else:
        raw = dict(usage)
    return {key: int(value) for key, value in raw.items() if value is not None and isinstance(value, (int, float))}


def usage_or_fail(usage: Any) -> dict[str, int]:
    result = numeric_usage(usage)
    if not result and os.environ.get("GRIPLINE_SDK_EXPECT_USAGE", "1") == "1":
        raise RuntimeError("provider response did not include usage")
    expected_raw = os.environ.get("GRIPLINE_SDK_EXPECT_USAGE_JSON")
    if expected_raw:
        expected = {key: int(value) for key, value in json.loads(expected_raw).items()}
        for key, value in expected.items():
            if result.get(key) != value:
                raise RuntimeError(f"usage mismatch for {key}: got {result.get(key)!r}, want {value}")
    return result


def scenario_request(model: str) -> tuple[str, dict[str, Any]]:
    scenario = os.environ.get("GRIPLINE_SDK_SCENARIO", "")
    suffix = os.environ.get("GRIPLINE_SDK_MODEL_SUFFIX", "")
    wire_model = f"{model}{suffix}-{scenario}" if scenario else f"{model}{suffix}"
    content = "qualification ping"
    if scenario == "large":
        content = "qualification large input " + ("x" * 65536)
    request: dict[str, Any] = {
        "model": wire_model,
        "messages": [{"role": "user", "content": content}],
    }
    if scenario == "tool":
        request["tools"] = [{
            "type": "function",
            "function": {
                "name": "lookup",
                "description": "qualification tool",
                "parameters": {"type": "object", "properties": {"ok": {"type": "boolean"}}},
            },
        }]
    return scenario, request


def run_openai(base_url: str, api_key: str, model: str, stream: bool) -> dict[str, Any]:
    from openai import OpenAI

    profile = os.environ.get("GRIPLINE_SDK_PROFILE", "chat")
    scenario, request = scenario_request(model)
    retries = 1 if scenario == "retry" else 0
    client = OpenAI(base_url=base_url, api_key=api_key, max_retries=retries, timeout=float(env("GRIPLINE_SDK_MAX_SECONDS", "30")))

    def call_once() -> dict[str, Any]:
        if profile == "models":
            response = client.models.list()
            if not getattr(response, "data", None):
                raise RuntimeError("OpenAI models profile returned no models")
            return {"usage": {}}
        if profile == "embeddings":
            response = client.embeddings.create(model=request["model"], input=request["messages"][0]["content"])
            return {"usage": usage_or_fail(response.usage)}
        if profile == "responses":
            current = {"model": request["model"], "input": request["messages"][0]["content"], "stream": stream}
            if stream:
                events = 0
                usage = None
                for event in client.responses.create(**current):
                    events += 1
                    if getattr(event, "type", "") == "response.completed":
                        response = getattr(event, "response", None)
                        usage = getattr(response, "usage", None)
                return {"events": events, "usage": usage_or_fail(usage)}
            response = client.responses.create(**current)
            return {"usage": usage_or_fail(response.usage)}
        current = dict(request)
        current["stream"] = stream
        if stream:
            current["stream_options"] = {"include_usage": True}
            chunks = client.chat.completions.create(**current)
            count = 0
            usage = None
            for chunk in chunks:
                count += 1
                if getattr(chunk, "usage", None) is not None:
                    usage = chunk.usage
            return {"chunks": count, "usage": usage_or_fail(usage)}
        response = client.chat.completions.create(**current)
        if scenario == "tool" and not response.choices[0].message.tool_calls:
            raise RuntimeError("OpenAI tool scenario did not return a tool call")
        return {"usage": usage_or_fail(response.usage)}

    parallel = int(os.environ.get("GRIPLINE_SDK_PARALLEL", "0"))
    requests = int(os.environ.get("GRIPLINE_SDK_REQUESTS", "1"))
    if parallel:
        with ThreadPoolExecutor(max_workers=parallel) as pool:
            results = list(pool.map(lambda _index: call_once(), range(parallel)))
    else:
        results = [call_once() for _index in range(requests)]
    return {"provider": "openai", "stream": stream, "requests": len(results), "usage": results[0]["usage"]}


def run_anthropic(base_url: str, api_key: str, model: str, stream: bool) -> dict[str, Any]:
    from anthropic import Anthropic

    scenario, request = scenario_request(model)
    request["max_tokens"] = int(os.environ.get("GRIPLINE_SDK_MAX_TOKENS", "64"))
    if scenario == "tool":
        request["tools"] = [{
            "name": "lookup",
            "description": "qualification tool",
            "input_schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}},
        }]
    retries = 1 if scenario == "retry" else 0
    client = Anthropic(base_url=os.environ.get("GRIPLINE_SDK_ANTHROPIC_BASE_URL", base_url), api_key=api_key, max_retries=retries, timeout=float(env("GRIPLINE_SDK_MAX_SECONDS", "30")))

    def call_once() -> dict[str, Any]:
        current = dict(request)
        current["stream"] = stream
        if stream:
            events = client.messages.create(**current)
            count = 0
            usage: dict[str, int] = {}
            for event in events:
                count += 1
                event_usage = getattr(event, "usage", None)
                if getattr(event, "type", "") == "message_start":
                    message = getattr(event, "message", None)
                    event_usage = getattr(message, "usage", event_usage)
                if event_usage is not None:
                    usage.update(numeric_usage(event_usage))
            return {"events": count, "usage": usage_or_fail(usage)}
        response = client.messages.create(**current)
        if scenario == "tool" and not any(getattr(item, "type", "") == "tool_use" for item in response.content):
            raise RuntimeError("Anthropic tool scenario did not return a tool use")
        return {"usage": usage_or_fail(response.usage)}

    parallel = int(os.environ.get("GRIPLINE_SDK_PARALLEL", "0"))
    requests = int(os.environ.get("GRIPLINE_SDK_REQUESTS", "1"))
    if parallel:
        with ThreadPoolExecutor(max_workers=parallel) as pool:
            results = list(pool.map(lambda _index: call_once(), range(parallel)))
    else:
        results = [call_once() for _index in range(requests)]
    return {"provider": "anthropic", "stream": stream, "requests": len(results), "usage": results[0]["usage"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", choices=("openai", "anthropic"))
    args = parser.parse_args()
    base_url = env("GRIPLINE_SDK_BASE_URL")
    api_key = env("GRIPLINE_SDK_API_KEY")
    model = env("GRIPLINE_SDK_MODEL")
    stream = os.environ.get("GRIPLINE_SDK_STREAM", "0") == "1"
    max_seconds = int(env("GRIPLINE_SDK_MAX_SECONDS", "30"))
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(max_seconds)
    try:
        result = run_openai(base_url, api_key, model, stream) if args.provider == "openai" else run_anthropic(base_url, api_key, model, stream)
    except QualificationTimeout as exc:
        print(f"qualification: {exc}", file=sys.stderr)
        return 124
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
