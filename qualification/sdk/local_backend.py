#!/usr/bin/env python3
"""Provider-shaped local backend for official SDK qualification."""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def response_for(path: str, stream: bool, request: dict) -> tuple[int, bytes, str, dict[str, str]]:
    model = request.get("model", "")
    if model.endswith("-cancel"):
        time.sleep(float(os.environ.get("GRIPLINE_SDK_CANCEL_DELAY", "4")))
    if model.endswith("-server-error"):
        return 503, b'{"error":{"type":"server_error","message":"qualification 5xx"}}', "application/json", {}
    if model.endswith("-retry"):
        with Handler._attempts_lock:
            attempt = Handler._attempts.get(model, 0) + 1
            Handler._attempts[model] = attempt
        if attempt == 1:
            return 429, b'{"error":{"type":"rate_limit_error","message":"qualification retry"}}', "application/json", {"Retry-After": "0.05"}
    if path.endswith("/messages"):
        cache_usage = {}
        if model.endswith("-cache"):
            cache_usage = {
                "cache_read_input_tokens": 4,
                "cache_creation_input_tokens": 3,
                "cache_creation": {
                    "ephemeral_5m_input_tokens": 2,
                    "ephemeral_1h_input_tokens": 1,
                },
            }
        if request.get("tools"):
            body = {
                "id": "msg_qualification_tool",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "toolu_qualification", "name": "lookup", "input": {"ok": True}}],
                "model": "local-qualification",
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 3, "output_tokens": 2, **cache_usage},
            }
            return 200, json.dumps(body).encode(), "application/json", {}
        body = {
            "id": "msg_qualification",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "qualification ok"}],
            "model": "local-qualification",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 3, "output_tokens": 2, **cache_usage},
        }
        if stream:
            stream_usage = {"input_tokens": 3, "output_tokens": 0, **cache_usage}
            events = [
                "event: message_start\ndata: " + json.dumps({"type": "message_start", "message": {"usage": stream_usage}}) + "\n\n",
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"qualification ok\"}}\n\n",
                "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":2}}\n\n",
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            ]
            return 200, "".join(events).encode(), "text/event-stream", {}
        return 200, json.dumps(body).encode(), "application/json", {}
    if path.endswith("/embeddings"):
        return 200, json.dumps({"object": "list", "data": [{"object": "embedding", "index": 0, "embedding": [0.0]}], "usage": {"prompt_tokens": 3, "total_tokens": 3}}).encode(), "application/json", {}
    if path.endswith("/responses"):
        response = {
            "id": "resp_qualification",
            "object": "response",
            "status": "completed",
            "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "qualification ok"}]}],
            "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
        }
        if stream:
            event = {"type": "response.completed", "response": response}
            return 200, ("event: response.completed\ndata: " + json.dumps(event) + "\n\n").encode(), "text/event-stream", {}
        return 200, json.dumps(response).encode(), "application/json", {}
    body = {
        "id": "chatcmpl_qualification",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "qualification ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
    }
    if request.get("tools"):
        body["choices"][0]["message"] = {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "call_qualification", "type": "function", "function": {"name": "lookup", "arguments": '{"ok":true}'}}],
        }
        body["choices"][0]["finish_reason"] = "tool_calls"
    if stream:
        events = [
            'data: {"choices":[{"delta":{"role":"assistant"}}]}\n\n',
            'data: {"choices":[{"delta":{"content":"qualification ok"}}]}\n\n',
            'data: {"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}\n\n',
            "data: [DONE]\n\n",
        ]
        return 200, "".join(events).encode(), "text/event-stream", {}
    return 200, json.dumps(body).encode(), "application/json", {}


class Handler(BaseHTTPRequestHandler):
    server_version = "gripline-qualification-backend"
    _attempts: dict[str, int] = {}
    _attempts_lock = threading.Lock()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self._body = self.rfile.read(min(length, 1 << 20))
        assertion = self.headers.get("X-Gripline-Assertion")
        expected = os.environ.get("GRIPLINE_INTERNAL_ASSERTION")
        if assertion is None and (not expected or self.headers.get("Authorization") != f"Bearer {expected}"):
            self.send_error(401, "gateway assertion required")
            return
        delay_ms = int(self.headers.get("X-Gripline-Qualification-Delay", "0"))
        if delay_ms > 0:
            time.sleep(min(delay_ms, 5000) / 1000)
        try:
            request = json.loads(self._body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "qualification request is not JSON")
            return
        stream = request.get("stream") is True
        status, payload, content_type, extra_headers = response_for(self.path, stream, request)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in extra_headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        assertion = self.headers.get("X-Gripline-Assertion")
        expected = os.environ.get("GRIPLINE_INTERNAL_ASSERTION")
        if assertion is None and (not expected or self.headers.get("Authorization") != f"Bearer {expected}"):
            self.send_error(401, "gateway assertion required")
            return
        if self.path.rstrip("/") != "/v1/models":
            self.send_error(404, "qualification endpoint not found")
            return
        payload = json.dumps({"object": "list", "data": [{"id": "local-qualification", "object": "model", "owned_by": "gripline-qualification"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    port = int(os.environ.get("GRIPLINE_LOCAL_BACKEND_PORT", "19090"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
