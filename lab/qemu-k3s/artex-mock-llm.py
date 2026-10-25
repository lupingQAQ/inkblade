#!/usr/bin/env python
"""Minimal OpenAI/Anthropic-compatible mock LLM for the ARTEX-in-VM benchmark.

Why: ARTEX is a fully LLM-driven agent (planner + worker on agent-core). The lab
has no paid model endpoint, so this server answers ``/v1/chat/completions`` (and
Anthropic ``/v1/messages``) with a *deterministic, protocol-valid* reply:

  * turn 1  -> a ``tool_calls`` entry using the first tool advertised by the
               client (arguments come from ``--tool-args`` when the name matches,
               otherwise ``{}``),
  * turn 2+ -> a plain assistant message (``finish_reason=stop``) that ends the
               agent loop.

Every request is appended to a JSONL log so the report can quote real
per-request timings instead of claiming an LLM was used.

Only the Python standard library is used (no pip install needed).

    python lab/qemu-k3s/artex-mock-llm.py --port 18081 --log out/mock-llm.jsonl
"""
from __future__ import annotations

import argparse
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_LOCK = threading.Lock()
STATE = {"requests": 0}
CONFIG = {
    "log_path": None,
    "max_tool_calls": 1,
    "model": "mock-agent-model",
    "final_text": "BENCH-MOCK: exploration stopped by mock LLM (protocol-valid reply).",
    "tool_args": {},
}


def _log(record: dict) -> None:
    path = CONFIG["log_path"]
    if not path:
        return
    with LOG_LOCK:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _count_tools(body: dict) -> list[str]:
    names = []
    for tool in body.get("tools") or []:
        if isinstance(tool, dict):
            fn = tool.get("function") or {}
            name = fn.get("name") or tool.get("name")
            if name:
                names.append(str(name))
    return names


def _pick_tool(body: dict) -> tuple[str, str] | None:
    """Return (name, arguments-json) for the next tool call, or None to stop."""
    if STATE["requests"] > CONFIG["max_tool_calls"]:
        return None
    names = _count_tools(body)
    if not names:
        return None
    name = names[0]
    args = CONFIG["tool_args"].get(name, "{}")
    if not isinstance(args, str):
        args = json.dumps(args, ensure_ascii=False)
    return name, args


def _openai_stream(handler: "Handler", body: dict, record: dict) -> None:
    call = _pick_tool(body)
    model = body.get("model") or CONFIG["model"]
    created = int(time.time())
    base = {"id": f"chatcmpl-mock-{uuid.uuid4().hex[:8]}", "created": created, "model": model}
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.end_headers()

    def sse(payload: dict) -> None:
        handler.wfile.write(b"data: " + json.dumps(payload).encode() + b"\n\n")
        handler.wfile.flush()

    sse({**base, "object": "chat.completion.chunk", "choices": [
        {"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]})
    if call:
        name, args = call
        record["reply"] = {"type": "tool_call", "name": name, "arguments": args}
        sse({**base, "object": "chat.completion.chunk", "choices": [{
            "index": 0,
            "delta": {"tool_calls": [{"index": 0, "id": f"call_mock_{STATE['requests']}",
                                       "type": "function",
                                       "function": {"name": name, "arguments": ""}}]},
            "finish_reason": None}]})
        sse({**base, "object": "chat.completion.chunk", "choices": [{
            "index": 0,
            "delta": {"tool_calls": [{"index": 0, "function": {"arguments": args}}]},
            "finish_reason": None}]})
        sse({**base, "object": "chat.completion.chunk", "choices": [
            {"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
    else:
        text = CONFIG["final_text"]
        record["reply"] = {"type": "text", "chars": len(text)}
        sse({**base, "object": "chat.completion.chunk", "choices": [
            {"index": 0, "delta": {"content": text}, "finish_reason": None}]})
        sse({**base, "object": "chat.completion.chunk", "choices": [
            {"index": 0, "delta": {}, "finish_reason": "stop"}]})
    handler.wfile.write(b"data: [DONE]\n\n")
    handler.wfile.flush()


def _openai_json(handler: "Handler", body: dict, record: dict) -> None:
    call = _pick_tool(body)
    model = body.get("model") or CONFIG["model"]
    message: dict = {"role": "assistant", "content": None}
    if call:
        name, args = call
        record["reply"] = {"type": "tool_call", "name": name, "arguments": args}
        message["tool_calls"] = [{"id": f"call_mock_{STATE['requests']}", "type": "function",
                                  "function": {"name": name, "arguments": args}}]
    else:
        message["content"] = CONFIG["final_text"]
        record["reply"] = {"type": "text", "chars": len(CONFIG["final_text"])}
    payload = {
        "id": f"chatcmpl-mock-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": "tool_calls" if call else "stop",
        }],
        # Deterministic token accounting (the mock is not a real tokenizer).
        "usage": {"prompt_tokens": record.get("prompt_chars", 0) // 4,
                  "completion_tokens": 16, "total_tokens": record.get("prompt_chars", 0) // 4 + 16},
    }
    body_bytes = json.dumps(payload).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


def _anthropic(handler: "Handler", body: dict, record: dict) -> None:
    call = _pick_tool(body)
    if call:
        name, args = call
        record["reply"] = {"type": "tool_use", "name": name, "arguments": args}
        try:
            input_obj = json.loads(args)
        except json.JSONDecodeError:
            input_obj = {}
        content = [{"type": "tool_use", "id": f"toolu_mock_{STATE['requests']}", "name": name,
                    "input": input_obj}]
        stop_reason = "tool_use"
    else:
        content = [{"type": "text", "text": CONFIG["final_text"]}]
        record["reply"] = {"type": "text", "chars": len(CONFIG["final_text"])}
        stop_reason = "end_turn"
    payload = {
        "id": f"msg_mock_{uuid.uuid4().hex[:8]}",
        "type": "message",
        "role": "assistant",
        "model": body.get("model") or CONFIG["model"],
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": record.get("prompt_chars", 0) // 4, "output_tokens": 16},
    }
    body_bytes = json.dumps(payload).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # keep stderr readable
        if self.path in ("/health", "/v1/models"):
            return
        print(f"[mock-llm] {self.address_string()} {fmt % args}", flush=True)

    def _json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {"_raw": raw.decode("utf-8", "replace")}

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") in ("/health", "/healthz"):
            self._send_json({"ok": True, "requests": STATE["requests"]})
        elif self.path.rstrip("/").endswith("/v1/models") or self.path == "/models":
            self._send_json({"object": "list", "data": [
                {"id": CONFIG["model"], "object": "model", "owned_by": "lab-mock"}]})
        elif self.path.rstrip("/").endswith("/__mock_stats__"):
            self._send_json({"requests": STATE["requests"], "max_tool_calls": CONFIG["max_tool_calls"]})
        else:
            self._send_json({"error": "not found", "path": self.path}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        body = self._json_body()
        STATE["requests"] += 1
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "n": STATE["requests"],
            "path": self.path,
            "method": "POST",
            "model": body.get("model"),
            "stream": bool(body.get("stream")),
            "messages": len(body.get("messages") or []),
            "tool_count": len(_count_tools(body)),
            "tools": _count_tools(body)[:12],
            "prompt_chars": len(json.dumps(body.get("messages") or [], ensure_ascii=False)),
        }
        path = self.path.rstrip("/")
        try:
            if path.endswith("/chat/completions"):
                if body.get("stream"):
                    _openai_stream(self, body, record)
                else:
                    _openai_json(self, body, record)
            elif path.endswith("/messages"):
                _anthropic(self, body, record)
            else:
                record["reply"] = {"type": "unsupported"}
                self._send_json({"error": "unsupported path", "path": self.path}, status=404)
        finally:
            record["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            _log(record)

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--log", default="")
    ap.add_argument("--max-tool-calls", type=int, default=1)
    ap.add_argument("--model", default="mock-agent-model")
    ap.add_argument("--tool-args", default="{}",
                    help='JSON map tool-name -> arguments JSON, e.g. \'{"bash":{"command":"id"}}\'')
    args = ap.parse_args()
    CONFIG["log_path"] = args.log or None
    CONFIG["max_tool_calls"] = args.max_tool_calls
    CONFIG["model"] = args.model
    try:
        CONFIG["tool_args"] = json.loads(args.tool_args or "{}")
    except json.JSONDecodeError:
        CONFIG["tool_args"] = {}
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[mock-llm] listening on http://{args.host}:{args.port} "
          f"(max_tool_calls={args.max_tool_calls}, log={CONFIG['log_path']})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
