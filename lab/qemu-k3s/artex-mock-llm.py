#!/usr/bin/env python
"""artex-mock-llm.py — scripted-planner mock LLM for the ARTEX-in-VM benchmark.

v2 (same-target run). The v1 mock answered one generic tool call and then
stopped, which left ARTEX's planner idle and the task stuck in `running`
(see docs/ARTEX-BENCH-RESULT.md §6.2). This version is a *scripted planner*
reverse-engineered from the ARTEX v0.3.23 source
(.slim/clonedeps/repos/RuoJi6__ARTEX: agent/planner.go, agent/worker.go,
agent/tools.go, agent/toolcatalog.go, server/engine.go, server/goals.go):

  * which agent is asking is derived from the advertised tool set
    (goals decomposer advertises set_goals/set_constraints/add_task_scope;
    the planner advertises add_intent/prove_goal among 40 tools; a worker
    advertises report_finding/record_fact + the SDK defaults like Bash);
  * the goals decomposer answers with one real ``set_goals`` call so the
    task gets a judgeable goal node;
  * the planner is *content-driven*: it parses the graph_overview JSON that
    ARTEX pre-injects into its prompt and answers ``add_intent`` (no open
    intent yet), ``prove_goal`` (a finding exists to prove the open goal),
    or a plain stop message (work in flight);
  * the worker answers a fixed probe plan against the mock target —
    GET /__routes__, POST /pause, POST /pull_weights (the same surface the
    Trident chain flat-network-admin-plane-weight-poison exercises), then
    ``report_finding`` quoting the real tool outputs as evidence, then a
    plain-text summary. The HTTP runner adapts curl -> wget -> python3 when
    a tool result shows the binary is missing.

Every request (full tools incl. schemas + full messages) is appended to a
JSONL log with epoch-ms timestamps so the report can quote real per-request
timings and per-request token estimates computed from the request body.

Only the Python standard library is used.

    python lab/qemu-k3s/artex-mock-llm.py --port 18081 \
        --target-url http://10.0.2.2:18080 --log out/mock-llm.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_LOCK = threading.Lock()
STATE = {"requests": 0, "replies": []}
CONFIG = {
    "log_path": None,
    "model": "mock-agent-model",
    "target_url": "http://10.0.2.2:18080",
    "final_text": "MOCK-SCRIPT: nothing more to do for this turn (scripted planner).",
}

# ---------------------------------------------------------------------------
# request parsing helpers
# ---------------------------------------------------------------------------

HTTP_MARKER = "[HTTP "          # our curl -w suffix marks a completed probe
FINDING_MARKER = "finding recorded"
MAX_WORKER_RESULTS = 14         # hard stop for a runaway worker session

PROBES = [
    ("GET", "/__routes__", None, "route manifest discovery"),
    ("POST", "/pause", {}, "unauthenticated admin action (fail-open)"),
    ("POST", "/pull_weights",
     {"source_dir": "trident-bench/src", "local_checkpoint_dir": "checkpoints_bench"},
     "unauthenticated weight pull / poison write"),
]


def _tool_names(body: dict) -> list[str]:
    names = []
    for tool in body.get("tools") or []:
        if isinstance(tool, dict):
            fn = tool.get("function") or {}
            name = fn.get("name") or tool.get("name")
            if name:
                names.append(str(name))
    return names


def _tool_specs(body: dict) -> dict:
    """tool name -> raw schema dict of its parameters (for arg-name adaptation)."""
    specs = {}
    for tool in body.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        fn = tool.get("function") or {}
        name = fn.get("name") or tool.get("name")
        if name:
            specs[str(name)] = fn.get("parameters") or tool.get("parameters") or {}
    return specs


def _message_text(msg: dict) -> str:
    """Flatten one wire message to searchable text (content + tool_calls)."""
    parts = []
    content = msg.get("content")
    if isinstance(content, str):
        parts.append(content)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                if isinstance(block.get("text"), str):
                    parts.append(block["text"])
                if isinstance(block.get("content"), str):
                    parts.append(block["content"])
    calls = msg.get("tool_calls")
    if isinstance(calls, list):
        for call in calls:
            if isinstance(call, dict):
                fn = call.get("function") or {}
                parts.append(json.dumps(fn, ensure_ascii=False))
    return "\n".join(parts)


def _messages_ctx(body: dict) -> str:
    return "\n".join(_message_text(m) for m in body.get("messages") or [] if isinstance(m, dict))


def _tool_results(body: dict) -> list[str]:
    """Completed tool results in order (role=tool messages on the OpenAI wire
    format ARTEX uses; user-carried tool_result blocks as a protocol fallback)."""
    out = []
    for msg in body.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") == "tool":
            out.append(_message_text(msg))
        elif msg.get("role") == "user":
            text = _message_text(msg)
            if "tool_result" in text or "[HTTP" in text:
                out.append(text)
    return out


def _turn_index(body: dict) -> int:
    """How many tool interactions already happened in THIS conversation."""
    msgs = body.get("messages") or []
    tool_msgs = sum(1 for m in msgs if isinstance(m, dict) and m.get("role") == "tool")
    asst_calls = 0
    for m in msgs:
        if isinstance(m, dict) and m.get("role") == "assistant" and m.get("tool_calls"):
            asst_calls += len(m["tool_calls"])
    return max(tool_msgs, asst_calls)


def classify_agent(tools: list[str]) -> str:
    names = set(tools)
    if "set_goals" in names and "add_intent" not in names:
        return "goals"
    if "add_intent" in names and "prove_goal" in names:
        return "planner"
    if "report_finding" in names and "add_intent" not in names:
        return "worker"
    return "other"


def _array_objects(ctx: str, key: str) -> list[dict]:
    """Parse the JSON array embedded as `"key":[...]` into field dicts.

    ARTEX marshals the graph_overview with Go's compact map ordering; every
    element is a flat object, so a per-object regex is enough.
    """
    m = re.search(r'"%s"\s*:\s*\[(.*?)\]\s*[,}]' % re.escape(key), ctx, re.S)
    if not m:
        return []
    out = []
    for obj in re.findall(r"\{[^{}]*\}", m.group(1)):
        fields: dict[str, str] = {}
        for km in re.finditer(r'"([A-Za-z_]+)"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+|true|false|null)', obj):
            raw = km.group(2)
            if raw.startswith('"'):
                try:
                    fields[km.group(1)] = json.loads(raw)
                except json.JSONDecodeError:
                    fields[km.group(1)] = raw.strip('"')
            else:
                fields[km.group(1)] = raw
        out.append(fields)
    return out


def _int_field(obj: dict, key: str) -> int:
    try:
        return int(str(obj.get(key, "0")))
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# probe command builders (curl -> wget -> python3)
# ---------------------------------------------------------------------------

def _probe_command(method: str, url: str, body, variant: int) -> str:
    data = json.dumps(body, ensure_ascii=False) if body is not None else None
    if variant == 0:
        cmd = ["curl", "-sS", "-m", "20"]
        if method != "GET":
            cmd += ["-X", method]
        if data is not None:
            cmd += ["-H", "Content-Type: application/json", "-d", "'" + data + "'"]
        cmd += ["-w", "'\\n[HTTP %{http_code}]'", "'" + url + "'"]
        return " ".join(cmd)
    if variant == 1:
        cmd = ["wget", "-q", "-O", "-"]
        if method != "GET":
            cmd += ["--method=" + method]
        if data is not None:
            cmd += ["--header='Content-Type: application/json'",
                    "--body-data='" + data + "'"]
        cmd += ["'" + url + "'", "&&", "echo", "'[HTTP wget-ok]'"]
        return " ".join(cmd)
    # variant 2: python3 urllib (prints body head + the [HTTP <code>] marker)
    script = (
        "import urllib.request, urllib.error\n"
        "req = urllib.request.Request({url!r}, data={data!r}, method={method!r})\n"
        "if req.data:\n"
        "    req.add_header('Content-Type', 'application/json')\n"
        "try:\n"
        "    r = urllib.request.urlopen(req, timeout=20)\n"
        "    print(r.read().decode('utf-8', 'replace')[:4000]); print('[HTTP', r.status, ']')\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.read().decode('utf-8', 'replace')[:4000]); print('[HTTP', e.code, ']')\n"
    ).format(url=url, data=data, method=method)
    return "python3 - <<'PYEOF'\n" + script + "PYEOF"


def _failed_result(text: str) -> bool:
    lowered = text.lower()
    return ("[http" not in lowered) and any(
        token in lowered for token in (
            "not found", "command not found", "exit code 127", "exit status 127",
            "curl:", "wget:", "no such file", "usage:", "syntax error",
            "invalid request", "unknown tool", "error"))


# ---------------------------------------------------------------------------
# the scripted decision function (pure; unit-tested in tests/test_artex_same_target.py)
# ---------------------------------------------------------------------------

def scripted_reply(body: dict, cfg: dict) -> dict:
    """Decide the reply for one chat/completions request.

    Returns {"kind": "tool", "name": ..., "args": {...}} or
    {"kind": "text", "text": ...}. Purely a function of the request body.
    """
    tools = _tool_names(body)
    agent = classify_agent(tools)
    ctx = _messages_ctx(body)
    target = str(cfg.get("target_url") or CONFIG["target_url"]).rstrip("/")
    turn = _turn_index(body)

    if agent == "goals":
        if turn == 0:
            return {"kind": "tool", "name": "set_goals", "args": {"goals": [
                {"text": ("Probe the authorized lab target %s without credentials and "
                          "record confirmed unauthenticated admin or weight-pull "
                          "endpoints as findings." % target)}]}}
        return {"kind": "text", "text": "MOCK-SCRIPT: goal decomposition complete (1 goal)."}

    if agent == "planner":
        results = _tool_results(body)
        # Within ONE Plan() conversation the graph overview is only injected
        # with the first user message (ARTEX planner.go puts situational data
        # in the launch turn), so later turns must be decided from the tool
        # results of THIS conversation: never dispatch twice, never loop.
        dispatched = any(("intent created:" in r) or ('"ids":[' in r) for r in results)
        proved = any("marked met" in r for r in results)
        refreshed = any('"goals"' in r and '"finding_list"' not in r and r.startswith("{") for r in results)
        if proved or dispatched or refreshed or turn > 4:
            return {"kind": "text", "text":
                    "MOCK-SCRIPT: this planning round already acted (or is capped); "
                    "waiting for the next wake-up with a fresh overview."}
        goals = _array_objects(ctx, "goals")
        open_goals = [g for g in goals if str(g.get("state", "")).lower() != "met"]
        if not open_goals:
            return {"kind": "text", "text": "MOCK-SCRIPT: all goals met, nothing to plan."}
        goal_id = _int_field(open_goals[0], "id")
        findings = _array_objects(ctx, "finding_list")
        mt = re.search(r'"findings_total"\s*:\s*(\d+)', ctx)
        findings_total = int(mt.group(1)) if mt else 0
        if findings:
            evidence_id = _int_field(findings[0], "id")
            return {"kind": "tool", "name": "prove_goal", "args": {
                "goal_id": goal_id,
                "evidence_id": evidence_id,
                "reason": ("Worker probe of the lab target confirmed unauthenticated "
                           "admin and weight-pull endpoints; finding node %d is the "
                           "evidence." % evidence_id)}}
        if findings_total > 0:
            # findings exist but the prefetch window missed them: refresh
            return {"kind": "tool", "name": "graph_overview", "args": {}}
        frontier = re.search(r'"frontier_open"\s*:\s*(\d+)', ctx)
        running_empty = '"running_intents":[]' in ctx.replace(" ", "")
        open_empty = '"open_intents":[]' in ctx.replace(" ", "")
        no_intents = (frontier is None or int(frontier.group(1)) == 0) and running_empty and open_empty
        if no_intents:
            return {"kind": "tool", "name": "add_intent", "args": {"intents": [{
                "summary": ("Probe the lab target %s without credentials: fetch the route "
                            "manifest, exercise unauthenticated admin action and weight "
                            "pull, then report confirmed endpoints as findings." % target),
                "priority": 8}]}}
        return {"kind": "text", "text": "MOCK-SCRIPT: intent already in flight, waiting."}

    if agent == "worker":
        results = _tool_results(body)
        specs = _tool_specs(body)
        m = re.search(r"意图\s*id[：:]\s*(\d+)", ctx)
        intent_id = int(m.group(1)) if m else 0

        done_probe = [r for r in results if HTTP_MARKER in r]
        reported = any(FINDING_MARKER in r for r in results)
        if reported or len(done_probe) >= len(PROBES):
            if not reported and len(done_probe) >= len(PROBES):
                evidence = "\n----\n".join(
                    (r.strip()[:600] + ("…" if len(r.strip()) > 600 else ""))
                    for r in done_probe[-3:])
                return {"kind": "tool", "name": "report_finding", "args": {
                    "vulnclass": "auth-bypass",
                    "name": "Lab target unauthenticated admin plane and weight pull",
                    "severity": "high",
                    "summary": ("Probed %s without credentials: route manifest readable, "
                                "POST /pause applied without auth, POST /pull_weights wrote "
                                "weights without auth." % target),
                    "evidence": evidence,
                    "intent_id": intent_id}}
            return {"kind": "text", "text":
                    "MOCK-SCRIPT: intent complete; probes and finding recorded, stopping."}

        if len(results) >= MAX_WORKER_RESULTS:
            return {"kind": "text", "text": "MOCK-SCRIPT: worker step budget reached, stopping."}

        # next probe index + runner variant derived from trailing failures
        idx = len(done_probe)
        method, path, payload, _title = PROBES[idx]
        url = target + path
        variant = 0
        for r in reversed(results):
            if HTTP_MARKER in r:
                break
            if _failed_result(r):
                variant += 1
            else:
                break
        variant = min(variant, 2)

        bash_name = next((t for t in tools if t.lower() in ("bash", "shell", "run_command")), None)
        fetch_name = next((t for t in tools if "fetch" in t.lower() or t.lower() == "webfetch"), None)
        if bash_name:
            props = (specs.get(bash_name) or {}).get("properties") or {}
            argname = "command" if "command" in props else next(
                (k for k in ("cmd", "script", "code") if k in props),
                next(iter(props), "command"))
            args = {argname: _probe_command(method, url, payload, variant)}
            return {"kind": "tool", "name": bash_name, "args": args}
        if fetch_name and method == "GET":
            return {"kind": "tool", "name": fetch_name, "args": {"url": url}}
        return {"kind": "text", "text": "MOCK-SCRIPT: no HTTP-capable tool available, stopping."}

    return {"kind": "text", "text": CONFIG["final_text"]}


# ---------------------------------------------------------------------------
# wire encoders (OpenAI SSE / OpenAI JSON / Anthropic)
# ---------------------------------------------------------------------------


def _openai_stream(handler: "Handler", body: dict, reply: dict, record: dict) -> None:
    model = body.get("model") or CONFIG["model"]
    base = {"id": f"chatcmpl-mock-{uuid.uuid4().hex[:8]}", "created": int(time.time()), "model": model}
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.end_headers()

    def sse(choices_delta: dict, finish=None) -> None:
        payload = {**base, "object": "chat.completion.chunk",
                   "choices": [{"index": 0, "delta": choices_delta, "finish_reason": finish}]}
        handler.wfile.write(b"data: " + json.dumps(payload).encode() + b"\n\n")
        handler.wfile.flush()

    sse({"role": "assistant", "content": ""})
    if reply["kind"] == "tool":
        args = json.dumps(reply["args"], ensure_ascii=False)
        call_id = f"call_mock_{record['n']}_{uuid.uuid4().hex[:6]}"
        sse({"tool_calls": [{"index": 0, "id": call_id, "type": "function",
                             "function": {"name": reply["name"], "arguments": ""}}]})
        sse({"tool_calls": [{"index": 0, "function": {"arguments": args}}]})
        sse({}, finish="tool_calls")
    else:
        sse({"content": reply["text"]})
        sse({}, finish="stop")
    handler.wfile.write(b"data: [DONE]\n\n")
    handler.wfile.flush()


def _openai_json(handler: "Handler", body: dict, reply: dict, record: dict) -> None:
    model = body.get("model") or CONFIG["model"]
    message: dict = {"role": "assistant", "content": None}
    if reply["kind"] == "tool":
        message["tool_calls"] = [{
            "id": f"call_mock_{record['n']}_{uuid.uuid4().hex[:6]}", "type": "function",
            "function": {"name": reply["name"],
                         "arguments": json.dumps(reply["args"], ensure_ascii=False)}}]
    else:
        message["content"] = reply["text"]
    payload = {
        "id": f"chatcmpl-mock-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": message,
                     "finish_reason": "tool_calls" if reply["kind"] == "tool" else "stop"}],
        "usage": {"prompt_tokens": record.get("tokens_in_est", 0),
                  "completion_tokens": record.get("tokens_out_est", 0),
                  "total_tokens": record.get("tokens_in_est", 0) + record.get("tokens_out_est", 0)},
    }
    body_bytes = json.dumps(payload).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


def _anthropic(handler: "Handler", body: dict, reply: dict, record: dict) -> None:
    if reply["kind"] == "tool":
        content = [{"type": "tool_use", "id": f"toolu_mock_{record['n']}",
                    "name": reply["name"], "input": reply["args"]}]
        stop_reason = "tool_use"
    else:
        content = [{"type": "text", "text": reply["text"]}]
        stop_reason = "end_turn"
    payload = {
        "id": f"msg_mock_{uuid.uuid4().hex[:8]}", "type": "message", "role": "assistant",
        "model": body.get("model") or CONFIG["model"], "content": content,
        "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": record.get("tokens_in_est", 0),
                  "output_tokens": record.get("tokens_out_est", 0)},
    }
    body_bytes = json.dumps(payload).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


def _log(record: dict) -> None:
    path = CONFIG["log_path"]
    if not path:
        return
    with LOG_LOCK:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        if self.path in ("/health", "/v1/models", "/__mock_stats__"):
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
            self._send_json({"requests": STATE["requests"],
                             "replies": list(STATE["replies"])[-40:],
                             "target_url": CONFIG["target_url"]})
        else:
            self._send_json({"error": "not found", "path": self.path}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        body = self._json_body()
        with LOG_LOCK:
            STATE["requests"] += 1
            n = STATE["requests"]
        t0 = time.time()
        tools = _tool_names(body)
        messages = body.get("messages") or []
        tools_json = json.dumps(body.get("tools") or [], ensure_ascii=False)
        messages_json = json.dumps(messages, ensure_ascii=False)
        try:
            reply = scripted_reply(body, CONFIG)
        except Exception as exc:  # never kill the server on a malformed request
            reply = {"kind": "text", "text": f"MOCK-SCRIPT: decision error {type(exc).__name__}"}
        reply_json = json.dumps(reply, ensure_ascii=False)
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "ts_epoch_ms": int(t0 * 1000),
            "n": n,
            "path": self.path,
            "model": body.get("model"),
            "stream": bool(body.get("stream")),
            "agent": classify_agent(tools),
            "turn": _turn_index(body),
            "messages_count": len(messages),
            "tool_count": len(tools),
            "tools": tools,
            "prompt_chars": len(messages_json),
            "tools_chars": len(tools_json),
            "tokens_in_est": (len(messages_json) + len(tools_json) + 3) // 4,
            "reply": reply,
            "reply_chars": len(reply_json),
            "tokens_out_est": (len(reply_json) + 3) // 4,
        }
        path = self.path.rstrip("/")
        try:
            if path.endswith("/chat/completions"):
                if body.get("stream"):
                    _openai_stream(self, body, reply, record)
                else:
                    _openai_json(self, body, reply, record)
            elif path.endswith("/messages"):
                _anthropic(self, body, reply, record)
            else:
                self._send_json({"error": "unsupported path", "path": self.path}, status=404)
        finally:
            record["duration_ms"] = int((time.time() - t0) * 1000)
            record["finished_epoch_ms"] = int(time.time() * 1000)
            # full protocol evidence: complete schemas for the first request of
            # every agent shape, full message list for every request
            first_of_shape = not any(r.get("agent") == record["agent"] for r in STATE["replies"])
            record["tools_schema"] = json.loads(tools_json) if n <= 2 or first_of_shape else None
            record["messages"] = json.loads(messages_json)
            with LOG_LOCK:
                STATE["replies"].append({"n": n, "agent": record["agent"],
                                         "turn": record["turn"], "reply": reply})
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
    ap.add_argument("--model", default="mock-agent-model")
    ap.add_argument("--target-url", default=CONFIG["target_url"],
                    help="mock target base URL as seen from the ARTEX guest, e.g. http://10.0.2.2:18080")
    args = ap.parse_args()
    CONFIG["log_path"] = args.log or None
    CONFIG["model"] = args.model
    CONFIG["target_url"] = args.target_url.rstrip("/")
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[mock-llm] scripted planner listening on http://{args.host}:{args.port} "
          f"(target={CONFIG['target_url']}, log={CONFIG['log_path']})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
