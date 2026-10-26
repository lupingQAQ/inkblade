"""routes — 端点全集静态提取（笛卡尔积扫掠的第一步：先枚举全集，再逐一测）。

- ARTEX：扫描 .slim/clonedeps/repos/RuoJi6__ARTEX/server/*.go 的
  `mux.HandleFunc("METHOD /path", handler)`（Go 1.22 pattern 路由，含 registerSideRoutes
  分散在各文件中的注册）。tools/extract_features.py 在本工作区不存在（已核验），
  故从 Go 源自提；产物带 repo commit 证据。
- Trident：扫描 trident/webui/server.py 的 `u.path == "..."` / `path == "..."`
  / `path in (...)` 字面量 + do_GET/do_POST 上下文推断方法。

读写分类：GET/HEAD=read，POST/PUT/PATCH/DELETE=write（按 HTTP 方法标准口径）。
路径参数 {id} 等 → 生成探测用的样本值替换表（probe 化）。

输出：routes-{tool}.json（方法、路径、参数化路径、handler/行号、读写分类、
是否流式、是否需鉴权可探测性标记）。
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ARTEX_SRC = REPO_ROOT.parent.parent / ".slim" / "clonedeps" / "repos" / "RuoJi6__ARTEX"
TRIDENT_SERVER = REPO_ROOT / "trident" / "webui" / "server.py"

GO_ROUTE = re.compile(
    r'\.\s*HandleFunc\(\s*"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[^"]*)"')
STREAM_HINT = re.compile(r"stream|sse|EventSource|Flusher", re.IGNORECASE)

READ_METHODS = {"GET", "HEAD", "OPTIONS"}

# {param} → 探测样本值（ARTEX Go 1.22 路径参数）
SAMPLE_VALUES = {
    "id": "1", "gid": "1", "cid": "1", "rid": "1", "sid": "1", "tid": "1",
    "aid": "1", "uid": "1", "mid": "1", "fid": "1", "iid": "1", "pid": "1",
    "nodeId": "1", "goalId": "1", "assetID": "1", "caseId": "1", "reviewId": "1",
    "file": "bench-probe.txt", "path": "bench-probe.txt", "name": "bench-probe",
    "key": "bench-probe", "kind": "site", "category": "1", "target": "http://10.0.2.2:18080",
}


def probe_path(path: str) -> str:
    """{param} → 样本值；未知参数名用 '1' 兜底。"""
    def sub(m):
        return SAMPLE_VALUES.get(m.group(1), "1")
    return re.sub(r"\{([A-Za-z][A-Za-z0-9_]*)\}", sub, path)


def extract_artex() -> list[dict]:
    out: dict[tuple[str, str], dict] = {}
    if not ARTEX_SRC.exists():
        raise FileNotFoundError(f"ARTEX 源码不存在: {ARTEX_SRC}")
    for f in sorted((ARTEX_SRC / "server").glob("*.go")):
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in GO_ROUTE.finditer(text):
            method, path = m.group(1), m.group(2)
            line = text[:m.start()].count("\n") + 1
            # 流式启发：handler 名或路径含 stream
            handler_m = re.search(r',\s*s\.(\w+)\)', text[m.start():m.start() + 200])
            handler = handler_m.group(1) if handler_m else "?"
            streaming = bool(STREAM_HINT.search(path)) or bool(
                STREAM_HINT.search(handler))
            key = (method, path)
            if key not in out:
                out[key] = {
                    "method": method, "path": path, "probe_path": probe_path(path),
                    "handler": f"{f.name}::{handler}", "line": line,
                    "class": "read" if method in READ_METHODS else "write",
                    "streaming": streaming,
                }
            else:
                out[key]["handler"] += f";{f.name}::{handler}"
    return sorted(out.values(), key=lambda r: (r["path"], r["method"]))


_TRIDENT_EQ_RE = re.compile(r'(?:u\.path|path)\s*==\s*[\(/]?"(/[^"\)]*)"')
_TRIDENT_IN_RE = re.compile(r'(?:u\.path|path)\s+in\s*\(([^)]*)\)', re.DOTALL)
_STR_IN_TUPLE = re.compile(r'"(/[^"]*)"')


def extract_trident() -> list[dict]:
    """server.py 端点字面量 + do_POST..do_GET 段界推断方法（含 _api_v1_post/_get）。"""
    text = TRIDENT_SERVER.read_text(encoding="utf-8")
    # 段界：do_POST 起到 do_GET 前（含其间的 _api_v1_post）为 POST 区；do_GET 起为 GET 区
    get_lo = text.index("def do_GET")
    post_lo = text.index("def do_POST")

    def method_at(pos: int) -> str:
        return "POST" if post_lo <= pos < get_lo else "GET"

    seen: dict[tuple[str, str], dict] = {}

    def add(path: str, pos: int):
        method = method_at(pos)
        key = (method, path)
        if key in seen:
            return
        line = text[:pos].count("\n") + 1
        seen[key] = {
            "method": method, "path": path, "probe_path": path,
            "handler": f"webui/server.py::{method}@L{line}",
            "line": line,
            "class": "read" if method in READ_METHODS else "write",
            "streaming": False,
        }

    for m in _TRIDENT_EQ_RE.finditer(text):
        add(m.group(1), m.start())
    for m in _TRIDENT_IN_RE.finditer(text):
        for s in _STR_IN_TUPLE.finditer(m.group(1)):
            add(s.group(1), m.start())
    return sorted(seen.values(), key=lambda r: (r["path"], r["method"]))


def artex_commit() -> str:
    try:
        r = subprocess.run(["git", "-C", str(ARTEX_SRC), "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=15)
        return r.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def build_routes(out_dir: Path) -> dict:
    artex = extract_artex()
    trident = extract_trident()
    out_dir.mkdir(parents=True, exist_ok=True)
    payload_artex = {
        "tool": "artex",
        "source": "RuoJi6/ARTEX server/*.go (mux.HandleFunc pattern routes)",
        "commit": artex_commit(),
        "extracted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endpoint_count": len(artex),
        "by_class": {
            "read": sum(1 for r in artex if r["class"] == "read"),
            "write": sum(1 for r in artex if r["class"] == "write"),
        },
        "endpoints": artex,
    }
    payload_trident = {
        "tool": "trident",
        "source": "trident/webui/server.py (path literals in do_GET/do_POST)",
        "extracted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endpoint_count": len(trident),
        "by_class": {
            "read": sum(1 for r in trident if r["class"] == "read"),
            "write": sum(1 for r in trident if r["class"] == "write"),
        },
        "endpoints": trident,
    }
    (out_dir / "routes-artex.json").write_text(
        json.dumps(payload_artex, ensure_ascii=False, indent=1), encoding="utf-8")
    (out_dir / "routes-trident.json").write_text(
        json.dumps(payload_trident, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"artex": payload_artex, "trident": payload_trident}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="端点全集静态提取")
    ap.add_argument("--out", default=str(REPO_ROOT / "reports" / "samples" / "perf" / "grid"))
    args = ap.parse_args(argv)
    res = build_routes(Path(args.out))
    for tool, p in res.items():
        print(f"[routes] {tool}: {p['endpoint_count']} endpoints "
              f"(read={p['by_class']['read']}, write={p['by_class']['write']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
