# -*- coding: utf-8 -*-
"""跨 run 过程检索（CM-02）：steps/prompts/findings/actions/traffic/归档全文 → 证据锚。

- 只读：不建 run、不写 evidence.db；查询工作区全部（或指定）run 的 SQLite 证据库；
- 每命中返回 ``{run, kind, id, snippet, evidence}``，``evidence`` 指向归档相对路径或
  流量记录，便于回到三层证据链；
- 归档全文检索（``artifacts``）解压 tar（gzip；无 zstd 库时跳过 .zst），逐成员大小上限
  8MB、命中数有界，避免把检索变成 DoS；
- LIKE 查询统一转义 ``%``/``_``，避免用户输入被当成通配符。
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path
from typing import Any

KINDS = ("steps", "findings", "actions", "traffic", "artifacts")
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024


class SearchError(ValueError):
    """检索参数非法。"""


def _runs(store) -> list[str]:
    ws = Path(store.ws_dir)
    if not ws.exists():
        return []
    rows = [p.name for p in ws.iterdir()
            if p.is_dir() and not p.name.startswith("_") and (p / "evidence.db").is_file()]
    return sorted(rows, key=lambda n: (ws / n).stat().st_mtime, reverse=True)


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _snippet(text: Any, query: str, width: int = 70) -> str:
    s = str(text or "")
    if not s:
        return ""
    idx = s.lower().find(query.lower())
    if idx < 0:
        return s[: width * 2]
    start = max(0, idx - width)
    end = min(len(s), idx + len(query) + width)
    return ("…" if start else "") + s[start:end].replace("\n", " ") + ("…" if end < len(s) else "")


def _query(run, sql: str, args: tuple) -> list[Any]:
    try:
        return run.query(sql, args)
    except Exception:
        return []


def _search_run(store, run_name: str, q: str, kinds: set[str], limit: int) -> list[dict]:
    try:
        run = store.open_run(run_name)
    except KeyError:
        return []
    pat = _like(q)
    out: list[dict] = []
    if "steps" in kinds:
        rows = _query(run,
                      "SELECT steps.id, steps.step_key, steps.result_summary, steps.archive, prompts.content"
                      " FROM steps LEFT JOIN prompts ON prompts.step_id = steps.id"
                      " WHERE steps.result_summary LIKE ? ESCAPE '\\'"
                      " OR prompts.content LIKE ? ESCAPE '\\' ORDER BY steps.id DESC LIMIT ?",
                      (pat, pat, limit))
        for step_id, step_key, summary, archive, prompt in rows:
            out.append({"run": run_name, "kind": "step", "id": step_id,
                        "step_key": step_key, "snippet": _snippet(f"{step_key}\n{prompt or ''}\n{summary}", q),
                        "evidence": archive or ""})
    if "findings" in kinds:
        rows = _query(run,
                      "SELECT id, step_key, severity, title, detail, evidence_path FROM findings"
                      " WHERE title LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\'"
                      " OR step_key LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT ?",
                      (pat, pat, pat, limit))
        for fid, step_key, sev, title, detail, ev in rows:
            out.append({"run": run_name, "kind": "finding", "id": fid,
                        "step_key": step_key, "severity": sev, "title": title,
                        "snippet": _snippet(f"{title}\n{detail}", q), "evidence": ev or ""})
    if "actions" in kinds:
        rows = _query(run,
                      "SELECT id, ts, actor, action, target, params, result FROM actions"
                      " WHERE action LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\'"
                      " OR params LIKE ? ESCAPE '\\' OR result LIKE ? ESCAPE '\\'"
                      " ORDER BY id DESC LIMIT ?",
                      (pat, pat, pat, pat, limit))
        for aid, ts, actor, action, target, params, result in rows:
            out.append({"run": run_name, "kind": "action", "id": aid, "actor": actor,
                        "action": action, "ts": ts,
                        "snippet": _snippet(f"{action} {target} {params} {result}", q),
                        "evidence": "evidence.db:actions"})
    if "traffic" in kinds:
        rows = _query(run,
                      "SELECT id, module, seq, method, url, status, req_body, resp_body, error"
                      " FROM traffic WHERE url LIKE ? ESCAPE '\\' OR req_body LIKE ? ESCAPE '\\'"
                      " OR resp_body LIKE ? ESCAPE '\\' OR error LIKE ? ESCAPE '\\'"
                      " ORDER BY id DESC LIMIT ?",
                      (pat, pat, pat, pat, limit))
        for tid, module, seq, method, url, status, req, resp, error in rows:
            out.append({"run": run_name, "kind": "traffic", "id": tid, "module": module,
                        "method": method, "url": url, "status": status,
                        "snippet": _snippet(f"{method} {url} {req or ''} {resp or ''} {error or ''}", q),
                        "evidence": f"evidence.db:traffic#{seq}"})
    return out


def _search_archives(store, run_name: str, q: str, limit: int) -> list[dict]:
    out: list[dict] = []
    try:
        run = store.open_run(run_name)
    except KeyError:
        return out
    rows = _query(run, "SELECT step_key, archive FROM steps ORDER BY id DESC", ())
    for step_key, archive in rows:
        if len(out) >= limit:
            break
        if not archive:
            continue
        path = Path(run.dir) / archive
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
            if path.suffix == ".gz":
                raw = gzip.decompress(raw)
            elif path.suffix == ".zst":
                continue  # 可选 zstd 依赖缺失时跳过，不阻断其它命中
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
                for member in tf.getmembers():
                    if len(out) >= limit or not member.isfile() or member.size > MAX_ARTIFACT_BYTES:
                        continue
                    fh = tf.extractfile(member)
                    if fh is None:
                        continue
                    text = fh.read().decode("utf-8", "replace")
                    if q.lower() in text.lower():
                        out.append({"run": run_name, "kind": "artifact",
                                    "id": member.name, "step_key": step_key,
                                    "snippet": _snippet(text, q),
                                    "evidence": f"{archive}#{member.name}"})
        except Exception:
            continue
    return out


def search(store, query: str, *, run: str = "", kinds: list[str] | None = None,
           limit: int = 50) -> dict:
    """跨 run 全文检索；返回命中与计数。query 为空/未知 kind 报错。"""
    q = str(query or "").strip()
    if not q:
        raise SearchError("query 不能为空")
    kinds_set = set(kinds or ("steps", "findings", "actions", "traffic"))
    unknown = kinds_set - set(KINDS)
    if unknown:
        raise SearchError(f"未知检索类型 {sorted(unknown)}（支持 {', '.join(KINDS)}）")
    limit = max(1, min(int(limit), 500))
    runs = [run] if run else _runs(store)
    if run and run not in _runs(store):
        raise SearchError(f"run 不存在：{run}")
    hits: list[dict] = []
    for name in runs:
        if len(hits) >= limit:
            break
        per_run_limit = max(1, limit - len(hits))
        if "artifacts" in kinds_set:
            hits.extend(_search_archives(store, name, q, per_run_limit))
        hits.extend(_search_run(store, name, q, kinds_set, per_run_limit))
        if len(hits) > limit:
            hits = hits[:limit]
    return {"query": q, "runs": len(runs), "kinds": sorted(kinds_set),
            "count": len(hits), "hits": hits,
            "anchors": sum(1 for h in hits if h.get("evidence"))}


def render_md(result: dict) -> str:
    lines = [f"# 过程检索：{result.get('query')}", "",
             f"命中 **{result.get('count', 0)}** 条（{result.get('runs', 0)} 个 run）", ""]
    for h in result.get("hits", []):
        lines.append(f"- `{h.get('run')}` / {h.get('kind')} / {h.get('step_key', '')} — "
                     f"{h.get('snippet', '')}")
        if h.get("evidence"):
            lines.append(f"  - 证据锚：`{h['evidence']}`")
    return "\n".join(lines) + "\n"
