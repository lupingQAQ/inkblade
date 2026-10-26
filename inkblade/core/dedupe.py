# -*- coding: utf-8 -*-
"""同根因归并 + 统一报告（CM-17）：跨 run 去重、根因确认工作流。

- 指纹：优先 CVE（``CVE-YYYY-NNNN``）；否则 ``module + 归一化标题``（IP/端口/十六进制/
  数字/空白归一），避免同一问题因目标地址不同被拆成多条；
- ``cluster`` 扫描工作区多个 run，输出分组（代表 finding、最高严重度、跨 run 出现次数、
  证据锚）；跨 run 去重不修改原 findings；
- ``confirm_root_cause`` 要求 lead/admin（approve），把根因确认写入 ``rootcauses.json``；
- ``render_unified`` 生成统一报告（Markdown），可选中英标题；只读扫描，不执行。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from . import jsonio

ROOTCAUSES_RELPATH = "rootcauses.json"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
_HEX = re.compile(r"\b[0-9a-f]{8,}\b", re.I)
_NUMS = re.compile(r"\b\d+\b")
_WS = re.compile(r"\s+")


class DedupeError(ValueError):
    """归并参数非法。"""


def normalize_title(title: str) -> str:
    text = str(title or "").lower()
    text = _IP.sub("#", text)
    text = _HEX.sub("#", text)
    text = _NUMS.sub("#", text)
    text = re.sub(r"[`'\"“”‘’()\[\]{}<>]", " ", text)
    return _WS.sub(" ", text).strip(" .:;,/-")


def fingerprint(finding: dict) -> str:
    blob = f"{finding.get('title', '')} {finding.get('detail', '')}"
    cve = _CVE.search(blob)
    if cve:
        return cve.group(0).upper()
    return f"{finding.get('step_key', '')}|{normalize_title(finding.get('title', ''))}"


def _runs(store, runs: list[str] | None) -> list[str]:
    if runs is not None:
        return list(runs)
    ws = Path(store.ws_dir)
    if not ws.exists():
        return []
    return sorted(p.name for p in ws.iterdir()
                  if p.is_dir() and not p.name.startswith("_")
                  and (p / "evidence.db").is_file())


def _rootcauses(store) -> dict:
    doc = jsonio.read_json(jsonio.ws_path(store, ROOTCAUSES_RELPATH), {})
    return doc if isinstance(doc, dict) else {}


def cluster(store, runs: list[str] | None = None) -> list[dict]:
    groups: dict[str, dict] = {}
    for run_name in _runs(store, runs):
        try:
            run = store.open_run(run_name)
        except KeyError as exc:
            raise DedupeError(f"run 不存在：{run_name}") from exc
        for f in run.findings:
            fp = fingerprint(f)
            g = groups.setdefault(fp, {"id": f"rc-{jsonio.fingerprint(fp)[:10]}",
                                       "fingerprint": fp, "title": f.get("title", ""),
                                       "module": f.get("step_key", ""),
                                       "severity": f.get("severity", "info"),
                                       "occurrences": [], "runs": set()})
            g["occurrences"].append({"run": run_name, "title": f.get("title", ""),
                                     "severity": f.get("severity", "info"),
                                     "evidence_path": f.get("evidence_path", "")})
            g["runs"].add(run_name)
            if SEV_ORDER.get(str(f.get("severity", "info")).lower(), 9) < \
                    SEV_ORDER.get(str(g["severity"]).lower(), 9):
                g["severity"] = f.get("severity", "info")
    confirmed = _rootcauses(store)
    out = []
    for g in groups.values():
        rc = confirmed.get(g["id"], {})
        item = {**g, "runs": sorted(g["runs"]), "run_count": len(g["runs"]),
                "occurrence_count": len(g["occurrences"]),
                "root_cause": rc.get("root_cause", ""),
                "confirmed_by": rc.get("confirmed_by", ""),
                "confirmed_at": rc.get("confirmed_at", 0),
                "cross_run": len(g["runs"]) > 1}
        out.append(item)
    out.sort(key=lambda x: (SEV_ORDER.get(str(x["severity"]).lower(), 9),
                            -x["occurrence_count"], x["id"]))
    return out


def confirm_root_cause(store, session, cluster_id: str, root_cause: str, *,
                       note: str = "") -> dict:
    if not session.can("approve"):
        raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
    if not str(root_cause).strip():
        raise DedupeError("root_cause 不能为空")
    groups = cluster(store)
    hit = next((g for g in groups if g["id"] == cluster_id or g["fingerprint"] == cluster_id), None)
    if hit is None:
        raise DedupeError(f"未知归并组 {cluster_id}")
    path = jsonio.ws_path(store, ROOTCAUSES_RELPATH)
    doc = _rootcauses(store)
    doc[hit["id"]] = {"root_cause": str(root_cause)[:2000], "note": str(note)[:1000],
                      "confirmed_by": session.name, "confirmed_at": time.time(),
                      "fingerprint": hit["fingerprint"],
                      "occurrences": hit["occurrence_count"]}
    jsonio.write_json(path, doc)
    jsonio.append_audit(store, session.name, "dedupe.confirm", hit["id"],
                        {"root_cause": root_cause}, "ok")
    return {**hit, "root_cause": doc[hit["id"]]["root_cause"],
            "confirmed_by": session.name, "confirmed_at": doc[hit["id"]]["confirmed_at"]}


def render_unified(groups: list[dict], *, title: str = "同根因统一报告") -> str:
    cross = sum(1 for g in groups if g.get("cross_run"))
    confirmed = sum(1 for g in groups if g.get("root_cause"))
    lines = [f"# {title}", "",
             f"- 分组：{len(groups)}（跨 run {cross}）",
             f"- 已确认根因：{confirmed}",
             f"- 去重前 finding 数：{sum(g.get('occurrence_count', 0) for g in groups)}", "",
             "| ID | 严重度 | 模块 | 标题 | 出现 | 跨 run | 根因 |",
             "|---|---|---|---|---|---|---|"]
    for g in groups:
        lines.append(f"| {g['id']} | {g['severity']} | {g['module']} | {g['title']} | "
                     f"{g['occurrence_count']} | {'是' if g.get('cross_run') else '否'} | "
                     f"{g.get('root_cause') or '待确认'} |")
    lines += ["", "## 证据锚", ""]
    for g in groups:
        lines.append(f"### {g['id']} — {g['title']}")
        for occ in g["occurrences"]:
            lines.append(f"- `{occ['run']}` → `{occ['evidence_path'] or '—'}`")
    return "\n".join(lines) + "\n"


def export(store, path: Path | str, *, runs: list[str] | None = None) -> Path:
    groups = cluster(store, runs)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_unified(groups), encoding="utf-8")
    jsonio.write_json(p.with_suffix(".json"),
                      {"groups": groups, "generated_at": time.time()})
    return p
