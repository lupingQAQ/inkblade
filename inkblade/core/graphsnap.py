# -*- coding: utf-8 -*-
"""资产/攻击图快照与跨 run 差异（clean-room 等价实现，cold graph）。

- 快照 = 资产库图（namespace→service）+ run 证据图（graph_nodes/graph_edges，若存在）
  + finding 摘要；持久化在 ``graphsnap/<id>.json``（保留最近 50 份）；
- ``diff`` 跨快照比较：节点新增/删除/属性变化、边新增/删除、finding 新增/修复；
- ``ui_data`` 输出前端可直接渲染的 nodes/edges（含分组与关系标签）；
- **只读**：生成快照只读资产库与证据库，不执行模块、不修改 run；写盘仅快照目录。
  “cold graph”语义：图完全由已落盘证据重算，不依赖在线集群。

快照生成不需要 approve（read 能力位即可）；不暴露任何密钥字段。
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from . import jsonio
from .discovery import AssetInventory

SNAP_RELPATH = "graphsnap"
MAX_SNAPSHOTS = 50


class GraphSnapError(ValueError):
    """快照参数非法。"""


def _runs(store) -> list[str]:
    ws = Path(store.ws_dir)
    if not ws.exists():
        return []
    return sorted(p.name for p in ws.iterdir()
                  if p.is_dir() and not p.name.startswith("_")
                  and (p / "evidence.db").is_file())


def _latest_run(store) -> str | None:
    runs = _runs(store)
    if not runs:
        return None
    return max(runs, key=lambda n: (Path(store.ws_dir) / n).stat().st_mtime)


def _evidence_graph(store, run_name: str | None) -> tuple[list[dict], list[dict]]:
    if not run_name:
        return [], []
    try:
        run = store.open_run(run_name)
        nodes = [{"id": r[0], "kind": r[1], "layer": r[2],
                  "attrs": _json_or_empty(r[3]), "source": f"run:{run_name}"}
                 for r in run.query("SELECT node_id, kind, layer, attrs FROM graph_nodes")]
        edges = [{"src": r[0], "dst": r[1], "verdict": r[2], "method": r[3],
                  "chain": r[4], "source": f"run:{run_name}"}
                 for r in run.query("SELECT src, dst, verdict, method, chain FROM graph_edges")]
        return nodes, edges
    except Exception:
        return [], []


def _json_or_empty(text: Any) -> dict:
    try:
        doc = json.loads(text or "{}")
        return doc if isinstance(doc, dict) else {}
    except ValueError:
        return {}


def build(store, *, run: str | None = None, label: str = "") -> dict:
    """计算快照（不落盘）：资产图 ∪ 证据图 ∪ finding 摘要。"""
    latest = run or _latest_run(store)
    inv = AssetInventory(store)
    asset = inv.graph()
    nodes: dict[str, dict] = {}
    for n in asset.get("nodes", []):
        nodes[n["id"]] = {"id": n["id"], "kind": n.get("kind", ""),
                          "layer": "资产层", "attrs": {
                              "label": n.get("label", ""), "product": n.get("product", ""),
                              "namespace": n.get("namespace", ""), "addr": n.get("addr", ""),
                              "port": n.get("port"), "missing": bool(n.get("missing"))},
                          "source": "assets"}
    edges: dict[tuple, dict] = {}
    for e in asset.get("edges", []):
        key = (e.get("src"), e.get("dst"), e.get("relation", ""), "配置证据", "")
        edges[key] = {"src": e.get("src"), "dst": e.get("dst"),
                      "verdict": e.get("relation", ""), "method": "配置证据",
                      "chain": "", "source": "assets"}
    ev_nodes, ev_edges = _evidence_graph(store, latest)
    for n in ev_nodes:
        if n["id"] in nodes:
            nodes[n["id"]]["source"] = "assets+evidence"
            nodes[n["id"]]["attrs"].update(n["attrs"])
        else:
            nodes[n["id"]] = n
    for e in ev_edges:
        key = (e["src"], e["dst"], e["verdict"], e["method"], e.get("chain", ""))
        edges[key] = e
    findings: list[dict] = []
    if latest:
        try:
            for f in store.open_run(latest).findings:
                findings.append({"key": f"{f.get('step_key', '')}|{f.get('title', '')}",
                                 "step_key": f.get("step_key", ""), "title": f.get("title", ""),
                                 "severity": f.get("severity", "info"),
                                 "is_novel": bool(f.get("is_novel"))})
        except Exception:
            pass
    return {
        "label": label or f"snapshot-{latest or 'empty'}",
        "created_at": time.time(), "run": latest, "cold": True,
        "source": {"assets": "assets.db", "evidence": f"run:{latest}" if latest else "",
                   "note": "图由已落盘证据重算，不依赖在线集群"},
        "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
        "edges": sorted(edges.values(), key=lambda e: (e["src"], e["dst"], e["verdict"])),
        "findings": findings,
        "stats": {"nodes": len(nodes), "edges": len(edges), "findings": len(findings)},
    }


class GraphSnapshots:
    def __init__(self, store, *, clock=time.time):
        self.store = store
        self.root = Path(store.ws_dir) / SNAP_RELPATH
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "index.json"
        self._clock = clock

    def _index(self) -> list[dict]:
        doc = jsonio.read_json(self.path, [])
        return doc if isinstance(doc, list) else []

    def _save_index(self, items: list[dict]) -> None:
        jsonio.write_json(self.path, items)

    def snapshot(self, session=None, *, run: str | None = None, label: str = "") -> dict:
        if session is not None and not session.can("read"):
            raise PermissionError(f"{session.name} 无 read 权限")
        doc = build(self.store, run=run, label=label)
        items = self._index()
        sid = f"gs-{time.strftime('%Y%m%d-%H%M%S', time.gmtime(self._clock()))}-{len(items) + 1:03d}"
        doc["id"] = sid
        jsonio.write_json(self.root / f"{sid}.json", doc)
        items.append({"id": sid, "label": doc["label"], "run": doc.get("run", ""),
                      "created_at": doc["created_at"], "stats": doc["stats"]})
        items = items[-MAX_SNAPSHOTS:]
        self._save_index(items)
        jsonio.append_audit(self.store, getattr(session, "name", "system"),
                            "graph.snapshot", sid, {"run": run, "stats": doc["stats"]}, "ok")
        return doc

    def list(self) -> list[dict]:
        return list(reversed(self._index()))

    def load(self, snapshot_id: str = "") -> dict:
        items = self._index()
        sid = snapshot_id or (items[-1]["id"] if items else "")
        if not sid:
            raise GraphSnapError("尚无图快照（先生成 snapshot）")
        doc = jsonio.read_json(self.root / f"{sid}.json", None)
        if not isinstance(doc, dict):
            raise GraphSnapError(f"快照不存在或损坏：{sid}")
        return doc

    def diff(self, base_id: str, head_id: str) -> dict:
        a, b = self.load(base_id), self.load(head_id)
        an = {n["id"]: n for n in a.get("nodes", [])}
        bn = {n["id"]: n for n in b.get("nodes", [])}
        added = sorted(set(bn) - set(an))
        removed = sorted(set(an) - set(bn))
        changed = []
        for nid in sorted(set(an) & set(bn)):
            old, new = an[nid], bn[nid]
            fields = {}
            for key in ("kind", "layer", "attrs"):
                if old.get(key) != new.get(key):
                    fields[key] = {"from": old.get(key), "to": new.get(key)}
            if fields:
                changed.append({"id": nid, "changes": fields})
        key = lambda e: (e.get("src"), e.get("dst"), e.get("verdict"), e.get("method"), e.get("chain", ""))
        ae = {key(e) for e in a.get("edges", [])}
        be = {key(e) for e in b.get("edges", [])}
        af = {f["key"]: f for f in a.get("findings", [])}
        bf = {f["key"]: f for f in b.get("findings", [])}
        return {
            "base": a.get("id"), "head": b.get("id"),
            "nodes": {"added": added, "removed": removed, "changed": changed,
                      "counts": {"added": len(added), "removed": len(removed),
                                 "changed": len(changed)}},
            "edges": {"added": [list(k) for k in sorted(be - ae)],
                      "removed": [list(k) for k in sorted(ae - be)],
                      "counts": {"added": len(be - ae), "removed": len(ae - be)}},
            "findings": {"new": [bf[k] for k in sorted(set(bf) - set(af))],
                         "fixed": [af[k] for k in sorted(set(af) - set(bf))],
                         "counts": {"new": len(set(bf) - set(af)),
                                    "fixed": len(set(af) - set(bf))}},
        }

    def ui_data(self, snapshot_id: str = "") -> dict:
        doc = self.load(snapshot_id)
        nodes = []
        for n in doc.get("nodes", []):
            attrs = n.get("attrs") or {}
            nodes.append({
                "id": n["id"], "label": attrs.get("label") or n["id"],
                "kind": n.get("kind", ""), "group": n.get("layer") or n.get("kind", ""),
                "product": attrs.get("product", ""), "missing": bool(attrs.get("missing")),
            })
        edges = [{"id": f"e{i}", "source": e["src"], "target": e["dst"],
                  "label": e.get("verdict", ""), "method": e.get("method", ""),
                  "chain": e.get("chain", "")}
                 for i, e in enumerate(doc.get("edges", []))]
        return {"snapshot": doc.get("id"), "cold": bool(doc.get("cold")),
                "nodes": nodes, "edges": edges,
                "findings": doc.get("findings", []),
                "stats": doc.get("stats", {}), "source": doc.get("source", {})}

    def neighbors(self, snapshot_id: str, node_id: str) -> dict:
        doc = self.load(snapshot_id)
        out, inc = [], []
        for e in doc.get("edges", []):
            if e.get("src") == node_id:
                out.append(e)
            if e.get("dst") == node_id:
                inc.append(e)
        return {"node": node_id, "out": out, "in": inc}
