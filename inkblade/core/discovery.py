# -*- coding: utf-8 -*-
"""资产自动发现（XBow 对标 ①）：种子 → 增量资产清单（新表 assets）→ 模块消费。

输入种子（三选一或组合）：
- ``namespaces``: 命名空间清单（骨架资产：namespace 节点）；
- ``services``: 服务清单（[{name, namespace, addr|cluster_ip, port, labels, product?}]）；
- ``kubeconfig_snapshot``: kubeconfig 快照（{contexts, clusters, users, namespaces}）。

增量语义（ingest 返回三类差异，不硬删除——保留审计轨迹）：
- added   本轮新见资产；
- updated 属性变化的既有资产（记录变更字段）；
- removed 同源资产本轮未见 → missing_since 打时间戳（软删除）。

模块消费：resolve_targets(module_key) 以版本矩阵 product 映射挑选资产，
模块/explorer/scheduler 以 bind_params 填充 target，替代散装 params。
存储：工作区级 ``assets.db``（SQLite，表 assets；per-run 库不适配工作区级资产）。
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .version_matrix import entry as matrix_entry

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets(
    asset_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    product TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    addr TEXT NOT NULL DEFAULT '',
    port INTEGER,
    labels TEXT NOT NULL DEFAULT '{}',
    source TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    missing_since REAL,
    attrs TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_assets_product ON assets(product);
CREATE INDEX IF NOT EXISTS idx_assets_source ON assets(source);
"""

# 名称/标签/端口 → 产品推断（与版本矩阵 products 对齐）
_PRODUCT_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("sglang",), "sglang"),
    (("vllm",), "vllm"),
    (("kuberay", "ray-head", "raycluster", "rayservice", "ray-job"), "kuberay"),
    (("ray",), "ray"),
    (("hami", "vgpu"), "hami"),
    (("litellm", "ai-gateway", "aigateway"), "litellm"),
    (("higress",), "litellm"),
    (("dify",), "dify"),
    (("webui",), "open-webui"),
    (("areal",), "areal"),
    (("verl",), "verl"),
    (("slime",), "slime"),
    (("skyrl",), "skyrl"),
    (("trl",), "trl"),
]
_PORT_HINTS = {30000: "sglang", 8265: "kuberay", 8777: "ray", 4000: "vllm", 8000: "vllm",
               8080: "hami", 8090: "dify", 8081: "litellm"}


def infer_product(name: str = "", labels: dict | None = None, port: int | None = None) -> str:
    """从名称/标签/端口推断产品（version-matrix product 键；未知返回 ''）。"""
    hay = " ".join([name or ""] + [f"{k}={v}" for k, v in (labels or {}).items()]).lower()
    for needles, product in _PRODUCT_HINTS:
        if any(n in hay for n in needles):
            return product
    if port in _PORT_HINTS:
        return _PORT_HINTS[port]
    return ""


class DiscoveryError(ValueError):
    """种子非法。"""


class AssetInventory:
    """工作区资产库（assets 表）：增量 ingest + 差异 + 模块目标解析。"""

    def __init__(self, store):
        self.store = store
        self.db_path = Path(store.ws_dir) / "assets.db"
        with self._tx() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _tx(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---------- 种子归一 ----------
    @staticmethod
    def _normalize_seeds(seeds: dict) -> list[dict]:
        if not isinstance(seeds, dict):
            raise DiscoveryError("seeds 必须是对象（namespaces/services/kubeconfig_snapshot）")
        assets: list[dict] = []
        for ns in seeds.get("namespaces") or []:
            if not isinstance(ns, str) or not ns:
                raise DiscoveryError(f"非法命名空间 {ns!r}")
            assets.append({"kind": "namespace", "name": ns, "namespace": ns})
        for svc in seeds.get("services") or []:
            if not isinstance(svc, dict) or not svc.get("name"):
                raise DiscoveryError(f"非法服务条目 {svc!r}")
            port = svc.get("port")
            labels = dict(svc.get("labels") or {})
            product = svc.get("product") or infer_product(svc["name"], labels, port)
            assets.append({
                "kind": "service", "name": str(svc["name"]),
                "namespace": str(svc.get("namespace", "default")),
                "addr": str(svc.get("addr") or svc.get("cluster_ip") or ""),
                "port": int(port) if port is not None else None,
                "labels": labels, "product": str(product),
            })
        snap = seeds.get("kubeconfig_snapshot")
        if snap:
            if not isinstance(snap, dict):
                raise DiscoveryError("kubeconfig_snapshot 必须是对象")
            src_ns = snap.get("namespaces") or []
            assets.append({
                "kind": "kubeconfig", "name": f"kubeconfig:{len(snap.get('contexts') or [])}ctx",
                "namespace": "", "attrs": {"contexts": snap.get("contexts") or [],
                                           "clusters": snap.get("clusters") or [],
                                           "users": len(snap.get("users") or [])},
            })
            for ns in src_ns:
                assets.append({"kind": "namespace", "name": str(ns), "namespace": str(ns)})
        if not assets:
            raise DiscoveryError("种子为空（namespaces/services/kubeconfig_snapshot 至少一项）")
        return assets

    @staticmethod
    def asset_key(kind: str, namespace: str, name: str) -> str:
        return f"{kind}/{namespace}/{name}".replace("//", "/")

    # ---------- 增量 ingest ----------
    def ingest(self, seeds: dict, source: str = "seed") -> dict[str, Any]:
        now = time.time()
        rows = self._normalize_seeds(seeds)
        current_keys: set[str] = set()
        added, updated = [], []
        with self._tx() as conn:
            existing = {r["asset_key"]: dict(r) for r in conn.execute("SELECT * FROM assets")}
            for a in rows:
                key = self.asset_key(a["kind"], a.get("namespace", ""), a["name"])
                current_keys.add(key)
                labels = a.get("labels", {})
                attrs = a.get("attrs", {})
                if key in existing:
                    old = existing[key]
                    changes = {}
                    for field, newval in (("product", a.get("product", "")),
                                          ("addr", a.get("addr", "")),
                                          ("port", a.get("port")),
                                          ("labels", json.dumps(labels, ensure_ascii=False, sort_keys=True)),
                                          ("namespace", a.get("namespace", ""))):
                        if newval != old.get(field):
                            changes[field] = {"from": old.get(field), "to": newval}
                    conn.execute(
                        "UPDATE assets SET product=?, namespace=?, addr=?, port=?, labels=?,"
                        " attrs=?, last_seen=?, seen_count=seen_count+1, missing_since=NULL"
                        " WHERE asset_key=?",
                        (a.get("product", old.get("product", "")), a.get("namespace", old.get("namespace", "")),
                         a.get("addr", old.get("addr", "")), a.get("port", old.get("port")),
                         json.dumps(labels, ensure_ascii=False), json.dumps(attrs, ensure_ascii=False),
                         now, key),
                    )
                    if changes:
                        updated.append({"asset_key": key, "changes": changes})
                else:
                    conn.execute(
                        "INSERT INTO assets(asset_key, kind, product, name, namespace, addr, port,"
                        " labels, source, first_seen, last_seen, seen_count, missing_since, attrs)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?,?,1,NULL,?)",
                        (key, a["kind"], a.get("product", ""), a["name"], a.get("namespace", ""),
                         a.get("addr", ""), a.get("port"),
                         json.dumps(labels, ensure_ascii=False), source, now, now,
                         json.dumps(attrs, ensure_ascii=False)),
                    )
                    added.append(key)
            # 同源未见 → 软删除
            removed: list[str] = []
            for key, old in existing.items():
                if key in current_keys or old["source"] != source:
                    continue
                conn.execute("UPDATE assets SET missing_since=? WHERE asset_key=?", (now, key))
                removed.append(key)
        return {"added": added, "updated": updated, "removed": removed,
                "total": self.count(), "source": source, "ts": now}

    # ---------- 查询 ----------
    def _row_to_dict(self, r) -> dict:
        d = dict(r)
        for field in ("labels", "attrs"):
            try:
                d[field] = json.loads(d.get(field) or "{}")
            except ValueError:
                d[field] = {}
        d["missing"] = d.get("missing_since") is not None
        return d

    def list(self, *, kind: str = "", product: str = "", include_missing: bool = False,
             source: str = "") -> list[dict]:
        sql, args = "SELECT * FROM assets WHERE 1=1", []
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        if product:
            sql += " AND product=?"
            args.append(product)
        if source:
            sql += " AND source=?"
            args.append(source)
        if not include_missing:
            sql += " AND missing_since IS NULL"
        sql += " ORDER BY asset_key"
        with self._tx() as conn:
            return [self._row_to_dict(r) for r in conn.execute(sql, args)]

    def count(self, *, include_missing: bool = True) -> int:
        sql = "SELECT COUNT(*) FROM assets" + ("" if include_missing else " WHERE missing_since IS NULL")
        with self._tx() as conn:
            return int(conn.execute(sql).fetchone()[0])

    def graph(self) -> dict:
        """资产图（SPA 资产图视图数据）：namespace → service 层级 + 产品着色。"""
        nodes, edges = [], []
        for a in self.list(include_missing=True):
            nodes.append({"id": a["asset_key"], "kind": a["kind"], "label": a["name"],
                          "product": a["product"], "namespace": a["namespace"],
                          "addr": a["addr"], "port": a["port"], "missing": a["missing"]})
            if a["kind"] == "service" and a["namespace"]:
                edges.append({"src": f"namespace/{a['namespace']}/{a['namespace']}".replace("//", "/"),
                              "dst": a["asset_key"], "relation": "contains"})
        return {"nodes": nodes, "edges": edges}

    # ---------- 模块消费 ----------
    def resolve_targets(self, module_key: str, *, limit: int = 0) -> list[dict]:
        """按版本矩阵 product 映射挑选在册资产（模块散装 target 的替代数据源）。"""
        e = matrix_entry(module_key)
        product = e["product"] if e else ""
        hits = self.list(kind="service", product=product) if product else []
        if limit > 0:
            hits = hits[:limit]
        return hits

    def bind_params(self, module_key: str, params: dict) -> dict:
        """params.use_assets=true 且未显式给 target 时，用资产 addr:port 填充。"""
        if not params.get("use_assets"):
            return dict(params)
        out = dict(params)
        if out.get("target"):
            return out
        hits = self.resolve_targets(module_key, limit=1)
        if hits:
            h = hits[0]
            base = h["addr"] or h["name"]
            out["target"] = f"http://{base}:{h['port']}" if h.get("port") else f"http://{base}"
            out["asset_key"] = h["asset_key"]
        return out


def discover(store, seeds: dict, source: str = "seed") -> dict[str, Any]:
    """便捷入口：构造库存并 ingest，返回差异报告。"""
    return AssetInventory(store).ingest(seeds, source=source)
