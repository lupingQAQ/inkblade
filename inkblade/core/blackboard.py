# -*- coding: utf-8 -*-
"""跨 run 上下文继承（clean-room 等价实现，只读 blackboard）。

用途：把**选定**的历史 findings / 资产摘要 / 备注固定到工作区黑板，explorer 生成提议时
只读注入上下文，作为排序理由的一部分。黑板不是执行通道：
- 注入只影响 ``proposal.context.blackboard``（评审可追溯），不会自动执行、不会修改 run；
- 固定/取消固定要求 lead/admin（approve）；读取对所有角色开放；
- 只存摘要（finding 标题/严重度/证据锚、资产键/产品/地址），不存原始凭据与请求正文；
- 每条操作写工作区 ``audit.jsonl``。
"""

from __future__ import annotations

import time
from typing import Any

from . import jsonio
from .discovery import AssetInventory

BLACKBOARD_RELPATH = "blackboard.json"
MAX_ENTRIES = 200
MAX_SUMMARY = 500


class BlackboardError(ValueError):
    """黑板条目非法。"""


class Blackboard:
    def __init__(self, store, *, clock=time.time):
        self.store = store
        self.path = jsonio.ws_path(store, BLACKBOARD_RELPATH)
        self._clock = clock

    def _load(self) -> dict:
        doc = jsonio.read_json(self.path, None)
        if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
            doc = {"version": 1, "entries": []}
        return doc

    def _save(self, doc: dict) -> None:
        if len(doc["entries"]) > MAX_ENTRIES:
            doc["entries"] = doc["entries"][-MAX_ENTRIES:]
        jsonio.write_json(self.path, doc)

    def _upsert(self, session, entry: dict) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        doc = self._load()
        for old in doc["entries"]:
            if old.get("ref") == entry["ref"]:
                old.update(entry)
                old["pinned_at"] = self._clock()
                old["pinned_by"] = session.name
                self._save(doc)
                jsonio.append_audit(self.store, session.name, "blackboard.update",
                                    entry["ref"], {"kind": entry["kind"]}, "ok")
                return old
        entry["id"] = f"bb-{len(doc['entries']) + 1:04d}"
        entry["pinned_at"] = self._clock()
        entry["pinned_by"] = session.name
        doc["entries"].append(entry)
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "blackboard.pin", entry["ref"],
                            {"kind": entry["kind"]}, "ok")
        return entry

    # ------------------------------------------------------------ 固定
    def pin_finding(self, session, run_name: str, title_or_index: Any,
                    *, note: str = "", include_detail: bool = False) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        try:
            run = self.store.open_run(run_name)
        except KeyError as exc:
            raise BlackboardError(f"run 不存在：{run_name}") from exc
        findings = run.findings
        picked = None
        if isinstance(title_or_index, int):
            if not (0 <= title_or_index < len(findings)):
                raise BlackboardError(f"finding 下标越界：{title_or_index}")
            picked = findings[title_or_index]
        else:
            for f in findings:
                if f.get("title") == title_or_index:
                    picked = f
                    break
        if picked is None:
            raise BlackboardError(f"未找到 finding：{title_or_index!r}")
        summary = f"[{picked.get('severity', 'info')}] {picked.get('title', '')}"
        entry = {"kind": "finding", "ref": f"finding:{run_name}:{picked.get('title', '')}",
                 "run": run_name, "summary": summary[:MAX_SUMMARY],
                 "evidence_path": picked.get("evidence_path", ""),
                 "step_key": picked.get("step_key", ""), "note": str(note)[:MAX_SUMMARY]}
        if include_detail:
            entry["detail"] = str(picked.get("detail", ""))[:MAX_SUMMARY]
        return self._upsert(session, entry)

    def pin_assets(self, session, *, kind: str = "service", product: str = "",
                   limit: int = 20, note: str = "") -> list[dict]:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        inv = AssetInventory(self.store)
        items = inv.list(kind=kind, product=product)[:max(1, min(int(limit), 100))]
        out = []
        for a in items:
            entry = {"kind": "asset", "ref": a["asset_key"],
                     "summary": f"{a['asset_key']} product={a.get('product') or '-'} "
                                f"addr={a.get('addr') or '-'}:{a.get('port') or '-'}"[:MAX_SUMMARY],
                     "asset_key": a["asset_key"], "product": a.get("product", ""),
                     "namespace": a.get("namespace", ""), "note": str(note)[:MAX_SUMMARY]}
            out.append(self._upsert(session, entry))
        return out

    def pin_note(self, session, text: str, *, ref: str = "", note: str = "") -> dict:
        text = str(text or "").strip()
        if not text:
            raise BlackboardError("备注不能为空")
        entry = {"kind": "note", "ref": ref or f"note:{jsonio.fingerprint(text)}",
                 "summary": text[:MAX_SUMMARY], "note": str(note)[:MAX_SUMMARY]}
        return self._upsert(session, entry)

    def unpin(self, session, ref_or_id: str) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        doc = self._load()
        keep = [e for e in doc["entries"]
                if e.get("id") != ref_or_id and e.get("ref") != ref_or_id]
        if len(keep) == len(doc["entries"]):
            raise BlackboardError(f"未知黑板条目 {ref_or_id}")
        doc["entries"] = keep
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "blackboard.unpin", ref_or_id, {}, "ok")
        return {"removed": ref_or_id}

    # ------------------------------------------------------------ 读取
    def list(self) -> list[dict]:
        return list(self._load()["entries"])

    def context(self, *, limit: int = 20) -> dict:
        """explorer 注入用：只读、摘要、有界。"""
        entries = self._load()["entries"]
        entries = sorted(entries, key=lambda e: float(e.get("pinned_at") or 0), reverse=True)
        entries = entries[:max(1, min(int(limit), MAX_ENTRIES))]
        groups: dict[str, list[dict]] = {"findings": [], "assets": [], "notes": []}
        for e in entries:
            item = {"ref": e.get("ref"), "summary": e.get("summary"),
                    "run": e.get("run", ""), "note": e.get("note", ""),
                    "evidence_path": e.get("evidence_path", "")}
            key = {"finding": "findings", "asset": "assets"}.get(e.get("kind"), "notes")
            groups[key].append(item)
        return {"readonly": True, "count": len(entries), **groups}
