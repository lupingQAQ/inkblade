# -*- coding: utf-8 -*-
"""任务情报登记（CM-01）与敏感证据三态引用存储（CM-06）。

- 情报类型：``credential``（凭据）/ ``clue``（线索）/ ``sensitive``（敏感数据）；
- 每条情报绑定来源：run + step_key + 证据归档相对路径（必须存在，写入时校验 SHA256）；
- 三态存储（CM-06 等价）：
  - ``metadata``（默认）：只存类型/标签/长度/指纹，不存值；
  - ``redact``：存脱敏预览（前 3 后 2 或前 40 字），原文不落库；
  - ``raw``：显式 ``allow_raw=True`` 且 lead/admin 审批，原文落工作区
    ``intel_raw/<id>.json``（权限 0600），主登记表只存引用；
- 列表/导出永远只返回元数据；``reveal`` 需要 approve 且仅 raw/redact 可回读；
- 所有写操作与回读都写工作区 ``audit.jsonl``。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from . import jsonio

INTEL_RELPATH = "intel.json"
MODES = ("metadata", "redact", "raw")
KINDS = ("credential", "clue", "sensitive")


class IntelError(ValueError):
    """情报条目非法。"""


class IntelRegistry:
    def __init__(self, store, *, clock=time.time):
        self.store = store
        self.path = jsonio.ws_path(store, INTEL_RELPATH)
        self.raw_dir = Path(store.ws_dir) / "intel_raw"
        self._clock = clock

    def _load(self) -> dict:
        doc = jsonio.read_json(self.path, None)
        if not isinstance(doc, dict) or not isinstance(doc.get("intel"), list):
            doc = {"version": 1, "intel": []}
        return doc

    def _save(self, doc: dict) -> None:
        jsonio.write_json(self.path, doc)

    def _run_binding(self, run: str | None, step: str, evidence_path: str) -> dict:
        if not run:
            if step or evidence_path:
                raise IntelError("绑定证据必须提供 run")
            return {}
        try:
            r = self.store.open_run(run)
        except KeyError as exc:
            raise IntelError(f"run 不存在：{run}") from exc
        if step:
            rows = r.query("SELECT COUNT(*) FROM steps WHERE step_key=?", (step,))
            if not rows or int(rows[0][0]) == 0:
                raise IntelError(f"run {run} 无步骤 {step}（证据绑定失败）")
        binding = {"run": run, "step": step, "evidence_path": evidence_path}
        if evidence_path:
            p = Path(r.dir) / evidence_path
            if not p.is_file():
                raise IntelError(f"证据路径不存在：{evidence_path}")
            binding["evidence_sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
        return binding

    @staticmethod
    def _preview(value: str, kind: str) -> str:
        text = str(value)
        if len(text) <= 6:
            return "***"
        if kind == "credential":
            return f"{text[:3]}***{text[-2:]}"
        return text[:40] + ("…" if len(text) > 40 else "")

    def add(self, session, *, kind: str, label: str, value: str = "",
            run: str | None = None, source_step: str = "",
            evidence_path: str = "", mode: str = "metadata",
            allow_raw: bool = False, note: str = "", intel_id: str = "") -> dict:
        if kind not in KINDS:
            raise IntelError(f"未知情报类型 {kind!r}")
        if mode not in MODES:
            raise IntelError(f"未知存储模式 {mode!r}")
        if not str(label).strip():
            raise IntelError("label 不能为空")
        if mode == "raw":
            if not allow_raw:
                raise IntelError("raw 模式须显式 allow_raw=True（默认拒绝落原文）")
            if not session.can("approve"):
                raise PermissionError(f"{session.name}({session.role}) 无 raw 存储审批权限")
        binding = self._run_binding(run, source_step, evidence_path)
        doc = self._load()
        iid = intel_id or f"intel-{len(doc['intel']) + 1:04d}"
        if any(i.get("id") == iid for i in doc["intel"]):
            raise IntelError(f"情报 id 重复 {iid}")
        text = str(value or "")
        fp = hashlib.sha256((text + "|" + kind + "|" + str(label)).encode("utf-8")).hexdigest()
        entry: dict[str, Any] = {
            "id": iid, "kind": kind, "label": str(label)[:200], "mode": mode,
            "fingerprint": fp, "length": len(text), "run": run or "",
            "step_key": source_step, "evidence_path": evidence_path,
            "evidence_sha256": binding.get("evidence_sha256", ""),
            "note": str(note)[:500], "created_by": session.name,
            "created_at": self._clock(),
        }
        if mode == "redact":
            entry["preview"] = self._preview(text, kind)
        if mode == "raw":
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            raw_path = self.raw_dir / f"{iid}.json"
            raw_path.write_text(json.dumps({"value": text}, ensure_ascii=False), encoding="utf-8")
            try:
                os.chmod(raw_path, 0o600)
            except OSError:
                pass
            entry["raw_ref"] = str(raw_path.relative_to(Path(self.store.ws_dir))).replace("\\", "/")
        doc["intel"].append(entry)
        self._save(doc)
        jsonio.append_audit(self.store, session.name, "intel.add", iid,
                            {"kind": kind, "mode": mode, "label": label, "run": run}, "ok")
        return self._public(entry)

    def list(self, *, run: str = "", kind: str = "", mode: str = "") -> list[dict]:
        rows = self._load()["intel"]
        if run:
            rows = [r for r in rows if r.get("run") == run]
        if kind:
            rows = [r for r in rows if r.get("kind") == kind]
        if mode:
            rows = [r for r in rows if r.get("mode") == mode]
        return [self._public(r) for r in rows]

    def get(self, intel_id: str) -> dict:
        for r in self._load()["intel"]:
            if r.get("id") == intel_id:
                return self._public(r)
        raise IntelError(f"未知情报 {intel_id}")

    @staticmethod
    def _public(entry: dict) -> dict:
        out = {k: v for k, v in entry.items() if k not in ("raw_ref", "preview")}
        if entry.get("preview"):
            out["preview"] = entry["preview"]
        out["has_raw"] = bool(entry.get("raw_ref"))
        return out

    def reveal(self, session, intel_id: str) -> dict:
        """回读脱敏预览或 raw 原文；raw 需要 approve。"""
        entry = next((r for r in self._load()["intel"] if r.get("id") == intel_id), None)
        if entry is None:
            raise IntelError(f"未知情报 {intel_id}")
        if entry.get("mode") == "metadata":
            raise IntelError("metadata 模式无值可回读")
        if entry.get("mode") == "raw":
            if not session.can("approve"):
                raise PermissionError(f"{session.name}({session.role}) 无 raw 回读权限")
            raw = jsonio.read_json(Path(self.store.ws_dir) / entry["raw_ref"], {})
            value = (raw or {}).get("value", "")
        else:
            value = entry.get("preview", "")
        jsonio.append_audit(self.store, session.name, "intel.reveal", intel_id,
                            {"mode": entry.get("mode")}, "ok")
        return {"id": intel_id, "mode": entry.get("mode"), "value": value}

    def update(self, session, intel_id: str, *, label: str = "", note: str = "") -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        doc = self._load()
        for entry in doc["intel"]:
            if entry.get("id") == intel_id:
                if label:
                    entry["label"] = str(label)[:200]
                if note:
                    entry["note"] = str(note)[:500]
                entry["updated_at"] = self._clock()
                self._save(doc)
                jsonio.append_audit(self.store, session.name, "intel.update", intel_id,
                                    {"label": label}, "ok")
                return self._public(entry)
        raise IntelError(f"未知情报 {intel_id}")

    def stats(self) -> dict:
        rows = self._load()["intel"]
        return {"total": len(rows),
                "by_kind": {k: sum(1 for r in rows if r.get("kind") == k) for k in KINDS},
                "by_mode": {m: sum(1 for r in rows if r.get("mode") == m) for m in MODES},
                "bound_to_evidence": sum(1 for r in rows if r.get("evidence_sha256"))}
