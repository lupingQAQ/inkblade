# -*- coding: utf-8 -*-
"""任务模板（clean-room 等价实现）：链子集 + 参数预设 + 计划；支持从 run 反推。

- 模板实体持久化在工作区 ``templates.json``，字段：id/name/chains/params/modules/
  source/tags/created_by/created_at；
- ``from_run`` **只读** run 的 steps/prompts/findings，解析步骤参数（``ast.literal_eval``
  或 JSON，仅 dict），按链定义反推「本次 run 覆盖的链子集」，并把参数预设脱敏后归档；
  不新建 run、不执行任何模块；
- ``instantiate`` 渲染 dry-run 计划（模块/参数/写面/备份要求/ROE 级别判定），
  与 chains.dry_run 同口径；计划本身不触发执行，执行仍须走 explorer 审批 + runner 三闸门；
- 管理动作（创建/更新/删除）要求 lead/admin（approve）；读取/实例化对所有角色开放。
"""

from __future__ import annotations

import ast
import json
import time
from pathlib import Path
from typing import Any

from . import jsonio
from .chains import load_chains
from .registry import load_modules
from .roe import LEVELS

TEMPLATES_RELPATH = "templates.json"


class TemplateError(ValueError):
    """模板参数/引用非法。"""


def _parse_params(text: str) -> dict:
    if not text:
        return {}
    for loader in (ast.literal_eval, json.loads):
        try:
            doc = loader(text)
        except Exception:
            continue
        if isinstance(doc, dict):
            return doc
    return {}


class TemplateStore:
    def __init__(self, store, *, chains_dir: Path | str | None = None,
                 modules_dir: Path | str | None = None):
        self.store = store
        self.path = jsonio.ws_path(store, TEMPLATES_RELPATH)
        self.chains_dir = Path(chains_dir) if chains_dir else \
            Path(__file__).resolve().parent.parent / "chains"
        self.modules_dir = Path(modules_dir) if modules_dir else Path(store.root) / "modules"

    # ------------------------------------------------------------ 持久化
    def _load(self) -> list[dict]:
        doc = jsonio.read_json(self.path, None)
        if isinstance(doc, list):
            return doc
        if isinstance(doc, dict) and isinstance(doc.get("templates"), list):
            return doc["templates"]
        return []

    def _save(self, items: list[dict]) -> None:
        jsonio.write_json(self.path, {"version": 1, "templates": items})

    def list(self) -> list[dict]:
        return list(self._load())

    def get(self, template_id: str) -> dict:
        for t in self._load():
            if t.get("id") == template_id:
                return t
        raise TemplateError(f"未知模板 {template_id}")

    # ------------------------------------------------------------ CRUD
    def add(self, session, *, name: str, chains: list[str] | None = None,
            params: dict | None = None, modules: list[str] | None = None,
            notes: str = "", tags: list[str] | None = None,
            template_id: str = "", source: dict | None = None) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        if not str(name).strip():
            raise TemplateError("name 不能为空")
        known = load_chains(self.chains_dir) if self.chains_dir.exists() else {}
        chain_list = list(chains or [])
        for cid in chain_list:
            if cid not in known:
                raise TemplateError(f"未知链 {cid}")
        module_list = list(modules or [])
        if not chain_list and not module_list:
            # 允许仅有 source.modules 的 run 反推模板
            module_list = list((source or {}).get("modules") or [])
        if not chain_list and not module_list:
            raise TemplateError("chains 与 modules 不能同时为空")
        preset = self._validate_params(params or {})
        items = self._load()
        tid = template_id or f"tmpl-{len(items) + 1:03d}"
        if any(t.get("id") == tid for t in items):
            raise TemplateError(f"模板 id 重复 {tid}")
        item = {
            "id": tid, "name": str(name), "chains": chain_list,
            "modules": module_list, "params": preset,
            "notes": str(notes), "tags": list(tags or []),
            "created_by": session.name, "created_at": time.time(),
            "source": dict(source or {"kind": "manual"}),
        }
        items.append(item)
        self._save(items)
        jsonio.append_audit(self.store, session.name, "template.add", tid,
                            {"name": name, "chains": chain_list, "modules": module_list}, "ok")
        return item

    @staticmethod
    def _validate_params(params: dict) -> dict:
        if not isinstance(params, dict):
            raise TemplateError("params 必须是 {module: {...}} 对象")
        out = {}
        for module, preset in params.items():
            if not isinstance(preset, dict):
                raise TemplateError(f"params[{module}] 必须是对象")
            out[str(module)] = jsonio.redact(preset)
        return out

    def update(self, session, template_id: str, **fields) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        items = self._load()
        for item in items:
            if item.get("id") != template_id:
                continue
            if "name" in fields:
                if not str(fields["name"]).strip():
                    raise TemplateError("name 不能为空")
                item["name"] = str(fields["name"])
            if "chains" in fields:
                known = load_chains(self.chains_dir) if self.chains_dir.exists() else {}
                for cid in fields["chains"] or []:
                    if cid not in known:
                        raise TemplateError(f"未知链 {cid}")
                item["chains"] = list(fields["chains"] or [])
            if "params" in fields:
                item["params"] = self._validate_params(fields["params"] or {})
            if "modules" in fields:
                item["modules"] = list(fields["modules"] or [])
            if "notes" in fields:
                item["notes"] = str(fields["notes"])
            if "tags" in fields:
                item["tags"] = list(fields["tags"] or [])
            item["updated_at"] = time.time()
            self._save(items)
            jsonio.append_audit(self.store, session.name, "template.update", template_id,
                                {k: v for k, v in fields.items() if k != "params"}, "ok")
            return item
        raise TemplateError(f"未知模板 {template_id}")

    def delete(self, session, template_id: str) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        items = self._load()
        keep = [t for t in items if t.get("id") != template_id]
        if len(keep) == len(items):
            raise TemplateError(f"未知模板 {template_id}")
        self._save(keep)
        jsonio.append_audit(self.store, session.name, "template.delete", template_id, {}, "ok")
        return {"removed": template_id}

    # ------------------------------------------------------------ 从 run 反推（只读）
    def from_run(self, session, run_name: str, *, name: str = "",
                 template_id: str = "", include_params: bool = True) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        try:
            run = self.store.open_run(run_name)
        except KeyError as exc:
            raise TemplateError(f"run 不存在：{run_name}") from exc
        rows = run.query(
            "SELECT steps.step_key, prompts.content FROM steps"
            " LEFT JOIN prompts ON prompts.step_id = steps.id ORDER BY steps.id")
        modules: list[str] = []
        params: dict[str, dict] = {}
        for step_key, prompt in rows:
            if step_key not in modules:
                modules.append(str(step_key))
            if include_params and step_key not in params:
                parsed = _parse_params(str(prompt or ""))
                if parsed:
                    params[str(step_key)] = parsed
        findings = run.findings
        chains = load_chains(self.chains_dir) if self.chains_dir.exists() else {}
        covered: list[str] = []
        present = set(modules)
        for cid, chain in sorted(chains.items()):
            need = {st.get("module") for st in chain.get("steps", [])}
            if need and need <= present:
                covered.append(cid)
        safe_params = {k: jsonio.redact(v) for k, v in params.items()}
        source = {"kind": "run", "run": run_name, "modules": modules,
                  "steps": len(rows), "findings": len(findings),
                  "covered_chains": covered, "derived_at": time.time()}
        return self.add(session, name=name or f"from-{run_name}",
                        chains=covered, modules=modules, params=safe_params,
                        notes=f"从 run {run_name} 反推（只读）",
                        tags=["derived"], template_id=template_id, source=source)

    # ------------------------------------------------------------ 计划（dry-run，不执行）
    def instantiate(self, template_id: str, *, overrides: dict | None = None,
                    roe_level: str | None = None) -> dict:
        template = self.get(template_id)
        chains = load_chains(self.chains_dir) if self.chains_dir.exists() else {}
        mods = load_modules(self.modules_dir) if self.modules_dir.exists() else {}
        ordered: list[str] = []
        for cid in template.get("chains", []):
            chain = chains.get(cid) or {}
            for st in chain.get("steps", []):
                m = st.get("module")
                if m and m not in ordered:
                    ordered.append(m)
        for m in template.get("modules", []):
            if m not in ordered:
                ordered.append(m)
        if roe_level is None:
            roe_level = (self.store.consent() or {}).get("fields", {}).get("level", "只读侦察")
        overrides = overrides or {}
        steps = []
        for module in ordered:
            preset = dict((template.get("params") or {}).get(module) or {})
            preset.update(dict(overrides.get(module) or {}))
            meta = mods.get(module)
            writes = bool(meta.writes) if meta is not None else False
            min_level = meta.min_level if meta is not None else ""
            allowed = (min_level in LEVELS and roe_level in LEVELS
                       and LEVELS.index(min_level) <= LEVELS.index(roe_level))
            steps.append({
                "module": module, "params": preset, "writes": writes,
                "min_level": min_level, "known": meta is not None,
                "allowed_by_roe": allowed,
                "backup_required": writes,
                "backup_targets": list(preset.get("backup_targets") or []),
            })
        return {"template": template_id, "name": template.get("name", ""),
                "chains": list(template.get("chains") or []),
                "roe_level": roe_level, "steps": steps,
                "counts": {"steps": len(steps),
                           "writes": sum(1 for s in steps if s["writes"]),
                           "blocked_by_roe": sum(1 for s in steps if not s["allowed_by_roe"])},
                "execution": {"performed": False,
                              "gate": "执行须经 explorer 提议 + lead 批准 + runner 三闸门"}}


def schedule_payload(store, template_id: str, *, cron: str | None = None,
                     interval_seconds: int | None = None) -> dict:
    """把模板转成 schedule.add 的载荷（不创建计划、不执行）。"""
    tpl = TemplateStore(store).get(template_id)
    return {"cron": cron, "interval_seconds": interval_seconds,
            "chains": list(tpl.get("chains") or []), "template_id": template_id,
            "warning": "params 预设不进入 scheduler（链参数以链定义/审批提议为准）"}
