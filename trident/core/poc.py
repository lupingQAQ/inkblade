# -*- coding: utf-8 -*-
"""验证级 PoC（XBow 对标 ⑤）：写类 finding 附「验证步骤 + 预期证据」+ 自动重验开关。

- ``build_verification(meta, params, result)``：为写类模块产出验证块——
  steps（复核者在靶场重放的操作序列）+ expected_evidence（预期观测=摘要/哈希/回滚一致性）；
- runner 对 writes=true 模块的每条 finding 自动附加 verification 块（detail JSON 内）；
- ``reverify(store, session, modules_dir, module_key, params)``：重跑模块（probe 参数化）
  与原 finding 标题集合比对 → {verified, evidence}；
- 自动重验开关：工作区 ``workspace.json`` ``{"poc": {"auto_reverify": true}}``
  （scheduler 漂移轮与 explorer 执行完成后对写类 finding 自动调用 reverify）。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

POC_SCHEMA = "trident-poc-verification-v1"


class PocError(ValueError):
    """验证块构造/重验非法。"""


def auto_reverify_enabled(store) -> bool:
    cfg_path = Path(store.ws_dir) / "workspace.json"
    if not cfg_path.exists():
        return False
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except ValueError:
        return False
    return bool((cfg.get("poc") or {}).get("auto_reverify"))


def set_auto_reverify(store, enabled: bool) -> dict:
    cfg_path = Path(store.ws_dir) / "workspace.json"
    cfg: dict[str, Any] = {}
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except ValueError:
            cfg = {}
    cfg.setdefault("poc", {})["auto_reverify"] = bool(enabled)
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=1), encoding="utf-8")
    return cfg


def build_verification(module_key: str, params: dict, result: dict) -> dict:
    """验证步骤 + 预期证据（数据全部来自本次执行结果，可独立复核）。"""
    artifacts = [Path(p).name for p in result.get("artifacts", [])]
    digest = hashlib.sha256(
        json.dumps({"summary": result.get("summary", ""), "artifacts": artifacts},
                   ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    steps = [
        "1. 复核 ROE 与备份回执：actions 表中该模块 started/success 行与 backups 快照在册",
        f"2. 以 probe-only 参数重放模块 {module_key}（params 供 explorer/scheduler 传递）",
        "3. 比对重放 findings 标题集合与本 finding（存在即复现）",
        "4. 写面复核：backups→rollbacks 回滚后目标 sha256 与快照一致（无残留）",
    ]
    expected = {
        "summary": str(result.get("summary", "")),
        "artifacts": artifacts,
        "result_sha256": digest,
        "rollback": "备份回滚后目标内容与快照 sha256 完全一致（BackupManager 断言）",
        "trace": "traces/<module>.json 内请求/响应全量记录（traffic 表同步入库）",
    }
    return {
        "schema": POC_SCHEMA,
        "module": module_key,
        "steps": steps,
        "expected_evidence": expected,
        "auto_reverify": "workspace.json poc.auto_reverify 开启时由 scheduler/explorer 触发",
        "params": {k: v for k, v in (params or {}).items()
                   if k not in ("backup_targets",)},  # 备份目标不进验证块（敏感面）
    }


def enrich_write_findings(module_key: str, meta_writes: bool, params: dict, result: dict) -> list[dict]:
    """runner 钩子：写类模块的每条 finding detail 附加 verification 块。"""
    findings = list(result.get("findings", []) or [])
    if not meta_writes:
        return findings
    verification = build_verification(module_key, params, result)
    for f in findings:
        try:
            detail = json.loads(f.get("detail") or "{}")
            if not isinstance(detail, dict):
                detail = {"detail": f.get("detail", "")}
        except ValueError:
            detail = {"detail": f.get("detail", "")}
        detail["verification"] = verification
        f["detail"] = json.dumps(detail, ensure_ascii=False)
    return findings


def reverify(store, session, modules_dir, module_key: str, params: dict,
             *, expected_titles: list[str] | None = None) -> dict[str, Any]:
    """自动重验：重跑模块并比对 finding 标题集合。"""
    from .runner import run_module

    probe_params = dict(params or {})
    probe_params.pop("mode", None)  # 探测模式（防 backup-write 演示分支）
    probe_params.pop("backup_targets", None)
    before = expected_titles
    if before is None:
        before = []
        if store.ws_dir.exists():
            for p in sorted(store.ws_dir.iterdir()):
                if not p.is_dir() or p.name.startswith("_"):
                    continue
                try:
                    run = store.open_run(p.name)
                except KeyError:
                    continue
                before += [f["title"] for f in run.findings
                           if f.get("step_key") == module_key]
    res = run_module(store, session, module_key, probe_params, modules_dir)
    run = store.open_run(res["run"])
    titles = [f["title"] for f in run.findings if f.get("step_key") == module_key]
    reproduced = sorted(set(before) & set(titles))
    return {
        "module": module_key, "verified": bool(reproduced),
        "reproduced_titles": reproduced,
        "replay_run": res["run"],
        "evidence": {"before_titles": sorted(set(before)), "after_titles": sorted(set(titles)),
                     "summary": res.get("result_summary", "")},
    }
