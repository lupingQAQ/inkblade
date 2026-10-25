"""编排引擎：授权闸门 + 备份闸门 + 模块执行 + 审计 + 三层落证。"""

from __future__ import annotations

import importlib.util
import time
import uuid
from pathlib import Path
from typing import Any

from .backup import BackupManager
from .evidence import EvidenceStore
from .registry import ModuleMeta, load_modules
from .roe import assert_execution_allowed


class BackupGateRefused(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.exit_code = 91


class ModuleFailure(Exception):
    pass


def _load_run_py(meta: ModuleMeta):
    spec = importlib.util.spec_from_file_location(f"trident_mod_{meta.key.replace('-', '_')}", meta.path / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_module(
    store: EvidenceStore,
    session,
    module_key: str,
    params: dict[str, Any],
    modules_dir: Path | str,
    run=None,
) -> dict[str, Any]:
    mods = load_modules(modules_dir)
    if module_key not in mods:
        raise KeyError(f"未知模块: {module_key}")
    meta = mods[module_key]

    # 授权与角色双闸门
    assert_execution_allowed(store, meta.__dict__)
    if not session.can("execute"):
        raise PermissionError(f"{session.name}({session.role}) 无 execute 权限")
    if meta.__dict__.get("private"):
        from .zeroday import assert_allowed

        assert_allowed(store, session, meta.__dict__)

    if run is None:
        run = store.create_run(f"run-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}")

    marker = f"TRIDENT-{run.name}"
    bm = BackupManager(store, run)

    # 备份闸门：写类模块必须先拿到快照回执
    if meta.writes:
        receipt = bm.snapshot(module_key, params.get("backup_targets", []))
        if receipt is None:
            run.log_action(session.name, "execute", module_key, params, "refused-no-backup")
            raise BackupGateRefused("写类模块缺少备份回执（backup_targets 为空或不可用）")

    run.log_action(session.name, "execute", module_key, params, "started",
                   rollback_to=module_key if meta.writes else None)
    try:
        mod = _load_run_py(meta)
        ctx = {"store": store, "run": run, "marker": marker, "backup": bm,
               "actor": session.name, "meta": meta.__dict__}
        result = mod.run(ctx, params) or {}
    except Exception as exc:  # 模块失败：审计 + 不留写残留（由回滚保障）
        run.log_action(session.name, "execute", module_key, params, f"failed:{exc}")
        if meta.writes:
            bm.rollback(module_key)
        raise

    step = run.add_step(
        module_key,
        prompt_or_cmd=str(params),
        env={"actor": session.name, "workspace": store.workspace, "module": module_key},
        result_summary=str(result.get("summary", "")),
        artifacts=[Path(p) for p in result.get("artifacts", [])],
    )
    # 验证级 PoC：写类模块 finding 附验证步骤+预期证据（core/poc.py）
    from .poc import enrich_write_findings

    findings = enrich_write_findings(module_key, bool(meta.writes), params, result)
    for f in findings:
        run.add_finding(module_key, sev=f.get("sev", "info"), title=f.get("title", ""),
                        detail=f.get("detail", ""), evidence_path=step["archive"],
                        is_zeroday=bool(f.get("is_zeroday", False)))
    # 流量录制：模块 traces/*.json 全量入 traffic 表（core/traffic.py，幂等）
    try:
        from .traffic import ingest_run

        ingest_run(run)
    except Exception:  # 流量入库失败不阻断执行（无 trace 的模块跳过）
        pass
    run.log_action(session.name, "execute", module_key, params, "success", rollback_to=module_key if meta.writes else None)
    return {"run": run.name, "step": module_key, **step}
