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
from .roe import ExecutionLocked, assert_execution_allowed, scope_violation
from .surface import SurfaceContext, gate as surface_gate


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
    surface_ctx: SurfaceContext | dict | None = None,
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
    is_zd = bool(meta.private)  # 私有（零日级）模块的每条审计行都打标

    # 紧急停止闸门：工作区级 kill switch 命中后拒绝一切新执行
    from .abort import assert_not_aborted

    try:
        assert_not_aborted(store)
    except ExecutionLocked as exc:
        run.log_action(session.name, "execute", module_key, params,
                       "refused-aborted", is_zeroday=is_zd)
        raise exc

    # 范围闸门：params 显式声明的 host / target_ns / namespace 必须落在授权范围内
    violation = scope_violation(store, params)
    if violation:
        run.log_action(session.name, "execute", module_key, params,
                       "refused-out-of-scope", is_zeroday=is_zd)
        raise ExecutionLocked(violation)

    # 真实面闸门：absent 不执行/不产 finding/不计覆盖；unknown 需显式 --probe。
    # 直接调用（旧测试/库调用）对默认启用模块保持兼容；被隔离模块始终受闸门约束。
    sctx = surface_ctx
    if sctx is None:
        if meta.default_enabled:
            sctx = SurfaceContext.build(params=params, enforce=False)
        else:
            sctx = SurfaceContext.build(
                params=params, probe=bool(params.get("probe") or params.get("allow_undeployed")),
                enforce=True)
    elif isinstance(sctx, dict):
        sctx = SurfaceContext.build(
            profile=sctx.get("profile"), collection=sctx.get("collection"),
            params=params, probe=bool(sctx.get("probe")), fixture=bool(sctx.get("fixture")),
            enforce=True)
    gate = surface_gate(meta, sctx)
    if gate["status"] != "run":
        run.log_action(session.name, "execute", module_key, params, gate["status"],
                       is_zeroday=is_zd)
        return {
            "run": run.name,
            "step": module_key,
            "status": gate["status"],
            "skipped": True,
            "summary": gate["reason"],
            "surface": gate,
            "findings": [],
            "artifacts": [],
        }

    # 备份闸门：写类模块必须先拿到快照回执
    if meta.writes:
        receipt = bm.snapshot(module_key, params.get("backup_targets", []))
        if receipt is None:
            run.log_action(session.name, "execute", module_key, params, "refused-no-backup",
                           is_zeroday=is_zd)
            raise BackupGateRefused("写类模块缺少备份回执（backup_targets 为空或不可用）")

    # Modules consume the real collection first; the runner exposes it without
    # overwriting an explicit module parameter.
    if sctx.collection and "collection" not in params:
        params["collection"] = sctx.collection
    if sctx.profile_name and "profile" not in params:
        params["profile"] = sctx.profile_name
    run.log_action(session.name, "execute", module_key, params, "started",
                   rollback_to=module_key if meta.writes else None, is_zeroday=is_zd)
    try:
        mod = _load_run_py(meta)
        ctx = {"store": store, "run": run, "marker": marker, "backup": bm,
               "actor": session.name, "meta": meta.__dict__, "surface": sctx}
        result = mod.run(ctx, params) or {}
    except Exception as exc:  # 模块失败：审计 + 不留写残留（由回滚保障）
        run.log_action(session.name, "execute", module_key, params, f"failed:{exc}",
                       is_zeroday=is_zd)
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
    run.log_action(session.name, "execute", module_key, params, "success",
                   rollback_to=module_key if meta.writes else None, is_zeroday=is_zd)
    return {"run": run.name, "step": module_key, "surface": gate, **step}
