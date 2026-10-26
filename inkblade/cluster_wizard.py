"""真实集群上手向导：kubeconfig 自动发现 → 校验/选择 context → pilot 只读画像。

设计目标（与 docs/UX-EVALUATION.md 的引导流一致）：

1. 零参数也能工作：显式 ``--kubeconfig`` > ``KUBECONFIG`` > ``~/.kube/config``
   > ``~/.kube/*.yaml``；找不到时给三行式人话 + 可复制命令，而不是堆栈；
2. 先 dry-run 后执行：``--dry-run`` 只做发现/解析/context 选择并打印下一步，
   不调用 kubectl、不写任何文件；
3. 默认只读：pilot 的 ``--allow-write`` 不在此向导暴露；写计划仍需另行走
   三闸门（授权/备份/审批）；
4. 离线可复现：``--snapshot`` 接受 kubectl get 导出的归一化 JSON，测试与
   客户先导采样都不需要真实集群。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

from .core.humanize import explain_exception
from .pilot import KubectlCollector, PilotError, load_snapshot_bundle, merge_kubeconfigs, run_pilot

SCHEMA = "inkblade-cluster-onboarding/1"


def _candidate_paths(explicit: Iterable[str | Path]) -> list[Path]:
    explicit = [Path(p).expanduser() for p in explicit]
    if explicit:
        return explicit
    out: list[Path] = []
    env = os.environ.get("KUBECONFIG", "")
    for part in env.split(os.pathsep):
        if part.strip():
            out.append(Path(part.strip()).expanduser())
    kube_dir = Path.home() / ".kube"
    out.append(kube_dir / "config")
    if kube_dir.is_dir():
        out.extend(sorted(kube_dir.glob("*.yaml")))
        out.extend(sorted(kube_dir.glob("*.yml")))
    seen: set[str] = set()
    deduped: list[Path] = []
    for path in out:
        key = str(path.resolve()) if path.exists() else str(path)
        if key not in seen:
            seen.add(key)
            deduped.append(path)
    return deduped


def _select_contexts(inventory: dict, requested: list[str], yes: bool) -> list[str]:
    available = [c.get("name", "") for c in inventory.get("contexts", []) if c.get("name")]
    if requested:
        missing = [c for c in requested if c not in available]
        if missing:
            raise PilotError(f"--context 不存在：{missing}（可用：{available}）")
        return requested
    if not available:
        raise PilotError("kubeconfig 合并后没有 context")
    # 非交互/默认：全部 context 只读清点；交互式但未给 --yes 时也默认全部，
    # 避免在 CI/管道里永久等待 stdin。
    return available


def _print_fix(exc: BaseException, context: dict[str, Any]) -> None:
    print(str(explain_exception(exc, context)))


def run_wizard(
    *,
    kubeconfigs: Iterable[str | Path] = (),
    context: str | Iterable[str] | None = None,
    snapshots: Iterable[str | Path] = (),
    out_dir: str | Path = "reports/pilot",
    workspace: str = "pilot-onboard",
    actor: str = "onboarding-wizard",
    role: str = "auditor",
    kubectl: str = "kubectl",
    timeout: int = 30,
    yes: bool = False,
    dry_run: bool = False,
    home: str | Path = ".",
) -> int:
    """返回进程退出码：0 成功 / 2 输入不可用（不抛堆栈）。"""
    if isinstance(context, str):
        requested = [context] if context.strip() else []
    else:
        requested = [c for c in (context or []) if str(c).strip()]

    snapshot_paths = [Path(p).expanduser() for p in snapshots]
    for path in snapshot_paths:
        if not path.is_file():
            _print_fix(FileNotFoundError(f"snapshot 不存在：{path}"),
                       {"path": str(path), "action": "inkblade onboard-cluster"})
            return 2

    print("InkBlade 真实集群引导（只读）")
    print("=" * 56)
    print("边界：默认只跑 pilot 只读清点（kubectl get / 离线 snapshot），不改集群。")
    print(f"输出目录：{Path(out_dir)} · 工作区：{workspace} · 角色：{role}")

    kube_paths: list[Path] = []
    contexts: list[str] = []
    inventory: dict[str, Any] | None = None

    if snapshot_paths:
        try:
            bundle = load_snapshot_bundle(snapshot_paths)
        except (PilotError, OSError, ValueError) as exc:
            _print_fix(exc, {"action": "inkblade onboard-cluster", "workspace": workspace})
            return 2
        contexts = [b.get("context") or Path(str(b.get("source", "snapshot"))).stem
                    for b in bundle]
        if requested:
            contexts = [c for c in contexts if c in requested]
            if not contexts:
                _print_fix(PilotError(f"--context 过滤后为空：{requested}"),
                           {"action": "inkblade onboard-cluster"})
                return 2
        print(f"输入：{len(snapshot_paths)} 个离线 snapshot（免 kubectl，可复现）")
        for path, ctx in zip(snapshot_paths, contexts):
            print(f"  - {ctx} ← {path}")
    else:
        kube_paths = _candidate_paths(kubeconfigs)
        missing = [p for p in kube_paths if not p.is_file()]
        if not kube_paths or (missing and kubeconfigs):
            target = str(missing[0] if missing else "~/.kube/config")
            _print_fix(FileNotFoundError(f"找不到可用的 kubeconfig：{target}"),
                       {"kubeconfig": target, "action": "inkblade onboard-cluster",
                        "workspace": workspace})
            print("\n也可以零配置看本地 mock：python -m inkblade demo")
            return 2
        existing = [p for p in kube_paths if p.is_file()]
        if not existing:
            _print_fix(FileNotFoundError("未发现 kubeconfig（KUBECONFIG / ~/.kube/config 均为空）"),
                       {"kubeconfig": "~/.kube/config", "action": "inkblade onboard-cluster"})
            print("\n也可以零配置看本地 mock：python -m inkblade demo")
            return 2
        try:
            inventory = merge_kubeconfigs(existing, stdlib_only=True)
            contexts = _select_contexts(inventory, requested, yes)
        except (PilotError, OSError, ValueError) as exc:
            _print_fix(exc, {"action": "inkblade onboard-cluster", "workspace": workspace})
            return 2
        print(f"输入：{len(existing)} 个 kubeconfig（自动发现）")
        for path in existing:
            print(f"  - {path}")
        for ctx in inventory.get("contexts", []):
            print(f"  context: {ctx.get('name')} · cluster={ctx.get('cluster')} · "
                  f"user={ctx.get('user')} · 来源={ctx.get('source')}")
        for conflict in inventory.get("conflicts", [])[:5]:
            print(f"  ! 冲突：{conflict}")

    if dry_run:
        print("\n[dry-run] 已完成发现/校验/context 选择，未调用 kubectl、未写文件。")
        print("下一步（只读画像）：")
        if snapshot_paths:
            args = " ".join(f'--snapshot "{p}"' for p in snapshot_paths)
            print(f'  python -m inkblade pilot {args} --out "{out_dir}" '
                  f'--workspace {workspace} --role {role}')
        else:
            args = " ".join(f'--kubeconfig "{p}"' for p in kube_paths if p.is_file())
            ctx_args = " ".join(f"--context {c}" for c in contexts)
            print(f'  python -m inkblade pilot {args} {ctx_args} --out "{out_dir}" '
                  f'--workspace {workspace} --role {role} --timeout {timeout}')
        print("  （pilot 默认只读；写计划需另行授权/备份/审批，三闸门缺一不可）")
        print(json.dumps({
            "schema": SCHEMA,
            "dry_run": True,
            "read_only": True,
            "kubeconfigs": [str(p) for p in kube_paths],
            "snapshots": [str(p) for p in snapshot_paths],
            "contexts": contexts,
            "out_dir": str(out_dir),
        }, ensure_ascii=False, indent=2))
        return 0

    collector = (KubectlCollector(kubectl, timeout=timeout)
                 if kube_paths and not snapshot_paths else None)
    try:
        result = run_pilot(
            kubeconfigs=kube_paths,
            snapshot_paths=snapshot_paths,
            out_dir=out_dir,
            workspace=workspace,
            actor=actor,
            role=role,
            allow_write=False,
            contexts=contexts,
            collector=collector,
        )
    except (PilotError, OSError, ValueError) as exc:
        _print_fix(exc, {"action": "inkblade onboard-cluster", "workspace": workspace})
        return 2

    summary = result.get("summary", {})
    print("\n只读清点完成（未改集群）")
    print(f"  contexts={summary.get('contexts')} clusters={summary.get('clusters')} "
          f"nodes={summary.get('nodes')} gpu_nodes={summary.get('gpu_nodes')} "
          f"findings={summary.get('findings')} top_risk={summary.get('top_risk')}")
    outputs = result.get("outputs", {})
    print(f"  报告：{Path(out_dir) / 'pilot-report.md'}")
    print(f"  机器可读：{Path(out_dir) / 'pilot-report.json'}")
    print(f"  审批清单：{Path(out_dir) / 'approvals.json'}")
    if outputs.get("manifest_sha256"):
        print(f"  manifest sha256：{outputs['manifest_sha256']}")
    print("\n下一步：")
    print(f"  python -m inkblade report-ctem --workspace {workspace} --run <run>  # 需要先产生 run")
    print("  python -m inkblade ui --port 8765  # 控制台查看发现与规则矩阵")
    return 0
