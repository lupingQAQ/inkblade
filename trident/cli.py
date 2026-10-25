"""Trident 命令行入口：python -m trident <子命令>。"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .core.registry import load_modules
from .core.users import ROLES, UserStore

DEFAULT_HOME = Path(".")


def _store(home: Path, ws: str):
    from .core.evidence import EvidenceStore

    return EvidenceStore(home, workspace=ws)


def main(argv=None) -> int:
    import sys

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="trident", description="Trident ML-cluster pentest platform (authorized testing)")
    ap.add_argument("--home", default=".", help="工作区根目录（含 evidence/ modules/ users.json）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("module", help="模块管理")
    msub = sp.add_subparsers(dest="mcmd", required=True)
    ml = msub.add_parser("list")
    ml.add_argument("--modules-dir", default=None)

    sub.add_parser("roe", help="查看授权状态").add_argument("--workspace", default="local-lab")

    u = sub.add_parser("user", help="用户管理")
    usub = u.add_subparsers(dest="ucmd", required=True)
    ua = usub.add_parser("add")
    ua.add_argument("name")
    ua.add_argument("password")
    ua.add_argument("role", choices=["admin", "lead", "tester", "auditor"])
    ua.add_argument("--workspaces", default="local-lab")

    sub.add_parser("ui", help="启动本地 Web 控制台").add_argument("--port", type=int, default=8765)

    mcp = sub.add_parser("mcp", help="MCP 只读服务器（stdio JSON-RPC）")
    mcp.add_argument("--workspace", default="local-lab")
    mcp.add_argument("--users", default=None, help="users.json（可选；配合 --token）")
    mcp.add_argument("--token", default=os.environ.get("TRIDENT_TOKEN"),
                     help="会话 token（默认取 TRIDENT_TOKEN；缺省为本机只读操作员）")
    mcp.add_argument("--actor", default="mcp-readonly")
    mcp.add_argument("--role", choices=list(ROLES), default="auditor")
    mcp.add_argument("--chains-dir", default=None)
    mcp.add_argument("--modules-dir", default=None)

    plan = sub.add_parser("plan", help="Agent 规划器：链推荐排序（只读，须 lead 审批）")
    plan.add_argument("--workspace", default="local-lab")
    plan.add_argument("--run", default=None)
    plan.add_argument("--format", choices=["json", "md"], default="json")
    plan.add_argument("--chains-dir", default=None)
    plan.add_argument("--modules-dir", default=None)

    sbom = sub.add_parser("sbom", help="导出 CycloneDX ML-BOM 风格 AI SBOM")
    sbom.add_argument("--models", required=True, help="模型清单 JSON（name/version/source/license/path|sha256）")
    sbom.add_argument("--root", default=".", help="权重相对路径根目录")
    sbom.add_argument("--out", default=None, help="输出 JSON（缺省 stdout）")

    vm = sub.add_parser("verify-model", help="校验模型签名 / 哈希 / 来源三元组")
    vm.add_argument("--weights", required=True)
    vm.add_argument("--bundle", required=True, help="cosign 风格 provenance bundle JSON")
    vm.add_argument("--trust-root", required=True)
    vm.add_argument("--expected-source", default=None)
    vm.add_argument("--out", default=None)

    at = sub.add_parser("attest", help="TDX/SEV-SNP/NVIDIA CC 证明核验与策略断言")
    at.add_argument("--evidence", required=True, help="attestation JSON fixture/真实报告")
    at.add_argument("--policy", default=None, help="策略 JSON（缺省使用内置 fixture 策略）")
    at.add_argument("--out", default=None)

    exp = sub.add_parser("export", help="机器可读导出：SARIF / OCSF / VEX")
    exp.add_argument("--workspace", default="local-lab")
    exp.add_argument("--run", required=True)
    exp.add_argument("--format", choices=["sarif", "ocsf", "vex"], required=True)
    exp.add_argument("--out", default=None, help="输出 JSON（缺省 stdout）")

    disc = sub.add_parser("discover", help="资产自动发现：种子 → 增量资产库（assets 表）")
    disc.add_argument("--workspace", default="local-lab")
    disc.add_argument("--seeds", required=True, help="种子 JSON（namespaces/services/kubeconfig_snapshot）")
    disc.add_argument("--source", default="cli")
    disc.add_argument("--graph", action="store_true", help="输出资产图（namespace→service）")

    expl = sub.add_parser("explore", help="审批制自主探索器：propose|list|approve|reject|execute")
    expl.add_argument("--workspace", default="local-lab")
    expl.add_argument("action", choices=["propose", "list", "approve", "reject", "execute"])
    expl.add_argument("--id", default=None, help="提议 id（approve/reject/execute）")
    expl.add_argument("--use-llm", default=None, help="true/false（缺省：有 env 则用 LLM，失败降级 rules）")
    expl.add_argument("--max-actions", type=int, default=5)
    expl.add_argument("--reason", default="")
    expl.add_argument("--actor", default="cli")
    expl.add_argument("--role", choices=list(ROLES), default="lead")

    sch = sub.add_parser("schedule", help="周期重测：add|list|remove|run-due（cron/interval → 链子集 → drift）")
    sch.add_argument("--workspace", default="local-lab")
    sch.add_argument("action", choices=["add", "list", "remove", "run-due"])
    sch.add_argument("--cron", default=None)
    sch.add_argument("--interval-seconds", type=int, default=None)
    sch.add_argument("--chains", default=None, help="逗号分隔链 id")
    sch.add_argument("--id", default=None)
    sch.add_argument("--actor", default="cli")
    sch.add_argument("--role", choices=list(ROLES), default="lead")

    tr = sub.add_parser("traffic", help="流量录制/回放：ingest|list|replay")
    tr.add_argument("--workspace", default="local-lab")
    tr.add_argument("action", choices=["ingest", "list", "replay"])
    tr.add_argument("--run", default=None)
    tr.add_argument("--module", default="")
    tr.add_argument("--live", action="store_true", help="真实重放（须 ROE+execute；默认 dry 断言计划）")
    tr.add_argument("--actor", default="cli")
    tr.add_argument("--role", choices=list(ROLES), default="tester")

    mine = sub.add_parser("mine", help="挖掘流水线闭环：模板验证→最新版本差异→登记册候选（不自动入库）")
    mine.add_argument("--out", default=None, help="输出目录（缺省 reports/samples/mining）")
    mine.add_argument("--targets", default=None, help="逗号分隔目标（vllm,sglang,kuberay,hami,litellm）")

    args = ap.parse_args(argv)
    home = Path(args.home)

    if args.cmd == "module" and args.mcmd == "list":
        mods_dir = Path(args.modules_dir) if args.modules_dir else home / "modules"
        mods = load_modules(mods_dir)
        for key in sorted(mods):
            m = mods[key]
            print(f"{key}\t{m.series}\t{m.min_level}\t{'写' if m.writes else '读'}")
        return 0

    if args.cmd == "roe":
        from .core.roe import roe_status

        print(roe_status(_store(home, args.workspace)))
        return 0

    if args.cmd == "user" and args.ucmd == "add":
        users = UserStore(home / "users.json")
        users.create_user(args.name, args.password, args.role, args.workspaces.split(","))
        print(f"created {args.name}({args.role})")
        return 0

    if args.cmd == "ui":
        from .webui.server import make_server

        users = UserStore(home / "users.json")
        httpd = make_server(home, users, port=args.port)
        print(f"Trident 控制台: http://127.0.0.1:{httpd.port} （Ctrl+C 退出）")
        try:
            import time

            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            httpd.shutdown()
        return 0

    if args.cmd == "mcp":
        from .mcp_server import run_stdio

        try:
            return run_stdio(
                home, args.workspace,
                users_path=Path(args.users) if args.users else None,
                token=args.token, actor=args.actor, role=args.role,
                chains_dir=args.chains_dir, modules_dir=args.modules_dir,
            )
        except ValueError as exc:
            print(f"trident mcp: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "plan":
        from .agent_planner import plan_workspace, render_plan_md

        try:
            data = plan_workspace(
                _store(home, args.workspace), run=args.run,
                chains_dir=args.chains_dir, modules_dir=args.modules_dir,
            )
        except KeyError as exc:
            print(f"trident plan: {exc}", file=sys.stderr)
            return 2
        if args.format == "md":
            print(render_plan_md(data))
        else:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "sbom":
        from . import supplychain as sc

        try:
            models = json.loads(Path(args.models).read_text(encoding="utf-8"))
            doc = sc.write_sbom(models, args.out, root=args.root)
        except (OSError, ValueError) as exc:
            print(f"trident sbom: {exc}", file=sys.stderr)
            return 2
        if args.out is None:
            print(json.dumps(doc, ensure_ascii=False, indent=2))
        else:
            print(f"sbom: {args.out}（{len(doc['components'])} components）")
        return 0

    if args.cmd == "verify-model":
        from . import supplychain as sc

        try:
            verdict = sc.verify_model(args.weights, args.bundle, args.trust_root,
                                      expected_source=args.expected_source)
            sc.write_verdict(verdict, args.out)
        except (OSError, ValueError) as exc:
            print(f"trident verify-model: {exc}", file=sys.stderr)
            return 2
        if args.out is None:
            print(json.dumps(verdict, ensure_ascii=False, indent=2))
        return 0 if verdict["ok"] else 2

    if args.cmd == "attest":
        from . import supplychain as sc

        try:
            policy = sc.load_policy(args.policy) if args.policy else sc.load_policy()
            verdict = sc.verify_attestation(args.evidence, policy)
            sc.write_verdict(verdict, args.out)
        except (OSError, ValueError) as exc:
            print(f"trident attest: {exc}", file=sys.stderr)
            return 2
        if args.out is None:
            print(json.dumps(verdict, ensure_ascii=False, indent=2))
        return 0 if verdict["ok"] else 2

    if args.cmd == "export":
        from .export import export_run, write_export

        try:
            doc = export_run(_store(home, args.workspace), args.run, args.format)
            write_export(doc, args.out)
        except KeyError as exc:
            print(f"trident export: {exc}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"trident export: {exc}", file=sys.stderr)
            return 2
        if args.out is None:
            print(json.dumps(doc, ensure_ascii=False, indent=2))
        else:
            print(f"export: {args.out}（format={args.format}）")
        return 0

    if args.cmd == "discover":
        from .core.discovery import AssetInventory

        try:
            seeds = json.loads(Path(args.seeds).read_text(encoding="utf-8"))
            inv = AssetInventory(_store(home, args.workspace))
            diff = inv.ingest(seeds, source=args.source)
        except (OSError, ValueError) as exc:
            print(f"trident discover: {exc}", file=sys.stderr)
            return 2
        payload = inv.graph() if args.graph else {"assets": inv.list(include_missing=True)}
        print(json.dumps({"diff": diff, **payload}, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "explore":
        from .core.explorer import ApprovalDenied, Explorer
        from .core.users import Session

        store = _store(home, args.workspace)
        session = Session(None, args.actor, args.role, [args.workspace], "cli-local")
        ex = Explorer(store, modules_dir=home / "modules")
        try:
            if args.action == "propose":
                use_llm = None if args.use_llm is None else args.use_llm == "true"
                data = ex.propose(session, use_llm=use_llm, max_actions=args.max_actions)
            elif args.action == "list":
                data = {"proposals": ex.list_proposals()}
            elif args.action in ("approve", "reject"):
                if not args.id:
                    raise ValueError("--id 必填")
                data = ex.approve(session, args.id) if args.action == "approve" \
                    else ex.reject(session, args.id, args.reason)
            else:
                if not args.id:
                    raise ValueError("--id 必填")
                data = ex.execute(session, args.id)
        except (ApprovalDenied, PermissionError) as exc:
            print(f"trident explore: {exc}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"trident explore: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0

    if args.cmd == "schedule":
        from .core.scheduler import Scheduler
        from .core.users import Session

        store = _store(home, args.workspace)
        session = Session(None, args.actor, args.role, [args.workspace], "cli-local")
        sched = Scheduler(store, modules_dir=home / "modules")
        try:
            if args.action == "add":
                chains = [c for c in (args.chains or "").split(",") if c]
                data = sched.add(session, cron=args.cron, interval_seconds=args.interval_seconds,
                                 chains=chains, schedule_id=args.id or "")
            elif args.action == "list":
                data = {"schedules": sched.list(), "due": [s["id"] for s in sched.due()]}
            elif args.action == "remove":
                data = sched.remove(args.id or "")
            else:
                data = sched.run_due(session)
        except (ValueError, PermissionError) as exc:
            print(f"trident schedule: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0

    if args.cmd == "traffic":
        from .core import traffic as traffic_mod
        from .core.users import Session

        store = _store(home, args.workspace)
        session = Session(None, args.actor, args.role, [args.workspace], "cli-local")
        try:
            if args.action == "ingest":
                if not args.run:
                    raise ValueError("--run 必填")
                data = {"ingested": traffic_mod.ingest_run(store.open_run(args.run))}
            elif args.action == "list":
                if not args.run:
                    raise ValueError("--run 必填")
                data = {"entries": traffic_mod.list_traffic(store, args.run, module=args.module)}
            else:
                if not args.run:
                    raise ValueError("--run 必填")
                data = traffic_mod.replay(store, session, args.run, module=args.module,
                                          live=args.live)
        except (ValueError, PermissionError, KeyError) as exc:
            print(f"trident traffic: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0

    if args.cmd == "mine":
        from .mining import run_pipeline

        out = Path(args.out) if args.out else home / "reports" / "samples" / "mining"
        targets = [t for t in (args.targets or "").split(",") if t] or None
        try:
            report = run_pipeline(out, targets=targets)
        except ValueError as exc:
            print(f"trident mine: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({k: report[k] for k in ("validation", "targets", "candidates_total")},
                         ensure_ascii=False, indent=2))
        print(f"mining: {out / 'mining-report.json'}（候选 pending-manual-review，不自动入库）")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
