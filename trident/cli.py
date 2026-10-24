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

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
