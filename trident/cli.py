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


def cigate_severities():
    from .core.cigate import SEVERITIES

    return SEVERITIES


def _json_arg(text: str | None, default=None):
    """JSON 字符串或 @文件 → Python 对象。"""
    if not text:
        return default
    raw = Path(text[1:]).read_text(encoding="utf-8") if text.startswith("@") else text
    return json.loads(raw)


def _session(ws: str, actor: str, role: str):
    from .core.users import Session

    return Session(None, actor, role, [ws], "cli-local")


def _print_json(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


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

    # ---- 执行/回滚/中止/报告/规则（终审 Minor#7）------------------------------
    runp = sub.add_parser("run", help="执行单个模块（授权+范围+备份闸门；拒绝退出码 91）")
    runp.add_argument("--module", required=True)
    runp.add_argument("--params", default="{}", help="JSON 字符串或 @file")
    runp.add_argument("--workspace", default="local-lab")
    runp.add_argument("--actor", default="cli")
    runp.add_argument("--role", choices=list(ROLES), default="tester")
    runp.add_argument("--run", default=None, help="复用既有 run（缺省新建）")
    runp.add_argument("--modules-dir", default=None)

    exq = sub.add_parser("execute", help="执行攻击链（--dry-run 只出计划；拒绝退出码 91）")
    exq.add_argument("--chain", required=True)
    exq.add_argument("--workspace", default="local-lab")
    exq.add_argument("--actor", default="cli")
    exq.add_argument("--role", choices=list(ROLES), default="tester")
    exq.add_argument("--dry-run", action="store_true")
    exq.add_argument("--strict", action="store_true", help="前置判定非「成立」即拒绝")
    exq.add_argument("--findings", default=None, help="既有发现 JSON 或 @file（前置判定输入）")
    exq.add_argument("--workers", type=int, default=4)
    exq.add_argument("--chains-dir", default=None)
    exq.add_argument("--modules-dir", default=None)

    rb = sub.add_parser("rollback", help="按步骤回滚（明细回执；failed>0 退出码 3）")
    rb.add_argument("--run", required=True)
    rb.add_argument("--step", required=True)
    rb.add_argument("--workspace", default="local-lab")

    ab = sub.add_parser("abort", help="工作区紧急停止：置位/清除（--clear）")
    ab.add_argument("--workspace", default="local-lab")
    ab.add_argument("--actor", default="cli")
    ab.add_argument("--reason", default="")
    ab.add_argument("--clear", action="store_true")

    rp = sub.add_parser("report", help="渲染双语报告（pentest|remediation）")
    rp.add_argument("--run", required=True)
    rp.add_argument("--kind", choices=["pentest", "remediation"], default="pentest")
    rp.add_argument("--lang", choices=["bi", "zh", "en"], default="bi")
    rp.add_argument("--redact", action="store_true", help="零日级细节可选脱敏")
    rp.add_argument("--disclosed", default=None, help="已披露标题 JSON 数组或 @file")
    rp.add_argument("--workspace", default="local-lab")
    rp.add_argument("--out", default=None)

    rl = sub.add_parser("rules", help="规则包 generate|validate（紫队覆盖率矩阵）")
    rlsub = rl.add_subparsers(dest="rcmd", required=True)
    rlg = rlsub.add_parser("generate")
    rlg.add_argument("--chains-dir", default=None)
    rlg.add_argument("--out", default=None)
    rlg.add_argument("--cni", choices=["native", "calico", "cilium", "vpc-native"], default="native")
    rlg.add_argument("--findings", default=None, help="演练发现 JSON 或 @file")
    rlv = rlsub.add_parser("validate")
    rlv.add_argument("--pack", default=None)
    rlv.add_argument("--mock-base", default=None)

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
    plan.add_argument("--record", action="store_true",
                      help="把推荐理由/选择写入 decisions 表（须有 run；只写决策不执行）")

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
    expl.add_argument("--workers", type=int, default=1,
                      help="已批准提议的并发执行数（1-8，默认 1；每动作独立 run）")
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

    llm = sub.add_parser("llm-pool", help="LLM 多模型池（默认关闭）：status|add|remove|enable|reset|health")
    llm.add_argument("action", choices=["status", "add", "remove", "enable", "disable", "reset",
                                        "health", "records", "models", "tokens"])
    llm.add_argument("--workspace", default="local-lab")
    llm.add_argument("--base-url", default="")
    llm.add_argument("--model", default="")
    llm.add_argument("--api-key-env", default="")
    llm.add_argument("--weight", type=int, default=1)
    llm.add_argument("--quota-requests", type=int, default=0)
    llm.add_argument("--quota-tokens", type=int, default=0)
    llm.add_argument("--id", default="")
    llm.add_argument("--usage", action="store_true", help="reset 时同时清用量")
    llm.add_argument("--actor", default="cli")
    llm.add_argument("--role", choices=list(ROLES), default="lead")

    nf = sub.add_parser("notify", help="通知渠道/事件规则/投递（默认关闭）")
    nf.add_argument("action", choices=["meta", "channels", "channels-add", "channels-test",
                                       "rules", "rules-add", "emit", "deliveries", "retry",
                                       "enable", "disable"])
    nf.add_argument("--workspace", default="local-lab")
    nf.add_argument("--kind", choices=["webhook", "slack", "email"], default="webhook")
    nf.add_argument("--name", default="")
    nf.add_argument("--config", default=None, help="渠道 config：JSON 字符串或 @文件")
    nf.add_argument("--event", default="finding.critical")
    nf.add_argument("--severity", default="info")
    nf.add_argument("--channels", default="", help="逗号分隔渠道 id")
    nf.add_argument("--payload", default=None, help="事件 payload：JSON 字符串或 @文件")
    nf.add_argument("--id", default="")
    nf.add_argument("--actor", default="cli")
    nf.add_argument("--role", choices=list(ROLES), default="lead")

    tpl = sub.add_parser("template", help="任务模板：list|add|from-run|get|plan|update|delete")
    tpl.add_argument("action", choices=["list", "add", "from-run", "get", "plan", "update", "delete"])
    tpl.add_argument("--workspace", default="local-lab")
    tpl.add_argument("--name", default="")
    tpl.add_argument("--chains", default=None, help="逗号分隔链 id")
    tpl.add_argument("--modules", default=None, help="逗号分隔模块键（无链模板）")
    tpl.add_argument("--params", default=None, help="参数预设 JSON 字符串或 @文件")
    tpl.add_argument("--run", default=None)
    tpl.add_argument("--id", default="")
    tpl.add_argument("--overrides", default=None)
    tpl.add_argument("--actor", default="cli")
    tpl.add_argument("--role", choices=list(ROLES), default="lead")

    cal = sub.add_parser("calendar", help="一次性测试窗口：list|add|pause|resume|remove|run-due|upcoming|events")
    cal.add_argument("action", choices=["list", "add", "pause", "resume", "remove", "run-due",
                                        "upcoming", "events"])
    cal.add_argument("--workspace", default="local-lab")
    cal.add_argument("--name", default="")
    cal.add_argument("--start", default=None, help="epoch 或 ISO 8601")
    cal.add_argument("--end", default=None)
    cal.add_argument("--chains", default=None)
    cal.add_argument("--id", default="")
    cal.add_argument("--days", type=int, default=14)
    cal.add_argument("--allow-past", action="store_true")
    cal.add_argument("--actor", default="cli")
    cal.add_argument("--role", choices=list(ROLES), default="lead")

    th = sub.add_parser("threads", help="run 内侧问：ask|reply|list|events|close|cancel|summary")
    th.add_argument("action", choices=["ask", "reply", "list", "events", "close", "cancel", "summary"])
    th.add_argument("--workspace", default="local-lab")
    th.add_argument("--run", default=None)
    th.add_argument("--subject", default="")
    th.add_argument("--body", default="")
    th.add_argument("--id", default="")
    th.add_argument("--reason", default="")
    th.add_argument("--resolution", default="")
    th.add_argument("--actor", default="cli")
    th.add_argument("--role", choices=list(ROLES), default="tester")

    gp = sub.add_parser("graph", help="图快照/差异/UI 数据：snapshot|list|diff|ui|neighbors")
    gp.add_argument("action", choices=["snapshot", "list", "diff", "ui", "neighbors"])
    gp.add_argument("--workspace", default="local-lab")
    gp.add_argument("--run", default=None)
    gp.add_argument("--label", default="")
    gp.add_argument("--id", default="")
    gp.add_argument("--base", default="")
    gp.add_argument("--head", default="")
    gp.add_argument("--node", default="")
    gp.add_argument("--actor", default="cli")
    gp.add_argument("--role", choices=list(ROLES), default="lead")

    bb = sub.add_parser("blackboard", help="跨 run 上下文黑板：list|context|pin-note|pin-finding|pin-assets|unpin")
    bb.add_argument("action", choices=["list", "context", "pin-note", "pin-finding",
                                       "pin-assets", "unpin"])
    bb.add_argument("--workspace", default="local-lab")
    bb.add_argument("--run", default=None)
    bb.add_argument("--title", default="")
    bb.add_argument("--text", default="")
    bb.add_argument("--ref", default="")
    bb.add_argument("--note", default="")
    bb.add_argument("--product", default="")
    bb.add_argument("--limit", type=int, default=20)
    bb.add_argument("--actor", default="cli")
    bb.add_argument("--role", choices=list(ROLES), default="lead")

    ci = sub.add_parser("ci-gate", help="CI 退出码契约：阈值判定 + 机器可读摘要")
    ci.add_argument("--workspace", default="local-lab")
    ci.add_argument("--run", required=True)
    ci.add_argument("--fail-on", default="high", choices=list(cigate_severities()))
    ci.add_argument("--baseline", default=None, help="基线 JSON（key 列表或 findings 对象）")
    ci.add_argument("--new-only", action="store_true")
    ci.add_argument("--allow-zeroday", action="store_true")
    ci.add_argument("--out", default=None)

    imp = sub.add_parser("import-scan", help="外部扫描器 JSON（Trivy/Syft/grype）→ findings")
    imp.add_argument("--workspace", default="local-lab")
    imp.add_argument("--run", required=True)
    imp.add_argument("--doc", required=True, help="扫描器 JSON 文件")
    imp.add_argument("--source", default="cli")

    cc = sub.add_parser("credcheck", help="fixture 驱动凭据有效性验证（不发网络）")
    cc.add_argument("--workspace", default="local-lab")
    cc.add_argument("--fixture", required=True)

    ctem = sub.add_parser("report-ctem", help="CTEM 五阶段报告叙事（只读）")
    ctem.add_argument("--workspace", default="local-lab")
    ctem.add_argument("--run", required=True)
    ctem.add_argument("--out", default=None, help="Markdown 输出路径（缺省 stdout）")

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
            if args.record:
                from .core.decisions import record_plan

                data["decisions"] = record_plan(_store(home, args.workspace), data,
                                                actor=args.actor)
        except (KeyError, ValueError) as exc:
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
                data = ex.execute(session, args.id, workers=args.workers)
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

    if args.cmd == "llm-pool":
        from .core.llmpool import LLMPool

        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        pool = LLMPool(store)
        try:
            if args.action == "status":
                data = pool.status()
            elif args.action == "add":
                data = pool.add_endpoint(session, base_url=args.base_url, model=args.model,
                                         api_key_env=args.api_key_env, weight=args.weight,
                                         quota_requests=args.quota_requests,
                                         quota_tokens=args.quota_tokens,
                                         endpoint_id=args.id)
            elif args.action == "remove":
                data = pool.remove_endpoint(session, args.id)
            elif args.action in ("enable", "disable"):
                data = pool.set_enabled(session, args.action == "enable")
            elif args.action == "reset":
                data = pool.reset(session, args.id, usage=args.usage)
            elif args.action == "records":
                data = {"records": pool.records()}
            elif args.action == "models":
                data = {"models": pool.models()}
            elif args.action == "tokens":
                data = pool.token_stats()
            else:
                data = pool.health_check(session)
        except (ValueError, PermissionError) as exc:
            print(f"trident llm-pool: {exc}", file=sys.stderr)
            return 2
        _print_json(data)
        return 0

    if args.cmd == "notify":
        from .core.notify import NotifyManager

        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        nm = NotifyManager(store)
        try:
            if args.action == "meta":
                data = nm.meta()
            elif args.action == "channels":
                data = {"channels": nm.list_channels(), "rules": nm.list_rules()}
            elif args.action == "channels-add":
                data = nm.add_channel(session, args.kind, args.name,
                                      _json_arg(args.config, {}), channel_id=args.id)
            elif args.action == "channels-test":
                data = nm.test_channel(session, args.id)
            elif args.action == "rules":
                data = {"rules": nm.list_rules()}
            elif args.action == "rules-add":
                channels = [c for c in args.channels.split(",") if c]
                data = nm.add_rule(session, args.event, channels,
                                   min_severity=args.severity, rule_id=args.id)
            elif args.action == "emit":
                if not session.can("execute"):
                    raise PermissionError(f"{session.name} 无 execute 权限")
                data = nm.emit(args.event, _json_arg(args.payload, {}),
                               severity=args.severity, actor=session.name)
            elif args.action == "deliveries":
                data = {"deliveries": nm.deliveries(event=args.event, limit=200)}
            elif args.action == "retry":
                data = nm.retry(session, args.id)
            else:
                data = nm.set_enabled(session, args.action == "enable")
        except (ValueError, PermissionError) as exc:
            print(f"trident notify: {exc}", file=sys.stderr)
            return 2
        _print_json(data)
        return 0

    if args.cmd == "template":
        from .core.templates import TemplateStore

        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        ts = TemplateStore(store, modules_dir=home / "modules")
        chains = [c for c in (args.chains or "").split(",") if c]
        modules = [m for m in (args.modules or "").split(",") if m]
        params = _json_arg(args.params, {})
        try:
            if args.action == "list":
                data = {"templates": ts.list()}
            elif args.action == "add":
                data = ts.add(session, name=args.name, chains=chains, params=params,
                              modules=modules, template_id=args.id)
            elif args.action == "from-run":
                data = ts.from_run(session, args.run or "", name=args.name,
                                   template_id=args.id)
            elif args.action == "get":
                data = ts.get(args.id)
            elif args.action == "plan":
                data = ts.instantiate(args.id, overrides=_json_arg(args.overrides, {}))
            elif args.action == "update":
                fields = {}
                if args.name:
                    fields["name"] = args.name
                if chains:
                    fields["chains"] = chains
                if modules:
                    fields["modules"] = modules
                if args.params:
                    fields["params"] = params
                data = ts.update(session, args.id, **fields)
            else:
                data = ts.delete(session, args.id)
        except (ValueError, PermissionError) as exc:
            print(f"trident template: {exc}", file=sys.stderr)
            return 2
        _print_json(data)
        return 0

    if args.cmd == "calendar":
        from .core.calendar import Calendar

        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        cal = Calendar(store, modules_dir=home / "modules")
        chains = [c for c in (args.chains or "").split(",") if c]
        try:
            if args.action == "list":
                data = {"windows": cal.list(), "due": [w["id"] for w in cal.due()]}
            elif args.action == "add":
                data = cal.add_window(session, name=args.name, start=args.start, end=args.end,
                                      chains=chains, window_id=args.id,
                                      allow_past=args.allow_past)
            elif args.action in ("pause", "resume"):
                data = (cal.pause if args.action == "pause" else cal.resume)(session, args.id)
            elif args.action == "remove":
                data = cal.remove(session, args.id)
            elif args.action == "run-due":
                data = cal.run_due(session)
            elif args.action == "upcoming":
                data = {"windows": cal.upcoming(days=args.days)}
            else:
                data = cal.event_calendar(days=args.days)
        except (ValueError, PermissionError) as exc:
            print(f"trident calendar: {exc}", file=sys.stderr)
            return 2
        _print_json(data)
        return 0

    if args.cmd == "threads":
        from .core.threads import Threads

        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        th = Threads(store)
        try:
            if args.action == "ask":
                data = th.ask(session, args.run or "", args.subject, args.body)
            elif args.action == "reply":
                data = th.reply(session, args.run or "", args.id, args.body)
            elif args.action == "list":
                data = {"threads": th.list_threads(args.run or None),
                        "summary": th.summary(args.run or None)}
            elif args.action == "events":
                data = th.events(args.run or "", args.id)
            elif args.action == "close":
                data = th.close(session, args.run or "", args.id, resolution=args.resolution)
            elif args.action == "cancel":
                data = th.cancel(session, args.run or "", args.id, reason=args.reason)
            else:
                data = th.summary(args.run or None)
        except (ValueError, PermissionError, KeyError) as exc:
            print(f"trident threads: {exc}", file=sys.stderr)
            return 2
        _print_json(data)
        return 0

    if args.cmd == "graph":
        from .core.graphsnap import GraphSnapshots

        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        gs = GraphSnapshots(store)
        try:
            if args.action == "snapshot":
                data = gs.snapshot(session, run=args.run, label=args.label)
            elif args.action == "list":
                data = {"snapshots": gs.list()}
            elif args.action == "diff":
                data = gs.diff(args.base, args.head)
            elif args.action == "ui":
                data = gs.ui_data(args.id)
            else:
                data = gs.neighbors(args.id, args.node)
        except (ValueError, PermissionError) as exc:
            print(f"trident graph: {exc}", file=sys.stderr)
            return 2
        _print_json(data)
        return 0

    if args.cmd == "blackboard":
        from .core.blackboard import Blackboard

        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        bb = Blackboard(store)
        try:
            if args.action == "list":
                data = {"entries": bb.list()}
            elif args.action == "context":
                data = bb.context()
            elif args.action == "pin-note":
                data = bb.pin_note(session, args.text, ref=args.ref, note=args.note)
            elif args.action == "pin-finding":
                data = bb.pin_finding(session, args.run or "", args.title, note=args.note)
            elif args.action == "pin-assets":
                data = {"pinned": bb.pin_assets(session, product=args.product,
                                                limit=args.limit, note=args.note)}
            else:
                data = bb.unpin(session, args.ref)
        except (ValueError, PermissionError) as exc:
            print(f"trident blackboard: {exc}", file=sys.stderr)
            return 2
        _print_json(data)
        return 0

    if args.cmd == "ci-gate":
        from .core.cigate import evaluate_run, write_summary

        store = _store(home, args.workspace)
        baseline = _json_arg(args.baseline, None) if args.baseline else None
        try:
            result = evaluate_run(store, args.run, {
                "fail_on": args.fail_on, "baseline": baseline,
                "fail_on_new_only": args.new_only,
                "allow_zeroday": args.allow_zeroday,
            })
        except ValueError as exc:
            print(f"trident ci-gate: {exc}", file=sys.stderr)
            return 1
        if args.out:
            write_summary(result, args.out)
        _print_json(result)
        return int(result["exit_code"])

    if args.cmd == "import-scan":
        from .core.importers import ingest

        try:
            doc = json.loads(Path(args.doc).read_text(encoding="utf-8"))
            result = ingest(_store(home, args.workspace), args.run, doc, source=args.source)
        except (OSError, ValueError) as exc:
            print(f"trident import-scan: {exc}", file=sys.stderr)
            return 2
        _print_json(result)
        return 0

    if args.cmd == "credcheck":
        from .core.credcheck import probe_plan, render_md, validate_file

        try:
            fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
            result = validate_file(args.fixture)
            result["probe_plan"] = probe_plan(fixture)
        except (OSError, ValueError) as exc:
            print(f"trident credcheck: {exc}", file=sys.stderr)
            return 2
        print(render_md(result))
        _print_json(result)
        return 0

    if args.cmd == "report-ctem":
        from .core.narrative import build, render_md

        try:
            report = build(_store(home, args.workspace), args.run)
        except (ValueError, KeyError) as exc:
            print(f"trident report-ctem: {exc}", file=sys.stderr)
            return 2
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(render_md(report), encoding="utf-8")
            print(f"report-ctem: {out}")
        else:
            print(render_md(report))
        return 0

    # ---- run / execute / rollback / abort / report / rules --------------------
    if args.cmd == "run":
        from .core.roe import ExecutionLocked
        from .core.runner import BackupGateRefused, run_module
        from .core.zeroday import ZerodayLocked

        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        try:
            params = _json_arg(args.params, {})
        except (OSError, ValueError) as exc:
            print(f"trident run: --params 解析失败：{exc}", file=sys.stderr)
            return 2
        mods_dir = Path(args.modules_dir) if args.modules_dir else home / "modules"
        try:
            run = store.open_run(args.run) if args.run else None
        except KeyError as exc:
            print(f"trident run: {exc}", file=sys.stderr)
            return 2
        try:
            result = run_module(store, session, args.module, params, mods_dir, run=run)
        except KeyError as exc:
            print(f"trident run: {exc}", file=sys.stderr)
            return 2
        except (ExecutionLocked, BackupGateRefused, ZerodayLocked, PermissionError) as exc:
            print(f"trident run: {exc}", file=sys.stderr)
            return 91
        _print_json(result)
        return 0

    if args.cmd == "execute":
        from .core.chains import PreconditionError, dry_run, execute, load_chains
        from .core.roe import ExecutionLocked
        from .core.runner import BackupGateRefused
        from .core.zeroday import ZerodayLocked

        chains_dir = Path(args.chains_dir) if args.chains_dir else home / "chains"
        if not chains_dir.exists():
            chains_dir = Path(__file__).resolve().parent / "chains"
        mods_dir = Path(args.modules_dir) if args.modules_dir else home / "modules"
        try:
            chains = load_chains(chains_dir)
        except ValueError as exc:
            print(f"trident execute: 链目录非法：{exc}", file=sys.stderr)
            return 2
        if args.chain not in chains:
            print(f"trident execute: 未知链 {args.chain}（{chains_dir}）", file=sys.stderr)
            return 2
        try:
            findings = _json_arg(args.findings, []) or []
        except (OSError, ValueError) as exc:
            print(f"trident execute: --findings 解析失败：{exc}", file=sys.stderr)
            return 2
        chain = chains[args.chain]
        if args.dry_run:
            _print_json(dry_run(chain, findings, mods_dir))
            return 0
        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        try:
            result = execute(chain, store, session, mods_dir, findings=findings,
                             workers=args.workers, strict=args.strict)
        except (PreconditionError, ExecutionLocked, BackupGateRefused, ZerodayLocked,
                PermissionError) as exc:
            print(f"trident execute: {exc}", file=sys.stderr)
            return 91
        _print_json(result)
        return 0 if result.get("ok") else 3

    if args.cmd == "rollback":
        from .core.backup import BackupManager

        store = _store(home, args.workspace)
        try:
            run = store.open_run(args.run)
        except KeyError as exc:
            print(f"trident rollback: {exc}", file=sys.stderr)
            return 2
        receipt = BackupManager(store, run).rollback(args.step)
        _print_json(receipt)
        return 0 if receipt["failed"] == 0 else 3

    if args.cmd == "abort":
        from .core.abort import abort_info, clear_abort, request_abort

        store = _store(home, args.workspace)
        doc = clear_abort(store, args.actor) if args.clear else request_abort(
            store, args.actor, args.reason)
        _print_json({"workspace": args.workspace, **doc, "state": abort_info(store)})
        return 0

    if args.cmd == "report":
        from .reports.render import render_pentest, render_remediation

        store = _store(home, args.workspace)
        try:
            disclosed = _json_arg(args.disclosed, None)
        except (OSError, ValueError) as exc:
            print(f"trident report: --disclosed 解析失败：{exc}", file=sys.stderr)
            return 2
        try:
            if args.kind == "remediation":
                text = render_remediation(store, args.run, lang=args.lang,
                                          disclosed=disclosed, redact_zeroday=args.redact)
            else:
                text = render_pentest(store, args.run, lang=args.lang,
                                      disclosed=disclosed, redact_zeroday=args.redact)
        except KeyError as exc:
            print(f"trident report: {exc}", file=sys.stderr)
            return 2
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            print(f"report: {out}（kind={args.kind}, lang={args.lang}）")
        else:
            print(text)
        return 0

    if args.cmd == "rules":
        from .rules.generate import RuleCoverageError, generate_all
        from .rules.validate import validate

        if args.rcmd == "generate":
            chains_dir = Path(args.chains_dir) if args.chains_dir else home / "chains"
            if not chains_dir.exists():
                chains_dir = Path(__file__).resolve().parent / "chains"
            out_dir = Path(args.out) if args.out else home / "reports" / "rules-pack"
            try:
                findings = _json_arg(args.findings, []) or []
            except (OSError, ValueError) as exc:
                print(f"trident rules: --findings 解析失败：{exc}", file=sys.stderr)
                return 2
            try:
                pack = generate_all(chains_dir, findings=findings, cni=args.cni,
                                    out_dir=out_dir)
            except (RuleCoverageError, ValueError, OSError) as exc:
                print(f"trident rules generate: {exc}", file=sys.stderr)
                return 2
            _print_json({"pack": str(out_dir), "rules": pack.total_rules,
                         "chains": pack.covered_chain_count, "files": len(pack.files)})
            return 0
        pack_dir = Path(args.pack) if args.pack else home / "reports" / "rules-pack"
        if not (pack_dir / "mapping.json").is_file():
            print(f"trident rules validate: 缺 {pack_dir / 'mapping.json'}", file=sys.stderr)
            return 2
        try:
            matrix = validate(pack_dir, mock_base=args.mock_base)
        except (ValueError, OSError, KeyError) as exc:
            print(f"trident rules validate: {exc}", file=sys.stderr)
            return 2
        _print_json(matrix)
        return 0 if matrix.get("ok") else 3

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
