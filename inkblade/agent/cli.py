# -*- coding: utf-8 -*-
"""CLI surface for the event-sourced agent runtime."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..core.evidence import EvidenceStore
from ..core.users import ROLES, Session
from .objectives import objective_keys
from .probes import probe_status
from .runtime import AgentRuntimeError, BudgetExceeded


def register(subparsers) -> None:
    sp = subparsers.add_parser(
        "agent", help="事件溯源 agent：图黑板/调度/worker/协议/评测（run|resume|replay|status）")
    asub = sp.add_subparsers(dest="agent_cmd", required=True)

    run = asub.add_parser("run", help="一次授权后自主运行目标图")
    run.add_argument("--objective", choices=objective_keys(), default="cluster-takeover")
    run.add_argument("--probe", required=True, help="探针 id（agent/probes.json 或 reference）")
    run.add_argument("--llm", default="pool", help="池名、mock:<script.json> 或 deterministic")
    run.add_argument("--budget-tokens", type=int, default=20000)
    run.add_argument("--budget-steps", type=int, default=12)
    run.add_argument("--budget-actions", type=int, default=20)
    run.add_argument("--budget-seconds", type=int, default=900)
    run.add_argument("--allow-destructive", action="store_true",
                     help="RoE 全影响 + 备份闸门满足时自动执行写/危险动作")
    run.add_argument("--dry-run", action="store_true", help="只规划，不执行探针")
    run.add_argument("--mode", choices=["graph-swarm", "supervisor", "deterministic"],
                     default="graph-swarm")
    run.add_argument("--workers", type=int, default=1)
    run.add_argument("--workspace", default="local-lab")
    run.add_argument("--actor", default="lead")
    run.add_argument("--role", choices=list(ROLES), default="lead")
    run.add_argument("--modules-dir", default=None)
    run.add_argument("--probe-bin", default=None, help="Rust 探针二进制（rust-local）")
    run.add_argument("--probe-token-env", default="INKBLADE_PROBE_TOKEN")
    run.add_argument("--k8s-api", default=None, help="Kubernetes API（reference/lab 或已注入的探针上下文）")
    run.add_argument("--k8s-token", default=None, help="Kubernetes bearer token（仅 lab/显式授权）")
    run.add_argument("--allow-reference", action="store_true",
                     help="显式允许 reference 运行时（mock range）")
    run.add_argument("--start-token", default="", help="lead 一次性启动 token")
    run.add_argument("--yes", action="store_true", help="lead 显式启动确认")
    run.add_argument("--approval", choices=["auto", "manual"], default="auto",
                     help="默认 auto（无逐步审批）；manual 仅暂停写 intent")
    run.add_argument("--approve-writes", action="store_true",
                     help="manual 模式下显式批准写 intent（一次性）")
    run.add_argument("--propose-skill", action="store_true",
                     help="成功链提交 pending 技能（仍需 lead 批准）")
    run.add_argument("--coverage", action="store_true",
                     help="启用覆盖闭包引擎：优先未覆盖节点，未闭包不得宣称完成")
    run.add_argument("--coverage-doc", default=None,
                     help="闭包证明 Markdown 输出路径（可选）")
    run.add_argument("--run-id", default=None)
    run.add_argument("--json", action="store_true", default=True)

    resume = asub.add_parser("resume", help="从 durable journal/checkpoint 恢复")
    resume.add_argument("--run-id", default=None)
    resume.add_argument("--llm", default=None, help="覆盖模型池/mock 脚本")
    resume.add_argument("--probe", default=None)
    resume.add_argument("--workspace", default="local-lab")
    resume.add_argument("--actor", default="lead")
    resume.add_argument("--role", choices=list(ROLES), default="lead")
    resume.add_argument("--modules-dir", default=None)
    resume.add_argument("--allow-reference", action="store_true")
    resume.add_argument("--manual-approved", action="store_true")
    resume.add_argument("--json", action="store_true", default=True)

    replay = asub.add_parser("replay", help="零执行回放事件/图/预算")
    replay.add_argument("--run-id", default=None)
    replay.add_argument("--to-seq", type=int, default=None)
    replay.add_argument("--workspace", default="local-lab")

    status = asub.add_parser("status", help="图/预算/目标/日志状态")
    status.add_argument("--run-id", default=None)
    status.add_argument("--workspace", default="local-lab")

    trace = asub.add_parser("trace", help="决策轨迹（每步观察/决策/动作/证据）")
    trace.add_argument("--run-id", default=None)
    trace.add_argument("--limit", type=int, default=200)
    trace.add_argument("--workspace", default="local-lab")

    stop = asub.add_parser("stop", help="kill switch：停止指定 run")
    stop.add_argument("--run-id", default=None)
    stop.add_argument("--reason", default="operator stop")
    stop.add_argument("--workspace", default="local-lab")

    auth = asub.add_parser("authorize", help="lead 签发一次性启动 token")
    auth.add_argument("--objective", choices=objective_keys(), default="cluster-takeover")
    auth.add_argument("--allow-destructive", action="store_true")
    auth.add_argument("--budget-tokens", type=int, default=20000)
    auth.add_argument("--budget-steps", type=int, default=12)
    auth.add_argument("--budget-actions", type=int, default=20)
    auth.add_argument("--budget-seconds", type=int, default=900)
    auth.add_argument("--ttl-seconds", type=int, default=1800)
    auth.add_argument("--workspace", default="local-lab")
    auth.add_argument("--actor", default="lead")
    auth.add_argument("--role", choices=list(ROLES), default="lead")
    auth.add_argument("--note", default="")

    probes = asub.add_parser("probes", help="探针配置与 reference opt-in 状态")
    probes.add_argument("--workspace", default="local-lab")

    ev = asub.add_parser("eval", help="评测基座：deterministic / supervisor / graph-swarm")
    ev.add_argument("--suite", default="golden")
    ev.add_argument("--modes", default="deterministic,supervisor,graph-swarm")
    ev.add_argument("--out", default=None)
    ev.add_argument("--workspace", default="agent-eval")
    ev.add_argument("--json", action="store_true", default=True)

    relay = asub.add_parser("relay", help="跨集群中继：add|list|status")
    rsub = relay.add_subparsers(dest="relay_cmd", required=True)
    add = rsub.add_parser("add", help="注册一个目标集群（多 kubeconfig/context）")
    add.add_argument("--cluster-id", required=True)
    add.add_argument("--kubeconfig", default="")
    add.add_argument("--context", default="")
    add.add_argument("--api-server", default="")
    add.add_argument("--namespace", default="default")
    add.add_argument("--parent", default="", help="父 cluster_id（跨集群中继链）")
    add.add_argument("--roe-level", default="只读侦察")
    add.add_argument("--transport", default="kubectl",
                     choices=["kubectl", "sa-token", "exec"])
    add.add_argument("--fallback", default="",
                     help="逗号分隔的失败回退传输列表")
    add.add_argument("--proxy", action="append", default=[],
                     help="socks5://host:port（可重复）")
    add.add_argument("--budget-steps", type=int, default=0)
    add.add_argument("--budget-actions", type=int, default=0)
    add.add_argument("--force", action="store_true", help="更新已注册集群")
    add.add_argument("--workspace", default="local-lab")
    lst = rsub.add_parser("list", help="列出已注册集群")
    lst.add_argument("--workspace", default="local-lab")
    st = rsub.add_parser("status", help="中继/探针/缺口/预算状态")
    st.add_argument("--cluster-id", default=None)
    st.add_argument("--workspace", default="local-lab")

    cov = asub.add_parser("coverage", help="覆盖闭包：status|proof")
    csub = cov.add_subparsers(dest="coverage_cmd", required=True)
    cs = csub.add_parser("status", help="读取 run 的覆盖闭包证明")
    cs.add_argument("--run-id", default=None)
    cs.add_argument("--workspace", default="local-lab")
    cp = csub.add_parser("proof", help="导出 coverage-proof.json / Markdown")
    cp.add_argument("--run-id", default=None)
    cp.add_argument("--workspace", default="local-lab")
    cp.add_argument("--out", default=None, help="JSON 输出路径（默认 run 目录）")
    cp.add_argument("--markdown", default=None, help="Markdown 输出路径")


def dispatch(args, home: Path) -> int:
    if args.agent_cmd == "probes":
        store = EvidenceStore(home, workspace=args.workspace)
        print(json.dumps(probe_status(store), ensure_ascii=False, indent=2))
        return 0
    if args.agent_cmd == "relay":
        return _relay_cmd(args, home)
    if args.agent_cmd == "coverage":
        return _coverage_cmd(args, home)
    if args.agent_cmd == "authorize":
        return _authorize(args, home)
    if args.agent_cmd == "status":
        from .supervisor import AgentSupervisor

        data = AgentSupervisor.status(EvidenceStore(home, workspace=args.workspace),
                                      args.run_id)
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0
    if args.agent_cmd == "replay":
        from .supervisor import AgentSupervisor

        data = AgentSupervisor.replay(EvidenceStore(home, workspace=args.workspace),
                                      args.run_id, to_seq=args.to_seq)
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0
    if args.agent_cmd == "trace":
        from .runtime import AgentRuntime

        runtime = AgentRuntime.load(EvidenceStore(home, workspace=args.workspace),
                                    args.run_id)
        print(json.dumps({"run_id": runtime.run_id,
                          "events": runtime.trace(limit=args.limit)},
                         ensure_ascii=False, indent=2, default=str))
        return 0
    if args.agent_cmd == "stop":
        from .supervisor import AgentSupervisor

        data = AgentSupervisor.stop(EvidenceStore(home, workspace=args.workspace),
                                    args.run_id, reason=args.reason)
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0
    if args.agent_cmd == "eval":
        from .eval import run_cli_eval

        data = run_cli_eval(EvidenceStore(home, workspace=args.workspace),
                            suite=args.suite, modes=args.modes, out=args.out)
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0
    # run / resume
    store = EvidenceStore(home, workspace=args.workspace)
    session = Session(None, args.actor, args.role, [args.workspace], "cli-agent")
    try:
        from .supervisor import AgentSupervisor, resume_agent

        if args.agent_cmd == "resume":
            data = resume_agent(
                store, session, args.run_id, llm=args.llm, probe_id=args.probe,
                modules_dir=args.modules_dir,
                allow_reference=True if args.allow_reference else None,
                manual_approved=True if getattr(args, "manual_approved", False) else False)
        else:
            budgets = {
                "tokens": args.budget_tokens, "steps": args.budget_steps,
                "actions": args.budget_actions,
                "duration_ms": max(1, args.budget_seconds) * 1000,
            }
            probe_spec = None
            if args.probe_bin:
                probe_spec = {"kind": "rust-local", "binary": args.probe_bin,
                              "token_env": args.probe_token_env}
            k8s = None
            if getattr(args, "k8s_api", None):
                from ..tpl.backends import K8sShim

                k8s = K8sShim(api=args.k8s_api, token=args.k8s_token or "")
            supervisor_cls = AgentSupervisor
            coverage = None
            if getattr(args, "coverage", False):
                from .coverage import CoverageGraph, CoverageSupervisor

                coverage = CoverageGraph(objective=args.objective)
                supervisor_cls = CoverageSupervisor or AgentSupervisor
            sup = supervisor_cls.create(
                store, session, objective=args.objective, probe_id=args.probe,
                llm=args.llm, budgets=budgets, mode=args.mode,
                modules_dir=args.modules_dir, allow_destructive=args.allow_destructive,
                approval=args.approval, start_token=args.start_token,
                confirm=args.yes, dry_run=args.dry_run, workers=args.workers,
                probe_spec=probe_spec, k8s=k8s,
                allow_reference=True if args.allow_reference else None,
                propose_skills=args.propose_skill, run_id=args.run_id,
                manual_approved=bool(getattr(args, "approve_writes", False)),
                **({"coverage": coverage} if coverage is not None else {}))
            data = sup.run()
            doc_path = getattr(args, "coverage_doc", None)
            if coverage is not None and doc_path:
                from .coverage import render_markdown

                proof = data.get("coverage") or coverage.proof(
                    graph=sup.graph, objective=getattr(sup, "_base_objective", None),
                    budget=sup.scheduler.budget, run_id=sup.runtime.run_id,
                    stop_reason=data.get("status", ""))
                Path(doc_path).parent.mkdir(parents=True, exist_ok=True)
                Path(doc_path).write_text(
                    render_markdown(proof), encoding="utf-8")
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0
    except (BudgetExceeded, AgentRuntimeError) as exc:
        print(f"inkblade agent: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"inkblade agent: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


def _relay_cmd(args, home: Path) -> int:
    from .relay import RelayManager, relay_add, relay_list, relay_status
    from .coverage import CoverageGraph

    store = EvidenceStore(home, workspace=args.workspace)
    if args.relay_cmd == "add":
        fallback = [x for x in str(getattr(args, "fallback", "") or "").split(",")
                    if x.strip()]
        data = relay_add(
            store, cluster_id=args.cluster_id, kubeconfig=args.kubeconfig,
            context=args.context, api_server=args.api_server,
            namespace=args.namespace, parent_id=args.parent,
            roe_level=args.roe_level, transport=args.transport,
            fallback=fallback or None, proxies=args.proxy,
            budget_steps=args.budget_steps, budget_actions=args.budget_actions,
            force=args.force, coverage=CoverageGraph())
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0
    if args.relay_cmd == "list":
        data = relay_list(store, coverage=CoverageGraph())
    else:
        data = relay_status(store, cluster_id=args.cluster_id,
                            coverage=CoverageGraph())
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    return 0


def _coverage_cmd(args, home: Path) -> int:
    from .coverage import CoverageGraph, render_markdown
    from .runtime import AgentRuntime

    store = EvidenceStore(home, workspace=args.workspace)
    runtime = AgentRuntime.load(store, args.run_id)
    path = Path(runtime.dir) / "coverage-proof.json"
    if not path.is_file():
        print(f"inkblade agent coverage: run {runtime.run_id} 没有 coverage-proof.json",
              file=sys.stderr)
        return 2
    try:
        proof = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"inkblade agent coverage: {exc}", file=sys.stderr)
        return 2
    if args.coverage_cmd == "proof":
        out = Path(args.out) if args.out else path
        CoverageGraph.from_proof(proof).write_proof(out, proof=proof)
        if args.markdown:
            md_path = Path(args.markdown)
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(render_markdown(proof), encoding="utf-8")
        print(json.dumps({"path": str(out), "markdown": args.markdown or "",
                          "closed": bool(proof.get("closed")),
                          "stop_reason": proof.get("stop_reason"),
                          "gaps": proof.get("gaps") or []},
                         ensure_ascii=False, indent=2, default=str))
        return 0
    print(json.dumps({"run_id": runtime.run_id, "path": str(path),
                      "closed": bool(proof.get("closed")),
                      "success": bool(proof.get("success")),
                      "stop_reason": proof.get("stop_reason"),
                      "criteria": proof.get("criteria") or [],
                      "coverage": proof.get("coverage") or {},
                      "gaps": proof.get("gaps") or []},
                     ensure_ascii=False, indent=2, default=str))
    return 0


def _authorize(args, home: Path) -> int:
    from .policy import issue_start

    store = EvidenceStore(home, workspace=args.workspace)
    session = Session(None, args.actor, args.role, [args.workspace], "cli-agent")
    budgets = {"tokens": args.budget_tokens, "steps": args.budget_steps,
               "actions": args.budget_actions,
               "duration_ms": max(1, args.budget_seconds) * 1000}
    try:
        doc, token = issue_start(store, session, objective=args.objective,
                                 allow_destructive=args.allow_destructive,
                                 budgets=budgets, ttl_seconds=args.ttl_seconds,
                                 note=args.note)
    except Exception as exc:  # noqa: BLE001
        print(f"inkblade agent authorize: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({**doc, "token": token,
                      "note": "token 明文只显示一次；run 时传 --start-token"},
                     ensure_ascii=False, indent=2, default=str))
    return 0
