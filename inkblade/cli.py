"""InkBlade 命令行入口：python -m inkblade <子命令>。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.env import getenv, lookup
from .core.registry import load_modules
from .core.users import ROLES, UserStore

DEFAULT_HOME = Path(".")


def _store(home: Path, ws: str):
    from .core.evidence import EvidenceStore

    return EvidenceStore(home, workspace=ws)


def _modules_dir(home: Path, explicit: str | None = None) -> Path:
    """显式 --modules-dir 优先；否则工作区 modules/，再回落安装包内 inkblade/modules。"""
    if explicit:
        return Path(explicit)
    ws_modules = Path(home) / "modules"
    if ws_modules.exists():
        return ws_modules
    return Path(__file__).resolve().parent / "modules"


def _human_error(exc: BaseException, *, context: dict | None = None) -> None:
    """把异常渲染成三行式人话（错误码 + 发生了什么/为什么/怎么修）。"""
    from .core.humanize import format_error

    print(format_error(exc, context), file=sys.stderr)


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


def _inventory_for_cli(home: Path, explicit: str | None, *, required: bool = False):
    """读取 --inventory / 自动发现 inventory.json；显式路径错误必须报错，不静默降级。"""
    from .assess.inventory import InventoryError, default_inventory_path, load_inventory

    p = Path(explicit) if explicit else default_inventory_path(home)
    if p is None:
        if required:
            raise InventoryError(
                "缺少环境清单：先运行 inkblade assess inventory --kubeconfig <路径> "
                "或 --snapshot <快照>，再传 --inventory。"
            )
        return None, None
    return load_inventory(p), p


def _assessment_for_cli(home: Path, inventory_arg: str | None = None,
                        catalog_arg: str | None = None, *, required: bool = False):
    """链/模块执行前的适用性评估入口（无清单时返回 None，不阻断旧路径）。"""
    from .core.applicability import assess_cves

    inv, path = _inventory_for_cli(home, inventory_arg, required=required)
    if inv is None:
        return None, None
    return assess_cves(inv, catalog_path=catalog_arg), path


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _print_json(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def main(argv=None) -> int:
    """CLI 入口：未捕获异常统一转人话，堆栈仅在 INKBLADE_DEBUG=1 时暴露。"""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("\n已取消（Ctrl+C）。", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 —— 陌生用户默认不该看到堆栈
        if getenv("DEBUG") == "1":
            raise
        _human_error(exc)
        return 2


def legacy_main(argv=None) -> int:
    """已弃用的旧入口（``trident`` console script）：提示迁移后转交 ``inkblade``。"""
    print(
        "DEPRECATED: `trident` 是 InkBlade 的旧命令名，将在 0.3.0 移除；"
        "请改用 `inkblade`（或 `python -m inkblade`）。",
        file=sys.stderr,
    )
    return main(argv)


def _main(argv=None) -> int:
    import sys

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="inkblade", description="InkBlade ML-cluster pentest platform (authorized testing)")
    ap.add_argument("--home", default=".", help="工作区根目录（含 evidence/ modules/ users.json）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    from .probe.cli import register as _register_probe_cli

    _register_probe_cli(sub)

    sp = sub.add_parser("module", help="模块管理")
    msub = sp.add_subparsers(dest="mcmd", required=True)
    ml = msub.add_parser("list")
    ml.add_argument("--modules-dir", default=None)

    srf = sub.add_parser("surfaces", help="真实部署面矩阵：每模块 required_surfaces × 部署画像")
    srf.add_argument("--profile", required=True)
    srf.add_argument("--collect", default=None, help="inkblade collect 输出目录")
    srf.add_argument("--json", action="store_true")
    srf.add_argument("--out", default=None, help="写 .json/.md（按扩展名）")
    srf.add_argument("--fixture", action="store_true",
                     help="使用画像合成 fixture 数据；输出显式标注 fixture")
    srf.add_argument("--include-disabled", action="store_true",
                     help="把 default_enabled=false 的模块计入覆盖率分母（默认只展示不计入）")

    col = sub.add_parser("collect", help="只读采集链：k8s/http/files/hardware")
    col.add_argument("--profile", default=None, help="部署画像（fixture 模式必填）")
    col.add_argument("--out", default="collection")
    col.add_argument("--kubeconfig", default=None)
    col.add_argument("--context", default=None)
    col.add_argument("--kubectl", default="kubectl")
    col.add_argument("--skip-k8s", action="store_true")
    col.add_argument("--target", action="append", default=[], help="HTTP 端点（可重复）")
    col.add_argument("--files", action="append", default=[], help="配置/模型导出目录（可重复）")
    col.add_argument("--hardware", action="append", default=[], help="BMC/交换机导出目录（可重复）")
    col.add_argument("--timeout", type=int, default=45)
    col.add_argument("--http-timeout", type=float, default=8.0)
    col.add_argument("--insecure", action="store_true", help="跳过 TLS 校验（仅授权测试）")
    col.add_argument("--fixture", action="store_true",
                     help="显式 fixture 模式：从画像合成采集，报告标注 FIXTURE")

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
    runp.add_argument("--inventory", default=None,
                      help="环境清单；缺省自动发现 <home>/inventory.json")
    runp.add_argument("--catalog", default=None, help="CVE 目录路径")
    runp.add_argument("--profile", default=None, help="部署画像（启用真实面闸门）")
    runp.add_argument("--collect", default=None, help="采集链输出目录")
    runp.add_argument("--probe", action="store_true", help="显式确认 unknown 面已部署")
    runp.add_argument("--fixture", action="store_true", help="显式 fixture 数据（报告标注）")

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
    exq.add_argument("--inventory", default=None,
                     help="环境清单 inventory.json；缺省自动发现 <home>/inventory.json")
    exq.add_argument("--catalog", default=None, help="CVE 目录路径（缺省 inkblade/core/cve-catalog.json）")
    exq.add_argument("--profile", default=None, help="部署画像（启用真实面闸门）")
    exq.add_argument("--collect", default=None, help="采集链输出目录")
    exq.add_argument("--probe", action="store_true", help="显式确认 unknown 面已部署")
    exq.add_argument("--fixture", action="store_true", help="显式 fixture 数据")

    wep = sub.add_parser(
        "exploit",
        help="武器包一键入口：inkblade exploit <id>（默认干跑；--real 走 RoE/备份/面闸门）")
    wep.add_argument("id", nargs="?", help="武器包 id / 模块名 / 唯一前缀；省略时配合 --list")
    wep.add_argument("--list", action="store_true", help="列出全部武器包与就绪度")
    wep.add_argument("--real", action="store_true", help="真实执行（默认只输出干跑计划）")
    wep.add_argument("--target", default=None, help="目标 URL / 本地文件/模型目录")
    wep.add_argument("--params", default=None, help="附加参数 JSON 或 @file")
    wep.add_argument("--backup-target", action="append", default=[],
                     help="写模块备份目标（JSON 或路径）；写模块缺少即拒绝（91）")
    wep.add_argument("--workspace", default="local-lab")
    wep.add_argument("--actor", default="cli")
    wep.add_argument("--role", choices=list(ROLES), default="tester")
    wep.add_argument("--run", default=None, help="复用已有 run 目录")
    wep.add_argument("--modules-dir", default=None)
    wep.add_argument("--profile", default=None, help="部署画像（真实面闸门）")
    wep.add_argument("--probe", action="store_true", help="显式确认 unknown 面已部署")
    wep.add_argument("--fixture", action="store_true", help="显式 fixture 数据")

    obj = sub.add_parser("objective", help="目标链编排：三闸门/逐阶段确认/阶段超时/清理校验")
    objsub = obj.add_subparsers(dest="objective_cmd", required=True)
    oc = objsub.add_parser("cluster-takeover", help="内网入口→集群最高权限夺权证明（真实 K8s 或 fake-kubectl）")
    oc.add_argument("--workspace", default="local-lab")
    oc.add_argument("--actor", default="cli")
    oc.add_argument("--role", choices=list(ROLES), default="lead")
    oc.add_argument("--proof-marker", required=True)
    oc.add_argument("--namespace", default=None, help="目标命名空间（默认 inkblade-killchain）")
    oc.add_argument("--max-stage", type=int, default=7, help="只执行到第 N 阶段；随后强制清理")
    oc.add_argument("--stage-timeout", type=float, default=None, help="覆盖每阶段超时秒数")
    oc.add_argument("--auto-approve", action="store_true",
                    help="跳过逐阶段确认（仅限 level=全影响演示 且 role=lead）")
    oc.add_argument("--dry-run", action="store_true")
    oc.add_argument("--backend", choices=["auto", "kubectl", "fake"], default="auto",
                    help="auto=真 kubectl 不可用时降级 fake-kubectl 夹具")
    oc.add_argument("--kubectl", default="kubectl")
    oc.add_argument("--kubeconfig", default=None)
    oc.add_argument("--entry-url", default=None, help="入口 HTTP 探测 URL（默认由 NodePort 推导）")
    oc.add_argument("--pod-image", default="alpine:3.21")
    oc.add_argument("--cleanup-fixture", action="store_true",
                    help="同时删除实验室脆弱 operator 夹具（仅实验室使用）")
    oc.add_argument("--out", default=None, help="额外写出 proof.json 的路径")
    oc.add_argument("--report", default=None, help="写出双语 PROOF 报告 Markdown")
    oc.add_argument("--inventory", default=None,
                    help="环境清单 inventory.json（执行前 CVE 适用性依据）")
    oc.add_argument("--catalog", default=None, help="CVE 目录路径")

    ass = sub.add_parser("assess", help="CVE 适用性：inventory|cves|explain（版本×前置×实测）")
    asub = ass.add_subparsers(dest="acmd", required=True)
    ai = asub.add_parser("inventory", help="只读采集环境清单（kubectl get / 或 --snapshot）")
    ai.add_argument("--kubeconfig", default=None)
    ai.add_argument("--context", default=None)
    ai.add_argument("--snapshot", action="append", default=[],
                    help="离线快照 JSON（inventory/K8s 对象/pilot snapshot）")
    ai.add_argument("--probes", default=None, help="主动探测结果 JSON（IMDS/网络/认证等）")
    ai.add_argument("--kubectl", default="kubectl")
    ai.add_argument("--timeout", type=int, default=30, help="单条 kubectl 超时秒")
    ai.add_argument("--skip-kubelet-config", action="store_true",
                    help="跳过 nodes/proxy/configz（受限 RBAC 更快）")
    ai.add_argument("--out", default=None)
    ai.add_argument("--json", action="store_true", help="stdout 输出完整 JSON")
    ac = asub.add_parser("cves", help="四态判定：applicable|blocked|not-applicable|unknown")
    ac.add_argument("--inventory", default=None)
    ac.add_argument("--catalog", default=None)
    ac.add_argument("--probes", default=None)
    ac.add_argument("--out", default=None)
    ac.add_argument("--format", choices=["json", "md", "both"], default="json")
    ac.add_argument("--json", action="store_true", help="stdout 输出完整 JSON")
    ae = asub.add_parser("explain", help="人话解释单个 CVE：为什么/缺什么/怎么补采")
    ae.add_argument("cve")
    ae.add_argument("--inventory", default=None)
    ae.add_argument("--catalog", default=None)
    ae.add_argument("--json", action="store_true")

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
    rp.add_argument("--inventory", default=None,
                    help="漏洞适用性矩阵使用的环境清单；缺省自动发现")
    rp.add_argument("--catalog", default=None, help="CVE 目录路径")
    rp.add_argument("--profile", default=None, help="附加模块真实面覆盖章节")
    rp.add_argument("--collect", default=None, help="采集链输出目录")
    rp.add_argument("--fixture", action="store_true", help="报告标注 FIXTURE 数据")

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

    pr = sub.add_parser("privesc", help="提权矩阵/路径/检测：matrix|paths|infer|detections|report")
    prsub = pr.add_subparsers(dest="pcmd", required=True)
    prm = prsub.add_parser("matrix")
    prm.add_argument("--json", action="store_true")
    prm.add_argument("--out", default=None, help="写出 Markdown（如 docs/PRIVESC-MATRIX.md）")
    prp = prsub.add_parser("paths")
    prp.add_argument("--from", dest="from_principal", required=True)
    prp.add_argument("--to", default="cluster-admin")
    prp.add_argument("--limit", type=int, default=5)
    prp.add_argument("--mode", choices=["weight", "hops"], default="weight")
    prp.add_argument("--snapshot", default=None, help="集群快照 JSON")
    prp.add_argument("--run", default=None, help="从 evidence run 的 artifacts/归档读取快照")
    prp.add_argument("--workspace", default="local-lab")
    prp.add_argument("--json", action="store_true")
    prp.add_argument("--mermaid", action="store_true")
    pri = prsub.add_parser("infer")
    pri.add_argument("--snapshot", default=None)
    pri.add_argument("--run", default=None)
    pri.add_argument("--workspace", default="local-lab")
    pri.add_argument("--json", action="store_true")
    prd = prsub.add_parser("detections")
    prd.add_argument("--out", default=None)
    prr = prsub.add_parser("report")
    prr.add_argument("--from", dest="from_principal", required=True)
    prr.add_argument("--to", default="cluster-admin")
    prr.add_argument("--limit", type=int, default=5)
    prr.add_argument("--snapshot", default=None)
    prr.add_argument("--run", default=None)
    prr.add_argument("--workspace", default="local-lab")
    prr.add_argument("--out", default=None)

    u = sub.add_parser("user", help="用户管理")
    usub = u.add_subparsers(dest="ucmd", required=True)
    ua = usub.add_parser("add")
    ua.add_argument("name")
    ua.add_argument("password")
    ua.add_argument("role", choices=["admin", "lead", "tester", "auditor"])
    ua.add_argument("--workspaces", default="local-lab")

    uip = sub.add_parser("ui", help="启动本地 Web 控制台")
    uip.add_argument("--port", type=int, default=8765)
    uip.add_argument("--host", default="127.0.0.1",
                     help="绑定地址（默认 127.0.0.1；容器/反向代理后使用 0.0.0.0）")

    doc = sub.add_parser("doctor", help="环境自检：Python/写权限/端口/可选依赖/mock 或真集群")
    doc.add_argument("--port", type=int, default=8765, help="检查 Web UI 端口（默认 8765）")
    doc.add_argument("--mode", choices=["auto", "mock", "cluster"], default="auto",
                     help="auto=有 kubeconfig 则提示真集群，否则 mock；cluster=要求 kubeconfig")
    doc.add_argument("--kubeconfig", default=None, help="kubeconfig 路径（缺省 KUBECONFIG / ~/.kube/config）")
    doc.add_argument("--workspace", default="local-lab")
    doc.add_argument("--json", action="store_true", help="机器可读输出")

    dem = sub.add_parser("demo", help="一键 demo：mock 靶场→授权→2 模块+1 链→双语报告+规则包")
    dem.add_argument("--out", default="demo", help="输出目录（默认 ./demo；拒绝覆盖非 demo 目录）")
    dem.add_argument("--temp", action="store_true", help="改用系统临时目录（默认成功后清理）")
    dem.add_argument("--keep", action="store_true", help="保留 mock 靶场进程与临时目录（Ctrl+C 结束）")
    dem.add_argument("--no-ui", action="store_true", help="跳过静态 Web UI 导出")
    dem.add_argument("--workers", type=int, default=2, help="链步骤并发数（默认 2）")
    dem.add_argument("--json", action="store_true", help="机器可读摘要")

    qs = sub.add_parser("quickstart", help="5 问交互向导：目标/范围/级别/用户/签授权")
    qs.add_argument("--workspace-dir", default="inkblade-workspace",
                    help="工作区根目录（默认 ./inkblade-workspace）")
    qs.add_argument("--yes", action="store_true", help="全部使用默认值（CI/非交互）")
    qs.add_argument("--json", action="store_true", help="机器可读摘要")

    tr = sub.add_parser("trial", help="试用：离线 demo + 试用报告 + 下一步（无需集群）")
    tr.add_argument("--out", default="demo-trial", help="输出目录（默认 ./demo-trial）")
    tr.add_argument("--no-demo", action="store_true", help="只做环境检查，不跑离线 demo")
    tr.add_argument("--kubeconfig", default=None,
                    help="可选：有授权集群时用于生成 pilot 下一步提示（不会连接）")
    tr.add_argument("--json", action="store_true", help="机器可读试用报告")

    sdkp = sub.add_parser("sdk", help="插件 SDK：new|lint|validate|trust|run|list")
    sdkp.add_argument("sdk_args", nargs=argparse.REMAINDER,
                      help="透传给 inkblade.sdk 的子命令参数")

    pilot = sub.add_parser("pilot", help="试点模式：kubeconfig 只读清点→画像/热图/计划/审批清单")
    pilot.add_argument("--kubeconfig", action="append", default=[],
                       help="可重复；多文件/多 context/多 cluster 合并")
    pilot.add_argument("--context", action="append", default=[], help="只扫描指定 context（可重复）")
    pilot.add_argument("--snapshot", action="append", default=[],
                       help="离线归一化 snapshot JSON（可重复；本地 mock/客户先导采样）")
    pilot.add_argument("--out", default="reports/pilot", help="pilot-report/审批清单输出目录")
    pilot.add_argument("--format", choices=["json", "md", "both"], default="both")
    pilot.add_argument("--workspace", default="pilot")
    pilot.add_argument("--actor", default="pilot")
    pilot.add_argument("--role", choices=list(ROLES), default="auditor")
    pilot.add_argument("--allow-write", action="store_true", help="允许生成写计划（仍须授权+备份闸门）")
    pilot.add_argument("--kubectl", default="kubectl", help="kubectl 路径（只读 get）")
    pilot.add_argument("--timeout", type=int, default=30, help="单条 kubectl 超时秒")

    ent = sub.add_parser("enterprise", help="企业集成：适配器/审批/报告签核/保留策略/本地补验")
    ent.add_argument("action", choices=["adapters", "deliver", "sign-report", "retention",
                                        "signoff", "approval-list", "local-checks"])
    ent.add_argument("--workspace", default="local-lab")
    ent.add_argument("--run", default=None)
    ent.add_argument("--kind", choices=["splunk", "elastic", "webhook", "jira", "servicenow"],
                     default="splunk")
    ent.add_argument("--url", default="")
    ent.add_argument("--token", default="")
    ent.add_argument("--dry-run", action="store_true", default=True)
    ent.add_argument("--send", action="store_true", help="真实发送（缺省 dry-run）")
    ent.add_argument("--report", default=None)
    ent.add_argument("--signer", default="lead")
    ent.add_argument("--key-env", default="INKBLADE_REPORT_KEY")
    ent.add_argument("--dir", default=None)
    ent.add_argument("--retain-days", type=int, default=365)
    ent.add_argument("--out", default=None)

    mcp = sub.add_parser("mcp", help="MCP 只读服务器（stdio JSON-RPC）")
    mcp.add_argument("--workspace", default="local-lab")
    mcp.add_argument("--users", default=None, help="users.json（可选；配合 --token）")
    mcp.add_argument("--token", default=getenv("TOKEN"),
                     help="会话 token（默认取 INKBLADE_TOKEN；缺省为本机只读操作员）")
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
    plan.add_argument("--inventory", default=None,
                      help="环境清单；缺省自动发现 <home>/inventory.json")
    plan.add_argument("--catalog", default=None, help="CVE 目录路径")

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

    skl = sub.add_parser("sign-keyless", help="Sigstore keyless 签名（Fulcio+Rekor；无 OIDC 时 fixture 降级）")
    skl.add_argument("--artifact", required=True)
    skl.add_argument("--out", default=None)
    skl.add_argument("--identity-token-env", default="SIGSTORE_ID_TOKEN")
    skl.add_argument("--identity", default="fixture@inkblade.local")
    skl.add_argument("--issuer", default="https://fixture.inkblade.local")
    skl.add_argument("--offline-fixture", action="store_true",
                     help="强制本地 Fulcio/Rekor fixture（不使用 OIDC token）")
    skl.add_argument("--live-rekor-key-entry", action="store_true",
                     help="无 OIDC 时额外向公共 Rekor 上传 key-based hashedrekord（非 keyless）")
    skl.add_argument("--fulcio-url", default="https://fulcio.sigstore.dev")
    skl.add_argument("--rekor-url", default="https://rekor.sigstore.dev")
    skl.add_argument("--no-upload", action="store_true", help="live 模式只取 Fulcio 证书，不上传 Rekor")

    vkl = sub.add_parser("verify-keyless", help="校验 Sigstore keyless bundle（Fulcio 链/Rekor/SET/身份）")
    vkl.add_argument("--artifact", required=True)
    vkl.add_argument("--bundle", required=True)
    vkl.add_argument("--identity", default=None, help="SAN email/URI 精确匹配")
    vkl.add_argument("--identity-regex", default=None)
    vkl.add_argument("--issuer", default=None, help="Fulcio OIDC issuer")
    vkl.add_argument("--trust-bundle", default=None, help="Fulcio trustBundle JSON（缺省 bundle/内置缓存）")
    vkl.add_argument("--rekor-log", default=None)
    vkl.add_argument("--rekor-public-key", default=None, help="PEM 路径或 PEM 文本")
    vkl.add_argument("--online", action="store_true", help="在线重取 Rekor 条目比对")
    vkl.add_argument("--rekor-url", default="https://rekor.sigstore.dev")
    vkl.add_argument("--revoked-serial", action="append", default=[])
    vkl.add_argument("--out", default=None)

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

    expl = sub.add_parser("explore", help="审批制自主探索器：propose|list|approve|reject|execute|autonomy")
    expl.add_argument("--workspace", default="local-lab")
    expl.add_argument("action", choices=["propose", "list", "approve", "reject", "execute",
                                         "autonomy"])
    expl.add_argument("--id", default=None, help="提议 id（approve/reject/execute）")
    expl.add_argument("--use-llm", default=None, help="true/false（缺省：有 env 则用 LLM，失败降级 rules）")
    expl.add_argument("--llm", action="store_true",
                      help="L3：强制使用 core/llmpool 真实端点（无端点拒绝）")
    expl.add_argument("--autonomy", choices=["L3"], default=None,
                      help="L3 = lead 预授权自主循环（需 --preauth-token）")
    expl.add_argument("--preauth-token", default="", help="lead 预授权 token（autonomy grant 输出）")
    expl.add_argument("--max-steps", type=int, default=None, help="L3 最大步数（不得超过 grant）")
    expl.add_argument("--max-actions", type=int, default=5)
    expl.add_argument("--reason", default="")
    expl.add_argument("--workers", type=int, default=1,
                      help="已批准提议的并发执行数（1-8，默认 1；每动作独立 run）")
    expl.add_argument("--actor", default="cli")
    expl.add_argument("--role", choices=list(ROLES), default="lead")

    sup = sub.add_parser("supervisor", help="分层 worker 队列：run|status（可挂 L3 护栏）")
    sup.add_argument("--workspace", default="local-lab")
    sup.add_argument("action", choices=["run", "status"])
    sup.add_argument("--workers", type=int, default=2, help="并发 worker 数（1-8）")
    sup.add_argument("--autonomy", choices=["L3"], default=None)
    sup.add_argument("--llm", action="store_true", help="L3：强制真实 LLM 端点")
    sup.add_argument("--preauth-token", default="")
    sup.add_argument("--actor", default="cli")
    sup.add_argument("--role", choices=list(ROLES), default="lead")

    swm = sub.add_parser("swarm", help="角色化多进程 swarm：roles|run（recon/exploit/verify/report）")
    swm.add_argument("action", choices=["roles", "run"])
    swm.add_argument("--tasks", default=None, help="run：任务 JSON 列表文件")
    swm.add_argument("--workers", type=int, default=4, help="worker 数（1-16）")
    swm.add_argument("--executor", choices=["simulate", "runner"], default="simulate")
    swm.add_argument("--workspace", default="local-lab")
    swm.add_argument("--actor", default="lead")
    swm.add_argument("--role", choices=list(ROLES), default="lead")

    aut = sub.add_parser("autonomy", help="L3 预授权/状态/撤销/回放（lead 预授权 + 全审计）")
    aut.add_argument("action", choices=["levels", "grant", "status", "revoke", "replay"])
    aut.add_argument("--workspace", default="local-lab")
    aut.add_argument("--allowlist", default="", help="逗号分隔模块键（白名单）")
    aut.add_argument("--max-actions", type=int, default=5)
    aut.add_argument("--max-steps", type=int, default=3)
    aut.add_argument("--budget-tokens", type=int, default=20000)
    aut.add_argument("--budget-latency-ms", type=int, default=120000)
    aut.add_argument("--budget-approvals", type=int, default=6)
    aut.add_argument("--budget-interventions", type=int, default=2)
    aut.add_argument("--ttl-seconds", type=int, default=1800)
    aut.add_argument("--allow-writes", action="store_true")
    aut.add_argument("--note", default="")
    aut.add_argument("--trace", default=None, help="replay 指定 trace 路径（缺省工作区 trace）")
    aut.add_argument("--reason", default="")
    aut.add_argument("--actor", default="cli")
    aut.add_argument("--role", choices=list(ROLES), default="lead")

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
    mine.add_argument("--trainstack", action="store_true",
                      help="训练栈五目标（megatron,deepspeed,llamafactory,msswift,trl），独立基线")

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

    ch = sub.add_parser("chaos", help="混沌编排：list|run|abort（稳态→注入→中止→回滚→度量）")
    csub = ch.add_subparsers(dest="chaos_cmd", required=True)
    cl = csub.add_parser("list", help="实验目录（≥15：网络/DNS/fabric/GPU/节点/IO/内存/控制面/训练 ML）")
    cl.add_argument("--json", action="store_true", help="输出 JSON")
    cr = csub.add_parser("run", help="运行实验（默认自动拉起本地仿真靶场，仅 127.0.0.1）")
    cr.add_argument("ids", nargs="+", help="实验 id（chaos list 查看；可多个）")
    cr.add_argument("--mode", choices=["sequential", "parallel"], default="sequential")
    cr.add_argument("--parallel", type=int, default=3, help="并行模式最大并发")
    cr.add_argument("--every", type=float, default=0.0, help=">0 时定时循环：每 N 秒一轮")
    cr.add_argument("--cycles", type=int, default=1, help="定时循环轮数（配合 --every）")
    cr.add_argument("--target", action="append", default=[], metavar="NAME=URL",
                    help="覆盖目标地址（可重复，如 fabric-dos=http://127.0.0.1:8000）")
    cr.add_argument("--json-out", default=None, help="报告 JSON 追加写出路径")
    cr.add_argument("--workspace", default="chaos")
    ca = csub.add_parser("abort", help="中止运行中的混沌编排（写标记文件，编排器逐阶段轮询）")
    ca.add_argument("--reason", default="manual")

    obc = sub.add_parser("onboard-cluster", help="真实集群引导：kubeconfig 导入向导→pilot 一键只读画像")
    obc.add_argument("--kubeconfig", action="append", default=[], help="显式 kubeconfig（可重复；缺省自动发现）")
    obc.add_argument("--context", default=None, help="只扫描指定 context")
    obc.add_argument("--snapshot", action="append", default=[], help="离线 snapshot JSON（可重复；免 kubectl）")
    obc.add_argument("--out", default="reports/pilot", help="pilot 输出目录")
    obc.add_argument("--workspace", default="pilot-onboard")
    obc.add_argument("--actor", default="onboarding-wizard")
    obc.add_argument("--role", choices=list(ROLES), default="auditor")
    obc.add_argument("--kubectl", default="kubectl")
    obc.add_argument("--timeout", type=int, default=30)
    obc.add_argument("--yes", action="store_true", help="非交互（全部默认值）")
    obc.add_argument("--dry-run", action="store_true", help="只做发现/校验/选择，不跑 pilot")

    args = ap.parse_args(argv)
    home = Path(args.home)

    # ---- 上手三条命令（doctor / demo / quickstart）--------------------------
    if args.cmd in ("session", "probe", "channel"):
        from .probe.cli import dispatch as _dispatch_probe_cli

        return _dispatch_probe_cli(args, home)
    if args.cmd == "doctor":
        from .onboarding import doctor

        return doctor(home, port=args.port, mode=args.mode, kubeconfig=args.kubeconfig,
                      workspace=args.workspace, json_out=args.json)

    if args.cmd == "demo":
        from .onboarding import run_demo

        return run_demo(args.out, temp=args.temp, keep=args.keep, no_ui=args.no_ui,
                        json_out=args.json, workers=args.workers)

    if args.cmd == "quickstart":
        from .onboarding import run_quickstart

        return run_quickstart(args.workspace_dir, yes=args.yes, json_out=args.json)

    if args.cmd == "trial":
        from .trial import run_trial

        return run_trial(args.out, no_demo=args.no_demo, json_out=args.json,
                         kubeconfig=args.kubeconfig)

    if args.cmd == "sdk":
        from .sdk.__main__ import main as sdk_main

        return sdk_main(list(args.sdk_args or []))

    if args.cmd == "pilot":
        from .pilot import KubectlCollector, PilotError, PilotGateRefused, run_pilot

        if not args.kubeconfig and not args.snapshot:
            print("inkblade pilot: 需要 --kubeconfig 或 --snapshot", file=sys.stderr)
            return 2
        collector = (KubectlCollector(args.kubectl, timeout=args.timeout)
                     if args.kubeconfig and not args.snapshot else None)
        try:
            result = run_pilot(
                kubeconfigs=args.kubeconfig,
                snapshot_paths=args.snapshot,
                out_dir=args.out,
                workspace=args.workspace,
                actor=args.actor,
                role=args.role,
                allow_write=args.allow_write,
                store=_store(home, args.workspace) if args.allow_write else None,
                session=_session(args.workspace, args.actor, args.role) if args.allow_write else None,
                contexts=args.context,
                collector=collector,
            )
        except PilotGateRefused as exc:
            _human_error(exc, context={"workspace": args.workspace, "action": "inkblade pilot"})
            return 91
        except (PilotError, OSError, ValueError) as exc:
            print(f"inkblade pilot: {exc}", file=sys.stderr)
            return 2
        if args.format == "json":
            _print_json(result)
        elif args.format == "md":
            from .pilot import render_markdown

            print(render_markdown(result))
        else:
            _print_json({"out": str(args.out), "read_only": True,
                         "write_authorized": result["plan"]["write_authorized"],
                         "summary": result["summary"],
                         "manifest_sha256": result.get("outputs", {}).get("manifest_sha256"),
                         "report": str(Path(args.out) / "pilot-report.md")})
        return 0

    if args.cmd == "enterprise":
        from .core import jsonio
        from .enterprise import (
            ApprovalChain, ElasticBulk, JiraSink, ServiceNowSink, SplunkHEC,
            WebhookSink, create_signoff, retention_plan, sign_report,
        )

        try:
            if args.action == "adapters":
                _print_json({"adapters": [
                    {"kind": "splunk", "mode": "Splunk HEC", "default": "dry-run"},
                    {"kind": "elastic", "mode": "Elastic _bulk", "default": "dry-run"},
                    {"kind": "webhook", "mode": "HMAC webhook", "default": "dry-run"},
                    {"kind": "jira", "mode": "Jira REST issue", "default": "dry-run"},
                    {"kind": "servicenow", "mode": "ServiceNow incident", "default": "dry-run"},
                ], "boundary": "本地契约适配；真实客户环境需联调证书/代理/字段映射"})
                return 0
            if args.action == "approval-list":
                _print_json({"approvals": ApprovalChain(_store(home, args.workspace)).list()})
                return 0
            if args.action == "local-checks":
                from .enterprise.localcheck import run_local_checks

                target = Path(args.dir or "reports/samples/enterprise-local")
                doc = run_local_checks(target)
                _print_json({"summary": doc["summary"], "out": str(target),
                             "checks": [{"id": c["id"], "status": c["status"]}
                                        for c in doc["checks"]]})
                return 0 if doc["summary"]["ok"] else 1
            if args.action == "retention":
                if not args.dir:
                    print("inkblade enterprise: --dir 必填", file=sys.stderr)
                    return 2
                _print_json(retention_plan(Path(args.dir).glob("*"),
                                            retain_days=args.retain_days, legal_hold=False))
                return 0
            if args.action == "sign-report":
                if not args.report:
                    print("inkblade enterprise: --report 必填", file=sys.stderr)
                    return 2
                key = lookup(args.key_env, "")
                if not key:
                    print(f"inkblade enterprise: 缺少签名密钥环境变量 {args.key_env}", file=sys.stderr)
                    return 2
                _print_json(sign_report(args.report, signer=args.signer, key=key, out=args.out))
                return 0
            if args.action == "signoff":
                if not args.report:
                    print("inkblade enterprise: --report 必填", file=sys.stderr)
                    return 2
                key = lookup(args.key_env, "")
                if not key:
                    print(f"inkblade enterprise: 缺少签名密钥环境变量 {args.key_env}", file=sys.stderr)
                    return 2
                _print_json(create_signoff(
                    args.report,
                    signers=[{"name": args.signer, "role": "lead"},
                             {"name": "security-owner", "role": "security-owner"}],
                    checklist={k: True for k in ("scope", "evidence_manifest",
                                                 "findings_reviewed", "fp_fn_reviewed",
                                                 "data_handling", "rollback_verified")},
                    key=key, out=args.out))
                return 0
            if not args.run:
                print("inkblade enterprise: deliver 需要 --run", file=sys.stderr)
                return 2
            from .export import export_run

            doc = export_run(_store(home, args.workspace), args.run, "ocsf")
            if not args.url:
                print("inkblade enterprise: --url 必填", file=sys.stderr)
                return 2
            if args.kind in ("jira", "servicenow"):
                if not doc.get("events"):
                    print("inkblade enterprise: run 无 findings", file=sys.stderr)
                    return 2
                ev = doc["events"][0]
                finding = {"title": ev.get("finding_info", {}).get("title", ""),
                           "detail": ev.get("finding_info", {}).get("desc", ""),
                           "severity": str(ev.get("severity", "info")).lower(),
                           "step_key": (ev.get("finding_info", {}).get("analytic") or {}).get("uid", "")}
                payload = (JiraSink(args.url, token=args.token).build(finding, run=args.run)
                           if args.kind == "jira"
                           else ServiceNowSink(args.url, token=args.token).build(finding, run=args.run))
                _print_json({"adapter": args.kind, "dry_run": True,
                             "payload": jsonio.redact(payload)})
                return 0
            if args.kind == "splunk":
                adapter = SplunkHEC(args.url, args.token, index="inkblade")
            elif args.kind == "elastic":
                adapter = ElasticBulk(args.url, index="inkblade-findings", api_key=args.token)
            else:
                adapter = WebhookSink(args.url, secret=args.token)
            body = adapter.build_payload(doc)
            if args.send:
                _print_json(adapter.send(doc))
            else:
                print(body.decode("utf-8"))
            return 0
        except (ValueError, OSError, KeyError) as exc:
            print(f"inkblade enterprise: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "module" and args.mcmd == "list":
        mods_dir = _modules_dir(home, args.modules_dir)
        mods = load_modules(mods_dir)
        for key in sorted(mods):
            m = mods[key]
            state = "default" if m.default_enabled else "quarantined"
            print(f"{key}\t{m.series}\t{m.min_level}\t{'写' if m.writes else '读'}"
                  f"\t{state}\t{len(m.required_surfaces)}")
        return 0

    if args.cmd == "surfaces":
        from .core.surface import SurfaceContext, matrix, render_matrix_md

        try:
            profile = args.profile
            if args.fixture:
                ctx = SurfaceContext.build(profile=profile, fixture=True,
                                          enforce=True)
                doc = matrix(profile, collection=ctx.collection, probe=False)
                doc["fixture"] = True
                doc["mode"] = "fixture"
            else:
                doc = matrix(profile, collection=args.collect,
                             include_disabled=args.include_disabled)
        except (OSError, ValueError) as exc:
            print(f"inkblade surfaces: {exc}", file=sys.stderr)
            return 2
        text_md = render_matrix_md(doc)
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            if out.suffix.lower() == ".json":
                out.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
            else:
                out.write_text(text_md + "\n", encoding="utf-8")
            print(f"surfaces: {out} (profile={doc['profile']}, "
                  f"coverage={doc['summary']['coverage_pct']}%)")
        elif args.json:
            print(json.dumps(doc, ensure_ascii=False, indent=2))
        else:
            print(text_md)
        return 0

    if args.cmd == "collect":
        from .collect import collect_all, summarize, write_collection

        try:
            if args.fixture and not args.profile:
                raise ValueError("--fixture requires --profile")
            doc = collect_all(
                profile=args.profile, kubeconfig=args.kubeconfig, context=args.context,
                kubectl=args.kubectl, collect_k8s=not args.skip_k8s,
                targets=args.target, files_dirs=args.files, hardware_dirs=args.hardware,
                timeout=args.timeout, http_timeout=args.http_timeout,
                verify_tls=not args.insecure, fixture=args.fixture)
            path = write_collection(doc, args.out)
        except (OSError, ValueError) as exc:
            print(f"inkblade collect: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({"collection": str(path), **summarize(doc)},
                         ensure_ascii=False, indent=2))
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
        import socket

        from .webui.server import make_server

        # SO_REUSEADDR 在 Windows 上可能让第二个进程也 bind 成功，先显式探活端口
        bind_host = args.host
        if bind_host not in ("127.0.0.1", "localhost", "::1"):
            print(f"警告: Web 控制台绑定 {bind_host}，将对网络可达；仅在隔离网络或反向代理后使用。",
                  file=sys.stderr)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((bind_host, int(args.port)))
            except OSError as exc:
                raise OSError(10048, f"address already in use: {bind_host}:{args.port}") from exc
        users = UserStore(home / "users.json")
        httpd = make_server(home, users, host=bind_host, port=args.port)
        shown = "127.0.0.1" if bind_host in ("0.0.0.0", "::") else bind_host
        print(f"InkBlade 控制台: http://{shown}:{httpd.port} （Ctrl+C 退出）")
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
            print(f"inkblade mcp: {exc}", file=sys.stderr)
            return 2

    if args.cmd == "plan":
        from .agent_planner import plan_workspace, render_plan_md

        try:
            inventory, _ = _inventory_for_cli(home, args.inventory)
        except (OSError, ValueError) as exc:
            print(f"inkblade plan: 环境清单读取失败：{exc}", file=sys.stderr)
            return 2
        try:
            data = plan_workspace(
                _store(home, args.workspace), run=args.run,
                chains_dir=args.chains_dir, modules_dir=args.modules_dir,
                inventory=inventory, catalog_path=args.catalog,
            )
            if args.record:
                from .core.decisions import record_plan

                data["decisions"] = record_plan(_store(home, args.workspace), data,
                                                actor=args.actor)
        except (KeyError, ValueError) as exc:
            print(f"inkblade plan: {exc}", file=sys.stderr)
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
            print(f"inkblade sbom: {exc}", file=sys.stderr)
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
            print(f"inkblade verify-model: {exc}", file=sys.stderr)
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
            print(f"inkblade attest: {exc}", file=sys.stderr)
            return 2
        if args.out is None:
            print(json.dumps(verdict, ensure_ascii=False, indent=2))
        return 0 if verdict["ok"] else 2

    if args.cmd == "sign-keyless":
        from . import sigstore_keyless as sk

        try:
            artifact = Path(args.artifact).read_bytes()
            token = None if args.offline_fixture else lookup(args.identity_token_env)
            bundle = None
            fallback = ""
            if token:
                try:
                    bundle = sk.keyless_sign(
                        artifact, identity_token=token, fulcio_url=args.fulcio_url,
                        rekor_url=args.rekor_url, upload=not args.no_upload)
                except sk.SigstoreError as exc:
                    fallback = str(exc)
                    print(f"inkblade sign-keyless: live 失败，降级 fixture：{exc}", file=sys.stderr)
            if bundle is None:
                bundle = sk.keyless_sign(
                    artifact, identity=args.identity, issuer=args.issuer,
                    rekor_url=args.rekor_url, live_rekor_key_entry=args.live_rekor_key_entry)
            if fallback:
                bundle.setdefault("inkblade", {})["fallback_reason"] = fallback
            if args.out:
                Path(args.out).parent.mkdir(parents=True, exist_ok=True)
                Path(args.out).write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n",
                                          encoding="utf-8")
        except (OSError, ValueError) as exc:
            print(f"inkblade sign-keyless: {exc}", file=sys.stderr)
            return 2
        mode = (bundle.get("inkblade") or {}).get("mode", "unknown")
        if args.out is None:
            print(json.dumps(bundle, ensure_ascii=False, indent=2))
        else:
            print(f"sign-keyless: {args.out}（mode={mode}）")
        return 0

    if args.cmd == "verify-keyless":
        from . import sigstore_keyless as sk

        try:
            artifact = Path(args.artifact).read_bytes()
            bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
            verdict = sk.keyless_verify(
                artifact, bundle, identity=args.identity,
                identity_regex=args.identity_regex, issuer=args.issuer,
                trust_bundle=args.trust_bundle, rekor_log=args.rekor_log,
                rekor_public_key=args.rekor_public_key, online=args.online,
                rekor_url=args.rekor_url, revoked_serials=args.revoked_serial)
            if args.out:
                Path(args.out).parent.mkdir(parents=True, exist_ok=True)
                Path(args.out).write_text(json.dumps(verdict, ensure_ascii=False, indent=2) + "\n",
                                          encoding="utf-8")
        except (OSError, ValueError) as exc:
            print(f"inkblade verify-keyless: {exc}", file=sys.stderr)
            return 2
        if args.out is None:
            print(json.dumps(verdict, ensure_ascii=False, indent=2))
        else:
            print(f"verify-keyless: {args.out}（ok={verdict['ok']} mode={verdict['mode']}）")
        return 0 if verdict["ok"] else 2

    if args.cmd == "export":
        from .export import export_run, write_export

        try:
            doc = export_run(_store(home, args.workspace), args.run, args.format)
            write_export(doc, args.out)
        except KeyError as exc:
            print(f"inkblade export: {exc}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"inkblade export: {exc}", file=sys.stderr)
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
            print(f"inkblade discover: {exc}", file=sys.stderr)
            return 2
        payload = inv.graph() if args.graph else {"assets": inv.list(include_missing=True)}
        print(json.dumps({"diff": diff, **payload}, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "explore":
        from .core.autonomy import (AutonomyGuard, AutonomyRunner, ExplorerPlanner,
                                    SupervisorExecutor)
        from .core.explorer import ApprovalDenied, Explorer
        from .core.users import Session

        store = _store(home, args.workspace)
        session = Session(None, args.actor, args.role, [args.workspace], "cli-local")
        ex = Explorer(store, modules_dir=home / "modules")
        try:
            if args.autonomy:
                if args.action != "autonomy":
                    raise ValueError("--autonomy 须与 action=autonomy 一起使用")
                guard = AutonomyGuard.preflight(
                    store, token=args.preauth_token, llm_required=args.llm)
                runner = AutonomyRunner(
                    guard,
                    ExplorerPlanner(ex, session, llm=args.llm, max_actions=args.max_actions),
                    SupervisorExecutor(store, session, workers=args.workers,
                                       modules_dir=home / "modules"),
                    session=session, llm_requested=args.llm, max_steps=args.max_steps)
                data = runner.run()
            elif args.action == "propose":
                use_llm = True if args.llm else (
                    None if args.use_llm is None else args.use_llm == "true")
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
            print(f"inkblade explore: {exc}", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"inkblade explore: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0

    if args.cmd == "supervisor":
        from .core.supervisor import Supervisor
        from .core.users import Session

        store = _store(home, args.workspace)
        session = Session(None, args.actor, args.role, [args.workspace], "cli-local")
        try:
            if args.action == "status":
                sup = Supervisor(store, session, workers=args.workers,
                                 modules_dir=home / "modules")
                tasks = sup.tasks()
                data = {"tasks": tasks,
                        "summary": {"total": len(tasks),
                                    "pending": sum(1 for t in tasks if t["status"] == "pending"),
                                    "success": sum(1 for t in tasks if t["status"] == "success"),
                                    "failed": sum(1 for t in tasks if t["status"] == "failed")}}
            elif args.autonomy:
                from .core.autonomy import AutonomyGuard, run_supervisor_guarded

                guard = AutonomyGuard.preflight(store, token=args.preauth_token,
                                                llm_required=args.llm)
                data = run_supervisor_guarded(store, session, guard, workers=args.workers,
                                              modules_dir=home / "modules")
            else:
                sup = Supervisor(store, session, workers=args.workers,
                                 modules_dir=home / "modules")
                data = sup.run()
        except (PermissionError, ValueError) as exc:
            print(f"inkblade supervisor: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0

    if args.cmd == "swarm":
        from .core.swarm import ROLE_CAPS, Swarm
        from .core.users import Session

        if args.action == "roles":
            print(json.dumps({"roles": ROLE_CAPS,
                              "workers_range": [1, 16],
                              "note": "每角色上限 ≥2；4 worker = 每角色 1 个"}, ensure_ascii=False,
                             indent=2))
            return 0
        try:
            if not args.tasks:
                raise ValueError("--tasks 必填（JSON 列表）")
            tasks = json.loads(Path(args.tasks).read_text(encoding="utf-8"))
            if not isinstance(tasks, list):
                raise ValueError("tasks 须为 JSON 列表")
            session = Session(None, args.actor, args.role, [args.workspace], "cli-local")
            executor = {"kind": "simulate"}
            if args.executor == "runner":
                executor = {"kind": "runner", "home": str(home), "workspace": args.workspace,
                            "modules_dir": str(home / "modules"), "actor": args.actor,
                            "session_role": args.role}
            swarm = Swarm(workers=args.workers, executor=executor)
            try:
                data = swarm.run(tasks)
            finally:
                swarm.close()
        except (OSError, ValueError) as exc:
            print(f"inkblade swarm: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0

    if args.cmd == "autonomy":
        from .core.autonomy import (AUTONOMY_LEVELS, AutonomyGrant, AutonomyGuard,
                                    replay_trace)
        from .core.users import Session

        store = _store(home, args.workspace)
        session = Session(None, args.actor, args.role, [args.workspace], "cli-local")
        if args.action == "levels":
            print(json.dumps({"levels": AUTONOMY_LEVELS,
                              "guardrails": ["preauth-token", "allowlist", "budget-hard-cap",
                                             "anomaly-stop", "full-audit", "replayable-trace"]},
                             ensure_ascii=False, indent=2))
            return 0
        try:
            if args.action == "grant":
                modules = [m.strip() for m in (args.allowlist or "").split(",") if m.strip()]
                grant, token = AutonomyGrant.create(
                    store, session, allowlist=modules, max_actions=args.max_actions,
                    max_steps=args.max_steps,
                    budget={"tokens": args.budget_tokens,
                            "latency_ms": args.budget_latency_ms,
                            "approvals": args.budget_approvals,
                            "interventions": args.budget_interventions},
                    allow_writes=args.allow_writes, ttl_seconds=args.ttl_seconds,
                    note=args.note)
                data = {"grant": grant.public_doc(), "token": token,
                        "note": "token 明文只显示一次；落盘仅存 sha256 + HMAC"}
            elif args.action == "status":
                from .core.autonomy import AutonomyRefused

                try:
                    grant = AutonomyGrant.load(store)
                    data = {"active": True, "grant": grant.public_doc()}
                except AutonomyRefused as exc:
                    data = {"active": False, "reason": str(exc)}
            elif args.action == "revoke":
                data = AutonomyGrant.revoke(store, session, reason=args.reason)
            else:
                data = replay_trace(store, path=args.trace)
        except (PermissionError, ValueError) as exc:
            print(f"inkblade autonomy: {exc}", file=sys.stderr)
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
            print(f"inkblade schedule: {exc}", file=sys.stderr)
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
            print(f"inkblade traffic: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0

    if args.cmd == "mine":
        from .mining import TRAINSTACK_BASELINE_PATH, TRAINSTACK_TARGETS, run_pipeline

        out = Path(args.out) if args.out else home / "reports" / "samples" / "mining"
        targets = [t for t in (args.targets or "").split(",") if t] or None
        try:
            if args.trainstack:
                report = run_pipeline(out, targets=targets or list(TRAINSTACK_TARGETS),
                                      baseline_path=TRAINSTACK_BASELINE_PATH)
            else:
                report = run_pipeline(out, targets=targets)
        except ValueError as exc:
            print(f"inkblade mine: {exc}", file=sys.stderr)
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
            print(f"inkblade llm-pool: {exc}", file=sys.stderr)
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
            print(f"inkblade notify: {exc}", file=sys.stderr)
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
            print(f"inkblade template: {exc}", file=sys.stderr)
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
            print(f"inkblade calendar: {exc}", file=sys.stderr)
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
            print(f"inkblade threads: {exc}", file=sys.stderr)
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
            print(f"inkblade graph: {exc}", file=sys.stderr)
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
            print(f"inkblade blackboard: {exc}", file=sys.stderr)
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
            print(f"inkblade ci-gate: {exc}", file=sys.stderr)
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
            print(f"inkblade import-scan: {exc}", file=sys.stderr)
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
            print(f"inkblade credcheck: {exc}", file=sys.stderr)
            return 2
        print(render_md(result))
        _print_json(result)
        return 0

    if args.cmd == "report-ctem":
        from .core.narrative import build, render_md

        try:
            report = build(_store(home, args.workspace), args.run)
        except (ValueError, KeyError) as exc:
            print(f"inkblade report-ctem: {exc}", file=sys.stderr)
            return 2
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(render_md(report), encoding="utf-8")
            print(f"report-ctem: {out}")
        else:
            print(render_md(report))
        return 0

    if args.cmd == "chaos":
        from .chaos import EXPERIMENTS, ChaosOrchestrator, abort_active_run, list_experiments
        from .chaos.orchestrator import abort_reason_of, clear_abort

        if args.chaos_cmd == "list":
            items = list_experiments()
            if args.json:
                _print_json({"count": len(items), "experiments": items})
                return 0
            print(f"混沌实验目录（{len(EXPERIMENTS)} 个；仅本地仿真靶场，不碰真实集群）")
            for it in items:
                tag = " [ML 专属]" if it["ml_specific"] else ""
                print(f"  {it['id']:<38} {it['category']:<14}{tag} {it['title']}")
            return 0

        if args.chaos_cmd == "run":
            targets = {}
            for item in args.target:
                name, _, url = item.partition("=")
                if not url:
                    print(f"--target 需要 NAME=URL 形式，收到: {item}", file=sys.stderr)
                    return 2
                targets[name.strip()] = url.strip()
            clear_abort(home)
            orch = ChaosOrchestrator(home, targets=targets)
            report = orch.run(args.ids, mode=args.mode, max_parallel=args.parallel,
                              every_s=args.every, cycles=args.cycles)
            for r in report["results"]:
                impact = r.get("slo_impact") or {}
                if "outcome" in r and "phases" not in r:
                    print(f"[chaos] {r.get('id')}: {r.get('outcome')}（{r.get('detail', '')}）")
                    continue
                print(f"[chaos] {r['id']}: {r['outcome']}  "
                      f"degraded={impact.get('degraded')} recovered={impact.get('recovered')}  "
                      f"({r.get('duration_s', 0)}s)")
                if impact.get("abort_reason"):
                    print(f"          中止原因: {impact['abort_reason']}")
            s = report["summary"]
            print(f"汇总: {s['total']} 实验 · 稳态破坏并恢复 {s['steady_break_then_recover']} · "
                  f"回滚失败 {s['outcomes'].get('rollback_failed', 0)} · 报告 {report.get('report_path')}")
            if args.json_out:
                out = Path(args.json_out)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                               encoding="utf-8")
                print(f"报告已写出: {out}")
            return 0 if s.get("steady_break_then_recover", 0) or s.get("degraded", 0) else 1

        if args.chaos_cmd == "abort":
            doc = abort_active_run(home, args.reason)
            reason = abort_reason_of(home)
            print(f"已请求中止（原因: {reason}）。运行中的编排器将在当前阶段结束后回滚并退出。")
            _print_json(doc)
            return 0

    if args.cmd == "onboard-cluster":
        from .cluster_wizard import run_wizard

        return run_wizard(
            kubeconfigs=args.kubeconfig, context=args.context, snapshots=args.snapshot,
            out_dir=args.out, workspace=args.workspace, actor=args.actor, role=args.role,
            kubectl=args.kubectl, timeout=args.timeout, yes=args.yes, dry_run=args.dry_run,
            home=home,
        )

    if args.cmd == "assess":
        from .assess.inventory import (
            InventoryError, collect_inventory, inventory_summary, load_inventory,
            load_probes, merge_probes, normalize_inventory, save_inventory,
        )
        from .core.applicability import (
            ApplicabilityError, assess_cves, explain as explain_cve, render_matrix,
        )

        try:
            probes = load_probes(args.probes) if getattr(args, "probes", None) else {}
            if args.acmd == "inventory":
                if args.snapshot:
                    if len(args.snapshot) > 1:
                        raise InventoryError("assess inventory 一次只接受一个 --snapshot")
                    inv = load_inventory(args.snapshot[0])
                    if probes:
                        inv = merge_probes(inv, probes, source=args.snapshot[0])
                else:
                    inv = collect_inventory(
                        kubeconfig=args.kubeconfig, context=args.context,
                        kubectl=args.kubectl, timeout=args.timeout,
                        probes=probes,
                        collect_kubelet_config=not args.skip_kubelet_config,
                    )
                if args.out:
                    out = save_inventory(inv, args.out)
                    print(json.dumps({"inventory": str(out),
                                      **inventory_summary(inv)},
                                     ensure_ascii=False, indent=2))
                elif args.json:
                    _print_json(inv)
                else:
                    _print_json(inventory_summary(inv))
                return 0

            if args.acmd == "cves":
                inv, inv_path = _inventory_for_cli(home, args.inventory, required=True)
                if probes:
                    inv = merge_probes(inv, probes, source=str(inv_path))
                assessment = assess_cves(inv, catalog_path=args.catalog)
                text_json = json.dumps(assessment, ensure_ascii=False, indent=2)
                text_md = render_matrix(assessment)
                if args.out:
                    out = Path(args.out)
                    if out.is_dir() or (args.format == "both" and not out.suffix):
                        out.mkdir(parents=True, exist_ok=True)
                        base = out / "cve-applicability"
                        json_path = base.with_suffix(".json")
                        md_path = base.with_suffix(".md")
                    elif args.format == "both":
                        json_path = out.with_suffix(".json")
                        md_path = out.with_suffix(".md")
                    elif args.format == "md":
                        json_path = out.with_suffix(".json") if out.suffix else out / "cve-applicability.json"
                        md_path = out
                    else:
                        json_path = out
                        md_path = out.with_suffix(".md") if out.suffix else out / "cve-applicability.md"
                    if args.format == "both":
                        _write_text(json_path, text_json)
                        _write_text(md_path, text_md)
                        print(json.dumps({"json": str(json_path), "md": str(md_path),
                                          "summary": assessment["summary"]},
                                         ensure_ascii=False, indent=2))
                    elif args.format == "md":
                        _write_text(md_path, text_md)
                        print(json.dumps({"md": str(md_path),
                                          "summary": assessment["summary"]},
                                         ensure_ascii=False, indent=2))
                    else:
                        _write_text(json_path, text_json)
                        print(json.dumps({"json": str(json_path),
                                          "summary": assessment["summary"]},
                                         ensure_ascii=False, indent=2))
                elif args.format == "md":
                    print(text_md)
                else:
                    print(text_json)
                return 0

            # explain
            inv, _ = _inventory_for_cli(home, args.inventory)
            if inv is None:
                inv = normalize_inventory({})
            assessment = assess_cves(inv, catalog_path=args.catalog)
            if args.json:
                entry = next((e for e in assessment.get("entries") or []
                              if e["cve"].upper() == args.cve.upper()), None)
                if entry is None:
                    raise ApplicabilityError(f"目录中没有 {args.cve}")
                _print_json({"inventory": assessment.get("inventory"),
                             "catalog": assessment.get("catalog"), "entry": entry})
            else:
                print(explain_cve(assessment, args.cve))
            return 0
        except (InventoryError, ApplicabilityError, OSError, ValueError) as exc:
            print(f"inkblade assess: {exc}", file=sys.stderr)
            return 2

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
            print(f"inkblade run: --params 解析失败：{exc}", file=sys.stderr)
            return 2
        mods_dir = _modules_dir(home, args.modules_dir)
        try:
            assessment, _ = _assessment_for_cli(home, args.inventory, args.catalog)
        except (OSError, ValueError) as exc:
            print(f"inkblade run: CVE 适用性评估失败：{exc}", file=sys.stderr)
            return 2
        if assessment is not None:
            from .core.applicability import gate_module

            gate = gate_module(assessment, args.module)
            if gate.get("gated") and not gate.get("allow"):
                _print_json({"module": args.module, "status": "blocked",
                             "exit_code": 91, "applicability": gate})
                print(f"inkblade run: {args.module} 被 CVE 适用性闸门拒绝"
                      f"（{gate.get('state')}）：{'；'.join(gate.get('basis') or [])}",
                      file=sys.stderr)
                return 91
        try:
            run = store.open_run(args.run) if args.run else None
        except KeyError as exc:
            print(f"inkblade run: {exc}", file=sys.stderr)
            return 2
        sctx = None
        if args.profile or args.collect or args.probe or args.fixture:
            from .core.surface import SurfaceContext

            try:
                sctx = SurfaceContext.build(profile=args.profile, collection=args.collect,
                                            params=params, probe=args.probe,
                                            fixture=args.fixture, enforce=True)
            except (OSError, ValueError) as exc:
                print(f"inkblade run: {exc}", file=sys.stderr)
                return 2
        try:
            result = run_module(store, session, args.module, params, mods_dir, run=run,
                                surface_ctx=sctx)
        except KeyError as exc:
            _human_error(exc, context={"workspace": args.workspace})
            return 2
        except (ExecutionLocked, BackupGateRefused, ZerodayLocked, PermissionError) as exc:
            _human_error(exc, context={"workspace": args.workspace, "action": "inkblade run"})
            return 91
        _print_json(result)
        return 0

    if args.cmd == "exploit":
        from .core.roe import ExecutionLocked
        from .core.runner import BackupGateRefused
        from .core.weapon_runner import execute, plan
        from .core.weaponization import WeaponPackError, readiness, resolve

        mods_dir = _modules_dir(home, args.modules_dir)
        if args.list:
            data = readiness(modules_dir=mods_dir)
            _print_json({
                "reserve": {k: v for k, v in data["reserve"].items() if k != "components"},
                "exploit_registry": {k: v for k, v in data["exploit_registry"].items()
                                     if k != "components"},
                "combined": {k: v for k, v in data["combined"].items() if k != "components"},
                "components": data["combined"]["components"],
            })
            return 0
        if not args.id:
            print("inkblade exploit: 需要武器包 id（或 --list）", file=sys.stderr)
            return 2
        try:
            pack = resolve(args.id)
        except WeaponPackError as exc:
            print(f"inkblade exploit: {exc}", file=sys.stderr)
            return 2
        if not args.real:
            try:
                _print_json(plan(pack, modules_dir=mods_dir))
            except WeaponPackError as exc:
                print(f"inkblade exploit: {exc}", file=sys.stderr)
                return 2
            return 0
        try:
            params = _json_arg(args.params, {}) or {}
        except (OSError, ValueError) as exc:
            print(f"inkblade exploit: --params 解析失败：{exc}", file=sys.stderr)
            return 2
        if args.target:
            params["target"] = args.target
        backups = []
        for raw in args.backup_target:
            if raw.startswith("{"):
                try:
                    backups.append(json.loads(raw))
                    continue
                except ValueError:
                    pass
            backups.append({"path": raw})
        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        try:
            run = store.open_run(args.run) if args.run else None
        except KeyError as exc:
            print(f"inkblade exploit: {exc}", file=sys.stderr)
            return 2
        sctx = None
        if args.profile or args.probe or args.fixture:
            from .core.surface import SurfaceContext

            try:
                sctx = SurfaceContext.build(profile=args.profile, params=params,
                                            probe=args.probe, fixture=args.fixture,
                                            enforce=True)
            except (OSError, ValueError) as exc:
                print(f"inkblade exploit: {exc}", file=sys.stderr)
                return 2
        try:
            result = execute(pack, store, session, params, modules_dir=mods_dir,
                             backup_targets=backups, run=run, surface_ctx=sctx)
        except (ExecutionLocked, BackupGateRefused, PermissionError) as exc:
            _human_error(exc, context={"workspace": args.workspace, "action": "inkblade exploit"})
            return 91
        except WeaponPackError as exc:
            print(f"inkblade exploit: {exc}", file=sys.stderr)
            return 2
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
        mods_dir = _modules_dir(home, args.modules_dir)
        try:
            chains = load_chains(chains_dir)
        except ValueError as exc:
            print(f"inkblade execute: 链目录非法：{exc}", file=sys.stderr)
            return 2
        if args.chain not in chains:
            print(f"inkblade execute: 未知链 {args.chain}（{chains_dir}）", file=sys.stderr)
            return 2
        try:
            findings = _json_arg(args.findings, []) or []
        except (OSError, ValueError) as exc:
            print(f"inkblade execute: --findings 解析失败：{exc}", file=sys.stderr)
            return 2
        chain = chains[args.chain]
        try:
            assessment, _ = _assessment_for_cli(home, args.inventory, args.catalog)
        except (OSError, ValueError) as exc:
            print(f"inkblade execute: CVE 适用性评估失败：{exc}", file=sys.stderr)
            return 2
        sctx = None
        if args.profile or args.collect or args.probe or args.fixture:
            from .core.surface import SurfaceContext

            try:
                sctx = SurfaceContext.build(profile=args.profile, collection=args.collect,
                                            probe=args.probe, fixture=args.fixture,
                                            enforce=True)
            except (OSError, ValueError) as exc:
                print(f"inkblade execute: {exc}", file=sys.stderr)
                return 2
        if args.dry_run:
            _print_json(dry_run(chain, findings, mods_dir, applicability=assessment,
                                surface_ctx=sctx))
            return 0
        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        try:
            result = execute(chain, store, session, mods_dir, findings=findings,
                             workers=args.workers, strict=args.strict,
                             applicability=assessment, surface_ctx=sctx)
        except (PreconditionError, ExecutionLocked, BackupGateRefused, ZerodayLocked,
                PermissionError) as exc:
            _human_error(exc, context={"workspace": args.workspace, "action": "inkblade execute"})
            return 91
        _print_json(result)
        return 0 if result.get("ok") else 3

    if args.cmd == "objective":
        try:
            from .core.objective import (
                FakeKubectlBackend, GateRefused, KubectlBackend, load_objective,
                run_objective, write_report,
            )
        except ImportError:
            print("inkblade objective: kill-chain objective 模块在并行任务中（当前版本提供 "
                  "`inkblade privesc` 与 core.objective.plan_objective 提权选路）", file=sys.stderr)
            return 2

        chains_dir = home / "chains"
        if not chains_dir.exists():
            chains_dir = Path(__file__).resolve().parent / "chains"
        try:
            chain = load_objective(chains_dir)
        except (OSError, ValueError) as exc:
            print(f"inkblade objective: 链定义非法：{exc}", file=sys.stderr)
            return 2
        store = _store(home, args.workspace)
        session = _session(args.workspace, args.actor, args.role)
        backend = None
        if args.backend == "fake":
            backend = FakeKubectlBackend()
        elif args.dry_run:
            backend = KubectlBackend(args.kubectl, args.kubeconfig) if args.backend == "kubectl" \
                else FakeKubectlBackend()
        else:
            candidate = KubectlBackend(args.kubectl, args.kubeconfig)
            if candidate.readyz().get("ok"):
                backend = candidate
            elif args.backend == "kubectl":
                print("inkblade objective: kubectl 后端不可用（--backend kubectl 显式要求）",
                      file=sys.stderr)
                return 91
            else:
                backend = FakeKubectlBackend()
        try:
            assessment, _ = _assessment_for_cli(home, args.inventory, args.catalog)
        except (OSError, ValueError) as exc:
            print(f"inkblade objective: CVE 适用性评估失败：{exc}", file=sys.stderr)
            return 2
        try:
            result = run_objective(
                store, session, chain, backend,
                proof_marker=args.proof_marker, namespace=args.namespace,
                auto_approve=args.auto_approve, max_stage=args.max_stage,
                stage_timeout=args.stage_timeout,
                cleanup_fixture=args.cleanup_fixture,
                entry_url=args.entry_url, pod_image=args.pod_image,
                out_dir=args.out, dry_run=args.dry_run,
            )
        except GateRefused as exc:
            _human_error(exc, context={"workspace": args.workspace,
                                       "action": "inkblade objective"})
            return 91
        except (ValueError, OSError) as exc:
            print(f"inkblade objective: {exc}", file=sys.stderr)
            return 2
        if assessment is not None:
            from .core.applicability import gate_chain

            result["applicability"] = gate_chain(chain, assessment)
        if args.report and not result.get("dry_run"):
            write_report(result["proof"], args.report)
        _print_json(result)
        if result.get("dry_run"):
            return 0
        return 0 if result.get("ok") else 3

    if args.cmd == "rollback":
        from .core.backup import BackupManager

        store = _store(home, args.workspace)
        try:
            run = store.open_run(args.run)
        except KeyError as exc:
            _human_error(exc, context={"workspace": args.workspace})
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
            print(f"inkblade report: --disclosed 解析失败：{exc}", file=sys.stderr)
            return 2
        try:
            inventory, _ = _inventory_for_cli(home, args.inventory)
        except (OSError, ValueError) as exc:
            print(f"inkblade report: 环境清单读取失败：{exc}", file=sys.stderr)
            return 2
        try:
            if args.kind == "remediation":
                text = render_remediation(store, args.run, lang=args.lang,
                                          disclosed=disclosed, redact_zeroday=args.redact,
                                          inventory=inventory, catalog_path=args.catalog)
            else:
                text = render_pentest(store, args.run, lang=args.lang,
                                      disclosed=disclosed, redact_zeroday=args.redact,
                                      inventory=inventory, catalog_path=args.catalog)
        except KeyError as exc:
            _human_error(exc, context={"workspace": args.workspace})
            return 2
        if args.profile or args.collect:
            from .core.surface import SurfaceContext, report_section

            try:
                if args.fixture and not args.profile:
                    raise ValueError("--fixture requires --profile")
                sctx = SurfaceContext.build(profile=args.profile, collection=args.collect,
                                            fixture=args.fixture, enforce=True)
                text += "\n\n" + report_section(args.profile or sctx.profile_name,
                                                collection=sctx.collection)
            except (OSError, ValueError) as exc:
                print(f"inkblade report: {exc}", file=sys.stderr)
                return 2
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            print(f"report: {out}（kind={args.kind}, lang={args.lang}）")
        else:
            print(text)
        return 0

    if args.cmd == "privesc":
        from .core.privesc import (
            PrivescError,
            PrivescGraph,
            UnknownPrincipal,
            UnknownTarget,
            explain,
            infer_principals,
            load_matrix,
            load_snapshot,
            load_snapshot_from_evidence,
            matrix_summary,
            render_matrix_md,
            render_path_mermaid,
            render_privesc_section,
            validate_matrix,
        )

        matrix = load_matrix()
        if args.pcmd == "matrix":
            if args.out:
                out = Path(args.out)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(render_matrix_md(matrix), encoding="utf-8")
                print(f"privesc matrix: {out}（{len(matrix['vectors'])} 向量）")
                return 0
            if args.json:
                _print_json({"summary": matrix_summary(matrix), "vectors": matrix["vectors"]})
                return 0
            print(render_matrix_md(matrix))
            return 0
        if args.pcmd == "detections":
            from .rules.privesc import write_rule_pack

            out = Path(args.out) if args.out else home / "reports" / "rules-pack" / "privesc"
            summary = write_rule_pack(matrix, out)
            _print_json({"out": str(out), **summary})
            return 0 if summary.get("ok") else 3
        if args.pcmd == "infer":
            try:
                if args.run:
                    store = _store(home, args.workspace)
                    snapshot = load_snapshot_from_evidence(store, args.run)
                else:
                    snapshot = load_snapshot(args.snapshot) if args.snapshot else {}
            except (OSError, ValueError, KeyError, PrivescError) as exc:
                _human_error(exc, context={"action": "inkblade privesc infer"})
                return 2
            principals = infer_principals(snapshot)
            if args.json:
                _print_json({"principals": [p.to_dict() for p in principals],
                             "assets": len(snapshot.get("assets", []) or [])})
            else:
                for p in principals:
                    admin = " [cluster-admin]" if p.cluster_admin else ""
                    print(f"{p.id}{admin}  caps={', '.join(p.capabilities) or '-'}")
            return 0
        # paths / report
        try:
            if args.run:
                store = _store(home, args.workspace)
                snapshot = load_snapshot_from_evidence(store, args.run)
            elif args.snapshot:
                snapshot = load_snapshot(args.snapshot)
            else:
                raise PrivescError("paths 需要 --snapshot 或 --run（真实快照/证据）")
            graph = PrivescGraph(matrix, snapshot=snapshot)
            paths = graph.paths(args.from_principal, to=args.to,
                                limit=args.limit, mode=getattr(args, "mode", "weight"))
        except (OSError, ValueError, KeyError, PrivescError) as exc:
            _human_error(exc, context={"action": "inkblade privesc paths"})
            return 2
        if args.pcmd == "paths":
            if args.json:
                _print_json({
                    "from": args.from_principal,
                    "to": args.to,
                    "paths": [p.to_dict() for p in paths],
                    "explanation": explain(paths[0]) if paths else "",
                })
                return 0
            if args.mermaid:
                if not paths:
                    print("（无提权路径）", file=sys.stderr)
                    return 3
                print(render_path_mermaid(paths[0]))
                return 0
            if not paths:
                print(f"无到 {args.to} 的提权路径（主体 {args.from_principal}）", file=sys.stderr)
                return 3
            print(explain(paths[0]))
            if len(paths) > 1:
                print("\n备选路径：")
                for i, p in enumerate(paths[1:], 1):
                    print(f"  {i}. 权重 {p.weight:g} / {p.hops} 步：{' → '.join(p.vector_ids)}")
            return 0
        section = render_privesc_section(matrix, paths, principal=args.from_principal)
        text = "\n".join(section)
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, encoding="utf-8")
            print(f"privesc report: {out}")
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
                print(f"inkblade rules: --findings 解析失败：{exc}", file=sys.stderr)
                return 2
            try:
                pack = generate_all(chains_dir, findings=findings, cni=args.cni,
                                    out_dir=out_dir)
            except (RuleCoverageError, ValueError, OSError) as exc:
                print(f"inkblade rules generate: {exc}", file=sys.stderr)
                return 2
            privesc_summary = {}
            try:
                from .rules.privesc import write_rule_pack

                privesc_summary = write_rule_pack(out_dir=out_dir / "privesc")
                mapping_path = out_dir / "mapping.json"
                if mapping_path.is_file():
                    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
                    mapping["privesc"] = privesc_summary
                    mapping_path.write_text(json.dumps(mapping, ensure_ascii=False, indent=2),
                                            encoding="utf-8")
            except (OSError, ValueError) as exc:
                print(f"inkblade rules generate: 提权规则包失败：{exc}", file=sys.stderr)
                return 2
            _print_json({"pack": str(out_dir), "rules": pack.total_rules,
                         "chains": pack.covered_chain_count, "files": len(pack.files),
                         "privesc_rules": privesc_summary.get("rules", 0),
                         "privesc_ok": privesc_summary.get("ok", False)})
            return 0
        pack_dir = Path(args.pack) if args.pack else home / "reports" / "rules-pack"
        if not (pack_dir / "mapping.json").is_file():
            print(f"inkblade rules validate: 缺 {pack_dir / 'mapping.json'}", file=sys.stderr)
            return 2
        try:
            matrix = validate(pack_dir, mock_base=args.mock_base)
        except (ValueError, OSError, KeyError) as exc:
            print(f"inkblade rules validate: {exc}", file=sys.stderr)
            return 2
        try:
            from .rules.privesc import purple_replay

            privesc = purple_replay(strict=False)
            matrix["privesc"] = {"summary": {k: privesc[k] for k in
                                             ("vectors", "rules", "hit", "ok")},
                                 "missed": [m["vector"] for m in privesc["missed"]]}
            matrix["ok"] = bool(matrix.get("ok")) and bool(privesc["ok"])
        except (ValueError, OSError, KeyError) as exc:
            print(f"inkblade rules validate: 提权紫队重放失败：{exc}", file=sys.stderr)
            return 2
        _print_json(matrix)
        return 0 if matrix.get("ok") else 3

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
