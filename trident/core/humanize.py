"""高频错误的「人话」文案：发生了什么 / 为什么 / 怎么修。

设计约束（与 docs/HOW-TO-DESIGN-COMMERCIAL-AGENT.md 第九节一致）：
- CLI 默认不把 Python 堆栈甩给陌生用户；堆栈只在 ``TRIDENT_DEBUG=1`` 时出现；
- 每个错误有稳定错误码（E1xx 环境 / E2xx 授权 / E3xx 备份 / E4xx 存储 / E9xx 未知）；
- 文案必须给出可复制执行的修复命令，不能只说「请检查配置」。

``explain_exception`` 只依赖异常类型、消息与可选上下文，不 import 重模块，
避免 CLI 在缺少可选依赖时二次失败。
"""

from __future__ import annotations

import errno
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HumanError:
    """一条可直接打印的人话错误。"""

    code: str
    title: str
    happened: str
    why: str
    fix: str
    doc: str = "docs/RUNBOOK.md"

    def lines(self) -> list[str]:
        return [
            f"[TRIDENT-{self.code}] {self.title}",
            f"发生了什么：{self.happened}",
            f"为什么：{self.why}",
            f"怎么修：{self.fix}",
        ]

    def __str__(self) -> str:
        out = "\n".join(self.lines())
        if self.doc:
            out += f"\n参考：{self.doc}"
        return out


def _ctx(context: dict[str, Any] | None, key: str, default: str = "") -> str:
    if not context:
        return default
    value = context.get(key)
    return str(value) if value not in (None, "") else default


def _text(exc: BaseException) -> str:
    try:
        return str(exc)
    except Exception:  # pragma: no cover - 极端异常对象的 __str__ 损坏
        return repr(exc)


def _is_auth(exc: BaseException) -> bool:
    return type(exc).__name__ in ("ExecutionLocked", "ZerodayLocked")


def _is_backup(exc: BaseException) -> bool:
    return type(exc).__name__ == "BackupGateRefused" or "备份回执" in _text(exc) \
        or "backup_targets" in _text(exc)


def _is_port_in_use(exc: BaseException) -> bool:
    if getattr(exc, "errno", None) == errno.EADDRINUSE:
        return True
    if getattr(exc, "winerror", None) in (10048, 10013):
        return True
    msg = _text(exc).lower()
    return "address already in use" in msg or "10048" in msg or "端口已被占用" in msg


def explain_exception(
    exc: BaseException,
    context: dict[str, Any] | None = None,
) -> HumanError:
    """把异常翻译成三行式人话；未知异常也返回可行动的建议。"""

    msg = _text(exc)
    low = msg.lower()
    workspace = _ctx(context, "workspace", "local-lab")
    path = _ctx(context, "path")
    port = _ctx(context, "port", "8765")
    m = re.search(r"127\.0\.0\.1:(\d+)", msg)
    if m:
        port = m.group(1)
    prefix = " ".join(filter(None, [_ctx(context, "action"), msg])).strip()

    # ---- demo / quickstart 自身的可预期拒绝 -------------------------------
    if type(exc).__name__ == "DemoRefused":
        return HumanError(
            "E402",
            "demo 无法安全开始",
            msg,
            "demo 默认只写 ./demo；输出目录已有非 demo 文件时拒绝覆盖，避免碰用户真实数据。",
            "换目录：python -m trident demo --out demo-2；"
            "或确认目录可清空后手动删除其中的旧文件再重跑。",
        )

    if type(exc).__name__ == "QuickstartAbort":
        return HumanError(
            "E207",
            "quickstart 未完成",
            msg,
            "向导在签署前被取消或输入不可用；此时不会留下半签授权（consent 仍为空/旧值）。",
            "在终端重跑 python -m trident quickstart；"
            "非交互场景加 --yes 使用默认值，或先跑 python -m trident demo。",
        )

    # ---- E1xx 环境 / 安装 -------------------------------------------------
    if _is_port_in_use(exc):
        return HumanError(
            "E103",
            f"端口 {port} 已被占用",
            f"启动本地服务时无法绑定 127.0.0.1:{port}（{msg or 'address already in use'}）。",
            "该端口已有其他程序在监听；Trident 不会抢占或杀掉别人的进程。",
            f"换一个端口：python -m trident ui --port {int(port) + 1 if str(port).isdigit() else 8766}；"
            "或先停止占用该端口的程序（Windows: netstat -ano | findstr :8765）。",
        )

    if isinstance(exc, FileNotFoundError):
        name = ""
        if getattr(exc, "filename", None):
            name = str(exc.filename)
        if "bash" in low or "bash" in name.lower():
            return HumanError(
                "E104",
                "找不到 bash",
                f"需要 bash 的步骤无法启动（{msg}）。",
                "Trident 核心、doctor、demo 和 mock 靶场都是纯 Python，不依赖 bash；"
                "只有 KIND / WSL / 部分 lab 脚本需要它。",
                "Windows 请安装 Git Bash 或 WSL2，并把 bash 加入 PATH；"
                "只想看 demo 可直接运行 python -m trident demo（无需 bash）。",
            )
        if "kubeconfig" in low or "kubeconfig" in name.lower() or _ctx(context, "kubeconfig"):
            kc = _ctx(context, "kubeconfig", name or "~/.kube/config")
            return HumanError(
                "E101",
                "找不到可用的 kubeconfig",
                f"无法读取真实集群凭据：{msg or kc}。",
                "真实集群模式需要 kubeconfig；demo 模式使用本地 mock，不需要集群凭据。",
                "设置 KUBECONFIG 环境变量或把 kubeconfig 放到 ~/.kube/config；"
                "然后运行 python -m trident doctor --mode cluster --kubeconfig <路径>。",
            )
        if "workspace" in low or "工作区" in msg or "run not found" in low:
            return HumanError(
                "E401",
                "工作区或 run 不存在",
                f"找不到请求的工作区/运行记录（{msg}）。",
                "工作区目录只在 demo/quickstart/首次执行后创建；拼错 --home/--workspace/--run 也会命中这里。",
                "先运行 python -m trident demo 建一个 demo 工作区；"
                f"或用 --home/--workspace 指向已存在的工作区（当前 workspace={workspace}）。",
            )
        return HumanError(
            "E105",
            "文件或目录不存在",
            f"找不到运行所需文件：{msg}。",
            "路径拼写、工作目录或安装包数据文件不完整。",
            "在仓库根目录重试；若已安装为 wheel，先 python -m pip install -e . 恢复数据文件；"
            "再运行 python -m trident doctor。",
        )

    # ---- E103 / E102：依赖与端口（部分平台抛 OSError 而非 FileNotFound）----
    if isinstance(exc, OSError) and _is_port_in_use(exc):
        return explain_exception(exc, {**context, "port": port})

    if isinstance(exc, (ModuleNotFoundError, ImportError)):
        name = getattr(exc, "name", "") or ""
        optional = name in ("zstandard", "cryptography", "psutil", "yaml")
        if optional:
            return HumanError(
                "E102",
                f"可选依赖 {name} 未安装",
                f"高级功能无法导入 {name}（{msg}）。",
                f"{name} 是可选增强：缺失时核心扫描、demo、报告仍可运行，只会降级（压缩/证书/采样）。",
                f"需要该能力时：python -m pip install {name}；否则忽略本提示，"
                "或运行 python -m trident doctor 查看降级说明。",
            )
        return HumanError(
            "E102",
            "Python 依赖缺失",
            f"导入模块失败：{msg}。",
            "当前 Python 环境不完整，或没有在仓库根目录安装 Trident。",
            "python -m pip install -e .；再运行 python -m trident doctor 确认。",
        )

    # ---- E2xx 授权 / 范围 / 权限 ------------------------------------------
    if _is_auth(exc):
        if "级别不足" in msg:
            return HumanError(
                "E202",
                "授权级别不足",
                f"模块要求更高的授权级别：{msg}。",
                "只读侦察级授权不能执行主动探测/利用验证/全影响演示模块；这是防止误改的硬闸门。",
                "用 python -m trident quickstart 重新签署更高级别授权（真实集群建议先只读）；"
                "或改用 trident module list 中「读」且级别更低的模块。",
            )
        if "不在授权范围" in msg or ("范围" in msg and "授权" in msg):
            return HumanError(
                "E203",
                "目标不在授权范围内",
                f"执行被范围闸门拒绝：{msg}。",
                "consent 只覆盖声明的 namespace / CIDR；params 里的 host/target_ns 必须落在其中。",
                "把目标 namespace/CIDR 加入授权后重签：python -m trident quickstart；"
                f"当前工作区：{workspace}。",
            )
        if "时间窗" in msg:
            return HumanError(
                "E204",
                "授权时间窗已过期或未开始",
                f"当前时间不在 consent 声明的时间窗内：{msg}。",
                "授权按时间窗失效，过期后所有执行路径都会拒绝（防止旧授权被复用）。",
                "用 python -m trident quickstart 重新签署（默认给 7 天窗口）；"
                "或联系授权人延期。",
            )
        return HumanError(
            "E201",
            "工作区尚未完成授权",
            f"执行被授权闸门拒绝：{msg or 'consent 未签署'}。",
            "Trident 只对已签署书面授权的资产执行；demo/quickstart 之前没有 consent.json。",
            "最快：python -m trident demo（自动签 demo 范围授权）。"
            f"真实集群：python -m trident quickstart --workspace-dir <目录>；"
            f"查看状态：python -m trident roe --workspace {workspace}。",
        )

    if isinstance(exc, PermissionError) or "access is denied" in low or "拒绝访问" in msg:
        return HumanError(
            "E205",
            "当前角色或系统权限不足",
            f"操作被权限校验拒绝：{msg}。",
            "Trident 角色矩阵（admin/lead/tester/auditor）或操作系统文件 ACL 不允许该动作。",
            "用有 execute 权限的 lead/tester 账号（--role tester --actor <名字>）；"
            "文件写权限问题请换 --home 到可写目录，或运行 python -m trident doctor 定位。",
        )

    # ---- E3xx 备份闸门 ----------------------------------------------------
    if _is_backup(exc):
        return HumanError(
            "E301",
            "写类模块缺少备份回执",
            f"写类模块在动手前被备份闸门拒绝：{msg}。",
            "写操作必须先声明 backup_targets 并成功生成快照；没有回执就不能保证可回滚。",
            "在 --params 里加 backup_targets，例如："
            '{"backup_targets":[{"kind":"file","path":"/tmp/target.conf"}]}；'
            "或改用 probe-only / 只读模块。demo 里有可复制的完整示例。",
        )

    # ---- E4xx / E3xx 存储与对象 ------------------------------------------
    if isinstance(exc, KeyError):
        key = msg.strip("'\"")
        if "run not found" in low or "run" in low:
            return HumanError(
                "E401",
                "找不到该 run",
                f"报告/回滚引用的 run 不存在：{key}。",
                "run 名称来自 evidence/<workspace>/<run>/；临时 demo 目录被清理后旧名称也会失效。",
                "先运行 python -m trident demo 生成 run；"
                "或检查 --home/--workspace/--run 是否与实际证据目录一致。",
            )
        return HumanError(
            "E302",
            "模块或链不存在",
            f"找不到请求的对象：{key}。",
            "模块/链键拼写错误，或 --modules-dir/--chains-dir 指向了空目录。",
            "python -m trident module list --modules-dir trident/modules 查看模块键；"
            "链定义在 trident/chains/*.json。",
        )

    if isinstance(exc, FileNotFoundError) and ("workspace" in low or "工作区" in msg):
        return HumanError(
            "E401",
            "工作区不存在",
            f"找不到工作区：{msg}。",
            "工作区尚未创建，或 --workspace 名称与 evidence/ 下的目录不一致。",
            "先运行 python -m trident demo（创建 demo 工作区），"
            "或用 --workspace 指定已存在的工作区。",
        )

    # ---- E9xx 兜底 --------------------------------------------------------
    return HumanError(
        "E900",
        "未预期的错误",
        f"{type(exc).__name__}: {msg or '（无消息）'}",
        "这是未归类的异常，通常意味着上游数据/环境与预期不符。",
        "设置 TRIDENT_DEBUG=1 重跑以查看堆栈；同时运行 python -m trident doctor，"
        "把这两段输出一起提交。",
    )


def format_error(err: HumanError | BaseException, context: dict[str, Any] | None = None) -> str:
    """便捷入口：传 HumanError 直接格式化，传异常则先翻译。"""
    if isinstance(err, HumanError):
        return str(err)
    return str(explain_exception(err, context))
