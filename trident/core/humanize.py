"""高频错误的「人话」文案：发生了什么 / 为什么 / 怎么修。

设计约束（与 docs/HOW-TO-DESIGN-COMMERCIAL-AGENT.md 第九节一致）：
- CLI 默认不把 Python 堆栈甩给陌生用户；堆栈只在 ``TRIDENT_DEBUG=1`` 时出现；
- 每个错误有稳定错误码（E1xx 环境/系统 / E2xx 授权 / E3xx 备份与回滚 /
  E4xx 存储与对象 / E5xx 混沌编排 / E6xx API 客户端 / E7xx 试点与 kubeconfig /
  E8xx 计划任务 / E9xx 未知）；
- 文案必须给出可复制执行的修复命令，不能只说「请检查配置」；
- ``catalog()`` 返回 ≥30 类错误码目录（测试与文档的可数口径）。

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


# --------------------------------------------------------------------------- E5xx 混沌
# 混沌错误族自带稳定错误码（exc.trident_code），这里只负责渲染成人话。

_CHAOS_CODE_TITLES = {
    "E501": ("混沌实验被中止", "中止条件命中或外部中止信号（trident chaos abort）触发。"),
    "E502": ("稳态未满足，已拒绝注入", "实验开始前的稳态假设探测未全部成立。"),
    "E503": ("回滚后稳态未恢复", "自动回滚已执行，但稳态复测仍未通过。"),
}


def _chaos_error(exc: BaseException) -> HumanError | None:
    code = getattr(exc, "trident_code", None)
    if code not in _CHAOS_CODE_TITLES:
        return None
    title, why = _CHAOS_CODE_TITLES[code]
    return HumanError(
        code,
        title,
        _text(exc) or title,
        why + "混沌编排只作用于本地仿真靶场，不影响真实集群。",
        "先 trident chaos list 查看实验稳态要求；重跑：trident chaos run <实验id>；"
        "持续失败时把 chaos-runs/latest.json 与报错一起提交。"
        if code == "E502" else
        "重试：trident chaos run <实验id>（回滚动作会先执行）；"
        "查看报告：chaos-runs/latest.json 的 phases.rollback 字段。",
    )


# --------------------------------------------------------------------------- 错误码目录
# 「≥30 类」的可数口径：每组规则一条 representative 异常 → 稳定错误码。
# catalog() 供测试与文档断言（不参与运行时判定路径）。

_REPRESENTATIVE_FIXTURES: tuple[tuple[str, BaseException | dict], ...] = (
    ("E101", FileNotFoundError("kubeconfig: ~/.kube/config")),
    ("E102", ModuleNotFoundError("No module named 'zstandard'")),
    ("E103", OSError(10048, "address already in use")),
    ("E104", FileNotFoundError("bash")),
    ("E105", FileNotFoundError("missing.bin")),
    ("E106", {"kind": "RuntimeError", "msg": "Python 3.9 不满足 requires-python >=3.10"}),
    ("E107", OSError(errno.ENOSPC, "no space left on device")),
    ("E108", ConnectionRefusedError(10061, "connection refused")),
    ("E109", {"kind": "SSLError", "msg": "CERTIFICATE_VERIFY_FAILED"}),
    ("E110", TimeoutError("timed out after 30s")),
    ("E111", {"kind": "JSONDecodeError", "msg": "Expecting value: line 1 column 1"}),
    ("E201", {"kind": "ExecutionLocked", "msg": "consent 未签署"}),
    ("E202", {"kind": "ExecutionLocked", "msg": "授权级别不足：需要 利用验证"}),
    ("E203", {"kind": "ExecutionLocked", "msg": "目标不在授权范围内: 10.0.0.0/8"}),
    ("E204", {"kind": "ExecutionLocked", "msg": "时间窗已过期"}),
    ("E205", PermissionError("access is denied")),
    ("E206", ValueError("consent 字段缺失：level")),
    ("E207", {"kind": "QuickstartAbort", "msg": "向导取消"}),
    ("E208", ValueError("未知角色: superadmin")),
    ("E301", {"kind": "BackupGateRefused", "msg": "backup_targets 缺失"}),
    ("E302", KeyError("no-such-module")),
    ("E303", RuntimeError("回滚失败：sha256 不一致")),
    ("E401", FileNotFoundError("workspace run not found: r1")),
    ("E402", {"kind": "DemoRefused", "msg": "目录不安全"}),
    ("E403", {"kind": "DatabaseError", "msg": "file is not a database"}),
    ("E501", {"kind": "ChaosAbortSignalled", "msg": "中止"}),
    ("E502", {"kind": "ChaosSteadyStateError", "msg": "稳态未满足"}),
    ("E503", {"kind": "ChaosRollbackError", "msg": "回滚未恢复"}),
    ("E601", {"kind": "ApiError", "msg": "login required", "status": 401}),
    ("E602", {"kind": "ApiError", "msg": "workspace 越权", "status": 403}),
    ("E603", {"kind": "ApiError", "msg": "工作区授权未完成（consent 未签署）", "status": 423}),
    ("E701", {"kind": "PilotError", "msg": "kubeconfig 解析失败"}),
    ("E801", {"kind": "ScheduleError", "msg": "cron 表达式非法: 99 * * *"}),
    ("E900", RuntimeError("surprise")),
)


class _ApiError(Exception):
    """fixture：API 客户端错误（status + message）。"""

    def __init__(self, msg: str, status: int = 0):
        super().__init__(msg)
        self.status = status


def _materialize(spec: tuple[str, BaseException | dict]) -> BaseException:
    if not isinstance(spec, dict):
        return spec
    kind = spec["kind"]
    msg = spec.get("msg", "")
    if kind == "ApiError":
        cls = type("ApiError", (_ApiError,), {})
        return cls(msg, spec.get("status", 0))
    attrs: dict = {}
    if kind in ("ChaosAbortSignalled", "ChaosSteadyStateError", "ChaosRollbackError"):
        attrs["trident_code"] = {"ChaosAbortSignalled": "E501",
                                 "ChaosSteadyStateError": "E502",
                                 "ChaosRollbackError": "E503"}[kind]
    cls = type(kind, (Exception,), attrs)
    exc = cls(msg)
    if "errno" in spec:
        exc.errno = spec["errno"]  # type: ignore[attr-defined]
    return exc


def catalog() -> list[HumanError]:
    """错误码目录（人话化覆盖面的可数口径；测试与文档用）。"""
    seen: dict[str, HumanError] = {}
    for code, spec in _REPRESENTATIVE_FIXTURES:
        err = explain_exception(_materialize((code, spec)))
        seen[err.code] = err
    return [seen[c] for c in sorted(seen)]


def catalog_codes() -> list[str]:
    return [e.code for e in catalog()]


def _is_conn_refused(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
        return True
    if getattr(exc, "errno", None) in (errno.ECONNREFUSED,):
        return True
    if getattr(exc, "winerror", None) in (10061, 10054):
        return True
    low = _text(exc).lower()
    return ("connection refused" in low or "connection reset" in low
            or "actively refused" in low or "目标不可达" in low
            or "connection aborted" in low)


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    low = _text(exc).lower()
    return type(exc).__name__ in ("TimeoutError", "timeout", "URLError") and "timeout" in low \
        or "timed out" in low or "请求超时" in low


def _is_ssl_error(exc: BaseException) -> bool:
    low = _text(exc).lower()
    return "ssl" in type(exc).__name__.lower() or "certificate verify failed" in low \
        or "CERTIFICATE_VERIFY_FAILED" in _text(exc)


def _is_disk_full(exc: BaseException) -> bool:
    if getattr(exc, "errno", None) == errno.ENOSPC:
        return True
    if getattr(exc, "winerror", None) == 112:
        return True
    low = _text(exc).lower()
    return "no space left" in low or "磁盘空间不足" in low or "not enough disk" in low


def _is_bad_config(exc: BaseException) -> bool:
    if type(exc).__name__ in ("JSONDecodeError", "YAMLError", "ScannerError",
                              "ParserError", "YamlishError", "ConfigError"):
        return True
    low = _text(exc).lower()
    msg = _text(exc)
    return "expecting value" in low or ("解析失败" in msg and (
        "json" in low or "yaml" in low or "kubeconfig" in low or "配置" in msg))


def _is_old_python(exc: BaseException) -> bool:
    low = _text(exc).lower()
    msg = _text(exc)
    return "requires-python" in low or "python 版本" in low or ("python 3." in low and "不满足" in msg)


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

    # ---- E5xx 混沌编排（异常自带稳定错误码） ------------------------------
    chaos = _chaos_error(exc)
    if chaos is not None:
        return chaos

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

    # ---- E1xx 系统/网络（连接/超时/SSL/磁盘/配置/解释器版本） --------------
    if _is_timeout(exc):
        return HumanError(
            "E110",
            "请求超时",
            f"等待目标响应超时：{msg or 'timed out'}。",
            "目标服务响应慢或不可达（mock 靶场未启动 / kubectl 卡住 / 上游限流）。",
            "先确认目标进程存活：python -m trident doctor；"
            "调大 --timeout（如 trident pilot --timeout 120）后重试；"
            "持续超时请检查代理设置（NO_PROXY=127.0.0.1）。",
        )

    if _is_conn_refused(exc):
        return HumanError(
            "E108",
            "目标不可达（连接被拒绝/重置）",
            f"无法连接目标服务：{msg or 'connection refused'}。",
            "目标端口没有进程监听（服务未启动或已退出），或被防火墙/代理拦截。",
            "mock 模式先运行 python -m trident demo（自动起本地靶场）；"
            "已有靶场请检查 --target 端口；Windows 代理用户设置 NO_PROXY=127.0.0.1。",
        )

    if _is_ssl_error(exc):
        return HumanError(
            "E109",
            "SSL/TLS 证书校验失败",
            f"建立 HTTPS 连接时证书校验失败：{msg}。",
            "自签证书/企业代理重签的 CA 不在系统信任库，或时间偏差导致证书失效。",
            "企业内网 CA 先导入信任库（不要全局禁用校验）；"
            "测试环境可设 SSL_CERT_FILE 指向内部 CA 捆绑文件后重试。",
        )

    if _is_disk_full(exc):
        return HumanError(
            "E107",
            "磁盘空间不足",
            f"写入文件时磁盘已满：{msg or 'no space left on device'}。",
            "证据归档/报告/备份需要落盘；剩余空间不足会中断 run 并留下未完成目录。",
            "清理 --home 下的 chaos-runs/、reports/ 或临时目录后重试；"
            "Windows 查看占用：Get-PSDrive C；归档可迁移到其他盘（--home D:\\...）。",
        )

    if _is_bad_config(exc):
        return HumanError(
            "E111",
            "配置文件解析失败",
            f"JSON/YAML 配置无法解析：{msg}。",
            "文件不是合法 JSON/YAML（多余逗号、Tab 缩进、引号不闭合），或文件被截断。",
            "用编辑器打开报错行号检查语法；"
            "kubeconfig 校验可先跑 python -m trident onboard-cluster --dry-run；"
            "链/模块定义请对照 trident/chains/*.json 的格式。",
        )

    if _is_old_python(exc):
        return HumanError(
            "E106",
            "Python 版本过低",
            f"当前解释器不满足版本要求：{msg}。",
            "Trident 需要 Python ≥ 3.10（match 语法与 dataclass 特性）；3.8/3.9 无法运行。",
            "安装 Python 3.10+ 后重建环境：python -m pip install -e .；"
            "或使用 uv/pyenv 切换版本：uv python install 3.12。",
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

    # ---- E2xx 补充：consent 字段 / 角色 -----------------------------------
    if "未知角色" in msg:
        return HumanError(
            "E208",
            "未知角色",
            f"角色名不在角色矩阵中：{msg}。",
            "Trident 角色只有 admin/lead/tester/auditor 四种（能力位不同）；写错名字会在此处兜住。",
            "改用 --role admin|lead|tester|auditor；"
            "查看能力位：python -m trident user add --help。",
        )

    if "consent" in low and ("字段" in msg or "缺失" in msg):
        return HumanError(
            "E206",
            "授权书字段不完整",
            f"签署 consent 时缺少必填字段：{msg}。",
            "quickstart/API 签授权都要 level/范围/时间窗齐备；缺字段不会写入半份授权。",
            "交互式补签：python -m trident quickstart；"
            "API 调 /api/v1/consent/sign 时补齐 fields（level 必填）。",
        )

    # ---- E3xx 补充：回滚失败 ----------------------------------------------
    if "回滚失败" in msg or "rollback failed" in low:
        return HumanError(
            "E303",
            "回滚失败",
            f"从备份恢复目标文件失败：{msg}。",
            "备份快照与目标当前内容校验不一致（期间被其他进程改动），或快照损坏。",
            "查看 run 的 evidence 归档（tar 内含快照 sha256）人工比对；"
            "重跑该模块前先确认目标文件未被他人占用；必要时手工恢复备份文件。",
        )

    # ---- E4xx 补充：证据库损坏 --------------------------------------------
    if type(exc).__name__ == "DatabaseError" or "file is not a database" in low:
        return HumanError(
            "E403",
            "证据库文件损坏",
            f"SQLite 证据库无法读取：{msg}。",
            "evidence.db 被截断/非 SQLite 格式（拷贝中断、磁盘满、0 字节覆盖）。",
            "从归档层恢复：run 目录的 tar+SHA256 归档是最终事实源；"
            "或换新 run 重跑（python -m trident demo 验证环境正常）。",
        )

    # ---- E6xx API 客户端 ---------------------------------------------------
    api_status = getattr(exc, "status", None) or getattr(exc, "code", None)
    if api_status == 401 or "login required" in low or "invalid credentials" in low:
        return HumanError(
            "E601",
            "API 未登录或令牌失效",
            f"API 调用被拒（401）：{msg}。",
            "Bearer token 缺失/过期，或用户名密码错误；本地服务重启后旧 token 全部失效。",
            "重新登录拿 token：POST /api/login；"
            "MCP/脚本场景设置 TRIDENT_TOKEN；demo 工作区默认账号见 demo 输出。",
        )
    if api_status == 403 or "越权" in msg:
        return HumanError(
            "E602",
            "API 工作区越权",
            f"API 调用被拒（403）：{msg}。",
            "会话只授权了部分工作区；访问未授权 workspace 会被拒（多租户隔离）。",
            "用 users.json 中授权的工作区名重试；"
            "需要扩权由 admin 重建用户：python -m trident user add --role <角色>。",
        )
    if api_status == 423 or ("consent 未签署" in msg and api_status):
        return HumanError(
            "E603",
            "API 授权锁（423）",
            f"执行类 API 被授权闸门锁定：{msg}。",
            "该工作区 consent 未签署时，所有执行/写路径一律 423（与 CLI 同一把锁）。",
            "先签署授权：python -m trident quickstart 或 POST /api/v1/consent/sign；"
            "只读浏览不受此锁影响。",
        )

    # ---- E7xx / E8xx 集成与计划 -------------------------------------------
    if type(exc).__name__ == "PilotError" or "kubeconfig" in low and "解析" in msg:
        return HumanError(
            "E701",
            "kubeconfig / 试点输入不可用",
            f"试点模式输入校验失败：{msg}。",
            "kubeconfig 不是合法 YAML/JSON、缺 clusters/contexts/users 键，或合并后没有 context。",
            "先跑导入向导校验：python -m trident onboard-cluster --dry-run；"
            "离线场景改用 --snapshot（kubectl get 导出的 JSON）；"
            "多文件合并冲突项见输出的 inventory.conflicts。",
        )

    if type(exc).__name__ == "ScheduleError" or "cron" in low and "非法" in msg:
        return HumanError(
            "E801",
            "计划（cron/interval）非法",
            f"创建计划任务被拒：{msg}。",
            "cron 只接受 5 字段白名单表达式；interval 需为正整数秒；同名计划不可重复。",
            "合法示例：--cron '0 3 * * *'（每日 03:00）或 --interval 86400；"
            "查看现有计划：python -m trident schedule list。",
        )

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
