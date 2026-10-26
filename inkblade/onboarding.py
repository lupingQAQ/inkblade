"""零摩擦上手：doctor / demo / quickstart 的实现。

三条命令覆盖陌生用户的前 5 分钟：

- ``inkblade doctor``：环境自检，PASS/WARN/FAIL + 可复制修复命令；
- ``inkblade demo``：一条命令跑完「建 demo 工作区 → 建 lead/tester → 签 demo 授权
  → 起 mock 靶场 → 2 模块 + 1 链 → 双语报告 + 规则包」，默认只写 ``./demo``；
- ``inkblade quickstart``：5 问向导（目标/范围/级别/用户/签授权），失败可重入。

设计边界：demo 只监听 127.0.0.1、只用 mock/fixture、不读真实 kubeconfig、不写
``./demo`` 以外的用户数据；所有授权仍走 ``EvidenceStore.pin_roe`` 的真实签名路径。
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import secrets
import shutil
import socket
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

DEMO_WORKSPACE = "demo-lab"
DEMO_MARKER = ".inkblade-demo"
DEMO_CHAIN = "flat-network-admin-plane-weight-poison"
DEMO_LEVEL = "全影响演示"
LEVELS = ["只读侦察", "主动探测", "利用验证", "全影响演示"]
QUICKSTART_WORKSPACE = "local-lab"
DEFAULT_DEMO_PASSWORD = "demo-pass"


class DemoRefused(RuntimeError):
    """demo 前置条件不满足（目录不安全、链失败等），可直接人话化。"""


class QuickstartAbort(RuntimeError):
    """quickstart 用户取消或输入不可用；不留下半签授权。"""


# --------------------------------------------------------------------------- 公共小工具

def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _now_window(days: int = 7) -> dict[str, str]:
    now = datetime.now()
    return {
        "start": (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M"),
        "end": (now + timedelta(days=days)).strftime("%Y-%m-%d %H:%M"),
    }


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _ensure_utf8_stdio() -> None:
    """直接调用 onboarding 函数（非 CLI）时也保证中文可打印。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", int(port)))
            return True
        except OSError:
            return False


def _load_mock_module(repo: Path):
    path = repo / "lab" / "mock_targets.py"
    if not path.is_file():
        raise DemoRefused(
            "找不到 lab/mock_targets.py：demo 需要仓库内的本地 mock 靶场。"
            "请在完整仓库根目录运行，或重新克隆仓库。"
        )
    spec = importlib.util.spec_from_file_location("inkblade_lab_mock_targets", path)
    if spec is None or spec.loader is None:
        raise DemoRefused(f"无法加载 mock 靶场：{path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parse_namespaces(text: str) -> list[str]:
    items = [x.strip() for x in str(text or "").replace("，", ",").split(",")]
    items = [x for x in items if x]
    if not items:
        raise ValueError("namespace 不能为空（例：train,infer,default）")
    return items


def _parse_cidrs(text: str) -> list[str]:
    import ipaddress

    items = [x.strip() for x in str(text or "").replace("，", ",").split(",")]
    items = [x for x in items if x]
    if not items:
        raise ValueError("CIDR 不能为空（例：127.0.0.0/8）")
    out = []
    for item in items:
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError as exc:
            raise ValueError(f"CIDR 不合法：{item}（{exc}）") from exc
    return out


def _find_kubeconfig(explicit: str | None = None) -> Path | None:
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.is_file() else None
    candidates: list[Path] = []
    env = os.environ.get("KUBECONFIG", "")
    for part in env.split(os.pathsep):
        if part.strip():
            candidates.append(Path(part.strip()).expanduser())
    candidates.append(Path.home() / ".kube" / "config")
    for p in candidates:
        if p.is_file():
            return p
    return None


def _looks_like_kubeconfig(path: Path) -> tuple[bool, str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"无法读取 {path}：{exc}"
    if "server:" not in text:
        return False, f"{path} 里没有 server: 字段，不像是 kubeconfig"
    return True, ""


def _repo_dirs(repo: Path) -> tuple[Path, Path]:
    return repo / "inkblade" / "modules", repo / "inkblade" / "chains"


# --------------------------------------------------------------------------- doctor

def _item(cid: str, status: str, title: str, detail: str = "", fix: str = "") -> dict[str, Any]:
    return {"id": cid, "status": status, "title": title, "detail": detail, "fix": fix}


def doctor(
    home: str | Path = ".",
    *,
    port: int = 8765,
    mode: str = "auto",
    kubeconfig: str | None = None,
    workspace: str = QUICKSTART_WORKSPACE,
    json_out: bool = False,
) -> int:
    """环境自检；返回 0=无阻塞，1=有 FAIL。"""
    if mode not in ("auto", "mock", "cluster"):
        raise ValueError(f"mode 必须是 auto/mock/cluster，收到 {mode!r}")
    _ensure_utf8_stdio()
    repo = repo_root()
    home_path = Path(home)
    base = home_path if home_path.exists() else Path.cwd()
    items: list[dict[str, Any]] = []

    # 1) Python
    ver = ".".join(str(x) for x in sys.version_info[:3])
    if sys.version_info >= (3, 10):
        items.append(_item("python", "PASS", f"Python {ver}（>=3.10）", sys.executable))
    else:
        items.append(_item(
            "python", "FAIL", f"Python {ver} 过低",
            "InkBlade 需要 Python 3.10+。",
            "安装 Python 3.10+ 并用新解释器重跑：python -m inkblade doctor",
        ))

    # 2) 入口 / 包
    try:
        spec = importlib.util.find_spec("inkblade")
        pkg = getattr(spec, "origin", "") if spec else ""
        entry = shutil.which("inkblade")
        if entry:
            items.append(_item("entry", "PASS", "inkblade 命令可用", entry))
        else:
            items.append(_item(
                "entry", "WARN", "未检测到 inkblade 命令入口",
                "仍可用 python -m inkblade 运行。",
                "可选：python -m pip install -e . 后直接使用 inkblade 命令。",
            ))
    except Exception as exc:  # noqa: BLE001
        items.append(_item("entry", "FAIL", "无法导入 inkblade", str(exc),
                           "在仓库根目录重跑；或 python -m pip install -e ."))

    # 3) 写权限 + 磁盘
    probe = base / f".inkblade-doctor-{os.getpid()}-{secrets.token_hex(3)}"
    try:
        base.mkdir(parents=True, exist_ok=True)
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        items.append(_item("write", "PASS", "工作目录可写", str(base)))
    except OSError as exc:
        items.append(_item(
            "write", "FAIL", "工作目录不可写", f"{base}: {exc}",
            "换到可写目录：cd %TEMP% 或在命令里加 --home %TEMP%\\inkblade-workspace；"
            "Windows 请检查文件属性/杀软只读保护。",
        ))
    try:
        free_mb = shutil.disk_usage(base).free // (1024 * 1024)
        status = "PASS" if free_mb >= 200 else "WARN"
        items.append(_item(
            "disk", status, f"磁盘剩余 {free_mb} MB",
            "demo/证据/报告所需空间很小（<50MB）。" if free_mb >= 200 else "空间偏低。",
            "" if free_mb >= 200 else "清理磁盘或换 --home/--out 到空间更大的盘。",
        ))
    except OSError as exc:
        items.append(_item("disk", "WARN", "无法读取磁盘余量", str(exc), "忽略；不影响 demo。"))

    # 4) 端口
    if int(port) > 0:
        if _port_free(port):
            items.append(_item("port", "PASS", f"端口 {port} 可用（Web UI）",
                               "mock 靶场使用随机端口，不会占用该端口。"))
        else:
            items.append(_item(
                "port", "FAIL", f"端口 {port} 已被占用",
                "Web UI 无法绑定 127.0.0.1:%d。" % int(port),
                f"换端口：python -m inkblade ui --port {int(port) + 1}；"
                f"或停止占用进程（Windows: netstat -ano | findstr :{int(port)}）。",
            ))

    # 5) 可选依赖
    optional = [
        ("zstandard", "证据归档 zstd 压缩（缺失时自动用 gzip）"),
        ("cryptography", "TEE/证书高级校验（缺失时 fixture 校验仍可用）"),
        ("psutil", "bench 内存采样（缺失时用系统 API 降级）"),
    ]
    missing = []
    for mod, purpose in optional:
        if importlib.util.find_spec(mod) is None:
            missing.append((mod, purpose))
    if missing:
        items.append(_item(
            "optional", "WARN", "可选依赖未安装（核心不受影响）",
            "；".join(f"{m}: {p}" for m, p in missing),
            "按需安装：python -m pip install " + " ".join(m for m, _ in missing) + "；"
            "不装也能跑 demo/doctor/报告。",
        ))
    else:
        items.append(_item("optional", "PASS", "可选依赖齐全", "zstandard / cryptography / psutil 均可导入。"))

    # 6) mock 靶场 / 模块 / 链
    mock_path = repo / "lab" / "mock_targets.py"
    modules_dir, chains_dir = _repo_dirs(repo)
    mock_ok = mock_path.is_file()
    data_ok = modules_dir.is_dir() and chains_dir.is_dir()
    if mock_ok and data_ok:
        items.append(_item("mock", "PASS", "本地 mock 靶场与数据文件就绪",
                           f"{mock_path}；{len(list(modules_dir.glob('*/module.json')))} 个模块"))
    else:
        miss = []
        if not mock_ok:
            miss.append("lab/mock_targets.py")
        if not modules_dir.is_dir():
            miss.append("inkblade/modules")
        if not chains_dir.is_dir():
            miss.append("inkblade/chains")
        items.append(_item(
            "mock", "FAIL", "demo 所需的本地数据缺失",
            "缺少：" + "、".join(miss),
            "在完整仓库根目录运行；若使用 wheel 安装，请从源码仓库运行 demo。",
        ))

    # 7) 真集群 / kubeconfig
    kc = _find_kubeconfig(kubeconfig)
    kc_ok = False
    if kc:
        kc_ok, kc_reason = _looks_like_kubeconfig(kc)
        if kc_ok:
            items.append(_item("kubeconfig", "PASS", "检测到可用 kubeconfig", str(kc)))
        else:
            items.append(_item(
                "kubeconfig", "FAIL" if mode == "cluster" else "WARN",
                "kubeconfig 不可用", kc_reason,
                "换一个 kubeconfig 或运行 python -m inkblade quickstart 选择 demo 模式。",
            ))
    else:
        status = "FAIL" if mode == "cluster" else "WARN"
        items.append(_item(
            "kubeconfig", status, "未检测到 kubeconfig",
            "真实集群模式需要凭据；demo 模式不需要。",
            "设置 KUBECONFIG、放到 ~/.kube/config，或 quickstart 里填写路径；"
            "只想体验：python -m inkblade demo。",
        ))

    # 8) bash / kubectl（仅部分 lab 脚本需要）
    bash = shutil.which("bash")
    kubectl = shutil.which("kubectl")
    items.append(_item(
        "bash",
        "PASS" if bash else "WARN",
        "bash 可用" if bash else "未找到 bash（demo 不需要）",
        bash or "KIND/WSL/部分 lab 脚本需要 bash；核心 Python 流程不需要。",
        "" if bash else "Windows 安装 Git Bash 或 WSL2 并加入 PATH；或只跑 python -m inkblade demo。",
    ))
    items.append(_item(
        "kubectl",
        "PASS" if kubectl else "WARN",
        "kubectl 可用" if kubectl else "未找到 kubectl（快照驱动模块不需要）",
        kubectl or "真集群实时采集需要 kubectl；fixture/快照驱动模块不需要。",
        "" if kubectl else "安装 kubectl 并加入 PATH，或使用快照 JSON 驱动模块。",
    ))

    # 9) 工作区授权状态
    ws_dir = home_path / "evidence" / workspace
    consent = ws_dir / "consent.json"
    if consent.exists():
        try:
            from .core.evidence import EvidenceStore
            from .core.roe import roe_status

            status = roe_status(EvidenceStore(home_path, workspace=workspace))
            if status == "complete":
                items.append(_item("consent", "PASS", f"工作区 {workspace} 授权有效", str(consent)))
            else:
                items.append(_item(
                    "consent", "FAIL", f"工作区 {workspace} 授权异常（{status}）",
                    "consent.json 存在但验签失败或已损坏。",
                    "重新签署：python -m inkblade quickstart --workspace-dir " + str(home_path),
                ))
        except Exception as exc:  # noqa: BLE001
            items.append(_item("consent", "WARN", "无法读取授权状态", str(exc),
                               "可运行 python -m inkblade quickstart 重建工作区。"))
    else:
        items.append(_item(
            "consent", "WARN", f"工作区 {workspace} 尚未签授权",
            "demo 会自动签 demo 范围授权；真实集群请用 quickstart。",
            "python -m inkblade demo（demo 范围）；或 python -m inkblade quickstart（真实/自定义范围）。",
        ))

    # 10) 时钟（授权时间窗依赖）
    now = datetime.now()
    if 2020 <= now.year <= 2100:
        items.append(_item("clock", "PASS", "系统时间合理", now.strftime("%Y-%m-%d %H:%M:%S %Z").strip()))
    else:
        items.append(_item("clock", "FAIL", "系统时间异常", now.isoformat(),
                           "校准系统时间；否则授权时间窗会立即过期。"))

    fails = [i for i in items if i["status"] == "FAIL"]
    warns = [i for i in items if i["status"] == "WARN"]
    if fails:
        conclusion = (
            f"结论：有 {len(fails)} 项阻塞（FAIL），先按上面的「修复」处理；"
            "修完重跑 python -m inkblade doctor。"
        )
    else:
        chosen = "真集群" if (mode == "cluster" and kc_ok) else "本地 mock"
        conclusion = (
            f"结论：环境可用（{chosen}）。推荐下一步：python -m inkblade demo"
            "（本地 mock，约 10 秒出报告）。"
        )

    if json_out:
        print(json.dumps(
            {"ok": not fails, "mode": mode, "items": items,
             "fails": len(fails), "warns": len(warns), "conclusion": conclusion},
            ensure_ascii=False, indent=2,
        ))
        return 0 if not fails else 1

    print("InkBlade doctor — 环境自检")
    print("=" * 56)
    for it in items:
        print(f"[{it['status']}] {it['title']}")
        if it.get("detail"):
            print(f"       {it['detail']}")
        if it.get("fix"):
            print(f"       修复：{it['fix']}")
    print("-" * 56)
    print(conclusion)
    if warns:
        print(f"提示：{len(warns)} 项 WARN 不阻塞；demo 不需要它们。")
    return 0 if not fails else 1


# --------------------------------------------------------------------------- demo

def _demo_paths(out: Path) -> dict[str, Path]:
    return {
        "root": out,
        "workspace": out / "workspace",
        "reports": out / "reports",
        "rules": out / "rules-pack",
        "webui": out / "webui",
        "mock": out / "mock-lab",
    }


def _prepare_demo_dir(out: Path) -> Path:
    """只清理 demo 自己拥有的子目录；非 demo 目录拒绝覆盖。"""
    marker = out / DEMO_MARKER
    if out.exists() and any(out.iterdir()) and not marker.exists():
        raise DemoRefused(
            f"输出目录 {out} 非空且不是 InkBlade demo 目录。"
            "为避免覆盖你的文件，请换 --out <新目录>，或手动清空后重试。"
        )
    out.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps({"tool": "inkblade demo", "created_at": datetime.now().isoformat(timespec="seconds")},
                   ensure_ascii=False),
        encoding="utf-8",
    )
    return marker


def run_demo(
    out: str | Path = "demo",
    *,
    temp: bool = False,
    keep: bool = False,
    no_ui: bool = False,
    json_out: bool = False,
    workers: int = 2,
) -> int:
    """一条命令完成 demo；返回 0=成功。"""
    _ensure_utf8_stdio()
    t0 = time.monotonic()
    explicit_out = Path(out).expanduser()
    if temp:
        root = Path(tempfile.mkdtemp(prefix="inkblade-demo-"))
    else:
        root = explicit_out
    _prepare_demo_dir(root)
    paths = _demo_paths(root)

    # 延迟 import：doctor 不应因这些模块缺失而失败
    from .core.chains import execute, load_chains
    from .core.evidence import EvidenceStore
    from .core.roe import init_roe, roe_status
    from .core.runner import run_module
    from .core.users import UserStore
    from .reports.render import render_pentest, render_remediation
    from .rules.generate import generate_all
    from .webui.export_static import export_static

    repo = repo_root()
    modules_dir, chains_dir = _repo_dirs(repo)
    if not modules_dir.is_dir() or not chains_dir.is_dir():
        raise DemoRefused(
            "demo 需要 inkblade/modules 与 inkblade/chains（源码仓库数据文件），"
            "当前安装形态缺少它们；请在完整仓库根目录运行。"
        )

    mock_mod = _load_mock_module(repo)
    lab = mock_mod.start_all(mode="vulnerable", root=paths["mock"])
    keep_wait = False
    try:
        ws = paths["workspace"]
        store = EvidenceStore(ws, workspace=DEMO_WORKSPACE)
        users = UserStore(ws / "users.json")
        users.create_user("demo-lead", DEFAULT_DEMO_PASSWORD, "lead", [DEMO_WORKSPACE])
        users.create_user("demo-tester", DEFAULT_DEMO_PASSWORD, "tester", [DEMO_WORKSPACE])
        lead = users.verify("demo-lead", DEFAULT_DEMO_PASSWORD)
        tester = users.verify("demo-tester", DEFAULT_DEMO_PASSWORD)
        if lead is None or tester is None:
            raise DemoRefused("demo 用户创建后无法登录（users.json 异常）")

        fields = {
            "level": DEMO_LEVEL,
            "namespaces": ["train", "infer", "default", "ray-system", "ml-agent"],
            "cidrs": ["127.0.0.0/8"],
            "window": _now_window(days=7),
            "client": "InkBlade Demo（synthetic mock；lab-only）",
            "demo": True,
        }
        init_roe(store, fields=fields)
        if roe_status(store) != "complete":
            raise DemoRefused("demo 授权签署失败（consent 未通过验签）")

        run = store.create_run(f"demo-{datetime.now():%Y%m%d-%H%M%S}")

        # 2 个模块：侦察端口匹配 + 混合云 IMDS（均只读，真实 HTTP/快照驱动）
        snapshot_path = repo / "lab" / "fixtures" / "recon" / "cluster-snapshot.json"
        if snapshot_path.is_file():
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        else:
            snapshot = {"services": [
                {"name": "sglang-admin", "namespace": "infer",
                 "ports": [{"name": "http", "port": 30000, "targetPort": 30000}]},
            ]}
        module_cases = [
            ("framework-port-matching", {"snapshot": snapshot}),
            ("multi-cloud-imds-credentials", {"target": lab.url("/"), "mode": "probe-only"}),
        ]
        module_summaries = []
        for key, params in module_cases:
            before = len(run.findings)
            run_module(store, tester, key, copy.deepcopy(params),
                       modules_dir=modules_dir, run=run)
            got = run.findings[before:]
            module_summaries.append({"module": key, "findings": len(got)})

        # 1 条链：平网 → 管理面 → 权重投毒（写步骤带 HTTP 备份回执）
        chains = load_chains(chains_dir)
        if DEMO_CHAIN not in chains:
            raise DemoRefused(f"找不到 demo 链 {DEMO_CHAIN}（inkblade/chains 不完整）")
        chain = copy.deepcopy(chains[DEMO_CHAIN])
        for st in chain.get("steps", []):
            st.setdefault("params", {})["target"] = lab.url("")
            if st["module"] == "slime-weight-pull-poison":
                backup = [{"kind": "http", "url": lab.url("/pull_weights"), "state": {}}]
                st["params"]["backup_targets"] = backup
                st["backup_targets"] = backup
        started = time.monotonic()
        chain_res = execute(chain, store, tester, modules_dir=modules_dir,
                            findings=run.findings, workers=workers, run=run)
        chain_seconds = round(time.monotonic() - started, 2)
        if not chain_res.get("ok"):
            raise DemoRefused(
                "demo 链执行失败：" + json.dumps(chain_res.get("steps", {}), ensure_ascii=False)
            )

        # 双语报告 + 规则包 + 静态 UI
        paths["reports"].mkdir(parents=True, exist_ok=True)
        pentest = render_pentest(store, run.name, lang="bi")
        remediation = render_remediation(store, run.name, lang="bi")
        (paths["reports"] / "pentest-bi.md").write_text(pentest, encoding="utf-8")
        (paths["reports"] / "remediation-bi.md").write_text(remediation, encoding="utf-8")

        pack = generate_all(chains_dir, findings=run.findings, out_dir=paths["rules"])
        webui_path = None
        if not no_ui:
            webui_path = export_static(run.dir, paths["webui"])

        all_findings = run.findings
        sev_counts: dict[str, int] = {}
        for f in all_findings:
            sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1
        elapsed = round(time.monotonic() - t0, 2)
        summary = {
            "ok": True,
            "elapsed_seconds": elapsed,
            "out": str(root.resolve()),
            "workspace": str(paths["workspace"].resolve()),
            "workspace_name": DEMO_WORKSPACE,
            "run": run.name,
            "run_dir": str(run.dir.resolve()),
            "consent": {"status": "complete", "level": DEMO_LEVEL,
                        "namespaces": fields["namespaces"], "cidrs": fields["cidrs"],
                        "window": fields["window"]},
            "users": [{"name": "demo-lead", "role": "lead"},
                      {"name": "demo-tester", "role": "tester"}],
            "password": DEFAULT_DEMO_PASSWORD,
            "modules": module_summaries,
            "chain": {"id": DEMO_CHAIN, "ok": True, "seconds": chain_seconds,
                      "steps": {k: v.get("status") for k, v in chain_res.get("steps", {}).items()}},
            "findings": {"total": len(all_findings), "by_severity": sev_counts,
                         "top": [{"severity": f.get("severity"), "title": f.get("title")}
                                 for f in all_findings[:3]]},
            "report": {
                "pentest": str((paths["reports"] / "pentest-bi.md").resolve()),
                "remediation": str((paths["reports"] / "remediation-bi.md").resolve()),
            },
            "rules": {"dir": str(paths["rules"].resolve()), "rules": pack.total_rules,
                      "chains": pack.covered_chain_count, "files": len(pack.files)},
            "webui": str(webui_path) if webui_path else "",
            "mock_url": lab.url("/"),
            "next_steps": [
                "打开报告：%s" % (paths["reports"] / "pentest-bi.md").resolve(),
                "启动控制台：python -m inkblade --home %s ui --port 8765" % paths["workspace"].resolve(),
                "接真实集群：python -m inkblade quickstart",
            ],
        }
        (paths["reports"] / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

        if json_out:
            print(json.dumps(summary, ensure_ascii=False, indent=2))
        else:
            _print_demo_summary(summary, no_ui=no_ui)

        if keep:
            keep_wait = True
            print("")
            print(f"mock 靶场保持运行：{lab.url('/')}（仅 127.0.0.1）；按 Ctrl+C 结束。")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n已停止 mock 靶场。")
    finally:
        if not keep_wait:
            try:
                lab.shutdown()
            except Exception:
                pass
            if not keep:
                shutil.rmtree(paths["mock"], ignore_errors=True)
        if temp and not keep:
            shutil.rmtree(root, ignore_errors=True)
    return 0


def _print_demo_summary(s: dict[str, Any], *, no_ui: bool) -> None:
    print("InkBlade demo 完成")
    print("=" * 64)
    print(f"耗时：{s['elapsed_seconds']} 秒（目标 ≤60 秒）")
    print(f"工作区：{s['workspace']}（{s['workspace_name']}）")
    print(f"授权：{s['consent']['level']} / {', '.join(s['consent']['cidrs'])} / "
          f"{s['consent']['window']['start']} – {s['consent']['window']['end']}")
    print(f"用户：demo-lead / demo-tester（密码：{s['password']}，仅本地 demo）")
    print(f"run：{s['run']}")
    print(f"模块：{', '.join(m['module'] + '(' + str(m['findings']) + ')' for m in s['modules'])}")
    print(f"链：{s['chain']['id']} → {'成功' if s['chain']['ok'] else '失败'}"
          f"（{s['chain']['seconds']} 秒；" +
          ", ".join(f"{k}:{v}" for k, v in s["chain"]["steps"].items()) + "）")
    print(f"发现：{s['findings']['total']} 条（" +
          ", ".join(f"{k} {v}" for k, v in s["findings"]["by_severity"].items()) + "）")
    for f in s["findings"]["top"]:
        print(f"  - [{f['severity']}] {f['title']}")
    print("")
    print("产物：")
    print(f"  报告（中英双语）：{s['report']['pentest']}")
    print(f"  修复报告：      {s['report']['remediation']}")
    print(f"  规则包：        {s['rules']['dir']}（{s['rules']['rules']} 条规则 / "
          f"{s['rules']['chains']} 链）")
    if no_ui:
        print("  Web UI：        已跳过（--no-ui）")
    else:
        print(f"  Web UI（file://）：{s['webui']}")
    print("")
    print("下一步：")
    for i, step in enumerate(s["next_steps"], 1):
        print(f"  {i}. {step}")


# --------------------------------------------------------------------------- quickstart

def _prompt(inputs: Callable[[str], str], text: str, default: str) -> str:
    try:
        raw = inputs(text)
    except EOFError as exc:
        raise QuickstartAbort(
            "当前不是交互终端，无法回答 quickstart 的 5 个问题。"
            "请在终端运行，或加 --yes 使用默认值。"
        ) from exc
    raw = str(raw).strip()
    return raw if raw else default


def _prompt_choice(inputs: Callable[[str], str], text: str, default: str,
                   valid: Iterable[str]) -> str:
    valid_set = set(valid)
    for _ in range(3):
        raw = _prompt(inputs, text, default)
        if raw in valid_set:
            return raw
        print(f"输入无效：{raw}；可选 {sorted(valid_set)}，请重试。")
    raise QuickstartAbort("连续 3 次输入无效，已停止；未写入任何授权。")


def _prompt_cidrs(inputs: Callable[[str], str], default: str) -> list[str]:
    for _ in range(3):
        raw = _prompt(inputs, f"CIDR（逗号分隔）[{default}]: ", default)
        try:
            return _parse_cidrs(raw)
        except ValueError as exc:
            print(f"{exc}；请重试。")
    raise QuickstartAbort("CIDR 连续 3 次不合法，已停止；未写入任何授权。")


def _prompt_kubeconfig(inputs: Callable[[str], str], default: str) -> Path:
    for _ in range(3):
        raw = _prompt(inputs, f"kubeconfig 路径 [{default}]: ", default)
        path = Path(raw).expanduser()
        ok, reason = _looks_like_kubeconfig(path) if path.is_file() else (False, f"文件不存在：{path}")
        if ok:
            return path
        print(f"kubeconfig 不可用：{reason}；请重试。")
    raise QuickstartAbort("kubeconfig 连续 3 次不可用，已停止；未写入任何授权。")


def run_quickstart(
    workspace_dir: str | Path = "inkblade-workspace",
    *,
    inputs: Callable[[str], str] | None = None,
    yes: bool = False,
    target: str | None = None,
    level: str | None = None,
    namespaces: str | None = None,
    cidrs: str | None = None,
    lead: str | None = None,
    password: str | None = None,
    kubeconfig: str | None = None,
    json_out: bool = False,
) -> int:
    """5 问向导：目标 / 范围 / 级别 / 用户 / 签授权。失败可重入。"""
    _ensure_utf8_stdio()
    ask = inputs or input
    ws_root = Path(workspace_dir).expanduser()
    ws_root.mkdir(parents=True, exist_ok=True)

    # 延迟 import，避免 --help / doctor 受牵连
    from .core.evidence import EvidenceStore
    from .core.roe import init_roe, read_workspace_config, roe_status, window_status, write_workspace_config
    from .core.users import UserStore

    store = EvidenceStore(ws_root, workspace=QUICKSTART_WORKSPACE)
    existing = store.consent()
    existing_fields = existing.get("fields", {}) if isinstance(existing, dict) and \
        existing.get("status") == "complete" else {}
    ws_cfg = read_workspace_config(store)
    existing_target = (ws_cfg.get("target") or {}) if isinstance(ws_cfg, dict) else {}

    print("InkBlade quickstart — 5 问签授权（可随时 Ctrl+C；失败可重跑）")
    print("=" * 64)

    # Q1 目标
    default_target = "2" if (existing_target.get("mode") == "cluster") else "1"
    if yes and target is None:
        target = "cluster" if (existing_target.get("mode") == "cluster") else "demo"
        if target == "cluster" and kubeconfig is None:
            kubeconfig = existing_target.get("kubeconfig") or None
    if target is None:
        print("第 1/5 问：这次测什么？")
        print("  [1] 本地 demo（推荐；mock 靶场，不碰真实集群）")
        print("  [2] 真实集群（需要 kubeconfig）")
        choice = _prompt_choice(ask, f"选择 [{default_target}]: ", default_target, {"1", "2"})
        target = "demo" if choice == "1" else "cluster"
    target = "cluster" if str(target).lower() in ("2", "cluster", "real", "kubeconfig") else "demo"

    kc_path: Path | None = None
    if target == "cluster":
        if yes:
            kc_path = Path(kubeconfig).expanduser() if kubeconfig else _find_kubeconfig()
            if kc_path is None:
                raise QuickstartAbort(
                    "选择了真实集群但未找到 kubeconfig；请加 --kubeconfig <路径>，"
                    "或先运行 python -m inkblade demo 体验本地模式。"
                )
            ok, reason = _looks_like_kubeconfig(kc_path) if kc_path.is_file() else (False, f"文件不存在：{kc_path}")
            if not ok:
                raise QuickstartAbort(f"kubeconfig 不可用：{reason}")
        else:
            default_kc = str(Path(kubeconfig).expanduser()) if kubeconfig else str(
                _find_kubeconfig() or (Path.home() / ".kube" / "config"))
            kc_path = _prompt_kubeconfig(ask, default_kc)

    # Q2 范围
    default_ns = ",".join(existing_fields.get("namespaces") or ["train", "infer", "default"])
    default_cidrs = ",".join(existing_fields.get("cidrs") or
                             (["10.0.0.0/8"] if target == "cluster" else ["127.0.0.0/8"]))
    if namespaces is None:
        if yes:
            namespaces = default_ns
        else:
            print("第 2/5 问：授权范围（namespace 与 CIDR；逗号分隔）")
            namespaces = _prompt(ask, f"namespace [{default_ns}]: ", default_ns)
    ns_list = _parse_namespaces(namespaces)
    if cidrs is None:
        cidr_list = _parse_cidrs(default_cidrs) if yes else _prompt_cidrs(ask, default_cidrs)
    else:
        cidr_list = _parse_cidrs(cidrs)

    # Q3 级别
    default_level = str(existing_fields.get("level") or
                        ("只读侦察" if target == "cluster" else "主动探测"))
    if level is None:
        if yes:
            level = default_level
        else:
            print("第 3/5 问：授权级别")
            print("  1) 只读侦察 — 不改任何东西（最安全）")
            print("  2) 主动探测 — 只发探测请求")
            print("  3) 利用验证 — 可能写，必须备份")
            print("  4) 全影响演示 — 允许完整演示，必须备份")
            idx = LEVELS.index(default_level) + 1 if default_level in LEVELS else 1
            choice = _prompt_choice(ask, f"选择 [1-4，默认 {idx}]: ", str(idx), {"1", "2", "3", "4"})
            level = LEVELS[int(choice) - 1]
    if level not in LEVELS:
        raise QuickstartAbort(f"未知级别：{level}；可选 {LEVELS}")
    if target == "cluster" and LEVELS.index(level) >= 2:
        print(f"注意：真实集群授权为「{level}」；写类动作仍需逐次备份回执，建议先跑 --dry-run。")

    # Q4 用户
    default_lead = str((existing_target.get("lead") or "lead"))
    if lead is None:
        if yes:
            lead = default_lead
        else:
            print("第 4/5 问：创建用户（lead 与 tester，同一密码）")
            lead = _prompt(ask, f"lead 用户名 [{default_lead}]: ", default_lead)
    lead = str(lead).strip() or "lead"
    if lead == "tester":
        raise QuickstartAbort("lead 用户名不能与内置 tester 冲突；请换一个名字。")
    if password is None:
        generated = "InkBlade-" + secrets.token_urlsafe(6)
        if yes:
            password = generated
        else:
            password = _prompt(ask, f"密码 [回车自动生成]: ", generated)
    if not password:
        raise QuickstartAbort("密码不能为空")

    # Q5 授权预览 + 签署
    fields = {
        "level": level,
        "namespaces": ns_list,
        "cidrs": cidr_list,
        "window": _now_window(days=7),
        "client": "InkBlade quickstart（%s）" % ("real-cluster" if target == "cluster" else "demo"),
    }
    print("第 5/5 问：确认授权")
    print(json.dumps(fields, ensure_ascii=False, indent=2))
    if target == "cluster" and kc_path:
        print(f"kubeconfig：{kc_path}")
    print("提示：授权会写入 consent.json（HMAC-SHA256 签名）；过期/篡改后所有执行路径自动拒绝。")
    if yes:
        confirmed = True
    else:
        answer = _prompt(ask, "确认并签署？[Y/n]: ", "y").lower()
        confirmed = answer in ("y", "yes", "是")
    if not confirmed:
        raise QuickstartAbort("已取消签署；未写入授权。可重跑 python -m inkblade quickstart。")

    same = bool(existing_fields) and existing_fields.get("level") == level and \
        existing_fields.get("namespaces") == ns_list and existing_fields.get("cidrs") == cidr_list
    window_ok = bool(existing_fields) and window_status(existing_fields)[0]
    if same and window_ok and roe_status(store) == "complete":
        print("现有授权字段一致且时间窗仍有效：保留原 consent（不重签）。")
    else:
        init_roe(store, fields=fields)
        if roe_status(store) != "complete":
            raise QuickstartAbort("授权签署后验签失败；请重试或运行 doctor。")

    users = UserStore(ws_root / "users.json")
    users.create_user(lead, password, "lead", [QUICKSTART_WORKSPACE])
    users.create_user("tester", password, "tester", [QUICKSTART_WORKSPACE])
    cfg = read_workspace_config(store)
    cfg["target"] = {
        "mode": target,
        "kubeconfig": str(kc_path) if kc_path else "",
        "lead": lead,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    write_workspace_config(store, cfg)

    consent = store.consent() or {}
    summary = {
        "ok": True,
        "workspace": str(ws_root.resolve()),
        "workspace_name": QUICKSTART_WORKSPACE,
        "target": target,
        "kubeconfig": str(kc_path) if kc_path else "",
        "fields": fields,
        "users": [{"name": lead, "role": "lead"}, {"name": "tester", "role": "tester"}],
        "password": password,
        "consent_sha256": consent.get("sha256", ""),
    }
    if json_out:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("")
        print("quickstart 完成")
        print("=" * 64)
        print(f"工作区：{ws_root.resolve()}（{QUICKSTART_WORKSPACE}）")
        print(f"目标：{'真实集群' if target == 'cluster' else '本地 demo'}" +
              (f" / {kc_path}" if kc_path else ""))
        print(f"级别：{level}；范围：{', '.join(ns_list)} / {', '.join(cidr_list)}")
        print(f"用户：{lead}(lead) / tester(tester)；密码：{password}")
        print(f"授权：complete；sha256={str(consent.get('sha256', ''))[:16]}…")
        print("")
        print("下一步：")
        if target == "cluster":
            print(f"  1. 自检：python -m inkblade doctor --mode cluster --kubeconfig \"{kc_path}\"")
            print(f"  2. 只读 dry-run：python -m inkblade --home \"{ws_root}\" "
                  f"execute --workspace {QUICKSTART_WORKSPACE} --chain {DEMO_CHAIN} --dry-run")
            print("  3. 确认计划后去掉 --dry-run；写类步骤仍需 backup_targets。")
        else:
            print("  1. 看完整演示：python -m inkblade demo")
            print(f"  2. 启动控制台：python -m inkblade --home \"{ws_root}\" ui --port 8765")
            print("  3. 接真实集群：python -m inkblade quickstart（选 2，填 kubeconfig）")
    return 0
