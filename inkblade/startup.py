"""一条命令启动：``inkblade up``（别名 ``start``）/ ``down`` / ``status``。

设计契约
--------
- 零配置：默认工作区 ``./inkblade-workspace``（``--home`` 可改）；首次自动建工作区、
  生成 admin 随机密码（**只打印一次**，不落盘明文）、签发「本地 demo」授权
  （127.0.0.0/8、train/infer/default、7 天），随后启动 127.0.0.1 上的控制台。
- 幂等：重复 ``up`` 不重建、不重印密码、不重复起进程；已有存活实例则复用。
- 可停：``down`` 只终止 pid 文件里记录、且确认是本工作区拉起的 python 进程；
  ``status`` 报告 UI / 授权 / 用户 / 证据状态。
- 纯本地：子进程脱离终端运行，日志写 ``<home>/.inkblade/ui.log``；不访问外网。

失败一律抛 :class:`StartupError`，内部携带三行式人话（见 ``core.humanize``）。
"""

from __future__ import annotations

import importlib.util
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_HOME = "inkblade-workspace"
WORKSPACE = "local-lab"
STATE_DIR = ".inkblade"
STATE_FILE = "ui.json"
LOG_FILE = "ui.log"
BOOTSTRAP_FILE = "bootstrap.json"
ADMIN = "admin"
DEFAULT_PORT = 8765
DEFAULT_HOST = "127.0.0.1"
DEMO_LEVEL = "主动探测"
DEMO_CIDRS = ["127.0.0.0/8"]
DEMO_NAMESPACES = ["train", "infer", "default"]
WINDOW_DAYS = 7


class StartupError(RuntimeError):
    """``up``/``down``/``status`` 的可预期失败；携带三行式人话。"""

    def __init__(self, human):
        self.human = human
        super().__init__(getattr(human, "title", str(human)))


# --------------------------------------------------------------------------- 小工具

def _ensure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 —— StringIO / 已包装流没有 reconfigure
            pass


def _human(code: str, title: str, happened: str, why: str, fix: str):
    from .core.humanize import HumanError

    return HumanError(code, title, happened, why, fix)


def resolve_home(explicit: str | Path | None = None) -> Path:
    """``--home`` 优先；否则 ``./inkblade-workspace``（绝对路径返回，便于打印/复用）。"""
    if explicit in (None, ""):
        return (Path.cwd() / DEFAULT_HOME).resolve()
    return Path(str(explicit)).expanduser().resolve()


def state_dir(home: str | Path) -> Path:
    return Path(home) / STATE_DIR


def _state_path(home: str | Path) -> Path:
    return state_dir(home) / STATE_FILE


def _log_path(home: str | Path) -> Path:
    return state_dir(home) / LOG_FILE


def read_state(home: str | Path) -> dict | None:
    p = _state_path(home)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _write_state(home: str | Path, state: dict[str, Any]) -> None:
    p = _state_path(home)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _clear_state(home: str | Path) -> None:
    try:
        _state_path(home).unlink()
    except OSError:
        pass


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


_PASSWORD_ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _random_password(length: int = 16) -> str:
    """可抄写的随机密码：去掉了 0/O/l/I 等易混字符。"""
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


def _window(days: int = WINDOW_DAYS) -> dict[str, str]:
    now = datetime.now()
    return {
        "start": (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M"),
        "end": (now + timedelta(days=days)).strftime("%Y-%m-%d %H:%M"),
    }


def _family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def port_free(port: int, host: str = DEFAULT_HOST) -> bool:
    if not port:
        return True
    with socket.socket(_family(host), socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, int(port)))
            return True
        except OSError:
            return False


def _url(host: str, port: int) -> str:
    shown = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    if ":" in shown and not shown.startswith("["):
        shown = f"[{shown}]"
    return f"http://{shown}:{int(port)}/"


def _http_ok(host: str, port: int, timeout: float = 0.6) -> bool:
    """控制台根路径 200 且页面含 InkBlade（用来区分旧 pid 被系统复用）。"""
    if not port:
        return False
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(_url(host, int(port)), timeout=timeout) as resp:
            body = resp.read(4096)
            return int(getattr(resp, "status", resp.getcode())) == 200 and b"InkBlade" in body
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _pid_alive(pid: int) -> bool:
    if not pid:
        return False
    if os.name == "nt":  # noqa: SIM108 —— tasklist 比 OpenProcess 更省依赖
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {int(pid)}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return str(int(pid)) in (out.stdout or "")
    try:
        os.kill(int(pid), 0)
    except OSError:
        return False
    try:
        # A zombie has released its sockets but still answers kill(pid, 0).
        fields = Path(f"/proc/{int(pid)}/stat").read_text(encoding="utf-8").split()
        if len(fields) > 2 and fields[2] == "Z":
            return False
    except OSError:
        pass
    return True


def _pid_image(pid: int) -> str:
    """进程镜像名（只用于「别杀错进程」的安全校验）。"""
    if os.name == "nt":
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {int(pid)}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        first = (out.stdout or "").strip().splitlines()
        if not first:
            return ""
        return first[0].split('","')[0].strip('"').lower()
    try:
        return Path(f"/proc/{int(pid)}/comm").read_text(encoding="utf-8").strip().lower()
    except OSError:
        return ""


def _looks_like_python(image: str) -> bool:
    image = (image or "").lower()
    return bool(image) and ("python" in image or image.startswith("pypy"))


def _stop_pid(pid: int, timeout: float = 8.0) -> bool:
    """终止 pid；只在调用方已确认是本地 UI 进程后使用。"""
    if not pid:
        return True
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                           capture_output=True, timeout=20, check=False)
        except (OSError, subprocess.SubprocessError):
            return False
    else:
        try:
            # The UI is started in its own session; kill the whole group so a
            # forked child cannot keep the port/pid alive.
            os.killpg(os.getpgid(int(pid)), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            try:
                os.kill(int(pid), signal.SIGTERM)
            except OSError:
                return True
    deadline = time.time() + float(timeout)
    while time.time() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.2)
    if os.name != "nt":
        try:
            os.killpg(os.getpgid(int(pid)), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                os.kill(int(pid), signal.SIGKILL)
            except OSError:
                return True
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if not _pid_alive(pid):
                return True
            time.sleep(0.2)
    return not _pid_alive(pid)


def _tail(path: Path, lines: int = 6) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    rows = [r for r in text.splitlines() if r.strip()]
    return "\n".join(rows[-lines:])


def inspect(home: str | Path) -> dict[str, Any]:
    """读取 pid 文件并核实：进程活着 **且** 端口上确实是控制台，才算 running。"""
    state = read_state(home) or {}
    pid = int(state.get("pid") or 0)
    host = str(state.get("host") or DEFAULT_HOST)
    port = int(state.get("port") or 0)
    alive = _pid_alive(pid) if pid else False
    http = _http_ok(host, port) if (alive and port) else False
    return {
        "state": state,
        "pid": pid,
        "host": host,
        "port": port,
        "alive": alive,
        "http": http,
        "running": bool(alive and http),
    }


# --------------------------------------------------------------------------- 自检

def preflight(home: Path, port: int = DEFAULT_PORT, host: str = DEFAULT_HOST) -> list[dict[str, Any]]:
    """doctor 精简版：只保留「一条命令启动」真正需要的检查。"""
    items: list[dict[str, Any]] = []

    def item(cid: str, status: str, title: str, detail: str = "") -> None:
        items.append({"id": cid, "status": status, "title": title, "detail": detail})

    ver = ".".join(str(x) for x in sys.version_info[:3])
    if sys.version_info >= (3, 10):
        item("python", "PASS", f"Python {ver}（>=3.10）", sys.executable)
    else:
        item("python", "FAIL", f"Python {ver} 过低", "InkBlade 需要 Python 3.10+。")

    try:
        spec = importlib.util.find_spec("inkblade")
        ok = bool(spec)
    except Exception:  # noqa: BLE001
        ok = False
    item("entry", "PASS" if ok else "FAIL", "inkblade 包可导入",
         str(Path(__file__).resolve().parents[1]))

    probe_dir = home
    created = False
    try:
        if not probe_dir.exists():
            probe_dir.mkdir(parents=True, exist_ok=True)
            created = True
        probe = probe_dir / f".inkblade-up-{os.getpid()}-{secrets.token_hex(3)}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        item("write", "PASS", "工作区可写", str(probe_dir))
    except OSError as exc:
        item("write", "FAIL", "工作区不可写", f"{probe_dir}: {exc}")
    finally:
        if created:
            try:
                probe_dir.rmdir()
            except OSError:
                pass

    try:
        free_mb = shutil.disk_usage(home if home.exists() else Path.cwd()).free // (1024 * 1024)
        status = "PASS" if free_mb >= 200 else "WARN"
        item("disk", status, f"磁盘剩余 {free_mb} MB",
             "" if free_mb >= 200 else "空间偏低；清理后可继续。")
    except OSError as exc:
        item("disk", "WARN", "无法读取磁盘余量", str(exc))

    if port:
        if port_free(int(port), host):
            item("port", "PASS", f"端口 {int(port)} 可用", f"{host}:{int(port)}")
        else:
            item("port", "FAIL", f"端口 {int(port)} 已被占用", f"{host}:{int(port)}")

    missing = [m for m in ("zstandard", "cryptography", "psutil")
               if importlib.util.find_spec(m) is None]
    if missing:
        item("optional", "WARN", "可选依赖未安装（不影响启动）", "、".join(missing))
    else:
        item("optional", "PASS", "可选依赖齐全", "zstandard / cryptography / psutil")
    return items


def _print_preflight(items: list[dict[str, Any]], stream=None) -> None:
    out = stream or sys.stdout
    print("环境自检（doctor 精简版）", file=out)
    for it in items:
        line = f"  [{it['status']}] {it['title']}"
        if it.get("detail") and it["status"] != "PASS":
            line += f" — {it['detail']}"
        print(line, file=out)


def _fail_from_preflight(items: list[dict[str, Any]], home: Path, port: int) -> None:
    """把第一条 FAIL 翻译成三行式人话。"""
    fails = [i for i in items if i["status"] == "FAIL"]
    if not fails:
        return
    first = fails[0]
    cid = first["id"]
    detail = str(first.get("detail") or "")
    if cid == "python":
        raise StartupError(_human(
            "E106", "Python 版本过低",
            f"当前解释器 {sys.version.split()[0]}，InkBlade 需要 3.10+。",
            "``up`` 会在当前解释器里直接启动控制台，版本过低时无法导入标准库新特性。",
            "安装 Python 3.10+ 并用它重跑：python3.12 -m inkblade up；"
            "或用 uv/venv 建一个 3.12 环境后再 pip install inkblade。",
        ))
    if cid == "write":
        raise StartupError(_human(
            "E112", "启动目录不可写",
            f"无法在 {home} 建工作区（{detail}）。",
            "``up`` 需要在 --home 下创建 evidence/、users.json 与 .inkblade/ 状态文件。",
            f"换可写目录：inkblade up --home \"{Path.home() / DEFAULT_HOME}\"；"
            "Windows 检查只读属性/杀软拦截，或改用 %TEMP% 下的目录。",
        ))
    if cid == "port":
        alt = int(port) + 1 if str(port).isdigit() else DEFAULT_PORT + 1
        raise StartupError(_human(
            "E103", f"端口 {port} 已被占用",
            f"控制台无法绑定 {detail}（address already in use）。",
            "该端口已有其他程序在监听；InkBlade 不会抢占或杀掉别人的进程。",
            f"换端口：inkblade up --port {alt}；或先停占用进程"
            f"（Windows: netstat -ano | findstr :{port}）；查看已有实例：inkblade status。",
        ))
    if cid == "disk":
        raise StartupError(_human(
            "E107", "磁盘空间不足",
            str(first.get("title") or "磁盘余量过低") + f"（{detail}）",
            "工作区、证据与报告都需要写入本地磁盘。",
            f"清理 --home（{home}）下的 reports/、evidence/ 或换到更大的盘："
            "inkblade up --home <新目录>。",
        ))
    raise StartupError(_human(
        "E900", "启动前自检未通过",
        f"{first.get('title')}：{detail}",
        "``up`` 在启动前做只读自检，未通过时不会拉起 UI，避免留下半初始化工作区。",
        "按上面 [FAIL] 行的提示处理，然后重跑 inkblade up；完整自检见 inkblade doctor。",
    ))


# --------------------------------------------------------------------------- 工作区

def _workspace_info(home: Path) -> dict[str, Any]:
    from .core.evidence import EvidenceStore
    from .core.roe import roe_status

    store = EvidenceStore(home, workspace=WORKSPACE)
    consent = store.consent() or {}
    fields = consent.get("fields") or {}
    try:
        runs = [p for p in store.ws_dir.iterdir() if p.is_dir() and not p.name.startswith("_")]
    except OSError:
        runs = []
    return {
        "store": store,
        "status": roe_status(store),
        "fields": fields if isinstance(fields, dict) else {},
        "runs": len(runs),
    }


def init_workspace(home: Path, *, sign_demo: bool = True) -> dict[str, Any]:
    """建工作区 + （首次）签本地 demo 授权 + （首次）建 admin。返回摘要。"""
    from .core.evidence import EvidenceStore
    from .core.roe import init_roe, read_workspace_config, roe_status, write_workspace_config
    from .core.users import UserStore

    try:
        home.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StartupError(_human(
            "E112", "启动目录不可写",
            f"无法创建 {home}（{exc}）。",
            "``up`` 需要在 --home 下创建工作区与状态文件。",
            "换可写目录：inkblade up --home <目录>；Windows 检查只读属性/杀软拦截。",
        )) from exc

    store = EvidenceStore(home, workspace=WORKSPACE)
    before = roe_status(store)
    signed_now = False
    if before == "complete":
        pass
    elif sign_demo:
        fields = {
            "level": DEMO_LEVEL,
            "namespaces": list(DEMO_NAMESPACES),
            "cidrs": list(DEMO_CIDRS),
            "window": _window(),
            "client": "InkBlade up（本地 demo，仅 127.0.0.1）",
        }
        try:
            init_roe(store, fields)
            signed_now = roe_status(store) == "complete"
        except Exception as exc:  # noqa: BLE001 —— 签名失败要人话化，不能留半签状态
            raise StartupError(_human(
                "E113", "本地授权签发失败",
                f"{type(exc).__name__}: {exc}",
                "工作区密钥或磁盘写入异常时，consent.json 无法自校验，执行路径会一直拒绝。",
                f"删除 {store.ws_dir / 'consent.json'} 后重跑 inkblade up；"
                "仍失败则换 --home 目录并附上 inkblade doctor 输出。",
            )) from exc
        if not signed_now:
            raise StartupError(_human(
                "E113", "本地授权签发失败",
                f"consent.json 写入后验签未通过（status={roe_status(store)}）。",
                "工作区密钥与 consent 字段不一致，或磁盘写入被截断。",
                f"删除 {store.ws_dir / 'consent.json'} 后重跑 inkblade up，"
                "或用 inkblade quickstart 重新签署。",
            ))

    cfg = read_workspace_config(store)
    if not isinstance(cfg, dict):
        cfg = {}
    target = cfg.get("target")
    if not isinstance(target, dict) or not target.get("mode"):
        cfg["target"] = {"mode": "demo", "lead": ADMIN, "created_at": _now()}
        write_workspace_config(store, cfg)

    try:
        users = UserStore(home / "users.json")
    except ValueError as exc:
        raise StartupError(_human(
            "E113", "users.json 无法解析",
            f"{home / 'users.json'} 不是合法 JSON（{exc}）。",
            "用户库损坏时无法创建 admin，也无法登录控制台；up 不会覆盖坏文件。",
            f"备份后删除 {home / 'users.json'} 再重跑 inkblade up；"
            "或手工修复该文件（需要 salt/hash/role/workspaces 四个键）。",
        )) from exc
    password = ""
    if not users.has(ADMIN):
        password = "InkBlade-" + _random_password()
        users.create_user(ADMIN, password, "admin", ["*"])
        marker = state_dir(home) / BOOTSTRAP_FILE
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps(
            {"admin": ADMIN, "created_at": _now(), "password_shown_once": True},
            ensure_ascii=False, indent=2,
        ), encoding="utf-8")

    info = _workspace_info(home)
    return {
        "home": str(home),
        "workspace": WORKSPACE,
        "status": info["status"],
        "fields": info["fields"],
        "runs": info["runs"],
        "users": users.names(),
        "roles": users.roles(),
        "admin_created": bool(password),
        "password": password,
        "signed_now": signed_now,
        "sign_demo": bool(sign_demo),
    }


# --------------------------------------------------------------------------- 启动/停止

def _child_env() -> dict[str, str]:
    env = os.environ.copy()
    pkg_root = str(Path(__file__).resolve().parents[1])
    old = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = pkg_root + (os.pathsep + old if old else "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONUTF8"] = "1"
    env["INKBLADE_UP_CHILD"] = "1"
    return env


def _spawn_ui(home: Path, host: str, port: int) -> subprocess.Popen:
    log = _log_path(home)
    log.parent.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-u", "-m", "inkblade", "--home", str(home), "ui",
           "--host", host, "--port", str(int(port))]
    kwargs: dict[str, Any] = {
        "cwd": str(home),
        "stdin": subprocess.DEVNULL,
        "env": _child_env(),
        "close_fds": True,
    }
    if os.name == "nt":
        # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP：父进程退出后 UI 继续跑
        kwargs["creationflags"] = 0x00000008 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    with open(log, "ab") as fh:
        header = f"\n--- inkblade up {_now()} pid={os.getpid()} ---\n".encode("utf-8")
        fh.write(header)
        fh.flush()
        kwargs["stdout"] = fh
        kwargs["stderr"] = subprocess.STDOUT
        return subprocess.Popen(cmd, **kwargs)  # noqa: S603 —— 参数由本模块常量拼装


def _ui_start_error(home: Path, host: str, port: int, tail: str, why: str):
    log = _log_path(home)
    alt = port + 1 if port < 65535 else 8765
    return StartupError(_human(
        "E113", "本地 UI 启动失败",
        f"{_url(host, port)} 未在预期时间内就绪。"
        + (f"\n最后几行日志：\n{tail}" if tail else ""),
        why,
        f"看完整日志：{log}；换端口重试：inkblade up --port {alt}；"
        "重试前可先 inkblade down 清理。",
    ))


def _serve_foreground(home: Path, host: str, port: int) -> int:
    from .core.users import UserStore
    from .webui.server import make_server

    users = UserStore(home / "users.json")
    httpd = make_server(home, users, host=host, port=port)
    print(f"InkBlade 控制台: {_url(host, httpd.port)} （前台运行；Ctrl+C 退出）")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n已停止。", file=sys.stderr)
        httpd.shutdown()
    return 0


def _next_steps(url: str, home: Path, *, ui_running: bool, port: int) -> list[str]:
    if ui_running:
        first = f"浏览器打开 {url} （已尝试自动打开；没弹出就手动复制）"
    else:
        first = f"启动 UI：inkblade up --home \"{home}\" --port {int(port)}"
    second = (f"登录：用户名 admin（密码只在首次显示）+ 工作区 {WORKSPACE}；"
              "本地 demo 授权已签发，接入已有探针/立足点后按需重签范围")
    third = ("接入：inkblade probe list（已有探针）→ "
             "inkblade channel start --session <session-id>；停止：inkblade down")
    return [first, second, third]


def _print_summary(info: dict[str, Any], *, url: str, ui_running: bool, pid: int,
                   port: int, no_ui: bool, log: Path, out=None) -> None:
    out = out or sys.stdout
    fields = info.get("fields") or {}
    window = fields.get("window") or {}
    scope = f"{', '.join(fields.get('namespaces') or [])} / " \
            f"{', '.join(fields.get('cidrs') or [])}"
    level = fields.get("level") or "-"
    status = info.get("status")
    if status == "complete":
        consent = (f"已签发（本地 demo：{level}；{scope}；"
                   f"{window.get('start', '?')} → {window.get('end', '?')}）"
                   if info.get("signed_now")
                   else f"保留原有授权（{level}；{scope}）")
    elif info.get("sign_demo") is False:
        consent = "未签发（--no-consent）；下一步：inkblade quickstart，或 POST /api/v1/consent/sign"
    else:
        consent = f"异常（{status}）；跑 inkblade doctor 或 inkblade quickstart 重签"

    print("", file=out)
    print(f"工作区 : {info['home']} （{WORKSPACE}）", file=out)
    print(f"授权   : {consent}", file=out)
    users = ", ".join(info.get("users") or []) or "（无）"
    if info.get("admin_created"):
        print(f"用户   : {users}（admin 本次新建）", file=out)
    else:
        print(f"用户   : {users}（admin 已存在；密码只在首次显示，本次不重印）", file=out)
    if info.get("password"):
        print("", file=out)
        print("首次密码（只显示这一次，请立即保存）：", file=out)
        print(f"  {ADMIN} / {info['password']}", file=out)
        print(f"  忘了就重置：inkblade --home \"{info['home']}\" "
              f"user add {ADMIN} '新密码' admin --workspaces '*'", file=out)
    print("", file=out)
    if no_ui:
        print("UI     : 未启动（--no-ui）。手动启动：", file=out)
        print(f"         inkblade --home \"{info['home']}\" ui --port {int(port)}", file=out)
        print(f"         或再跑：inkblade up --home \"{info['home']}\" --port {int(port)}", file=out)
    elif ui_running:
        print(f"UI     : {url} （pid {pid}；日志 {log}）", file=out)
    print("", file=out)
    print("下一步：", file=out)
    for idx, line in enumerate(_next_steps(url, Path(info["home"]),
                                           ui_running=ui_running, port=port), start=1):
        print(f"  {idx}. {line}", file=out)


def run_up(
    home: str | Path | None = None,
    *,
    port: int = DEFAULT_PORT,
    host: str = DEFAULT_HOST,
    no_ui: bool = False,
    no_browser: bool = False,
    foreground: bool = False,
    sign_demo: bool = True,
    json_out: bool = False,
    wait: float = 20.0,
) -> int:
    """一条命令启动。返回进程退出码（0 成功；2 可预期失败）。"""
    _ensure_stdio()
    path = resolve_home(home)
    port = int(port)
    try:
        if not 1 <= port <= 65535:
            raise StartupError(_human(
                "E112", "端口不合法",
                f"--port {port} 超出 1–65535。",
                "端口必须是 1–65535 的整数；up 不支持 0（随机端口会让 pid 文件与实际端口不一致）。",
                "换一个端口：inkblade up --port 8766；查看端口占用：inkblade status。",
            ))
        if not json_out:
            print("InkBlade up — 一条命令启动（本地；默认只监听 127.0.0.1）")
            print("=" * 60)
            print(f"启动目录 : {path}")

        # 先看是否已有存活实例：复用时不检查端口（端口本来就是它占的）
        current = inspect(path)
        busy = bool(current["state"] and current["alive"])
        if host not in ("127.0.0.1", "localhost", "::1") and not json_out:
            print(f"警告: 控制台绑定 {host}，将对网络可达；仅在隔离网络或反向代理后使用。",
                  file=sys.stderr)
        items = preflight(path, port=0 if (no_ui or busy) else port, host=host)
        if busy and not no_ui:
            items.append({"id": "reuse", "status": "PASS", "title":
                          f"已有实例 pid {current['pid']}（{_url(current['host'], current['port'])}）",
                          "detail": ""})
        if not json_out:
            _print_preflight(items)
            print("")
        _fail_from_preflight(items, path, port)

        info = init_workspace(path, sign_demo=sign_demo)

        if current["running"]:
            existing_url = str(current["state"].get("url") or _url(current["host"], current["port"]))
            if current["port"] != port:
                print(f"提示：本工作区已有 UI 在 {existing_url}（端口 {current['port']}）；"
                      f"本次 --port {port} 未生效。如需换端口：先 inkblade down 再 up。",
                      file=sys.stderr)
            if not no_browser:
                _open_browser(existing_url)
            if json_out:
                _print_json({"ok": True, "home": str(path), "workspace": WORKSPACE,
                             "running": True, "reused": True, "port": current["port"],
                             "url": existing_url, "pid": current["pid"],
                             "admin_created": info["admin_created"],
                             "password": info["password"],
                             "consent": info["status"], "users": info["users"]})
            else:
                _print_summary(info, url=existing_url, ui_running=True, pid=current["pid"],
                               port=current["port"], no_ui=False,
                               log=_log_path(path))
            return 0

        if current["state"] and current["alive"]:
            # 进程还在但不响应：不要偷偷再拉一个（会抢端口/丢 pid），交给 down 收尾
            raise StartupError(_human(
                "E113", "已有 UI 进程但无响应",
                f"pid {current['pid']} 仍在，但 {_url(current['host'], current['port'])} 无响应。",
                "上次启动的进程可能卡死，或被安全软件挂起；直接再 up 会留下两个进程。",
                "先 inkblade down 结束旧进程，再 inkblade up；"
                f"down 失败时手动 taskkill /PID {current['pid']} /T /F。",
            ))

        if current["state"]:
            # 有状态文件但进程/端口都不在：清理残留，保持幂等
            _clear_state(path)

        if no_ui:
            url = _url(host, port)
            if json_out:
                _print_json({"ok": True, "home": str(path), "workspace": WORKSPACE,
                             "running": False, "port": port, "url": url,
                             "admin_created": info["admin_created"],
                             "password": info["password"], "consent": info["status"],
                             "users": info["users"]})
            else:
                _print_summary(info, url=url, ui_running=False, pid=0, port=port,
                               no_ui=True, log=_log_path(path))
            return 0

        if foreground:
            url = _url(host, port)
            if json_out:
                _print_json({"ok": True, "home": str(path), "workspace": WORKSPACE,
                             "running": True, "foreground": True, "port": port, "url": url,
                             "admin_created": info["admin_created"],
                             "password": info["password"], "consent": info["status"],
                             "users": info["users"]})
            else:
                _print_summary(info, url=url, ui_running=True, pid=os.getpid(),
                               port=port, no_ui=False, log=_log_path(path))
            return _serve_foreground(path, host, port)

        try:
            proc = _spawn_ui(path, host, port)
        except OSError as exc:
            raise _ui_start_error(
                path, host, port, "",
                f"无法启动子进程（{type(exc).__name__}: {exc}）；通常是解释器路径或权限问题。",
            ) from exc
        log = _log_path(path)
        deadline = time.time() + max(1.0, float(wait))
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                raise _ui_start_error(
                    path, host, port, _tail(log),
                    "子进程已退出；常见原因是端口被并发抢占、home 无写权限或依赖缺失。",
                )
            if _http_ok(host, port):
                ready = True
                break
            time.sleep(0.2)
        if not ready:
            _stop_pid(proc.pid, timeout=3.0)
            raise _ui_start_error(
                path, host, port, _tail(log),
                "进程已拉起但端口一直无响应，通常是被安全软件拦截或绑定地址不可用。",
            )
        url = _url(host, port)
        _write_state(path, {
            "pid": proc.pid,
            "host": host,
            "port": port,
            "url": url,
            "workspace": WORKSPACE,
            "home": str(path),
            "log": str(log),
            "started_at": _now(),
        })
        if not no_browser:
            _open_browser(url)
        if json_out:
            _print_json({"ok": True, "home": str(path), "workspace": WORKSPACE,
                         "running": True, "reused": False, "port": port, "url": url,
                         "pid": proc.pid, "admin_created": info["admin_created"],
                         "password": info["password"], "consent": info["status"],
                         "users": info["users"]})
        else:
            _print_summary(info, url=url, ui_running=True, pid=proc.pid, port=port,
                           no_ui=False, log=log)
        return 0
    except StartupError as exc:
        try:
            sys.stdout.flush()
        except Exception:  # noqa: BLE001
            pass
        print(str(exc.human), file=sys.stderr)
        return 2


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url, new=2, autoraise=True)
    except Exception:  # noqa: BLE001 —— 无桌面环境（容器/SSH）时忽略
        pass


def run_down(home: str | Path | None = None, *, json_out: bool = False) -> int:
    """停止本工作区由 ``up`` 拉起的 UI 进程；幂等。"""
    _ensure_stdio()
    path = resolve_home(home)
    try:
        current = inspect(path)
        pid = current["pid"]
        if not current["state"]:
            if json_out:
                _print_json({"ok": True, "home": str(path), "running": False,
                             "stopped": False, "reason": "no-state"})
            else:
                print(f"未运行：{path} 没有记录中的 UI 进程（幂等；可重复执行）。")
                if _http_ok(DEFAULT_HOST, DEFAULT_PORT):
                    print(f"提示：{DEFAULT_PORT} 上有控制台在响应，但不是本工作区 up 拉起的"
                          "（没有 pid 文件）；请在启动它的终端按 Ctrl+C 停止。")
            return 0

        if not current["alive"]:
            _clear_state(path)
            if json_out:
                _print_json({"ok": True, "home": str(path), "running": False,
                             "stopped": False, "reason": "stale-state", "pid": pid})
            else:
                print(f"未运行：残留状态文件已清理（pid {pid} 已退出）。")
            return 0

        image = _pid_image(pid)
        owns = current["http"] or _looks_like_python(image)
        if not owns:
            _clear_state(path)
            msg = (f"未终止 pid {pid}（镜像 {image or '未知'} 不是本工作区拉起的 python 进程）；"
                   "状态文件已清理。")
            if json_out:
                _print_json({"ok": False, "home": str(path), "running": True,
                             "stopped": False, "reason": "not-ours", "pid": pid})
            else:
                print(msg, file=sys.stderr)
            return 1

        stopped = _stop_pid(pid)
        if not stopped and current.get("port") and not _http_ok(
                current.get("host") or DEFAULT_HOST, int(current["port"])):
            # Process table can briefly show a zombie after SIGKILL; if the
            # console port is already closed, the UI is stopped for our purpose.
            stopped = True
        _clear_state(path)
        if not stopped:
            raise StartupError(_human(
                "E113", "UI 进程未能停止",
                f"pid {pid} 在超时后仍然存活。",
                "进程可能卡在内核态，或被安全软件保护。",
                f"手动结束：Windows: taskkill /PID {pid} /T /F；"
                f"类 Unix: kill -9 {pid}；随后重跑 inkblade down 清理状态。",
            ))
        if json_out:
            _print_json({"ok": True, "home": str(path), "running": False,
                         "stopped": True, "pid": pid, "port": current["port"]})
        else:
            print(f"已停止：pid {pid}（端口 {current['port']} 已释放）。")
        return 0
    except StartupError as exc:
        print(str(exc.human), file=sys.stderr)
        return 2


def _dir_size(path: Path) -> int:
    total = 0
    try:
        for p in path.rglob("*"):
            try:
                if p.is_file():
                    total += p.stat().st_size
            except OSError:
                continue
    except OSError:
        return total
    return total


def run_status(home: str | Path | None = None, *, json_out: bool = False) -> int:
    """查看 UI 进程与工作区状态；不修改任何文件。"""
    _ensure_stdio()
    path = resolve_home(home)
    current = inspect(path)
    initialized = (path / "users.json").exists() or (path / "evidence" / WORKSPACE).is_dir()
    info: dict[str, Any] = {}
    user_roles: dict[str, str] = {}
    if initialized:
        try:
            info = _workspace_info(path)
        except Exception:  # noqa: BLE001 —— 状态查询不应因坏文件失败
            info = {}
        try:
            from .core.users import UserStore

            user_roles = UserStore(path / "users.json").roles()
        except Exception:  # noqa: BLE001
            user_roles = {}

    if json_out:
        state = current["state"]
        _print_json({
            "ok": True,
            "home": str(path),
            "initialized": initialized,
            "running": current["running"],
            "pid": current["pid"] if current["alive"] else 0,
            "port": current["port"],
            "url": str(state.get("url") or _url(current["host"], current["port"]))
            if state else "",
            "workspace": WORKSPACE,
            "consent": info.get("status", "absent"),
            "fields": info.get("fields", {}),
            "users": user_roles,
            "runs": info.get("runs", 0),
            "bytes": _dir_size(path / "evidence" / WORKSPACE) if initialized else 0,
        })
        return 0

    print(f"InkBlade status — {path}")
    print("=" * 60)
    if not initialized:
        print(f"工作区 : 尚未初始化（{path}）")
        print("UI     : 未运行")
        print("下一步 : inkblade up（默认在 ./inkblade-workspace 初始化并启动）")
        return 0

    if current["running"]:
        state = current["state"]
        shown = state.get("url") or _url(current["host"], current["port"])
        print(f"UI     : 运行中（pid {current['pid']}）{shown}")
        print(f"         日志：{state.get('log') or _log_path(path)}")
        print(f"         启动于：{state.get('started_at') or '-'}")
    elif current["alive"]:
        print(f"UI     : 进程存活但端口无响应（pid {current['pid']}，端口 {current['port']}）")
        print("         处理：inkblade down 后重跑 inkblade up")
    elif current["state"]:
        print(f"UI     : 未运行（残留状态 pid {current['pid']} 已退出；下次 up 会自动清理）")
    else:
        print("UI     : 未运行（inkblade up 启动）")

    fields = info.get("fields") or {}
    window = fields.get("window") or {}
    print(f"工作区 : {WORKSPACE}")
    print(f"授权   : {info.get('status', 'absent')}"
          f"（{fields.get('level', '-')}；"
          f"{', '.join(fields.get('namespaces') or []) or '-'} / "
          f"{', '.join(fields.get('cidrs') or []) or '-'}；"
          f"{window.get('start', '?')} → {window.get('end', '?')}）")
    print(f"用户   : {', '.join(f'{n}({r})' for n, r in user_roles.items()) or '（无）'}")
    size = _dir_size(path / "evidence" / WORKSPACE)
    print(f"证据   : {int(info.get('runs') or 0)} 个 run；{size / 1024 / 1024:.1f} MB")
    if current["running"]:
        print("下一步 : inkblade down 停止；inkblade demo 生成样例；inkblade doctor 自检")
    else:
        print("下一步 : inkblade up 启动；inkblade demo 生成样例；inkblade doctor 自检")
    return 0


def _print_json(doc: dict[str, Any]) -> None:
    print(json.dumps(doc, ensure_ascii=False, indent=2, default=str))
