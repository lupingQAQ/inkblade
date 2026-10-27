# -*- coding: utf-8 -*-
"""一条命令启动验收：up/start、down、status、安装脚本语法与 QUICKSTART 文档。

约束：全部本机离线；真实 UI 只监听 127.0.0.1 的随机空闲端口，测试结束必须 down。
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
SCRIPTS = ROOT / "scripts"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from inkblade import startup  # noqa: E402
from inkblade.cli import main  # noqa: E402

PASSWORD_RE = re.compile(r"admin / (InkBlade-[A-Za-z0-9]+)")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
    except SystemExit as exc:  # argparse --help / 用法错误
        code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def _http(url: str, timeout: float = 6.0):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return opener.open(url, timeout=timeout)


def _port_closed(port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return True
        time.sleep(0.2)
    return False


def _find_bash() -> str | None:
    """找一个真正能执行的 bash（Windows 的 WSL 存根不算）。"""
    cands: list[str] = []
    found = shutil.which("bash")
    if found:
        cands.append(found)
    git = shutil.which("git")
    if git:
        try:
            exec_path = subprocess.run([git, "--exec-path"], capture_output=True,
                                       text=True, timeout=20).stdout.strip()
            if exec_path:
                p = Path(exec_path)
                for root in (p.parents[2] if len(p.parents) > 2 else p,
                             p.parents[1] if len(p.parents) > 1 else p):
                    cand = root / "bin" / "bash.exe"
                    if cand.is_file():
                        cands.append(str(cand))
        except (OSError, subprocess.SubprocessError):
            pass
    for base in (os.environ.get("ProgramFiles", ""),
                 os.environ.get("ProgramFiles(x86)", "")):
        if base:
            cands.append(str(Path(base) / "Git" / "bin" / "bash.exe"))
    for cand in cands:
        if not cand or not Path(cand).exists():
            continue
        try:
            probe = subprocess.run([cand, "-c", "echo bash-ok"],
                                   capture_output=True, text=True, timeout=25)
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0 and "bash-ok" in probe.stdout:
            return cand
    return None


class TestUpInit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="inkblade-up-init-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "ws"

    def test_first_run_initialises_and_prints_password_once(self):
        code, out, err = _run_cli("up", "--home", str(self.home), "--no-ui", "--no-browser")
        self.assertEqual(code, 0, err)
        self.assertIn("首次密码（只显示这一次，请立即保存）", out)
        match = PASSWORD_RE.search(out)
        self.assertIsNotNone(match, out)
        password = match.group(1)
        self.assertGreaterEqual(len(password), 16)

        users = json.loads((self.home / "users.json").read_text(encoding="utf-8"))
        self.assertIn("admin", users)
        self.assertNotIn(password, json.dumps(users), "明文密码不得落盘")

        consent = json.loads(
            (self.home / "evidence" / startup.WORKSPACE / "consent.json").read_text(encoding="utf-8")
        )
        self.assertEqual(consent["status"], "complete")
        self.assertEqual(consent["fields"]["cidrs"], ["127.0.0.0/8"])

        # 三条「下一步」
        for idx in ("  1. ", "  2. ", "  3. "):
            self.assertIn(idx, out)
        self.assertIn("UI     : 未启动（--no-ui）", out)
        self.assertIn("ui --port", out)

        # --no-ui 不写 pid 文件、不起进程
        self.assertFalse(startup._state_path(self.home).exists())

    def test_second_run_is_idempotent_and_never_reprints_password(self):
        code1, out1, err1 = _run_cli("up", "--home", str(self.home), "--no-ui", "--no-browser")
        self.assertEqual(code1, 0, err1)
        password = PASSWORD_RE.search(out1).group(1)
        users_before = (self.home / "users.json").read_bytes()
        consent_before = (self.home / "evidence" / startup.WORKSPACE / "consent.json").read_bytes()

        code2, out2, err2 = _run_cli("up", "--home", str(self.home), "--no-ui", "--no-browser")
        self.assertEqual(code2, 0, err2)
        self.assertNotIn(password, out2)
        self.assertNotIn("首次密码", out2)
        self.assertIn("密码只在首次显示，本次不重印", out2)
        self.assertIn("保留原有授权", out2)
        self.assertEqual((self.home / "users.json").read_bytes(), users_before)
        self.assertEqual(
            (self.home / "evidence" / startup.WORKSPACE / "consent.json").read_bytes(),
            consent_before,
        )

    def test_no_consent_skips_automatic_signing(self):
        code, out, err = _run_cli("up", "--home", str(self.home), "--no-ui",
                                  "--no-browser", "--no-consent")
        self.assertEqual(code, 0, err)
        self.assertIn("未签发（--no-consent）", out)
        self.assertFalse((self.home / "evidence" / startup.WORKSPACE / "consent.json").exists())

    def test_start_alias_and_home_precedence(self):
        code, out, err = _run_cli("start", "--home", str(self.home), "--no-ui", "--no-browser")
        self.assertEqual(code, 0, err)
        self.assertTrue((self.home / "users.json").exists())

        other = Path(self.tmp.name) / "ws-global"
        code, out, err = _run_cli("--home", str(other), "up", "--no-ui", "--no-browser")
        self.assertEqual(code, 0, err)
        self.assertTrue((other / "users.json").exists())
        self.assertIn(str(other.resolve()), out)

    def test_home_that_is_a_file_fails_with_human_error(self):
        blocker = Path(self.tmp.name) / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")
        code, out, err = _run_cli("up", "--home", str(blocker), "--no-ui", "--no-browser")
        self.assertEqual(code, 2)
        self.assertIn("[INKBLADE-E112]", err)
        for phrase in ("发生了什么：", "为什么：", "怎么修："):
            self.assertIn(phrase, err)


class TestPortConflict(unittest.TestCase):
    def test_port_in_use_fails_with_three_line_error(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-up-port-") as tmp:
            home = Path(tmp) / "ws"
            port = _free_port()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
                blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                blocker.bind(("127.0.0.1", port))
                blocker.listen(1)
                code, out, err = _run_cli("up", "--home", str(home), "--port", str(port),
                                          "--no-browser", "--wait", "2")
            self.assertEqual(code, 2)
            self.assertIn("[INKBLADE-E103]", err)
            for phrase in ("发生了什么：", "为什么：", "怎么修："):
                self.assertIn(phrase, err)
            self.assertIn("inkblade up --port", err)
            self.assertFalse(startup._state_path(home).exists())

    def test_no_ui_does_not_require_a_free_port(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-up-noport-") as tmp:
            home = Path(tmp) / "ws"
            port = _free_port()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
                blocker.bind(("127.0.0.1", port))
                blocker.listen(1)
                code, out, err = _run_cli("up", "--home", str(home), "--port", str(port),
                                          "--no-ui", "--no-browser")
            self.assertEqual(code, 0, err)
            self.assertIn("UI     : 未启动（--no-ui）", out)

    def test_invalid_port_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-up-badport-") as tmp:
            home = Path(tmp) / "ws"
            code, out, err = _run_cli("up", "--home", str(home), "--port", "70000",
                                      "--no-ui", "--no-browser")
            self.assertEqual(code, 2)
            self.assertIn("端口不合法", err)
            self.assertFalse(home.exists())


class TestLiveUi(unittest.TestCase):
    """真实拉起 UI：随机端口 → 登录 → status → down。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="inkblade-up-live-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "ws"
        self.port = _free_port()

    def _start(self) -> tuple[int, str, str]:
        code, out, err = _run_cli("up", "--home", str(self.home), "--port", str(self.port),
                                  "--no-browser", "--wait", "25")
        # 不论断言成败都要收尾，避免留下后台进程
        self.addCleanup(_run_cli, "down", "--home", str(self.home))
        return code, out, err

    def test_live_ui_login_status_and_down(self):
        code, out, err = self._start()
        self.assertEqual(code, 0, err)
        password = PASSWORD_RE.search(out).group(1)
        self.assertIn(f"http://127.0.0.1:{self.port}/", out)

        state = json.loads(startup._state_path(self.home).read_text(encoding="utf-8"))
        self.assertEqual(int(state["port"]), self.port)
        self.assertEqual(int(state["pid"]), startup.inspect(self.home)["pid"])
        self.assertTrue(startup.inspect(self.home)["running"])

        with _http(f"http://127.0.0.1:{self.port}/") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"InkBlade", resp.read(4096))

        payload = json.dumps({"name": "admin", "password": password}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/login", data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(body["role"], "admin")
        self.assertTrue(body["token"])

        code, out, err = _run_cli("status", "--home", str(self.home), "--json")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertTrue(doc["running"])
        self.assertEqual(doc["consent"], "complete")
        self.assertEqual(doc["users"], {"admin": "admin"})

        code, out, err = _run_cli("down", "--home", str(self.home))
        self.assertEqual(code, 0, err)
        self.assertIn("已停止", out)
        self.assertTrue(_port_closed(self.port), "down 后端口应释放")
        self.assertFalse(startup._state_path(self.home).exists())

        # 幂等：再 down 一次也是 0
        code, out, err = _run_cli("down", "--home", str(self.home))
        self.assertEqual(code, 0, err)
        self.assertIn("未运行", out)

    def test_up_reuses_running_instance(self):
        code, out, err = self._start()
        self.assertEqual(code, 0, err)
        password = PASSWORD_RE.search(out).group(1)

        code2, out2, err2 = _run_cli("up", "--home", str(self.home), "--port", str(self.port),
                                     "--no-browser", "--wait", "10")
        self.assertEqual(code2, 0, err2)
        self.assertNotIn(password, out2)
        self.assertIn("pid", out2)
        self.assertIn("下一步", out2)

    def test_foreground_serves_without_pid_file(self):
        """容器路径：up --foreground 在前台提供服务，不写 pid 文件。"""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.Popen(
            [PY, "-m", "inkblade", "up", "--home", str(self.home), "--port", str(self.port),
             "--foreground", "--no-browser"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace", env=env,
        )
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        deadline = time.time() + 30
        ready = False
        while time.time() < deadline and proc.poll() is None:
            try:
                with _http(f"http://127.0.0.1:{self.port}/", timeout=1) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:  # noqa: BLE001 —— 启动过程中连接会被拒绝
                pass
            time.sleep(0.2)
        if not ready:
            output = proc.stdout.read() if proc.poll() is not None else ""
            self.fail(f"foreground 未就绪（rc={proc.poll()}）：{output}")
        self.assertFalse(startup._state_path(self.home).exists(), "前台模式不写 pid 文件")
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
        self.assertTrue(_port_closed(self.port), "前台进程退出后端口应释放")


class TestStatusAndDown(unittest.TestCase):
    def test_status_on_missing_home_says_uninitialised(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-status-") as tmp:
            home = Path(tmp) / "missing"
            code, out, err = _run_cli("status", "--home", str(home))
            self.assertEqual(code, 0, err)
            self.assertIn("尚未初始化", out)
            self.assertFalse(home.exists(), "status 不应创建工作区")

    def test_down_without_state_is_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-down-") as tmp:
            home = Path(tmp) / "ws"
            code, out, err = _run_cli("down", "--home", str(home))
            self.assertEqual(code, 0, err)
            self.assertIn("未运行", out)
            code, out, err = _run_cli("down", "--home", str(home))
            self.assertEqual(code, 0, err)

    def test_stale_state_is_cleaned(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-stale-") as tmp:
            home = Path(tmp) / "ws"
            startup._write_state(home, {"pid": 999999, "host": "127.0.0.1",
                                        "port": _free_port(), "url": "http://127.0.0.1:1/"})
            code, out, err = _run_cli("down", "--home", str(home))
            self.assertEqual(code, 0, err)
            self.assertIn("残留状态文件已清理", out)
            self.assertFalse(startup._state_path(home).exists())


class TestInstallScripts(unittest.TestCase):
    def test_bash_scripts_parse(self):
        bash = _find_bash()
        if not bash:
            self.skipTest("没有可执行的 bash（Windows 需 Git Bash；WSL 存根不算）")
        for name in ("install.sh", "run-docker.sh"):
            path = SCRIPTS / name
            proc = subprocess.run([bash, "-n", str(path)], capture_output=True, text=True,
                                  timeout=60)
            self.assertEqual(proc.returncode, 0, f"{name}: {proc.stderr}")

    def test_install_sh_is_local_only(self):
        text = (SCRIPTS / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("curl ", text)
        self.assertNotIn("wget ", text)
        self.assertIn("inkblade up", text)
        self.assertIn("pip install", text)
        self.assertIn("--system", text)  # uv 分支
        self.assertIn("python", text)

    def test_powershell_script_parses(self):
        exe = shutil.which("pwsh") or shutil.which("powershell")
        if not exe:
            self.skipTest("没有 PowerShell")
        target = str(SCRIPTS / "install.ps1").replace("'", "''")
        script = (
            "$e=$null;$t=$null;"
            f"[void][System.Management.Automation.Language.Parser]::ParseFile('{target}',[ref]$t,[ref]$e);"
            "if ($e.Count -gt 0) { $e | ForEach-Object { $_.Message }; exit 1 } else { exit 0 }"
        )
        proc = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", script],
                              capture_output=True, text=True, timeout=90)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_docker_script_maps_port_and_volume(self):
        text = (SCRIPTS / "run-docker.sh").read_text(encoding="utf-8")
        for needle in ("docker run", "127.0.0.1:", ":8765", ":/data", "--foreground"):
            self.assertIn(needle, text)
        self.assertNotIn("curl ", text)


class TestCliWiring(unittest.TestCase):
    def test_help_lists_new_commands(self):
        code, out, err = _run_cli("--help")
        self.assertEqual(code, 0, err)
        for cmd in ("up", "down", "status"):
            self.assertIn(cmd, out)

    def test_up_output_is_probe_first(self):
        """探针优先：下一步只讲 probe/channel，不提示 kubeconfig 导入。"""
        with tempfile.TemporaryDirectory(prefix="inkblade-probe-first-") as tmp:
            home = Path(tmp) / "ws"
            code, out, err = _run_cli("up", "--home", str(home), "--no-ui", "--no-browser")
            self.assertEqual(code, 0, err)
            self.assertNotIn("kubeconfig", out.lower())
            self.assertNotIn("kubeconfig", err.lower())
            self.assertIn("probe list", out)
            self.assertIn("channel start", out)
            self.assertIn("inkblade down", out)

    def test_up_help_documents_defaults(self):
        code, out, err = _run_cli("up", "--help")
        self.assertEqual(code, 0, err)
        for flag in ("--home", "--port", "--no-ui", "--no-browser", "--foreground", "--no-consent"):
            self.assertIn(flag, out)


if __name__ == "__main__":
    unittest.main()
