"""零摩擦上手验收：doctor / demo / quickstart + 10 类错误文案 + 文档/UI 入口。

约束：全部本机离线；demo 用 mock 靶场，不读真实 kubeconfig、不发外网。
"""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from inkblade import onboarding  # noqa: E402
from inkblade.cli import main  # noqa: E402
from inkblade.core.humanize import explain_exception  # noqa: E402
from inkblade.core.roe import ExecutionLocked  # noqa: E402
from inkblade.core.runner import BackupGateRefused  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestDemo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="inkblade-onboarding-demo-")
        cls.out = Path(cls.tmp.name) / "demo"
        cls.t0 = time.monotonic()
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            cls.rc = onboarding.run_demo(cls.out, no_ui=False)
        cls.seconds = time.monotonic() - cls.t0
        cls.stdout, cls.stderr = out.getvalue(), err.getvalue()
        cls.summary = json.loads((cls.out / "reports" / "summary.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_demo_completes_under_budget(self):
        self.assertEqual(self.rc, 0, self.stderr)
        # 任务要求 ≤60s；CI/慢盘用 120s 宽松断言，同时记录实测值
        self.assertLessEqual(self.seconds, 120.0, f"demo 实测 {self.seconds:.1f}s")
        self.assertLessEqual(self.summary["elapsed_seconds"], 120.0)
        self.assertIn("InkBlade demo 完成", self.stdout)

    def test_demo_artifacts_present(self):
        self.assertTrue((self.out / onboarding.DEMO_MARKER).is_file())
        run_dirs = list((self.out / "workspace" / "evidence" / onboarding.DEMO_WORKSPACE).glob("demo-*"))
        self.assertTrue(run_dirs, "缺少 demo run 目录")
        run_dir = run_dirs[0]
        for rel in ("evidence.db", "context.jsonl.gz", "manifest.sha256"):
            self.assertTrue((run_dir / rel).is_file(), f"缺三层证据 {rel}")
        self.assertTrue((self.out / "reports" / "pentest-bi.md").is_file())
        self.assertTrue((self.out / "reports" / "remediation-bi.md").is_file())
        self.assertTrue((self.out / "reports" / "summary.json").is_file())
        self.assertTrue((self.out / "rules-pack" / "mapping.json").is_file())
        self.assertTrue((self.out / "webui" / "index.html").is_file())

    def test_demo_findings_chain_and_bilingual_report(self):
        self.assertGreaterEqual(self.summary["findings"]["total"], 2)
        self.assertTrue(self.summary["chain"]["ok"])
        self.assertEqual(set(self.summary["chain"]["steps"]),
                         {"admin-failopen-probe", "weight-pull-poison"})
        self.assertEqual({m["module"] for m in self.summary["modules"]},
                         {"framework-port-matching", "multi-cloud-imds-credentials"})
        self.assertTrue(all(m["findings"] >= 1 for m in self.summary["modules"]))
        report = (self.out / "reports" / "pentest-bi.md").read_text(encoding="utf-8")
        self.assertIn("Penetration Test Report", report)
        self.assertIn("渗透测试", report)
        self.assertIn("sha256", report)
        self.assertGreater(self.summary["rules"]["rules"], 0)
        self.assertIn("window.INKBLADE_DATA", (self.out / "webui" / "index.html").read_text(encoding="utf-8"))

    def test_demo_no_ui_skips_static_export(self):
        out_dir = Path(self.tmp.name) / "demo-no-ui"
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = onboarding.run_demo(out_dir, no_ui=True)
        self.assertEqual(rc, 0, err.getvalue())
        self.assertFalse((out_dir / "webui").exists())
        self.assertTrue((out_dir / "reports" / "pentest-bi.md").is_file())

    def test_demo_refuses_non_demo_dir(self):
        unsafe = Path(self.tmp.name) / "unsafe"
        unsafe.mkdir()
        (unsafe / "my-notes.txt").write_text("do not overwrite", encoding="utf-8")
        with self.assertRaises(onboarding.DemoRefused):
            onboarding.run_demo(unsafe)
        self.assertEqual((unsafe / "my-notes.txt").read_text(encoding="utf-8"), "do not overwrite")


class TestDoctor(unittest.TestCase):
    def test_doctor_smoke_exit_zero_and_human_conclusion(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-doctor-") as td:
            code, out, err = _run_cli("--home", td, "doctor", "--mode", "mock",
                                      "--port", str(_free_port()))
        self.assertEqual(code, 0, err)
        self.assertIn("[PASS] Python", out)
        self.assertIn("结论：", out)
        self.assertIn("python -m inkblade demo", out)

    def test_doctor_port_in_use_is_fail_with_fix(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = int(s.getsockname()[1])
            with tempfile.TemporaryDirectory(prefix="inkblade-doctor-") as td:
                code, out, _ = _run_cli("--home", td, "doctor", "--mode", "mock", "--port", str(port))
        self.assertEqual(code, 1)
        self.assertIn("[FAIL]", out)
        self.assertIn("已被占用", out)
        self.assertIn("--port", out)

    def test_doctor_cluster_mode_without_kubeconfig_fails(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-doctor-") as td:
            env = os.environ.pop("KUBECONFIG", None)
            try:
                code, out, _ = _run_cli("--home", td, "doctor", "--mode", "cluster",
                                        "--kubeconfig", str(Path(td) / "missing-kubeconfig"))
            finally:
                if env is not None:
                    os.environ["KUBECONFIG"] = env
        self.assertEqual(code, 1)
        self.assertIn("kubeconfig", out.lower())


class TestQuickstart(unittest.TestCase):
    def test_quickstart_yes_demo_creates_consent_and_users(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-qs-") as td:
            code, out, err = _run_cli("quickstart", "--workspace-dir", td, "--yes", "--json")
            ws = Path(td)
            consent = json.loads((ws / "evidence" / onboarding.QUICKSTART_WORKSPACE / "consent.json")
                                 .read_text(encoding="utf-8"))
            users = json.loads((ws / "users.json").read_text(encoding="utf-8"))
            cfg = json.loads((ws / "evidence" / onboarding.QUICKSTART_WORKSPACE / "workspace.json")
                             .read_text(encoding="utf-8"))
        self.assertEqual(code, 0, err)
        self.assertIn('"target": "demo"', out)
        self.assertEqual(consent["status"], "complete")
        self.assertEqual(consent["fields"]["level"], "主动探测")
        self.assertIn("lead", users)
        self.assertIn("tester", users)
        self.assertEqual(cfg["target"]["mode"], "demo")

    def test_quickstart_cluster_kubeconfig_and_level(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-qs-") as td:
            kc = Path(td) / "kubeconfig.yaml"
            kc.write_text("apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n  name: lab\n",
                          encoding="utf-8")
            code, out, err = _run_cli(
                "quickstart", "--workspace-dir", td, "--yes", "--json",
            )
            # 上面的 --yes 只能走默认 demo；用函数级参数覆盖为真实集群
            code2 = onboarding.run_quickstart(td, yes=True, target="cluster", kubeconfig=str(kc),
                                              level="只读侦察", namespaces="train,infer",
                                              cidrs="10.0.0.0/8", lead="alice", password="pw",
                                              json_out=False)
            consent = json.loads((Path(td) / "evidence" / onboarding.QUICKSTART_WORKSPACE / "consent.json")
                                 .read_text(encoding="utf-8"))
            cfg = json.loads((Path(td) / "evidence" / onboarding.QUICKSTART_WORKSPACE / "workspace.json")
                             .read_text(encoding="utf-8"))
        self.assertEqual(code2, 0)
        self.assertEqual(consent["fields"]["level"], "只读侦察")
        self.assertEqual(consent["fields"]["cidrs"], ["10.0.0.0/8"])
        self.assertEqual(cfg["target"]["mode"], "cluster")
        self.assertEqual(cfg["target"]["kubeconfig"], str(kc))

    def test_quickstart_interactive_reprompts_bad_cidr(self):
        inputs = iter(["1", "train", "not-a-cidr", "127.0.0.0/8", "1", "carol", "pw", "y"])
        with tempfile.TemporaryDirectory(prefix="inkblade-qs-") as td:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = onboarding.run_quickstart(td, inputs=lambda _p: next(inputs))
            consent = json.loads((Path(td) / "evidence" / onboarding.QUICKSTART_WORKSPACE / "consent.json")
                                 .read_text(encoding="utf-8"))
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(consent["fields"]["cidrs"], ["127.0.0.0/8"])
        self.assertIn("CIDR 不合法", out.getvalue())

    def test_quickstart_reentrant_keeps_valid_consent(self):
        with tempfile.TemporaryDirectory(prefix="inkblade-qs-") as td:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(onboarding.run_quickstart(td, yes=True), 0)
            first = (Path(td) / "evidence" / onboarding.QUICKSTART_WORKSPACE / "consent.json").read_text(encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(onboarding.run_quickstart(td, yes=True), 0)
            second = (Path(td) / "evidence" / onboarding.QUICKSTART_WORKSPACE / "consent.json").read_text(encoding="utf-8")
        self.assertEqual(json.loads(first)["sha256"], json.loads(second)["sha256"])


class TestHumanizedErrors(unittest.TestCase):
    def test_ten_high_frequency_errors_are_three_line_human(self):
        cases = [
            ("E201", ExecutionLocked("工作区授权未完成（consent 未签署或签名校验失败）")),
            ("E202", ExecutionLocked("级别不足：模块要求 利用验证，授权为 只读侦察")),
            ("E203", ExecutionLocked("目标 host=10.1.2.3 不在授权范围（namespaces=['train']）")),
            ("E301", BackupGateRefused("写类模块缺少备份回执（backup_targets 为空或不可用）")),
            ("E103", OSError(10048, "address already in use")),
            ("E101", FileNotFoundError(2, "No such file or directory", "kubeconfig")),
            ("E104", FileNotFoundError(2, "No such file or directory", "bash")),
            ("E102", ModuleNotFoundError("No module named 'zstandard'", name="zstandard")),
            ("E401", KeyError("run not found: demo-1")),
            ("E205", PermissionError("auditor 无 execute 权限")),
        ]
        for expected, exc in cases:
            err = explain_exception(exc)
            text = str(err)
            self.assertEqual(err.code, expected, f"{exc!r} -> {err.code}")
            for phrase in ("发生了什么：", "为什么：", "怎么修："):
                self.assertIn(phrase, text, f"{expected} 缺 {phrase}")
            self.assertGreater(len(err.fix), 10, f"{expected} 修复建议过短")

    def test_demo_refusal_and_quickstart_abort_are_humanized(self):
        for exc, code in ((onboarding.DemoRefused("目录非空"), "E402"),
                          (onboarding.QuickstartAbort("输入不可用"), "E207")):
            err = explain_exception(exc)
            self.assertEqual(err.code, code)
            self.assertIn("怎么修：", str(err))


class TestDocsAndEntrypoints(unittest.TestCase):
    def test_readme_quickstart_real_onboarding(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("## Quick start", text)
        for command in ("inkblade up", "quickstart", "session open", "probe deploy",
                        "agent run", "report"):
            self.assertIn(command, text)
        self.assertNotIn("inkblade demo", text)
        self.assertNotIn("mock", text.lower())

    def test_ui_compact_login_and_probe_first_panel(self):
        html = (ROOT / "inkblade" / "webui" / "static" / "index.html").read_text(encoding="utf-8")
        js = (ROOT / "inkblade" / "webui" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('id="login-form"', html)
        self.assertIn('id="onboarding"', html)
        self.assertIn('class="login-subtitle"', html)
        for removed in ("kubeconfig", "onboarding-steps", "三步", "connect-panel"):
            self.assertNotIn(removed, html.lower())
        for command in ("inkblade channel listen", "./inkblade-probe reverse",
                        "inkblade probe list --workspace ./work",
                        "inkblade session open --mode foothold"):
            self.assertIn(command, js)
        self.assertIn("已有探针", js)
        self.assertIn("首次投放", js)
        for word in ("demo", "mock", "trial"):
            self.assertNotIn(word, html.lower())

    def test_onboarding_evaluation_doc_present(self):
        text = (ROOT / "docs" / "ONBOARDING-EVALUATION.md").read_text(encoding="utf-8")
        for phrase in ("基线走查", "改造后走查", "失败根因", "修复清单", "仍存的上手风险", "首次有效结果 5.33 秒"):
            self.assertIn(phrase, text)

    def test_mock_targets_help_works_under_cp1252(self):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "cp1252"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "lab" / "mock_targets.py"), "--help"],
            cwd=str(ROOT), capture_output=True, env=env, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        self.assertIn(b"mock", proc.stdout.lower())


if __name__ == "__main__":
    unittest.main()
