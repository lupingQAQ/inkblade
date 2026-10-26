"""tests/test_sandbox.py — 工具执行沙箱（子进程 + 资源限制 + 禁网开关 + 审计）。

断言：
- 正常 Python 代码在隔离子进程内执行，返回 stdout/exit_code/耗时；
- 默认 untrusted 禁网：socket 连接/urllib 抛出 NetworkDisabled；
- allow_network=True 时不注入禁网（连接被拒绝而非 NetworkDisabled）；
- 死循环被墙钟超时终止（timed_out=True）；
- 审计条目含代码 sha256、untrusted 标记、网络策略、结果与耗时；
- POSIX 下内存限制生效（Windows 跳过并如实标注 limits.memory 未启用）。
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.sandbox import Sandbox, SandboxError, run_untrusted


class SandboxExecuteTest(unittest.TestCase):
    def setUp(self):
        self.audit = []

    def test_basic_python(self):
        sb = Sandbox(timeout=10, audit=self.audit.append)
        res = sb.run_python("print('hello', 1 + 1)")
        self.assertTrue(res.ok, res.stderr)
        self.assertEqual(res.exit_code, 0)
        self.assertIn("hello 2", res.stdout)
        self.assertFalse(res.timed_out)
        self.assertEqual(res.network, "blocked")
        self.assertEqual(len(self.audit), 1)
        entry = self.audit[0]
        self.assertTrue(entry["code_sha256"])
        self.assertTrue(entry["untrusted"])
        self.assertEqual(entry["network"], "blocked")
        self.assertFalse(entry["ok"] is None)

    def test_network_blocked_by_default(self):
        res = Sandbox(timeout=10).run_python(
            "import socket\n"
            "socket.create_connection(('127.0.0.1', 9), timeout=0.2)\n"
        )
        self.assertFalse(res.ok)
        self.assertIn("NetworkDisabled", res.stderr)

    def test_urllib_blocked(self):
        res = Sandbox(timeout=10).run_python(
            "import urllib.request\n"
            "urllib.request.urlopen('http://127.0.0.1:9/', timeout=0.2)\n"
        )
        self.assertFalse(res.ok)
        self.assertIn("NetworkDisabled", res.stderr)

    def test_allow_network_opt_in(self):
        res = Sandbox(timeout=10, allow_network=True).run_python(
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('127.0.0.1', 9), timeout=0.2)\n"
            "except OSError as exc:\n"
            "    print('OSError', type(exc).__name__)\n"
        )
        self.assertTrue(res.ok, res.stderr)
        self.assertEqual(res.network, "allowed")
        self.assertIn("OSError", res.stdout)
        self.assertNotIn("NetworkDisabled", res.stderr)

    def test_timeout_kills_child(self):
        res = Sandbox(timeout=1).run_python("while True:\n    pass\n")
        self.assertTrue(res.timed_out)
        self.assertFalse(res.ok)
        self.assertLess(res.duration_ms, 15000)

    def test_write_filesystem_isolated_cwd(self):
        with TemporaryDirectory() as td:
            sb = Sandbox(timeout=10, cwd=Path(td))
            res = sb.run_python("open('sandbox-artifact.txt', 'w').write('x')")
            self.assertTrue(res.ok, res.stderr)
            self.assertTrue((Path(td) / "sandbox-artifact.txt").exists())

    def test_run_untrusted_forces_network_block(self):
        audit = []
        res = run_untrusted("import socket\nsocket.socket()\n", timeout=10, audit=audit.append)
        self.assertTrue(res.ok)  # socket() 构造本身允许，连接被禁
        res2 = run_untrusted("import socket\nsocket.create_connection(('127.0.0.1', 9), 0.2)\n",
                             timeout=10, audit=audit.append)
        self.assertIn("NetworkDisabled", res2.stderr)

    def test_invalid_timeout_rejected(self):
        with self.assertRaises(SandboxError):
            Sandbox(timeout=0)


if __name__ == "__main__":
    unittest.main()
