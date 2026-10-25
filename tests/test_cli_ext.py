# -*- coding: utf-8 -*-
"""新 CLI 子命令烟测：JSON 输出/退出码契约；不触达真实目标。"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.roe import init_roe

PY = sys.executable
REPO = Path(__file__).resolve().parents[1]


def _run(home: Path, *args):
    return subprocess.run([PY, "-m", "trident", "--home", str(home), *args],
                          capture_output=True, timeout=40, cwd=str(REPO))


class TestCliExt(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.home = Path(self.tmp.name)
        store = EvidenceStore(self.home, workspace="local-lab")
        init_roe(store, {"level": "利用验证", "namespaces": ["ml"],
                         "cidrs": ["10.0.0.0/8"]})
        run = store.create_run("r1")
        run.add_step("sglang-admin-failopen", "cmd", {}, "ok")
        run.add_finding("sglang-admin-failopen", "high", "admin unauth", "d")

    def tearDown(self):
        self.tmp.cleanup()

    def test_read_only_json_commands(self):
        for args in (("notify", "channels"), ("template", "list"), ("calendar", "list"),
                     ("threads", "list"), ("graph", "list"), ("blackboard", "list"),
                     ("llm-pool", "status")):
            r = _run(self.home, *args)
            self.assertEqual(r.returncode, 0, f"{args}: {r.stderr.decode('utf-8', 'replace')}")
            json.loads(r.stdout.decode("utf-8", "replace"))

    def test_ci_gate_and_report(self):
        r = _run(self.home, "ci-gate", "--run", "r1", "--fail-on", "high")
        self.assertEqual(r.returncode, 2, r.stderr.decode("utf-8", "replace"))
        body = json.loads(r.stdout.decode("utf-8", "replace"))
        self.assertEqual(body["exit_code"], 2)
        out = self.home / "ctem.md"
        r = _run(self.home, "report-ctem", "--run", "r1", "--out", str(out))
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        self.assertIn("暴露验证", out.read_text(encoding="utf-8"))

    def test_credcheck_fixture(self):
        fixture = self.home / "cred.json"
        fixture.write_text(json.dumps({
            "credentials": [{"id": "c1", "kind": "aws", "tenant": "a",
                             "expected_tenant": "b"}],
            "probes": [{"credential_id": "c1", "ok": True, "tenant": "a",
                        "permissions": ["s3:GetObject"]}]}), encoding="utf-8")
        r = _run(self.home, "credcheck", "--fixture", str(fixture))
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        self.assertIn("credential", r.stdout.decode("utf-8", "replace"))


if __name__ == "__main__":
    unittest.main()
