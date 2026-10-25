"""CLI：trident privesc matrix|paths 与 trident objective plan 的机器可读输出。"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "lab" / "fixtures" / "privesc" / "rbac.json"
PY = sys.executable


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([PY, "-m", "trident", *args], cwd=REPO,
                          capture_output=True, timeout=60)


class TestPrivescCli(unittest.TestCase):
    def test_matrix_json(self):
        r = run_cli("privesc", "matrix", "--json")
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        doc = json.loads(r.stdout.decode("utf-8"))
        self.assertGreaterEqual(doc["summary"]["vectors"], 30)
        self.assertGreaterEqual(len(doc["vectors"]), 30)

    def test_paths_from_snapshot(self):
        r = run_cli("privesc", "paths", "--from",
                    "system:serviceaccount:privesc-lab:esc-sa",
                    "--snapshot", str(FIXTURE), "--json", "--limit", "3")
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        doc = json.loads(r.stdout.decode("utf-8"))
        self.assertTrue(doc["paths"], doc)
        self.assertIn("rbac-escalate-verb", doc["paths"][0]["vector_ids"])
        self.assertIn("cluster-admin", doc["explanation"])

    def test_explain_plain_text(self):
        r = run_cli("privesc", "paths", "--from",
                    "system:serviceaccount:privesc-lab:bind-sa",
                    "--snapshot", str(FIXTURE))
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        out = r.stdout.decode("utf-8")
        self.assertIn("rbac-bind-verb", out)
        self.assertIn("检测", out)

    def test_objective_plan_via_library(self):
        # objective CLI 由并行任务维护（kill-chain 7 阶段）；提权选路在 core.objective 中集成，
        # 这里直接验证库入口，避免与在途 CLI 参数冲突。
        from trident.core.objective import plan_objective
        from trident.core.privesc import load_snapshot

        plan = plan_objective("cluster-takeover", snapshot=load_snapshot(FIXTURE),
                              from_principal="system:serviceaccount:privesc-lab:esc-sa")
        self.assertEqual(plan["objective"], "cluster-takeover")
        self.assertIn("rbac-escalate-verb", plan["phases"][2]["selection"]["chosen"]["vector_ids"])

    def test_unknown_principal_is_human_error(self):
        r = run_cli("privesc", "paths", "--from", "nobody",
                    "--snapshot", str(FIXTURE))
        self.assertEqual(r.returncode, 2)
        err = r.stderr.decode("utf-8", "replace")
        self.assertIn("主体", err)


if __name__ == "__main__":
    unittest.main()
