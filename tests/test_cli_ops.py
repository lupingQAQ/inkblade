"""终审 Minor#7：CLI 补齐 run/execute/rollback/abort/report/rules/export 与退出码 91 落点。

退出码契约：
- 0  成功；
- 2  用法/未知对象/参数错误；
- 91 授权闸门拒绝（ExecutionLocked / BackupGateRefused / ZerodayLocked / 紧急停止）；
- 3  rollback 存在 failed 项（需人工介入）。
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.backup import BackupManager
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import init_roe

REPO = Path(__file__).resolve().parents[1]
PY = sys.executable
CHAINS = REPO / "inkblade" / "chains"


def _cli(home: Path, *args: str, timeout: int = 120):
    return subprocess.run([PY, "-m", "inkblade", "--home", str(home), *args],
                          cwd=str(REPO), capture_output=True, timeout=timeout,
                          env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"})


def _module(root: Path, key: str, *, writes=False, fail=False, min_level="利用验证"):
    d = root / "modules" / key
    d.mkdir(parents=True, exist_ok=True)
    meta = {"key": key, "name": {"zh": key, "en": key}, "series": "横向利用",
            "description": "t", "min_level": min_level, "writes": writes, "requires": []}
    (d / "module.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    steps = ([{"id": "boom", "op": "fs", "action": "read",
               "path": str(root / "missing-boom.txt"), "save": "boom"}] if fail else
             [{"id": "noop", "op": "fs", "action": "stat", "path": "/", "save": "noop"}])
    template = {
        "schema": "inkblade-probe-template-v1", "key": key, "version": "1.0.0",
        "meta": {"name": meta["name"], "series": meta["series"],
                 "min_level": min_level, "writes": writes, "requires": []},
        "steps": steps, "findings": [],
    }
    if writes:
        template["modes"] = {"probe_only": True, "backup_write": True,
                             "requires_backup": True}
    (d / "template.json").write_text(json.dumps(template, ensure_ascii=False),
                                     encoding="utf-8")


class TestCliOps(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.store = EvidenceStore(self.home, workspace="local-lab")
        init_roe(self.store, fields={
            "level": "利用验证", "namespaces": ["train", "infer"],
            "cidrs": ["127.0.0.0/8", "10.1.0.0/16"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    def _out(self, r):
        return r.stdout.decode("utf-8", "replace")

    def _err(self, r):
        return r.stderr.decode("utf-8", "replace")

    # ---------- run ----------
    def test_run_success_returns_json_and_lands_step(self):
        _module(self.home, "probe-cli")
        r = _cli(self.home, "run", "--module", "probe-cli",
                 "--params", json.dumps({"host": "127.0.0.1"}),
                 "--actor", "tester", "--role", "tester")
        self.assertEqual(r.returncode, 0, self._err(r))
        body = json.loads(self._out(r))
        self.assertEqual(body["step"], "probe-cli")
        db = (self.home / "evidence" / "local-lab" / body["run"] / "evidence.db")
        self.assertTrue(db.is_file())

    def test_run_accepts_params_file(self):
        _module(self.home, "probe-cli")
        pfile = self.home / "params.json"
        pfile.write_text(json.dumps({"host": "127.0.0.2"}), encoding="utf-8")
        r = _cli(self.home, "run", "--module", "probe-cli", "--params", "@" + str(pfile),
                 "--actor", "tester", "--role", "tester")
        self.assertEqual(r.returncode, 0, self._err(r))

    def test_run_backup_gate_exit_91(self):
        _module(self.home, "writes-cli", writes=True)
        r = _cli(self.home, "run", "--module", "writes-cli",
                 "--params", json.dumps({"host": "127.0.0.1"}),
                 "--actor", "tester", "--role", "tester")
        self.assertEqual(r.returncode, 91, self._err(r))
        self.assertIn("备份回执", self._err(r))

    def test_run_out_of_scope_exit_91(self):
        _module(self.home, "probe-cli")
        r = _cli(self.home, "run", "--module", "probe-cli",
                 "--params", json.dumps({"host": "10.9.9.9"}),
                 "--actor", "tester", "--role", "tester")
        self.assertEqual(r.returncode, 91, self._err(r))
        self.assertIn("不在授权范围", self._err(r))

    def test_run_unknown_module_exit_2(self):
        r = _cli(self.home, "run", "--module", "nope", "--params", "{}")
        self.assertEqual(r.returncode, 2)

    # ---------- execute ----------
    def test_execute_dry_run_chain(self):
        r = _cli(self.home, "execute", "--chain", "flat-network-admin-plane-weight-poison",
                 "--dry-run", "--chains-dir", str(CHAINS), "--role", "lead", "--actor", "lead")
        self.assertEqual(r.returncode, 0, self._err(r))
        body = json.loads(self._out(r))
        self.assertEqual(body["chain"], "flat-network-admin-plane-weight-poison")
        self.assertIn(body["verdict"], ("成立", "部分成立", "不成立"))
        self.assertTrue(body["steps"])
        self.assertTrue(any(s.get("writes") for s in body["steps"]))

    def test_execute_unknown_chain_exit_2(self):
        r = _cli(self.home, "execute", "--chain", "no-such-chain", "--dry-run",
                 "--chains-dir", str(CHAINS))
        self.assertEqual(r.returncode, 2)

    # ---------- rollback ----------
    def test_rollback_reports_receipt_and_restores(self):
        run = self.store.create_run("rb-cli")
        victim = self.home / "victim.txt"
        victim.write_text("original", encoding="utf-8")
        bm = BackupManager(self.store, run)
        bm.snapshot("step-cli", [{"kind": "file", "path": str(victim)}])
        victim.write_text("tampered", encoding="utf-8")

        r = _cli(self.home, "rollback", "--run", "rb-cli", "--step", "step-cli")
        self.assertEqual(r.returncode, 0, self._err(r))
        receipt = json.loads(self._out(r))
        self.assertEqual(receipt["restored"], 1)
        self.assertEqual(receipt["failed"], 0)
        self.assertEqual(victim.read_text(encoding="utf-8"), "original")

    def test_rollback_missing_run_exit_2(self):
        r = _cli(self.home, "rollback", "--run", "ghost", "--step", "s")
        self.assertEqual(r.returncode, 2)

    # ---------- abort ----------
    def test_abort_blocks_then_clear_resumes(self):
        _module(self.home, "probe-cli")
        r = _cli(self.home, "abort", "--workspace", "local-lab", "--actor", "lead")
        self.assertEqual(r.returncode, 0, self._err(r))
        abort_file = self.home / "evidence" / "local-lab" / "abort.json"
        self.assertTrue(abort_file.is_file())
        doc = json.loads(abort_file.read_text(encoding="utf-8"))
        self.assertTrue(doc["requested"])
        self.assertEqual(doc["actor"], "lead")

        blocked = _cli(self.home, "run", "--module", "probe-cli",
                       "--params", json.dumps({"host": "127.0.0.1"}),
                       "--actor", "tester", "--role", "tester")
        self.assertEqual(blocked.returncode, 91, self._err(blocked))
        self.assertIn("紧急停止", self._err(blocked))

        cleared = _cli(self.home, "abort", "--workspace", "local-lab", "--clear",
                       "--actor", "lead")
        self.assertEqual(cleared.returncode, 0, self._err(cleared))
        ok = _cli(self.home, "run", "--module", "probe-cli",
                  "--params", json.dumps({"host": "127.0.0.1"}),
                  "--actor", "tester", "--role", "tester")
        self.assertEqual(ok.returncode, 0, self._err(ok))

    # ---------- report ----------
    def test_report_writes_markdown(self):
        run = self.store.create_run("report-cli")
        run.add_step("s1", "probe", {"k": "v"}, "summary")
        run.add_finding("s1", "high", "权重可写", "detail body")
        out = self.home / "out" / "pentest.md"
        r = _cli(self.home, "report", "--run", "report-cli", "--kind", "pentest",
                 "--lang", "zh", "--out", str(out))
        self.assertEqual(r.returncode, 0, self._err(r))
        text = out.read_text(encoding="utf-8")
        self.assertIn("渗透测试报告", text)
        self.assertIn("权重可写", text)

    def test_report_bad_kind_exit_2(self):
        r = _cli(self.home, "report", "--run", "x", "--kind", "nope")
        self.assertEqual(r.returncode, 2)

    # ---------- rules ----------
    def test_rules_generate_then_validate(self):
        pack = self.home / "rules-pack"
        gen = _cli(self.home, "rules", "generate", "--chains-dir", str(CHAINS),
                   "--out", str(pack))
        self.assertEqual(gen.returncode, 0, self._err(gen))
        self.assertTrue((pack / "mapping.json").is_file())
        body = json.loads(self._out(gen))
        self.assertGreaterEqual(body["rules"], 1)
        self.assertGreaterEqual(body["chains"], 1)

        val = _cli(self.home, "rules", "validate", "--pack", str(pack))
        self.assertEqual(val.returncode, 0, self._err(val))
        matrix = json.loads(self._out(val))
        self.assertTrue(matrix["ok"], matrix.get("summary"))
        self.assertEqual(matrix["summary"]["missed"], 0)

    # ---------- export ----------
    def test_export_sarif(self):
        run = self.store.create_run("export-cli")
        run.add_step("s1", "probe", {"k": "v"}, "summary")
        run.add_finding("s1", "high", "权重可写", "detail body")
        out = self.home / "out" / "findings.sarif"
        r = _cli(self.home, "export", "--run", "export-cli", "--format", "sarif",
                 "--out", str(out))
        self.assertEqual(r.returncode, 0, self._err(r))
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])


if __name__ == "__main__":
    unittest.main()
