"""终审 Important#3/#4/#5：范围接线 + 零日审计标记 + zeroday.enable 审计行。

- runner 对 ``params.host`` / ``params.target_ns`` / ``params.namespace`` 逐项做 in_scope，
  范围外一律 ExecutionLocked（并在 run 内留 refused-out-of-scope 审计行）；
- ``meta.private`` 模块的全部审计行（refused-no-backup / refused-out-of-scope /
  started / failed / success）标 ``is_zeroday=1``；
- ``zeroday.enable`` 成功与拒绝都写审计行（actor=操作者，lead 审批留痕）。
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import ExecutionLocked, init_roe
from inkblade.core.runner import BackupGateRefused, run_module
from inkblade.core.users import UserStore
from inkblade.core.zeroday import ZerodayLocked, enable, zeroday_enabled


def _fixture_module(root: Path, key: str, *, writes=False, fail=False, private=False,
                    min_level="利用验证"):
    d = root / "modules" / key
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "key": key, "name": {"zh": key, "en": key}, "series": "横向利用",
        "description": "t", "min_level": min_level, "writes": writes, "requires": [],
    }
    if private:
        meta["private"] = True
    (d / "module.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    steps = ([{"id": "boom", "op": "fs", "action": "read",
               "path": str(root / "missing-boom.txt"), "save": "boom"}] if fail else
             [{"id": "noop", "op": "fs", "action": "stat", "path": "/", "save": "noop"}])
    template = {
        "schema": "inkblade-probe-template-v1", "key": key, "version": "1.0.0",
        "meta": {"name": meta["name"], "series": meta["series"],
                 "min_level": min_level, "writes": writes, "requires": []},
        "steps": steps,
        "findings": ([{"id": "f", "sev": "high", "title": "demo", "detail": "x",
                       "when": "true"}] if not fail else []),
    }
    if writes:
        template["modes"] = {"probe_only": True, "backup_write": True,
                             "requires_backup": True}
    (d / "template.json").write_text(json.dumps(template, ensure_ascii=False),
                                     encoding="utf-8")


class TestRunnerScopeAndZerodayAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("lead", "x", "lead", ["local-lab"])
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.lead = users.verify("lead", "x")
        self.tester = users.verify("tester", "x")
        init_roe(self.store, fields={
            "level": "利用验证",
            "namespaces": ["train", "infer"],
            "cidrs": ["10.1.0.0/16", "127.0.0.0/8"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    # ---------- 范围接线 ----------
    def test_out_of_scope_host_locked(self):
        _fixture_module(self.root, "probe-host")
        run = self.store.create_run("scope-host")
        with self.assertRaises(ExecutionLocked) as cm:
            run_module(self.store, self.tester, "probe-host",
                       params={"host": "10.9.9.9"}, modules_dir=self.root / "modules", run=run)
        self.assertIn("不在授权范围", str(cm.exception))
        rows = run.query("SELECT action, result FROM actions ORDER BY id")
        self.assertEqual([tuple(r) for r in rows], [("execute", "refused-out-of-scope")])

    def test_in_scope_host_accepts_url_and_ip(self):
        _fixture_module(self.root, "probe-host")
        for host in ("10.1.2.3", "http://10.1.2.3:8080", "10.1.2.3:9000", "127.0.0.1"):
            with self.subTest(host=host):
                result = run_module(self.store, self.tester, "probe-host",
                                    params={"host": host}, modules_dir=self.root / "modules")
                self.assertEqual(result["step"], "probe-host")

    def test_out_of_scope_namespace_locked(self):
        _fixture_module(self.root, "probe-ns")
        for key in ("target_ns", "namespace"):
            with self.subTest(param=key):
                with self.assertRaises(ExecutionLocked):
                    run_module(self.store, self.tester, "probe-ns",
                               params={key: "prod"}, modules_dir=self.root / "modules")

    def test_in_scope_namespace_allowed(self):
        _fixture_module(self.root, "probe-ns")
        for params in ({"target_ns": "train"}, {"namespace": "infer"}):
            result = run_module(self.store, self.tester, "probe-ns", params=params,
                                modules_dir=self.root / "modules")
            self.assertEqual(result["step"], "probe-ns")

    def test_unrelated_params_not_scope_checked(self):
        """未声明 host/namespace 的模块不受影响（scope.json 的 namespaces 是白名单）。"""
        _fixture_module(self.root, "probe-plain")
        target = self.root / "plain.txt"
        result = run_module(self.store, self.tester, "probe-plain",
                            params={"target": str(target)}, modules_dir=self.root / "modules")
        self.assertEqual(result["step"], "probe-plain")

    # ---------- 审计行 is_zeroday ----------
    def test_private_module_all_actions_marked_zeroday(self):
        _fixture_module(self.root, "private-probe", private=True)
        enable(self.store, self.lead)
        run = self.store.create_run("zd-marks")
        run_module(self.store, self.tester, "private-probe", params={"host": "127.0.0.1"},
                   modules_dir=self.root / "modules", run=run)
        rows = run.query("SELECT action, result, is_zeroday FROM actions ORDER BY id")
        self.assertEqual(len(rows), 2, rows)  # started + success
        for action, result, flag in rows:
            self.assertEqual(flag, 1, f"{action}/{result} 未标零日")

    def test_private_module_failure_and_backup_refusal_marked(self):
        _fixture_module(self.root, "private-writes", private=True, writes=True)
        enable(self.store, self.lead)
        run = self.store.create_run("zd-refused")
        with self.assertRaises(BackupGateRefused):
            run_module(self.store, self.tester, "private-writes", params={"host": "127.0.0.1"},
                       modules_dir=self.root / "modules", run=run)
        rows = run.query("SELECT result, is_zeroday FROM actions ORDER BY id")
        self.assertEqual([tuple(r) for r in rows], [("refused-no-backup", 1)])

        _fixture_module(self.root, "private-boom", private=True, fail=True)
        run2 = self.store.create_run("zd-failed")
        with self.assertRaises(RuntimeError):
            run_module(self.store, self.tester, "private-boom", params={"host": "127.0.0.1"},
                       modules_dir=self.root / "modules", run=run2)
        rows2 = run2.query("SELECT result, is_zeroday FROM actions ORDER BY id")
        self.assertEqual([r[1] for r in rows2], [1, 1])
        self.assertTrue(str(rows2[-1][0]).startswith("failed:"))

    def test_public_module_actions_not_marked(self):
        _fixture_module(self.root, "public-probe")
        run = self.store.create_run("public")
        run_module(self.store, self.tester, "public-probe", params={"host": "127.0.0.1"},
                   modules_dir=self.root / "modules", run=run)
        rows = run.query("SELECT is_zeroday FROM actions")
        self.assertEqual([r[0] for r in rows], [0, 0])

    def test_out_of_scope_private_attempt_marked(self):
        _fixture_module(self.root, "private-scope", private=True)
        enable(self.store, self.lead)
        run = self.store.create_run("zd-scope")
        with self.assertRaises(ExecutionLocked):
            run_module(self.store, self.tester, "private-scope", params={"host": "10.9.9.9"},
                       modules_dir=self.root / "modules", run=run)
        rows = run.query("SELECT result, is_zeroday FROM actions ORDER BY id")
        self.assertEqual([tuple(r) for r in rows], [("refused-out-of-scope", 1)])

    # ---------- zeroday.enable 审计 ----------
    def test_zeroday_enable_writes_audit_row(self):
        self.assertFalse(zeroday_enabled(self.store))
        enable(self.store, self.lead)
        self.assertTrue(zeroday_enabled(self.store))
        audit = self.store.open_run("_audit")
        rows = audit.query("SELECT actor, action, target, result, is_zeroday FROM actions ORDER BY id")
        self.assertEqual(len(rows), 1)
        actor, action, target, result, flag = rows[0]
        self.assertEqual((actor, action, target, result, flag),
                         ("lead", "zeroday-enable", "local-lab", "success", 1))

    def test_zeroday_enable_denied_attempt_is_audited(self):
        with self.assertRaises(PermissionError):
            enable(self.store, self.tester)
        audit = self.store.open_run("_audit")
        rows = audit.query("SELECT actor, result, is_zeroday FROM actions ORDER BY id")
        self.assertEqual(rows[0][0], "tester")
        self.assertTrue(str(rows[0][1]).startswith("denied"))
        self.assertEqual(rows[0][2], 1)
        self.assertFalse(zeroday_enabled(self.store))

    def test_zeroday_gate_still_blocks_before_scope(self):
        _fixture_module(self.root, "private-probe", private=True)
        with self.assertRaises(ZerodayLocked):
            run_module(self.store, self.tester, "private-probe", params={"host": "127.0.0.1"},
                       modules_dir=self.root / "modules")


if __name__ == "__main__":
    unittest.main()
