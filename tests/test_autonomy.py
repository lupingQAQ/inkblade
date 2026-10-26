# -*- coding: utf-8 -*-
"""core/autonomy.py — L3 自主执行护栏测试。

口径：
- L3 = **lead 预授权**下的自主循环，不是「模型自由行动」：必须先签 RoE 全影响演示 +
  lead 签发一次性 token；token 落盘只存 sha256，明文只在 grant 时返回一次；
- 白名单（模块级）+ 预算硬顶（token/时延/审批）+ 异常即停（连续失败/越界/写未授权）；
- 每一步都写 `audit.jsonl`，每次决策写 `autonomy/trace.jsonl`（可回放、digest 校验）；
- LLM 只做候选排序：无端点时 `--llm` 直接拒绝；运行中失败则确定性回退 rules，
  回退本身留痕。
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core import autonomy as A
from inkblade.core.evidence import EvidenceStore
from inkblade.core.journal import Journal
from inkblade.core.llmpool import LLMPool
from inkblade.core.roe import init_roe
from inkblade.core.supervisor import Supervisor
from inkblade.core.users import Session

FULL = "全影响演示"


def approved_action(module: str, writes: bool = False, **params) -> dict:
    return {"module": module, "params": params, "writes": writes,
            "approval": {"status": "approved", "approved_by": "lead"}}


class FakePlanner:
    def __init__(self, batches, *, mode: str = "rules", notes=None):
        self.batches = batches
        self.mode = mode
        self.notes = list(notes or [])
        self.calls = 0

    def __call__(self, step, guard):
        self.calls += 1
        if step > len(self.batches):
            return {"id": f"prop-{step}", "actions": [], "mode": self.mode,
                    "llm_note": ""}
        batch = self.batches[min(step - 1, len(self.batches) - 1)]
        return {"id": f"prop-{step}", "actions": [dict(a) for a in batch],
                "mode": self.mode,
                "llm_note": self.notes[step - 1] if step - 1 < len(self.notes) else ""}


class FakeExecutor:
    def __init__(self, fail_modules=()):
        self.fail_modules = set(fail_modules)
        self.calls: list[str] = []

    def __call__(self, proposal):
        self.calls.append(proposal["id"])
        results = []
        for action in proposal["actions"]:
            ok = action["module"] not in self.fail_modules
            results.append({"module": action["module"],
                            "status": "success" if ok else "failed",
                            "error": "" if ok else "RuntimeError: boom"})
        return {"results": results, "ok": all(r["status"] == "success" for r in results),
                "duration_ms": 5}


class AutonomyTestBase(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.root = Path(self.td.name)
        self.store = EvidenceStore(self.root, workspace="l3-lab")
        self.session = Session(None, "lead", "lead", ["l3-lab"], "t")

    def tearDown(self):
        self.td.cleanup()

    def sign_roe(self, level: str = FULL):
        init_roe(self.store, fields={"level": level, "namespaces": ["tenant-a"],
                                     "cidrs": ["10.0.0.0/8"], "client": "unit"})

    def make_grant(self, *, allowlist=("recon", "verify"), allow_writes=False,
                   max_actions=4, max_steps=3, budget=None, ttl_seconds=600):
        return A.AutonomyGrant.create(
            self.store, self.session, allowlist=list(allowlist), allow_writes=allow_writes,
            max_actions=max_actions, max_steps=max_steps,
            budget=budget or {"tokens": 20000, "latency_ms": 120000,
                              "approvals": 8, "interventions": 2},
            ttl_seconds=ttl_seconds, note="unit test")

    def enable_llm_pool(self):
        pool = LLMPool(self.store)
        pool.add_endpoint(self.session, base_url="http://127.0.0.1:9/v1", model="unit-model")
        pool.set_enabled(self.session, True)


class TestGrant(AutonomyTestBase):
    def test_grant_requires_lead_and_never_stores_plaintext_token(self):
        tester = Session(None, "tester", "tester", ["l3-lab"], "t")
        with self.assertRaises(PermissionError):
            A.AutonomyGrant.create(self.store, tester, allowlist=["recon"])
        grant, token = self.make_grant()
        self.assertTrue(token)
        doc_text = grant.path.read_text(encoding="utf-8")
        self.assertNotIn(token, doc_text, "预授权 token 明文不得落盘")
        self.assertIn("token_sha256", doc_text)
        self.assertNotIn("token_sha256", json.dumps(grant.public_doc(), ensure_ascii=False))
        self.assertTrue(grant.verify_token(token))
        self.assertFalse(grant.verify_token(token + "x"))

    def test_grant_validation(self):
        with self.assertRaises(A.AutonomyRefused):
            A.AutonomyGrant.create(self.store, self.session, allowlist=[])
        with self.assertRaises(A.AutonomyRefused):
            A.AutonomyGrant.create(self.store, self.session, allowlist=["recon"], max_actions=0)
        with self.assertRaises(A.AutonomyRefused):
            A.AutonomyGrant.create(self.store, self.session, allowlist=["recon"],
                                   budget={"tokens": -1})

    def test_tampered_grant_is_refused(self):
        grant, token = self.make_grant()
        doc = json.loads(grant.path.read_text(encoding="utf-8"))
        doc["allowlist"].append("exploit-write")
        grant.path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(A.AutonomyRefused):
            A.AutonomyGrant.load(self.store)

    def test_revoke(self):
        grant, token = self.make_grant()
        A.AutonomyGrant.revoke(self.store, self.session, reason="unit")
        with self.assertRaises(A.AutonomyRefused):
            A.AutonomyGrant.load(self.store)


class TestPreflight(AutonomyTestBase):
    def test_requires_signed_full_impact_roe(self):
        grant, token = self.make_grant()
        with self.assertRaises(A.AutonomyRefused) as ctx:
            A.AutonomyGuard.preflight(self.store, token=token)
        self.assertIn("授权", str(ctx.exception))
        self.sign_roe("利用验证")
        with self.assertRaises(A.AutonomyRefused) as ctx:
            A.AutonomyGuard.preflight(self.store, token=token)
        self.assertIn(FULL, str(ctx.exception))

    def test_requires_valid_preauth_token(self):
        self.sign_roe()
        grant, token = self.make_grant()
        with self.assertRaises(A.AutonomyRefused):
            A.AutonomyGuard.preflight(self.store, token="")
        with self.assertRaises(A.AutonomyRefused):
            A.AutonomyGuard.preflight(self.store, token="wrong")
        put = json.loads(grant.path.read_text(encoding="utf-8"))
        put["expires_at"] = time.time() - 1
        # 过期也要验签：直接改字段会被 HMAC 拒绝（这里先构造合法签名再测时钟过期）
        from inkblade.core import roe
        put.pop("hmac", None)
        put["hmac"] = roe.signature({k: v for k, v in put.items() if k != "hmac"},
                                    roe.workspace_key(self.store))
        grant.path.write_text(json.dumps(put, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(A.AutonomyRefused) as ctx:
            A.AutonomyGuard.preflight(self.store, token=token)
        self.assertIn("过期", str(ctx.exception))

    def test_llm_required_refused_without_endpoint(self):
        self.sign_roe()
        grant, token = self.make_grant()
        saved = os.environ.pop("INKBLADE_LLM_BASE_URL", None)
        try:
            with self.assertRaises(A.AutonomyRefused) as ctx:
                A.AutonomyGuard.preflight(self.store, token=token, llm_required=True)
        finally:
            if saved is not None:
                os.environ["INKBLADE_LLM_BASE_URL"] = saved
        self.assertIn("端点", str(ctx.exception))
        self.enable_llm_pool()
        guard = A.AutonomyGuard.preflight(self.store, token=token, llm_required=True)
        self.assertTrue(guard.llm_required)
        self.assertEqual(guard.grant.id, grant.id)

    def test_preflight_is_audited(self):
        self.sign_roe()
        grant, token = self.make_grant()
        A.AutonomyGuard.preflight(self.store, token=token)
        rows = [json.loads(line) for line in
                (self.store.ws_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()]
        pre = [r for r in rows if r["action"] == "autonomy.preflight"]
        self.assertEqual(len(pre), 1)
        self.assertEqual(pre[0]["target"], grant.id)
        self.assertNotIn(token, json.dumps(rows, ensure_ascii=False))


class TestRunner(AutonomyTestBase):
    def _guard(self, **kwargs):
        self.sign_roe()
        _, token = self.make_grant(**kwargs)
        return A.AutonomyGuard.preflight(self.store, token=token)

    def test_two_steps_executed_with_trace_and_audit(self):
        guard = self._guard()
        planner = FakePlanner([[approved_action("recon"), approved_action("recon")],
                               [approved_action("verify")]])
        executor = FakeExecutor()
        runner = A.AutonomyRunner(guard, planner, executor, session=self.session)
        result = runner.run()
        self.assertEqual(result["mode"], "L3")
        self.assertEqual(len(result["steps"]), 2)
        self.assertEqual(executor.calls, ["prop-1", "prop-2"])
        self.assertEqual(guard.budget.used["approvals"], 3)
        trace = [json.loads(line) for line in guard.trace_path.read_text(encoding="utf-8").splitlines()
                 if line.strip()]
        self.assertEqual(len(trace), 2)
        for row in trace:
            self.assertEqual(len(row["plan_sha256"]), 64)
        audit_text = (self.store.ws_dir / "audit.jsonl").read_text(encoding="utf-8")
        self.assertIn("autonomy.step", audit_text)
        self.assertIn("autonomy.grant", audit_text)

    def test_allowlist_violation_stops_before_execution(self):
        guard = self._guard(allowlist=("recon",))
        planner = FakePlanner([[approved_action("recon"), approved_action("exploit")]])
        executor = FakeExecutor()
        result = A.AutonomyRunner(guard, planner, executor, session=self.session).run()
        self.assertEqual(executor.calls, [])
        self.assertEqual(result["stop"]["reason"], "allowlist")
        self.assertIn("exploit", result["stop"]["detail"])
        audit_text = (self.store.ws_dir / "audit.jsonl").read_text(encoding="utf-8")
        self.assertIn("autonomy.action.denied", audit_text)

    def test_write_action_requires_explicit_grant(self):
        guard = self._guard(allowlist=("exploit",), allow_writes=False)
        planner = FakePlanner([[approved_action("exploit", writes=True)]])
        result = A.AutonomyRunner(guard, planner, FakeExecutor(), session=self.session).run()
        self.assertEqual(result["stop"]["reason"], "write-not-granted")

    def test_budget_hard_cap_blocks_next_action(self):
        guard = self._guard(allowlist=("recon",), max_actions=4,
                            budget={"tokens": 20000, "latency_ms": 120000,
                                    "approvals": 1, "interventions": 2})
        planner = FakePlanner([[approved_action("recon"), approved_action("recon")]])
        executor = FakeExecutor()
        result = A.AutonomyRunner(guard, planner, executor, session=self.session).run()
        self.assertEqual(executor.calls, [])
        self.assertEqual(result["stop"]["reason"], "budget")
        self.assertLessEqual(guard.budget.used["approvals"], 1)

    def test_token_budget_hard_cap(self):
        guard = self._guard(allowlist=("recon",), max_actions=4,
                            budget={"tokens": 1, "latency_ms": 120000,
                                    "approvals": 8, "interventions": 2})
        planner = FakePlanner([[approved_action("recon", pad="x" * 400)]])
        result = A.AutonomyRunner(guard, planner, FakeExecutor(), session=self.session).run()
        self.assertEqual(result["stop"]["reason"], "budget")

    def test_consecutive_failures_trigger_anomaly_stop(self):
        guard = self._guard(allowlist=("recon", "verify"))
        planner = FakePlanner([[approved_action("recon"), approved_action("recon")],
                               [approved_action("verify")]])
        executor = FakeExecutor(fail_modules={"recon"})
        result = A.AutonomyRunner(guard, planner, executor, session=self.session).run()
        self.assertEqual(executor.calls, ["prop-1"])
        self.assertEqual(result["stop"]["reason"], "anomaly")
        self.assertEqual(planner.calls, 1)

    def test_scope_violation_is_anomaly(self):
        guard = self._guard(allowlist=("recon",))
        planner = FakePlanner([[approved_action("recon", namespace="tenant-b")]])
        result = A.AutonomyRunner(guard, planner, FakeExecutor(), session=self.session).run()
        self.assertEqual(result["stop"]["reason"], "scope")
        self.assertIn("tenant-b", result["stop"]["detail"])

    def test_llm_failure_falls_back_to_rules_deterministically(self):
        self.sign_roe()
        _, token = self.make_grant()
        self.enable_llm_pool()
        guard = A.AutonomyGuard.preflight(self.store, token=token, llm_required=True)
        planner = FakePlanner([[approved_action("recon")]], notes=["TimeoutError: llm down"])
        result = A.AutonomyRunner(guard, planner, FakeExecutor(), session=self.session,
                                  llm_requested=True).run()
        self.assertEqual(result["llm_fallbacks"], 1)
        audit_text = (self.store.ws_dir / "audit.jsonl").read_text(encoding="utf-8")
        self.assertIn("autonomy.llm.fallback", audit_text)

    def test_executor_crash_triggers_stop_and_audit(self):
        guard = self._guard()
        planner = FakePlanner([[approved_action("recon")]])

        def crash(proposal):
            raise RuntimeError("runner exploded")

        result = A.AutonomyRunner(guard, planner, crash, session=self.session).run()
        self.assertEqual(result["stop"]["reason"], "executor-error")
        audit_text = (self.store.ws_dir / "audit.jsonl").read_text(encoding="utf-8")
        self.assertIn("autonomy.executor.error", audit_text)

    def test_replay_reproduces_plan_and_detects_tamper(self):
        guard = self._guard()
        planner = FakePlanner([[approved_action("recon")], [approved_action("verify")]])
        A.AutonomyRunner(guard, planner, FakeExecutor(), session=self.session).run()
        replay = A.replay_trace(self.store)
        self.assertTrue(replay["deterministic"])
        self.assertFalse(replay["executed"])
        self.assertEqual([s["step"] for s in replay["steps"]], [1, 2])
        self.assertEqual(replay["steps"][0]["actions"][0]["module"], "recon")
        lines = guard.trace_path.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[0])
        row["plan"][0]["module"] = "exploit"
        guard.trace_path.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
        with self.assertRaises(A.AutonomyRefused):
            A.replay_trace(self.store)


class TestSupervisorGuarded(AutonomyTestBase):
    def _queue(self, modules):
        sup = Supervisor(self.store, self.session, workers=1, max_attempts=1,
                         executor=lambda task: {"ok": True},
                         journal=Journal(self.root / "journal.jsonl"))
        sup.submit([approved_action(m) for m in modules])
        return sup

    def test_runs_approved_queue_and_records_budget(self):
        self.sign_roe()
        _, token = self.make_grant(allowlist=("recon", "verify"))
        guard = A.AutonomyGuard.preflight(self.store, token=token)
        self._queue(["recon", "verify"])
        calls = []
        result = A.run_supervisor_guarded(
            self.store, self.session, guard, workers=1,
            executor=lambda task: calls.append(task["module"]) or {"ok": True})
        self.assertEqual(result["summary"]["success"], 2)
        self.assertEqual(calls, ["recon", "verify"])
        self.assertEqual(guard.budget.used["approvals"], 2)
        audit_text = (self.store.ws_dir / "audit.jsonl").read_text(encoding="utf-8")
        self.assertIn("autonomy.supervisor.run", audit_text)

    def test_unlisted_task_refused_before_any_execution(self):
        self.sign_roe()
        _, token = self.make_grant(allowlist=("recon",))
        guard = A.AutonomyGuard.preflight(self.store, token=token)
        self._queue(["recon", "exploit"])
        calls = []
        with self.assertRaises(A.AutonomyRefused):
            A.run_supervisor_guarded(
                self.store, self.session, guard, workers=1,
                executor=lambda task: calls.append(task["module"]) or {"ok": True})
        self.assertEqual(calls, [])


class TestAutonomyCli(unittest.TestCase):
    def setUp(self):
        self.td = TemporaryDirectory()
        self.home = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def _run(self, argv):
        from inkblade import cli
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--home", str(self.home), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_explore_l3_without_endpoint_is_refused(self):
        init_roe(EvidenceStore(self.home, workspace="local-lab"),
                 fields={"level": FULL, "namespaces": ["tenant-a"],
                         "cidrs": ["10.0.0.0/8"]})
        code, _, err = self._run(["explore", "autonomy", "--workspace", "local-lab",
                                  "--autonomy", "L3", "--llm"])
        self.assertEqual(code, 2)
        self.assertIn("预授权", err + "")

    def test_autonomy_grant_status_levels(self):
        code, out, err = self._run(["autonomy", "levels"])
        self.assertEqual(code, 0, err)
        self.assertIn("L3", out)
        code, out, err = self._run(["autonomy", "grant", "--allowlist", "recon,verify",
                                    "--max-actions", "2", "--max-steps", "2",
                                    "--ttl-seconds", "600"])
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertTrue(doc["token"])
        self.assertTrue(doc["grant"]["allowlist"])
        code, out, err = self._run(["autonomy", "status"])
        self.assertEqual(code, 0, err)
        status = json.loads(out)
        self.assertTrue(status["active"])
        self.assertNotIn(doc["token"], out)

    def test_supervisor_cli_l3_gates_queued_task(self):
        from inkblade.core import autonomy as A
        from inkblade.core.journal import Journal
        from inkblade.core.supervisor import Supervisor
        from inkblade.core.users import Session

        store = EvidenceStore(self.home, workspace="local-lab")
        init_roe(store, fields={"level": FULL, "namespaces": ["tenant-a"],
                                "cidrs": ["10.0.0.0/8"]})
        session = Session(None, "lead", "lead", ["local-lab"], "t")
        grant, token = A.AutonomyGrant.create(store, session, allowlist=["recon"],
                                              max_actions=2, max_steps=2, ttl_seconds=600)
        Supervisor(store, session, workers=1, max_attempts=1,
                   executor=lambda task: {"ok": True},
                   journal=Journal(self.home / "journal.jsonl")).submit(
            [{"module": "recon", "params": {},
              "approval": {"status": "approved", "approved_by": "lead"}}])
        code, out, err = self._run(["supervisor", "run", "--workspace", "local-lab",
                                    "--autonomy", "L3", "--preauth-token", token,
                                    "--workers", "1"])
        self.assertEqual(code, 0, err + out)
        data = json.loads(out)
        self.assertEqual(data["summary"]["total"], 1)
        self.assertEqual(data["autonomy"]["grant"], grant.id)


if __name__ == "__main__":
    unittest.main()
