# -*- coding: utf-8 -*-
"""End-to-end autonomous graph supervisor tests on the mock probe range."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.agent_fixture import (K8S_OBJECTS, ROOT, golden_script, make_lab,
                                 supervisor_kwargs)
from inkblade.agent.objectives import get_objective
from inkblade.agent.planner import DeterministicPlanner, ScriptedPlanner
from inkblade.agent.runtime import AgentRuntime
from inkblade.agent.supervisor import AgentSupervisor
from inkblade.tpl.probe import ProbeUnavailable


class SupervisorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store, self.session, self.modules, self.rng, self.k8s = make_lab(self.root)
        self.script = golden_script(self.rng.url())

    def tearDown(self):
        if self.rng is not None:
            self.rng.stop()
        self.tmp.cleanup()

    def _create(self, **overrides):
        script = overrides.pop("script", self.script)
        kwargs = supervisor_kwargs(self.root, self.modules, self.rng, self.k8s,
                                   script=script, **overrides)
        return AgentSupervisor.create(self.store, self.session, **kwargs)

    def _module_map(self):
        return {"recon": "lab-recon", "exposure": "lab-exposure", "rbac": "lab-rbac",
                "drop": "lab-drop", "privesc": "lab-privesc", "proof": "lab-proof",
                "report": "agent-report", "cleanup": "lab-cleanup"}

    def test_autonomous_chain_success_and_trace(self):
        sup = self._create()
        result = sup.run()
        self.assertEqual(result["status"], "success", result)
        self.assertTrue(result["success"])
        metrics = result["metrics"]
        self.assertEqual(metrics["steps"], 8)
        self.assertEqual(metrics["probe_calls"], 7)
        self.assertEqual(metrics["interventions"], 0)
        self.assertGreaterEqual(metrics["evidence_coverage"], 1.0)
        self.assertEqual(len(sup.graph.intents(status="done")), 8)
        kinds = [e["kind"] for e in sup.runtime.events()]
        for kind in ("run.created", "plan.proposed", "decision.made",
                     "intent.claimed", "observation", "graph.evidence.added",
                     "graph.fact.added", "intent.completed", "report.written",
                     "run.completed"):
            self.assertIn(kind, kinds, kind)
        self.assertNotIn("approval.required", kinds)
        observations = [e for e in sup.runtime.events() if e["kind"] == "observation"]
        self.assertEqual(len(observations), 7)
        for event in observations:
            for ref in event["payload"]["observation"]["evidence"]:
                self.assertEqual(len(ref["sha256"]), 64)
        self.assertTrue(Path(result["trace"]).is_file())
        self.assertTrue(sup.runtime.log.verify()["ok"])
        self.assertTrue(Path(result["reflection"]["path"]).is_file())

    def test_budget_steps_hard_stop(self):
        sup = self._create(budgets={"tokens": 20000, "steps": 3, "actions": 20,
                                    "duration_ms": 120000})
        result = sup.run()
        self.assertEqual(result["status"], "budget-exceeded", result)
        self.assertFalse(result["success"])
        self.assertEqual(result["metrics"]["steps"], 3)
        self.assertEqual(result["metrics"]["probe_calls"], 3)
        self.assertLess(len(sup.graph.intents(status="done")), 8)
        self.assertIn("budget.exceeded", [e["kind"] for e in sup.runtime.events()])

    def test_budget_tokens_stops_before_any_probe(self):
        sup = self._create(budgets={"tokens": 1, "steps": 12, "actions": 20,
                                    "duration_ms": 120000})
        result = sup.run()
        self.assertEqual(result["status"], "budget-exceeded", result)
        self.assertEqual(result["metrics"]["probe_calls"], 0)
        self.assertEqual(result["metrics"]["steps"], 0)
        self.assertEqual(sup.graph.intents(status="done"), [])

    def test_out_of_scope_refused_without_probe(self):
        script = {"responses": [{
            "decision": "propose_intents", "rationale": "try external target",
            "intents": [{"role": "recon", "module": "lab-recon",
                         "params": {"target": "http://10.0.0.1", "namespace": "train"},
                         "priority": 9}]}]}
        sup = self._create(script=script)
        result = sup.run()
        self.assertEqual(result["status"], "policy-refused", result)
        self.assertEqual(result["metrics"]["probe_calls"], 0)
        kinds = [e["kind"] for e in sup.runtime.events()]
        self.assertIn("policy.refused", kinds)
        self.assertEqual(sup.graph.intents()[0]["status"], "blocked")

    def test_no_probe_refuses_before_run_creation(self):
        store, session, modules, rng, k8s = make_lab(self.root / "noprobe",
                                                     with_range=False)
        try:
            with self.assertRaises(ProbeUnavailable):
                AgentSupervisor.create(store, session, objective="cluster-takeover",
                                       probe_id="missing", llm="deterministic",
                                       mode="deterministic",
                                       modules_dir=modules)
            self.assertFalse((Path(store.ws_dir) / "agent" / "runs").exists())
        finally:
            if rng is not None:
                rng.stop()

    def test_no_llm_refuses_agent_mode(self):
        with self.assertRaises(Exception) as ctx:
            AgentSupervisor.create(self.store, self.session, **{
                **supervisor_kwargs(self.root, self.modules, self.rng, self.k8s,
                                    script=None),
                "llm": "",
                "mode": "graph-swarm",
            })
        self.assertIn("llm", str(ctx.exception).lower())
        self.assertFalse((Path(self.store.ws_dir) / "agent" / "runs").exists())

    def test_dry_run_plans_without_probe(self):
        sup = self._create(dry_run=True)
        result = sup.run()
        self.assertEqual(result["status"], "dry-run")
        self.assertEqual(result["metrics"]["probe_calls"], 0)
        self.assertGreaterEqual(len(sup.graph.intents()), 1)
        self.assertIn("plan.proposed", [e["kind"] for e in sup.runtime.events()])

    def test_write_refused_without_allow_destructive(self):
        script = {"responses": [{
            "decision": "propose_intents", "rationale": "write attempt",
            "intents": [{"role": "exploit", "module": "lab-drop",
                         "params": {"target": self.rng.url(), "namespace": "train",
                                    "backup_targets": [{"kind": "kube", "name": "x",
                                                        "manifest": "x"}]},
                         "priority": 9, "writes": True}]}]}
        sup = self._create(script=script, allow_destructive=False)
        result = sup.run()
        self.assertEqual(result["status"], "policy-refused", result)
        self.assertEqual(result["metrics"]["probe_calls"], 0)

    def test_write_requires_backup_receipt(self):
        script = {"responses": [{
            "decision": "propose_intents", "rationale": "write without backup",
            "intents": [{"role": "exploit", "module": "lab-drop",
                         "params": {"target": self.rng.url(), "namespace": "train"},
                         "priority": 9, "writes": True}]}]}
        sup = self._create(script=script)
        result = sup.run()
        self.assertEqual(result["status"], "policy-refused", result)
        self.assertEqual(result["metrics"]["probe_calls"], 0)
        self.assertIn("backup", " ".join(
            e["payload"].get("reason", "") for e in sup.runtime.events()
            if e["kind"] == "policy.refused").lower())

    def test_manual_approval_is_optional_and_default_is_auto(self):
        script = {"responses": [{
            "decision": "propose_intents", "rationale": "write attempt",
            "intents": [{"role": "exploit", "module": "lab-drop",
                         "params": {"target": self.rng.url(), "namespace": "train",
                                    "backup_targets": [{"kind": "kube", "name": "x",
                                                        "manifest": "x"}]},
                         "priority": 9, "writes": True}]}]}
        sup = self._create(script=script, approval="manual")
        result = sup.run()
        self.assertEqual(result["status"], "policy-refused", result)
        kinds = [e["kind"] for e in sup.runtime.events()]
        self.assertIn("approval.required", kinds)
        self.assertEqual(result["metrics"]["interventions"], 1)

    def test_one_time_start_token_and_signature(self):
        from inkblade.agent.policy import (AuthorizationRequired, issue_start,
                                           preflight, verify_authorization)

        doc, token = issue_start(self.store, self.session, objective="cluster-takeover",
                                 allow_destructive=True,
                                 budgets={"tokens": 100, "steps": 2},
                                 ttl_seconds=60)
        self.assertNotIn("token", doc)
        auth = preflight(self.store, self.session, objective="cluster-takeover",
                         mode="graph-swarm", allow_destructive=True,
                         budgets={"tokens": 100, "steps": 2}, start_token=token,
                         confirm=False)
        self.assertEqual(auth.start_mode, "token")
        self.assertTrue(verify_authorization(self.store, auth.to_dict()))
        with self.assertRaises(AuthorizationRequired):
            preflight(self.store, self.session, objective="cluster-takeover",
                      mode="graph-swarm", allow_destructive=True,
                      budgets={"tokens": 100, "steps": 2}, start_token="wrong",
                      confirm=False)

    def test_kill_switch_stops_before_probe(self):
        sup = self._create()
        AgentSupervisor.stop(self.store, sup.runtime.run_id, reason="test kill")
        result = sup.run()
        self.assertEqual(result["status"], "stopped", result)
        self.assertEqual(result["metrics"]["probe_calls"], 0)
        self.assertTrue(sup.runtime.is_stopped())

    def test_resume_skips_completed_intents(self):
        sup = self._create(mode="deterministic", llm="deterministic",
                           max_rounds=3, module_map=self._module_map())
        first = sup.run()
        self.assertEqual(first["status"], "paused", first)
        done_first = {i["id"] for i in sup.graph.intents(status="done")}
        self.assertEqual(len(done_first), 3)
        run_id = sup.runtime.run_id
        loaded = AgentSupervisor.load(
            self.store, run_id, session=self.session,
            modules_dir=self.modules, max_rounds=10, k8s=self.k8s,
            probe_spec={"kind": "reference"}, allow_reference=True,
            workdir=self.rng.workdir)
        second = loaded.run(resume=True)
        self.assertEqual(second["status"], "success", second)
        self.assertEqual(len(loaded.graph.intents(status="done")), 8)
        events = loaded.runtime.events()
        for iid in done_first:
            claims = [e for e in events if e["kind"] == "intent.claimed"
                      and e["payload"].get("intent") == iid]
            self.assertEqual(len(claims), 1, iid)

    def test_replay_time_travel(self):
        sup = self._create()
        result = sup.run()
        self.assertEqual(result["status"], "success")
        events = sup.runtime.events()
        first_done = next(e for e in events if e["kind"] == "intent.completed")
        early = AgentSupervisor.replay(self.store, sup.runtime.run_id,
                                       to_seq=first_done["seq"])
        self.assertFalse(early["objective_eval"]["success"])
        self.assertLess(len(early["graph_state"]["nodes"]),
                        len(sup.graph.to_dict()["nodes"]))
        full = AgentSupervisor.replay(self.store, sup.runtime.run_id)
        self.assertTrue(full["objective_eval"]["success"])
        self.assertEqual(full["graph"]["intent_done"], 8)


if __name__ == "__main__":
    unittest.main()
