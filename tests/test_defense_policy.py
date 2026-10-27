# -*- coding: utf-8 -*-
"""Defense-aware bypass policy, posture parsing and scheduler wiring tests."""
from __future__ import annotations

import json
import unittest

from tests.agent_fixture import ROOT  # noqa: F401 - path setup
from inkblade.core import defense_policy as dp
from inkblade.agent.graph import PlanGraph
from inkblade.agent.observer import normalize_run
from inkblade.agent.runtime import Budget
from inkblade.agent.scheduler import TaskScheduler
from inkblade.tpl import lower, schema

EVIDENCE = "a" * 64


def posture_fixture() -> dict:
    return {
        "schema": "inkblade-security-posture/1",
        "namespace": "default",
        "products": [
            {
                "product": "falco", "display": "Falco",
                "evidence": ["process:falco", "ruleset:/proc/1/root/etc/falco/falco_rules.yaml"],
                "version": "falcosecurity/falco:0.45.1",
                "sensor": {"running": True, "driver": "modern_ebpf_inferred"},
                "rulesets": [{
                    "product": "falco",
                    "path": "/proc/1/root/etc/falco/falco_rules.yaml",
                    "rule_count": 164,
                    "interesting_rules": ["executing-binary", "terminal-shell"],
                }],
            },
            {
                "product": "kyverno", "display": "Kyverno",
                "evidence": ["process:kyverno", "admission:kyverno:3"],
                "version": "reg.kyverno.io/kyverno/kyverno:v1.19.2",
            },
        ],
        "admission": {
            "available": True,
            "kyverno": {
                "available": True, "api": "policies.kyverno.io/v1", "count": 3,
                "items": [
                    {"name": "defense-lab-disallow-privileged",
                     "scope": "[request.namespace == 'defense-lab']"},
                    {"name": "defense-lab-disallow-hostpath",
                     "scope": "[request.namespace == 'defense-lab']"},
                    {"name": "defense-lab-require-automount-false",
                     "scope": "[request.namespace == 'defense-lab']"},
                ],
            },
            "gatekeeper": {"available": False, "error": "not installed"},
        },
        "processes": [
            {"pid": 1, "comm": "falco", "cmdline": "/usr/bin/falco",
             "matched": ["falco"]},
            {"pid": 2, "comm": "kyverno", "cmdline": "kyverno",
             "matched": ["kyverno"]},
        ],
        "kernel_modules": ["kvm", "overlay"],
        "agent_dirs": [{"path": "/etc/falco", "product": "falco", "present": False}],
    }


class TestTechniqueSelection(unittest.TestCase):
    def test_catalog_is_ranked_by_risk_adjusted_success(self):
        tech = dp.select_technique("falco")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.id, "path-evasion")
        ordered = sorted(
            [dp.TECHNIQUES[t] for t in dp.PRODUCT_TECHNIQUES["falco"]],
            key=lambda t: (-t.score, t.risk, t.id))
        self.assertEqual([t.id for t in ordered][0], tech.id)
        self.assertGreater(tech.score, 0)

    def test_product_without_technique_stops(self):
        for product in ("imagescan", "waf-inference", "netobserv", "veinmind"):
            with self.subTest(product=product):
                plan = dp.plan_bypass(product)
                self.assertEqual(plan["status"], "no-technique")
                self.assertTrue(plan["stop"])
                self.assertIn("不可绕过", plan["reason"])
                report = dp.refusal_report(product)
                self.assertEqual(report["status"], "policy-refused")
                self.assertFalse(report["technique_id"])

    def test_alias_resolution(self):
        self.assertEqual(dp.normalize_product("kyverno"), "admission")
        self.assertEqual(dp.normalize_product("trivy"), "imagescan")
        self.assertEqual(dp.select_technique("kyverno").id, "namespace-scope-evasion")


class TestPostureFacts(unittest.TestCase):
    def test_parse_and_fact_claims(self):
        detected = dp.parse_posture(posture_fixture())
        products = [item.product for item in detected]
        self.assertIn("falco", products)
        self.assertIn("admission", products)
        falco = next(item for item in detected if item.product == "falco")
        self.assertEqual(falco.version, "falcosecurity/falco:0.45.1")
        self.assertEqual(falco.ruleset["rule_count"], 164)
        facts = dp.defense_facts(detected, [EVIDENCE], source_intent="intent-1")
        claims = {fact["claim"] for fact in facts}
        self.assertIn("defense:falco", claims)
        self.assertIn("defense:admission", claims)
        for fact in facts:
            self.assertEqual(fact["fact_kind"], "defense")
            self.assertEqual(fact["status"], "confirmed")
            self.assertEqual(fact["evidence"], [EVIDENCE])

    def test_apply_posture_to_graph(self):
        graph = PlanGraph(objective="defense-lab")
        applied = dp.apply_posture(graph, posture_fixture(), EVIDENCE,
                                   source_intent="collect-1")
        self.assertTrue(applied["evidence"].startswith("ev-"))
        claims = {fact["claim"] for fact in graph.facts(fact_kind="defense")}
        self.assertEqual(claims, {"defense:falco", "defense:admission"})
        self.assertTrue(all(f["status"] == "confirmed"
                            for f in graph.facts(fact_kind="defense")))

    def test_observer_normalizes_posture(self):
        class FakeRun:
            name = "run-1"

            def query(self, sql, params=()):
                if "FROM findings" in sql:
                    return [("defense-probe", "info",
                             "security posture collected",
                             "falco + admission", "")]
                if "FROM evidence" in sql:
                    return [("archive.tar", EVIDENCE, "archive")]
                if "FROM env" in sql:
                    return []
                return []

        intent = {
            "id": "intent-1", "module": "defense-probe", "role": "recon",
            "params": {"security_posture": posture_fixture()},
        }
        observation = normalize_run(FakeRun(), intent, step_rowid=1)
        claims = {fact["claim"] for fact in observation.facts}
        self.assertIn("defense:falco", claims)
        self.assertIn("defense:admission", claims)
        defense_facts = [fact for fact in observation.facts
                         if fact["fact_kind"] == "defense"]
        for fact in defense_facts:
            self.assertEqual(fact["evidence"], [EVIDENCE])


class TestDefenseGate(unittest.TestCase):
    def _graph(self, product="falco"):
        graph = PlanGraph(objective="gate")
        graph.add_evidence(EVIDENCE, step="probe.collect")
        graph.add_fact(f"defense:{product}", status="confirmed",
                       evidence=[f"ev-{EVIDENCE[:16]}"], kind="defense")
        return graph

    def test_offensive_intent_requires_bypass(self):
        graph = self._graph("falco")
        gate = dp.DefenseGate(graph)
        intent = {"id": "i1", "role": "exploit", "module": "privileged-pod-escape",
                  "params": {}}
        decision = gate.check_intent(intent, graph)
        self.assertFalse(decision.allow)
        self.assertEqual(decision.kind, "DefenseBypassRequired")
        self.assertIn("fileless-memfd-exec", decision.available)

    def test_valid_bypass_is_allowed_and_recorded(self):
        graph = self._graph("falco")
        tech = dp.select_technique("falco")
        bypass = dp.bypass_params(tech, script="echo INKBLADE-BENIGN")
        intent = {"id": "i2", "role": "exploit", "module": "lateral-exec",
                  "params": {"bypass": bypass}}
        decision = dp.DefenseGate(graph).check_intent(intent, graph)
        self.assertTrue(decision.allow)
        self.assertEqual(decision.technique_id, tech.id)
        self.assertEqual(decision.product, "falco")

    def test_mismatched_technique_is_refused(self):
        graph = self._graph("falco")
        intent = {"id": "i3", "role": "exploit", "module": "lateral-exec",
                  "params": {"bypass": {"technique_id": "namespace-scope-evasion"}}}
        decision = dp.DefenseGate(graph).check_intent(intent, graph)
        self.assertFalse(decision.allow)
        self.assertEqual(decision.kind, "DefenseTechniqueMismatch")

    def test_product_without_primitive_stops(self):
        graph = self._graph("imagescan")
        gate = dp.DefenseGate(graph)
        intent = {"id": "i4", "role": "exploit", "module": "image-escape",
                  "params": {}}
        decision = gate.check_intent(intent, graph)
        self.assertFalse(decision.allow)
        self.assertEqual(decision.kind, "NoBypassTechnique")
        self.assertTrue(decision.stop)

    def test_recon_intent_is_not_gated(self):
        graph = self._graph("falco")
        intent = {"id": "i5", "role": "recon", "module": "kubelet-surface",
                  "params": {}}
        self.assertTrue(dp.DefenseGate(graph).check_intent(intent, graph).allow)


class TestSchedulerDefenseWiring(unittest.TestCase):
    def _graph(self):
        graph = PlanGraph(objective="scheduler-defense")
        graph.add_evidence(EVIDENCE, step="probe.collect")
        graph.add_fact("defense:falco", status="confirmed",
                       evidence=[f"ev-{EVIDENCE[:16]}"], kind="defense")
        return graph

    def test_exploit_intent_is_blocked_and_recon_proceeds(self):
        graph = self._graph()
        exploit = graph.add_intent("exploit", "privileged-pod-escape",
                                   priority=10)
        recon = graph.add_intent("recon", "kubelet-surface", priority=1)
        scheduler = TaskScheduler(graph, Budget(steps=5, actions=5, tokens=50),
                                  defense_gate=dp.DefenseGate(graph))
        claimed = scheduler.claim_next("w1")
        self.assertEqual(claimed["id"], recon["id"])
        blocked = [i for i in graph.intents() if i["id"] == exploit["id"]]
        self.assertEqual(blocked[0]["status"], "blocked")
        self.assertGreaterEqual(scheduler.status.defense_refused, 1)
        state = scheduler.state()["status"]
        self.assertEqual(state["defense_refused"], 1)

    def test_bypass_variant_is_claimed_with_technique_id(self):
        graph = self._graph()
        tech = dp.select_technique("falco")
        bypass = dp.bypass_params(tech, script="echo INKBLADE-BENIGN")
        intent = graph.add_intent("exploit", "lateral-exec", priority=10,
                                  params={"bypass": bypass})
        scheduler = TaskScheduler(graph, Budget(steps=5, actions=5, tokens=50),
                                  defense_gate=dp.DefenseGate(graph))
        claimed = scheduler.claim_next("w1")
        self.assertEqual(claimed["id"], intent["id"])
        self.assertEqual(claimed["defense_bypass"]["technique_id"], tech.id)
        self.assertEqual(claimed["params"]["bypass"]["technique_id"], tech.id)

    def test_bypass_params_shape(self):
        tech = dp.select_technique("falco")
        params = dp.bypass_params(
            tech, script="echo INKBLADE-BENIGN", workdir="/dev/shm",
            monitored_paths=["/tmp"], target={"namespace": "default", "pod": "p"})
        plan = params["plan"]
        self.assertEqual(plan["techniques"], [tech.id])
        self.assertTrue(plan["clean_env"])
        self.assertEqual(plan["workdir"], "/dev/shm")
        self.assertEqual(plan["target"]["namespace"], "default")


class TestAlertParsing(unittest.TestCase):
    FALCO = (
        "00:59:06.552981500: Notice Unexpected connection to K8s API Server from container"
        " | connection=10.42.0.1:1->10.43.0.1:443 container_name=attacker"
        " k8s_ns_name=default proc_exepath=/proc/self/fd/3 command=kubectl exec\n"
        "00:58:31.1: Critical Executing binary not part of base image"
        " | proc_exe=/tmp/inkblade-echo container_name=falco-probe"
        " k8s_ns_name=default command=inkblade-echo INKBLADE-BENIGN\n"
        "Tue Oct 27 00:58:38 2026: One ring buffer every '2' CPUs.\n"
    )
    KYVERNO = (
        'Error from server: error when creating "STDIN": admission webhook '
        '"vpol.validate.kyverno.svc-fail-finegrained-defense-lab-disallow-privileged" '
        'denied the request: Policy defense-lab-disallow-privileged failed: '
        'Privileged mode is disallowed in defense-lab.\n'
    )

    def test_falco_alerts(self):
        alerts = dp.parse_falco_alerts(self.FALCO)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[1]["priority"], "Critical")
        self.assertEqual(alerts[1]["rule"],
                         "Executing binary not part of base image")
        self.assertEqual(alerts[1]["fields"]["container_name"], "falco-probe")
        attributed = dp.attribute_alerts(alerts)
        self.assertIn("existing-binary-exec", attributed[1]["technique_ids"])
        self.assertIn("sa-permission-selection", attributed[0]["technique_ids"])

    def test_kyverno_denials(self):
        denials = dp.parse_kyverno_denials(self.KYVERNO)
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0]["policy"],
                         "defense-lab-disallow-privileged")
        self.assertIn("Privileged mode", denials[0]["message"])

    def test_record_bypass_shape(self):
        record = dp.record_bypass(
            {"marker": "INKBLADE-BENIGN", "namespace": "default"},
            detected=dp.parse_posture(posture_fixture()),
            technique_id="namespace-scope-evasion",
            alerts=dp.parse_falco_alerts(self.FALCO),
            denials=dp.parse_kyverno_denials(self.KYVERNO))
        self.assertEqual(record["detected_products"], ["admission", "falco"])
        self.assertEqual(record["technique_id"], "namespace-scope-evasion")
        self.assertEqual(record["alert_count"], 2)
        self.assertEqual(record["denial_count"], 1)
        self.assertTrue(record["benign_only"])


class TestBypassTemplateWiring(unittest.TestCase):
    def _template(self):
        return {
            "schema": schema.SCHEMA_ID,
            "key": "bypass-probe",
            "version": "1.0.0",
            "meta": {
                "name": {"zh": "bypass", "en": "bypass"},
                "series": schema.SERIES[0],
                "min_level": schema.LEVELS[0],
                "writes": True,
            },
            "steps": [{
                "id": "run",
                "op": "bypass",
                "techniques": ["fileless-memfd-exec"],
                "script": "echo INKBLADE-BENIGN",
                "workdir": "/dev/shm",
                "save": "bypass",
            }],
            "checks": [],
            "payloads": {},
        }

    def test_schema_accepts_bypass_step(self):
        errors = schema.validate(self._template())
        self.assertEqual(errors, [])

    def test_lowering_keeps_bypass_native(self):
        compilation = lower.compile_template(self._template(), {}, {})
        self.assertEqual(compilation.gaps, [])
        step = compilation.native_template["steps"][0]
        self.assertEqual(step["op"], "bypass")
        self.assertEqual(step["techniques"], ["fileless-memfd-exec"])
        self.assertEqual(step["workdir"], "/dev/shm")

    def test_schema_rejects_bypass_without_payload(self):
        template = self._template()
        template["steps"][0].pop("script")
        self.assertTrue(any("bypass" in error for error in schema.validate(template)))


class TestProbePrimitivesSource(unittest.TestCase):
    """The Rust primitives exist and keep the fileless/existing-binary split."""

    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "probe" / "src" / "bypass.rs").read_text(encoding="utf-8")

    def test_memfd_primitive(self):
        self.assertIn("SYS_memfd_create", self.source)
        self.assertIn("/proc/self/fd/", self.source)
        self.assertIn("artifact_paths", self.source)

    def test_existing_binary_primitive(self):
        self.assertIn("existing-binary-exec", self.source)
        self.assertIn("/bin/busybox", self.source)
        self.assertIn("binary_sha256", self.source)

    def test_no_disk_fallback_for_memfd(self):
        self.assertIn("fileless", self.source)
        self.assertIn("no_new_binary", self.source)


if __name__ == "__main__":
    unittest.main()
