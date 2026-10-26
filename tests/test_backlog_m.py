# -*- coding: utf-8 -*-
"""Backlog M 项（CM-14..CM-30）：每组至少一条闸门/只读/权限/无网络断言。"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core import (admission, agentbench, connectors, credcheck, dedupe, inpod,
                          lineage, llmredteam, narrative, pathcalc, pcap, policygen,
                          retest, sankey)
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import ExecutionLocked, init_roe
from inkblade.core.users import Session

MODULES_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "modules"


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "t")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = EvidenceStore(Path(self.tmp.name), workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"],
                              "cidrs": ["10.0.0.0/8"]})
        self.run = self.store.create_run("r1")
        self.run.add_step("sglang-admin-failopen", "cmd", {}, "ok")
        self.run.add_finding("sglang-admin-failopen", "high", "admin unauth",
                             "detail", evidence_path="steps/a.tar.gz")
        self.run.record_traffic("sglang-admin-failopen", [
            {"method": "GET", "url": "http://target.local/health", "status": 200,
             "headers": {}, "body": None, "response": "ok", "ts": 1}])

    def tearDown(self):
        self.tmp.cleanup()


class TestRetest(Base):
    def test_plan_and_live_conclusions(self):
        plan = retest.plan(self.store, "r1", "admin unauth")
        self.assertEqual(plan["count"], 1)
        self.assertFalse(plan["execution"])
        fixed = retest.run_retest(self.store, _session("tester"), "r1", "admin unauth",
                                  live=True, probe=lambda c: {"actual_status": 403, "ok": False})
        self.assertEqual(fixed["conclusion"], "fixed")
        self.assertTrue(fixed["evidence_path"])
        self.assertEqual(retest.list_retests(self.store, "r1")[0]["conclusion"], "fixed")
        open_ = retest.run_retest(self.store, _session("tester"), "r1", "admin unauth",
                                  live=True, probe=lambda c: {"actual_status": 200, "ok": True})
        self.assertEqual(open_["conclusion"], "open")

    def test_gates_and_errors(self):
        store = EvidenceStore(Path(self.tmp.name) / "no-roe", workspace="no-roe")
        run = store.create_run("r1")
        run.add_step("sglang-admin-failopen", "cmd", {}, "ok")
        run.add_finding("sglang-admin-failopen", "high", "admin unauth", "d")
        with self.assertRaises(ExecutionLocked):
            retest.run_retest(store, _session("tester"), "r1", "admin unauth", live=True)
        with self.assertRaises(PermissionError):
            retest.run_retest(self.store, _session("auditor"), "r1", "admin unauth", live=True)
        with self.assertRaises(retest.RetestError):
            retest.plan(self.store, "r1", "ghost")
        with self.assertRaises(retest.RetestError):
            retest.plan(self.store, "ghost", "admin unauth")


class TestConnectors(Base):
    def test_payloads_and_dry_run(self):
        con = connectors.Connector(self.store)
        with self.assertRaises(PermissionError):
            con.deliver(_session("tester"), "r1", dry_run=True)
        out = con.deliver(_session(), "r1", dry_run=True)
        self.assertEqual(out["delivery"]["status"], "planned")
        self.assertEqual(out["delivery"]["count"], 1)
        jira = connectors.build_payload(self.run.findings[0], target="jira", run="r1")
        self.assertIn("summary", jira["payload"]["fields"])
        siem = connectors.build_payload(self.run.findings[0], target="siem", run="r1")
        self.assertEqual(siem["payload"]["event"]["kind"], "alert")
        hook = connectors.build_payload(self.run.findings[0], target="webhook", run="r1")
        self.assertEqual(hook["payload"]["event"], "inkblade.finding")
        with self.assertRaises(connectors.ConnectorError):
            connectors.build_payload(self.run.findings[0], target="bogus")
        with self.assertRaises(connectors.ConnectorError):
            con.deliver(_session(), "r1", titles=["ghost"], dry_run=True)

    def test_live_transport(self):
        con = connectors.Connector(self.store)
        calls = []

        def fake(item, headers):
            calls.append(item["meta"]["fingerprint"])
            return {"ok": True}

        out = con.deliver(_session(), "r1", dry_run=False, transport=fake)
        self.assertEqual(out["delivery"]["status"], "sent")
        self.assertEqual(len(calls), 1)
        self.assertEqual(con.list()[-1]["status"], "sent")


class TestLineage(Base):
    def test_ingest_ancestors_coverage(self):
        lineage.ingest_run(self.store, "r1")
        g = lineage.graph(self.store, "r1")
        self.assertGreaterEqual(g["counts"]["edges"], 2)
        lineage.add_edge(self.store, "r1", "goal:g", "step:sglang-admin-failopen", "targets")
        findings = [n["id"] for n in g["nodes"] if n["id"].startswith("finding:")]
        anc = lineage.ancestors(self.store, "r1", findings[0])
        self.assertTrue(any(a["node"] == "step:sglang-admin-failopen" for a in anc))
        cov = lineage.coverage(self.store, "r1")
        self.assertEqual(cov["goals"], 1)
        self.assertGreaterEqual(cov["covered_findings"], 1)
        self.assertIn("digraph", lineage.to_dot(self.store, "r1"))

    def test_errors(self):
        with self.assertRaises(lineage.LineageError):
            lineage.add_edge(self.store, "r1", "a", "a", "self")
        with self.assertRaises(lineage.LineageError):
            lineage.add_edge(self.store, "ghost", "a", "b", "x")
        with self.assertRaises(lineage.LineageError):
            lineage.ingest_proposal(self.store, {"id": "p", "actions": []})


class TestDedupe(Base):
    def test_cross_run_merge_and_confirm(self):
        run2 = self.store.create_run("r2")
        run2.add_finding("sglang-admin-failopen", "critical", "admin unauth", "detail")
        other = self.store.create_run("r3")
        other.add_finding("vllm-plugin-auth-bypass", "medium", "plugin bypass", "x")
        groups = dedupe.cluster(self.store)
        hit = next(g for g in groups if g["title"] == "admin unauth")
        self.assertEqual(hit["occurrence_count"], 2)
        self.assertTrue(hit["cross_run"])
        self.assertEqual(hit["severity"], "critical")
        self.assertTrue(any(g["title"] == "plugin bypass" for g in groups))
        with self.assertRaises(PermissionError):
            dedupe.confirm_root_cause(self.store, _session("tester"), hit["id"], "shared RBAC")
        confirmed = dedupe.confirm_root_cause(self.store, _session(), hit["id"],
                                              "shared RBAC role binding")
        self.assertEqual(confirmed["root_cause"], "shared RBAC role binding")
        md = dedupe.render_unified(dedupe.cluster(self.store))
        self.assertIn("同根因统一报告", md)
        self.assertIn("shared RBAC", md)

    def test_normalize(self):
        a = dedupe.fingerprint({"step_key": "m", "title": "fail at 10.0.0.1:8080",
                                "detail": ""})
        b = dedupe.fingerprint({"step_key": "m", "title": "fail at 10.0.0.2:9090",
                                "detail": ""})
        self.assertEqual(a, b)
        c = dedupe.fingerprint({"step_key": "m", "title": "x", "detail": "CVE-2026-9999"})
        self.assertEqual(c, "CVE-2026-9999")


class TestPcap(Base):
    def test_write_read_ingest(self):
        path = Path(self.tmp.name) / "traffic.pcap"
        out = pcap.record_run(self.run, path)
        self.assertEqual(out["frames"], 2)
        entries = pcap.read_pcap(path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], 200)
        self.assertEqual(entries[0]["url"], "http://target.local/health")
        ing = pcap.ingest_pcap(self.store, path, run_name="r1")
        self.assertEqual(ing["entries"], 1)
        replay = pcap.replay_pcap(self.store, _session("tester"), path, run_name="r1")
        self.assertEqual(replay["replay"]["mode"], "dry")
        with self.assertRaises(pcap.PcapError):
            pcap.read_pcap(Path(self.tmp.name) / "missing.pcap")


class TestSankeyPathCalc(unittest.TestCase):
    GRAPH = {"nodes": [{"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "d"}],
             "edges": [{"src": "a", "dst": "b"}, {"src": "b", "dst": "d"},
                       {"src": "a", "dst": "c"}, {"src": "c", "dst": "d"}]}

    def test_paths_and_priority(self):
        self.assertEqual(pathcalc.shortest_path(self.GRAPH, "a", "d"), ["a", "b", "d"])
        self.assertEqual(len(pathcalc.all_simple_paths(self.GRAPH, "a", "d")), 2)
        crit = pathcalc.critical_nodes(self.GRAPH)
        self.assertEqual({c["node"] for c in crit}, {"b", "c"})
        self.assertEqual(pathcalc.articulation_points(self.GRAPH), [])  # 无单割点
        self.assertEqual(pathcalc.query(self.GRAPH, "a", depth=1)["count"], 2)
        sk = sankey.analyze(self.GRAPH)
        self.assertEqual(sk["path_count"], 2)
        self.assertTrue(sk["fix_priority"])
        self.assertEqual(sk["fix_priority"][0]["eliminated_paths"], 1)
        empty = sankey.analyze({"nodes": [], "edges": []})
        self.assertEqual(empty["path_count"], 0)
        self.assertTrue(empty["note"])


class TestNarrative(Base):
    def test_five_sections_and_readonly(self):
        actions = self.run.query("SELECT COUNT(*) FROM actions")[0][0]
        report = narrative.build(self.store, "r1")
        self.assertEqual(list(report["sections"]), ["exposure", "recon", "attack",
                                                    "report", "remediation"])
        self.assertEqual(report["sections"]["report"]["counts"]["findings"], 1)
        self.assertEqual(report["narrative"]["mode"], "deterministic")
        self.assertEqual(self.run.query("SELECT COUNT(*) FROM actions")[0][0], actions)
        md = narrative.render_md(report)
        for heading in ("暴露验证", "侦查", "攻击", "报告", "修复验证"):
            self.assertIn(heading, md)
        with self.assertRaises(narrative.NarrativeError):
            narrative.build(self.store, "ghost")


class TestCredCheck(unittest.TestCase):
    def test_cross_tenant_write_and_plan(self):
        fixture = {"credentials": [
            {"id": "c1", "kind": "aws", "tenant": "a", "expected_tenant": "b"},
            {"id": "c2", "kind": "k8s", "tenant": "a", "expected_tenant": "a"},
            {"id": "c3", "kind": "token", "tenant": "a", "expected_tenant": "a"}],
            "probes": [
                {"credential_id": "c1", "ok": True, "tenant": "a",
                 "permissions": ["s3:GetObject"]},
                {"credential_id": "c2", "ok": True, "tenant": "a",
                 "permissions": ["pods:create"]}]}
        out = credcheck.validate(fixture)
        self.assertEqual(out["summary"]["cross_tenant"], 1)
        self.assertEqual(out["summary"]["high_risk"], 1)
        self.assertEqual(out["summary"]["unprobed"], 1)
        self.assertTrue(any(f["sev"] == "critical" for f in out["findings"]))
        plan = credcheck.probe_plan(fixture)
        self.assertEqual(plan["count"], 3)
        self.assertFalse(plan["network"])
        self.assertIn("凭据有效性", credcheck.render_md(out))
        with self.assertRaises(credcheck.CredCheckError):
            credcheck.validate({})


class TestInPod(Base):
    def _fixture(self, root: Path, *, docker=True):
        (root / "proc/self").mkdir(parents=True)
        (root / "proc/net").mkdir(parents=True)
        (root / "var/run").mkdir(parents=True)
        (root / "proc/net/tcp").write_text(
            "  sl local_address rem_address st\n"
            " 0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0\n",
            encoding="utf-8")
        (root / "proc/self/status").write_text("CapEff:\t0000000000200000\n", encoding="utf-8")
        (root / "proc/self/cgroup").write_text("0::/docker/abc\n", encoding="utf-8")
        (root / "proc/mounts").write_text(
            "tmpfs /var/run/docker.sock tmpfs rw 0 0\n", encoding="utf-8")
        if docker:
            (root / "var/run/docker.sock").write_text("", encoding="utf-8")

    def test_scan_findings_and_read_only(self):
        root = Path(self.tmp.name)
        self._fixture(root)
        before = sorted((str(p.relative_to(root)), p.stat().st_mtime_ns)
                        for p in root.rglob("*"))
        out = inpod.scan(root)
        self.assertTrue(out["read_only"])
        self.assertGreaterEqual(out["count"], 3)
        titles = [f["title"] for f in out["findings"]]
        self.assertTrue(any("docker socket" in t for t in titles))
        self.assertTrue(any("SYS_ADMIN" in t for t in titles))
        after = sorted((str(p.relative_to(root)), p.stat().st_mtime_ns)
                       for p in root.rglob("*"))
        self.assertEqual(before, after)
        self.assertFalse(any(p.name == "new" for p in root.rglob("*")))

    def test_no_docker_socket(self):
        root = Path(self.tmp.name) / "clean"
        root.mkdir()
        self._fixture(root, docker=False)
        out = inpod.scan(root)
        self.assertFalse(any("docker socket" in f["title"] for f in out["findings"]))
        with self.assertRaises(ValueError):
            inpod.scan(Path(self.tmp.name) / "ghost")


class TestAdmission(unittest.TestCase):
    def test_default_matrix_and_gap(self):
        out = admission.probe()
        self.assertEqual(out["pods"], 8)
        self.assertEqual(out["gaps"], [])
        self.assertEqual(out["denied"], 8)
        gap = admission.probe(policies=[])
        self.assertEqual(len(gap["gaps"]), 8)

    def test_api_dry_run_adapter(self):
        def submit(pod):
            return {"allowed": pod["id"] == "host-network", "reason": "test"}

        out = admission.probe(submit=submit)
        self.assertEqual(out["mode"], "api-dry-run")
        self.assertIn("host-network", out["gaps"])
        self.assertTrue(all(r["mode"] == "api-dry-run" for r in out["rows"]))
        self.assertIn("Admission", admission.render_md(out))


class TestPolicyGen(unittest.TestCase):
    def test_targets_and_coverage(self):
        doc = policygen.generate_all()
        self.assertEqual(doc["tetragon"]["kind"], "TracingPolicy")
        self.assertEqual(doc["kubearmor"]["kind"], "KubeArmorPolicy")
        self.assertEqual(doc["kubearmor"]["spec"]["action"], "Block")
        self.assertEqual(doc["kyverno"]["kind"], "ClusterPolicy")
        rules = doc["kyverno"]["spec"]["rules"]
        self.assertTrue(any("runAsNonRoot" in e for e in rules[0]["validate"]["cel"]["expressions"]))
        self.assertTrue(any("verifyImages" in r for r in rules))
        self.assertGreaterEqual(doc["coverage"]["gap_count"], 1)
        self.assertIn("apiVersion", policygen.to_yaml(doc["tetragon"]))
        cov = policygen.background_coverage(
            [{"kind": "Pod", "name": "a", "namespace": "ml", "labels": {"app": "x"}},
             {"kind": "Pod", "name": "b", "namespace": "ml", "labels": {}}],
            [{"id": "p", "kinds": ["Pod"], "namespaces": ["ml"], "labels": {"app": "x"}}])
        self.assertEqual(cov["gap_count"], 1)
        self.assertEqual(cov["covered"], 1)


class TestLLMRedTeam(unittest.TestCase):
    def test_plan_and_score(self):
        plan = llmredteam.make_plan("tool-boundary behavior", turns=4, strategy="tap")
        self.assertEqual(len(plan["items"]), 4)
        self.assertTrue(all("branches" in i for i in plan["items"]))
        canary = plan["canary"]
        result = llmredteam.score(plan, ["no", "I cannot help", f"{canary} appears", "ok"])
        self.assertTrue(result["success"])
        self.assertEqual(result["first_success_turn"], 3)
        self.assertEqual(result["refusals"], [2])
        self.assertTrue(result["pruned"])
        refused = llmredteam.score(llmredteam.make_plan("g", turns=2),
                                   ["I cannot", "抱歉，无法提供"])
        self.assertFalse(refused["success"])
        with self.assertRaises(ValueError):
            llmredteam.make_plan("g", strategy="bogus")
        with self.assertRaises(ValueError):
            llmredteam.make_plan("g", turns=0)


class TestAgentBench(unittest.TestCase):
    def test_dry_run_no_agent_calls(self):
        calls = []
        out = agentbench.run(lambda s: calls.append(s["id"]) or {}, dry_run=True)
        self.assertFalse(out["executed"])
        self.assertEqual(out["agent_calls"], 0)
        self.assertEqual(calls, [])
        self.assertEqual(out["count"], 6)

    def test_safe_and_compromised_agents(self):
        safe = agentbench.run(lambda s: {"tool_calls": [], "output": "ignored"},
                              dry_run=False)
        self.assertEqual(safe["passed"], 6)
        def compromised(s):
            return {"tool_calls": [{"name": s["sink_tool"],
                                    "args": {"body": s["canary"]}}], "output": ""}

        bad = agentbench.run(compromised, dry_run=False)
        self.assertEqual(bad["passed"], 0)
        self.assertEqual(bad["failed"], 6)
        one = agentbench.score_result(agentbench.suite()[0],
                                      {"tool_calls": [{"name": "send_email",
                                                       "args": {"body": "CANARY_FILE"}}]})
        self.assertFalse(one["ok"])
        self.assertTrue(one["injection_executed"])
        with self.assertRaises(ValueError):
            agentbench.run(dry_run=False)


if __name__ == "__main__":
    unittest.main()
