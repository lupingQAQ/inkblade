# -*- coding: utf-8 -*-
"""Backlog S 项（CM-01..CM-13）：每组至少一条断言含闸门/只读/权限。"""

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core import (cigate, decisions, dispatch, evalconfig, importers, intel, kb,
                          rulemacro, search, tokenaudit)
from inkblade.core.discovery import AssetInventory
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import ExecutionLocked, init_roe
from inkblade.core.runner import run_module
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
        AssetInventory(self.store).ingest({"services": [
            {"name": "sglang-admin", "namespace": "ml", "addr": "10.96.0.11",
             "port": 30000, "labels": {"app": "sglang"}}]})
        self.run = self.store.create_run("r1")
        art = Path(self.run.dir) / "artifacts" / "note.txt"
        art.parent.mkdir(exist_ok=True)
        art.write_text("needle artifact content", encoding="utf-8")
        self.step = self.run.add_step("sglang-admin-failopen",
                                      "{'probe': 'auth-bypass'} needle prompt",
                                      {"k": "v"}, "needle summary", artifacts=[art])
        self.run.add_finding("sglang-admin-failopen", "high", "needle admin unauth",
                             "detail needle", evidence_path=self.step["archive"])

    def tearDown(self):
        self.tmp.cleanup()


class TestIntel(Base):
    def test_three_states_and_evidence_binding(self):
        ir = intel.IntelRegistry(self.store)
        e = ir.add(_session(), kind="credential", label="key", value="sk-123456789",
                   run="r1", source_step="sglang-admin-failopen",
                   evidence_path=self.step["archive"], mode="metadata")
        self.assertEqual(e["mode"], "metadata")
        self.assertEqual(e["length"], 12)
        self.assertNotIn("preview", e)
        self.assertTrue(e["evidence_sha256"])
        r = ir.add(_session(), kind="credential", label="key2", value="sk-abcdefgh",
                   mode="redact")
        self.assertEqual(r["preview"], "sk-***gh")
        with self.assertRaises(PermissionError):
            ir.add(_session("tester"), kind="credential", label="raw", value="x",
                   mode="raw", allow_raw=True)
        raw = ir.add(_session(), kind="credential", label="raw", value="top-secret",
                     mode="raw", allow_raw=True)
        self.assertTrue(raw["has_raw"])
        with self.assertRaises(PermissionError):
            ir.reveal(_session("auditor"), raw["id"])
        self.assertEqual(ir.reveal(_session(), raw["id"])["value"], "top-secret")
        with self.assertRaises(intel.IntelError):
            ir.add(_session(), kind="clue", label="x", run="r1", source_step="ghost")
        with self.assertRaises(intel.IntelError):
            ir.add(_session(), kind="clue", label="x", run="r1",
                   source_step="sglang-admin-failopen", evidence_path="nope.tar.gz")
        self.assertNotIn("value", json.dumps(ir.list(), ensure_ascii=False))

    def test_update_and_stats(self):
        ir = intel.IntelRegistry(self.store)
        e = ir.add(_session(), kind="clue", label="c", value="v")
        with self.assertRaises(PermissionError):
            ir.update(_session("tester"), e["id"], label="x")
        up = ir.update(_session(), e["id"], label="renamed", note="n")
        self.assertEqual(up["label"], "renamed")
        self.assertEqual(ir.stats()["bound_to_evidence"], 0)


class TestSearch(Base):
    def _seed(self):
        self.run.record_traffic("m", [{"method": "GET", "url": "http://needle.local/x",
                                       "status": 200, "headers": {},
                                       "body": None, "response": "needle resp", "ts": 1}])
        self.run.log_action("tester", "probe", "needle-target", {}, "started")

    def test_cross_run_search_and_anchors(self):
        self._seed()
        out = search.search(self.store, "needle", kinds=["steps", "findings", "actions", "traffic"])
        kinds = {h["kind"] for h in out["hits"]}
        self.assertIn("step", kinds)
        self.assertIn("finding", kinds)
        self.assertIn("action", kinds)
        self.assertIn("traffic", kinds)
        self.assertTrue(all(h["run"] == "r1" for h in out["hits"]))
        self.assertGreaterEqual(out["anchors"], 3)
        art = search.search(self.store, "needle", kinds=["artifacts"])
        self.assertEqual(art["hits"][0]["kind"], "artifact")
        self.assertIn("#note.txt", art["hits"][0]["evidence"])

    def test_search_is_read_only_and_validates(self):
        actions = self.run.query("SELECT COUNT(*) FROM actions")[0][0]
        search.search(self.store, "needle")
        self.assertEqual(self.run.query("SELECT COUNT(*) FROM actions")[0][0], actions)
        with self.assertRaises(search.SearchError):
            search.search(self.store, "")
        with self.assertRaises(search.SearchError):
            search.search(self.store, "x", kinds=["bogus"])
        with self.assertRaises(search.SearchError):
            search.search(self.store, "x", run="ghost")
        self.assertEqual(search.search(self.store, "no-such-token")["count"], 0)


class TestDecisions(Base):
    def test_record_and_validate(self):
        d = decisions.record(self.store, "r1", kind="tactic", goal="chain:x",
                             options=["a", "b"], chosen="a", rationale="证据优先",
                             actor="lead")
        self.assertEqual(d["chosen"], "a")
        self.assertEqual(len(decisions.list_decisions(self.store, "r1")), 1)
        with self.assertRaises(decisions.DecisionError):
            decisions.record(self.store, "r1", kind="tactic", goal="g", options=["a"],
                             chosen="c", rationale="x", actor="lead")
        with self.assertRaises(decisions.DecisionError):
            decisions.record(self.store, "r1", kind="tactic", goal="g", options=[],
                             chosen="a", rationale="", actor="lead")
        actions = [r[0] for r in self.run.query("SELECT action FROM actions")]
        self.assertIn("decision", actions)

    def test_record_plan(self):
        plan = {"run": "r1", "candidates": [
            {"chain": "c1", "rank": 1, "verdict": "成立", "reasons": {"zh": ["ok"]}},
            {"chain": "c2", "rank": 2, "verdict": "部分成立", "reasons": {"zh": ["maybe"]}}]}
        out = decisions.record_plan(self.store, plan, actor="cli")
        self.assertEqual(out["count"], 2)
        rows = decisions.list_decisions(self.store, "r1")
        self.assertEqual(rows[0]["chosen"], "c1")
        self.assertIn("rank=1", rows[0]["rationale"])
        with self.assertRaises(decisions.DecisionError):
            decisions.record_plan(self.store, {"candidates": plan["candidates"]}, actor="cli")


class TestTokenAudit(unittest.TestCase):
    def test_legacy_write_expired_duplicate_and_wildcard(self):
        tokens = [
            {"name": "legacy-a", "namespace": "ml", "legacy": True, "jti": "same",
             "expires_at": 1, "rules": [{"verbs": ["*"], "resources": ["*"]}]},
            {"name": "legacy-b", "namespace": "ml", "legacy": True, "jti": "same",
             "rules": [{"verbs": ["get"], "resources": ["secrets"]}]},
        ]
        requests = [
            {"verb": "create", "resource": "pods", "namespace": "ml", "name": "p"},
            {"verb": "get", "resource": "secrets", "namespace": "ml", "name": "s"},
            {"verb": "delete", "resource": "deployments", "namespace": "other", "name": "d"},
        ]
        out = tokenaudit.audit_tokens(tokens, requests, now=100)
        self.assertEqual(out["tokens"], 2)
        legacy = out["per_token"][0]
        self.assertEqual(legacy["summary"]["allowed"], 3)
        self.assertTrue(any("legacy" in f["title"] for f in legacy["findings"]))
        self.assertTrue(any("过期" in f["title"] for f in legacy["findings"]))
        self.assertTrue(any("敏感" in f["title"] for f in legacy["findings"]))
        self.assertTrue(any("重复 jti" in f["title"] for f in out["findings"]))
        self.assertEqual(out["summary"]["legacy"], 2)
        self.assertGreaterEqual(out["summary"]["high_risk"], 1)
        with self.assertRaises(tokenaudit.TokenAuditError):
            tokenaudit.audit_tokens([], requests)


class TestKB(unittest.TestCase):
    def test_cite_bilingual_and_fallback(self):
        hit = kb.cite({"step_key": "sglang-admin-failopen", "title": "admin unauth"})
        self.assertEqual(hit["key"], "INKBLADE-KB-003")
        self.assertTrue(hit["title"]["zh"] and hit["title"]["en"])
        miss = kb.cite({"step_key": "mystery", "title": "unmapped behavior"})
        self.assertEqual(miss["key"], "INKBLADE-KB-000")
        self.assertIn("Unclassified", kb.render_md("INKBLADE-KB-000"))
        self.assertEqual(kb.stats()["bilingual"], True)


class TestKubeletModule(Base):
    @unittest.skip('legacy run.py module assertions retired with the Python execution path')
    def test_read_only_module_and_gate(self):
        snap = {"kubelets": [{"addr": "10.0.0.5", "port": 10250, "anonymous_auth": True,
                              "token_harvestable": True, "running_pods_exposed": True}]}
        res = run_module(self.store, _session("tester"), "kubelet-surface",
                         {"snapshot": snap}, MODULES_DIR)
        run = self.store.open_run(res["run"])
        titles = [f["title"] for f in run.findings]
        self.assertEqual(len(titles), 3)
        self.assertTrue(any("匿名鉴权" in t for t in titles))
        self.assertTrue(any("token" in t for t in titles))
        meta = next(m for m in __import__("inkblade.core.registry", fromlist=["load_modules"])
                    .load_modules(MODULES_DIR).values() if m.key == "kubelet-surface")
        self.assertFalse(meta.writes)

    def test_roe_gate(self):
        store = EvidenceStore(Path(self.tmp.name) / "no-roe", workspace="no-roe")
        with self.assertRaises(ExecutionLocked):
            run_module(store, _session("tester"), "kubelet-surface",
                       {"snapshot": {"kubelets": []}}, MODULES_DIR)


class TestRuleMacro(unittest.TestCase):
    def test_expand_and_falco(self):
        b = rulemacro.default_builder()
        exp = b.expand("${macro:container_escape_signal}")
        self.assertIn("execve", exp["condition"])
        self.assertIn("shell_binaries", exp["lists"])
        self.assertEqual(exp["depth"], 2)
        falco = b.to_falco(rule="InkBlade Shell", expr="${macro:spawn_shell}")
        self.assertEqual(falco["rule"], "InkBlade Shell")
        self.assertIn("condition", falco)

    def test_cycle_unknown_and_validate(self):
        b = rulemacro.RuleBuilder()
        b.add_macro("a", "${macro:b}")
        b.add_macro("b", "${macro:a}")
        with self.assertRaises(rulemacro.MacroError):
            b.expand("${macro:a}")
        with self.assertRaises(rulemacro.MacroError):
            rulemacro.RuleBuilder().expand("${list:missing}")
        with self.assertRaises(rulemacro.MacroError):
            rulemacro.RuleBuilder().add_list("Bad-Name", ["x"])
        b2 = rulemacro.RuleBuilder()
        b2.add_list("empty", [])
        self.assertEqual(b2.expand("${list:empty}")["condition"], "(false)")


class TestDispatch(Base):
    def test_file_stdout_and_safety_defaults(self):
        out = dispatch.dispatch(self.store, "finding.critical", {"title": "x"},
                                [{"type": "stdout"}, {"type": "file", "path": "dispatch.jsonl"}])
        self.assertEqual(out["planned"], 1)
        self.assertIn("finding.critical", out["results"][0]["line"])
        self.assertFalse((self.store.ws_dir / "dispatch.jsonl").exists())
        dispatch.dispatch(self.store, "finding.critical", {"title": "x"},
                          [{"type": "file", "path": "dispatch.jsonl"}], allow_write=True)
        self.assertTrue((self.store.ws_dir / "dispatch.jsonl").is_file())
        outside = dispatch.dispatch(self.store, "x", {}, [{"type": "file", "path": "../escape.jsonl"}],
                                    allow_write=True)
        self.assertFalse(outside["results"][0]["ok"])
        with self.assertRaises(dispatch.DispatchError):
            dispatch.dispatch(self.store, "x", {}, [{"type": "bogus"}])

    def test_program_and_http_require_switches(self):
        prog = dispatch.dispatch(self.store, "x", {}, [{"type": "program", "path": "x"}])
        self.assertFalse(prog["results"][0]["ok"])
        planned = dispatch.dispatch(self.store, "x", {}, [{"type": "http", "url": "http://127.0.0.1:9/x"}])
        self.assertTrue(planned["results"][0]["planned"])
        self.assertTrue((self.store.ws_dir / "audit.jsonl").is_file())


class TestCiGate(Base):
    def test_exit_codes_and_baseline(self):
        high = [{"step_key": "m", "title": "A", "severity": "high", "evidence_path": "e"}]
        r = cigate.evaluate(high, {"fail_on": "high"})
        self.assertEqual(r["exit_code"], cigate.EXIT_POLICY)
        r = cigate.evaluate(high, {"fail_on": "high",
                                   "baseline": [{"step_key": "m", "title": "A"}]})
        self.assertEqual(r["exit_code"], cigate.EXIT_POLICY)
        r = cigate.evaluate(high, {"fail_on": "high", "fail_on_new_only": True,
                                   "baseline": [{"step_key": "m", "title": "A"}]})
        self.assertEqual(r["exit_code"], cigate.EXIT_OK)
        new = [{"step_key": "m", "title": "B", "severity": "critical"}]
        r = cigate.evaluate(new, {"fail_on": "high", "baseline": [{"step_key": "m", "title": "A"}]})
        self.assertEqual(r["exit_code"], cigate.EXIT_REGRESSION)
        with self.assertRaises(cigate.CiGateError):
            cigate.evaluate(high, {"fail_on": "bogus"})
        zero = [{"step_key": "m", "title": "Z", "severity": "critical", "is_zeroday": True}]
        self.assertEqual(cigate.evaluate(zero, {"fail_on": "high",
                                                "allow_zeroday": True})["exit_code"], 0)

    def test_run_and_summary(self):
        res = cigate.evaluate_run(self.store, "r1", {"fail_on": "high"})
        self.assertEqual(res["exit_code"], cigate.EXIT_POLICY)
        out = Path(self.tmp.name) / "gate.json"
        cigate.write_summary(res, out)
        self.assertTrue(out.is_file())
        self.assertEqual(cigate.baseline_from_runs(self.store, ["r1"]),
                         ["sglang-admin-failopen|needle admin unauth"])


class TestEvalConfig(Base):
    def test_yaml_evaluate_and_baseline(self):
        cfg = evalconfig.loads(
            "name: baseline\n"
            "modules:\n"
            "  - sglang-admin-failopen\n"
            "chains:\n"
            "  - flat-network-admin-plane-weight-poison\n"
            "thresholds:\n"
            "  fail_on: high\n"
            "  fail_on_new_only: true\n")
        res = evalconfig.evaluate(self.store, cfg, run="r1",
                                  modules_dir=MODULES_DIR)
        self.assertEqual(res["matrix"]["modules"][0]["module"], "sglang-admin-failopen")
        self.assertEqual(res["matrix"]["modules"][0]["status"], "fail")
        self.assertEqual(res["gate"]["exit_code"], cigate.EXIT_REGRESSION)
        self.assertIn("评估矩阵", evalconfig.render_md(res))

    def test_invalid_configs(self):
        with self.assertRaises(evalconfig.EvalConfigError):
            evalconfig.loads("modules: []\n")
        with self.assertRaises(evalconfig.EvalConfigError):
            evalconfig.loads("name: x\nmodules:\n  - a\nthresholds:\n  fail_on: nope\n")
        with self.assertRaises(evalconfig.EvalConfigError):
            evalconfig.loads("modules: [a\n")


class TestImporters(Base):
    def test_trivy_ingest_idempotent_and_gate(self):
        doc = {"Results": [{"Target": "img", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2025-1", "PkgName": "x", "InstalledVersion": "1",
             "Severity": "HIGH", "Title": "t", "FixedVersion": "2"}]}]}
        self.assertEqual(importers.detect(doc), "trivy")
        norm = importers.normalize(doc)
        self.assertEqual(norm["findings"][0]["sev"], "high")
        out = importers.ingest(self.store, "r1", doc)
        self.assertEqual(out["findings"], 1)
        again = importers.ingest(self.store, "r1", doc)
        self.assertTrue(again["skipped"])
        run = self.store.open_run("r1")
        self.assertTrue(any(f["title"].startswith("CVE-2025-1") for f in run.findings))
        self.assertTrue(any(s.get("step_key") == "import-trivy"
                            for s in [{"step_key": r[0]} for r in
                                      run.query("SELECT step_key FROM steps")]))

    def test_grype_syft_and_scopesentry(self):
        grype = {"matches": [{"vulnerability": {"id": "CVE-2025-2", "severity": "Medium"},
                              "artifact": {"name": "p", "version": "3", "type": "python"}}]}
        self.assertEqual(importers.detect(grype), "grype")
        self.assertEqual(importers.normalize(grype)["findings"][0]["sev"], "medium")
        syft = {"artifacts": [{"name": "torch", "version": "2.0", "type": "python"}],
                "descriptor": {"name": "syft"}}
        self.assertEqual(importers.detect(syft), "syft")
        self.assertEqual(importers.normalize(syft)["findings"][0]["sev"], "info")
        with self.assertRaises(importers.ScanImportError):
            importers.detect({"foo": 1})
        diff = importers.sync_scopesentry(self.store, {
            "projects": [{"name": "ml"}],
            "assets": [{"name": "vllm", "host": "10.0.0.9", "port": 8000, "project": "ml"}]})
        self.assertIn("service/ml/vllm", diff["diff"]["added"])


if __name__ == "__main__":
    unittest.main()
