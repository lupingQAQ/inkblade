# -*- coding: utf-8 -*-
"""S1: declarative template contract, reference engine, probe gating, bootstrap."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))

from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import init_roe
from inkblade.core.runner import run_module
from inkblade.core.users import UserStore
from inkblade.tpl import expr
from inkblade.tpl.backends import K8sShim, LocalBackend
from inkblade.tpl.engine import Engine, ProbeError, ReferenceProbe
from inkblade.tpl.probe import (ProbeFailed, ProbeUnavailable, RustProbe, bootstrap_modules,
                                install_probe, is_bootstrap, reference_allowed, resolve_probe,
                                validate_result)
from inkblade.tpl.schema import TemplateError, load_template, validate
from template_range import Range


def _module(root: Path, key: str, *, template: dict, writes: bool = False,
            execution: str | None = None) -> Path:
    d = root / "modules" / key
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "key": key,
        "name": {"zh": key, "en": key},
        "series": "横向利用",
        "description": "test module",
        "min_level": "利用验证",
        "writes": writes,
        "requires": [],
    }
    if execution:
        meta["execution"] = execution
    (d / "module.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    template = {**template, "key": key,
                "meta": {**template.get("meta", {}), "name": {"zh": key, "en": key},
                         "series": "横向利用", "min_level": "利用验证", "writes": writes}}
    (d / "template.json").write_text(json.dumps(template, ensure_ascii=False), encoding="utf-8")
    return d


class TestExpressions(unittest.TestCase):
    def test_precedence_and_paths(self):
        scope = {"steps": {"a": {"json": {"items": [{"v": 1}, {"v": 2}]}}}}
        self.assertTrue(expr.truthy("1 + 2 * 3 == 7", scope))
        self.assertEqual(expr.evaluate("steps.a.json.items[*].v", scope), [1, 2])
        self.assertTrue(expr.truthy("contains(steps.a.json.items[*].v, 2)", scope))
        self.assertTrue(expr.truthy("any(steps.a.json.items, it.v == 2)", scope))
        self.assertEqual(expr.evaluate("count_if(steps.a.json.items, it.v > 0)", scope), 2)

    def test_glob_and_functions(self):
        self.assertTrue(expr.truthy("matches('falco*', 'falco-ebpf')"))
        self.assertFalse(expr.truthy("matches('falco', 'falco-ebpf')"))
        self.assertEqual(expr.evaluate("default(null, 'x')"), "x")
        self.assertEqual(expr.evaluate("sha256('a')"),
                         "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")
        self.assertEqual(expr.evaluate("len('abc')"), 3)
        self.assertEqual(expr.evaluate("int('7') + 1"), 8)

    def test_missing_values_do_not_raise(self):
        self.assertIsNone(expr.evaluate("steps.nope.body.x"))
        self.assertFalse(expr.truthy("steps.nope.body.x == 1"))
        self.assertTrue(expr.truthy("steps.nope.body.x == null"))

    def test_interpolation(self):
        scope = {"params": {"tenant": "tenant-a"}, "steps": {"s": {"json": {"n": 2}}}}
        self.assertEqual(expr.render("{{params.tenant}}/{{steps.s.json.n}}", scope),
                         "tenant-a/2")
        self.assertEqual(expr.render_value({"a": "{{params.tenant}}"}, scope),
                         {"a": "tenant-a"})

    def test_rejects_unsafe_syntax(self):
        with self.assertRaises(expr.ExprError):
            expr.evaluate("__import__('os')")
        with self.assertRaises(expr.ExprError):
            expr.parse("a.b(")


class TestSchema(unittest.TestCase):
    def _valid(self) -> dict:
        return {
            "schema": "inkblade-probe-template-v1", "key": "demo", "version": "1.0.0",
            "meta": {"name": {"zh": "演示", "en": "Demo"}, "series": "横向利用",
                     "min_level": "利用验证", "writes": False},
            "steps": [{"id": "s", "op": "http", "method": "GET",
                       "url": "{{params.target}}/healthz", "save": "s"}],
            "findings": [{"id": "f", "when": "steps.s.status == 200", "sev": "info",
                          "title": "ok"}],
        }

    def test_valid_template(self):
        self.assertEqual(validate(self._valid()), [])

    def test_requires_steps_and_valid_expressions(self):
        doc = self._valid()
        doc["steps"] = []
        self.assertTrue(any("steps" in e for e in validate(doc)))
        doc = self._valid()
        doc["steps"][0]["url"] = "{{params.target"
        self.assertTrue(any("未闭合" in e for e in validate(doc)))

    def test_rejects_unknown_binding(self):
        doc = self._valid()
        doc["findings"][0]["when"] = "bogus.value == 1"
        self.assertTrue(any("未知根" in e for e in validate(doc)))

    def test_rejects_shell_string_exec(self):
        doc = self._valid()
        doc["steps"].append({"id": "x", "op": "exec", "argv": ["sh -c id"], "save": "x"})
        self.assertTrue(any("分离参数" in e for e in validate(doc)))

    def test_write_requires_backup_mode(self):
        doc = self._valid()
        doc["steps"].append({"id": "w", "op": "fs", "action": "write",
                             "path": "{{params.path}}", "content": "x", "write": True,
                             "save": "w"})
        self.assertTrue(any("backup_write" in e for e in validate(doc)))
        doc["modes"] = {"backup_write": True, "requires_backup": True}
        doc["meta"]["writes"] = True
        self.assertEqual([e for e in validate(doc) if "backup" in e], [])


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.range = Range().start()
        self.engine = Engine(LocalBackend(workdir=self.range.workdir))

    def tearDown(self):
        self.range.stop()

    def _template(self, **overrides) -> dict:
        doc = {
            "schema": "inkblade-probe-template-v1", "key": "demo", "version": "1.0.0",
            "meta": {"name": {"zh": "演示", "en": "Demo"}, "series": "横向利用",
                     "min_level": "利用验证", "writes": False},
            "inputs": {"target": {"from": "params.target", "required": True}},
            "steps": [{"id": "models", "op": "http", "method": "GET",
                       "url": "{{input.target}}/v1/models", "save": "models",
                       "expect": {"status": [200]}}],
            "findings": [{"id": "f", "when": "steps.models.status == 200", "sev": "medium",
                          "title": "{{steps.models.json.object}} exposed",
                          "detail": "{{steps.models.sha256}}"}],
            "artifacts": [{"name": "models.json", "from": "steps.models.json"}],
        }
        doc.update(overrides)
        return doc

    def test_http_finding_and_artifact(self):
        result = self.engine.run(self._template(), {"target": self.range.url()})
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["findings"][0]["title"], "list exposed")
        artifact = result["artifacts"][0]
        self.assertEqual(artifact["name"], "models.json")
        self.assertEqual(len(artifact["sha256"]), 64)
        self.assertNotIn(self.range.workdir.as_posix(), artifact["text"])

    def test_missing_input_is_skipped(self):
        result = self.engine.run(self._template(), {})
        self.assertEqual(result["status"], "skipped")
        self.assertIn("target", result["error"])

    def test_expect_mismatch_is_error(self):
        doc = self._template()
        doc["steps"][0]["expect"] = {"status": [418]}
        result = self.engine.run(doc, {"target": self.range.url()})
        self.assertEqual(result["status"], "error")
        self.assertIn("unexpected status", result["error"])

    def test_write_step_skipped_in_probe_only(self):
        target = Path(self.range.workdir) / "canary.txt"
        doc = self._template()
        doc["steps"].append({"id": "w", "op": "fs", "action": "write", "write": True,
                             "path": str(target), "content": "x", "save": "w"})
        result = self.engine.run(doc, {"target": self.range.url()})
        self.assertFalse(target.exists())
        self.assertTrue([s for s in result["steps"] if s["id"] == "w"][0]["skipped"])

    def test_for_each_findings_and_checks(self):
        snap = self.range.fixture("snap.json", {"roles": [
            {"name": "admin", "verbs": ["escalate"]},
            {"name": "reader", "verbs": ["get"]}]})
        doc = self._template()
        doc["steps"] = [{"id": "snap", "op": "fs", "action": "read", "path": snap,
                         "json": True, "save": "snap"}]
        doc["checks"] = [{"id": "has-roles", "when": "len(steps.snap.json.roles) == 2",
                          "fatal": True}]
        doc["findings"] = [{"id": "esc", "for_each": "steps.snap.json.roles", "as": "role",
                            "when": "contains(role.verbs, 'escalate')", "sev": "critical",
                            "title": "{{role.name}} can escalate"}]
        result = self.engine.run(doc, {"target": self.range.url()})
        self.assertEqual([f["title"] for f in result["findings"]], ["admin can escalate"])
        self.assertTrue(result["checks"][0]["ok"])

    def test_tcp_and_k8s_ops(self):
        doc = self._template()
        doc["steps"] = [
            {"id": "tcp", "op": "tcp", "host": "127.0.0.1", "port": self.range.tcp_port,
             "send": "PING\r\n", "expect_prefix": "+PONG", "save": "tcp"},
            {"id": "pods", "op": "k8s", "verb": "list", "api_version": "v1",
             "resource": "pods", "namespace": "default", "save": "pods"},
        ]
        shim = K8sShim(api=self.range.k8s_url, token=self.range._k8s.token, validate=False)
        engine = Engine(LocalBackend(workdir=self.range.workdir, k8s=shim))
        result = engine.run(doc, {"target": self.range.url()})
        self.assertEqual(result["steps"][0]["text"], "+PONG\r\n")
        self.assertEqual(result["steps"][1]["json"]["kind"], "List")

    def test_fatal_check_blocks_findings(self):
        doc = self._template()
        doc["checks"] = [{"id": "impossible", "when": "1 == 2", "fatal": True}]
        result = self.engine.run(doc, {"target": self.range.url()})
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["findings"], [])


class TestProbeGating(unittest.TestCase):
    def test_no_probe_no_fallback(self):
        old = os.environ.pop("INKBLADE_ALLOW_REFERENCE_PROBE", None)
        try:
            with self.assertRaises(ProbeUnavailable):
                resolve_probe(None)
            self.assertFalse(reference_allowed())
        finally:
            if old is not None:
                os.environ["INKBLADE_ALLOW_REFERENCE_PROBE"] = old

    def test_reference_requires_explicit_opt_in(self):
        from inkblade.tpl.probe import run_reference

        old = os.environ.pop("INKBLADE_ALLOW_REFERENCE_PROBE", None)
        try:
            with self.assertRaises(ProbeUnavailable):
                run_reference({}, {}, {})
        finally:
            if old is not None:
                os.environ["INKBLADE_ALLOW_REFERENCE_PROBE"] = old

    def test_rust_probe_validates_result(self):
        template = {"key": "demo", "version": "1.0.0", "limits": {"timeout_ms": 1000},
                    "steps": [{"id": "s", "op": "fs", "action": "stat", "path": "/",
                               "save": "s"}]}

        class Client:
            def task(self, native, params, task_id):
                self.native = native
                return {"ok": True, "vars": {"steps.s": {"path": "/", "size": 0}},
                        "steps": [{"step": "s", "op": "fs", "ok": True,
                                   "result": {"path": "/"}}], "duration_ms": 1}

        probe = RustProbe(Client())
        result = probe.run(template, {}, {})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["runtime"], "rust")

        class WrongKey(Client):
            def task(self, native, params, task_id):
                return {"ok": True, "vars": {}, "steps": [], "duration_ms": 1}

        # fold_result always stamps the canonical key; a transport-level schema
        # mismatch is detected before folding.
        with self.assertRaises(ProbeFailed):
            validate_result({"schema": "wrong", "key": "demo"}, template)
        with self.assertRaises(ProbeUnavailable):
            RustProbe(WrongKey()).run({"key": "demo", "version": "1.0.0",
                                       "steps": [{"id": "x", "op": "socks",
                                                  "socket_path": "/tmp/x",
                                                  "request": "GET /"}]}, {}, {})

    def test_bootstrap_registry_is_explicit_and_minimal(self):
        modules = bootstrap_modules()
        self.assertEqual([m["key"] for m in modules], ["probe-bootstrap"])
        self.assertTrue(is_bootstrap("probe-bootstrap"))
        self.assertFalse(is_bootstrap("cache-timing-sidechannel"))

    def test_install_probe_uploads_binary(self):
        class UploadSession:
            def __init__(self):
                self.calls = []

            def upload(self, data, remote):
                self.calls.append(("upload", len(data), remote))

            def exec(self, argv, stdin=None, timeout=None):
                self.calls.append(("exec", argv))
                return 0, "", ""

        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "inkblade-probe"
            binary.write_bytes(b"#!/bin/sh\necho probe\n")
            session = UploadSession()
            receipt = install_probe(session, {"source": str(binary)}, remote="/tmp/p")
            self.assertEqual(receipt["binary"], "/tmp/p")
            self.assertTrue(any(call[0] == "upload" for call in session.calls))
            self.assertTrue(any(call[0] == "exec" for call in session.calls))


class TestRunnerIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={"level": "利用验证", "namespaces": ["train"],
                                     "cidrs": ["127.0.0.0/8"]})
        self.range = Range().start()

    def tearDown(self):
        self.range.stop()
        self.tmp.cleanup()

    def _template(self, writes: bool = False) -> dict:
        return {
            "schema": "inkblade-probe-template-v1", "version": "1.0.0",
            "meta": {}, "inputs": {"target": {"from": "params.target", "required": True}},
            "steps": [{"id": "models", "op": "http", "method": "GET",
                       "url": "{{params.target}}/v1/models", "save": "models"}],
            "findings": [{"id": "f", "sev": "high", "title": "models exposed",
                          "when": "steps.models.status == 200"}],
            "artifacts": [{"name": "models.json", "from": "steps.models.json"}],
        }

    def test_runner_template_finding_and_evidence(self):
        _module(self.root, "demo-mod", template=self._template())
        result = run_module(self.store, self.session, "demo-mod",
                            {"target": self.range.url()}, modules_dir=self.root / "modules")
        run = self.store.open_run(result["run"])
        findings = run.findings
        self.assertTrue(any(f["title"] == "models exposed" for f in findings))
        step = run.query("SELECT archive FROM steps ORDER BY id DESC LIMIT 1")[0][0]
        self.assertTrue((run.dir / step).is_file())
        self.assertTrue((run.dir / "artifacts" / "demo-mod" / "models.json").is_file())

    def test_runner_refuses_write_without_backup(self):
        target = Path(self.range.workdir) / "victim.txt"
        target.write_text("original", encoding="utf-8")
        template = self._template(writes=True)
        template["modes"] = {"backup_write": True, "requires_backup": True}
        template["steps"] = [{"id": "w", "op": "fs", "action": "write", "write": True,
                              "path": str(target), "content": "INKBLADE", "save": "w"}]
        template["findings"] = []
        _module(self.root, "write-mod", template=template, writes=True)
        from inkblade.core.runner import BackupGateRefused

        with self.assertRaises(BackupGateRefused):
            run_module(self.store, self.session, "write-mod",
                       {"mode": "backup-write"}, modules_dir=self.root / "modules")
        self.assertEqual(target.read_text(encoding="utf-8"), "original")

    def test_runner_rejects_legacy_run_py_module(self):
        d = self.root / "modules" / "legacy-mod"
        d.mkdir(parents=True)
        (d / "module.json").write_text(json.dumps({
            "key": "legacy-mod", "name": {"zh": "x", "en": "x"}, "series": "横向利用",
            "description": "x", "min_level": "只读侦察", "writes": False, "requires": []}),
            encoding="utf-8")
        (d / "run.py").write_text("def run(ctx, params):\n    return {}\n", encoding="utf-8")
        with self.assertRaises(ValueError) as cm:
            run_module(self.store, self.session, "legacy-mod", {},
                       modules_dir=self.root / "modules")
        self.assertIn("template.json", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
