# -*- coding: utf-8 -*-
"""Lowering canonical templates to the Rust probe dialect + folding evidence."""
from __future__ import annotations

import unittest

from inkblade.tpl.lower import compile_template, fold_result


def _template(**overrides) -> dict:
    doc = {
        "schema": "inkblade-probe-template-v1", "key": "demo", "version": "1.0.0",
        "meta": {"name": {"zh": "演示", "en": "Demo"}, "series": "横向利用",
                 "min_level": "利用验证", "writes": False},
        "inputs": {"target": {"from": "params.target", "required": True}},
        "defaults": {"timeout_ms": 5000},
        "steps": [
            {"id": "models", "op": "http", "method": "GET",
             "url": "{{input.target}}/v1/models",
             "headers": {"X-Tenant": "{{params.tenant}}"},
             "save": "models", "allow_failure": True},
            {"id": "scan", "op": "tcp", "host": "127.0.0.1", "port": 6379,
             "send": "PING {{params.tenant}}\r\n", "save": "scan"},
        ],
        "checks": [{"id": "reachable", "when": "steps.models.status != null"}],
        "findings": [{"id": "f", "when": "steps.models.status == 200", "sev": "high",
                      "title": "models exposed for {{params.tenant}}"}],
        "artifacts": [{"name": "models.json", "from": "steps.models.json"}],
    }
    doc.update(overrides)
    return doc


class TestLowering(unittest.TestCase):
    def test_precomputes_inputs_and_params(self):
        compilation = compile_template(_template(), {"target": "http://lab", "tenant": "a"})
        self.assertTrue(compilation.native_ready, compilation.gaps)
        steps = {step["id"]: step for step in compilation.native_template["steps"]}
        self.assertEqual(steps["models"]["url"], "http://lab/v1/models")
        self.assertEqual(steps["models"]["headers"]["X-Tenant"], "a")
        self.assertNotIn("save", steps["models"])
        self.assertNotIn("allow_failure", steps["models"])
        self.assertEqual(steps["scan"]["send_b64"], "UElORyBhDQo=")

    def test_write_step_skipped_in_probe_only(self):
        template = _template()
        template["steps"].append({"id": "w", "op": "fs", "action": "write",
                                  "path": "{{params.target}}/x", "content": "x",
                                  "write": True, "save": "w"})
        template["modes"] = {"backup_write": True, "requires_backup": True}
        compilation = compile_template(template, {"target": "/tmp/zero"}, mode="probe-only")
        self.assertNotIn("w", [s["id"] for s in compilation.native_template["steps"]])
        compilation = compile_template(template, {"target": "/tmp/zero"}, mode="backup-write")
        self.assertIn("w", [s["id"] for s in compilation.native_template["steps"]])

    def test_gaps_are_reported_not_faked(self):
        template = _template()
        template["steps"] = [{"id": "sock", "op": "socks",
                              "socket_path": "/var/run/docker.sock",
                              "request": "GET /version HTTP/1.0\r\n\r\n", "save": "sock"}]
        compilation = compile_template(template, {"target": "x"})
        self.assertFalse(compilation.native_ready)
        self.assertEqual(compilation.gaps[0]["reason"],
                         "probe socks op is a server, not a Unix-socket client")
        self.assertEqual(compilation.native_template["steps"], [])

    def test_k8s_write_is_a_gap(self):
        template = _template()
        template["meta"]["writes"] = True
        template["modes"] = {"backup_write": True, "requires_backup": True}
        template["steps"] = [{"id": "crb", "op": "k8s", "verb": "create",
                              "api_version": "rbac.authorization.k8s.io/v1",
                              "resource": "clusterrolebindings", "body": {}, "write": True,
                              "save": "crb"}]
        compilation = compile_template(template, {"mode": "backup-write"})
        self.assertFalse(compilation.native_ready)
        self.assertIn("k8s verb create", compilation.gaps[0]["reason"])

    def test_fold_result_builds_findings_and_artifacts(self):
        compilation = compile_template(_template(), {"target": "http://lab", "tenant": "a"})
        native = {"ok": True, "duration_ms": 3,
                  "vars": {"steps.models": {"status": 200, "headers": {},
                                            "body": '{"object":"list"}'}}}
        result = fold_result(compilation, native)
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["findings"][0]["title"], "models exposed for a")
        self.assertEqual(result["findings"][0]["sev"], "high")
        self.assertEqual(result["artifacts"][0]["kind"], "json")
        self.assertIn('"object"', result["artifacts"][0]["text"])

    def test_fold_result_fatal_check_blocks_findings(self):
        template = _template()
        template["checks"] = [{"id": "never", "when": "1 == 2", "fatal": True}]
        compilation = compile_template(template, {"target": "x"})
        native = {"ok": True, "vars": {"steps.models": {"status": 200, "body": "{}"}}}
        result = fold_result(compilation, native)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
