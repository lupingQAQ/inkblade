# -*- coding: utf-8 -*-
"""CLI surface tests for agent status/trace/replay/probes."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tests.agent_fixture import ROOT, golden_script, make_lab, supervisor_kwargs
from inkblade.agent.supervisor import AgentSupervisor
from inkblade.cli import main


class AgentCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.store, self.session, self.modules, self.rng, self.k8s = make_lab(self.home)
        self.sup = AgentSupervisor.create(
            self.store, self.session,
            **supervisor_kwargs(self.home, self.modules, self.rng, self.k8s,
                                script=golden_script(self.rng.url())))
        self.result = self.sup.run()

    def tearDown(self):
        if self.rng is not None:
            self.rng.stop()
        self.tmp.cleanup()

    def _call(self, argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_status_and_trace(self):
        code, out = self._call(["--home", str(self.home), "agent", "status",
                                "--workspace", "lab",
                                "--run-id", self.sup.runtime.run_id])
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertEqual(data["run_id"], self.sup.runtime.run_id)
        self.assertTrue(data["journal"]["ok"])
        self.assertTrue(data["objective_eval"]["success"])
        code, out = self._call(["--home", str(self.home), "agent", "trace",
                                "--workspace", "lab",
                                "--run-id", self.sup.runtime.run_id, "--limit", "20"])
        self.assertEqual(code, 0, out)
        trace = json.loads(out)["events"]
        self.assertTrue(any(e["kind"] == "decision.made" for e in trace))
        self.assertTrue(any(e["kind"] == "observation" for e in trace))

    def test_replay_zero_execution(self):
        code, out = self._call(["--home", str(self.home), "agent", "replay",
                                "--workspace", "lab",
                                "--run-id", self.sup.runtime.run_id])
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertTrue(data["objective_eval"]["success"])
        self.assertEqual(data["events"]["facts"], 7)

    def test_probes_status(self):
        code, out = self._call(["--home", str(self.home), "agent", "probes",
                                "--workspace", "lab"])
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertIn("reference_allowed", data)

    def test_stop_after_success_is_recorded(self):
        code, out = self._call(["--home", str(self.home), "agent", "stop",
                                "--workspace", "lab",
                                "--run-id", self.sup.runtime.run_id,
                                "--reason", "cli test"])
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertTrue(data["stopped"])

    def test_run_cli_with_mock_llm_and_reference_probe(self):
        script_path = self.home / "agent-script.json"
        script_path.write_text(json.dumps(golden_script(self.rng.url()),
                                          ensure_ascii=False), encoding="utf-8")
        (self.home / "agent-probes.json").write_text(json.dumps({
            "probes": [{"id": "test-probe", "kind": "reference",
                        "runtime": "reference"}]}), encoding="utf-8")
        code, out = self._call([
            "--home", str(self.home), "agent", "run",
            "--objective", "cluster-takeover",
            "--probe", "test-probe",
            "--llm", f"mock:{script_path}",
            "--workspace", "lab",
            "--role", "lead",
            "--modules-dir", str(self.modules),
            "--budget-tokens", "20000", "--budget-steps", "12",
            "--budget-actions", "20", "--budget-seconds", "120",
            "--allow-destructive", "--allow-reference", "--yes",
            "--k8s-api", self.rng.k8s_url,
            "--k8s-token", self.rng._k8s.token,
            "--workers", "1",
        ])
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertEqual(data["status"], "success", data)
        self.assertEqual(data["metrics"]["steps"], 8)
        self.assertEqual(data["metrics"]["interventions"], 0)


if __name__ == "__main__":
    unittest.main()
