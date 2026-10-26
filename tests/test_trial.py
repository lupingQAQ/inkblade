"""`inkblade trial` contract tests (environment-check path).

The full offline demo is exercised by `tests/test_onboarding.py`; here we pin the
trial-specific behaviour: JSON schema, artifact inventory semantics, report
location, next steps, and that the CLI exposes the subcommand.
"""

import contextlib
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade import VERSION, cli
from inkblade.trial import SCHEMA, run_trial

REPO = Path(__file__).resolve().parents[1]


class TestTrialCommand(unittest.TestCase):
    def _run(self, *, no_demo=True, kubeconfig=None):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "trial"
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = run_trial(out, no_demo=no_demo, json_out=True, kubeconfig=kubeconfig)
            payload = json.loads(buffer.getvalue())
            payload["_report_file"] = Path(payload["report_path"]).is_file()
            payload["_report_parent"] = Path(payload["report_path"]).parent.name
        return code, payload

    def test_environment_check_writes_report(self):
        code, payload = self._run()
        self.assertEqual(code, 0)
        self.assertEqual(payload["schema"], SCHEMA)
        self.assertEqual(payload["version"], VERSION)
        self.assertEqual(payload["mode"], "environment-check")
        self.assertEqual(payload["demo"], {})
        self.assertTrue(payload["_report_file"])
        self.assertEqual(payload["_report_parent"], "reports")

    def test_artifacts_are_planned_not_claimed(self):
        _, payload = self._run()
        labels = {item["label"]: item for item in payload["artifacts"]}
        self.assertIn("pentest report", labels)
        self.assertIn("trial report", labels)
        self.assertTrue(labels["trial report"]["exists"])
        self.assertEqual(labels["trial report"]["kind"], "file")
        self.assertFalse(labels["pentest report"]["exists"])

    def test_next_steps_cover_trial_pilot_plugin(self):
        _, payload = self._run()
        joined = " ".join(payload["next_steps"]).lower()
        self.assertIn("doctor", joined)
        self.assertIn("quickstart", joined)
        self.assertIn("pilot", joined)
        self.assertIn("sdk new", joined)
        self.assertIn("plugin-sdk", joined)

    def test_kubeconfig_only_changes_guidance(self):
        _, payload = self._run(kubeconfig="/nonexistent/kubeconfig.yaml")
        pilot_steps = [s for s in payload["next_steps"] if "pilot" in s.lower()]
        self.assertTrue(pilot_steps)
        self.assertIn("--kubeconfig", pilot_steps[-1])
        self.assertFalse(any("contacted" in s.lower() for s in payload["next_steps"]))

    def test_disclaimer_present(self):
        _, payload = self._run()
        self.assertIn("loopback", payload["disclaimer"].lower())
        self.assertEqual(payload["docs"]["trial"], "docs/TRIAL.md")
        self.assertEqual(payload["docs"]["pilot"], "docs/PILOT-KIT.md")

    def test_docs_exist(self):
        for rel in ("docs/TRIAL.md", "docs/PILOT-KIT.md", "docs/FEEDBACK.md",
                    "docs/PLUGIN-SDK.md", "docs/AUDIT-PACKAGE.md", "docs/VERSIONING.md"):
            self.assertTrue((REPO / rel).is_file(), f"missing {rel}")

    def test_cli_exposes_trial(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["trial", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("trial", buffer.getvalue())
        self.assertIn("--no-demo", buffer.getvalue())

    def test_cli_ui_host_flag_defaults_to_loopback(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            with self.assertRaises(SystemExit) as ctx:
                cli.main(["ui", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--host", buffer.getvalue())
        self.assertIn("127.0.0.1", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
