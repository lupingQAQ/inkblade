# -*- coding: utf-8 -*-
"""Bilingual report integration for the highest-privilege proof section."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.objective import FakeKubectlBackend, load_objective, run_objective
from trident.core.roe import init_roe
from trident.core.users import Session
from trident.reports.render import render_pentest

REPO = Path(__file__).resolve().parents[1]
CHAINS = REPO / "trident" / "chains"


class HighestPrivilegeReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.store = EvidenceStore(self.home, workspace="local-lab")
        init_roe(self.store, {"level": "全影响演示",
                              "namespaces": ["trident-killchain"],
                              "cidrs": ["127.0.0.1/32"]})
        self.session = Session(None, "lead-user", "lead", ["local-lab"], "t")

    def tearDown(self):
        self.tmp.cleanup()

    def test_section_present_when_proof_artifact_exists(self):
        chain = load_objective(CHAINS)
        result = run_objective(
            self.store, self.session, chain, FakeKubectlBackend(),
            proof_marker="report-proof", auto_approve=True,
        )
        self.assertTrue(result["ok"])
        text = render_pentest(self.store, result["run"], lang="bi")
        for token in ("最高权限证明", "Highest-Privilege Proof", "cluster-admin",
                      "已清理", "proof_sha256", "集群级动作清单"):
            self.assertIn(token, text)
        self.assertNotIn("fake-token-", text)

    def test_section_is_explicit_when_no_proof(self):
        run = self.store.create_run("plain-run")
        run.add_step("recon", "cmd", {}, "ok")
        text = render_pentest(self.store, "plain-run", lang="bi")
        self.assertIn("未包含 objective 夺权证明", text)
        self.assertIn("No objective takeover proof", text)


if __name__ == "__main__":
    unittest.main()
