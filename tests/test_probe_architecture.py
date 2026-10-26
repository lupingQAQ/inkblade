# -*- coding: utf-8 -*-
"""Architecture guards for the probe-centric execution model."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from inkblade.core.registry import load_modules

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"
PROBE = ROOT / "probe"


class TestProbeArchitecture(unittest.TestCase):
    def test_probe_source_and_ci_workflow_exist(self):
        for name in ("Cargo.toml", "Cargo.lock", "TEMPLATE-ENGINE.md", "README.md"):
            self.assertTrue((PROBE / name).is_file(), name)
        for name in ("main.rs", "server.rs", "template.rs", "protocol.rs", "auth.rs",
                     "http.rs", "k8s.rs", "spawn.rs", "collect.rs", "exec.rs"):
            self.assertTrue((PROBE / "src" / name).is_file(), name)
        workflow = ROOT / ".github" / "workflows" / "probe-release.yml"
        self.assertTrue(workflow.is_file())
        text = workflow.read_text(encoding="utf-8")
        for marker in ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
                       "SHA256SUMS", "cosign"):
            self.assertIn(marker, text)

    def test_all_modules_are_declarative_templates(self):
        modules = load_modules(MODULES)
        self.assertGreaterEqual(len(modules), 10)
        templates = 0
        bootstrap = 0
        for meta in modules.values():
            if meta.execution == "bootstrap":
                bootstrap += 1
                self.assertTrue((meta.path / "bootstrap.py").is_file())
                continue
            self.assertEqual(meta.execution, "template")
            self.assertTrue((meta.path / "template.json").is_file())
            self.assertFalse((meta.path / "run.py").exists(), meta.key)
            templates += 1
        self.assertGreaterEqual(templates, 275)
        self.assertEqual(bootstrap, 1)

    def test_probe_runtime_has_no_interpreter_path(self):
        text = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in (PROBE / "src").glob("*.rs")
        )
        # There is deliberately no interpreter subprocess in the runtime.
        self.assertNotIn("python3", text.lower())
        self.assertNotIn("python -c", text.lower())
        self.assertNotIn("sh -c", text.lower())
        self.assertIn("challenge", text.lower())
        self.assertIn("hmac", text.lower())

    def test_docs_are_present_and_public(self):
        for name in ("PROBE-PROTOCOL.md", "PROBE-CHANNEL.md", "ARCHITECTURE-PROBE.md"):
            self.assertTrue((ROOT / "docs" / name).is_file(), name)
        channel = (ROOT / "docs" / "PROBE-CHANNEL.md").read_text(encoding="utf-8")
        for marker in ("external", "foothold", "kubeconfig", "127.0.0.1",
                       "no host fallback", "Rust"):
            self.assertIn(marker, channel)
        features = (ROOT / "docs" / "FEATURES.md").read_text(encoding="utf-8")
        self.assertIn("In-pod probe / channel", features)
        self.assertIn("PROBE-CHANNEL.md", features)

    def test_manifest_security_contract(self):
        from inkblade.probe.deploy import ProbeDeploySpec, pod_manifest

        doc = pod_manifest(ProbeDeploySpec(namespace="ns", name="probe", token_secret="t"))
        spec = doc["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertTrue(spec["securityContext"]["runAsNonRoot"])
        container = spec["containers"][0]
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
        self.assertFalse(any("hostPath" in v for v in spec["volumes"]))

    def test_no_python_module_code_is_uploaded(self):
        from inkblade.entry.base import build_upload_plan

        plan = build_upload_plan(b"binary")
        joined = " ".join(plan.commands)
        self.assertIn("base64", joined)
        self.assertNotIn("python", joined.lower())
        self.assertNotIn("kubectl", joined.lower())


if __name__ == "__main__":
    unittest.main()
