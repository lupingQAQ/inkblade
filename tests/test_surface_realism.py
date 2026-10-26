# -*- coding: utf-8 -*-
"""Real surface detection, collection chain, profile matrix and quarantine tests."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from inkblade.collect import files as files_collect
from inkblade.collect import fixture_collection
from inkblade.collect import hardware as hardware_collect
from inkblade.collect import http as http_collect
from inkblade.collect import k8s as k8s_collect
from inkblade.core import surface
from inkblade.core.evidence import EvidenceStore
from inkblade.core.registry import load_modules
from inkblade.core.roe import init_roe
from inkblade.core.runner import run_module
from inkblade.core.users import Session

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"
REGISTRY = ROOT / "inkblade" / "core" / "exploit-registry.json"
FOCUS = {
    "confidential-containers-audit", "spiffe-spire-audit", "ambient-mesh-audit",
    "wasm-runtime-audit", "post-quantum-tls-audit", "federated-learning-audit",
    "model-watermark-backdoor-audit", "data-provenance-audit", "dpu-smartnic-surface",
    "pcie-iommu-audit", "tpm-attestation-audit",
}
NO_SURFACE = {
    "wasm-runtime-audit", "post-quantum-tls-audit", "federated-learning-audit",
    "model-watermark-backdoor-audit", "cxl-memory-security",
    "hypervisor-audit-integrity", "agent-skill-registry-supply-chain",
    "mcp-control-plane-governance", "agent-native-control-plane",
}
# C-tier research-only modules: implemented and surface-gated, but excluded
# from the default chain/coverage denominator until a customer opts in.
RESEARCH_ONLY = {"spdm-pcie-doe", "nvlink-imex-isolation", "cxl-memory-security"}
# Owned by a parallel infra2026 workstream; its module.json stays default-enabled
# until that owner applies quarantine, but the profile matrix still proves it
# has no production surface in the six mainstream deployments.
PARALLEL_NO_SURFACE = {"data-provenance-audit"}


def _session(role="lead"):
    return Session(None, f"s-{role}", role, ["local-lab"], "test")


def _write_module(root: Path, key: str, surfaces: list[dict], *, default=True,
                  sentinel: Path) -> Path:
    directory = root / key
    directory.mkdir(parents=True)
    meta = {
        "key": key,
        "name": {"zh": key, "en": key},
        "series": "侦察",
        "description": "test module",
        "min_level": "只读侦察",
        "writes": False,
        "requires": [],
        "surfaces": surfaces,
        "default_enabled": default,
    }
    (directory / "module.json").write_text(json.dumps(meta, ensure_ascii=False),
                                           encoding="utf-8")
    (directory / "run.py").write_text(
        "from pathlib import Path\n"
        "def run(ctx, params):\n"
        f"    Path({str(sentinel)!r}).write_text('ran', encoding='utf-8')\n"
        "    return {'summary': 'executed', 'artifacts': [], "
        "'findings': [{'sev': 'info', 'title': 'executed', 'detail': 'x'}]}\n",
        encoding="utf-8")
    return directory


class SurfaceCase(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.store = EvidenceStore(self.home, workspace="local-lab")
        init_roe(self.store, {"level": "利用验证", "namespaces": ["ml"],
                              "cidrs": ["10.0.0.0/8", "127.0.0.0/8"]})

    def tearDown(self):
        self.tmp.cleanup()

    def _module(self, key, surfaces, default=True):
        self.modules = self.home / "modules"
        sentinel = self.home / f"{key}.ran"
        _write_module(self.modules, key, surfaces, default=default, sentinel=sentinel)
        return sentinel


class TestSurfaceGate(SurfaceCase):
    def test_absent_does_not_execute_or_count(self):
        sentinel = self._module("test-absent", [{"type": "http-endpoint",
                                                 "selector": "/definitely-absent"}])
        ctx = surface.SurfaceContext.build(profile="ray-vllm", enforce=True)
        run = self.store.create_run("absent")
        result = run_module(self.store, _session(), "test-absent", {}, self.modules,
                            run=run, surface_ctx=ctx)
        self.assertEqual(result["status"], "skipped-surface-absent")
        self.assertTrue(result["skipped"])
        self.assertFalse(sentinel.exists())
        self.assertEqual(run.query("SELECT COUNT(*) FROM steps")[0][0], 0)
        self.assertEqual(run.findings, [])
        actions = run.query("SELECT result FROM actions ORDER BY id")
        self.assertIn("skipped-surface-absent", {a[0] for a in actions})

    def test_unknown_requires_probe(self):
        sentinel = self._module("test-unknown", [{"type": "config-file",
                                                  "selector": "special.yaml"}])
        collection = {"schema": "inkblade-collection-v1", "mode": "live", "fixture": False,
                      "k8s": {"status": "unavailable", "objects": []},
                      "http": {"status": "unavailable", "endpoints": []},
                      "files": {"status": "unavailable", "files": []},
                      "hardware": {"status": "unavailable", "bmc": [], "switches": []}}
        ctx = surface.SurfaceContext.build(collection=collection, enforce=True)
        run = self.store.create_run("unknown")
        result = run_module(self.store, _session(), "test-unknown", {}, self.modules,
                            run=run, surface_ctx=ctx)
        self.assertEqual(result["status"], "skipped-surface-unknown")
        self.assertFalse(sentinel.exists())

        ctx_probe = surface.SurfaceContext.build(collection=collection, probe=True,
                                                 enforce=True)
        run2 = self.store.create_run("probed")
        result2 = run_module(self.store, _session(), "test-unknown", {}, self.modules,
                             run=run2, surface_ctx=ctx_probe)
        self.assertEqual(result2.get("status", "success"), "success")
        self.assertTrue(sentinel.exists())
        self.assertTrue(any(r["probed"] for r in result2["surface"]["results"]))

    def test_present_executes(self):
        sentinel = self._module("test-present", [{"type": "http-endpoint",
                                                  "selector": "/v1/models"}])
        ctx = surface.SurfaceContext.build(profile="ray-vllm", enforce=True)
        result = run_module(self.store, _session(), "test-present", {}, self.modules,
                            surface_ctx=ctx)
        self.assertEqual(result.get("status", "success"), "success")
        self.assertTrue(sentinel.exists())
        self.assertEqual(result["surface"]["status"], "run")

    def test_default_chain_marks_quarantine_blocked(self):
        self._module("test-chain-off", [{"type": "http-endpoint", "selector": "/never"}],
                     default=False)
        from inkblade.core.chains import dry_run

        chain = {"id": "test-chain", "title": {"zh": "t", "en": "t"},
                 "category": "经典攻击链",
                 "steps": [{"id": "s1", "module": "test-chain-off"}]}
        doc = dry_run(chain, [], self.modules)
        self.assertEqual(doc["steps"][0]["status"], "blocked")
        self.assertIn("default_enabled=false", doc["steps"][0]["blocked_reason"])

    def test_quarantined_module_skips_without_context(self):
        sentinel = self._module("test-quarantine", [{"type": "http-endpoint",
                                                     "selector": "/never"}],
                                default=False)
        result = run_module(self.store, _session(), "test-quarantine", {}, self.modules)
        self.assertTrue(result["skipped"])
        self.assertIn(result["status"], ("skipped-surface-absent",
                                         "skipped-surface-unknown"))
        self.assertFalse(sentinel.exists())

    def test_fixture_mode_is_stamped(self):
        self._module("test-fixture", [{"type": "http-endpoint", "selector": "/v1/models"}])
        ctx = surface.SurfaceContext.build(profile="ray-vllm", fixture=True, enforce=True)
        result = run_module(self.store, _session(), "test-fixture", {}, self.modules,
                            surface_ctx=ctx)
        self.assertEqual(result["surface"]["context"]["mode"], "fixture")
        self.assertTrue(result["surface"]["context"]["fixture"])
        doc = fixture_collection("ray-vllm")
        self.assertTrue(doc["fixture"])
        section = surface.report_section("ray-vllm", collection=doc)
        self.assertIn("FIXTURE DATA", section)


class TestProfilesAndMetadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mods = load_modules(MODULES)
        cls.profiles = surface.profile_names()

    def test_every_module_declares_surfaces(self):
        missing = [k for k, m in self.mods.items() if not m.required_surfaces]
        self.assertEqual(missing, [])
        for key, meta in self.mods.items():
            for raw in meta.required_surfaces:
                req = surface.normalize_requirement(raw)
                self.assertIn(req.type, surface.SURFACE_TYPES, key)

    def test_focus_modules_and_quarantine(self):
        self.assertTrue(FOCUS <= set(self.mods))
        for key in FOCUS:
            self.assertTrue(self.mods[key].required_surfaces, key)
        quarantined = {k for k, m in self.mods.items() if not m.default_enabled}
        self.assertEqual(quarantined, NO_SURFACE | RESEARCH_ONLY)
        for key in PARALLEL_NO_SURFACE:
            self.assertTrue(self.mods[key].default_enabled)
        self.assertTrue(self.mods["dpu-smartnic-surface"].default_enabled)

    def test_research_only_modules_are_marked(self):
        for key in RESEARCH_ONLY:
            self.assertTrue(self.mods[key].research_only, key)
            self.assertFalse(self.mods[key].default_enabled, key)
            self.assertTrue(self.mods[key].default_disabled_reason, key)
        for key in ("iommu-smmu-config", "gpu-memory-residue-isolation",
                    "gpu-cc-attestation-chain", "firmware-signature-inventory",
                    "secure-boot-chain"):
            self.assertFalse(self.mods[key].research_only, key)
            self.assertTrue(self.mods[key].default_enabled, key)

    def test_profiles_are_complete_and_have_coverage(self):
        self.assertEqual(set(self.profiles), {
            "bare-k8s-gpu", "ray-vllm", "managed-ack-tke",
            "slurm-hpc", "airgapped", "gpu-pooling"})
        for name in self.profiles:
            doc = surface.matrix(name, modules=self.mods)
            self.assertTrue(doc["complete"], name)
            self.assertGreater(doc["summary"]["default_enabled"], 0, name)
            self.assertGreater(doc["summary"]["coverage_pct"], 0, name)
            self.assertEqual(len(doc["modules"]), len(self.mods), name)

    def test_profile_specific_verdicts(self):
        expected = {
            ("dpu-smartnic-surface", "bare-k8s-gpu"): "production-testable",
            ("dpu-smartnic-surface", "ray-vllm"): "no-surface",
            ("bmc-ipmi-exposure", "bare-k8s-gpu"): "production-testable",
            ("bmc-ipmi-exposure", "ray-vllm"): "no-surface",
            ("bmc-ipmi-exposure", "slurm-hpc"): "production-testable",
            ("ray-control-plane", "ray-vllm"): "production-testable",
            ("ray-control-plane", "slurm-hpc"): "no-surface",
            ("spiffe-spire-audit", "airgapped"): "production-testable",
            ("spiffe-spire-audit", "ray-vllm"): "no-surface",
            ("ambient-mesh-audit", "managed-ack-tke"): "production-testable",
            ("ambient-mesh-audit", "ray-vllm"): "no-surface",
            ("confidential-containers-audit", "airgapped"): "production-testable",
            ("tpm-attestation-audit", "ray-vllm"): "no-surface",
            ("tpm-attestation-audit", "bare-k8s-gpu"): "production-testable",
            # chip/accelerator posture: configured exports vs unconfigured profiles
            ("gpu-cc-attestation-chain", "bare-k8s-gpu"): "production-testable",
            ("gpu-cc-attestation-chain", "airgapped"): "production-testable",
            ("gpu-cc-attestation-chain", "gpu-pooling"): "conditional",
            ("gpu-cc-attestation-chain", "slurm-hpc"): "no-surface",
            ("spdm-pcie-doe", "slurm-hpc"): "production-testable",
            ("spdm-pcie-doe", "gpu-pooling"): "no-surface",
            ("iommu-smmu-config", "bare-k8s-gpu"): "production-testable",
            ("secure-boot-chain", "slurm-hpc"): "production-testable",
            ("firmware-signature-inventory", "airgapped"): "production-testable",
            ("gpu-memory-residue-isolation", "gpu-pooling"): "production-testable",
            ("gpu-memory-residue-isolation", "ray-vllm"): "conditional",
            ("nvlink-imex-isolation", "airgapped"): "production-testable",
            ("cxl-memory-security", "bare-k8s-gpu"): "no-surface",
        }
        cache = {name: surface.matrix(name, modules=self.mods) for name in self.profiles}
        for (module, profile), verdict in expected.items():
            row = next(r for r in cache[profile]["modules"] if r["module"] == module)
            self.assertEqual(row["verdict"], verdict, f"{module}/{profile}")

    def test_quarantined_modules_are_no_surface_everywhere(self):
        for name in self.profiles:
            doc = surface.matrix(name, modules=self.mods)
            rows = {r["module"]: r for r in doc["modules"]}
            for key in NO_SURFACE:
                self.assertEqual(rows[key]["verdict"], "no-surface", f"{key}/{name}")
                self.assertFalse(rows[key]["default_enabled"])

    def test_parallel_no_surface_rows_are_still_no_surface(self):
        for name in self.profiles:
            doc = surface.matrix(name, modules=self.mods)
            rows = {r["module"]: r for r in doc["modules"]}
            for key in PARALLEL_NO_SURFACE:
                self.assertEqual(rows[key]["verdict"], "no-surface", f"{key}/{name}")

    def test_default_enabled_filter(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            sentinel = root / "x"
            _write_module(root, "test-default", [], default=True, sentinel=sentinel)
            _write_module(root, "test-off", [], default=False, sentinel=sentinel)
            mods = load_modules(root)
            self.assertEqual(surface.default_module_keys(mods), ["test-default"])
            self.assertEqual(surface.no_surface_modules(mods), ["test-off"])
            doc = surface.matrix("ray-vllm", modules=mods)
            self.assertEqual(doc["summary"]["modules"], 2)
            self.assertEqual(doc["summary"]["default_enabled"], 1)
            self.assertEqual(doc["summary"]["quarantined"], 1)
            self.assertEqual(len(doc["modules"]), 2)
            with_disabled = surface.matrix("ray-vllm", modules=mods, include_disabled=True)
            self.assertEqual(with_disabled["summary"]["coverage_basis"], "all_modules")


class TestCollect(unittest.TestCase):
    def test_k8s_collect_is_read_only(self):
        payload = {"items": [{
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "gpu-0", "labels": {"nvidia.com/gpu": "true"}},
            "status": {"capacity": {"nvidia.com/gpu": "8"}},
        }]}
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")

        with mock.patch("inkblade.collect.k8s.subprocess.run", side_effect=fake_run):
            doc = k8s_collect.collect(kubectl="kubectl", timeout=1)
        self.assertEqual(doc["status"], "ok")
        self.assertEqual(doc["verb"], "get")
        self.assertTrue(doc["objects"])
        for cmd in calls:
            self.assertIn("get", cmd)
            for verb in ("apply", "delete", "patch", "exec", "create"):
                self.assertNotIn(verb, cmd)

    def test_http_fingerprint(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"version": "0.8.4", "product": "vllm"}'
                self.send_response(200)
                self.send_header("Server", "vllm/0.8.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            ep = http_collect.probe_one(f"http://127.0.0.1:{server.server_port}/v1/models")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(ep["status"], 200)
        self.assertEqual(ep["product"], "vllm")
        self.assertEqual(ep["version"], "0.8.4")

    def test_files_and_hardware_import(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "litellm").mkdir()
            (root / "litellm" / "config.yaml").write_text("model_list: []\n",
                                                          encoding="utf-8")
            (root / "weights").mkdir()
            (root / "weights" / "model.safetensors").write_bytes(b"\0" * 16)
            files = files_collect.collect(root)
            kinds = {f["path"]: f["kind"] for f in files["files"]}
            self.assertEqual(kinds["litellm/config.yaml"], "config-file")
            self.assertEqual(kinds["weights/model.safetensors"], "model-file")

            (root / "bmc").mkdir()
            (root / "bmc" / "redfish.json").write_text(json.dumps({
                "id": "bmc-1", "vendor": "Dell", "password": "s3cret",
                "address": "10.0.0.2"}), encoding="utf-8")
            hw = hardware_collect.collect(root)
            self.assertEqual(hw["status"], "ok")
            self.assertEqual(hw["bmc"][0]["id"], "bmc-1")
            self.assertEqual(hw["bmc"][0]["password"], "<redacted>")


class TestDocsAndRegistry(unittest.TestCase):
    def test_surface_docs(self):
        text = (ROOT / "docs" / "SURFACE-REALISM.md").read_text(encoding="utf-8")
        for name in ("bare-k8s-gpu", "ray-vllm", "managed-ack-tke",
                     "slurm-hpc", "airgapped", "gpu-pooling"):
            self.assertIn(f"`{name}`", text)
        self.assertIn("production-testable", text)
        self.assertIn("conditional", text)
        self.assertIn("no-surface", text)
        self.assertIn("Quarantined by default", text)
        self.assertIn("Production coverage", text)

    def test_exploit_deployment_dimension(self):
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        entries = registry["entries"]
        allowed = {"default-exposed", "needs-config", "function-level", "hardware-only"}
        for entry in entries:
            self.assertIn(entry.get("deployment_requirement"), allowed, entry["id"])
            self.assertTrue(entry.get("deployment_evidence"), entry["id"])
        dep = registry["deployment"]
        self.assertEqual(dep["schema"], "inkblade-deployment-requirement-v1")
        for bucket, count in dep["counts"].items():
            self.assertEqual(count, sum(1 for e in entries
                                        if e["deployment_requirement"] == bucket))
        self.assertEqual(sorted(dep["default_exposed"]),
                         sorted(e["id"] for e in entries
                                if e["deployment_requirement"] == "default-exposed"))
        self.assertEqual(sorted(dep["default_exploitable"]),
                         sorted(e["id"] for e in entries
                                if e["deployment_requirement"] == "default-exposed"
                                and e["status"] == "verified"))
        self.assertEqual(sorted(dep["default_exposure_verified"]),
                         sorted(e["id"] for e in entries
                                if e["deployment_requirement"] == "default-exposed"
                                and e["status"] == "exposure-verified"))
        for entry in entries:
            if entry["deployment_requirement"] == "default-exposed":
                self.assertIn(entry["status"], {"verified", "exposure-verified",
                                                "static-only"}, entry["id"])
        text = (ROOT / "docs" / "EXPLOIT-VERIFICATION.md").read_text(encoding="utf-8")
        self.assertIn("deployment_requirement", text)
        self.assertIn("default-exposed", text)
        self.assertIn("Default-exploitable PoCs", text)

    def test_cli_surfaces(self):
        proc = subprocess.run(
            [sys.executable, "-m", "inkblade", "surfaces", "--profile", "ray-vllm", "--json"],
            cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["profile"], "ray-vllm")
        self.assertGreater(doc["summary"]["default_enabled"], 0)
        self.assertTrue(any(r["module"] == "dpu-smartnic-surface" for r in doc["modules"]))


if __name__ == "__main__":
    unittest.main()
