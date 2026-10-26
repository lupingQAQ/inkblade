"""Guards for the QEMU-TCG real-cluster lab deliverables.

Two kinds of checks:

* scripts/docs exist and still describe the method that was actually run
  (TCG, hostfwd 2222/6445/30080, setup-alpine answers, k3s install flags);
* the recorded evidence JSON has the shape the docs claim, and its verdicts are
  internally consistent (e.g. netpol verdict recomputed from the probes).

The lab itself is not executed here: it needs QEMU, a 30+ minute TCG boot and a
k3s install. tests/test_real_cluster_artifacts.py validates what was produced.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LAB = REPO / "lab" / "qemu-k3s"
EVIDENCE = REPO / "reports" / "samples" / "real-cluster"
DOC = REPO / "docs" / "REAL-CLUSTER-VERIFICATION.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


class ScriptsAndDocs(unittest.TestCase):
    def test_lab_scripts_exist(self):
        for name in ("start-vm.ps1", "setup-alpine.sh", "install-k3s.sh",
                     "run-real-cluster-check.ps1", "vm_console.py",
                     "collect_snapshot.py", "verify_real_cluster.py",
                     "provision_alpine.py", "resume_provision.py"):
            with self.subTest(script=name):
                path = LAB / name
                self.assertTrue(path.is_file(), f"missing lab script {name}")
                self.assertGreater(path.stat().st_size, 400, f"{name} looks like a stub")

    def test_manifests_exist(self):
        for name in ("10-default-deny.yaml", "20-mock-target.yaml", "30-probe-pods.yaml"):
            with self.subTest(manifest=name):
                self.assertTrue((LAB / "manifests" / name).is_file(), f"missing manifest {name}")

    def test_start_vm_uses_tcg_and_expected_port_forwards(self):
        text = _read(LAB / "start-vm.ps1")
        self.assertIn("'tcg'", text)
        self.assertIn("hostfwd", text)
        for port in (2222, 6445, 30080):
            self.assertIn(str(port), text, f"missing port forward {port}")
        self.assertNotIn("whpx", text.lower(), "must not depend on Windows Hypervisor Platform")

    def test_setup_alpine_is_unattended(self):
        answers = _read(LAB / "http" / "answers")
        self.assertIn('HOSTNAMEOPTS="-n k3s"', answers)
        self.assertIn("DISKOPTS=\"-m sys /dev/vda\"", answers)
        self.assertIn("SSHDOPTS=\"-c openssh\"", answers)
        script = _read(LAB / "setup-alpine.sh")
        self.assertIn("setup-alpine -f /tmp/answers", script)

    def test_install_k3s_flags(self):
        text = _read(LAB / "install-k3s.sh")
        self.assertIn("INSTALL_K3S_SKIP_SELINUX_RUNTIME=1", text)
        self.assertIn("get.k3s.io", text)
        self.assertIn("K3S-READY", text)

    def test_orchestrator_calls_verifier(self):
        text = _read(LAB / "run-real-cluster-check.ps1")
        self.assertIn("verify_real_cluster.py", text)
        self.assertIn("k3s.yaml", text)
        self.assertIn("6445", text)

    def test_doc_exists_and_is_honest(self):
        self.assertTrue(DOC.is_file(), "missing docs/REAL-CLUSTER-VERIFICATION.md")
        text = _read(DOC)
        for heading in ("QEMU", "k3s", "NetworkPolicy", "hostNetwork", "性能", "局限"):
            self.assertIn(heading, text, f"doc missing section/keyword: {heading}")
        # the doc must not claim a production-grade cluster
        self.assertRegex(text, r"非生产|not production|单节点|single-node")
        # and must record the actual verdict rather than a generic "verified"
        verdict = json.loads(_read(EVIDENCE / "netpol-proof.json"))["verdict"]
        self.assertIn(verdict, text, "doc must state the recorded NetworkPolicy verdict")


class EvidenceShape(unittest.TestCase):
    def setUp(self):
        if not EVIDENCE.is_dir():
            self.skipTest("real-cluster evidence not generated in this checkout")

    def test_cluster_info(self):
        info = json.loads(_read(EVIDENCE / "cluster-info.json"))
        self.assertGreaterEqual(info["node_count"], 1)
        self.assertTrue(info["all_ready"], "recorded node was not Ready")
        self.assertIsInstance(info["api_latency_s"], list)
        self.assertGreater(len(info["api_latency_s"]), 0)
        self.assertTrue(all(isinstance(x, (int, float)) for x in info["api_latency_s"]))
        node = info["nodes"][0]
        self.assertIn("k3s", node["kubelet"])
        self.assertIn("containerd", node["containerRuntime"])
        self.assertIn("6.18", node["kernel"])

    def test_snapshot_is_from_live_kubectl(self):
        snap = json.loads(_read(EVIDENCE / "snapshot.json"))
        self.assertEqual(snap["source"], "live-kubectl")
        self.assertIn("kubectl get", snap["provenance"]["note"])
        for key in ("pods", "services", "networkpolicies", "clusterroles", "nodes"):
            self.assertIsInstance(snap[key], list, f"snapshot.{key} must be a list")
        self.assertTrue(snap["pods"], "live snapshot contained no pods")
        self.assertTrue(snap["nodes"], "live snapshot contained no nodes")
        # the mock target and the probe pods are real objects in the snapshot
        names = {p["name"] for p in snap["pods"]}
        self.assertIn("mock-target", " ".join(names))
        self.assertTrue(any(p["hostNetwork"] for p in snap["pods"]),
                        "hostNetwork probe pod missing from snapshot")

    def test_recon_modules_ran_on_live_snapshot(self):
        recon = json.loads(_read(EVIDENCE / "recon-findings.json"))
        self.assertTrue(recon["modules"], "no modules recorded")
        self.assertTrue(all(m["ok"] for m in recon["modules"]), recon["modules"])
        keys = {m["key"] for m in recon["modules"]}
        self.assertIn("exposure-mapping", keys)
        self.assertIn("network-policy-coverage", keys)
        self.assertIn("rbac-mapping", keys)
        self.assertEqual(recon["finding_count"], len(recon["findings"]))
        self.assertGreater(recon["finding_count"], 0, "recon produced no findings")
        for finding in recon["findings"]:
            self.assertIn(finding["sev"], ("critical", "high", "medium", "low", "info"))
            self.assertTrue(finding.get("title"))

    def test_service_probe_hit_real_service(self):
        probe = json.loads(_read(EVIDENCE / "service-probe.json"))
        self.assertTrue(probe["windows_http"]["ok"], "Windows could not reach the NodePort")
        attempts = probe["windows_http"]["attempts"]
        self.assertTrue(any(a.get("status") == 200 for a in attempts))
        module = probe["inkblade_module"]
        entries = module["trace"]["entries"]
        self.assertTrue(entries, "InkBlade module recorded no HTTP trace")
        listing = [e for e in entries if e["url"].endswith("/plugins/list")]
        control = [e for e in entries if e["url"].endswith("/v1/models")]
        self.assertEqual(listing[0]["status"], 200, "mock target did not serve /plugins/list")
        self.assertIn(control[0]["status"], (401, 403), "control route should require api-key")

    def test_netpol_verdict_matches_probes(self):
        proof = json.loads(_read(EVIDENCE / "netpol-proof.json"))
        self.assertGreaterEqual(len(proof["probes"]), 4)
        normal = [p for p in proof["probes"] if p["pod"] == "proof-normal"]
        hostnet = [p for p in proof["probes"] if p["pod"] == "proof-hostnet"]
        self.assertTrue(normal and hostnet)
        normal_blocked = all(p["verdict"] == "blocked" for p in normal)
        hostnet_ok = any(p["verdict"] == "connected" for p in hostnet)
        self.assertEqual(proof["normal_all_blocked"], normal_blocked)
        self.assertEqual(proof["hostnet_any_connected"], hostnet_ok)
        if normal_blocked and hostnet_ok:
            self.assertEqual(proof["verdict"], "bypass-confirmed")
        elif not normal_blocked:
            self.assertEqual(proof["verdict"], "environment-invalid (policy not enforced)")
        else:
            self.assertEqual(proof["verdict"], "bypass-not-observed")

    def test_verification_summary_declares_tcg_limits(self):
        summary = json.loads(_read(EVIDENCE / "verification-summary.json"))
        for step in ("cluster", "deploy", "service_probe", "netpol", "recon"):
            self.assertIn(step, summary["steps"])
        self.assertIn("tcg", summary["qemu_tcg"]["note"].lower())
        self.assertRegex(summary["qemu_tcg"]["implication"], r"slower|慢")


if __name__ == "__main__":
    unittest.main()
