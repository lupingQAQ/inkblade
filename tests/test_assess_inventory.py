# -*- coding: utf-8 -*-
"""只读 inventory 采集：命令白名单 / 字段证据 / snapshot 归一 / 缺失即 unknown。"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from trident.assess.inventory import (
    InventoryError,
    KubectlReader,
    collect_inventory,
    default_inventory_path,
    inventory_from_snapshot,
    inventory_summary,
    load_inventory,
    load_probes,
    merge_probes,
)
from trident.core import applicability as a

REPO = Path(__file__).resolve().parents[1]
PY = sys.executable
FIX = REPO / "tests" / "fixtures" / "assess"


def _proc(data, rc=0, stderr=""):
    text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    return SimpleNamespace(returncode=rc, stdout=text, stderr=stderr)


NODE = {
    "apiVersion": "v1", "kind": "Node",
    "metadata": {"name": "node-1",
                 "labels": {"kubernetes.io/os": "linux",
                            "nvidia.com/gpu.product": "A100"},
                 "annotations": {"flannel.alpha.coreos.com/backend-type": "vxlan"}},
    "spec": {"providerID": "aws:///us-east-1a/i-abc"},
    "status": {
        "capacity": {"nvidia.com/gpu": "1"},
        "conditions": [{"type": "Ready", "status": "True"}],
        "nodeInfo": {"operatingSystem": "linux", "osImage": "Ubuntu 22.04",
                     "kernelVersion": "5.15.0-105-generic",
                     "kubeletVersion": "v1.28.3",
                     "containerRuntimeVersion": "containerd://1.7.2",
                     "architecture": "amd64"},
        "runtimeHandlers": [{"name": "runc", "features": {}}],
    },
}
POD = {
    "apiVersion": "v1", "kind": "Pod",
    "metadata": {"name": "ray-head-0", "namespace": "ray-system",
                 "labels": {"app": "ray"}},
    "spec": {
        "nodeName": "node-1", "serviceAccountName": "ray-sa",
        "hostNetwork": False, "hostPID": True,
        "automountServiceAccountToken": True,
        "containers": [{
            "name": "ray", "image": "rayproject/ray:2.7.0",
            "args": ["ray", "start", "--dashboard-host=0.0.0.0"],
            "env": [{"name": "RAY_AUTH_MODE", "value": ""}],
            "securityContext": {"privileged": True,
                                "capabilities": {"add": ["SYS_ADMIN"]}},
        }],
        "volumes": [{"name": "root", "hostPath": {"path": "/"}},
                    {"name": "sock",
                     "hostPath": {"path": "/var/run/containerd/containerd.sock"}}],
    },
    "status": {"phase": "Running"},
}


def _fake_runner(argv, timeout):
    text = " ".join(argv)
    if "get --raw /version" in text or ("--raw" in argv and "/version" in argv):
        return _proc({"gitVersion": "v1.28.3", "major": "1", "minor": "28"})
    if "/metrics" in text:
        return _proc('kubernetes_feature_enabled{name="HTTP2",stage="BETA"} 1\n'
                     'kubernetes_feature_enabled{name="SideCar",stage="ALPHA"} 0\n')
    if "proxy/configz" in text:
        return _proc({"kubeletconfig": {"readOnlyPort": 0,
                                        "authentication": {"anonymous": {"enabled": False}},
                                        "authorization": {"mode": "Webhook"}}})
    if "auth can-i" in text:
        return _proc("yes\n")
    if "customresourcedefinitions" in text:
        return _proc({"items": []})
    if "ingressclasses" in text:
        return _proc({"items": []})
    if "gatewayclasses" in text or " gateways" in text:
        return _proc("error: the server doesn't have a resource type", rc=1)
    if "get nodes" in text:
        return _proc({"items": [NODE]})
    if "get namespaces" in text:
        return _proc({"items": [{"metadata": {"name": "default"}},
                                {"metadata": {"name": "ray-system"}}]})
    if "get pods" in text:
        return _proc({"items": [POD]})
    if "get daemonsets" in text:
        return _proc({"items": []})
    if "serviceaccounts" in text:
        return _proc({"items": [{"metadata": {"namespace": "ray-system",
                                              "name": "ray-sa",
                                              "annotations": {
                                                  "eks.amazonaws.com/role-arn":
                                                      "arn:aws:iam::123:role/ray"}}}]})
    if "storageclasses" in text or "csidrivers" in text or "persistentvolumes" in text \
            or "persistentvolumeclaims" in text or "ingresses" in text:
        return _proc({"items": []})
    return _proc({"items": []})


class TestKubectlReadOnly(unittest.TestCase):
    def test_rejects_non_whitelisted_verb(self):
        with TemporaryDirectory() as tmp:
            kc = Path(tmp) / "kubeconfig"
            kc.write_text("apiVersion: v1\n", encoding="utf-8")
            reader = KubectlReader("kubectl", kubeconfig=kc, runner=_fake_runner)
            for args in (["delete", "pod", "x"], ["get", "pods"], ["exec", "x"]):
                with self.subTest(args=args):
                    if args[0] == "get":
                        continue
                    with self.assertRaises(InventoryError):
                        reader.call(args)


class TestLiveCollector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        kc = Path(cls.tmp.name) / "kubeconfig"
        kc.write_text("apiVersion: v1\n", encoding="utf-8")
        cls.inv = collect_inventory(kubeconfig=kc, kubectl="kubectl",
                                    runner=_fake_runner, timeout=5)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_version_nodes_and_runtime(self):
        self.assertEqual(self.inv["cluster"]["version"], "v1.28.3")
        self.assertEqual(self.inv["nodes"][0]["kernel"], "5.15.0-105-generic")
        self.assertEqual(self.inv["nodes"][0]["containerd"], "1.7.2")
        self.assertTrue(self.inv["nodes"][0]["runc_present"])

    def test_components_images_and_cni(self):
        comp = self.inv["components"][0]
        self.assertEqual(comp["product"], "ray")
        self.assertEqual(comp["version"], "2.7.0")
        self.assertEqual(self.inv["cni"]["name"], "flannel")
        self.assertEqual(self.inv["gpu"]["driver_version"], "")

    def test_facts_and_evidence_have_sources(self):
        facts = self.inv["facts"]
        self.assertTrue(facts["workloads.privileged"])
        self.assertTrue(facts["workloads.host_path"])
        self.assertTrue(facts["workloads.runtime_socket"])
        self.assertTrue(facts["workloads.cap_sys_admin"])
        self.assertEqual(facts["kubelet.read_only_port"], 0)
        self.assertTrue(facts["feature_gates.HTTP2"])
        self.assertTrue(self.inv["evidence"])
        for ev in self.inv["evidence"]:
            self.assertIn("field", ev)
            self.assertIn("source", ev)
        self.assertEqual(self.inv["source"]["mode"], "live-kubectl")

    def test_rbac_and_coverage(self):
        self.assertTrue(self.inv["rbac"]["create_pods"])
        self.assertTrue(self.inv["coverage"]["pods"])
        self.assertTrue(self.inv["coverage"]["kubelet_config"])
        self.assertTrue(self.inv["collection"]["read_only"])
        self.assertFalse(any(tok in {"apply", "delete", "patch", "exec"}
                             for call in self.inv["collection"]["commands"]
                             for tok in call.get("argv") or []))

    def test_cloud_identity_hint(self):
        self.assertEqual(self.inv["cloud"]["provider"], "aws")
        self.assertTrue(any("role-arn" in h for h in self.inv["cloud"]["identity_hints"]))

    def test_collector_inventory_is_assessable(self):
        result = a.assess_cves(self.inv, catalog_path=FIX / "catalog-four-states.json")
        summary = result["summary"]
        self.assertEqual(summary["total"], 7)
        # runc 版本没暴露 → 不能升级为 applicable
        entry = next(e for e in result["entries"] if e["cve"] == "CVE-2024-21626")
        self.assertEqual(entry["state"], "unknown")


class TestSnapshotMode(unittest.TestCase):
    def test_simplified_snapshot(self):
        raw = {
            "cluster": {"name": "snap", "version": "v1.28.3", "provider": "aws"},
            "collected_at": "2026-10-26T00:00:00Z",
            "nodes": [{"name": "n1", "os": "linux", "kernel": "5.15.0",
                       "kubelet": "v1.28.3", "container_runtime": "containerd://1.7.2",
                       "runc": "1.1.11", "gpu": {"count": 1,
                                                   "driver_version": "535.0"}}],
            "pods": [{"namespace": "train", "name": "p", "serviceAccount": "sa",
                      "automountServiceAccountToken": True,
                      "containers": [{"name": "vllm",
                                      "image": "vllm/vllm-openai:v0.7.0",
                                      "securityContext": {"privileged": True}}],
                      "volumes": [{"name": "h", "hostPath": {"path": "/data"}}]}],
            "namespaces": ["train"],
            "bmc": [{"vendor": "Dell", "model": "iDRAC9", "version": "7.0"}],
            "switches": [{"vendor": "NVIDIA", "os": "cumulus", "version": "5.13.0"}],
            "probes": {"imds_reachable": True},
        }
        inv = inventory_from_snapshot(raw, "snap.json")
        self.assertEqual(inv["schema"], "trident-inventory-v1")
        self.assertEqual(inv["source"]["mode"], "snapshot")
        self.assertIn("snap.json", inv["source"]["label"])
        self.assertEqual(inv["cluster"]["version"], "v1.28.3")
        self.assertEqual(inv["nodes"][0]["runc"], "1.1.11")
        self.assertEqual(inv["bmc"][0]["version"], "7.0")
        self.assertTrue(inv["coverage"]["hardware"])
        self.assertEqual(inv["probes"]["imds_reachable"], True)

    def test_empty_snapshot_is_honest_unknown(self):
        inv = inventory_from_snapshot({"nodes": [], "pods": []}, "empty.json")
        self.assertTrue(inv["coverage"]["pods"])
        self.assertEqual(inv["components"], [])
        result = a.assess_cves(inv)
        if result["catalog"]["found"]:
            self.assertGreater(result["summary"]["unknown"], 0)
            self.assertEqual(result["summary"]["applicable"], 0)

    def test_load_schema_inventory(self):
        inv = load_inventory(FIX / "inventory-four-states.json")
        self.assertEqual(inv["schema"], "trident-inventory-v1")
        self.assertEqual(inv["path"], str(FIX / "inventory-four-states.json"))
        summary = inventory_summary(inv)
        self.assertEqual(summary["counts"]["nodes"], 1)
        self.assertEqual(summary["counts"]["components"], 2)

    def test_probes_merge(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "probes.json"
            p.write_text(json.dumps({"imds_reachable": True,
                                     "component_auth": {"ray": True}}), encoding="utf-8")
            probes = load_probes(p)
            inv = merge_probes(load_inventory(FIX / "inventory-four-states.json"),
                               probes, source=str(p))
            self.assertTrue(inv["probes"]["imds_reachable"])
            self.assertTrue(inv["facts"]["probes.imds_reachable"])
            self.assertTrue(inv["cloud"]["imds_reachable"])
            self.assertTrue(any(ev["field"] == "probes.imds_reachable"
                                for ev in inv["evidence"]))

    def test_default_inventory_path(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertIsNone(default_inventory_path(root))
            (root / "inventory.json").write_text("{}", encoding="utf-8")
            self.assertEqual(default_inventory_path(root), root / "inventory.json")


class TestCliAssess(unittest.TestCase):
    def _cli(self, home: Path, *args: str):
        return subprocess.run([PY, "-m", "trident", "--home", str(home), *args],
                              cwd=str(REPO), capture_output=True, timeout=120,
                              env={**__import__("os").environ,
                                   "PYTHONIOENCODING": "utf-8"})

    def test_inventory_snapshot_and_cves_and_explain(self):
        with TemporaryDirectory() as tmp:
            home = Path(tmp)
            r = self._cli(home, "assess", "inventory",
                          "--snapshot", str(FIX / "inventory-four-states.json"),
                          "--out", str(home / "inventory.json"))
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            body = json.loads(r.stdout.decode("utf-8", "replace"))
            self.assertEqual(body["schema"], "trident-inventory-v1")
            r = self._cli(home, "assess", "cves",
                          "--inventory", str(home / "inventory.json"),
                          "--catalog", str(FIX / "catalog-four-states.json"),
                          "--out", str(home / "assessment.json"),
                          "--format", "both")
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            body = json.loads(r.stdout.decode("utf-8", "replace"))
            self.assertEqual(body["summary"]["total"], 7)
            self.assertTrue((home / "assessment.json").is_file())
            self.assertTrue((home / "assessment.md").is_file())
            r = self._cli(home, "assess", "explain", "CVE-2024-21626",
                          "--inventory", str(home / "inventory.json"),
                          "--catalog", str(FIX / "catalog-four-states.json"))
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            text = r.stdout.decode("utf-8", "replace")
            self.assertIn("结论", text)
            self.assertIn("为什么", text)
            self.assertIn("怎么补采", text)

    def test_execute_dry_run_uses_applicability_gate(self):
        with TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "inventory.json").write_text(
                (FIX / "inventory-four-states.json").read_text(encoding="utf-8"),
                encoding="utf-8")
            mods = home / "modules"
            for key in ("runc-escape-detect", "kubelet-surface"):
                d = mods / key
                d.mkdir(parents=True)
                (d / "module.json").write_text(json.dumps({
                    "key": key, "name": {"zh": key, "en": key},
                    "series": "横向利用", "description": "fixture",
                    "min_level": "只读侦察", "writes": False, "requires": [],
                }, ensure_ascii=False), encoding="utf-8")
                (d / "run.py").write_text(
                    "def run(ctx, params):\n    return {'summary': 'ok'}\n",
                    encoding="utf-8")
            chains = home / "chains"
            chains.mkdir()
            (chains / "cve-gate.json").write_text(json.dumps({
                "id": "cve-gate", "title": {"zh": "闸门", "en": "gate"},
                "category": "经典攻击链", "requires": [], "preconditions": [],
                "steps": [{"id": "runc", "module": "runc-escape-detect"},
                          {"id": "kubelet", "module": "kubelet-surface"}],
                "evidence": [], "mitre": [],
            }, ensure_ascii=False), encoding="utf-8")
            r = self._cli(home, "execute", "--chain", "cve-gate", "--dry-run",
                          "--modules-dir", str(mods), "--chains-dir", str(chains),
                          "--catalog", str(FIX / "catalog-four-states.json"))
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            plan = json.loads(r.stdout.decode("utf-8", "replace"))
            steps = {s["id"]: s for s in plan["steps"]}
            self.assertEqual(steps["runc"]["status"], "ready")
            self.assertEqual(steps["kubelet"]["status"], "blocked")
            self.assertTrue(plan["applicability"]["evaluated"])

            # 单模块 run：blocked 在 ROE/runner 之前返回 91
            r = self._cli(home, "run", "--module", "kubelet-surface",
                          "--modules-dir", str(mods),
                          "--catalog", str(FIX / "catalog-four-states.json"))
            self.assertEqual(r.returncode, 91,
                             r.stderr.decode("utf-8", "replace"))
            body = json.loads(r.stdout.decode("utf-8", "replace"))
            self.assertEqual(body["status"], "blocked")

    def test_missing_inventory_exit_2(self):
        with TemporaryDirectory() as tmp:
            r = self._cli(Path(tmp), "assess", "cves")
            self.assertEqual(r.returncode, 2)
            self.assertIn("缺少环境清单", r.stderr.decode("utf-8", "replace"))


class TestLiveLabNoFabrication(unittest.TestCase):
    """QEMU k3s 实测快照：只读 API 拿不到的 runc/带外信息必须保持 unknown。"""

    def test_k3s_sample_does_not_upgrade_unknown(self):
        inv_path = REPO / "reports" / "samples" / "assess" / "inventory-k3s.json"
        if not inv_path.is_file():
            self.skipTest("live k3s inventory artifact not present")
        inv = load_inventory(inv_path)
        result = a.assess_cves(inv)
        if not result["catalog"]["found"]:
            self.skipTest("cve catalog not on disk")
        states = {e["cve"]: e["state"] for e in result["entries"]}
        self.assertEqual(states.get("CVE-2024-21626"), "unknown")
        self.assertEqual(states.get("CVE-2025-31133"), "unknown")
        self.assertEqual(states.get("CVE-2013-4786"), "unknown")
        self.assertEqual(states.get("CVE-2025-32444"), "not-applicable")
        self.assertEqual(result["summary"]["applicable"], 0)
        for e in result["entries"]:
            if e["cve"] in ("CVE-2024-21626", "CVE-2025-31133"):
                self.assertNotEqual(e["state"], "applicable")
                self.assertTrue(e["missing"])


if __name__ == "__main__":
    unittest.main()
