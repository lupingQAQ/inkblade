"""tests/test_modules_attack_surface.py — 攻击面缺口补齐模块（21 个）fixture 命中与空基线。"""
import importlib.util
import json
import unittest
from pathlib import Path

from inkblade.core.registry import load_modules

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"
FIXTURE = ROOT / "lab" / "fixtures" / "attack-surface" / "cluster-surface.json"

MODULE_KEYS = (
    "kubehound-edges", "kubehound-token-edges", "attack-path-ranking", "kdigger-buckets",
    "kdigger-admission", "cdk-techniques", "cdk-persistence-detect", "kubehunter-checks",
    "kubelet-api-surface", "peirates-primitives", "reverse-rbac-lookup", "kube-bench-cis",
    "kubiscan-risky", "secret-scanner", "kubernetes-cve-catalog", "cloud-token-harvest",
    "kubetrail-collector", "kubetrail-token-audit", "kubetrail-manifest-secrets",
    "kubetrail-lpe", "kubetrail-persistence",
)


def load_run(key: str):
    spec = importlib.util.spec_from_file_location(f"surface_{key.replace('-', '_')}",
                                                  MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AttackSurfaceFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def run_mod(self, key: str, snapshot=None) -> dict:
        result = load_run(key).run({}, {"snapshot": self.snapshot if snapshot is None else snapshot})
        for field in ("summary", "findings", "artifacts"):
            self.assertIn(field, result, key)
        return result

    @staticmethod
    def titles(result):
        return [f["title"] for f in result["findings"]]

    @staticmethod
    def summary(result):
        return json.loads(result["summary"])

    def test_kubehound_edges(self):
        result = self.run_mod("kubehound-edges")
        edges = set(self.summary(result)["edges"])
        self.assertGreaterEqual(len(result["findings"]), 18)
        self.assertGreaterEqual(len(edges), 20)
        for edge in ("CE_PRIV_MOUNT", "CE_VAR_LOG_SYMLINK", "TOKEN_STEAL", "ROLE_BIND",
                     "POD_CREATE", "IDENTITY_IMPERSONATE", "SHARE_PS", "CONTAINER_ATTACH",
                     "PERMISSION_DISCOVER" if "PERMISSION_DISCOVER" in edges else "VOLUME_ACCESS"):
            self.assertIn(edge, edges)
        self.assertEqual(self.summary(result)["edges_total"], 26)

    def test_kubehound_token_edges(self):
        result = self.run_mod("kubehound-token-edges")
        s = self.summary(result)
        self.assertEqual(set(s["edges"]), {"TOKEN_STEAL", "TOKEN_LIST", "TOKEN_BRUTEFORCE"})
        text = " ".join(self.titles(result))
        self.assertIn("TOKEN_STEAL", text)
        self.assertIn("TOKEN_BRUTEFORCE", text)

    def test_attack_path_ranking(self):
        mod = load_run("attack-path-ranking")
        paths = mod.rank_paths(self.snapshot)
        self.assertGreaterEqual(len(paths), 2)
        self.assertTrue(all(p["nodes"] and p["edges"] for p in paths))
        self.assertGreater(paths[0]["score"], 0)
        result = self.run_mod("attack-path-ranking")
        self.assertTrue(any("最短攻击路径" in t for t in self.titles(result)))
        self.assertTrue(any("瓶颈节点" in t for t in self.titles(result)))

    def test_kdigger_buckets(self):
        result = self.run_mod("kdigger-buckets")
        buckets = {f.get("bucket") for f in result["findings"]}
        self.assertGreaterEqual(len(result["findings"]), 15)
        for bucket in ("capabilities", "mount", "runtime", "cloudmetadata", "token", "syscalls"):
            self.assertIn(bucket, buckets)
        self.assertGreaterEqual(self.summary(result)["buckets_observed"], 18)

    def test_kdigger_admission(self):
        result = self.run_mod("kdigger-admission")
        s = self.summary(result)
        self.assertEqual(s["templates"], 6)
        self.assertEqual(sorted(s["allowed"]), ["hostpath", "hostpid", "priv-escalation", "privileged"])
        self.assertEqual(sorted(s["denied"]), ["hostnetwork", "runasroot"])
        allowed = [f for f in result["findings"] if f.get("allowed") is True]
        self.assertEqual(len(allowed), 4)

    def test_cdk_techniques(self):
        result = self.run_mod("cdk-techniques")
        s = self.summary(result)
        self.assertEqual(s["exp_total"], 30)
        self.assertEqual(s["evaluate_total"], 13)
        self.assertGreaterEqual(s["exp_available"], 15)
        self.assertTrue(all(f.get("technique", "").startswith("cdk:") for f in result["findings"]))
        self.assertEqual(s["evaluate_checked"], 13)

    def test_cdk_persistence(self):
        result = self.run_mod("cdk-persistence-detect")
        titles = " ".join(self.titles(result)).lower()
        self.assertGreaterEqual(len(result["findings"]), 7)
        for token in ("cluster-admin", "影子 kubeconfig", "tokenrequest", "pull", "webhook"):
            self.assertIn(token, titles)
        self.assertIn("static_pods", titles.lower() + self.summary(result)["indicators"].keys().__str__())

    def test_kubehunter_checks(self):
        result = self.run_mod("kubehunter-checks")
        s = self.summary(result)
        self.assertEqual(s["checks_catalog"], 47)
        self.assertEqual(s["checks_run"], 29)
        self.assertGreaterEqual(s["failed"], 20)
        self.assertTrue(all(f.get("vid") and f.get("mitre") for f in result["findings"]))
        vids = {f["vid"] for f in result["findings"]}
        self.assertIn("KHV-APISERVER-ANON", vids)
        self.assertIn("KHV-KUBELET-EXEC", vids)
        self.assertIn("KHV-ETCD-NOAUTH", vids)

    def test_kubelet_api_surface(self):
        result = self.run_mod("kubelet-api-surface")
        s = self.summary(result)
        self.assertEqual(s["api_groups"], 15)
        self.assertEqual(s["rce_channels"], ["cri", "exec", "run"])
        self.assertIn(10255, s["readonly_ports"])
        titles = " ".join(self.titles(result))
        self.assertIn("exec", titles)
        self.assertIn("10255", titles)

    def test_peirates_primitives(self):
        result = self.run_mod("peirates-primitives")
        s = self.summary(result)
        self.assertEqual(s["primitives_total"], 37)
        self.assertGreaterEqual(s["available"], 15)
        titles = " ".join(self.titles(result))
        self.assertIn("scan-configmaps", titles)
        self.assertIn("dump-token", titles)
        cm = [f for f in result["findings"] if f.get("primitive") == "scan-configmaps"]
        self.assertTrue(cm)
        self.assertNotIn("wJalrXUtnFEMI", json.dumps(cm, ensure_ascii=False))

    def test_reverse_rbac_lookup(self):
        mod = load_run("reverse-rbac-lookup")
        subjects = mod.lookup(self.snapshot, "get", "secrets")
        self.assertIn("user:intern", subjects)
        self.assertIn("system:serviceaccount:kube-system:node-agent", subjects)
        result = self.run_mod("reverse-rbac-lookup")
        self.assertTrue(any("谁可以 get secrets" in t for t in self.titles(result)))
        imp = [f for f in result["findings"] if f.get("verb") == "impersonate"]
        self.assertTrue(imp)

    def test_kube_bench_cis(self):
        result = self.run_mod("kube-bench-cis")
        s = self.summary(result)
        self.assertEqual(s["checks_run"], 26)
        self.assertGreaterEqual(s["failed"], 20)
        self.assertEqual(s["skipped"], 1)
        self.assertTrue(all(f.get("cis_id") for f in result["findings"]))
        cis_ids = {f["cis_id"] for f in result["findings"]}
        self.assertIn("1.2.1", cis_ids)
        self.assertIn("4.2.1", cis_ids)
        self.assertIn("5.1.1", cis_ids)
        self.assertTrue(s["profile"].startswith("cis-"))

    def test_kubiscan_risky(self):
        result = self.run_mod("kubiscan-risky")
        titles = " ".join(self.titles(result))
        self.assertIn("risky 主体", titles)
        self.assertIn("Secret 挂载盘点", titles)
        self.assertIn("Token dump", titles)
        self.assertGreaterEqual(self.summary(result)["risky_subjects"], 3)

    def test_secret_scanner(self):
        result = self.run_mod("secret-scanner")
        kinds = set(self.summary(result)["by_kind"])
        for kind in ("aws-access-key", "gcp-service-account", "private-key", "openai-key"):
            self.assertIn(kind, kinds)
        blob = json.dumps(result["findings"], ensure_ascii=False)
        self.assertNotIn("wJalrXUtnFEMI", blob)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)
        self.assertNotIn("-----BEGIN PRIVATE KEY-----\nMIIE", blob)
        self.assertIn("****", blob)

    def test_kubernetes_cve_catalog(self):
        result = self.run_mod("kubernetes-cve-catalog")
        cves = self.summary(result)["cves"]
        for cve in ("CVE-2024-21626", "CVE-2022-0492", "CVE-2020-8558"):
            self.assertIn(cve, cves)
        all_cves = [f["cve"] for f in result["findings"]]
        self.assertEqual(len(all_cves), len(set(all_cves)), "CVE 不得重复")
        self.assertTrue(all(f.get("confidence") == "version-range" for f in result["findings"]))

    def test_cloud_token_harvest(self):
        result = self.run_mod("cloud-token-harvest")
        providers = set(self.summary(result)["providers_hit"])
        self.assertEqual(providers, {"aws", "azure", "gcp"})
        titles = " ".join(self.titles(result))
        self.assertIn("IMDS", titles)
        self.assertIn("GCP", titles)

    def test_kubetrail_collector(self):
        result = self.run_mod("kubetrail-collector")
        s = self.summary(result)
        self.assertEqual(s["collectors"], 13)
        self.assertGreaterEqual(len(result["findings"]), 15)
        titles = " ".join(self.titles(result))
        self.assertIn("docker.sock", titles)
        self.assertIn("core_pattern", titles)
        self.assertIn("云元数据可达", titles)
        self.assertIn("/etc/shadow", titles)

    def test_kubetrail_token_audit(self):
        result = self.run_mod("kubetrail-token-audit")
        s = self.summary(result)
        self.assertEqual(s["tokens"], 3)
        self.assertEqual(s["legacy"], 2)
        self.assertGreaterEqual(s["critical"], 1)
        detail = " ".join(f["detail"] for f in result["findings"])
        self.assertIn("legacy", detail)
        self.assertIn("通配符", detail)

    def test_kubetrail_manifest_secrets(self):
        result = self.run_mod("kubetrail-manifest-secrets")
        kinds = set(self.summary(result)["by_kind"])
        self.assertIn("aws-access-key", kinds)
        self.assertIn("gcp-service-account", kinds)
        self.assertIn("private-key", kinds)
        self.assertFalse(any("wJalrXUtnFEMI" in json.dumps(f, ensure_ascii=False)
                             for f in result["findings"]))
        self.assertIn("redact+metadata", self.summary(result)["tri_state"])

    def test_kubetrail_lpe(self):
        result = self.run_mod("kubetrail-lpe")
        s = self.summary(result)
        self.assertEqual(s["rules"], 16)
        self.assertGreaterEqual(s["cves_at_risk"], 5)
        for cve in ("CVE-2022-0847", "CVE-2024-21626", "CVE-2022-0492"):
            self.assertIn(cve, s["cves"])
        self.assertTrue(all(f.get("confidence") == "heuristic" for f in result["findings"]
                            if f.get("cve")))

    def test_kubetrail_persistence(self):
        result = self.run_mod("kubetrail-persistence")
        self.assertGreaterEqual(len(result["findings"]), 7)
        titles = " ".join(self.titles(result)).lower()
        for token in ("影子 kubeconfig", "tokenrequest", "pull", "webhook", "权限绑定"):
            self.assertIn(token, titles)

    def test_empty_snapshot_zero_findings(self):
        for key in MODULE_KEYS:
            with self.subTest(module=key):
                result = self.run_mod(key, {})
                self.assertEqual(result["findings"], [], f"{key}: {self.titles(result)}")

    def test_registry_contract(self):
        mods = load_modules(MODULES)
        for key in MODULE_KEYS:
            meta = mods[key]
            self.assertEqual(meta.series, "侦察", key)
            self.assertFalse(meta.writes, key)
            self.assertFalse(meta.private, key)
            self.assertIn(meta.min_level, ("只读侦察", "主动探测"), key)
        self.assertEqual(mods["kdigger-admission"].min_level, "主动探测")
        self.assertEqual(mods["kubelet-api-surface"].min_level, "主动探测")


if __name__ == "__main__":
    unittest.main()
