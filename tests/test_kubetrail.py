"""tests/test_kubetrail.py — KubeTrail 移植最小闭环（采集/token 审计/三态脱敏/manifest 扫描/LPE/持久化）。"""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.kubetrail import collector, lpe, manifestscan, persistence, redact3, token_audit


class Redact3Test(unittest.TestCase):
    def test_three_modes(self):
        with TemporaryDirectory() as td:
            store = redact3.TriStore(Path(td) / "raw")
            ref = store.put("AKIAIOSFODNN7EXAMPLE", kind="aws-access-key")
            raw = store.get(ref, "raw")
            redacted = store.get(ref, "redact")
            meta = store.get(ref, "metadata")
            self.assertEqual(raw, "AKIAIOSFODNN7EXAMPLE")
            self.assertTrue(redacted.startswith("AKIA"))
            self.assertTrue(redacted.endswith("MPLE"))
            self.assertNotIn("IOSFODNN7EXAM", redacted)
            self.assertEqual(meta["kind"], "aws-access-key")
            self.assertEqual(meta["length"], 20)
            self.assertEqual(len(meta["sha256"]), 64)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", json.dumps(meta))
            self.assertEqual(store.refs()[0]["has_raw"], True)

    def test_raw_requires_store(self):
        store = redact3.TriStore()
        ref = store.put("secret-value-123456", kind="generic")
        with self.assertRaises(redact3.RedactError):
            store.get(ref, "raw")
        with self.assertRaises(redact3.RedactError):
            store.get(ref, "bogus")
        with self.assertRaises(redact3.RedactError):
            store.get("secret:9999", "redact")

    def test_mask_short_values(self):
        self.assertEqual(redact3.mask("abc"), "***")
        self.assertEqual(redact3.entropy("aaaa"), 0.0)
        self.assertGreater(redact3.entropy("aB3$xY9!"), 2.0)


class ManifestScanTest(unittest.TestCase):
    def test_rules_and_redaction(self):
        text = ('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'
                'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'
                'OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n'
                '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n')
        hits = manifestscan.scan_text(text)
        kinds = {h["kind"] for h in hits}
        for kind in ("aws-access-key", "aws-secret-key", "openai-key", "private-key"):
            self.assertIn(kind, kinds)
        blob = json.dumps([{k: v for k, v in h.items() if k != "value"} for h in hits])
        self.assertNotIn("wJalrXUtnFEMI", blob)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)

    def test_escaped_gcp_json(self):
        doc = {"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE\n"}
        manifests = [{"path": "sa.json", "kind": "ConfigMap",
                      "doc": {"key.json": json.dumps(doc)}}]
        report = manifestscan.scan_manifests(manifests)
        kinds = {f["secret_kind"] for f in report["findings"]}
        self.assertIn("gcp-service-account", kinds)
        self.assertIn("private-key", kinds)

    def test_configmap_and_tri_store(self):
        with TemporaryDirectory() as td:
            store = redact3.TriStore(Path(td))
            report = manifestscan.scan_configmaps([
                {"name": "cfg", "namespace": "default",
                 "data": {"token": "AKIAIOSFODNN7EXAMPLE"}}])
            self.assertTrue(report["findings"])
            self.assertTrue((Path(td)).exists())


class TokenAuditTest(unittest.TestCase):
    def test_decode_and_audit(self):
        token = token_audit.decode_jwt(
            "eyJhbGciOiJub25lIn0."
            "eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpkZWZhdWx0IiwiZXhwIjoyNTM0MDIzMDA3OTl9."
        )
        self.assertIn("sub", token)
        report = token_audit.audit_tokens([
            {"name": "legacy", "namespace": "default", "legacy": True,
             "subject": "system:serviceaccount:default:default",
             "exp": 253402300799, "allowed": ["*"]},
            {"name": "bound", "namespace": "infer", "legacy": False,
             "subject": "system:serviceaccount:infer:sa", "exp": 1800000000,
             "audience": ["https://kubernetes.default.svc"], "allowed": ["get pods"]},
        ])
        self.assertEqual(report["summary"]["total"], 2)
        self.assertEqual(report["summary"]["legacy"], 1)
        legacy = report["tokens"][0]
        self.assertEqual(legacy["sev"], "critical")
        self.assertTrue(any("通配符" in r for r in legacy["reasons"]))
        self.assertTrue(any("default SA" in r for r in legacy["reasons"]))

    def test_invalid_token(self):
        with self.assertRaises(token_audit.TokenAuditError):
            token_audit.decode_jwt("not-a-jwt")
        with self.assertRaises(token_audit.TokenAuditError):
            token_audit.audit_token({})


class CollectorRootTest(unittest.TestCase):
    def _tree(self, root: Path) -> None:
        (root / "proc" / "self").mkdir(parents=True)
        (root / "proc" / "sys" / "kernel").mkdir(parents=True)
        (root / "etc").mkdir(parents=True)
        (root / "var/run/secrets/kubernetes.io/serviceaccount").mkdir(parents=True)
        (root / "proc/self/status").write_text(
            "Name:\ttrain\nUid:\t0\t0\t0\t0\nNSpid:\t1234\nCapEff:\t000001ffffffffff\n",
            encoding="utf-8")
        (root / "proc/self/mountinfo").write_text(
            "1 0 0:1 / / rw - overlay overlay rw\n"
            "2 0 0:2 / /var/run/docker.sock rw - bind /var/run/docker.sock rw\n",
            encoding="utf-8")
        (root / "proc/sys/kernel/core_pattern").write_text("|/bin/sh -c id\n", encoding="utf-8")
        (root / "etc/shadow").write_text("root:$6$hash:19000:0:99999:7:::\n", encoding="utf-8")
        (root / "var/run/secrets/kubernetes.io/serviceaccount/token").write_text("a.b.c", encoding="utf-8")

    def test_collect_from_root(self):
        with TemporaryDirectory() as td:
            root = Path(td) / "rootfs"
            self._tree(root)
            report = collector.collect({}, root=root)
            self.assertEqual(report["collector_count"], 13)
            titles = " ".join(f["title"] for f in report["findings"])
            self.assertIn("root（uid=0）", titles)
            self.assertIn("PID 命名空间", titles)
            self.assertIn("core_pattern", titles)
            self.assertIn("docker.sock", titles)
            self.assertIn("/etc/shadow", titles)
            view = report["view"]
            self.assertEqual(view["identity"]["uid"], 0)
            self.assertEqual(view["identity"]["pid_namespace"], "host")

    def test_path_traversal_blocked(self):
        with TemporaryDirectory() as td:
            root = Path(td) / "rootfs"
            root.mkdir()
            outside = Path(td) / "outside.txt"
            outside.write_text("secret", encoding="utf-8")
            self.assertEqual(collector._read_under(root, "../outside.txt"), "")

    def test_empty_view_no_findings(self):
        report = collector.collect({})
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["collector_count"], 13)


class LpeTest(unittest.TestCase):
    def test_version_compare(self):
        self.assertTrue(lpe.version_lt("5.15.0", "5.15.25"))
        self.assertFalse(lpe.version_lt("5.15.25", "5.15.25"))
        self.assertTrue(lpe.version_lt("1.1.4", "1.1.12"))
        with self.assertRaises(lpe.LpeError):
            lpe.parse_version("not-a-version")

    def test_assess_hits(self):
        view = {
            "node": {"kernel": "5.15.0-91-generic", "os": "Ubuntu 22.04"},
            "runtime": {"runc": "1.1.4", "socket": "/var/run/docker.sock"},
            "capabilities": {"effective": ["SYS_ADMIN"]},
            "cgroups": {"version": "v1", "writable": True, "release_agent": "/x"},
            "seccomp": {"mode": "Unconfined"},
            "userns": {"mode": "host"},
        }
        report = lpe.assess(view)
        cves = {h["cve"] for h in report["hits"]}
        self.assertIn("CVE-2022-0847", cves)
        self.assertIn("CVE-2024-21626", cves)
        self.assertIn("CVE-2022-0492", cves)
        self.assertEqual(len(report["hits"]) + len(report["skipped"]) <= 16, True)
        findings = lpe.findings(report)
        self.assertTrue(all(f.get("confidence") == "heuristic" for f in findings if f.get("cve")))

    def test_empty_view(self):
        report = lpe.assess({})
        self.assertEqual(report["hits"], [])
        self.assertEqual(lpe.findings(report), [])


class PersistenceTest(unittest.TestCase):
    def test_detect_all_templates(self):
        snapshot = {
            "clusterrolebindings": [
                {"name": "b", "role": "cluster-admin", "subjects": ["user:backdoor"]},
            ],
            "persistence": {
                "shadow_kubeconfigs": ["/tmp/.kube/config"],
                "suspicious_bindings": [
                    {"name": "b2", "role": "backdoor-admin", "subject": "user:x"},
                ],
                "workloads": [
                    {"kind": "DaemonSet", "name": "ds", "namespace": "kube-system",
                     "privileged": True, "hostPath": "/"},
                ],
                "token_requests": [{"subject": "sa", "expiration": 63072000}],
                "pull_secret_patches": [{"serviceaccount": "default", "namespace": "default",
                                         "secret": "reg"}],
                "webhooks": [{"name": "w", "failurePolicy": "Ignore",
                              "url": "https://attacker.invalid/m"}],
            },
        }
        report = persistence.detect(snapshot)
        titles = " ".join(f["title"] for f in report["findings"]).lower()
        for token in ("cluster-admin", "影子 kubeconfig", "tokenrequest", "pull", "webhook"):
            self.assertIn(token, titles)
        self.assertEqual(report["indicators"]["shadow_kubeconfigs"], 1)
        self.assertGreaterEqual(report["indicators"]["bindings"], 2)

    def test_empty(self):
        report = persistence.detect({})
        self.assertEqual(report["findings"], [])


if __name__ == "__main__":
    unittest.main()
