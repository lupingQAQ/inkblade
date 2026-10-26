# -*- coding: utf-8 -*-
"""CVE 武器化模块测试：mock 两态（vulnerable/fixed）+ marker 清理 + 快照只读探测。"""

import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lab.cve_sim import start_all
from inkblade.core.registry import load_modules
from tests.test_lab_mocks import request

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "inkblade" / "modules"
FIXTURE = ROOT / "lab" / "fixtures" / "cve" / "host-surface.json"

WRITE_HTTP_MODULES = (
    ("ray-job-marker-rce", "CVE-2023-48022"),
    ("sglang-zmq-pickle-rce", "CVE-2026-3059"),
    ("sglang-route-poison", "CVE-2026-92972"),
    ("vllm-pickle-pipe-rce", "CVE-2025-32444"),
    ("litellm-config-update-rce", "CVE-2026-35029"),
    ("sonic-config-plane-write", "CVE-2025-38741"),
    ("sonic-rsyslog-injection", "GHSA-h26v-922j-28cg"),
    ("cumulus-nvue-injection", "CVE-2025-33180"),
    ("megatron-checkpoint-rce", "CVE-2026-65110"),
    ("deepspeed-checkpoint-rce", "CVE-2024-43497"),
    ("torch-weights-bypass-rce", "CVE-2025-32434"),
    ("mlflow-trace-write", "CVE-2026-53995"),
    ("mlflow-model-rce", "CVE-2024-0520"),
    ("dify-code-node-escape", "CVE-2025-3466"),
    ("open-webui-file-overwrite", "CVE-2026-28788"),
)

READONLY_HTTP_MODULES = (
    ("sglang-weight-exfil", "CVE-2026-15978"),
    ("vllm-timing-oracle", "CVE-2025-59425"),
    ("litellm-default-key-exfil", "LITELLM-DEFAULT-KEY"),
    ("ipmi-cipher-zero-bypass", "CVE-2013-4786"),
    ("redfish-default-credentials", "REDFISH-DEFAULT-CREDS"),
    ("hami-scheduler-auth-gap", "HAMI-ADV-2026-01"),
)

SNAPSHOT_MODULES = (
    ("runc-escape-detect", "CVE-2024-21626"),
    ("containerd-shim-escape-detect", "CVE-2020-15257"),
    ("kubelet-gitrepo-exec-detect", "CVE-2024-10220"),
    ("nvidia-toolkit-escape-detect", "CVE-2024-0132"),
    ("gpu-operator-driver-audit", "CVE-2025-23266"),
    ("cgpu-isolation-audit", "CGPU-ADV-2026-01"),
    ("lws-leader-endpoint-audit", "LWS-ADV-2026-01"),
)


class _Run:
    def __init__(self, path: Path):
        self.dir = path
        self.name = "cve-test"


def load_run(key: str):
    spec = importlib.util.spec_from_file_location(f"cve_{key.replace('-', '_')}", MODULES / key / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def details(result: dict) -> list[dict]:
    out = []
    for f in result.get("findings") or []:
        try:
            out.append(json.loads(f.get("detail") or "{}"))
        except ValueError:
            out.append({})
    return out


class CveModuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.vuln = start_all(mode="vulnerable", root=cls.root / "vuln")
        cls.fixed = start_all(mode="fixed", root=cls.root / "fixed")
        cls.snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.mods = load_modules(MODULES)

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.fixed.shutdown()
        cls.tmp.cleanup()

    def run_mod(self, key: str, params: dict, sub: str = "a") -> dict:
        run = _Run(self.root / "runs" / key / sub)
        run.dir.mkdir(parents=True, exist_ok=True)
        return load_run(key).run({"run": run, "marker": "INKBLADE-CVE-TEST", "backup": None}, params)

    def test_metadata_and_gates(self):
        for key, _ in WRITE_HTTP_MODULES + READONLY_HTTP_MODULES + SNAPSHOT_MODULES:
            meta = self.mods[key]
            self.assertRegex(key, r"^[a-z][a-z-]*$")
            self.assertTrue(meta.description)
            if key in {k for k, _ in WRITE_HTTP_MODULES}:
                self.assertTrue(meta.writes, f"{key} 写类模块必须 writes=True")
            if key in {k for k, _ in SNAPSHOT_MODULES}:
                self.assertFalse(meta.writes, f"{key} 只读模块不得 writes=True")

    def test_write_modules_full_exploit_and_cleanup(self):
        for key, cve in WRITE_HTTP_MODULES:
            with self.subTest(module=key):
                params = {
                    "target": self.vuln.url(""),
                    "mode": "backup-write",
                    "backup_targets": [{"kind": "http", "url": self.vuln.url(""), "state": {}}],
                    "cleanup": False,
                }
                result = self.run_mod(key, params)
                self.assertGreaterEqual(len(result["findings"]), 1, key)
                detail = details(result)[0]
                self.assertIn(cve, detail.get("cves", []), f"{key} finding 未标 CVE")
                self.assertEqual(detail.get("exploit_level"), "full-mock", key)
                self.assertTrue(detail.get("marker_path"), key)
                marker = Path(detail["marker_path"])
                self.assertTrue(marker.is_file(), f"{key} marker 未落盘")
                self.assertIn("INKBLADE-CVE-TEST", marker.read_text(encoding="utf-8", errors="replace"), key)
                self.assertEqual(detail.get("cleanup", {}).get("status"), "skipped", key)
                cleanup = request("POST", self.vuln.url("/__cleanup__"),
                                  {"marker": "INKBLADE-CVE-TEST"})
                self.assertEqual(cleanup[0], 200, key)
                self.assertFalse(marker.exists(), f"{key} cleanup 未删除 marker")

    def test_write_modules_probe_only_and_fixed(self):
        for key, _ in WRITE_HTTP_MODULES:
            with self.subTest(module=key):
                probe = self.run_mod(key, {"target": self.vuln.url(""), "mode": "probe-only"}, sub="probe")
                self.assertEqual(probe["findings"], [], f"{key} probe-only 不应利用")
                fixed = self.run_mod(key, {
                    "target": self.fixed.url(""),
                    "mode": "backup-write",
                    "backup_targets": [{"kind": "http", "url": self.fixed.url(""), "state": {}}],
                }, sub="fixed")
                self.assertEqual(fixed["findings"], [], f"{key} 在 fixed 模式不应命中")

    def test_readonly_http_modules(self):
        for key, cve in READONLY_HTTP_MODULES:
            with self.subTest(module=key):
                result = self.run_mod(key, {"target": self.vuln.url("")}, sub="readonly")
                self.assertGreaterEqual(len(result["findings"]), 1, key)
                self.assertIn(cve, details(result)[0].get("cves", []), key)
                fixed = self.run_mod(key, {"target": self.fixed.url("")}, sub="fixed")
                self.assertEqual(fixed["findings"], [], f"{key} 在 fixed 模式不应命中")

    def test_snapshot_modules_flag_cves_and_unsupported(self):
        for key, cve in SNAPSHOT_MODULES:
            with self.subTest(module=key):
                result = self.run_mod(key, {"snapshot": self.snapshot}, sub="snapshot")
                self.assertGreaterEqual(len(result["findings"]), 1, key)
                self.assertIn(cve, details(result)[0].get("cves", []), key)
                empty = self.run_mod(key, {}, sub="empty")
                blob = json.dumps(empty, ensure_ascii=False)
                self.assertIn("unsupported", blob, key)


if __name__ == "__main__":
    unittest.main()
