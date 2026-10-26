# -*- coding: utf-8 -*-
"""模型供应链与机密计算测试：CycloneDX ML-BOM / cosign 风格 provenance / TEE 策略断言。

全部为本地 fixture 驱动；篡改用例必须失败（哈希、来源、签名、测量值、nonce、TCB、debug）。
"""

import copy
import hashlib
import hmac
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade import supplychain

REPO = Path(__file__).resolve().parents[1]
PY = sys.executable
SECRET = "INKBLADE-FIXTURE-ONLY-model-key-2026-10"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _model(tmp: Path, name: str = "inkblade-test-model") -> dict:
    weights = tmp / "model.safetensors"
    weights.write_bytes(b"INKBLADE-FIXTURE-WEIGHTS-v1")
    return {
        "name": name,
        "version": "2026.10",
        "path": "model.safetensors",
        "source": "https://example.invalid/inkblade/models/deepseek-v3",
        "license": "Apache-2.0",
        "format": "safetensors",
        "task": "text-generation",
        "dataset": [{
            "name": "inkblade-fixture-dataset",
            "version": "2026.10",
            "source": "https://example.invalid/inkblade/datasets/fixture",
            "license": "CC-BY-4.0",
        }],
    }


def _bundle(tmp: Path) -> dict:
    weights = tmp / "model.safetensors"
    bundle = {
        "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
        "artifact": {"name": "model.safetensors", "sha256": _sha(weights.read_bytes())},
        "source": {
            "repository": "https://example.invalid/inkblade/models/deepseek-v3",
            "revision": "a" * 40,
            "ref": "refs/tags/v2026.10",
        },
        "builder": {"id": "inkblade-fixture-builder"},
        "certificate": {"issuer": "https://fixture.invalid/oidc", "subject": "model@fixture.invalid"},
        "transparency": {"logIndex": 42, "logId": "fixture-rekor", "integratedTime": 1790000000},
    }
    return supplychain.sign_bundle(bundle, SECRET, keyid="fixture-model-key-1")


def _trust_root() -> dict:
    return {
        "keys": {
            "fixture-model-key-1": {
                "alg": "HMAC-SHA256",
                "fixture_secret": SECRET,
                "issuer": "https://fixture.invalid/oidc",
                "allowed_repositories": ["https://example.invalid/inkblade/models/deepseek-v3"],
            }
        },
        "require_transparency_log": True,
    }


class TestSbom(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cyclonedx_ml_bom_shape(self):
        model = _model(self.root)
        sbom = supplychain.build_sbom([model], root=self.root)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertTrue(sbom["serialNumber"].startswith("urn:uuid:"))
        self.assertEqual(sbom["version"], 1)
        self.assertEqual(sbom["metadata"]["tools"][0]["name"], "inkblade")
        self.assertIn("component", sbom["metadata"])

        comp = next(c for c in sbom["components"]
                    if c["type"] == "machine-learning-model" and c["name"] == model["name"])
        self.assertEqual(comp["version"], "2026.10")
        self.assertEqual(comp["hashes"][0]["alg"], "SHA-256")
        self.assertEqual(comp["hashes"][0]["content"], _sha(b"INKBLADE-FIXTURE-WEIGHTS-v1"))
        self.assertEqual(comp["licenses"][0]["license"]["id"], "Apache-2.0")
        self.assertEqual(comp["externalReferences"][0]["url"], model["source"])
        self.assertEqual(comp["modelCard"]["modelParameters"]["task"], "text-generation")
        dataset_refs = [p["value"] for p in comp["properties"] if p["name"] == "inkblade:dataset"]
        self.assertEqual(len(dataset_refs), 1)

        ds = next(c for c in sbom["components"] if c["type"] == "data")
        self.assertEqual(ds["name"], "inkblade-fixture-dataset")
        self.assertEqual(ds["licenses"][0]["license"]["id"], "CC-BY-4.0")
        self.assertIn("inkblade:dataset", json.dumps(comp["properties"]))

    def test_explicit_hash_supported(self):
        model = _model(self.root)
        model.pop("path")
        model["sha256"] = _sha(b"INKBLADE-FIXTURE-WEIGHTS-v1")
        sbom = supplychain.build_sbom([model], root=self.root)
        comp = next(c for c in sbom["components"] if c["type"] == "machine-learning-model")
        self.assertEqual(comp["hashes"][0]["content"], model["sha256"])

    def test_tampered_explicit_hash_rejected(self):
        model = _model(self.root)
        model["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            supplychain.build_sbom([model], root=self.root)

    def test_missing_provenance_fields_rejected(self):
        for field in ("source", "license", "version"):
            model = _model(self.root)
            model.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                supplychain.build_sbom([model], root=self.root)
        model = _model(self.root)
        model.pop("path")
        with self.assertRaises(ValueError):
            supplychain.build_sbom([model], root=self.root)

    def test_duplicate_model_rejected(self):
        model = _model(self.root)
        with self.assertRaises(ValueError):
            supplychain.build_sbom([model, dict(model)], root=self.root)

    def test_missing_weights_file_rejected(self):
        model = _model(self.root)
        model["path"] = "nope.safetensors"
        with self.assertRaises(ValueError):
            supplychain.build_sbom([model], root=self.root)


class TestVerifyModel(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.weights = self.root / "model.safetensors"
        self.weights.write_bytes(b"INKBLADE-FIXTURE-WEIGHTS-v1")
        self.bundle = _bundle(self.root)
        self.trust = _trust_root()

    def tearDown(self):
        self.tmp.cleanup()

    def _verify(self, weights=None, bundle=None, trust=None):
        return supplychain.verify_model(weights or self.weights, bundle or self.bundle,
                                        trust or self.trust)

    def test_good_bundle(self):
        verdict = self._verify()
        self.assertTrue(verdict["ok"], verdict)
        for name in ("schema", "artifact-hash", "signature-key", "signature",
                     "certificate-issuer", "source-repository", "transparency-log"):
            check = next(c for c in verdict["checks"] if c["name"] == name)
            self.assertTrue(check["ok"], check)
        self.assertEqual(verdict["artifact"]["sha256"], _sha(self.weights.read_bytes()))

    def test_tampered_weights_fail_hash(self):
        self.weights.write_bytes(b"TAMPERED-WEIGHTS")
        verdict = self._verify()
        self.assertFalse(verdict["ok"])
        self.assertIn("artifact-hash", verdict["errors"])
        self.assertTrue(any(c["name"] == "artifact-hash" and not c["ok"] for c in verdict["checks"]))

    def test_tampered_source_fails(self):
        bundle = copy.deepcopy(self.bundle)
        bundle["source"]["repository"] = "https://evil.invalid/model"
        verdict = self._verify(bundle=bundle)
        self.assertFalse(verdict["ok"])
        self.assertIn("source-repository", verdict["errors"])

    def test_tampered_signature_fails(self):
        bundle = copy.deepcopy(self.bundle)
        sig = bundle["signature"]["value"]
        bundle["signature"]["value"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        verdict = self._verify(bundle=bundle)
        self.assertFalse(verdict["ok"])
        self.assertIn("signature", verdict["errors"])

    def test_untrusted_key_fails(self):
        bundle = copy.deepcopy(self.bundle)
        bundle["signature"]["keyid"] = "unknown-key"
        verdict = self._verify(bundle=bundle)
        self.assertFalse(verdict["ok"])
        self.assertIn("signature-key", verdict["errors"])

    def test_missing_transparency_fails(self):
        bundle = copy.deepcopy(self.bundle)
        bundle.pop("transparency")
        verdict = self._verify(bundle=bundle)
        self.assertFalse(verdict["ok"])
        self.assertIn("transparency-log", verdict["errors"])

    def test_shipped_provenance_example(self):
        data = REPO / "inkblade" / "data" / "supplychain"
        verdict = supplychain.verify_model(
            data / "artifact.example.bin",
            data / "provenance.example.json",
            data / "trust-root.example.json",
        )
        self.assertTrue(verdict["ok"], verdict)

    def test_expected_source_mismatch(self):
        verdict = supplychain.verify_model(
            self.weights, self.bundle, self.trust,
            expected_source="https://example.invalid/inkblade/models/other")
        self.assertFalse(verdict["ok"])
        self.assertIn("source-repository", verdict["errors"])


class TestAttestation(unittest.TestCase):
    def test_all_three_tees_pass_policy(self):
        policy = supplychain.load_policy()
        for tee in ("tdx", "sev-snp", "nvidia-cc"):
            doc = supplychain.load_attestation(tee)
            verdict = supplychain.verify_attestation(doc, policy)
            self.assertTrue(verdict["ok"], f"{tee}: {verdict}")
            self.assertEqual(verdict["tee"], tee)
            names = {c["name"] for c in verdict["checks"]}
            for required in ("schema", "tee-allowed", "nonce-freshness",
                             "report-data-binding", "launch-measurement",
                             "debug-disabled", "tcb-status", "signature"):
                self.assertIn(required, names, tee)
        nvidia = supplychain.verify_attestation(
            supplychain.load_attestation("nvidia-cc"), policy)
        self.assertTrue(any(c["name"] == "gpu-cc-mode" and c["ok"] for c in nvidia["checks"]))

    def test_tampered_measurement_fails(self):
        policy = supplychain.load_policy()
        doc = copy.deepcopy(supplychain.load_attestation("tdx"))
        doc["quote"]["mrtd"] = "0" * 96
        doc = supplychain.sign_attestation(doc, "fixture-tdx-root", policy["trusted_keys"]["fixture-tdx-root"])
        verdict = supplychain.verify_attestation(doc, policy)
        self.assertFalse(verdict["ok"])
        self.assertIn("launch-measurement", verdict["errors"])

    def test_tampered_nonce_fails(self):
        policy = supplychain.load_policy()
        doc = copy.deepcopy(supplychain.load_attestation("sev-snp"))
        doc["nonce"] = "replayed-nonce"
        doc = supplychain.sign_attestation(
            doc, "fixture-snp-root", policy["trusted_keys"]["fixture-snp-root"])
        verdict = supplychain.verify_attestation(doc, policy)
        self.assertFalse(verdict["ok"])
        self.assertIn("nonce-freshness", verdict["errors"])

    def test_tampered_report_data_fails(self):
        policy = supplychain.load_policy()
        doc = copy.deepcopy(supplychain.load_attestation("nvidia-cc"))
        doc["report_data"] = "f" * 64
        doc = supplychain.sign_attestation(
            doc, "fixture-nvidia-root", policy["trusted_keys"]["fixture-nvidia-root"])
        verdict = supplychain.verify_attestation(doc, policy)
        self.assertFalse(verdict["ok"])
        self.assertIn("report-data-binding", verdict["errors"])

    def test_debug_enabled_fails(self):
        policy = supplychain.load_policy()
        doc = copy.deepcopy(supplychain.load_attestation("tdx"))
        doc["quote"]["debug"] = True
        doc = supplychain.sign_attestation(
            doc, "fixture-tdx-root", policy["trusted_keys"]["fixture-tdx-root"])
        verdict = supplychain.verify_attestation(doc, policy)
        self.assertFalse(verdict["ok"])
        self.assertIn("debug-disabled", verdict["errors"])

    def test_bad_tcb_fails(self):
        policy = supplychain.load_policy()
        doc = copy.deepcopy(supplychain.load_attestation("sev-snp"))
        doc["quote"]["tcb"]["status"] = "OutOfDate"
        doc = supplychain.sign_attestation(
            doc, "fixture-snp-root", policy["trusted_keys"]["fixture-snp-root"])
        verdict = supplychain.verify_attestation(doc, policy)
        self.assertFalse(verdict["ok"])
        self.assertIn("tcb-status", verdict["errors"])

    def test_tampered_signature_fails(self):
        policy = supplychain.load_policy()
        doc = copy.deepcopy(supplychain.load_attestation("tdx"))
        doc["signature"]["value"] = "0" * 64
        verdict = supplychain.verify_attestation(doc, policy)
        self.assertFalse(verdict["ok"])
        self.assertIn("signature", verdict["errors"])

    def test_tee_not_allowed(self):
        policy = supplychain.load_policy()
        policy = dict(policy, allowed_tees=["tdx"])
        verdict = supplychain.verify_attestation(supplychain.load_attestation("nvidia-cc"), policy)
        self.assertFalse(verdict["ok"])
        self.assertIn("tee-allowed", verdict["errors"])

    def test_unknown_tee_rejected(self):
        with self.assertRaises(ValueError):
            supplychain.load_attestation("sgx-mock")
        policy = supplychain.load_policy()
        doc = supplychain.load_attestation("tdx")
        verdict = supplychain.verify_attestation(dict(doc, tee="unknown-tee"), policy)
        self.assertFalse(verdict["ok"])
        self.assertIn("schema", verdict["errors"])


class TestSupplyChainCli(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.weights = self.root / "model.safetensors"
        self.weights.write_bytes(b"INKBLADE-FIXTURE-WEIGHTS-v1")
        self.models_file = self.root / "models.json"
        self.models_file.write_text(json.dumps([_model(self.root)], ensure_ascii=False),
                                    encoding="utf-8")
        self.bundle_file = self.root / "bundle.json"
        self.bundle_file.write_text(json.dumps(_bundle(self.root), ensure_ascii=False),
                                    encoding="utf-8")
        self.trust_file = self.root / "trust.json"
        self.trust_file.write_text(json.dumps(_trust_root()), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run([PY, "-m", "inkblade", *args], cwd=str(REPO),
                              capture_output=True, timeout=60, env=env)

    def test_cli_sbom(self):
        out = self.root / "sbom.json"
        r = self._run("sbom", "--models", str(self.models_file), "--root", str(self.root),
                      "--out", str(out))
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        sbom = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertTrue(any(c["type"] == "machine-learning-model" for c in sbom["components"]))

    def test_cli_verify_model_good_and_tampered(self):
        args = ("verify-model", "--weights", str(self.weights),
                "--bundle", str(self.bundle_file), "--trust-root", str(self.trust_file))
        good = self._run(*args)
        self.assertEqual(good.returncode, 0, good.stderr.decode("utf-8", "replace"))
        verdict = json.loads(good.stdout.decode("utf-8"))
        self.assertTrue(verdict["ok"])

        self.weights.write_bytes(b"TAMPERED")
        bad = self._run(*args)
        self.assertEqual(bad.returncode, 2)
        verdict = json.loads(bad.stdout.decode("utf-8"))
        self.assertFalse(verdict["ok"])
        self.assertIn("artifact-hash", verdict["errors"])

    def test_cli_attest(self):
        policy = self.root / "policy.json"
        policy.write_text(json.dumps(supplychain.load_policy(), ensure_ascii=False),
                          encoding="utf-8")
        doc = self.root / "tdx.json"
        doc.write_text(json.dumps(supplychain.load_attestation("tdx"), ensure_ascii=False),
                       encoding="utf-8")
        r = self._run("attest", "--evidence", str(doc), "--policy", str(policy))
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        self.assertTrue(json.loads(r.stdout.decode("utf-8"))["ok"])

        tampered = copy.deepcopy(supplychain.load_attestation("tdx"))
        tampered["quote"]["mrtd"] = "0" * 96
        doc.write_text(json.dumps(tampered, ensure_ascii=False), encoding="utf-8")
        r = self._run("attest", "--evidence", str(doc), "--policy", str(policy))
        self.assertEqual(r.returncode, 2)
        self.assertFalse(json.loads(r.stdout.decode("utf-8"))["ok"])


if __name__ == "__main__":
    unittest.main()
