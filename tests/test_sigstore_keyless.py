# -*- coding: utf-8 -*-
"""Sigstore keyless：fixture CA/Rekor、公共日志真实样本、篡改/吊销/身份与 CLI。

网络相关断言默认离线；``TRIDENT_ONLINE=1`` 时才在线重取 Rekor 条目。
真实公共样本：reports/samples/sigstore/real-keyless-*（cosign v3.1.4 checksums，
Fulcio 公共 CA 签发，Rekor 公共日志收录）。
"""

import base64
import contextlib
import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from trident import sigstore_keyless as sk
from trident.tee.keys import CURVES, PrivateKey, pem_wrap

REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "reports" / "samples" / "sigstore"
NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
IDENTITY = "fixture@trident.local"
ISSUER = "https://fixture.trident.local"


def _key(seed: str = "unit-key") -> PrivateKey:
    d = int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big") % CURVES["P-256"].n
    return PrivateKey(kind="ec", curve="P-256", d=d or 1)


def _bundle(artifact: bytes = b"unit artifact\n") -> tuple[bytes, dict]:
    auth = sk.build_fixture_authority(now=NOW)
    bundle = sk.keyless_sign(artifact, private_key=_key(), authority=auth, now=NOW,
                             identity=IDENTITY, issuer=ISSUER)
    return artifact, bundle


def _verify(artifact: bytes, bundle: dict, **kw) -> dict:
    return sk.keyless_verify(artifact, bundle, identity=IDENTITY, issuer=ISSUER, **kw)


class TestFixtureKeyless(unittest.TestCase):
    def test_fixture_sign_verify_ok(self):
        artifact, bundle = _bundle()
        verdict = _verify(artifact, bundle)
        self.assertTrue(verdict["ok"], verdict["errors"])
        self.assertEqual(verdict["mode"], "fixture")
        names = {c["name"] for c in verdict["checks"]}
        for required in ("artifact-digest", "message-signature", "certificate-chain",
                         "identity", "issuer", "tlog-body", "tlog-set",
                         "tlog-inclusion", "tlog-checkpoint"):
            self.assertIn(required, names)
        self.assertEqual(verdict["identity"]["oidc_issuer"], ISSUER)
        self.assertEqual(verdict["identity"]["sans"][0]["value"], IDENTITY)

    def test_tampered_artifact_fails(self):
        artifact, bundle = _bundle()
        verdict = _verify(artifact + b"x", bundle)
        self.assertFalse(verdict["ok"])
        self.assertIn("artifact-digest", verdict["errors"])
        self.assertIn("message-signature", verdict["errors"])

    def test_tampered_signature_fails(self):
        artifact, bundle = _bundle()
        bad = copy.deepcopy(bundle)
        sig = bytearray(base64.b64decode(bad["messageSignature"]["signature"]))
        sig[-1] ^= 0x01
        bad["messageSignature"]["signature"] = base64.b64encode(sig).decode()
        verdict = _verify(artifact, bad)
        self.assertFalse(verdict["ok"])
        self.assertIn("message-signature", verdict["errors"])

    def test_wrong_identity_fails(self):
        artifact, bundle = _bundle()
        verdict = sk.keyless_verify(artifact, bundle, identity="attacker@example.com", issuer=ISSUER)
        self.assertFalse(verdict["ok"])
        self.assertIn("identity", verdict["errors"])

    def test_wrong_issuer_fails(self):
        artifact, bundle = _bundle()
        verdict = sk.keyless_verify(artifact, bundle, identity=IDENTITY,
                                    issuer="https://evil.example.com")
        self.assertFalse(verdict["ok"])
        self.assertIn("issuer", verdict["errors"])

    def test_identity_regex(self):
        artifact, bundle = _bundle()
        verdict = sk.keyless_verify(artifact, bundle, identity_regex=r".*@trident\.local", issuer=ISSUER)
        self.assertTrue(verdict["ok"], verdict["errors"])

    def test_revoked_serial_fails(self):
        artifact, bundle = _bundle()
        serial = _verify(artifact, bundle)["identity"]["serial"]
        verdict = _verify(artifact, bundle, revoked_serials=[serial])
        self.assertFalse(verdict["ok"])
        self.assertIn("revocation", verdict["errors"])

    def test_expired_certificate_fails(self):
        auth = sk.build_fixture_authority(now=NOW)
        key = _key("expired")
        leaf = auth.issue(key.public_key(), identity=IDENTITY, issuer=ISSUER,
                          not_before=NOW - timedelta(hours=2),
                          not_after=NOW - timedelta(hours=1))
        artifact = b"expired artifact\n"
        bundle = sk._make_bundle(artifact, key.sign(sk.ALG_ECDSA_SHA256, artifact),
                                 [leaf, auth.intermediate], auth.log_key, auth.log_id,
                                 int(NOW.timestamp()), mode="fixture",
                                 extra={"trust_bundle": auth.trust_bundle(),
                                        "rekor_public_key": pem_wrap(
                                            auth.log_key.public_key().to_spki_der(), "PUBLIC KEY")})
        verdict = _verify(artifact, bundle)
        self.assertFalse(verdict["ok"])
        self.assertIn("certificate-chain", verdict["errors"])
        self.assertIn("certificate-time", verdict["errors"])

    def test_tampered_rekor_body_fails(self):
        artifact, bundle = _bundle()
        bad = copy.deepcopy(bundle)
        entry = bad["verificationMaterial"]["tlogEntries"][0]
        body = json.loads(base64.b64decode(entry["canonicalizedBody"]))
        body["spec"]["data"]["hash"]["value"] = "00" * 32
        entry["canonicalizedBody"] = base64.b64encode(
            sk._canonical_json(body)).decode()
        verdict = _verify(artifact, bad)
        self.assertFalse(verdict["ok"])
        self.assertIn("tlog-body", verdict["errors"])
        self.assertIn("tlog-set", verdict["errors"])
        self.assertIn("tlog-inclusion", verdict["errors"])

    def test_tampered_inclusion_root_fails(self):
        artifact, bundle = _bundle()
        bad = copy.deepcopy(bundle)
        bad["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"] = "11" * 32
        verdict = _verify(artifact, bad)
        self.assertFalse(verdict["ok"])
        self.assertIn("tlog-inclusion", verdict["errors"])
        self.assertIn("tlog-checkpoint", verdict["errors"])

    def test_wrong_rekor_key_fails(self):
        artifact, bundle = _bundle()
        wrong = pem_wrap(_key("other-log").public_key().to_spki_der(), "PUBLIC KEY")
        verdict = _verify(artifact, bundle, rekor_public_key=wrong)
        self.assertFalse(verdict["ok"])
        self.assertIn("tlog-logid", verdict["errors"])
        self.assertIn("tlog-set", verdict["errors"])
        self.assertIn("tlog-checkpoint", verdict["errors"])

    def test_tampered_checkpoint_fails(self):
        artifact, bundle = _bundle()
        bad = copy.deepcopy(bundle)
        proof = bad["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
        lines = proof["checkpoint"].splitlines()
        lines[1] = "99"
        proof["checkpoint"] = "\n".join(lines) + "\n"
        verdict = _verify(artifact, bad)
        self.assertFalse(verdict["ok"])
        self.assertIn("tlog-checkpoint", verdict["errors"])

    def test_missing_tlog_fails(self):
        artifact, bundle = _bundle()
        bad = copy.deepcopy(bundle)
        bad["verificationMaterial"].pop("tlogEntries")
        verdict = _verify(artifact, bad)
        self.assertFalse(verdict["ok"])
        self.assertIn("tlog", verdict["errors"])

    def test_no_artifact_allows_digest_only(self):
        artifact, bundle = _bundle()
        verdict = sk.keyless_verify(None, bundle, identity=IDENTITY, issuer=ISSUER)
        # 无 artifact 时无法验签；digest 存在但 ok=False（诚实失败）
        self.assertFalse(verdict["ok"])
        self.assertIn("message-signature", verdict["errors"])


class TestRealSigstoreSamples(unittest.TestCase):
    def test_cached_trust_bundle_parses(self):
        tb = sk.load_trust_bundle()
        roots, intermediates = sk._trust_roots(tb)
        self.assertGreaterEqual(len(roots), 1)
        self.assertTrue(all(r.verify_self_signed() for r in roots))
        log = sk.load_rekor_log()
        self.assertGreater(int(log["treeSize"]), 1_000_000)

    def test_real_keyless_bundle_verifies_offline(self):
        artifact = (SAMPLES / "real-keyless-cosign-checksums.txt").read_bytes()
        bundle = json.loads((SAMPLES / "real-keyless-bundle.json").read_text(encoding="utf-8"))
        verdict = sk.keyless_verify(
            artifact, bundle, identity="keyless@projectsigstore.iam.gserviceaccount.com",
            issuer="https://accounts.google.com")
        self.assertTrue(verdict["ok"], verdict["errors"])
        self.assertEqual(verdict["artifact"]["sha256"],
                         "e70e59b328d52949b3a9ae3e0d04721ea8f380c4e91c28197aa91df02afbf4c0")
        self.assertEqual(verdict["identity"]["oidc_issuer"], "https://accounts.google.com")
        self.assertTrue(all(c["ok"] for c in verdict["checks"] if c["name"].startswith("tlog")))

    @unittest.skipUnless(os.environ.get("TRIDENT_ONLINE") == "1",
                         "在线 Rekor 重取需 TRIDENT_ONLINE=1")
    def test_real_keyless_bundle_online(self):
        artifact = (SAMPLES / "real-keyless-cosign-checksums.txt").read_bytes()
        bundle = json.loads((SAMPLES / "real-keyless-bundle.json").read_text(encoding="utf-8"))
        verdict = sk.keyless_verify(
            artifact, bundle, identity="keyless@projectsigstore.iam.gserviceaccount.com",
            issuer="https://accounts.google.com", online=True)
        self.assertTrue(verdict["ok"], verdict["errors"])
        check = next(c for c in verdict["checks"] if c["name"] == "tlog-online")
        self.assertIn("rekor.sigstore.dev", check["detail"])

    def test_live_rekor_key_entry_log_checks(self):
        artifact = (SAMPLES / "live-rekor-artifact.txt").read_bytes()
        bundle = json.loads((SAMPLES / "live-rekor-bundle.json").read_text(encoding="utf-8"))
        verdict = sk.keyless_verify(artifact, bundle)
        # key-based（非 keyless）：证书链检查必须失败，但真实 Rekor 日志四项必须通过
        self.assertFalse(verdict["ok"])
        self.assertIn("keyless-certificate", verdict["errors"])
        tlog = {c["name"]: c["ok"] for c in verdict["checks"] if c["name"].startswith("tlog")}
        for name in ("tlog-body", "tlog-logid", "tlog-set", "tlog-inclusion", "tlog-checkpoint"):
            self.assertTrue(tlog.get(name), (name, verdict["checks"]))
        record = json.loads((SAMPLES / "live-rekor-record.json").read_text(encoding="utf-8"))
        self.assertIn("rekor.sigstore.dev", record["url"])
        self.assertEqual(record["artifact_sha256"], verdict["artifact"]["sha256"])


class TestCLI(unittest.TestCase):
    def test_cli_sign_and_verify_roundtrip(self):
        from trident.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            art = Path(tmp) / "artifact.bin"
            bundle_path = Path(tmp) / "bundle.json"
            verdict_path = Path(tmp) / "verdict.json"
            art.write_bytes(b"cli keyless artifact\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = main(["sign-keyless", "--artifact", str(art), "--out", str(bundle_path),
                           "--offline-fixture"])
            self.assertEqual(rc, 0)
            self.assertTrue(bundle_path.is_file())
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = main(["verify-keyless", "--artifact", str(art), "--bundle", str(bundle_path),
                           "--identity", IDENTITY, "--issuer", ISSUER, "--out", str(verdict_path)])
            self.assertEqual(rc, 0)
            verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
            self.assertTrue(verdict["ok"], verdict["errors"])


if __name__ == "__main__":
    unittest.main()
