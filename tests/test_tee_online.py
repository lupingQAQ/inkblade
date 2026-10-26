# -*- coding: utf-8 -*-
"""TEE 厂商公共证书链在线校验：Intel PCS / AMD KDS / NVIDIA NRAS。

默认离线：对 2026-10-25 抓取的官方样本复验；fixture 仅用于覆盖吊销/篡改/ES384
等真实样本无法安全制造的负例。网络抓取测试通过 fake HTTP 注入，不依赖外网。
"""

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from inkblade.tee import online
from inkblade.tee.fixtures import nvidia_fixture
from inkblade.tee.keys import (ALG_ECDSA_SHA256, ALG_ECDSA_SHA384, CURVES, PrivateKey,
                              b64url_encode)
from inkblade.tee.x509 import build_certificate, parse_certificate

NOW = datetime(2026, 10, 25, 16, 0, 0, tzinfo=timezone.utc)
REPO = Path(__file__).resolve().parents[1]
CACHE = REPO / "inkblade" / "tee" / "online_cache"


def _fixture_intel(status: str = "Revoked") -> online.IntelTcbInfo:
    # 独立 fixture 链，避免复用 TDX quote fixture 的私有状态
    root_key = PrivateKey(kind="ec", curve="P-256",
                          d=int.from_bytes(b"intel-fixture-root", "big") % CURVES["P-256"].n)
    signer_key = PrivateKey(kind="ec", curve="P-256",
                            d=int.from_bytes(b"intel-fixture-signer", "big") % CURVES["P-256"].n)
    root = build_certificate(subject="InkBlade Fixture Intel Root", issuer="InkBlade Fixture Intel Root",
                             public_key=root_key.public_key(), signer=root_key.sign,
                             serial=1, not_before=NOW - timedelta(days=1),
                             not_after=NOW + timedelta(days=365), is_ca=True)
    signer = build_certificate(subject="InkBlade Fixture Intel TCB Signing",
                               issuer="InkBlade Fixture Intel Root",
                               public_key=signer_key.public_key(), signer=root_key.sign,
                               serial=2, not_before=NOW - timedelta(days=1),
                               not_after=NOW + timedelta(days=365), is_ca=False)
    tcb = {
        "id": "TDX", "version": 3,
        "issueDate": "2026-10-25T00:00:00Z",
        "nextUpdate": "2026-11-25T00:00:00Z",
        "fmspc": "90c06f000000", "pceId": "0000", "tcbType": 0,
        "tcbLevels": [{
            "tcb": {"sgxtcbcomponents": [{"svn": 3}] * 16,
                    "tdxtcbcomponents": [{"svn": 3}] * 16, "pcesvn": 13},
            "tcbStatus": status,
        }],
    }
    payload = json.dumps(tcb, ensure_ascii=False, separators=(",", ":")).encode()
    doc = {"tcbInfo": tcb, "signature": signer_key.sign(ALG_ECDSA_SHA256, payload).hex()}
    return online.IntelTcbInfo(fmspc="90c06f000000", doc=doc, chain=[signer, root],
                               headers={}, url="fixture://intel", source="fixture")


def _jwt_es384(key: PrivateKey, claims: dict, kid: str = "fixture-es384") -> str:
    header = {"alg": "ES384", "typ": "JWT", "kid": kid}
    signing = (b64url_encode(json.dumps(header, separators=(",", ":")).encode()) + "." +
               b64url_encode(json.dumps(claims, separators=(",", ":")).encode()))
    sig = key.sign(ALG_ECDSA_SHA384, signing.encode(), raw=True)
    return signing + "." + b64url_encode(sig)


def _es384_jwks(key: PrivateKey, kid: str = "fixture-es384") -> dict:
    pub = key.public_key()
    return {"keys": [{"kty": "EC", "crv": "P-384", "kid": kid,
                      "x": b64url_encode(pub.x.to_bytes(48, "big")),
                      "y": b64url_encode(pub.y.to_bytes(48, "big"))}]}


def _claims(**over) -> dict:
    now = int(NOW.timestamp())
    base = {"iss": "https://nras.attestation.nvidia.com", "aud": "nras",
            "iat": now - 10, "nbf": now - 10, "exp": now + 3600,
            "eat_nonce": "fixture-nonce-0001", "x-nvidia-ver": "2.0",
            "x-nvidia-overall-att-result": True, "dbgstat": "disabled", "secboot": True}
    base.update(over)
    return base


class TestIntelPCS(unittest.TestCase):
    def test_cached_official_tcb_verifies(self):
        info = online.cached_intel_tcb()
        verdict = online.verify_intel_tcb(info, now=NOW)
        self.assertTrue(verdict.ok, verdict.errors)
        self.assertEqual(info.fmspc, "90c06f000000")
        names = {c["name"] for c in verdict.checks}
        self.assertIn("tcb-signature", names)
        self.assertIn("certificate-chain", names)

    def test_tampered_tcb_info_fails_signature(self):
        info = online.cached_intel_tcb()
        doc = copy.deepcopy(info.doc)
        doc["tcbInfo"]["tcbEvaluationDataNumber"] += 1
        bad = online.IntelTcbInfo(info.fmspc, doc, info.chain, info.headers, info.url)
        verdict = online.verify_intel_tcb(bad, now=NOW)
        self.assertFalse(verdict.ok)
        self.assertIn("tcb-signature", verdict.errors)

    def test_expired_tcb_window_fails(self):
        info = online.cached_intel_tcb()
        verdict = online.verify_intel_tcb(info, now=datetime(2027, 1, 1, tzinfo=timezone.utc))
        self.assertFalse(verdict.ok)
        self.assertIn("validity-window", verdict.errors)

    def test_fmspc_mismatch_fails(self):
        info = online.cached_intel_tcb()
        verdict = online.verify_intel_tcb(info, now=NOW, fmspc="000000000000")
        self.assertFalse(verdict.ok)
        self.assertIn("fmspc", verdict.errors)

    def test_out_of_date_level_is_rejected(self):
        info = online.cached_intel_tcb()
        # 真实 TCB levels 中含 OutOfDate；构造与其完全匹配的组件
        out = next(x for x in info.doc["tcbInfo"]["tcbLevels"] if x["tcbStatus"] == "OutOfDate")
        components = {
            "sgxtcbcomponents": [c["svn"] for c in out["tcb"]["sgxtcbcomponents"]],
            "tdxtcbcomponents": [c["svn"] for c in out["tcb"]["tdxtcbcomponents"]],
            "pcesvn": out["tcb"]["pcesvn"],
        }
        verdict = online.verify_intel_tcb(info, now=NOW, components=components)
        self.assertFalse(verdict.ok)
        self.assertIn("tcb-up-to-date", verdict.errors)

    def test_revoked_level_fixture_is_rejected(self):
        info = _fixture_intel("Revoked")
        components = {"sgxtcbcomponents": [3] * 16, "tdxtcbcomponents": [3] * 16, "pcesvn": 13}
        verdict = online.verify_intel_tcb(info, now=NOW, components=components)
        self.assertFalse(verdict.ok)
        self.assertIn("tcb-not-revoked", verdict.errors)
        allowed = online.verify_intel_tcb(info, now=NOW, components=components,
                                          allow_revoked=True)
        self.assertTrue(allowed.ok, allowed.errors)

    def test_tampered_chain_fails(self):
        info = online.cached_intel_tcb()
        bad_chain = list(info.chain)
        bad_chain[0] = parse_certificate(info.chain[0].der[:-1] + bytes([info.chain[0].der[-1] ^ 1]))
        bad = online.IntelTcbInfo(info.fmspc, info.doc, bad_chain, info.headers, info.url)
        verdict = online.verify_intel_tcb(bad, now=NOW)
        self.assertFalse(verdict.ok)
        self.assertIn("certificate-chain", verdict.errors)

    def test_fetch_with_fake_http_caches(self):
        body = (CACHE / "intel_tdx_tcb_90c06f000000.json").read_bytes()
        headers = json.loads((CACHE / "intel_tdx_tcb_90c06f000000.headers.json").read_text())

        def fake_http(url, hdrs, timeout):
            self.assertIn("fmspc=90c06f000000", url)
            return 200, headers, body

        with tempfile.TemporaryDirectory() as tmp:
            info = online.fetch_intel_tcb("90c06f000000", http=fake_http, cache_dir=Path(tmp))
            self.assertEqual(info.source, "live")
            self.assertTrue((Path(tmp) / "intel_tdx_tcb_90c06f000000.json").is_file())
            self.assertTrue(online.verify_intel_tcb(info, now=NOW).ok)


class TestAmdKDS(unittest.TestCase):
    def test_cached_amd_chain_vcek_crl(self):
        amd = online.cached_amd()
        verdict = online.verify_amd_vcek(amd["vcek"], amd["chain"], amd["crl"], now=NOW)
        self.assertTrue(verdict.ok, verdict.errors)
        self.assertFalse(verdict.revoked)
        self.assertGreaterEqual(len(amd["crl"].serials), 1)
        self.assertTrue(amd["crl"].signature_valid)

    def test_real_crl_revoked_serial(self):
        amd = online.cached_amd()
        revoked = amd["crl"].serials[0]
        self.assertEqual(amd["crl"].is_revoked(revoked, now=NOW), (True, "serial 在 CRL 中"))
        self.assertEqual(amd["crl"].is_revoked(123456789, now=NOW), (False, "serial 未吊销"))

    def test_tampered_vcek_fails_chain(self):
        amd = online.cached_amd()
        der = bytearray(amd["vcek"].der)
        der[-1] ^= 0x01
        bad = parse_certificate(bytes(der))
        verdict = online.verify_amd_vcek(bad, amd["chain"], amd["crl"], now=NOW)
        self.assertFalse(verdict.ok)
        self.assertIn("vcek-chain", verdict.errors)

    def test_tampered_crl_signature_fails(self):
        amd = online.cached_amd()
        raw = bytearray(amd["crl"].raw)
        raw[-1] ^= 0x01
        crl = online.parse_crl(bytes(raw), issuer=amd["chain"][-1])
        self.assertFalse(crl.signature_valid)
        verdict = online.verify_amd_vcek(amd["vcek"], amd["chain"], crl, now=NOW)
        self.assertFalse(verdict.ok)
        self.assertIn("crl-signature", verdict.errors)

    def test_stale_crl_fails_closed(self):
        amd = online.cached_amd()
        verdict = online.verify_amd_vcek(amd["vcek"], amd["chain"], amd["crl"],
                                         now=datetime(2027, 1, 1, tzinfo=timezone.utc))
        self.assertFalse(verdict.ok)
        self.assertIn("crl-fresh", verdict.errors)
        self.assertIn("vcek-not-revoked", verdict.errors)

    def test_crl_parsed_metadata(self):
        amd = online.cached_amd()
        crl = amd["crl"]
        self.assertIsNotNone(crl.this_update)
        self.assertIsNotNone(crl.next_update)
        self.assertGreater(crl.next_update, crl.this_update)


class TestNvidiaNRAS(unittest.TestCase):
    def test_cached_official_jwks_structure(self):
        jwks = online.cached_nvidia_jwks()
        ok, checks, errors = online.verify_nvidia_jwks(jwks)
        self.assertTrue(ok, errors)
        self.assertGreaterEqual(len(jwks["keys"]), 100)
        self.assertTrue(all(c["ok"] for c in checks))

    def test_fixture_rs256_jwt(self):
        fx = nvidia_fixture(nonce="fixture-nonce-0001", now=NOW)
        verdict = online.verify_nvidia_jwt(fx.token, fx.jwks, expected_nonce="fixture-nonce-0001",
                                           now=NOW.timestamp())
        self.assertTrue(verdict.ok, verdict.errors)

    def test_fixture_rs256_tampered(self):
        fx = nvidia_fixture(nonce="fixture-nonce-0001", now=NOW)
        token = fx.token[:-4] + ("AAAA" if not fx.token.endswith("AAAA") else "BBBB")
        verdict = online.verify_nvidia_jwt(token, fx.jwks, expected_nonce="fixture-nonce-0001",
                                           now=NOW.timestamp())
        self.assertFalse(verdict.ok)
        self.assertIn("jwt-signature", verdict.errors)

    def test_fixture_rs256_expired(self):
        fx = nvidia_fixture(nonce="fixture-nonce-0001", exp_offset=-10, now=NOW)
        verdict = online.verify_nvidia_jwt(fx.token, fx.jwks, expected_nonce="fixture-nonce-0001",
                                           now=NOW.timestamp())
        self.assertFalse(verdict.ok)
        self.assertIn("jwt-claims", verdict.errors)

    def test_es384_jwt_matches_real_jwks_shape(self):
        key = PrivateKey(kind="ec", curve="P-384",
                         d=int.from_bytes(b"nras-es384-fixture", "big") % CURVES["P-384"].n)
        jwks = _es384_jwks(key)
        token = _jwt_es384(key, _claims())
        verdict = online.verify_nvidia_jwt(token, jwks, expected_nonce="fixture-nonce-0001",
                                           now=NOW.timestamp())
        self.assertTrue(verdict.ok, verdict.errors)
        tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        self.assertFalse(online.verify_nvidia_jwt(
            tampered, jwks, expected_nonce="fixture-nonce-0001",
            now=NOW.timestamp()).ok)

    def test_real_jwks_can_parse_ec_keys(self):
        jwks = online.cached_nvidia_jwks()
        from inkblade.tee.keys import PublicKey
        ec = [k for k in jwks["keys"] if k.get("kty") == "EC"]
        self.assertTrue(ec)
        pub = PublicKey.from_jwk(ec[0])
        self.assertEqual(pub.curve, "P-384")


class TestAggregate(unittest.TestCase):
    def test_verify_all_cached(self):
        out = online.verify_all_cached(now=NOW)
        self.assertTrue(out["ok"], out)
        for name in ("intel", "amd", "nvidia"):
            self.assertTrue(out[name]["ok"], (name, out[name]))
        self.assertEqual(out["source"].split("(")[0].strip(), "online_cache")


if __name__ == "__main__":
    unittest.main()
