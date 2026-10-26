"""tests/test_tee.py — 硬件 TEE 证明的本地密码学验证（TDX / SEV-SNP / NVIDIA CC）。

覆盖三层：
1. 密码学底座：P-256/P-384 ECDSA、RSA-2048 PKCS#1 v1.5、X.509 链、DER 严格性；
2. 三类证明对象：合法样本通过 + 篡改任一字段/签名失败 + 过期/claims 不符失败；
3. 边界：fixture 是自签样本（`inkblade/tee/fixtures.py`），测试只证明「解析与验签逻辑」，
   不证明硬件真实性——文档边界由 docs/TEE-VERIFICATION.md 锁定。
"""
import unittest
from datetime import datetime, timedelta, timezone

from inkblade.tee import fixtures, nvidia_cc, sev_snp, tdx
from inkblade.tee._asn1 import DerError, read_tlv
from inkblade.tee.keys import (ALG_ECDSA_SHA256, ALG_ECDSA_SHA384, ALG_RSA_SHA256, CURVES,
                              PrivateKey, PublicKey, der_sig_to_rs, rs_to_der_sig)
from inkblade.tee.x509 import build_certificate, verify_chain

NOW = fixtures.FIXTURE_NOW


class CryptoPrimitiveTest(unittest.TestCase):
    def test_ecdsa_p256(self):
        key = PrivateKey(kind="ec", curve="P-256", d=0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF)
        msg = b"inkblade-tee-p256"
        sig = key.sign(ALG_ECDSA_SHA256, msg)
        self.assertTrue(key.public_key().verify(ALG_ECDSA_SHA256, msg, sig))
        self.assertFalse(key.public_key().verify(ALG_ECDSA_SHA256, msg + b"!", sig))
        r, s = der_sig_to_rs(sig)
        self.assertEqual(rs_to_der_sig(r, s), sig)

    def test_ecdsa_p384(self):
        key = PrivateKey(kind="ec", curve="P-384", d=2 ** 200 + 12345)
        msg = b"inkblade-tee-p384"
        raw = key.sign(ALG_ECDSA_SHA384, msg, raw=True)
        self.assertEqual(len(raw), 96)
        self.assertTrue(key.public_key().verify(ALG_ECDSA_SHA384, msg, raw))
        self.assertFalse(key.public_key().verify(ALG_ECDSA_SHA384, msg, raw[:-1] + bytes([raw[-1] ^ 1])))

    def test_rsa_pkcs1_and_jwk(self):
        pki = fixtures.fixture_pki()
        key = pki.nras_key
        msg = b"inkblade-tee-rs256"
        sig = key.sign(ALG_RSA_SHA256, msg)
        self.assertEqual(len(sig), (key.n.bit_length() + 7) // 8)
        self.assertTrue(key.public_key().verify(ALG_RSA_SHA256, msg, sig))
        self.assertFalse(key.public_key().verify(ALG_RSA_SHA256, msg + b"!", sig))
        jwk = key.public_key().to_jwk(pki.nras_kid)
        self.assertEqual(PublicKey.from_jwk(jwk).n, key.n)
        self.assertTrue(PublicKey.from_jwk(jwk).verify(ALG_RSA_SHA256, msg, sig))

    def test_x509_chain(self):
        root_key = PrivateKey(kind="ec", curve="P-256", d=0xA1)
        inter_key = PrivateKey(kind="ec", curve="P-256", d=0xA2)
        leaf_key = PrivateKey(kind="ec", curve="P-256", d=0xA3)
        root = build_certificate(subject="T Root", issuer="T Root", public_key=root_key.public_key(),
                                 signer=root_key.sign, serial=1, not_before=NOW - timedelta(days=1),
                                 not_after=NOW + timedelta(days=10), is_ca=True)
        inter = build_certificate(subject="T Inter", issuer="T Root", public_key=inter_key.public_key(),
                                  signer=root_key.sign, serial=2, not_before=NOW - timedelta(days=1),
                                  not_after=NOW + timedelta(days=10), is_ca=True)
        leaf = build_certificate(subject="T Leaf", issuer="T Inter", public_key=leaf_key.public_key(),
                                 signer=inter_key.sign, serial=3, not_before=NOW - timedelta(days=1),
                                 not_after=NOW + timedelta(days=10))
        self.assertTrue(root.verify_self_signed())
        self.assertEqual(verify_chain([leaf, inter], root, now=NOW), [])
        self.assertTrue(verify_chain([leaf], root, now=NOW), "缺中间证书必须报错")
        # 叶子证书当签发者 → CA 位校验失败
        self.assertTrue(any("不是 CA" in e for e in verify_chain([leaf], leaf, now=NOW)))

    def test_der_rejects_malformed(self):
        with self.assertRaises(DerError):
            read_tlv(b"\x30\x80\x00\x00")          # BER 不定长
        with self.assertRaises(DerError):
            read_tlv(b"\x30\x05\x01")              # 值越界
        with self.assertRaises(DerError):
            read_tlv(b"\x30\x81\x05" + b"\x00" * 5)  # 非最短长度


class TdxQuoteTest(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.tdx_fixture(report_data=b"nonce-tdx-0001")
        self.quote = self.fx.quote
        self.pki = self.fx.pki

    def verify(self, quote, **kwargs):
        kwargs.setdefault("ak_chain", quote.cert_chain)
        kwargs.setdefault("trust_root", self.pki.tdx_root)
        kwargs.setdefault("expected_report_data", b"nonce-tdx-0001")
        kwargs.setdefault("mr_td_allowlist", [self.fx.mr_td])
        return tdx.verify_quote(quote, **kwargs)

    def test_parse_fields(self):
        q = self.quote
        self.assertEqual(q.version, 4)
        self.assertEqual(q.tee_type, tdx.TDX_TEE_TYPE)
        self.assertEqual(len(q.signed_data), 696)
        self.assertEqual(len(q.mr_td), 48)
        self.assertEqual(len(q.report_data), 64)
        self.assertEqual(len(q.cert_chain), 2)
        self.assertFalse(q.debug_enabled)
        self.assertEqual(q.mr_td, self.fx.mr_td)

    def test_valid_quote_passes(self):
        result = self.verify(self.quote)
        self.assertTrue(result.ok, result.errors)
        self.assertTrue(result.signature_valid)
        self.assertTrue(result.chain_valid)
        self.assertTrue(result.policy_valid)
        self.assertIn("通过", result.summary)

    def test_tampered_body_fails_signature(self):
        raw = bytearray(self.fx.raw)
        raw[136] ^= 0x01  # mr_td 首字节
        result = self.verify(tdx.parse_quote(bytes(raw)))
        self.assertFalse(result.ok)
        self.assertFalse(result.signature_valid)
        self.assertTrue(any("签名" in e for e in result.errors))

    def test_tampered_signature_fails(self):
        raw = bytearray(self.fx.raw)
        sig_offset = 696 + 4
        raw[sig_offset] ^= 0x01
        result = self.verify(tdx.parse_quote(bytes(raw)))
        self.assertFalse(result.signature_valid)

    def test_report_data_mismatch(self):
        result = self.verify(self.quote, expected_report_data=b"other-nonce")
        self.assertFalse(result.ok)
        self.assertFalse(result.policy_valid)
        self.assertTrue(any("report_data" in e for e in result.errors))

    def test_debug_bit_rejected(self):
        fx = fixtures.tdx_fixture(report_data=b"nonce-tdx-0001", debug=True)
        result = tdx.verify_quote(fx.quote, ak_chain=fx.quote.cert_chain,
                                  trust_root=self.pki.tdx_root)
        self.assertFalse(result.ok)
        self.assertTrue(any("DEBUG" in e for e in result.errors))

    def test_measurement_not_allowlisted(self):
        result = self.verify(self.quote, mr_td_allowlist=[b"\x00" * 48])
        self.assertFalse(result.ok)
        self.assertTrue(any("mr_td" in e for e in result.errors))

    def test_tcb_downgrade(self):
        result = self.verify(self.quote, min_tcb_svn=bytes([9, 9, 9, 9]))
        self.assertFalse(result.ok)
        self.assertTrue(any("TCB" in e or "tcb" in e for e in result.errors))

    def test_wrong_root_fails_chain(self):
        other_key = PrivateKey(kind="ec", curve="P-256", d=0xBEEF)
        other_root = build_certificate(subject="InkBlade Fixture TDX Root CA",
                                       issuer="InkBlade Fixture TDX Root CA",
                                       public_key=other_key.public_key(), signer=other_key.sign,
                                       serial=0x9001, not_before=NOW - timedelta(days=1),
                                       not_after=NOW + timedelta(days=10), is_ca=True)
        result = self.verify(self.quote, trust_root=other_root)
        self.assertFalse(result.ok)
        self.assertFalse(result.chain_valid)

    def test_ak_cert_public_key_mismatch(self):
        """把链里的 AK 换成另一把公钥（同 issuer）→ AK 与 quote 内公钥不一致。"""
        pki = self.pki
        inter_key = fixtures._key("P-256", "inkblade-fixture-tdx-intermediate")
        other_ak = PrivateKey(kind="ec", curve="P-256", d=0xCAFE)
        fake_ak = build_certificate(subject="InkBlade Fixture TDX AK",
                                    issuer="InkBlade Fixture TDX Intermediate",
                                    public_key=other_ak.public_key(), signer=inter_key.sign,
                                    serial=0x9999, not_before=NOW - timedelta(days=1),
                                    not_after=NOW + timedelta(days=10))
        result = self.verify(self.quote, ak_chain=[fake_ak, pki.tdx_intermediate])
        self.assertFalse(result.ok)
        self.assertTrue(any("不一致" in e for e in result.errors))

    def test_expired_ak_certificate(self):
        pki = self.pki
        ak_pub = self.quote.attestation_key
        inter_key = fixtures._key("P-256", "inkblade-fixture-tdx-intermediate")
        expired = build_certificate(subject="InkBlade Fixture TDX AK",
                                    issuer="InkBlade Fixture TDX Intermediate",
                                    public_key=ak_pub, signer=inter_key.sign, serial=0x9998,
                                    not_before=NOW - timedelta(days=30),
                                    not_after=NOW - timedelta(days=1))
        result = self.verify(self.quote, ak_chain=[expired, pki.tdx_intermediate])
        self.assertFalse(result.ok)
        self.assertFalse(result.chain_valid)
        self.assertTrue(any("有效期" in e for e in result.errors))

    def test_truncated_quote_rejected(self):
        with self.assertRaises(tdx.TeeQuoteError):
            tdx.parse_quote(self.fx.raw[:100])
        bad_version = bytearray(self.fx.raw)
        bad_version[0] = 9
        with self.assertRaises(tdx.TeeQuoteError):
            tdx.parse_quote(bytes(bad_version))


class SnpReportTest(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.snp_fixture(report_data=b"nonce-snp-0001")
        self.report = self.fx.report
        self.pki = self.fx.pki

    def verify(self, report, **kwargs):
        kwargs.setdefault("vcek_chain", self.pki.vcek_chain)
        kwargs.setdefault("trust_root", self.pki.amd_root)
        kwargs.setdefault("expected_report_data", b"nonce-snp-0001")
        kwargs.setdefault("measurement_allowlist", [self.fx.measurement])
        return sev_snp.verify_report(report, **kwargs)

    def test_parse_fields(self):
        r = self.report
        self.assertEqual(len(r.raw), sev_snp.SNP_REPORT_LEN)
        self.assertEqual(len(r.signed_bytes), 672)
        self.assertEqual(r.version, 3)
        self.assertEqual(len(r.measurement), 48)
        self.assertEqual(r.signature_algo, sev_snp.SNP_SIGNATURE_ALGO_ECDSA_P384)
        self.assertFalse(r.debug_enabled)

    def test_valid_report_passes(self):
        result = self.verify(self.report)
        self.assertTrue(result.ok, result.errors)
        self.assertTrue(result.signature_valid)
        self.assertTrue(result.chain_valid)

    def test_tampered_report_fails(self):
        raw = bytearray(self.fx.raw)
        raw[150] ^= 0x01  # measurement 内部
        result = self.verify(sev_snp.parse_report(bytes(raw)),
                             measurement_allowlist=[sev_snp.parse_report(bytes(raw)).measurement])
        self.assertFalse(result.ok)
        self.assertFalse(result.signature_valid)

    def test_tampered_signature_fails(self):
        raw = bytearray(self.fx.raw)
        raw[672] ^= 0x01
        result = self.verify(sev_snp.parse_report(bytes(raw)))
        self.assertFalse(result.signature_valid)

    def test_nonce_mismatch(self):
        result = self.verify(self.report, expected_report_data=b"nope")
        self.assertFalse(result.ok)
        self.assertTrue(any("report_data" in e for e in result.errors))

    def test_debug_policy_rejected(self):
        fx = fixtures.snp_fixture(report_data=b"nonce-snp-0001", debug=True)
        result = self.verify(fx.report)
        self.assertFalse(result.ok)
        self.assertTrue(any("DEBUG" in e for e in result.errors))

    def test_measurement_allowlist(self):
        result = self.verify(self.report, measurement_allowlist=[b"\x00" * 48])
        self.assertFalse(result.ok)
        self.assertTrue(any("measurement" in e for e in result.errors))

    def test_tcb_floor(self):
        result = self.verify(self.report, min_tcb=0xFFFFFFFFFFFFFFFF)
        self.assertFalse(result.ok)
        self.assertTrue(any("tcb" in e.lower() for e in result.errors))

    def test_wrong_root(self):
        other = PrivateKey(kind="ec", curve="P-384", d=0xDEADBEEF)
        root = build_certificate(subject="InkBlade Fixture AMD ARK", issuer="InkBlade Fixture AMD ARK",
                                 public_key=other.public_key(), signer=other.sign, serial=0x8001,
                                 not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=10),
                                 is_ca=True)
        result = self.verify(self.report, trust_root=root)
        self.assertFalse(result.ok)
        self.assertFalse(result.chain_valid)

    def test_missing_vcek(self):
        result = sev_snp.verify_report(self.report, vcek_chain=None, trust_root=None)
        self.assertFalse(result.ok)
        self.assertTrue(any("VCEK" in e for e in result.errors))

    def test_malformed_reports(self):
        with self.assertRaises(sev_snp.SnpReportError):
            sev_snp.parse_report(b"\x00" * 100)
        bad = bytearray(self.fx.raw)
        bad[0] = 7
        with self.assertRaises(sev_snp.SnpReportError):
            sev_snp.parse_report(bytes(bad))


class NvidiaJwtTest(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.nvidia_fixture(nonce="nonce-gpu-0001")

    def verify(self, token, **kwargs):
        kwargs.setdefault("expected_nonce", "nonce-gpu-0001")
        return nvidia_cc.verify_jwt(token, self.fx.jwks, **kwargs)

    def test_valid_jwt_passes(self):
        result = self.verify(self.fx.token)
        self.assertTrue(result.ok, result.errors)
        self.assertTrue(result.signature_valid)
        self.assertTrue(result.claims_valid)
        self.assertEqual(result.jwt.claims["x-nvidia-gpu-name"], "H100")

    def test_tampered_payload_fails(self):
        head, payload, sig = self.fx.token.split(".")
        import base64
        import json

        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["x-nvidia-gpu-name"] = "A100"
        forged = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":"), sort_keys=True)
                                          .encode()).rstrip(b"=").decode()
        result = self.verify(f"{head}.{forged}.{sig}")
        self.assertFalse(result.ok)
        self.assertFalse(result.signature_valid)

    def test_signature_replaced_fails(self):
        head, payload, sig = self.fx.token.split(".")
        flipped = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
        result = self.verify(f"{head}.{payload}.{flipped}")
        self.assertFalse(result.ok)
        self.assertFalse(result.signature_valid)

    def test_expired_fails(self):
        now = datetime.now(timezone.utc)
        fx = fixtures.nvidia_fixture(nonce="nonce-gpu-0001", exp_offset=-10, now=now)
        result = nvidia_cc.verify_jwt(fx.token, fx.jwks, expected_nonce="nonce-gpu-0001",
                                      now=now.timestamp() + 60)
        self.assertFalse(result.ok)
        self.assertTrue(any("过期" in e for e in result.errors))

    def test_not_yet_valid_fails(self):
        now = datetime.now(timezone.utc)
        fx = fixtures.nvidia_fixture(nonce="nonce-gpu-0001", now=now + timedelta(hours=1))
        result = nvidia_cc.verify_jwt(fx.token, fx.jwks, expected_nonce="nonce-gpu-0001",
                                      now=now.timestamp())
        self.assertFalse(result.ok)
        self.assertTrue(any("尚未生效" in e for e in result.errors))

    def test_nonce_mismatch(self):
        result = self.verify(self.fx.token, expected_nonce="other")
        self.assertFalse(result.ok)
        self.assertTrue(any("eat_nonce" in e for e in result.errors))

    def test_debug_state_rejected(self):
        fx = fixtures.nvidia_fixture(nonce="nonce-gpu-0001", dbgstat="enabled")
        result = nvidia_cc.verify_jwt(fx.token, fx.jwks, expected_nonce="nonce-gpu-0001")
        self.assertFalse(result.ok)
        self.assertTrue(any("dbgstat" in e for e in result.errors))

    def test_overall_result_false(self):
        fx = fixtures.nvidia_fixture(nonce="nonce-gpu-0001", overall=False)
        result = nvidia_cc.verify_jwt(fx.token, fx.jwks, expected_nonce="nonce-gpu-0001")
        self.assertFalse(result.ok)
        self.assertTrue(any("overall-att-result" in e for e in result.errors))

    def test_old_version_rejected(self):
        fx = fixtures.nvidia_fixture(nonce="nonce-gpu-0001", version="1.0")
        result = nvidia_cc.verify_jwt(fx.token, fx.jwks, expected_nonce="nonce-gpu-0001")
        self.assertFalse(result.ok)
        self.assertTrue(any("x-nvidia-ver" in e for e in result.errors))

    def test_wrong_issuer_and_audience(self):
        fx = fixtures.nvidia_fixture(nonce="nonce-gpu-0001", issuer="https://evil.example")
        result = nvidia_cc.verify_jwt(fx.token, fx.jwks, expected_nonce="nonce-gpu-0001")
        self.assertFalse(result.ok)
        self.assertTrue(any("iss" in e for e in result.errors))
        fx2 = fixtures.nvidia_fixture(nonce="nonce-gpu-0001", audience="other")
        result2 = nvidia_cc.verify_jwt(fx2.token, fx2.jwks, expected_nonce="nonce-gpu-0001")
        self.assertFalse(result2.ok)
        self.assertTrue(any("aud" in e for e in result2.errors))

    def test_alg_none_rejected(self):
        import base64
        import json

        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        _, payload, _ = self.fx.token.split(".")
        with self.assertRaises(nvidia_cc.NvidiaJwtError):
            nvidia_cc.parse_jwt(f"{header}.{payload}.")
        result = nvidia_cc.verify_jwt(f"{header}.{payload}.", self.fx.jwks)
        self.assertFalse(result.ok)
        self.assertIn("RS256", result.errors[0])

    def test_foreign_jwks_fails(self):
        # 不同模数的 RSA 公钥（同 kid）：验证必须失败（证明验签不是「有 key 就过」）
        foreign = PublicKey(kind="rsa", n=fixtures.RSA_N + 2, e=65537)
        jwks = {"keys": [foreign.to_jwk("nras-fixture-2026")]}
        result = nvidia_cc.verify_jwt(self.fx.token, jwks, expected_nonce="nonce-gpu-0001")
        self.assertFalse(result.ok)
        self.assertFalse(result.signature_valid)


class FixtureBoundaryTest(unittest.TestCase):
    """把「自签 fixture」的边界写成可执行断言，防止后续误用成硬件证据。"""

    def test_fixture_roots_are_self_signed(self):
        pki = fixtures.fixture_pki()
        self.assertTrue(pki.tdx_root.verify_self_signed())
        self.assertTrue(pki.amd_root.verify_self_signed())
        self.assertIn("Fixture", pki.tdx_root.subject_cn)
        self.assertIn("Fixture", pki.amd_root.subject_cn)

    def test_fixture_pki_is_not_vendor_pki(self):
        pki = fixtures.fixture_pki()
        for cert in (pki.tdx_root, pki.amd_root):
            self.assertTrue(cert.subject_cn.startswith("InkBlade Fixture"),
                            f"fixture 证书必须是显式自签命名：{cert.subject_cn}")
        # 证书只有 CN 一个 RDN（无 O/OU/C 厂商字段），且 JWKS kid 带 fixture 标记
        self.assertEqual(pki.nras_kid, "nras-fixture-2026")
        self.assertTrue(pki.nras_kid.startswith("nras-fixture"))

    def test_quote_carries_embedded_chain(self):
        fx = fixtures.tdx_fixture()
        self.assertEqual(len(fx.quote.cert_chain), 2)
        self.assertEqual(fx.quote.cert_chain[0].subject_cn, "InkBlade Fixture TDX AK")


if __name__ == "__main__":
    unittest.main()
