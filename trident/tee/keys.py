"""P-256/P-384 与 RSA-2048 的公钥/私钥运算（仅标准库，用于本地验签与 fixture 生成）。

范围与边界（重要）：
- 只实现**验证**所需的数学（ECDSA verify / RSA PKCS#1 v1.5 verify）与**fixture 生成**所需的签名。
- 不做侧信道防护、不做随机数生成器、不做密钥管理：私钥是本仓库自签样本的固定测试密钥，
  公开在 `fixtures.py` 里，绝不可用于生产。
- 支持算法：ecdsa-with-SHA256（P-256）、ecdsa-with-SHA384（P-384）、sha256WithRSAEncryption。

公开 API：
    PublicKey.from_pem / from_spki / verify / to_spki_der
    PrivateKey.from_pem / sign
    der_sig_to_rs / rs_to_der_sig
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from ._asn1 import DerError, bit_string, decode_oid, integer, oid, read_tlv, seq

__all__ = ["Curve", "CURVES", "PublicKey", "PrivateKey", "der_sig_to_rs", "rs_to_der_sig",
           "load_pem_blocks", "ALG_ECDSA_SHA256", "ALG_ECDSA_SHA384", "ALG_RSA_SHA256"]

OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_P256 = "1.2.840.10045.3.1.7"
OID_P384 = "1.3.132.0.34"
ALG_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
ALG_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
ALG_RSA_SHA256 = "1.2.840.113549.1.1.11"
_SIG_HASH = {ALG_ECDSA_SHA256: "sha256", ALG_ECDSA_SHA384: "sha384", ALG_RSA_SHA256: "sha256"}


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int
    size: int          # 字节数（32 或 48）
    hash_name: str
    oid: str


CURVES = {
    "P-256": Curve(
        name="P-256",
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        size=32, hash_name="sha256", oid=OID_P256,
    ),
    "P-384": Curve(
        name="P-384",
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
        b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
        gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        size=48, hash_name="sha384", oid=OID_P384,
    ),
}
_CURVE_BY_OID = {curve.oid: curve for curve in CURVES.values()}


# ---------------------------------------------------------------- EC 点运算
# 内部用仿射坐标 (x, y)；None 表示无穷远点。P-256/384 均为素数域，用 Fermat 逆元。

Point = tuple[int, int] | None


def _inv(value: int, mod: int) -> int:
    return pow(value, -1, mod)


def _point_add(curve: Curve, p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + curve.a) * _inv(2 * y1, curve.p) % curve.p
    else:
        lam = (y2 - y1) * _inv(x2 - x1, curve.p) % curve.p
    x3 = (lam * lam - x1 - x2) % curve.p
    y3 = (lam * (x1 - x3) - y1) % curve.p
    return x3, y3


def _point_mul(curve: Curve, k: int, point: Point) -> Point:
    if k % curve.n == 0 or point is None:
        return None
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(curve, result, addend)
        addend = _point_add(curve, addend, addend)
        k >>= 1
    return result


def _ecdsa_verify(curve: Curve, pub: tuple[int, int], message: bytes, r: int, s: int) -> bool:
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
    z = int.from_bytes(hashlib.new(curve.hash_name, message).digest(), "big")
    if z.bit_length() > curve.n.bit_length():
        z >>= z.bit_length() - curve.n.bit_length()
    w = _inv(s, curve.n)
    u1 = z * w % curve.n
    u2 = r * w % curve.n
    point = _point_add(curve, _point_mul(curve, u1, (curve.gx, curve.gy)),
                       _point_mul(curve, u2, pub))
    if point is None:
        return False
    return point[0] % curve.n == r


def _ecdsa_sign(curve: Curve, priv: int, message: bytes) -> tuple[int, int]:
    """fixture 专用确定性签名（k = H(priv||H(msg)) mod n）；不可用于生产签名。"""
    if not 1 <= priv < curve.n:
        raise ValueError("私钥超出曲线阶")
    z = int.from_bytes(hashlib.new(curve.hash_name, message).digest(), "big")
    k = int.from_bytes(hashlib.sha256(priv.to_bytes(curve.size, "big") + z.to_bytes(curve.size, "big")).digest(), "big") % curve.n or 1
    point = _point_mul(curve, k, (curve.gx, curve.gy))
    assert point is not None
    r = point[0] % curve.n
    s = _inv(k, curve.n) * (z + r * priv) % curve.n
    if r == 0 or s == 0:
        raise ValueError("签名退化（fixture 密钥与消息组合不可用）")
    return r, s


def der_sig_to_rs(signature: bytes) -> tuple[int, int]:
    tag, body, end = read_tlv(signature, 0)
    if tag != 0x30 or end != len(signature):
        raise DerError("ECDSA 签名不是单个 SEQUENCE")
    r_tag, r_raw, off = read_tlv(body, 0)
    s_tag, s_raw, off2 = read_tlv(body, off)
    if r_tag != 0x02 or s_tag != 0x02 or off2 != len(body):
        raise DerError("ECDSA 签名 R/S 结构非法")
    return int.from_bytes(r_raw, "big"), int.from_bytes(s_raw, "big")


def rs_to_der_sig(r: int, s: int) -> bytes:
    return seq(integer(r), integer(s))


def _raw_sig_to_rs(signature: bytes, size: int) -> tuple[int, int]:
    if len(signature) == 2 * size:
        return int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
    return der_sig_to_rs(signature)


# ---------------------------------------------------------------- 公钥


@dataclass(frozen=True)
class PublicKey:
    kind: str                       # "ec" | "rsa"
    curve: str = ""                 # P-256 / P-384
    x: int = 0
    y: int = 0
    n: int = 0
    e: int = 0

    # ---------- 构造 ----------
    @classmethod
    def from_spki(cls, der: bytes) -> "PublicKey":
        tag, body, end = read_tlv(der, 0)
        if tag != 0x30 or end != len(der):
            raise DerError("SPKI 不是单个 SEQUENCE")
        alg_tag, alg_body, off = read_tlv(body, 0)
        if alg_tag != 0x30:
            raise DerError("SPKI.algorithm 非 SEQUENCE")
        alg_oid_tag, alg_oid_raw, alg_off = read_tlv(alg_body, 0)
        if alg_oid_tag != 0x06:
            raise DerError("SPKI.algorithm 缺 OID")
        alg_oid = decode_oid(alg_oid_raw)
        key_tag, key_bits, off = read_tlv(body, off)
        if key_tag != 0x03 or not key_bits:
            raise DerError("SPKI.subjectPublicKey 非 BIT STRING")
        if key_bits[0] != 0:
            raise DerError("SPKI 密钥 BIT STRING 含未用位")
        key = key_bits[1:]
        if alg_oid == OID_EC_PUBLIC_KEY:
            if alg_off >= len(alg_body):
                raise DerError("EC SPKI 缺曲线参数")
            par_tag, par_raw, _ = read_tlv(alg_body, alg_off)
            if par_tag != 0x06:
                raise DerError("EC 曲线参数非 OID")
            curve_oid = decode_oid(par_raw)
            curve = _CURVE_BY_OID.get(curve_oid)
            if curve is None:
                raise DerError(f"不支持的曲线 {curve_oid}")
            size = curve.size
            if len(key) != 1 + 2 * size or key[0] != 0x04:
                raise DerError("EC 公钥不是未压缩点")
            return cls(kind="ec", curve=curve.name,
                       x=int.from_bytes(key[1:1 + size], "big"),
                       y=int.from_bytes(key[1 + size:], "big"))
        if alg_oid == OID_RSA_ENCRYPTION:
            seq_tag, rsa_body, _ = read_tlv(key, 0)
            if seq_tag != 0x30:
                raise DerError("RSAPublicKey 非 SEQUENCE")
            n_tag, n_raw, rsa_off = read_tlv(rsa_body, 0)
            e_tag, e_raw, _ = read_tlv(rsa_body, rsa_off)
            if n_tag != 0x02 or e_tag != 0x02:
                raise DerError("RSAPublicKey 字段非法")
            return cls(kind="rsa", n=int.from_bytes(n_raw, "big"), e=int.from_bytes(e_raw, "big"))
        raise DerError(f"不支持的 SPKI 算法 {alg_oid}")

    @classmethod
    def from_pem(cls, pem: str | bytes) -> "PublicKey":
        blocks = load_pem_blocks(pem, "PUBLIC KEY")
        if not blocks:
            raise DerError("PEM 中没有 PUBLIC KEY 块")
        return cls.from_spki(blocks[0])

    @classmethod
    def from_jwk(cls, jwk: dict) -> "PublicKey":
        """JWKS/JWK 的 RSA 公钥（n/e 为 base64url）。"""
        if jwk.get("kty") != "RSA":
            raise DerError(f"仅支持 RSA JWK，收到 {jwk.get('kty')!r}")
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return cls(kind="rsa", n=n, e=e)

    # ---------- 编码 ----------
    def to_spki_der(self) -> bytes:
        if self.kind == "ec":
            curve = CURVES[self.curve]
            point = b"\x04" + self.x.to_bytes(curve.size, "big") + self.y.to_bytes(curve.size, "big")
            return seq(seq(oid(OID_EC_PUBLIC_KEY), oid(curve.oid)), bit_string(point))
        return seq(seq(oid(OID_RSA_ENCRYPTION), b"\x05\x00"),
                   bit_string(seq(integer(self.n), integer(self.e))))

    def to_jwk(self, kid: str = "") -> dict:
        if self.kind != "rsa":
            raise DerError("仅 RSA 公钥可导出 JWK")
        jwk = {"kty": "RSA", "n": _b64url(self.n.to_bytes((self.n.bit_length() + 7) // 8, "big")),
               "e": _b64url(self.e.to_bytes((self.e.bit_length() + 7) // 8, "big")),
               "alg": "RS256", "use": "sig"}
        if kid:
            jwk["kid"] = kid
        return jwk

    # ---------- 验签 ----------
    def verify(self, alg_oid: str, message: bytes, signature: bytes) -> bool:
        if self.kind == "ec":
            curve = CURVES[self.curve]
            expected = {"P-256": ALG_ECDSA_SHA256, "P-384": ALG_ECDSA_SHA384}[self.curve]
            if alg_oid != expected:
                return False
            try:
                r, s = _raw_sig_to_rs(signature, curve.size)
            except DerError:
                return False
            return _ecdsa_verify(curve, (self.x, self.y), message, r, s)
        if self.kind == "rsa":
            if alg_oid != ALG_RSA_SHA256:
                return False
            return _rsa_pkcs1_verify(self.n, self.e, message, signature)
        return False


# ---------------------------------------------------------------- RSA


_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _rsa_pkcs1_verify(n: int, e: int, message: bytes, signature: bytes) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    digest = hashlib.sha256(message).digest()
    expected_tail = _SHA256_DIGEST_INFO_PREFIX + digest
    padding_len = k - len(expected_tail) - 3
    if padding_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + expected_tail
    # 常数时间比较（本地 fixture 场景也保持一致习惯）
    diff = 0
    for a, b in zip(em, expected):
        diff |= a ^ b
    return diff == 0


def _rsa_pkcs1_sign(n: int, d: int, message: bytes) -> bytes:
    k = (n.bit_length() + 7) // 8
    digest = hashlib.sha256(message).digest()
    tail = _SHA256_DIGEST_INFO_PREFIX + digest
    padding = b"\xff" * (k - len(tail) - 3)
    em = b"\x00\x01" + padding + b"\x00" + tail
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


# ---------------------------------------------------------------- 私钥（fixture 专用）


@dataclass(frozen=True)
class PrivateKey:
    kind: str
    curve: str = ""
    d: int = 0
    n: int = 0
    e: int = 0

    def public_key(self) -> PublicKey:
        if self.kind == "ec":
            curve = CURVES[self.curve]
            point = _point_mul(curve, self.d, (curve.gx, curve.gy))
            assert point is not None
            return PublicKey(kind="ec", curve=self.curve, x=point[0], y=point[1])
        return PublicKey(kind="rsa", n=self.n, e=self.e)

    def sign(self, alg_oid: str, message: bytes, raw: bool = False) -> bytes:
        """raw=True 输出 r||s（Intel/AMD 结构体要求），否则 DER。"""
        if self.kind == "ec":
            curve = CURVES[self.curve]
            expected = {"P-256": ALG_ECDSA_SHA256, "P-384": ALG_ECDSA_SHA384}[self.curve]
            if alg_oid != expected:
                raise ValueError(f"{self.curve} 只支持 {expected}")
            r, s = _ecdsa_sign(curve, self.d, message)
            if raw:
                return r.to_bytes(curve.size, "big") + s.to_bytes(curve.size, "big")
            return rs_to_der_sig(r, s)
        if alg_oid != ALG_RSA_SHA256:
            raise ValueError("RSA 私钥只支持 sha256WithRSAEncryption")
        return _rsa_pkcs1_sign(self.n, self.d, message)


# ---------------------------------------------------------------- PEM / base64url


def load_pem_blocks(pem: str | bytes, label: str) -> list[bytes]:
    text = pem.decode("ascii") if isinstance(pem, bytes) else pem
    begin, end = f"-----BEGIN {label}-----", f"-----END {label}-----"
    out: list[bytes] = []
    cursor = 0
    while True:
        start = text.find(begin, cursor)
        if start < 0:
            break
        stop = text.find(end, start)
        if stop < 0:
            raise DerError(f"PEM {label} 块未闭合")
        body = "".join(text[start + len(begin):stop].split())
        out.append(base64.b64decode(body, validate=True))
        cursor = stop + len(end)
    return out


def pem_wrap(der: bytes, label: str) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "\n".join([f"-----BEGIN {label}-----", *lines, f"-----END {label}-----"]) + "\n"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


b64url_encode = _b64url
b64url_decode = _b64url_decode
