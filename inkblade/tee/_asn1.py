"""最小 ASN.1 DER 编解码（仅标准库）。

只覆盖 X.509 / PKCS#1 / ECDSA 签名所需子集：SEQUENCE、SET、INTEGER、OID、BIT STRING、
OCTET STRING、UTF8String、UTCTime、GeneralizedTime、NULL 与显式上下文标签。

设计约束：
- 解析一侧严格校验长度（防越界/截断），不做 BER 的变长长度形式（拒收 0x80 不定长）。
- 编码一侧只产出 DER（最短长度编码、正数 INTEGER 前置 0x00）。
- 本模块与 trident/tee 的其余部分一样只做**本地密码学校验**，不联网、不读硬件。
"""
from __future__ import annotations

from datetime import datetime, timezone

__all__ = [
    "DerError", "read_tlv", "read_int", "encode", "seq", "set_of", "integer", "oid",
    "bit_string", "octet_string", "null", "utf8", "utc_time", "generalized_time",
    "explicit", "decode_oid", "parse_time",
]


class DerError(ValueError):
    """DER 结构非法（截断、长度越界、非最短编码等）。"""


def _read_length(data: bytes, off: int) -> tuple[int, int]:
    if off >= len(data):
        raise DerError("长度字段截断")
    first = data[off]
    off += 1
    if first < 0x80:
        return first, off
    count = first & 0x7F
    if count == 0:
        raise DerError("不支持 BER 不定长（0x80）")
    if count > 4:
        raise DerError(f"长度字段过长：{count} 字节")
    if off + count > len(data):
        raise DerError("长度字段截断")
    value = int.from_bytes(data[off:off + count], "big")
    if value < 0x80:
        raise DerError("长度非最短编码")
    return value, off + count


def read_tlv(data: bytes, off: int = 0) -> tuple[int, bytes, int]:
    """读一个 TLV，返回 (tag, value, next_offset)。"""
    if off >= len(data):
        raise DerError("TLV 截断")
    tag = data[off]
    if tag & 0x1F == 0x1F:
        raise DerError("不支持多字节 tag")
    length, off = _read_length(data, off + 1)
    end = off + length
    if end > len(data):
        raise DerError(f"TLV 值越界（需要 {length}，剩余 {len(data) - off}）")
    return tag, data[off:end], end


def read_int(data: bytes, off: int = 0) -> tuple[int, int]:
    tag, value, nxt = read_tlv(data, off)
    if tag != 0x02:
        raise DerError(f"期望 INTEGER(0x02)，得到 0x{tag:02x}")
    return int.from_bytes(value, "big", signed=True), nxt


def decode_oid(data: bytes) -> str:
    if not data:
        raise DerError("空 OID")
    first = data[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def parse_time(raw: bytes, tag: int) -> datetime:
    text = raw.decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        if len(text) < 13 or not text.endswith("Z"):
            raise DerError(f"UTCTime 非法：{text!r}")
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        return datetime(year, int(text[2:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]),
                        int(text[10:12]), tzinfo=timezone.utc)
    if tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSSZ
        if len(text) < 15 or not text.endswith("Z"):
            raise DerError(f"GeneralizedTime 非法：{text!r}")
        return datetime(int(text[0:4]), int(text[4:6]), int(text[6:8]), int(text[8:10]),
                        int(text[10:12]), int(text[12:14]), tzinfo=timezone.utc)
    raise DerError(f"不支持的 ASN.1 时间 tag 0x{tag:02x}")


# ---------------------------------------------------------------- 编码


def _encode_length(length: int) -> bytes:
    if length < 0:
        raise DerError("负长度")
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def encode(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(payload)) + payload


def seq(*items: bytes) -> bytes:
    return encode(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return encode(0x31, b"".join(items))


def integer(value: int) -> bytes:
    if value == 0:
        return encode(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return encode(0x02, raw)


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    if len(parts) < 2:
        raise DerError(f"OID 至少两段：{dotted}")
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part == 0:
            body.append(0)
            continue
        chunks = []
        while part:
            chunks.append(part & 0x7F)
            part >>= 7
        for i, chunk in enumerate(reversed(chunks)):
            body.append(chunk | (0x80 if i < len(chunks) - 1 else 0))
    return encode(0x06, bytes(body))


def bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    return encode(0x03, bytes([unused_bits]) + data)


def octet_string(data: bytes) -> bytes:
    return encode(0x04, data)


def null() -> bytes:
    return encode(0x05, b"")


def utf8(text: str) -> bytes:
    return encode(0x0C, text.encode("utf-8"))


def utc_time(when: datetime) -> bytes:
    return encode(0x17, when.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def generalized_time(when: datetime) -> bytes:
    return encode(0x18, when.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def explicit(number: int, payload: bytes) -> bytes:
    return encode(0xA0 | number, payload)
