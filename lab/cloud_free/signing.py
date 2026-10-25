# -*- coding: utf-8 -*-
"""AWS SigV4 与 Azure SharedKey 的纯标准库实现（适配器与 mock 服务端共用）。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import urllib.parse
from datetime import datetime, timezone


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="-_.~")


def aws_canonical_query(query: str) -> str:
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    return "&".join(f"{_quote(k)}={_quote(v)}" for k, v in sorted(pairs))


def aws_canonical_request(method: str, path: str, query: str, host: str,
                          amz_date: str, payload_hash: str) -> tuple[str, str]:
    canonical_uri = urllib.parse.quote(path or "/", safe="/~")
    canonical_query = aws_canonical_query(query)
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_headers = (f"host:{host}\n"
                         f"x-amz-content-sha256:{payload_hash}\n"
                         f"x-amz-date:{amz_date}\n")
    request = "\n".join([method, canonical_uri, canonical_query, canonical_headers,
                         signed_headers, payload_hash])
    return request, signed_headers


def aws_signature(method: str, path: str, query: str, host: str, amz_date: str,
                  payload: bytes, access_key: str, secret_key: str,
                  region: str = "us-east-1", service: str = "s3") -> str:
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical, signed_headers = aws_canonical_request(
        method, path, query, host, amz_date, payload_hash)
    date = amz_date[:8]
    scope = f"{date}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                     hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(("AWS4" + secret_key).encode(), date)
    key = _hmac(key, region)
    key = _hmac(key, service)
    key = _hmac(key, "aws4_request")
    return hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()


def aws_sign_headers(method: str, path: str, query: str, host: str,
                     payload: bytes, access_key: str, secret_key: str,
                     region: str = "us-east-1", service: str = "s3",
                     now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    payload_hash = hashlib.sha256(payload).hexdigest()
    sig = aws_signature(method, path, query, host, amz_date, payload,
                        access_key, secret_key, region, service)
    scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    return {
        "Host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                          f"SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
                          f"Signature={sig}"),
    }


def azure_string_to_sign(method: str, headers: dict, account: str, path: str,
                         query: str = "") -> str:
    lower = {k.lower(): v for k, v in headers.items()}
    canonical_headers = "".join(
        f"{k}:{v.strip()}\n" for k, v in sorted(lower.items())
        if k.startswith("x-ms-"))
    resource = f"/{account}{path}"
    for key, value in sorted(urllib.parse.parse_qsl(query, keep_blank_values=True)):
        resource += f"\n{key.lower()}:{value}"
    fields = [
        method,
        lower.get("content-encoding", ""),
        lower.get("content-language", ""),
        lower.get("content-length", ""),
        lower.get("content-md5", ""),
        lower.get("content-type", ""),
        lower.get("date", ""),
        lower.get("if-modified-since", ""),
        lower.get("if-match", ""),
        lower.get("if-none-match", ""),
        lower.get("if-unmodified-since", ""),
        lower.get("range", ""),
    ]
    return "\n".join(fields) + "\n" + canonical_headers + resource


def azure_signature(method: str, headers: dict, account: str, key_b64: str,
                    path: str, query: str = "") -> str:
    sts = azure_string_to_sign(method, headers, account, path, query)
    digest = hmac.new(base64.b64decode(key_b64), sts.encode("utf-8"),
                      hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def azure_auth_header(method: str, headers: dict, account: str, key_b64: str,
                      path: str, query: str = "") -> str:
    return f"SharedKey {account}:{azure_signature(method, headers, account, key_b64, path, query)}"
