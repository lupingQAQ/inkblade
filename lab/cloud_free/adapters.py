# -*- coding: utf-8 -*-
"""三家对象存储适配器（真实签名 + 真实 HTTP；可指向 LocalStack/Azurite/fake-gcs）。"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.utils import formatdate
from typing import Any

from .signing import aws_sign_headers, azure_auth_header, azure_signature


class CloudError(RuntimeError):
    def __init__(self, status: int, code: str, message: str, body: bytes = b""):
        super().__init__(f"HTTP {status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.body = body


@dataclass
class CloudObject:
    bucket: str
    key: str
    data: bytes
    etag: str
    metadata: dict[str, str]
    content_type: str = "application/octet-stream"


class _Base:
    def __init__(self, endpoint: str, timeout: float = 10):
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, query: str = "", body: bytes = b"",
                 headers: dict | None = None) -> tuple[int, dict, bytes]:
        url = self.endpoint + path + (("?" + query) if query else "")
        req = urllib.request.Request(url, data=body if body else None, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read()
        except urllib.error.URLError as exc:
            raise CloudError(0, "NetworkError", str(exc.reason)) from exc

    # 统一接口
    def ensure_bucket(self, bucket: str) -> None: raise NotImplementedError
    def put_object(self, bucket: str, key: str, data: bytes,
                   metadata: dict[str, str] | None = None) -> CloudObject: raise NotImplementedError
    def get_object(self, bucket: str, key: str) -> bytes: raise NotImplementedError
    def head_object(self, bucket: str, key: str) -> CloudObject: raise NotImplementedError
    def list_objects(self, bucket: str, prefix: str = "") -> list[CloudObject]: raise NotImplementedError
    def delete_object(self, bucket: str, key: str) -> None: raise NotImplementedError


class AwsS3Adapter(_Base):
    def __init__(self, endpoint: str, access_key: str = "trident",
                 secret_key: str = "trident-secret", region: str = "us-east-1",
                 timeout: float = 10):
        super().__init__(endpoint, timeout)
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region

    def _headers(self, method: str, path: str, query: str, body: bytes,
                 extra: dict | None = None) -> dict:
        host = urllib.parse.urlsplit(self.endpoint).netloc
        signed = aws_sign_headers(method, path, query, host, body, self.access_key,
                                  self.secret_key, self.region, "s3")
        signed.update(extra or {})
        return signed

    def _error(self, status: int, body: bytes) -> CloudError:
        code = message = ""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(body)
            code = root.findtext("Code") or ""
            message = root.findtext("Message") or ""
        except Exception:
            message = body[:200].decode("utf-8", "replace")
        return CloudError(status, code or "S3Error", message, body)

    def ensure_bucket(self, bucket: str) -> None:
        path = f"/{bucket}"
        status, _, body = self._request("PUT", path, "", b"",
                                        self._headers("PUT", path, "", b""))
        if status not in (200, 204):
            if status == 409:
                return
            raise self._error(status, body)

    def put_object(self, bucket: str, key: str, data: bytes,
                   metadata: dict[str, str] | None = None) -> CloudObject:
        path = f"/{bucket}/{urllib.parse.quote(key, safe='/~')}"
        extra = {f"x-amz-meta-{k.lower()}": str(v) for k, v in (metadata or {}).items()}
        extra["Content-Type"] = "application/octet-stream"
        status, headers, body = self._request(
            "PUT", path, "", data, self._headers("PUT", path, "", data, extra))
        if status not in (200, 201):
            raise self._error(status, body)
        etag = headers.get("ETag", "").strip('"')
        return CloudObject(bucket, key, data, etag, {k.lower(): v for k, v in (metadata or {}).items()})

    def get_object(self, bucket: str, key: str) -> bytes:
        path = f"/{bucket}/{urllib.parse.quote(key, safe='/~')}"
        status, _, body = self._request("GET", path, "", b"",
                                        self._headers("GET", path, "", b""))
        if status != 200:
            raise self._error(status, body)
        return body

    def head_object(self, bucket: str, key: str) -> CloudObject:
        path = f"/{bucket}/{urllib.parse.quote(key, safe='/~')}"
        status, headers, body = self._request("HEAD", path, "", b"",
                                              self._headers("HEAD", path, "", b""))
        if status != 200:
            raise self._error(status, body)
        meta = {k[11:].lower(): v for k, v in headers.items() if k.lower().startswith("x-amz-meta-")}
        return CloudObject(bucket, key, b"", headers.get("ETag", "").strip('"'), meta,
                           headers.get("Content-Type", "application/octet-stream"))

    def list_objects(self, bucket: str, prefix: str = "") -> list[CloudObject]:
        path = f"/{bucket}"
        query = "list-type=2"
        if prefix:
            query += "&prefix=" + urllib.parse.quote(prefix)
        status, _, body = self._request("GET", path, query, b"",
                                        self._headers("GET", path, query, b""))
        if status != 200:
            raise self._error(status, body)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(body)
        out: list[CloudObject] = []
        for item in root.findall(".//{*}Contents"):
            key = item.findtext("{*}Key") or item.findtext("Key") or ""
            size = int(item.findtext("{*}Size") or item.findtext("Size") or 0)
            etag = (item.findtext("{*}ETag") or item.findtext("ETag") or "").strip('"')
            out.append(CloudObject(bucket, key, b"\x00" * size, etag, {}))
        return out

    def delete_object(self, bucket: str, key: str) -> None:
        path = f"/{bucket}/{urllib.parse.quote(key, safe='/~')}"
        status, _, body = self._request("DELETE", path, "", b"",
                                        self._headers("DELETE", path, "", b""))
        if status not in (200, 204):
            raise self._error(status, body)


class AzureBlobAdapter(_Base):
    def __init__(self, endpoint: str, account: str = "devstoreaccount1",
                 key_b64: str = "dHJpZGVudC1henVyZS1rZXk=", timeout: float = 10):
        super().__init__(endpoint, timeout)
        self.account = account
        self.key_b64 = key_b64

    def _headers(self, method: str, path: str, query: str, body: bytes,
                 extra: dict | None = None) -> dict:
        headers = {
            "x-ms-date": formatdate(usegmt=True),
            "x-ms-version": "2021-12-02",
            "Content-Length": str(len(body)),
            "Content-Type": "application/octet-stream",
        }
        headers.update(extra or {})
        headers["Authorization"] = azure_auth_header(
            method, headers, self.account, self.key_b64, path, query)
        return headers

    def _error(self, status: int, body: bytes) -> CloudError:
        import xml.etree.ElementTree as ET
        code = message = ""
        try:
            root = ET.fromstring(body)
            code = root.findtext("Code") or ""
            message = root.findtext("Message") or ""
        except Exception:
            message = body[:200].decode("utf-8", "replace")
        return CloudError(status, code or "AzureError", message, body)

    def ensure_bucket(self, bucket: str) -> None:
        path = f"/{bucket}"
        query = "restype=container"
        status, _, body = self._request("PUT", path, query, b"",
                                        self._headers("PUT", path, query, b""))
        if status not in (201, 200, 409):
            raise self._error(status, body)

    def put_object(self, bucket: str, key: str, data: bytes,
                   metadata: dict[str, str] | None = None) -> CloudObject:
        path = f"/{bucket}/{urllib.parse.quote(key, safe='/~')}"
        extra = {"x-ms-blob-type": "BlockBlob"}
        extra.update({f"x-ms-meta-{k.lower()}": str(v) for k, v in (metadata or {}).items()})
        status, headers, body = self._request(
            "PUT", path, "", data, self._headers("PUT", path, "", data, extra))
        if status not in (201, 200):
            raise self._error(status, body)
        return CloudObject(bucket, key, data, headers.get("ETag", "").strip('"'),
                           {k.lower(): v for k, v in (metadata or {}).items()})

    def get_object(self, bucket: str, key: str) -> bytes:
        path = f"/{bucket}/{urllib.parse.quote(key, safe='/~')}"
        status, _, body = self._request("GET", path, "", b"",
                                        self._headers("GET", path, "", b""))
        if status != 200:
            raise self._error(status, body)
        return body

    def head_object(self, bucket: str, key: str) -> CloudObject:
        path = f"/{bucket}/{urllib.parse.quote(key, safe='/~')}"
        status, headers, body = self._request("HEAD", path, "", b"",
                                              self._headers("HEAD", path, "", b""))
        if status != 200:
            raise self._error(status, body)
        meta = {k[10:].lower(): v for k, v in headers.items() if k.lower().startswith("x-ms-meta-")}
        return CloudObject(bucket, key, b"", headers.get("ETag", "").strip('"'), meta,
                           headers.get("Content-Type", "application/octet-stream"))

    def list_objects(self, bucket: str, prefix: str = "") -> list[CloudObject]:
        path = f"/{bucket}"
        query = "restype=container&comp=list"
        if prefix:
            query += "&prefix=" + urllib.parse.quote(prefix)
        status, _, body = self._request("GET", path, query, b"",
                                        self._headers("GET", path, query, b""))
        if status != 200:
            raise self._error(status, body)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(body)
        out: list[CloudObject] = []
        for item in root.findall(".//Blob"):
            name = item.findtext("Name") or ""
            size = int(item.findtext("Properties/Content-Length") or 0)
            etag = (item.findtext("Properties/Etag") or "").strip('"')
            out.append(CloudObject(bucket, name, b"\x00" * size, etag, {}))
        return out

    def delete_object(self, bucket: str, key: str) -> None:
        path = f"/{bucket}/{urllib.parse.quote(key, safe='/~')}"
        status, _, body = self._request("DELETE", path, "", b"",
                                        self._headers("DELETE", path, "", b""))
        if status not in (202, 204):
            raise self._error(status, body)


class GcpStorageAdapter(_Base):
    def __init__(self, endpoint: str, token: str = "fake-gcs-token", timeout: float = 10):
        super().__init__(endpoint, timeout)
        self.token = token

    def _headers(self, content_type: str = "application/json") -> dict:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": content_type}

    def _error(self, status: int, body: bytes) -> CloudError:
        try:
            doc = json.loads(body)
            err = doc.get("error") or {}
            return CloudError(status, str(err.get("code") or status),
                              str(err.get("message") or ""), body)
        except Exception:
            return CloudError(status, "GcsError", body[:200].decode("utf-8", "replace"), body)

    def ensure_bucket(self, bucket: str) -> None:
        path = "/storage/v1/b"
        payload = json.dumps({"name": bucket}).encode()
        status, _, body = self._request("POST", path, "project=trident", payload,
                                        self._headers())
        if status not in (200, 409):
            raise self._error(status, body)

    def put_object(self, bucket: str, key: str, data: bytes,
                   metadata: dict[str, str] | None = None) -> CloudObject:
        path = f"/upload/storage/v1/b/{bucket}/o"
        query = "uploadType=media&name=" + urllib.parse.quote(key, safe="")
        headers = self._headers("application/octet-stream")
        for k, v in (metadata or {}).items():
            headers[f"x-goog-meta-{k.lower()}"] = str(v)
        status, _, body = self._request("POST", path, query, data, headers)
        if status != 200:
            raise self._error(status, body)
        doc = json.loads(body)
        return CloudObject(bucket, key, data, doc.get("etag", "").strip('"'),
                           {k.lower(): v for k, v in (metadata or {}).items()})

    def get_object(self, bucket: str, key: str) -> bytes:
        path = f"/storage/v1/b/{bucket}/o/{urllib.parse.quote(key, safe='')}"
        status, _, body = self._request("GET", path, "alt=media", b"", self._headers())
        if status != 200:
            raise self._error(status, body)
        return body

    def head_object(self, bucket: str, key: str) -> CloudObject:
        path = f"/storage/v1/b/{bucket}/o/{urllib.parse.quote(key, safe='')}"
        status, _, body = self._request("GET", path, "", b"", self._headers())
        if status != 200:
            raise self._error(status, body)
        doc = json.loads(body)
        return CloudObject(bucket, key, b"", doc.get("etag", "").strip('"'),
                           {k.lower(): v for k, v in (doc.get("metadata") or {}).items()},
                           doc.get("contentType", "application/octet-stream"))

    def list_objects(self, bucket: str, prefix: str = "") -> list[CloudObject]:
        path = f"/storage/v1/b/{bucket}/o"
        query = ""
        if prefix:
            query = "prefix=" + urllib.parse.quote(prefix)
        status, _, body = self._request("GET", path, query, b"", self._headers())
        if status != 200:
            raise self._error(status, body)
        doc = json.loads(body)
        return [CloudObject(bucket, item["name"], b"\x00" * int(item.get("size", 0)),
                            str(item.get("etag", "")).strip('"'),
                            {k.lower(): v for k, v in (item.get("metadata") or {}).items()})
                for item in doc.get("items", [])]

    def delete_object(self, bucket: str, key: str) -> None:
        path = f"/storage/v1/b/{bucket}/o/{urllib.parse.quote(key, safe='')}"
        status, _, body = self._request("DELETE", path, "", b"", self._headers())
        if status not in (200, 204):
            raise self._error(status, body)
