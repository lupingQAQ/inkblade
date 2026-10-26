# -*- coding: utf-8 -*-
"""纯标准库三云对象存储端点（无 Docker 时的可执行路径）。

- `/s3/*`      AWS S3 path-style（SigV4 真实验签、ListObjectsV2 XML）
- `/azure/*`   Azure Blob（SharedKey 真实验签、Azurite 形状）
- `/gcs/*`     GCS JSON API（fake-gcs-server 形状）

同一套端点也可由 docker-compose 中的 LocalStack/Azurite/fake-gcs-server 替换；
适配器只关心 endpoint，不关心后端是 mock 还是官方 emulator。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

from .signing import (aws_canonical_request, aws_signature, azure_signature)

DEFAULT_ACCOUNT = "devstoreaccount1"
DEFAULT_AZURE_KEY = "dHJpZGVudC1henVyZS1rZXk="
DEFAULT_AWS_ACCESS = "inkblade"
DEFAULT_AWS_SECRET = "inkblade-secret"


@dataclass
class Stored:
    data: bytes
    metadata: dict[str, str] = field(default_factory=dict)
    content_type: str = "application/octet-stream"
    updated: str = ""


class Store:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.buckets: dict[str, dict[str, Stored]] = {}

    def create(self, bucket: str) -> bool:
        with self.lock:
            if bucket in self.buckets:
                return False
            self.buckets[bucket] = {}
            return True

    def has_bucket(self, bucket: str) -> bool:
        return bucket in self.buckets

    def put(self, bucket: str, key: str, obj: Stored) -> None:
        with self.lock:
            self.buckets.setdefault(bucket, {})[key] = obj

    def get(self, bucket: str, key: str) -> Stored | None:
        return (self.buckets.get(bucket) or {}).get(key)

    def delete(self, bucket: str, key: str) -> bool:
        with self.lock:
            return (self.buckets.get(bucket) or {}).pop(key, None) is not None

    def list(self, bucket: str, prefix: str = "") -> list[tuple[str, Stored]]:
        return sorted((k, v) for k, v in (self.buckets.get(bucket) or {}).items()
                      if k.startswith(prefix))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def _md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _md5_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.md5(data).digest()).decode()


class _Handler(BaseHTTPRequestHandler):
    store: Store = None  # type: ignore[assignment]
    aws_access = DEFAULT_AWS_ACCESS
    aws_secret = DEFAULT_AWS_SECRET
    azure_account = DEFAULT_ACCOUNT
    azure_key = DEFAULT_AZURE_KEY
    gcs_token = "fake-gcs-token"

    def log_message(self, *args):  # 静默
        pass

    # ---------- HTTP helpers ----------
    def _send(self, status: int, body: bytes = b"", headers: dict | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, str(value))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    # ---------- auth ----------
    def _aws_auth(self, method: str, path: str, query: str, body: bytes) -> bool:
        auth = self.headers.get("Authorization", "")
        match = re.match(
            r"AWS4-HMAC-SHA256 Credential=([^/]+)/\d{8}/([^/]+)/s3/aws4_request, "
            r"SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$", auth)
        if not match:
            return False
        access, region, signed_headers, signature = match.groups()
        if access != self.aws_access:
            return False
        amz_date = self.headers.get("x-amz-date", "")
        payload_hash = self.headers.get("x-amz-content-sha256") or hashlib.sha256(body).hexdigest()
        canonical, expected_signed = aws_canonical_request(
            method, path, query, self.headers.get("Host", ""), amz_date, payload_hash)
        if signed_headers != expected_signed:
            return False
        expected = aws_signature(method, path, query, self.headers.get("Host", ""),
                                 amz_date, body, access, self.aws_secret, region, "s3")
        return hmac.compare_digest(signature, expected)

    def _azure_auth(self, method: str, path: str, query: str) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("SharedKey ") or not self.headers.get("x-ms-date"):
            return False
        account, _, provided = auth[len("SharedKey "):].partition(":")
        if account != self.azure_account:
            return False
        # path 去掉 /azure 前缀；canonical resource 从账号根开始
        rel = path[len("/azure"):] if path.startswith("/azure") else path
        expected = azure_signature(method, dict(self.headers), account, self.azure_key, rel, query)
        return hmac.compare_digest(provided, expected)

    def _gcs_auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        return auth.startswith("Bearer ") and bool(auth[7:].strip())

    # ---------- errors ----------
    def _aws_error(self, status: int, code: str, message: str) -> None:
        body = (f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>{escape(code)}</Code>'
                f'<Message>{escape(message)}</Message><RequestId>inkblade-mock</RequestId></Error>')
        self._send(status, body.encode(), {"Content-Type": "application/xml"})

    def _azure_error(self, status: int, code: str, message: str) -> None:
        body = (f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>{escape(code)}</Code>'
                f'<Message>{escape(message)}</Message></Error>')
        self._send(status, body.encode(), {"Content-Type": "application/xml"})

    def _gcs_error(self, status: int, code: int, message: str) -> None:
        body = json.dumps({"error": {"code": code, "message": message,
                                     "errors": [{"message": message, "domain": "global"}]}})
        self._send(status, body.encode(), {"Content-Type": "application/json"})

    # ---------- dispatch ----------
    def do_GET(self): self._handle("GET")
    def do_HEAD(self): self._handle("HEAD")
    def do_PUT(self): self._handle("PUT")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._handle("DELETE")

    def _handle(self, method: str) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path, query = parsed.path, parsed.query
        body = self._body()
        if path.startswith("/s3"):
            return self._aws(method, path[len("/s3"):] or "/", query, body)
        if path.startswith("/azure"):
            return self._azure(method, path, query, body)
        if path.startswith("/gcs"):
            return self._gcs(method, path[len("/gcs"):] or "/", query, body)
        if path == "/health":
            return self._send(200, b'{"ok":true}', {"Content-Type": "application/json"})
        self._send(404, b"not found")

    # ---------- AWS ----------
    def _aws(self, method: str, path: str, query: str, body: bytes) -> None:
        if not self._aws_auth(method, path, query, body):
            return self._aws_error(403, "SignatureDoesNotMatch", "SigV4 校验失败")
        parts = path.lstrip("/").split("/", 1)
        bucket = urllib.parse.unquote(parts[0]) if parts and parts[0] else ""
        key = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
        if not bucket:
            return self._aws_error(400, "InvalidRequest", "缺少 bucket")
        if method == "PUT" and not key:
            ok = self.store.create(bucket)
            if not ok:
                return self._aws_error(409, "BucketAlreadyOwnedByYou",
                                       "Your previous request to create the named bucket succeeded")
            return self._send(200, b"", {"Location": f"/{bucket}"})
        if method == "PUT":
            if not self.store.has_bucket(bucket):
                return self._aws_error(404, "NoSuchBucket", "The specified bucket does not exist")
            meta = {k[11:].lower(): v for k, v in self.headers.items()
                    if k.lower().startswith("x-amz-meta-")}
            stored = Stored(body, meta, self.headers.get("Content-Type", "application/octet-stream"), _now())
            self.store.put(bucket, key, stored)
            return self._send(200, b"", {"ETag": f'"{_md5_hex(body)}"'})
        if method in ("GET", "HEAD") and not key:
            if not self.store.has_bucket(bucket):
                return self._aws_error(404, "NoSuchBucket", "The specified bucket does not exist")
            q = urllib.parse.parse_qs(query, keep_blank_values=True)
            prefix = (q.get("prefix") or [""])[0]
            items = self.store.list(bucket, prefix)
            xml = ['<?xml version="1.0" encoding="UTF-8"?>',
                   '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">',
                   f"<Name>{escape(bucket)}</Name><Prefix>{escape(prefix)}</Prefix>",
                   f"<KeyCount>{len(items)}</KeyCount><MaxKeys>1000</MaxKeys>",
                   "<IsTruncated>false</IsTruncated>"]
            for name, obj in items:
                xml.append("<Contents>"
                           f"<Key>{escape(name)}</Key><LastModified>{obj.updated}</LastModified>"
                           f'<ETag>"{_md5_hex(obj.data)}"</ETag><Size>{len(obj.data)}</Size>'
                           "<StorageClass>STANDARD</StorageClass></Contents>")
            xml.append("</ListBucketResult>")
            return self._send(200, "".join(xml).encode(), {"Content-Type": "application/xml"})
        if method in ("GET", "HEAD"):
            obj = self.store.get(bucket, key)
            if obj is None:
                return self._aws_error(404, "NoSuchKey", "The specified key does not exist.")
            headers = {"ETag": f'"{_md5_hex(obj.data)}"', "Content-Type": obj.content_type,
                       "Last-Modified": obj.updated}
            for k, v in obj.metadata.items():
                headers[f"x-amz-meta-{k}"] = v
            return self._send(200, obj.data if method == "GET" else b"", headers)
        if method == "DELETE":
            if not key:
                if (self.store.buckets.get(bucket) or {}):
                    return self._aws_error(409, "BucketNotEmpty", "The bucket you tried to delete is not empty")
                self.store.buckets.pop(bucket, None)
                return self._send(204)
            self.store.delete(bucket, key)
            return self._send(204)
        self._aws_error(405, "MethodNotAllowed", method)

    # ---------- Azure ----------
    def _azure(self, method: str, path: str, query: str, body: bytes) -> None:
        if not self._azure_auth(method, path, query):
            return self._azure_error(403, "AuthenticationFailed",
                                     "Server failed to authenticate the request.")
        rel = path[len("/azure"):].lstrip("/")
        parts = rel.split("/", 1)
        container = urllib.parse.unquote(parts[0]) if parts and parts[0] else ""
        blob = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
        q = urllib.parse.parse_qs(query, keep_blank_values=True)
        if not container:
            return self._azure_error(400, "InvalidUri", "缺少 container")
        if method == "PUT" and not blob and (q.get("restype") or [""])[0] == "container":
            if not self.store.create(container):
                return self._azure_error(409, "ContainerAlreadyExists",
                                         "The specified container already exists.")
            return self._send(201, b"", {"ETag": f'"{_md5_hex(b"")}"'})
        if method == "PUT" and blob:
            if not self.store.has_bucket(container):
                return self._azure_error(404, "ContainerNotFound", "The specified container does not exist.")
            if self.headers.get("x-ms-blob-type") != "BlockBlob":
                return self._azure_error(400, "InvalidHeaderValue", "x-ms-blob-type must be BlockBlob")
            if self.headers.get("If-None-Match") == "*" and self.store.get(container, blob) is not None:
                return self._azure_error(409, "BlobAlreadyExists", "The specified blob already exists.")
            meta = {k[10:].lower(): v for k, v in self.headers.items()
                    if k.lower().startswith("x-ms-meta-")}
            stored = Stored(body, meta, self.headers.get("Content-Type", "application/octet-stream"), _now())
            self.store.put(container, blob, stored)
            return self._send(201, b"", {"ETag": f'"{_md5_hex(body)}"'})
        if method in ("GET", "HEAD") and not blob:
            if not self.store.has_bucket(container):
                return self._azure_error(404, "ContainerNotFound", "The specified container does not exist.")
            prefix = (q.get("prefix") or [""])[0]
            items = self.store.list(container, prefix)
            xml = ['<?xml version="1.0" encoding="UTF-8"?>',
                   f'<EnumerationResults ContainerName="{escape(container)}"><Prefix>{escape(prefix)}</Prefix><Blobs>']
            for name, obj in items:
                meta = "".join(f"<{escape(k)}>{escape(v)}</{escape(k)}>" for k, v in obj.metadata.items())
                xml.append(f"<Blob><Name>{escape(name)}</Name><Properties>"
                           f"<Last-Modified>{obj.updated}</Last-Modified>"
                           f'<Etag>"{_md5_hex(obj.data)}"</Etag>'
                           f"<Content-Length>{len(obj.data)}</Content-Length>"
                           f"<Content-Type>{escape(obj.content_type)}</Content-Type>"
                           f"</Properties><Metadata>{meta}</Metadata></Blob>")
            xml.append("</Blobs><NextMarker /></EnumerationResults>")
            return self._send(200, "".join(xml).encode(), {"Content-Type": "application/xml"})
        if method in ("GET", "HEAD"):
            obj = self.store.get(container, blob)
            if obj is None:
                return self._azure_error(404, "BlobNotFound", "The specified blob does not exist.")
            headers = {"ETag": f'"{_md5_hex(obj.data)}"', "Content-Type": obj.content_type,
                       "Last-Modified": obj.updated, "x-ms-blob-type": "BlockBlob"}
            for k, v in obj.metadata.items():
                headers[f"x-ms-meta-{k}"] = v
            return self._send(200, obj.data if method == "GET" else b"", headers)
        if method == "DELETE":
            if not self.store.delete(container, blob):
                return self._azure_error(404, "BlobNotFound", "The specified blob does not exist.")
            return self._send(202)
        self._azure_error(405, "MethodNotAllowed", method)

    # ---------- GCS ----------
    def _gcs(self, method: str, path: str, query: str, body: bytes) -> None:
        if not self._gcs_auth():
            return self._gcs_error(401, 401, "Anonymous caller does not have storage.objects access.")
        q = urllib.parse.parse_qs(query, keep_blank_values=True)
        if method == "POST" and path == "/storage/v1/b":
            doc = json.loads(body or b"{}")
            name = str(doc.get("name") or "")
            if not name:
                return self._gcs_error(400, 400, "bucket name required")
            if not self.store.create(name):
                return self._gcs_error(409, 409, f"Bucket {name} already exists")
            return self._send(200, json.dumps({"kind": "storage#bucket", "name": name}).encode(),
                              {"Content-Type": "application/json"})
        m = re.match(r"^/storage/v1/b/([^/]+)/o(?:/(.*))?$", path)
        if m and method in ("GET", "DELETE"):
            bucket = urllib.parse.unquote(m.group(1))
            key = urllib.parse.unquote(m.group(2) or "")
            if not key:
                prefix = (q.get("prefix") or [""])[0]
                items = [self._gcs_meta(bucket, k, obj) for k, obj in self.store.list(bucket, prefix)]
                return self._send(200, json.dumps({"kind": "storage#objects", "items": items}).encode(),
                                  {"Content-Type": "application/json"})
            obj = self.store.get(bucket, key)
            if obj is None:
                return self._gcs_error(404, 404, f"No such object: {bucket}/{key}")
            if method == "DELETE":
                self.store.delete(bucket, key)
                return self._send(204)
            if (q.get("alt") or [""])[0] == "media":
                return self._send(200, obj.data, {"Content-Type": obj.content_type,
                                                  "ETag": f'"{_md5_hex(obj.data)}"'})
            return self._send(200, json.dumps(self._gcs_meta(bucket, key, obj)).encode(),
                              {"Content-Type": "application/json"})
        m = re.match(r"^/upload/storage/v1/b/([^/]+)/o$", path)
        if m and method == "POST":
            bucket = urllib.parse.unquote(m.group(1))
            key = (q.get("name") or [""])[0]
            if not bucket or not key:
                return self._gcs_error(400, 400, "bucket and name required")
            if not self.store.has_bucket(bucket):
                return self._gcs_error(404, 404, f"No such bucket: {bucket}")
            meta = {k[12:].lower(): v for k, v in self.headers.items()
                    if k.lower().startswith("x-goog-meta-")}
            stored = Stored(body, meta, self.headers.get("Content-Type", "application/octet-stream"), _now())
            self.store.put(bucket, key, stored)
            return self._send(200, json.dumps(self._gcs_meta(bucket, key, stored)).encode(),
                              {"Content-Type": "application/json"})
        self._gcs_error(404, 404, f"No such route: {method} {path}")

    def _gcs_meta(self, bucket: str, key: str, obj: Stored) -> dict:
        return {"kind": "storage#object", "bucket": bucket, "name": key,
                "size": str(len(obj.data)), "md5Hash": _md5_b64(obj.data),
                "etag": _md5_b64(obj.data), "contentType": obj.content_type,
                "metadata": obj.metadata, "updated": obj.updated}


class MockCloudServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.store = Store()
        handler = type("BoundHandler", (_Handler,), {"store": self.store})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "MockCloudServer":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def __enter__(self): return self.start()
    def __exit__(self, *exc): self.stop()


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="InkBlade free-cloud mock endpoints")
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args(argv)
    server = MockCloudServer(port=args.port).start()
    print(f"mock cloud: {server.url}  (s3={server.url}/s3 azure={server.url}/azure gcs={server.url}/gcs)")
    try:
        server.thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
