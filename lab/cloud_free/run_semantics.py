# -*- coding: utf-8 -*-
"""跑三云适配器语义表并写 reports/samples/cloud-free/semantics.json（确定性）。"""
from __future__ import annotations

import argparse
import json
import urllib.parse
from pathlib import Path

if __package__ in (None, ""):  # `python lab/cloud_free/run_semantics.py`
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from lab.cloud_free.adapters import (AwsS3Adapter, AzureBlobAdapter, CloudError,
                                         GcpStorageAdapter)
    from lab.cloud_free.mock_cloud import MockCloudServer
else:
    from .adapters import AwsS3Adapter, AzureBlobAdapter, CloudError, GcpStorageAdapter
    from .mock_cloud import MockCloudServer

REPO = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO / "reports" / "samples" / "cloud-free" / "semantics.json"


def _etag_kind(etag: str) -> str:
    return "hex-md5" if len(etag) == 32 and all(c in "0123456789abcdef" for c in etag) else "base64"


def _run(adapter, bucket: str) -> dict:
    steps: list[dict] = []
    adapter.ensure_bucket(bucket)
    obj = adapter.put_object(bucket, "weights/model.bin", b"inkblade-cloud-free", {"owner": "tenant-a"})
    steps.append({"op": "put", "ok": True, "etag_kind": _etag_kind(obj.etag)})
    got = adapter.get_object(bucket, "weights/model.bin")
    steps.append({"op": "get", "ok": got == b"inkblade-cloud-free", "bytes": len(got)})
    head = adapter.head_object(bucket, "weights/model.bin")
    steps.append({"op": "head", "ok": head.metadata.get("owner") == "tenant-a",
                  "metadata_keys": sorted(head.metadata)})
    listed = adapter.list_objects(bucket, prefix="weights/")
    steps.append({"op": "list", "ok": [x.key for x in listed] == ["weights/model.bin"],
                  "count": len(listed)})
    adapter.delete_object(bucket, "weights/model.bin")
    try:
        adapter.get_object(bucket, "weights/model.bin")
        missing = None
    except CloudError as exc:
        missing = {"status": exc.status, "code": exc.code}
    steps.append({"op": "get-missing", "ok": missing is not None, "error": missing})
    return {"steps": steps}


def run(out: Path | str | None = None) -> dict:
    path = Path(out) if out else DEFAULT_OUT
    server = MockCloudServer().start()
    try:
        result = {
            "schema": "inkblade-cloud-free-semantics/2026-10",
            "mode": "python-mock-endpoints (Docker/LocalStack absent on this host)",
            "clouds": {
                "aws": _run(AwsS3Adapter(server.url + "/s3"), "inkblade-aws"),
                "azure": _run(AzureBlobAdapter(server.url + "/azure"), "inkblade-azure"),
                "gcp": _run(GcpStorageAdapter(server.url + "/gcs"), "inkblade-gcp"),
            },
            "note": "语义/签名/错误码可复现；不是真实云账号或官方 emulator",
        }
    finally:
        server.stop()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)
    result = run(args.out)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
