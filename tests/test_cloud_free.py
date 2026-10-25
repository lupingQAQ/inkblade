# -*- coding: utf-8 -*-
"""免费/模拟三云对象存储：适配器 CRUD、签名、错误码、ETag/元数据语义、契约仿真。"""

import json
import unittest
import urllib.request
from pathlib import Path

from lab.cloud_free.adapters import (AwsS3Adapter, AzureBlobAdapter, CloudError,
                                     GcpStorageAdapter)
from lab.cloud_free.aliyun_tencent_contract import run as run_contract
from lab.cloud_free.mock_cloud import MockCloudServer

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "lab" / "cloud_free" / "docker-compose.yml"


class TestCloudFree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MockCloudServer().start()
        cls.aws = AwsS3Adapter(cls.server.url + "/s3")
        cls.azure = AzureBlobAdapter(cls.server.url + "/azure")
        cls.gcp = GcpStorageAdapter(cls.server.url + "/gcs")

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.server.store.buckets.clear()

    def test_aws_crud(self):
        self.aws.ensure_bucket("aws-b")
        obj = self.aws.put_object("aws-b", "weights/model.bin", b"hello", {"owner": "a"})
        self.assertEqual(obj.etag, "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(self.aws.get_object("aws-b", "weights/model.bin"), b"hello")
        head = self.aws.head_object("aws-b", "weights/model.bin")
        self.assertEqual(head.metadata, {"owner": "a"})
        self.assertEqual([x.key for x in self.aws.list_objects("aws-b", "weights/")],
                         ["weights/model.bin"])
        self.aws.delete_object("aws-b", "weights/model.bin")
        with self.assertRaises(CloudError) as ctx:
            self.aws.get_object("aws-b", "weights/model.bin")
        self.assertEqual((ctx.exception.status, ctx.exception.code), (404, "NoSuchKey"))

    def test_azure_crud(self):
        self.azure.ensure_bucket("azure-b")
        obj = self.azure.put_object("azure-b", "weights/model.bin", b"hello", {"owner": "a"})
        self.assertEqual(obj.etag, "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(self.azure.get_object("azure-b", "weights/model.bin"), b"hello")
        self.assertEqual(self.azure.head_object("azure-b", "weights/model.bin").metadata,
                         {"owner": "a"})
        self.assertEqual(len(self.azure.list_objects("azure-b")), 1)
        self.azure.delete_object("azure-b", "weights/model.bin")
        with self.assertRaises(CloudError) as ctx:
            self.azure.get_object("azure-b", "weights/model.bin")
        self.assertEqual((ctx.exception.status, ctx.exception.code), (404, "BlobNotFound"))

    def test_gcp_crud(self):
        self.gcp.ensure_bucket("gcp-b")
        obj = self.gcp.put_object("gcp-b", "weights/model.bin", b"hello", {"owner": "a"})
        self.assertEqual(obj.etag, "XUFAKrxLKna5cZ2REBfFkg==")
        self.assertEqual(self.gcp.get_object("gcp-b", "weights/model.bin"), b"hello")
        self.assertEqual(self.gcp.head_object("gcp-b", "weights/model.bin").metadata,
                         {"owner": "a"})
        self.assertEqual(len(self.gcp.list_objects("gcp-b", "weights/")), 1)
        self.gcp.delete_object("gcp-b", "weights/model.bin")
        with self.assertRaises(CloudError) as ctx:
            self.gcp.get_object("gcp-b", "weights/model.bin")
        self.assertEqual(ctx.exception.status, 404)

    def test_etag_and_metadata_semantics_differ(self):
        self.aws.ensure_bucket("b")
        self.azure.ensure_bucket("b")
        self.gcp.ensure_bucket("b")
        a = self.aws.put_object("b", "k", b"hello", {"Owner": "X"})
        z = self.azure.put_object("b", "k", b"hello", {"Owner": "X"})
        g = self.gcp.put_object("b", "k", b"hello", {"Owner": "X"})
        self.assertRegex(a.etag, r"^[0-9a-f]{32}$")
        self.assertEqual(a.etag, z.etag)
        self.assertNotEqual(a.etag, g.etag)
        self.assertEqual(self.aws.head_object("b", "k").metadata, {"owner": "X"})
        self.assertEqual(self.azure.head_object("b", "k").metadata, {"owner": "X"})
        self.assertEqual(self.gcp.head_object("b", "k").metadata, {"owner": "X"})

    def test_duplicate_bucket_codes(self):
        self.aws._request("PUT", "/dup", "", b"", self.aws._headers("PUT", "/dup", "", b""))
        status, _, body = self.aws._request("PUT", "/dup", "", b"",
                                            self.aws._headers("PUT", "/dup", "", b""))
        self.assertEqual(status, 409)
        self.assertIn(b"BucketAlreadyOwnedByYou", body)

        self.azure._request("PUT", "/dup", "restype=container", b"",
                            self.azure._headers("PUT", "/dup", "restype=container", b""))
        status, _, body = self.azure._request("PUT", "/dup", "restype=container", b"",
                                              self.azure._headers("PUT", "/dup", "restype=container", b""))
        self.assertEqual(status, 409)
        self.assertIn(b"ContainerAlreadyExists", body)

        payload = json.dumps({"name": "dup"}).encode()
        self.gcp._request("POST", "/storage/v1/b", "project=x", payload, self.gcp._headers())
        status, _, body = self.gcp._request("POST", "/storage/v1/b", "project=x", payload,
                                            self.gcp._headers())
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["error"]["code"], 409)

    def test_missing_auth_is_rejected(self):
        self.aws.ensure_bucket("b")
        for path in ("/s3/b/k", "/azure/b/k", "/gcs/storage/v1/b/b/o/k"):
            req = urllib.request.Request(self.server.url + path)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            self.assertIn(ctx.exception.code, (401, 403))

    def test_azure_blob_already_exists(self):
        self.azure.ensure_bucket("b")
        self.azure.put_object("b", "k", b"x")
        headers = self.azure._headers("PUT", "/b/k", "", b"y",
                                      {"x-ms-blob-type": "BlockBlob", "If-None-Match": "*"})
        status, _, body = self.azure._request("PUT", "/b/k", "", b"y", headers)
        self.assertEqual(status, 409)
        self.assertIn(b"BlobAlreadyExists", body)

    def test_aws_prefix_and_bucket_errors(self):
        self.aws.ensure_bucket("b")
        self.aws.put_object("b", "a/1", b"1")
        self.aws.put_object("b", "a/2", b"22")
        self.aws.put_object("b", "b/1", b"333")
        self.assertEqual([x.key for x in self.aws.list_objects("b", "a/")], ["a/1", "a/2"])
        self.assertEqual([x.key for x in self.aws.list_objects("b", "b/")], ["b/1"])
        with self.assertRaises(CloudError) as ctx:
            self.aws.put_object("missing", "k", b"x")
        self.assertEqual(ctx.exception.code, "NoSuchBucket")

    def test_azure_container_missing(self):
        with self.assertRaises(CloudError) as ctx:
            self.azure.put_object("missing", "k", b"x")
        self.assertEqual(ctx.exception.code, "ContainerNotFound")

    def test_gcs_missing_bucket(self):
        with self.assertRaises(CloudError) as ctx:
            self.gcp.put_object("missing", "k", b"x")
        self.assertEqual(ctx.exception.status, 404)

    def test_delete_semantics_differ(self):
        self.aws.ensure_bucket("b")
        self.aws.delete_object("b", "never")  # AWS 幂等 204
        self.azure.ensure_bucket("b")
        with self.assertRaises(CloudError):
            self.azure.delete_object("b", "never")  # Azure 404
        self.gcp.ensure_bucket("b")
        with self.assertRaises(CloudError):
            self.gcp.delete_object("b", "never")  # GCS 404

    def test_semantics_artifact_shape(self):
        out = REPO / "reports" / "samples" / "cloud-free" / "semantics.json"
        self.assertTrue(out.is_file())
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(set(doc["clouds"]), {"aws", "azure", "gcp"})
        for cloud in doc["clouds"].values():
            self.assertTrue(all(step["ok"] for step in cloud["steps"]))
        self.assertIn("python-mock-endpoints", doc["mode"])

    def test_contract_simulation_aliyun_tencent(self):
        with self.subTest("contract"):
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                doc = run_contract(Path(tmp) / "contract.json")
            for mode in ("vulnerable", "fixed"):
                self.assertEqual(doc[mode]["scenarios"], 8)
                self.assertEqual(doc[mode]["as_expected"], 8)
            self.assertEqual(doc["vulnerable"]["cross_tenant_ok"], 8)
            self.assertEqual(doc["fixed"]["cross_tenant_ok"], 0)

    def test_compose_declares_three_emulators(self):
        text = COMPOSE.read_text(encoding="utf-8")
        for token in ("localstack", "azurite", "fake-gcs-server", "4566:4566",
                      "10000:10000", "4443:4443"):
            self.assertIn(token, text)
        self.assertIn("Docker", (REPO / "lab" / "cloud_free" / "README.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
