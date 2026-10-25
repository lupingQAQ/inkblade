# lab/cloud_free — 免费/本地云对象存储语义与适配器

**状态：模拟验证**。本机（2026-10-25）没有 Docker，因此 `docker-compose.yml` 是交付待跑；
实际执行的是 `python-mock-endpoints`：同一套 `AwsS3Adapter` / `AzureBlobAdapter` /
`GcpStorageAdapter`，对本地三云 HTTP 端点做**真实 SigV4 / SharedKey 签名**、真实
XML/JSON 错误码与 ETag 语义。适配器把 endpoint 换成 LocalStack/Azurite/fake-gcs-server
即可复用，不改业务代码。

## 运行

```bash
python -m unittest tests.test_cloud_free -v
python lab/cloud_free/run_semantics.py
python lab/cloud_free/aliyun_tencent_contract.py
```

产物：

- `reports/samples/cloud-free/semantics.json`（AWS/Azure/GCP 适配器语义）
- `reports/samples/cloud-free/aliyun-tencent-contract.json`（契约仿真 24/24）

## 有 Docker 时

```bash
cd lab/cloud_free
docker compose up -d
# 适配器 endpoint：
#   AWS   http://127.0.0.1:4566         （path-style；access/secret 任意）
#   Azure http://127.0.0.1:10000        （account=devstoreaccount1，默认 key 见 Azurite 文档）
#   GCP   http://127.0.0.1:4443
docker compose down -v
```

> LocalStack 免费版仅覆盖部分服务；本实验只用 S3。Azurite/fake-gcs-server 为 MIT/Apache-2.0
> 开源 emulator。它们验证的是 API 语义，不是云厂商真实 IAM/网络/计费行为。
