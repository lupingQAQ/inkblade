# Trident 实效验证报告（Effect Verification）

- 生成时间：2026-10-24T19:22:06Z
- 验证 Run：`effects-20261025-032204`；链 Run：`effects-chain-20261025-032204`
- 范围与边界：本机真实进程 + 真实 HTTP（127.0.0.1 回环 mock 靶场：mock_targets / longctx_sim / gpu_cloud_sim / ai_gateway_sim）效果级验证；非 live K8s 集群 / 真实 GPU 驱动 / 真实云账号。KIND/ARTEX 需启用虚拟化后按 lab/kind 与 lab/bench 脚本执行。
- 汇总：**17/17 PASS**（FAIL 0）

> **边界声明（必须随报告阅读）**：本验证为本机真实进程/真实 HTTP 效果级（`lab/mock_targets.py` + `lab/longctx_sim.py` + `lab/gpu_cloud_sim.py` + `lab/ai_gateway_sim.py`，仅 127.0.0.1），**非 live K8s 集群 / 真实 GPU 驱动 / 真实云账号**。KIND hostNetwork 绕过 NetworkPolicy 与 ARTEX（AGPL，黑盒对标）需启用虚拟化后，分别执行 `lab/kind/run-proof.sh` 与 `lab/bench/artex-bench.sh`；在虚拟化启用前，这两项不构成本报告的 PASS 结论。

| 项 | 验证内容 | 结果 | 证据摘要 |
|---|---|---|---|
| `admin-plane-failopen` | 未授权管理面利用：真实 HTTP 200 + 服务端状态文件变更 | PASS | {"http_status": 200, "route": "/pause", "state_file": "sglang/admin-state.json", "state_sha256_before": "5b377a070bfa3e011a6994667613cd33be1f9abed8c0a75e0547230dd4089318", "state_sha256_after": "e32bcf14d2c41e7bfb9abb39d9d6a75472d1e1a6db8df8e3fb7dce269e93f901", "state_applied": true, "state_response_sha256": "c20af1952456e3238b37b2f954263f4d96b2370f173ded12b35f3519a38d421a"} |
| `weight-poison-write` | 权重投毒实效：文件副本 sha256 变化 + benign marker | PASS | {"http_status": 200, "file": "slime/checkpoints_victim-TRIDENT-effects-20261025-032204/model.safetensors", "sha256_before": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "sha256_after": "90e5fd97f192a6b481676e6cd7b9e65d8894032d862e7b278ed6aa213ee6a4f7", "marker": "TRIDENT-effects-20261025-032204", "marker_present": true, "server_weights_sha256": "90e5fd97f192a6b481676e6cd7b9e65d8894032d862e7b… |
| `backup-rollback` | 备份回滚实效：快照 → 投毒 → rollback 后 sha256 与原始完全一致 | PASS | {"rollback_rows": 1, "sha256_original": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "sha256_after_rollback": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "exact_restore": true, "backup_receipt_sha256": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0"} |
| `rce-marker` | RCE 实效：AReaL 三步链触发 mock 侧真实 marker 文件（含 run 标记） | PASS | {"http_statuses": {"set_env": 200, "create_engine": 200, "call": 200}, "marker_file": "areal/call/engine-6433b7b35a374717a38c993df7622682-CALL.marker", "env_marker_file": "areal/env/ENV-SET.marker", "marker": "TRIDENT-effects-20261025-032204", "marker_present": true, "engine_id": "engine-6433b7b35a374717a38c993df7622682"} |
| `gpu-tenant-residue-marker` | GPU 跨租户残留实效：benign marker 分配→释放→读回（含释放后）+ sha256 一致 | PASS | {"allocate_status": 200, "release_status": 200, "readback_status": 200, "victim_read_status": 200, "tenant": "tenant-a", "victim_tenant": "tenant-b", "device": "gpu-a-1", "victim_device": "gpu-b-0", "marker": "TRIDENT-BENIGN-RESIDUE-TRIDENT-effects-20261025-032204", "marker_sha256": "1ed2d21f456aeb78b19d5729087016339498d7d5be7db6e5f5cd9542cda9dec3", "expected_marker_sha256": "1ed2d21f456aeb78b19d5729087016339498d7… |
| `cloud-assume-role-cross-account` | 云身份实效：通配 trust policy 跨账户 AssumeRole 成功（mock，凭据脱敏） | PASS | {"identity_status": 200, "assume_role_status": 200, "role_arn": "arn:aws:iam::222222222222:role/weight-reader", "source_account": "999999999999", "cross_account": true, "wildcard_principal": true, "trust_policy_principal": "*", "external_id_required": false, "masked_credentials": {"AccessKeyId": "MOCK****0001", "SecretAccessKey": "MOCK****0001", "SessionToken": "MOCK****0001"}, "full_credential_absent": true} |
| `cloud-bucket-public-listing` | 云桶实效：公共桶策略 + 跨租户列目录成功（权重/检查点清单） | PASS | {"policy_status": 200, "list_status": 200, "bucket": "weights-b", "bucket_owner": "tenant-b", "requester": "tenant-a", "public": true, "cross_tenant": true, "object_count": 3, "objects": ["tenant-b/model.safetensors", "tenant-b/checkpoint-00001.safetensors", "tenant-b/tokenizer.json"], "policy_principal": "*"} |
| `longctx-window-overflow` | 长上下文超窗实效：真实 HTTP 200 + prefill_tokens 超窗 + queue_depth 增长 | PASS | {"http_status": 200, "context_window_tokens": 131072, "prefill_tokens": 200000, "queue_depth_before": 0, "queue_depth_after": 1, "queue_depth_delta": 1, "prefill_pool": {"capacity": 4, "active": 1, "queued": 1}, "route": "/v1/chat/completions"} |
| `longctx-prefix-reuse` | prefix cache 跨租户实效：无 cache_salt 复用他租户 prefix（cached_tokens>0） | PASS | {"prime_status": 200, "reuse_status": 200, "prime_tenant": "tenant-a", "reuse_tenant": "tenant-b", "cache_salt_present_on_reuse": false, "cached_tokens": 4096, "cross_tenant": true, "route": "/v1/chat/completions"} |
| `longctx-kv-channel-write` | PD KV 通道实效：benign marker 真实写入并独立读回（sha256 一致） | PASS | {"write_status": 200, "readback_status": 200, "block_id": "kv-block-effects-20261025-032204", "readback_found": true, "readback_marker_present": true, "write_sha256": "ba03b66f69c00d9a955af8efde6f828b083032f4b9c34901ac280c5e2a42ff64", "readback_sha256": "ba03b66f69c00d9a955af8efde6f828b083032f4b9c34901ac280c5e2a42ff64", "bytes": 136} |
| `longctx-checkpoint-rollback` | checkpoint 分片实效：投毒 sha256 变化 + rollback 后 sha256 与原始完全一致 | PASS | {"http_status": 200, "shard_file": "checkpoints/trident-effects-shard.safetensors", "sha256_before": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645", "sha256_after": "e83c85b6c703033ddeea4766eded72c47c66fb048a008a2597f0660aae850099", "sha256_after_rollback": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645", "rollback_rows": 1, "exact_restore": true, "marker_present": true, "wri… |
| `gateway-default-master-key-exfil` | AI 网关默认 master key：/config 读到上游 MOCK key，报告仅尾4位 | PASS | {"http_status": 200, "route": "/config", "master_key_class": "default", "master_key_used": true, "upstream_key_count": 2, "upstream_providers": ["openai", "anthropic"], "upstream_key_tail4": "9f3c", "upstream_key_masked": "MOCK****9f3c", "full_key_in_finding": false, "report_full_key_absent": true, "report_redacted_sample": "MOCK****9f3c"} |
| `gateway-forwarded-user-impersonation` | AI 网关伪造 X-Forwarded-User：admin 全局 key 视图 + 全租户日志 | PASS | {"impersonated_user": "admin", "key_info_status": 200, "scope": "global", "visible_tenants": ["tenant-a", "tenant-b"], "logs_status": 200, "logs_tenants": ["tenant-a", "tenant-b"], "log_entry_count": 3, "finding_count": 3} |
| `gateway-semantic-cache-cross-tenant` | AI 网关语义缓存跨租户：tenant-a 命中 tenant-b 缓存条目（共享前缀键） | PASS | {"requester_status": 200, "victim_status": 200, "hit": true, "requester_tenant": "tenant-a", "entry_tenant": "tenant-b", "cache_key": "sc:b918ca5cbe91e61a88057d63", "victim_cache_key": "sc:b918ca5cbe91e61a88057d63", "shared_key": true, "cross_tenant": true, "finding_count": 1} |
| `data-leak-redaction` | 数据泄露实效：fixture 假密钥仅尾4位进入报告 | PASS | {"finding_count": 5, "tail4": "wxyz", "redacted_sample": "****wxyz", "full_token_absent": true, "report_full_token_absent": true, "report_redacted_sample": "****wxyz"} |
| `rules-detection` | 检测规则实效：规则引擎对本次靶场重放 ≥1 条命中 | PASS | {"rules_evaluated": 64, "rules_detected": 42, "rules_blocked": 18, "rules_missed": 0, "hits": 60, "sample_hit": "flat-network-admin-plane-weight-poison · alert-combo-signature · 拦截", "matrix_ok": true, "coverage_file": "rules-coverage-matrix.json"} |
| `chain-e2e` | 端到端链：dry-run → execute（全影响演示级 + 备份 + 三层证据） | PASS | {"chain": "flat-network-admin-plane-weight-poison", "verdict": "部分成立", "missing": ["findings('framework-port-matching').reachable.any(port == 30000)"], "ok": true, "steps": {"admin-failopen-probe": "success", "weight-pull-poison": "success"}, "backup_receipts": 1, "weights_sha256_before": "3b3c43cbb5b6a9223cc39aea3d4f86a9ffe5bc3c25bb9162d9363dd950d012cb", "weights_sha256_after": "5fe24cb695815a55ba6f13cd9798836d3f… |

## 逐项证据

### admin-plane-failopen — PASS

```json
{
  "http_status": 200,
  "route": "/pause",
  "state_file": "sglang/admin-state.json",
  "state_sha256_before": "5b377a070bfa3e011a6994667613cd33be1f9abed8c0a75e0547230dd4089318",
  "state_sha256_after": "e32bcf14d2c41e7bfb9abb39d9d6a75472d1e1a6db8df8e3fb7dce269e93f901",
  "state_applied": true,
  "state_response_sha256": "c20af1952456e3238b37b2f954263f4d96b2370f173ded12b35f3519a38d421a"
}
```

### weight-poison-write — PASS

```json
{
  "http_status": 200,
  "file": "slime/checkpoints_victim-TRIDENT-effects-20261025-032204/model.safetensors",
  "sha256_before": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0",
  "sha256_after": "90e5fd97f192a6b481676e6cd7b9e65d8894032d862e7b278ed6aa213ee6a4f7",
  "marker": "TRIDENT-effects-20261025-032204",
  "marker_present": true,
  "server_weights_sha256": "90e5fd97f192a6b481676e6cd7b9e65d8894032d862e7b278ed6aa213ee6a4f7"
}
```

### backup-rollback — PASS

```json
{
  "rollback_rows": 1,
  "sha256_original": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0",
  "sha256_after_rollback": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0",
  "exact_restore": true,
  "backup_receipt_sha256": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0"
}
```

### rce-marker — PASS

```json
{
  "http_statuses": {
    "set_env": 200,
    "create_engine": 200,
    "call": 200
  },
  "marker_file": "areal/call/engine-6433b7b35a374717a38c993df7622682-CALL.marker",
  "env_marker_file": "areal/env/ENV-SET.marker",
  "marker": "TRIDENT-effects-20261025-032204",
  "marker_present": true,
  "engine_id": "engine-6433b7b35a374717a38c993df7622682"
}
```

### gpu-tenant-residue-marker — PASS

```json
{
  "allocate_status": 200,
  "release_status": 200,
  "readback_status": 200,
  "victim_read_status": 200,
  "tenant": "tenant-a",
  "victim_tenant": "tenant-b",
  "device": "gpu-a-1",
  "victim_device": "gpu-b-0",
  "marker": "TRIDENT-BENIGN-RESIDUE-TRIDENT-effects-20261025-032204",
  "marker_sha256": "1ed2d21f456aeb78b19d5729087016339498d7d5be7db6e5f5cd9542cda9dec3",
  "expected_marker_sha256": "1ed2d21f456aeb78b19d5729087016339498d7d5be7db6e5f5cd9542cda9dec3",
  "readback_file_sha256": "71dbe718f27d41076a20c62a26d0cc33dbf160701645dbe59ec968def0e112c1",
  "residue_file_sha256": "71dbe718f27d41076a20c62a26d0cc33dbf160701645dbe59ec968def0e112c1",
  "actual_file_sha256": "71dbe718f27d41076a20c62a26d0cc33dbf160701645dbe59ec968def0e112c1",
  "residue_file": "gpu/residue/gpu-a-1/alloc-e40b201bd1.json",
  "readback_after_release": true,
  "victim_marker_sha256": "20e59e65ff218abffa5bd1af1ddd62e9f4571ff762b408c8e26dd171235b0fad",
  "victim_readable": true
}
```

### cloud-assume-role-cross-account — PASS

```json
{
  "identity_status": 200,
  "assume_role_status": 200,
  "role_arn": "arn:aws:iam::222222222222:role/weight-reader",
  "source_account": "999999999999",
  "cross_account": true,
  "wildcard_principal": true,
  "trust_policy_principal": "*",
  "external_id_required": false,
  "masked_credentials": {
    "AccessKeyId": "MOCK****0001",
    "SecretAccessKey": "MOCK****0001",
    "SessionToken": "MOCK****0001"
  },
  "full_credential_absent": true
}
```

### cloud-bucket-public-listing — PASS

```json
{
  "policy_status": 200,
  "list_status": 200,
  "bucket": "weights-b",
  "bucket_owner": "tenant-b",
  "requester": "tenant-a",
  "public": true,
  "cross_tenant": true,
  "object_count": 3,
  "objects": [
    "tenant-b/model.safetensors",
    "tenant-b/checkpoint-00001.safetensors",
    "tenant-b/tokenizer.json"
  ],
  "policy_principal": "*"
}
```

### longctx-window-overflow — PASS

```json
{
  "http_status": 200,
  "context_window_tokens": 131072,
  "prefill_tokens": 200000,
  "queue_depth_before": 0,
  "queue_depth_after": 1,
  "queue_depth_delta": 1,
  "prefill_pool": {
    "capacity": 4,
    "active": 1,
    "queued": 1
  },
  "route": "/v1/chat/completions"
}
```

### longctx-prefix-reuse — PASS

```json
{
  "prime_status": 200,
  "reuse_status": 200,
  "prime_tenant": "tenant-a",
  "reuse_tenant": "tenant-b",
  "cache_salt_present_on_reuse": false,
  "cached_tokens": 4096,
  "cross_tenant": true,
  "route": "/v1/chat/completions"
}
```

### longctx-kv-channel-write — PASS

```json
{
  "write_status": 200,
  "readback_status": 200,
  "block_id": "kv-block-effects-20261025-032204",
  "readback_found": true,
  "readback_marker_present": true,
  "write_sha256": "ba03b66f69c00d9a955af8efde6f828b083032f4b9c34901ac280c5e2a42ff64",
  "readback_sha256": "ba03b66f69c00d9a955af8efde6f828b083032f4b9c34901ac280c5e2a42ff64",
  "bytes": 136
}
```

### longctx-checkpoint-rollback — PASS

```json
{
  "http_status": 200,
  "shard_file": "checkpoints/trident-effects-shard.safetensors",
  "sha256_before": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645",
  "sha256_after": "e83c85b6c703033ddeea4766eded72c47c66fb048a008a2597f0660aae850099",
  "sha256_after_rollback": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645",
  "rollback_rows": 1,
  "exact_restore": true,
  "marker_present": true,
  "write_status": 200
}
```

### gateway-default-master-key-exfil — PASS

```json
{
  "http_status": 200,
  "route": "/config",
  "master_key_class": "default",
  "master_key_used": true,
  "upstream_key_count": 2,
  "upstream_providers": [
    "openai",
    "anthropic"
  ],
  "upstream_key_tail4": "9f3c",
  "upstream_key_masked": "MOCK****9f3c",
  "full_key_in_finding": false,
  "report_full_key_absent": true,
  "report_redacted_sample": "MOCK****9f3c"
}
```

### gateway-forwarded-user-impersonation — PASS

```json
{
  "impersonated_user": "admin",
  "key_info_status": 200,
  "scope": "global",
  "visible_tenants": [
    "tenant-a",
    "tenant-b"
  ],
  "logs_status": 200,
  "logs_tenants": [
    "tenant-a",
    "tenant-b"
  ],
  "log_entry_count": 3,
  "finding_count": 3
}
```

### gateway-semantic-cache-cross-tenant — PASS

```json
{
  "requester_status": 200,
  "victim_status": 200,
  "hit": true,
  "requester_tenant": "tenant-a",
  "entry_tenant": "tenant-b",
  "cache_key": "sc:b918ca5cbe91e61a88057d63",
  "victim_cache_key": "sc:b918ca5cbe91e61a88057d63",
  "shared_key": true,
  "cross_tenant": true,
  "finding_count": 1
}
```

### data-leak-redaction — PASS

```json
{
  "finding_count": 5,
  "tail4": "wxyz",
  "redacted_sample": "****wxyz",
  "full_token_absent": true,
  "report_full_token_absent": true,
  "report_redacted_sample": "****wxyz"
}
```

### rules-detection — PASS

```json
{
  "rules_evaluated": 64,
  "rules_detected": 42,
  "rules_blocked": 18,
  "rules_missed": 0,
  "hits": 60,
  "sample_hit": "flat-network-admin-plane-weight-poison · alert-combo-signature · 拦截",
  "matrix_ok": true,
  "coverage_file": "rules-coverage-matrix.json"
}
```

### chain-e2e — PASS

```json
{
  "chain": "flat-network-admin-plane-weight-poison",
  "verdict": "部分成立",
  "missing": [
    "findings('framework-port-matching').reachable.any(port == 30000)"
  ],
  "ok": true,
  "steps": {
    "admin-failopen-probe": "success",
    "weight-pull-poison": "success"
  },
  "backup_receipts": 1,
  "weights_sha256_before": "3b3c43cbb5b6a9223cc39aea3d4f86a9ffe5bc3c25bb9162d9363dd950d012cb",
  "weights_sha256_after": "5fe24cb695815a55ba6f13cd9798836d3f48bc73cfbfccaa1ba4799e755277cf",
  "marker_present": true,
  "layers": {
    "context": true,
    "database": true,
    "archives": 2,
    "manifest": true
  },
  "run": "effects-chain-20261025-032204"
}
```

## 环境与限制

- python: `3.12.15`
- platform: `win32`
- mock_mode: `vulnerable`
- mock_host: `127.0.0.1`
- 限制：靶场为 lab/mock_targets.py + lab/longctx_sim.py + lab/gpu_cloud_sim.py + lab/ai_gateway_sim.py 单进程仿真（仅 127.0.0.1），非真实 K8s API/容器运行时/GPU 推理/云账号。
- 限制：sglang/areal/slime 的写面以 mock server 侧真实文件落盘为证据，不是远端生产文件系统。
- 限制：长上下文仿真以 token 计数提示 + KV 计数器表达 128K–1M 窗口行为，不执行真实 attention/KV 传输。
- 限制：GPU 池化/云租户仿真以池状态文件与 benign marker 表达 MIG/MPS/显存残留与云身份/桶策略，不调用真实 nvidia-smi/STS/S3。
- 限制：AI 网关仿真为内存态（key/别名/缓存/配额/日志），上游 provider key 一律 MOCK 前缀；不连接真实模型厂商。
- 限制：KIND hostNetwork 绕过 NetworkPolicy 实证需启用 WSL2/虚拟化后执行 lab/kind/run-proof.sh。
- 限制：ARTEX（AGPL）仅作外部黑盒对标，本仓库不复用其代码；对标需虚拟化环境执行 lab/bench/artex-bench.sh。

## 复现命令

```bash
python -m trident.verify-effects --out reports/samples/effects/
python -m unittest tests.test_verify_effects -v
```
