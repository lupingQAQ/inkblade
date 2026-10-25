# Trident 实效验证报告（Effect Verification）

- 生成时间：2026-10-25T16:50:43Z
- 验证 Run：`effects-20261026-005037`；链 Run：`effects-chain-20261026-005037`
- 范围与边界：本机真实进程 + 真实 HTTP（127.0.0.1 回环 mock 靶场：mock_targets / longctx_sim / gpu_cloud_sim / ai_gateway_sim / fabric_dos_sim / hardware_sim）+ fake-kubectl 提权闭环（lab/privesc_sim.py）效果级验证；非 live K8s 集群 / 真实 GPU 驱动 / 真实 BMC / 真实交换机 / 真实云账号。KIND/ARTEX 需启用虚拟化后按 lab/kind 与 lab/bench 脚本执行；真集群提权见 docs/PRIVESC-VERIFICATION.md。
- 汇总：**31/31 PASS**（FAIL 0）

> **边界声明（必须随报告阅读）**：本验证为本机真实进程/真实 HTTP 效果级（`lab/mock_targets.py` + `lab/longctx_sim.py` + `lab/gpu_cloud_sim.py` + `lab/ai_gateway_sim.py`，仅 127.0.0.1），**非 live K8s 集群 / 真实 GPU 驱动 / 真实云账号**。KIND hostNetwork 绕过 NetworkPolicy 与 ARTEX（AGPL，黑盒对标）需启用虚拟化后，分别执行 `lab/kind/run-proof.sh` 与 `lab/bench/artex-bench.sh`；在虚拟化启用前，这两项不构成本报告的 PASS 结论。

| 项 | 验证内容 | 结果 | 证据摘要 |
|---|---|---|---|
| `admin-plane-failopen` | 未授权管理面利用：真实 HTTP 200 + 服务端状态文件变更 | PASS | {"http_status": 200, "route": "/pause", "state_file": "sglang/admin-state.json", "state_sha256_before": "5b377a070bfa3e011a6994667613cd33be1f9abed8c0a75e0547230dd4089318", "state_sha256_after": "fa1768345a1e8b9e487993c981b4d80a16f4bc9bfe1df234529700ff42471f4d", "state_applied": true, "state_response_sha256": "c46ede3dba5b44fb4b151835239ba0fac14a57d5dac21f2d57046e1ee390945f"} |
| `weight-poison-write` | 权重投毒实效：文件副本 sha256 变化 + benign marker | PASS | {"http_status": 200, "file": "slime/checkpoints_victim-TRIDENT-effects-20261026-005037/model.safetensors", "sha256_before": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "sha256_after": "19cd18ec5fd27762fba2f4f02a407684ae9fc749fd7dc873d2d43760308762ac", "marker": "TRIDENT-effects-20261026-005037", "marker_present": true, "server_weights_sha256": "19cd18ec5fd27762fba2f4f02a407684ae9fc749fd7dc8… |
| `backup-rollback` | 备份回滚实效：快照 → 投毒 → rollback 后 sha256 与原始完全一致 | PASS | {"rollback_rows": 1, "sha256_original": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "sha256_after_rollback": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "exact_restore": true, "backup_receipt_sha256": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0"} |
| `rce-marker` | RCE 实效：AReaL 三步链触发 mock 侧真实 marker 文件（含 run 标记） | PASS | {"http_statuses": {"set_env": 200, "create_engine": 200, "call": 200}, "marker_file": "areal/call/engine-8e676b49f9cf489796c4696eee7584cb-CALL.marker", "env_marker_file": "areal/env/ENV-SET.marker", "marker": "TRIDENT-effects-20261026-005037", "marker_present": true, "engine_id": "engine-8e676b49f9cf489796c4696eee7584cb"} |
| `gpu-tenant-residue-marker` | GPU 跨租户残留实效：benign marker 分配→释放→读回（含释放后）+ sha256 一致 | PASS | {"allocate_status": 200, "release_status": 200, "readback_status": 200, "victim_read_status": 200, "tenant": "tenant-a", "victim_tenant": "tenant-b", "device": "gpu-a-1", "victim_device": "gpu-b-0", "marker": "TRIDENT-BENIGN-RESIDUE-TRIDENT-effects-20261026-005037", "marker_sha256": "f100ee1e480d58aadabb3cadea838fa2cef20d5fc3418f68b3ea50f68986d163", "expected_marker_sha256": "f100ee1e480d58aadabb3cadea838fa2cef20d… |
| `cloud-assume-role-cross-account` | 云身份实效：通配 trust policy 跨账户 AssumeRole 成功（mock，凭据脱敏） | PASS | {"identity_status": 200, "assume_role_status": 200, "role_arn": "arn:aws:iam::222222222222:role/weight-reader", "source_account": "999999999999", "cross_account": true, "wildcard_principal": true, "trust_policy_principal": "*", "external_id_required": false, "masked_credentials": {"AccessKeyId": "MOCK****0001", "SecretAccessKey": "MOCK****0001", "SessionToken": "MOCK****0001"}, "full_credential_absent": true} |
| `cloud-bucket-public-listing` | 云桶实效：公共桶策略 + 跨租户列目录成功（权重/检查点清单） | PASS | {"policy_status": 200, "list_status": 200, "bucket": "weights-b", "bucket_owner": "tenant-b", "requester": "tenant-a", "public": true, "cross_tenant": true, "object_count": 3, "objects": ["tenant-b/model.safetensors", "tenant-b/checkpoint-00001.safetensors", "tenant-b/tokenizer.json"], "policy_principal": "*"} |
| `longctx-window-overflow` | 长上下文超窗实效：真实 HTTP 200 + prefill_tokens 超窗 + queue_depth 增长 | PASS | {"http_status": 200, "context_window_tokens": 131072, "prefill_tokens": 200000, "queue_depth_before": 0, "queue_depth_after": 1, "queue_depth_delta": 1, "prefill_pool": {"capacity": 4, "active": 1, "queued": 1}, "route": "/v1/chat/completions"} |
| `longctx-prefix-reuse` | prefix cache 跨租户实效：无 cache_salt 复用他租户 prefix（cached_tokens>0） | PASS | {"prime_status": 200, "reuse_status": 200, "prime_tenant": "tenant-a", "reuse_tenant": "tenant-b", "cache_salt_present_on_reuse": false, "cached_tokens": 4096, "cross_tenant": true, "route": "/v1/chat/completions"} |
| `longctx-kv-channel-write` | PD KV 通道实效：benign marker 真实写入并独立读回（sha256 一致） | PASS | {"write_status": 200, "readback_status": 200, "block_id": "kv-block-effects-20261026-005037", "readback_found": true, "readback_marker_present": true, "write_sha256": "3d5ce64beb2aa9ade332fc6bd884ef030ba68c7ae50f7fa58fe654e9ed22426f", "readback_sha256": "3d5ce64beb2aa9ade332fc6bd884ef030ba68c7ae50f7fa58fe654e9ed22426f", "bytes": 136} |
| `longctx-checkpoint-rollback` | checkpoint 分片实效：投毒 sha256 变化 + rollback 后 sha256 与原始完全一致 | PASS | {"http_status": 200, "shard_file": "checkpoints/trident-effects-shard.safetensors", "sha256_before": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645", "sha256_after": "3f4dde06b5dde1cd73fcad8976dd8aa02da441b22513407c9e33c2fe55ef6c3a", "sha256_after_rollback": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645", "rollback_rows": 1, "exact_restore": true, "marker_present": true, "wri… |
| `gateway-default-master-key-exfil` | AI 网关默认 master key：/config 读到上游 MOCK key，报告仅尾4位 | PASS | {"http_status": 200, "route": "/config", "master_key_class": "default", "master_key_used": true, "upstream_key_count": 2, "upstream_providers": ["openai", "anthropic"], "upstream_key_tail4": "9f3c", "upstream_key_masked": "MOCK****9f3c", "full_key_in_finding": false, "report_full_key_absent": true, "report_redacted_sample": "MOCK****9f3c"} |
| `gateway-forwarded-user-impersonation` | AI 网关伪造 X-Forwarded-User：admin 全局 key 视图 + 全租户日志 | PASS | {"impersonated_user": "admin", "key_info_status": 200, "scope": "global", "visible_tenants": ["tenant-a", "tenant-b"], "logs_status": 200, "logs_tenants": ["tenant-a", "tenant-b"], "log_entry_count": 3, "finding_count": 3} |
| `gateway-semantic-cache-cross-tenant` | AI 网关语义缓存跨租户：tenant-a 命中 tenant-b 缓存条目（共享前缀键） | PASS | {"requester_status": 200, "victim_status": 200, "hit": true, "requester_tenant": "tenant-a", "entry_tenant": "tenant-b", "cache_key": "sc:b918ca5cbe91e61a88057d63", "victim_cache_key": "sc:b918ca5cbe91e61a88057d63", "shared_key": true, "cross_tenant": true, "finding_count": 1} |
| `fabric-sharp-reduce-tamper` | SHARP 在网聚合实效：入组后 reduce 结果被改（前后值差分 + 服务端计数） | PASS | {"join_status": 200, "baseline_status": 200, "tamper_status": 200, "baseline_result": 36.0, "tampered_result": 108.0, "results_differ": true, "silent": true, "tampered_reduces": 1, "route": "/sharp/sessions,/sharp/reduce"} |
| `fabric-pfc-storm-counter` | PFC 风暴实效：配置写入后暂停帧计数暴增（≥50000） | PASS | {"read_status": 200, "pfc_pause_frames_before": 0, "pfc_pause_frames_after": 75000, "pfc_pause_frames_delta": 75000, "ecn_marks": 7500, "storm_active": true, "route": "/roce/pfc"} |
| `fabric-straggler-step-slowdown` | 慢 rank 注入实效：训练步时被拖慢 ≥2×（计时差分） | PASS | {"inject_status": 200, "baseline_step_ms": 120.0, "slowed_step_ms": 5120.0, "step_time_ratio": 42.667, "straggler_ms": 5000, "route": "/nccl/rank,/train/step"} |
| `hardware-bmc-default-credential` | BMC 默认凭据实效：Redfish 默认凭据登录 200 + IPMI/匿名管理面（mock） | PASS | {"http_status": 200, "default_login_status": 200, "default_username": "root", "credential_class": "vendor-default", "ipmi_over_lan": true, "ipmi_port": 623, "anonymous_manager_read": true, "accounts_status": 200, "network_protocol_status": 200, "detected": true, "route": "/redfish/v1/Systems/1"} |
| `hardware-firmware-manifest-tamper` | 固件清单篡改实效：blob 哈希不匹配（签名仍有效），finding 为 high | PASS | {"manifest": "firmware-tamper/manifest.json", "tampered_components": ["nvswitch-fw"], "expected_sha256": "66853eb2b3ab00c1a1bcc26b39fb2ddbdd017b49ae2e33aa7b2bf893aa6b1ff2", "actual_sha256": "42bd51ccbfacf041d5c3a1b77cf63c7a917d772d0741a3028fdcf80e9fb95756", "sha256_before": "66853eb2b3ab00c1a1bcc26b39fb2ddbdd017b49ae2e33aa7b2bf893aa6b1ff2", "sha256_after": "42bd51ccbfacf041d5c3a1b77cf63c7a917d772d0741a3028fdcf80e9… |
| `data-leak-redaction` | 数据泄露实效：fixture 假密钥仅尾4位进入报告 | PASS | {"finding_count": 5, "tail4": "wxyz", "redacted_sample": "****wxyz", "full_token_absent": true, "report_full_token_absent": true, "report_redacted_sample": "****wxyz"} |
| `rules-detection` | 检测规则实效：规则引擎对本次靶场重放 ≥1 条命中 | PASS | {"rules_evaluated": 89, "rules_detected": 64, "rules_blocked": 21, "rules_missed": 0, "hits": 85, "sample_hit": "flat-network-admin-plane-weight-poison · alert-combo-signature · 拦截", "matrix_ok": true, "coverage_file": "rules-coverage-matrix.json"} |
| `chain-e2e` | 端到端链：dry-run → execute（全影响演示级 + 备份 + 三层证据） | PASS | {"chain": "flat-network-admin-plane-weight-poison", "verdict": "部分成立", "missing": ["findings('framework-port-matching').reachable.any(port == 30000)"], "ok": true, "steps": {"admin-failopen-probe": "success", "weight-pull-poison": "success"}, "backup_receipts": 1, "weights_sha256_before": "3b3c43cbb5b6a9223cc39aea3d4f86a9ffe5bc3c25bb9162d9363dd950d012cb", "weights_sha256_after": "be12566924ef8386357fe08f615af3aec8… |
| `ray-job-rce-marker` | Ray 未授权 Job RCE：提交 entrypoint → 服务端 marker 落盘并读回 | PASS | {"submit_status": 200, "job_id": "raysubmit-846982b00ae84bfb9f63e98d75dda613", "marker": "TRIDENT-effects-20261026-005037", "marker_present": true, "marker_path": "<abs-path>", "marker_sha256": "b30f2d8207751e9f8d36946c162cb348e7ce9eee9b7b7950c6881cd246b4e019", "cleanup_deleted": 1, "cleanu… |
| `gateway-default-key-exfil` | AI 网关默认 key：sk-1234 → 上游 provider key 读取（仅尾 4 位入证据） | PASS | {"http_status": 200, "key_class": "default", "upstream_key_count": 2, "upstream_key_tail4": ["9f3c", "71ab"], "masked_only": true, "full_key_in_finding": false, "finding_cves": ["LITELLM-DEFAULT-KEY"]} |
| `ipmi-cipher-zero-bypass` | IPMI cipher zero 认证绕过：mock BMC 建立 admin 会话（真实协议 UDP/623） | PASS | {"auth_status": 200, "cipher": 0, "privilege": "admin", "username": "admin", "session": "ipmi-2baa45896e", "session_established": true, "finding_cves": ["CVE-2013-4786"]} |
| `redfish-default-credentials` | Redfish 默认凭据：admin/admin → BMC 管理员会话 + Systems 读取 | PASS | {"session_status": 201, "accepted_username": "admin", "token_issued": true, "systems_status": 200, "systems_name": "mock-node", "finding_cves": ["REDFISH-DEFAULT-CREDS", "CVE-2023-34329", "CVE-2017-12542"]} |
| `runc-surface-detection` | runc 逃逸面检测：只读快照判定 CVE-2024-21626 / CVE-2025-31133（unsupported 真硬件） | PASS | {"findings": 4, "cves": ["CVE-2022-0492", "CVE-2024-21626", "CVE-2025-31133"], "writes": false, "read_only": true, "fixture": "host-surface.json"} |
| `privesc-escalate` | escalate 动词改写已绑定角色 → cluster-admin | PASS | {"subject": "system:serviceaccount:lab:esc-sa", "before_admin": false, "after_admin": true, "escalate_allowed": true, "role_rules": [{"apiGroups": ["*"], "verbs": ["*"], "resources": ["*"]}]} |
| `privesc-bind` | bind cluster-admin + create CRB → cluster-admin | PASS | {"subject": "system:serviceaccount:lab:bind-sa", "before_admin": false, "after_admin": true, "binding_created": true, "role": "cluster-admin"} |
| `privesc-sa-token` | create serviceaccounts/token → 高权 SA 身份 | PASS | {"subject": "system:serviceaccount:lab:token-sa", "target_sa": "privesc-admin", "before_admin": false, "token_issued": true, "token_sha256_8": "cfdbb755", "authenticated_subject": "system:serviceaccount:lab:privesc-admin", "after_admin": true} |
| `privesc-webhook` | 写入准入 Webhook → Pod 注入 privileged/hostPath | PASS | {"subject": "system:serviceaccount:lab:webhook-sa", "before_can_create_pods": false, "webhook_written": true, "failure_policy": "Ignore", "pod_privileged": true, "host_root_mounted": true, "escape_primitive": true, "mutated_by": ["trident-injector"]} |

## 逐项证据

### admin-plane-failopen — PASS

```json
{
  "http_status": 200,
  "route": "/pause",
  "state_file": "sglang/admin-state.json",
  "state_sha256_before": "5b377a070bfa3e011a6994667613cd33be1f9abed8c0a75e0547230dd4089318",
  "state_sha256_after": "fa1768345a1e8b9e487993c981b4d80a16f4bc9bfe1df234529700ff42471f4d",
  "state_applied": true,
  "state_response_sha256": "c46ede3dba5b44fb4b151835239ba0fac14a57d5dac21f2d57046e1ee390945f"
}
```

### weight-poison-write — PASS

```json
{
  "http_status": 200,
  "file": "slime/checkpoints_victim-TRIDENT-effects-20261026-005037/model.safetensors",
  "sha256_before": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0",
  "sha256_after": "19cd18ec5fd27762fba2f4f02a407684ae9fc749fd7dc873d2d43760308762ac",
  "marker": "TRIDENT-effects-20261026-005037",
  "marker_present": true,
  "server_weights_sha256": "19cd18ec5fd27762fba2f4f02a407684ae9fc749fd7dc873d2d43760308762ac"
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
  "marker_file": "areal/call/engine-8e676b49f9cf489796c4696eee7584cb-CALL.marker",
  "env_marker_file": "areal/env/ENV-SET.marker",
  "marker": "TRIDENT-effects-20261026-005037",
  "marker_present": true,
  "engine_id": "engine-8e676b49f9cf489796c4696eee7584cb"
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
  "marker": "TRIDENT-BENIGN-RESIDUE-TRIDENT-effects-20261026-005037",
  "marker_sha256": "f100ee1e480d58aadabb3cadea838fa2cef20d5fc3418f68b3ea50f68986d163",
  "expected_marker_sha256": "f100ee1e480d58aadabb3cadea838fa2cef20d5fc3418f68b3ea50f68986d163",
  "readback_file_sha256": "966299135ddda8415dc21b253f26d260d61530fd585f50d9239d08ef9c6987fd",
  "residue_file_sha256": "966299135ddda8415dc21b253f26d260d61530fd585f50d9239d08ef9c6987fd",
  "actual_file_sha256": "966299135ddda8415dc21b253f26d260d61530fd585f50d9239d08ef9c6987fd",
  "residue_file": "gpu/residue/gpu-a-1/alloc-e5ca05ef35.json",
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
  "block_id": "kv-block-effects-20261026-005037",
  "readback_found": true,
  "readback_marker_present": true,
  "write_sha256": "3d5ce64beb2aa9ade332fc6bd884ef030ba68c7ae50f7fa58fe654e9ed22426f",
  "readback_sha256": "3d5ce64beb2aa9ade332fc6bd884ef030ba68c7ae50f7fa58fe654e9ed22426f",
  "bytes": 136
}
```

### longctx-checkpoint-rollback — PASS

```json
{
  "http_status": 200,
  "shard_file": "checkpoints/trident-effects-shard.safetensors",
  "sha256_before": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645",
  "sha256_after": "3f4dde06b5dde1cd73fcad8976dd8aa02da441b22513407c9e33c2fe55ef6c3a",
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

### fabric-sharp-reduce-tamper — PASS

```json
{
  "join_status": 200,
  "baseline_status": 200,
  "tamper_status": 200,
  "baseline_result": 36.0,
  "tampered_result": 108.0,
  "results_differ": true,
  "silent": true,
  "tampered_reduces": 1,
  "route": "/sharp/sessions,/sharp/reduce"
}
```

### fabric-pfc-storm-counter — PASS

```json
{
  "read_status": 200,
  "pfc_pause_frames_before": 0,
  "pfc_pause_frames_after": 75000,
  "pfc_pause_frames_delta": 75000,
  "ecn_marks": 7500,
  "storm_active": true,
  "route": "/roce/pfc"
}
```

### fabric-straggler-step-slowdown — PASS

```json
{
  "inject_status": 200,
  "baseline_step_ms": 120.0,
  "slowed_step_ms": 5120.0,
  "step_time_ratio": 42.667,
  "straggler_ms": 5000,
  "route": "/nccl/rank,/train/step"
}
```

### hardware-bmc-default-credential — PASS

```json
{
  "http_status": 200,
  "default_login_status": 200,
  "default_username": "root",
  "credential_class": "vendor-default",
  "ipmi_over_lan": true,
  "ipmi_port": 623,
  "anonymous_manager_read": true,
  "accounts_status": 200,
  "network_protocol_status": 200,
  "detected": true,
  "route": "/redfish/v1/Systems/1"
}
```

### hardware-firmware-manifest-tamper — PASS

```json
{
  "manifest": "firmware-tamper/manifest.json",
  "tampered_components": [
    "nvswitch-fw"
  ],
  "expected_sha256": "66853eb2b3ab00c1a1bcc26b39fb2ddbdd017b49ae2e33aa7b2bf893aa6b1ff2",
  "actual_sha256": "42bd51ccbfacf041d5c3a1b77cf63c7a917d772d0741a3028fdcf80e9fb95756",
  "sha256_before": "66853eb2b3ab00c1a1bcc26b39fb2ddbdd017b49ae2e33aa7b2bf893aa6b1ff2",
  "sha256_after": "42bd51ccbfacf041d5c3a1b77cf63c7a917d772d0741a3028fdcf80e9fb95756",
  "signature_status": "valid",
  "detected": true,
  "route": "firmware manifest + blob sha256"
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
  "rules_evaluated": 89,
  "rules_detected": 64,
  "rules_blocked": 21,
  "rules_missed": 0,
  "hits": 85,
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
  "weights_sha256_after": "be12566924ef8386357fe08f615af3aec89130b2d311d61847468ee8b67ad7d5",
  "marker_present": true,
  "layers": {
    "context": true,
    "database": true,
    "archives": 2,
    "manifest": true
  },
  "run": "effects-chain-20261026-005037"
}
```

### ray-job-rce-marker — PASS

```json
{
  "submit_status": 200,
  "job_id": "raysubmit-846982b00ae84bfb9f63e98d75dda613",
  "marker": "TRIDENT-effects-20261026-005037",
  "marker_present": true,
  "marker_path": "<abs-path>",
  "marker_sha256": "b30f2d8207751e9f8d36946c162cb348e7ce9eee9b7b7950c6881cd246b4e019",
  "cleanup_deleted": 1,
  "cleanup_removed": true,
  "cve": "CVE-2023-48022",
  "finding_cves": [
    "CVE-2023-48022",
    "CVE-2023-48023",
    "CVE-2026-32981"
  ],
  "artifact": null
}
```

### gateway-default-key-exfil — PASS

```json
{
  "http_status": 200,
  "key_class": "default",
  "upstream_key_count": 2,
  "upstream_key_tail4": [
    "9f3c",
    "71ab"
  ],
  "masked_only": true,
  "full_key_in_finding": false,
  "finding_cves": [
    "LITELLM-DEFAULT-KEY"
  ]
}
```

### ipmi-cipher-zero-bypass — PASS

```json
{
  "auth_status": 200,
  "cipher": 0,
  "privilege": "admin",
  "username": "admin",
  "session": "ipmi-2baa45896e",
  "session_established": true,
  "finding_cves": [
    "CVE-2013-4786"
  ]
}
```

### redfish-default-credentials — PASS

```json
{
  "session_status": 201,
  "accepted_username": "admin",
  "token_issued": true,
  "systems_status": 200,
  "systems_name": "mock-node",
  "finding_cves": [
    "REDFISH-DEFAULT-CREDS",
    "CVE-2023-34329",
    "CVE-2017-12542"
  ]
}
```

### runc-surface-detection — PASS

```json
{
  "findings": 4,
  "cves": [
    "CVE-2022-0492",
    "CVE-2024-21626",
    "CVE-2025-31133"
  ],
  "writes": false,
  "read_only": true,
  "fixture": "host-surface.json"
}
```

### privesc-escalate — PASS

```json
{
  "subject": "system:serviceaccount:lab:esc-sa",
  "before_admin": false,
  "after_admin": true,
  "escalate_allowed": true,
  "role_rules": [
    {
      "apiGroups": [
        "*"
      ],
      "verbs": [
        "*"
      ],
      "resources": [
        "*"
      ]
    }
  ]
}
```

### privesc-bind — PASS

```json
{
  "subject": "system:serviceaccount:lab:bind-sa",
  "before_admin": false,
  "after_admin": true,
  "binding_created": true,
  "role": "cluster-admin"
}
```

### privesc-sa-token — PASS

```json
{
  "subject": "system:serviceaccount:lab:token-sa",
  "target_sa": "privesc-admin",
  "before_admin": false,
  "token_issued": true,
  "token_sha256_8": "cfdbb755",
  "authenticated_subject": "system:serviceaccount:lab:privesc-admin",
  "after_admin": true
}
```

### privesc-webhook — PASS

```json
{
  "subject": "system:serviceaccount:lab:webhook-sa",
  "before_can_create_pods": false,
  "webhook_written": true,
  "failure_policy": "Ignore",
  "pod_privileged": true,
  "host_root_mounted": true,
  "escape_primitive": true,
  "mutated_by": [
    "trident-injector"
  ]
}
```

## 环境与限制

- python: `3.12.15`
- platform: `win32`
- mock_mode: `vulnerable`
- mock_host: `127.0.0.1`
- 限制：靶场为 lab/mock_targets.py + lab/longctx_sim.py + lab/gpu_cloud_sim.py + lab/ai_gateway_sim.py + lab/fabric_dos_sim.py + lab/hardware_sim.py 单进程仿真（仅 127.0.0.1），非真实 K8s API/容器运行时/GPU 推理/云账号。
- 限制：sglang/areal/slime 的写面以 mock server 侧真实文件落盘为证据，不是远端生产文件系统。
- 限制：长上下文仿真以 token 计数提示 + KV 计数器表达 128K–1M 窗口行为，不执行真实 attention/KV 传输。
- 限制：GPU 池化/云租户仿真以池状态文件与 benign marker 表达 MIG/MPS/显存残留与云身份/桶策略，不调用真实 nvidia-smi/STS/S3。
- 限制：AI 网关仿真为内存态（key/别名/缓存/配额/日志），上游 provider key 一律 MOCK 前缀；不连接真实模型厂商。
- 限制：fabric 破坏面仿真以内存计数器/状态位表达 SHARP 篡改、PFC 暂停帧、端口耗尽、I/O 洪与驱动复位等效果，不触碰真实交换机/IB SM/NCCL 进程/GPU 驱动；破坏效果均以计数器与状态变化度量（不真破坏）。
- 限制：硬件/交换机面为 lab/hardware_sim.py 的只读 mock（Redfish/SONiC/NVSwitch/DPU/telemetry）与 lab/hardware-fixtures 的合成 fixture；无真实 GPU/BMC/交换机验证，固件签名仅 HMAC fixture，不等于厂商 PKI/生产供应链。
- 限制：KIND hostNetwork 绕过 NetworkPolicy 实证需启用 WSL2/虚拟化后执行 lab/kind/run-proof.sh。
- 限制：ARTEX（AGPL）仅作外部黑盒对标，本仓库不复用其代码；对标需虚拟化环境执行 lab/bench/artex-bench.sh。
- 限制：提权 4 项（escalate/bind/SA token/webhook）使用 lab/privesc_sim.py 的 fake-kubectl 内存态闭环；QEMU k3s 真集群 4 条路径证据见 reports/samples/privesc/real-paths.json 与 docs/PRIVESC-VERIFICATION.md。

## 复现命令

```bash
python -m trident.verify-effects --out reports/samples/effects/
python -m unittest tests.test_verify_effects -v
```
