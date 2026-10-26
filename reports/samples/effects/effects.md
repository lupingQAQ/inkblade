# Trident 实效验证报告（Effect Verification）

- 生成时间：2026-10-26T09:05:47Z
- 验证 Run：`effects-20261026-170531`；链 Run：`effects-chain-20261026-170531`
- 范围与边界：本机真实进程 + 真实 HTTP（127.0.0.1 回环 mock 靶场：mock_targets / longctx_sim / gpu_cloud_sim / ai_gateway_sim / fabric_dos_sim / hardware_sim / chipsec_sim）+ fake-kubectl 提权闭环（lab/privesc_sim.py）效果级验证；非 live K8s 集群 / 真实 GPU 驱动 / 真实 BMC / 真实交换机 / 真实云账号 / 硅片实验室。KIND/ARTEX 需启用虚拟化后按 lab/kind 与 lab/bench 脚本执行；真集群提权见 docs/PRIVESC-VERIFICATION.md。
- 汇总：**53/53 PASS**（FAIL 0）

> **边界声明（必须随报告阅读）**：本验证为本机真实进程/真实 HTTP 效果级（`lab/mock_targets.py` + `lab/longctx_sim.py` + `lab/gpu_cloud_sim.py` + `lab/ai_gateway_sim.py`，仅 127.0.0.1），**非 live K8s 集群 / 真实 GPU 驱动 / 真实云账号**。KIND hostNetwork 绕过 NetworkPolicy 与 ARTEX（AGPL，黑盒对标）需启用虚拟化后，分别执行 `lab/kind/run-proof.sh` 与 `lab/bench/artex-bench.sh`；在虚拟化启用前，这两项不构成本报告的 PASS 结论。

| 项 | 验证内容 | 结果 | 证据摘要 |
|---|---|---|---|
| `admin-plane-failopen` | 未授权管理面利用：真实 HTTP 200 + 服务端状态文件变更 | PASS | {"http_status": 200, "route": "/pause", "state_file": "sglang/admin-state.json", "state_sha256_before": "5b377a070bfa3e011a6994667613cd33be1f9abed8c0a75e0547230dd4089318", "state_sha256_after": "be465ea63024243f2cc56bead086739d82c8d95a93923b08ce98ad5d0f1c1ca2", "state_applied": true, "state_response_sha256": "a87ff9d4adea46b33c9c3a28e5f84927c3fc4b0ba78b0fe20e234a55d2530bb4"} |
| `weight-poison-write` | 权重投毒实效：文件副本 sha256 变化 + benign marker | PASS | {"http_status": 200, "file": "slime/checkpoints_victim-TRIDENT-effects-20261026-170531/model.safetensors", "sha256_before": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "sha256_after": "139098a60af8f28d3230ec3ea0a27d4a6e501e10a971daf424badde3daf46534", "marker": "TRIDENT-effects-20261026-170531", "marker_present": true, "server_weights_sha256": "139098a60af8f28d3230ec3ea0a27d4a6e501e10a971da… |
| `backup-rollback` | 备份回滚实效：快照 → 投毒 → rollback 后 sha256 与原始完全一致 | PASS | {"rollback_rows": 1, "sha256_original": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "sha256_after_rollback": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "exact_restore": true, "backup_receipt_sha256": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0"} |
| `rce-marker` | RCE 实效：AReaL 三步链触发 mock 侧真实 marker 文件（含 run 标记） | PASS | {"http_statuses": {"set_env": 200, "create_engine": 200, "call": 200}, "marker_file": "areal/call/engine-0845a128e1ab4c50947de01a94df6f9c-CALL.marker", "env_marker_file": "areal/env/ENV-SET.marker", "marker": "TRIDENT-effects-20261026-170531", "marker_present": true, "engine_id": "engine-0845a128e1ab4c50947de01a94df6f9c"} |
| `gpu-tenant-residue-marker` | GPU 跨租户残留实效：benign marker 分配→释放→读回（含释放后）+ sha256 一致 | PASS | {"allocate_status": 200, "release_status": 200, "readback_status": 200, "victim_read_status": 200, "tenant": "tenant-a", "victim_tenant": "tenant-b", "device": "gpu-a-1", "victim_device": "gpu-b-0", "marker": "TRIDENT-BENIGN-RESIDUE-TRIDENT-effects-20261026-170531", "marker_sha256": "2d6783a9219ac01e16d91320eff4080837b68549f22d67b3c449aa620689d004", "expected_marker_sha256": "2d6783a9219ac01e16d91320eff4080837b685… |
| `cloud-assume-role-cross-account` | 云身份实效：通配 trust policy 跨账户 AssumeRole 成功（mock，凭据脱敏） | PASS | {"identity_status": 200, "assume_role_status": 200, "role_arn": "arn:aws:iam::222222222222:role/weight-reader", "source_account": "999999999999", "cross_account": true, "wildcard_principal": true, "trust_policy_principal": "*", "external_id_required": false, "masked_credentials": {"AccessKeyId": "MOCK****0001", "SecretAccessKey": "MOCK****0001", "SessionToken": "MOCK****0001"}, "full_credential_absent": true} |
| `cloud-bucket-public-listing` | 云桶实效：公共桶策略 + 跨租户列目录成功（权重/检查点清单） | PASS | {"policy_status": 200, "list_status": 200, "bucket": "weights-b", "bucket_owner": "tenant-b", "requester": "tenant-a", "public": true, "cross_tenant": true, "object_count": 3, "objects": ["tenant-b/model.safetensors", "tenant-b/checkpoint-00001.safetensors", "tenant-b/tokenizer.json"], "policy_principal": "*"} |
| `longctx-window-overflow` | 长上下文超窗实效：真实 HTTP 200 + prefill_tokens 超窗 + queue_depth 增长 | PASS | {"http_status": 200, "context_window_tokens": 131072, "prefill_tokens": 200000, "queue_depth_before": 0, "queue_depth_after": 1, "queue_depth_delta": 1, "prefill_pool": {"capacity": 4, "active": 1, "queued": 1}, "route": "/v1/chat/completions"} |
| `longctx-prefix-reuse` | prefix cache 跨租户实效：无 cache_salt 复用他租户 prefix（cached_tokens>0） | PASS | {"prime_status": 200, "reuse_status": 200, "prime_tenant": "tenant-a", "reuse_tenant": "tenant-b", "cache_salt_present_on_reuse": false, "cached_tokens": 4096, "cross_tenant": true, "route": "/v1/chat/completions"} |
| `longctx-kv-channel-write` | PD KV 通道实效：benign marker 真实写入并独立读回（sha256 一致） | PASS | {"write_status": 200, "readback_status": 200, "block_id": "kv-block-effects-20261026-170531", "readback_found": true, "readback_marker_present": true, "write_sha256": "87bd3e7d6e8ecd1faa2b5713f14228b0ca4fda9237ae54380a3c3b505bc187fc", "readback_sha256": "87bd3e7d6e8ecd1faa2b5713f14228b0ca4fda9237ae54380a3c3b505bc187fc", "bytes": 136} |
| `longctx-checkpoint-rollback` | checkpoint 分片实效：投毒 sha256 变化 + rollback 后 sha256 与原始完全一致 | PASS | {"http_status": 200, "shard_file": "checkpoints/trident-effects-shard.safetensors", "sha256_before": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645", "sha256_after": "d71b6bbda39004d432845a9de496172b36a69ebe5bceb2ef88f77cb51737c4cb", "sha256_after_rollback": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645", "rollback_rows": 1, "exact_restore": true, "marker_present": true, "wri… |
| `gateway-default-master-key-exfil` | AI 网关默认 master key：/config 读到上游 MOCK key，报告仅尾4位 | PASS | {"http_status": 200, "route": "/config", "master_key_class": "default", "master_key_used": true, "upstream_key_count": 2, "upstream_providers": ["openai", "anthropic"], "upstream_key_tail4": "9f3c", "upstream_key_masked": "MOCK****9f3c", "full_key_in_finding": false, "report_full_key_absent": true, "report_redacted_sample": "MOCK****9f3c"} |
| `gateway-forwarded-user-impersonation` | AI 网关伪造 X-Forwarded-User：admin 全局 key 视图 + 全租户日志 | PASS | {"impersonated_user": "admin", "key_info_status": 200, "scope": "global", "visible_tenants": ["tenant-a", "tenant-b"], "logs_status": 200, "logs_tenants": ["tenant-a", "tenant-b"], "log_entry_count": 3, "finding_count": 3} |
| `gateway-semantic-cache-cross-tenant` | AI 网关语义缓存跨租户：tenant-a 命中 tenant-b 缓存条目（共享前缀键） | PASS | {"requester_status": 200, "victim_status": 200, "hit": true, "requester_tenant": "tenant-a", "entry_tenant": "tenant-b", "cache_key": "sc:b918ca5cbe91e61a88057d63", "victim_cache_key": "sc:b918ca5cbe91e61a88057d63", "shared_key": true, "cross_tenant": true, "finding_count": 1} |
| `fabric-sharp-reduce-tamper` | SHARP 在网聚合实效：入组后 reduce 结果被改（前后值差分 + 服务端计数） | PASS | {"join_status": 200, "baseline_status": 200, "tamper_status": 200, "baseline_result": 36.0, "tampered_result": 108.0, "results_differ": true, "silent": true, "tampered_reduces": 1, "route": "/sharp/sessions,/sharp/reduce"} |
| `fabric-pfc-storm-counter` | PFC 风暴实效：配置写入后暂停帧计数暴增（≥50000） | PASS | {"read_status": 200, "pfc_pause_frames_before": 0, "pfc_pause_frames_after": 75000, "pfc_pause_frames_delta": 75000, "ecn_marks": 7500, "storm_active": true, "route": "/roce/pfc"} |
| `fabric-straggler-step-slowdown` | 慢 rank 注入实效：训练步时被拖慢 ≥2×（计时差分） | PASS | {"inject_status": 200, "baseline_step_ms": 120.0, "slowed_step_ms": 5120.0, "step_time_ratio": 42.667, "straggler_ms": 5000, "route": "/nccl/rank,/train/step"} |
| `hardware-bmc-default-credential` | BMC 默认凭据实效：Redfish 默认凭据登录 200 + IPMI/匿名管理面（mock） | PASS | {"http_status": 200, "default_login_status": 200, "default_username": "root", "credential_class": "vendor-default", "ipmi_over_lan": true, "ipmi_port": 623, "anonymous_manager_read": true, "accounts_status": 200, "network_protocol_status": 200, "detected": true, "route": "/redfish/v1/Systems/1"} |
| `hardware-firmware-manifest-tamper` | 固件清单篡改实效：blob 哈希不匹配（签名仍有效），finding 为 high | PASS | {"manifest": "firmware-tamper/manifest.json", "tampered_components": ["nvswitch-fw"], "expected_sha256": "66853eb2b3ab00c1a1bcc26b39fb2ddbdd017b49ae2e33aa7b2bf893aa6b1ff2", "actual_sha256": "42bd51ccbfacf041d5c3a1b77cf63c7a917d772d0741a3028fdcf80e9fb95756", "sha256_before": "66853eb2b3ab00c1a1bcc26b39fb2ddbdd017b49ae2e33aa7b2bf893aa6b1ff2", "sha256_after": "42bd51ccbfacf041d5c3a1b77cf63c7a917d772d0741a3028fdcf80e9… |
| `chip-cc-attestation-tamper` | GPU CC 证明篡改实效：有效 JWT 通过、改 payload 后验签失败（NRAS JWKS） | PASS | {"valid_high": 0, "valid_signature_valid": true, "tampered_high": 3, "signature_valid": false, "claims_valid": false, "nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", "jwks_source": "inline", "detected": true, "route": "/chip/gpu-cc + NRAS fixture JWKS"} |
| `chip-iommu-passthrough` | IOMMU 直通实效：vulnerable iommu=pt + 多设备 identity 组 → high；fixed 无 high | PASS | {"passthrough": true, "iommu_enabled": true, "risky_groups": 1, "kernel_cmdline": "intel_iommu=on iommu=pt iommu.passthrough=1", "fixed_high": 0, "detected": true, "route": "/chip/iommu vulnerable/fixed"} |
| `chip-pcr-baseline-offset` | PCR 基线偏移实效：PCR 0/4 与 golden 不一致 → high；fixed 0 偏移 | PASS | {"pcr_mismatches": 2, "mismatched_pcrs": ["0", "4"], "uki_signature_valid": false, "fixed_mismatches": 0, "fixed_high": 0, "detected": true, "route": "/chip/boot vulnerable/fixed"} |
| `chip-gpu-memory-residue` | 显存残留实效：benign marker 释放后读回 + sha256 一致 → high；fixed 404 | PASS | {"readback_status": 200, "marker_sha256": "6a2a729b0f2383d29564437edc3a5c11c09bed4cf0e3dabb52b7093c9722c0d9", "marker_sha256_match": true, "readable_after_release": true, "zeroized": false, "fixed_readback_status": 404, "fixed_high": 0, "detected": true, "route": "/chip/gpu/allocate → release → residue"} |
| `infra2026-coco-attestation-mismatch` | CoCo 证明实效：SEV-SNP 测量值与预期不一致且 debug 开启，finding 为 high | PASS | {"http_status": 200, "tee": "sev-snp", "measurement": "sha256:1111000000000000000000000000000000000000000000000000000000000000", "expected_measurement": "sha256:2222000000000000000000000000000000000000000000000000000000000000", "debug": true, "policy_enforced": false, "detected": true, "route": "/coco/attestation,/coco/policy"} |
| `infra2026-spire-wildcard-identity` | SPIRE 实效：通配 SPIFFE ID + 无选择器 + admin 无 ACL，finding 为 high | PASS | {"http_status": 200, "trust_domain": "example.org", "entries": 3, "wildcard_entries": 2, "admin_acl": false, "detected": true, "route": "/spire/entries"} |
| `infra2026-pq-tls-weak-posture` | 后量子 TLS 实效：TLS1.2 + RSA 密钥交换 + 无 hybrid group，finding 为 high | PASS | {"http_status": 200, "min_version": "TLS1.2", "key_exchange": "rsa", "hybrid_group": "", "hndl_exposed": true, "detected": true, "route": "/tls/posture"} |
| `data-leak-redaction` | 数据泄露实效：fixture 假密钥仅尾4位进入报告 | PASS | {"finding_count": 5, "tail4": "wxyz", "redacted_sample": "****wxyz", "full_token_absent": true, "report_full_token_absent": true, "report_redacted_sample": "****wxyz"} |
| `rules-detection` | 检测规则实效：规则引擎对本次靶场重放 ≥1 条命中 | PASS | {"rules_evaluated": 98, "rules_detected": 73, "rules_blocked": 21, "rules_missed": 0, "hits": 94, "sample_hit": "flat-network-admin-plane-weight-poison · alert-combo-signature · 拦截", "matrix_ok": true, "coverage_file": "rules-coverage-matrix.json"} |
| `chain-e2e` | 端到端链：dry-run → execute（全影响演示级 + 备份 + 三层证据） | PASS | {"chain": "flat-network-admin-plane-weight-poison", "verdict": "部分成立", "missing": ["findings('framework-port-matching').reachable.any(port == 30000)"], "ok": true, "steps": {"admin-failopen-probe": "success", "weight-pull-poison": "success"}, "backup_receipts": 1, "weights_sha256_before": "3b3c43cbb5b6a9223cc39aea3d4f86a9ffe5bc3c25bb9162d9363dd950d012cb", "weights_sha256_after": "130b76be088c2ed17659968e76e0ba7611… |
| `trainstack-optimizer-state-marker` | optimizer state 实效：benign marker 写入并读回（sha256 一致）+ 回滚精确复原 | PASS | {"http_statuses": {"write": 200, "read": 200}, "shard_file": "ckpt/optimizer/ckpt-optim-effects.pt", "sha256_before": "8804d39c121c3316936add5d8d85dc80796a7059e20eb52002ee79ad5be02a8b", "sha256_after": "930dd0691ffb6b0ad9c95cea5180ef25ce27f7c9948c0568ba5f4664209f7606", "sha256_after_rollback": "8804d39c121c3316936add5d8d85dc80796a7059e20eb52002ee79ad5be02a8b", "readback_sha256": "930dd0691ffb6b0ad9c95cea5180ef25ce… |
| `trainstack-data-tamper-detect` | 数据采样篡改实效：分片追加重复/未知样本，采样器重算 sha256 检出并可回滚 | PASS | {"http_status": 200, "shard_file": "data/shard-0001.jsonl", "appended": 3, "expected_sha256": "8521aa8852f1c7ee2820779014dcc7858687acf5a9391f3d964eee116d838052", "actual_sha256": "a43903116484770c2bfb2cd5485afd3374120a1c3adc5d8b9b3b35a444602afd", "tamper_detected": true, "duplicate_ids": 1, "unknown_ids": 1, "order_changed": true, "sha256_after_rollback": "8521aa8852f1c7ee2820779014dcc7858687acf5a9391f3d964eee116d… |
| `trainstack-template-injection-detect` | 模板注入实效：system 槽被注入 run marker 指令并检出（原样渲染）+ 回滚精确复原 | PASS | {"http_status": 200, "template_file": "tokenizer/template.jinja", "sha256_before": "261786c1a0f44d3a24640c75cfa471aa18ddb2aadaaaf202bb904d4af29db4a8", "sha256_after": "288ee8ad6453d5eaf2a824bfee374ffc33043e797f2a87549438406155122775", "template_modified": true, "injected_directive": true, "sanitized": false, "system_block_sha256": "d2cf31bc19345be3ad3eea0110fa7d37d1ddcd3c887f897e62b36b4b932a669b", "marker": "TRIDE… |
| `residual-hypervisor-audit-race` | R01 实效：guest 内采集器 + 可写日志 + 竞态窗口 → high；fixed 0 high | PASS | {"vulnerable_high": 6, "collector_location": "guest", "guest_writable_log": true, "race_window_ms": 1200, "fixed_high": 0, "detected": true} |
| `residual-agent-skill-poison` | R02 实效：未签名 skill + curl|sh 安装 → critical；fixed 0 high | PASS | {"vulnerable_critical": 1, "skills": 2, "signature_required": false, "fixed_high": 0, "detected": true} |
| `residual-operator-cross-namespace` | R03 实效：Operator 全 ns watch + CR 跨 ns 引用 Secret → high；fixed 0 high | PASS | {"vulnerable_high": 5, "cross_namespace_refs": 2, "operators": 1, "fixed_high": 0, "detected": true} |
| `residual-mcp-control-plane` | R04 实效：MCP 无认证/0.0.0.0/通配工具 → critical；fixed 0 high | PASS | {"vulnerable_critical": 1, "servers": 1, "signed_registry": false, "fixed_high": 0, "detected": true} |
| `slurm-jwt-weak-key` | Slurm JWT 实效：短 HS256 + 0644 key + 无轮换/过期 → high；fixed 0 high | PASS | {"vulnerable_high": 5, "weak_hs_keys": 1, "key_file_mode": "0644", "max_token_lifetime_seconds": 0, "fixed_high": 0, "detected": true} |
| `slurm-cgroup-device-escape` | Slurm cgroup 实效：核心/内存/设备约束全关 → high；fixed 0 high | PASS | {"vulnerable_high": 6, "constrain_cores": false, "constrain_ram": false, "constrain_devices": false, "fixed_high": 0, "detected": true} |
| `ray-job-rce-marker` | Ray 未授权 Job RCE：提交 entrypoint → 服务端 marker 落盘并读回 | PASS | {"submit_status": 200, "job_id": "raysubmit-143eba50259e44c4ac5770756ef40a67", "marker": "TRIDENT-effects-20261026-170531", "marker_present": true, "marker_path": "<abs-path>", "marker_sha256": "3a068d2c2beb925a5c1925e620e817e4f8adf5a8858e674c45512d6bd89c501e", "cleanup_deleted": 1, "cleanu… |
| `gateway-default-key-exfil` | AI 网关默认 key：sk-1234 → 上游 provider key 读取（仅尾 4 位入证据） | PASS | {"http_status": 200, "key_class": "default", "upstream_key_count": 2, "upstream_key_tail4": ["9f3c", "71ab"], "masked_only": true, "full_key_in_finding": false, "finding_cves": ["LITELLM-DEFAULT-KEY"]} |
| `ipmi-cipher-zero-bypass` | IPMI cipher zero 认证绕过：mock BMC 建立 admin 会话（真实协议 UDP/623） | PASS | {"auth_status": 200, "cipher": 0, "privilege": "admin", "username": "admin", "session": "ipmi-0378382fd2", "session_established": true, "finding_cves": ["CVE-2013-4786"]} |
| `redfish-default-credentials` | Redfish 默认凭据：admin/admin → BMC 管理员会话 + Systems 读取 | PASS | {"session_status": 201, "accepted_username": "admin", "token_issued": true, "systems_status": 200, "systems_name": "mock-node", "finding_cves": ["REDFISH-DEFAULT-CREDS", "CVE-2023-34329", "CVE-2017-12542"]} |
| `runc-surface-detection` | runc 逃逸面检测：只读快照判定 CVE-2024-21626 / CVE-2025-31133（unsupported 真硬件） | PASS | {"findings": 4, "cves": ["CVE-2022-0492", "CVE-2024-21626", "CVE-2025-31133"], "writes": false, "read_only": true, "fixture": "host-surface.json"} |
| `depth-vllm-fuzz` | vLLM 五接口面 240 用例差分：vulnerable vs fixed 真实 HTTP | PASS | {"cases": 240, "vulnerable_bypasses": 144, "fixed_bypasses": 0, "control_status": 401, "surfaces_hit": ["admin", "dev-mode", "plugin", "serialization", "weights"], "fixed_control_status": 401, "vulnerable_results_sha256": "1c68f5b8301a8ef2002d4ba32220a7ec5b476698f477c29458491cc600562eaf", "fixed_results_sha256": "eae1ccd2a5e764bec5965743ef574994cc3667f0062d88d97b0c2dd43eb5aa1e", "matrix_entries": 40, "fixed_pairs"… |
| `depth-admission-semantics` | Kyverno/Gatekeeper 20 语义用例：vulnerable 准入 vs 加固拒绝 | PASS | {"cases": 20, "vulnerable_admitted": 20, "hardened_admitted": 0, "findings": 20, "mechanisms": ["audit-mode", "crd-conversion", "dryrun", "ephemeral-container", "exemption", "init-container", "mutation-order", "parameter-wildcard", "precondition", "scope", "subresource"], "results_sha256": "cef2cf8d75f3aa5bb7a4b4a780219f11ba97fcc62a6d19f09955f4929b5caae6"} |
| `depth-ebpf-blindspot` | Falco/Tetragon 14 事件覆盖：默认 missed vs 加固全覆盖 | PASS | {"cases": 14, "missed": 14, "hardened_missed": 0, "coverage_gaps": 6, "categories": {"short-lived": 2, "syscall-filter": 5, "post-escape": 3, "host-network": 2, "child-process": 1, "container-identity": 1}, "results_sha256": "0f0b530d3a587923ef6499f72f39bf76b86fc00c01e6ae08610fb52e8905b957"} |
| `depth-gpu-operator-config` | GPU Operator 20 检查：privileged/MIG/DCGM/DRA 差分 | PASS | {"checks": 20, "findings": 19, "critical": 5, "high": 13, "hardened_findings": 0, "domains": ["dcgm", "device-plugin", "dra", "driver", "mig", "workload"], "snapshot_sha256": "f20dc58ffb66760d98ee77460c8cfa72a0537c200faec4918ede1a21d609a61d"} |
| `depth-sonic-fabric-link` | SONiC/IB/SHARP 28 检查 + fabric_sim PFC 场景联动 | PASS | {"checks": 28, "failed": 28, "hardened_failed": 0, "domains": ["ib", "sharp", "sonic"], "scenarios": ["pfc-storm", "ecn", "rail-mismatch"], "detectors": ["fabric.pfc-pause-storm"], "baseline": ["fabric.baseline-clean"], "nodes": 1024, "snapshot_sha256": "d169da6b68ceefc45147640c01ebef02e57eb250c088f740177ed949ea9decae"} |
| `depth-identity-federation` | IRSA/RRSA/PodIdentity/GCP/Azure 21 信任用例差分 | PASS | {"cases": 21, "allowed": 21, "hardened_allowed": 0, "legit_allowed": 21, "findings": 21, "categories": ["audience-wildcard", "empty-set", "external-id-optional", "missing-condition", "oidc-confusion", "source-account-missing", "subject-wildcard", "wildcard-principal"], "results_sha256": "b2257d302192db6258eb8917f81844400ea00d4ed82c3b494db1675952206716"} |
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
  "state_sha256_after": "be465ea63024243f2cc56bead086739d82c8d95a93923b08ce98ad5d0f1c1ca2",
  "state_applied": true,
  "state_response_sha256": "a87ff9d4adea46b33c9c3a28e5f84927c3fc4b0ba78b0fe20e234a55d2530bb4"
}
```

### weight-poison-write — PASS

```json
{
  "http_status": 200,
  "file": "slime/checkpoints_victim-TRIDENT-effects-20261026-170531/model.safetensors",
  "sha256_before": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0",
  "sha256_after": "139098a60af8f28d3230ec3ea0a27d4a6e501e10a971daf424badde3daf46534",
  "marker": "TRIDENT-effects-20261026-170531",
  "marker_present": true,
  "server_weights_sha256": "139098a60af8f28d3230ec3ea0a27d4a6e501e10a971daf424badde3daf46534"
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
  "marker_file": "areal/call/engine-0845a128e1ab4c50947de01a94df6f9c-CALL.marker",
  "env_marker_file": "areal/env/ENV-SET.marker",
  "marker": "TRIDENT-effects-20261026-170531",
  "marker_present": true,
  "engine_id": "engine-0845a128e1ab4c50947de01a94df6f9c"
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
  "marker": "TRIDENT-BENIGN-RESIDUE-TRIDENT-effects-20261026-170531",
  "marker_sha256": "2d6783a9219ac01e16d91320eff4080837b68549f22d67b3c449aa620689d004",
  "expected_marker_sha256": "2d6783a9219ac01e16d91320eff4080837b68549f22d67b3c449aa620689d004",
  "readback_file_sha256": "c86c89f4788dfcf0c091b36ac7f8e67e83a3167fdf7a972eaa79903673c9497b",
  "residue_file_sha256": "c86c89f4788dfcf0c091b36ac7f8e67e83a3167fdf7a972eaa79903673c9497b",
  "actual_file_sha256": "c86c89f4788dfcf0c091b36ac7f8e67e83a3167fdf7a972eaa79903673c9497b",
  "residue_file": "gpu/residue/gpu-a-1/alloc-65c0e3df06.json",
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
  "block_id": "kv-block-effects-20261026-170531",
  "readback_found": true,
  "readback_marker_present": true,
  "write_sha256": "87bd3e7d6e8ecd1faa2b5713f14228b0ca4fda9237ae54380a3c3b505bc187fc",
  "readback_sha256": "87bd3e7d6e8ecd1faa2b5713f14228b0ca4fda9237ae54380a3c3b505bc187fc",
  "bytes": 136
}
```

### longctx-checkpoint-rollback — PASS

```json
{
  "http_status": 200,
  "shard_file": "checkpoints/trident-effects-shard.safetensors",
  "sha256_before": "8922fec3b98bc9b255761d7208df88911a8c790c3709026dc4a8cc448cda6645",
  "sha256_after": "d71b6bbda39004d432845a9de496172b36a69ebe5bceb2ef88f77cb51737c4cb",
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

### chip-cc-attestation-tamper — PASS

```json
{
  "valid_high": 0,
  "valid_signature_valid": true,
  "tampered_high": 3,
  "signature_valid": false,
  "claims_valid": false,
  "nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "jwks_source": "inline",
  "detected": true,
  "route": "/chip/gpu-cc + NRAS fixture JWKS"
}
```

### chip-iommu-passthrough — PASS

```json
{
  "passthrough": true,
  "iommu_enabled": true,
  "risky_groups": 1,
  "kernel_cmdline": "intel_iommu=on iommu=pt iommu.passthrough=1",
  "fixed_high": 0,
  "detected": true,
  "route": "/chip/iommu vulnerable/fixed"
}
```

### chip-pcr-baseline-offset — PASS

```json
{
  "pcr_mismatches": 2,
  "mismatched_pcrs": [
    "0",
    "4"
  ],
  "uki_signature_valid": false,
  "fixed_mismatches": 0,
  "fixed_high": 0,
  "detected": true,
  "route": "/chip/boot vulnerable/fixed"
}
```

### chip-gpu-memory-residue — PASS

```json
{
  "readback_status": 200,
  "marker_sha256": "6a2a729b0f2383d29564437edc3a5c11c09bed4cf0e3dabb52b7093c9722c0d9",
  "marker_sha256_match": true,
  "readable_after_release": true,
  "zeroized": false,
  "fixed_readback_status": 404,
  "fixed_high": 0,
  "detected": true,
  "route": "/chip/gpu/allocate → release → residue"
}
```

### infra2026-coco-attestation-mismatch — PASS

```json
{
  "http_status": 200,
  "tee": "sev-snp",
  "measurement": "sha256:1111000000000000000000000000000000000000000000000000000000000000",
  "expected_measurement": "sha256:2222000000000000000000000000000000000000000000000000000000000000",
  "debug": true,
  "policy_enforced": false,
  "detected": true,
  "route": "/coco/attestation,/coco/policy"
}
```

### infra2026-spire-wildcard-identity — PASS

```json
{
  "http_status": 200,
  "trust_domain": "example.org",
  "entries": 3,
  "wildcard_entries": 2,
  "admin_acl": false,
  "detected": true,
  "route": "/spire/entries"
}
```

### infra2026-pq-tls-weak-posture — PASS

```json
{
  "http_status": 200,
  "min_version": "TLS1.2",
  "key_exchange": "rsa",
  "hybrid_group": "",
  "hndl_exposed": true,
  "detected": true,
  "route": "/tls/posture"
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
  "rules_evaluated": 98,
  "rules_detected": 73,
  "rules_blocked": 21,
  "rules_missed": 0,
  "hits": 94,
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
  "weights_sha256_after": "130b76be088c2ed17659968e76e0ba7611d03f1509c2c84bccc08d5b2744c3ac",
  "marker_present": true,
  "layers": {
    "context": true,
    "database": true,
    "archives": 2,
    "manifest": true
  },
  "run": "effects-chain-20261026-170531"
}
```

### trainstack-optimizer-state-marker — PASS

```json
{
  "http_statuses": {
    "write": 200,
    "read": 200
  },
  "shard_file": "ckpt/optimizer/ckpt-optim-effects.pt",
  "sha256_before": "8804d39c121c3316936add5d8d85dc80796a7059e20eb52002ee79ad5be02a8b",
  "sha256_after": "930dd0691ffb6b0ad9c95cea5180ef25ce27f7c9948c0568ba5f4664209f7606",
  "sha256_after_rollback": "8804d39c121c3316936add5d8d85dc80796a7059e20eb52002ee79ad5be02a8b",
  "readback_sha256": "930dd0691ffb6b0ad9c95cea5180ef25ce27f7c9948c0568ba5f4664209f7606",
  "marker": "TRIDENT-effects-20261026-170531",
  "marker_present": true,
  "optimizer_state": true,
  "rollback_rows": 1,
  "exact_restore": true
}
```

### trainstack-data-tamper-detect — PASS

```json
{
  "http_status": 200,
  "shard_file": "data/shard-0001.jsonl",
  "appended": 3,
  "expected_sha256": "8521aa8852f1c7ee2820779014dcc7858687acf5a9391f3d964eee116d838052",
  "actual_sha256": "a43903116484770c2bfb2cd5485afd3374120a1c3adc5d8b9b3b35a444602afd",
  "tamper_detected": true,
  "duplicate_ids": 1,
  "unknown_ids": 1,
  "order_changed": true,
  "sha256_after_rollback": "8521aa8852f1c7ee2820779014dcc7858687acf5a9391f3d964eee116d838052",
  "exact_restore": true
}
```

### trainstack-template-injection-detect — PASS

```json
{
  "http_status": 200,
  "template_file": "tokenizer/template.jinja",
  "sha256_before": "261786c1a0f44d3a24640c75cfa471aa18ddb2aadaaaf202bb904d4af29db4a8",
  "sha256_after": "288ee8ad6453d5eaf2a824bfee374ffc33043e797f2a87549438406155122775",
  "template_modified": true,
  "injected_directive": true,
  "sanitized": false,
  "system_block_sha256": "d2cf31bc19345be3ad3eea0110fa7d37d1ddcd3c887f897e62b36b4b932a669b",
  "marker": "TRIDENT-effects-20261026-170531",
  "marker_in_system_block": true,
  "sha256_after_rollback": "261786c1a0f44d3a24640c75cfa471aa18ddb2aadaaaf202bb904d4af29db4a8",
  "rollback_rows": 1,
  "exact_restore": true
}
```

### residual-hypervisor-audit-race — PASS

```json
{
  "vulnerable_high": 6,
  "collector_location": "guest",
  "guest_writable_log": true,
  "race_window_ms": 1200,
  "fixed_high": 0,
  "detected": true
}
```

### residual-agent-skill-poison — PASS

```json
{
  "vulnerable_critical": 1,
  "skills": 2,
  "signature_required": false,
  "fixed_high": 0,
  "detected": true
}
```

### residual-operator-cross-namespace — PASS

```json
{
  "vulnerable_high": 5,
  "cross_namespace_refs": 2,
  "operators": 1,
  "fixed_high": 0,
  "detected": true
}
```

### residual-mcp-control-plane — PASS

```json
{
  "vulnerable_critical": 1,
  "servers": 1,
  "signed_registry": false,
  "fixed_high": 0,
  "detected": true
}
```

### slurm-jwt-weak-key — PASS

```json
{
  "vulnerable_high": 5,
  "weak_hs_keys": 1,
  "key_file_mode": "0644",
  "max_token_lifetime_seconds": 0,
  "fixed_high": 0,
  "detected": true
}
```

### slurm-cgroup-device-escape — PASS

```json
{
  "vulnerable_high": 6,
  "constrain_cores": false,
  "constrain_ram": false,
  "constrain_devices": false,
  "fixed_high": 0,
  "detected": true
}
```

### ray-job-rce-marker — PASS

```json
{
  "submit_status": 200,
  "job_id": "raysubmit-143eba50259e44c4ac5770756ef40a67",
  "marker": "TRIDENT-effects-20261026-170531",
  "marker_present": true,
  "marker_path": "<abs-path>",
  "marker_sha256": "3a068d2c2beb925a5c1925e620e817e4f8adf5a8858e674c45512d6bd89c501e",
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
  "session": "ipmi-0378382fd2",
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

### depth-vllm-fuzz — PASS

```json
{
  "cases": 240,
  "vulnerable_bypasses": 144,
  "fixed_bypasses": 0,
  "control_status": 401,
  "surfaces_hit": [
    "admin",
    "dev-mode",
    "plugin",
    "serialization",
    "weights"
  ],
  "fixed_control_status": 401,
  "vulnerable_results_sha256": "1c68f5b8301a8ef2002d4ba32220a7ec5b476698f477c29458491cc600562eaf",
  "fixed_results_sha256": "eae1ccd2a5e764bec5965743ef574994cc3667f0062d88d97b0c2dd43eb5aa1e",
  "matrix_entries": 40,
  "fixed_pairs": 32
}
```

### depth-admission-semantics — PASS

```json
{
  "cases": 20,
  "vulnerable_admitted": 20,
  "hardened_admitted": 0,
  "findings": 20,
  "mechanisms": [
    "audit-mode",
    "crd-conversion",
    "dryrun",
    "ephemeral-container",
    "exemption",
    "init-container",
    "mutation-order",
    "parameter-wildcard",
    "precondition",
    "scope",
    "subresource"
  ],
  "results_sha256": "cef2cf8d75f3aa5bb7a4b4a780219f11ba97fcc62a6d19f09955f4929b5caae6"
}
```

### depth-ebpf-blindspot — PASS

```json
{
  "cases": 14,
  "missed": 14,
  "hardened_missed": 0,
  "coverage_gaps": 6,
  "categories": {
    "short-lived": 2,
    "syscall-filter": 5,
    "post-escape": 3,
    "host-network": 2,
    "child-process": 1,
    "container-identity": 1
  },
  "results_sha256": "0f0b530d3a587923ef6499f72f39bf76b86fc00c01e6ae08610fb52e8905b957"
}
```

### depth-gpu-operator-config — PASS

```json
{
  "checks": 20,
  "findings": 19,
  "critical": 5,
  "high": 13,
  "hardened_findings": 0,
  "domains": [
    "dcgm",
    "device-plugin",
    "dra",
    "driver",
    "mig",
    "workload"
  ],
  "snapshot_sha256": "f20dc58ffb66760d98ee77460c8cfa72a0537c200faec4918ede1a21d609a61d"
}
```

### depth-sonic-fabric-link — PASS

```json
{
  "checks": 28,
  "failed": 28,
  "hardened_failed": 0,
  "domains": [
    "ib",
    "sharp",
    "sonic"
  ],
  "scenarios": [
    "pfc-storm",
    "ecn",
    "rail-mismatch"
  ],
  "detectors": [
    "fabric.pfc-pause-storm"
  ],
  "baseline": [
    "fabric.baseline-clean"
  ],
  "nodes": 1024,
  "snapshot_sha256": "d169da6b68ceefc45147640c01ebef02e57eb250c088f740177ed949ea9decae"
}
```

### depth-identity-federation — PASS

```json
{
  "cases": 21,
  "allowed": 21,
  "hardened_allowed": 0,
  "legit_allowed": 21,
  "findings": 21,
  "categories": [
    "audience-wildcard",
    "empty-set",
    "external-id-optional",
    "missing-condition",
    "oidc-confusion",
    "source-account-missing",
    "subject-wildcard",
    "wildcard-principal"
  ],
  "results_sha256": "b2257d302192db6258eb8917f81844400ea00d4ed82c3b494db1675952206716"
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
- 限制：芯片/加速器面为 lab/chipsec_sim.py 双态 mock 与自签 JWT/X.509 fixture；无真实 H100/H200/GB200、真实 NRAS 生产 JWT、真实 CXL/IMEX/SPDM 设备；不做硅片实验室/物理故障注入/Rowhammer/微架构侧信道实操。
- 限制：KIND hostNetwork 绕过 NetworkPolicy 实证需启用 WSL2/虚拟化后执行 lab/kind/run-proof.sh。
- 限制：ARTEX（AGPL）仅作外部黑盒对标，本仓库不复用其代码；对标需虚拟化环境执行 lab/bench/artex-bench.sh。
- 限制：提权 4 项（escalate/bind/SA token/webhook）使用 lab/privesc_sim.py 的 fake-kubectl 内存态闭环；QEMU k3s 真集群 4 条路径证据见 reports/samples/privesc/real-paths.json 与 docs/PRIVESC-VERIFICATION.md。
- 限制：训练栈仿真是 lab/trainstack_sim.py（真实 HTTP + 真实文件落盘）：不加载 Megatron/DeepSpeed 权重、不执行 LLaMA-Factory/ms-swift/TRL 训练、不连接真实 MLflow/W&B/TensorBoard 或 etcd。
- 限制：研究级深度六项（depth-*）为 lab/depth_sim.py 双态 HTTP、配置快照与准入/信任语义引擎：不连接 live K8s、真实 GPU 驱动、真实交换机/IB SM/SHARP 或真实云账号；vLLM 240 用例只读探针不投递真实 pickle、不下载权重。

## 复现命令

```bash
python -m trident.verify-effects --out reports/samples/effects/
python -m unittest tests.test_verify_effects -v
```
