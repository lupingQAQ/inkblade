# Trident 实效验证报告（Effect Verification）

- 生成时间：2026-10-24T18:04:14Z
- 验证 Run：`effects-20261025-020413`；链 Run：`effects-chain-20261025-020413`
- 范围与边界：本机真实进程 + 真实 HTTP（127.0.0.1 回环 mock 靶场）效果级验证；非 live K8s 集群。KIND/ARTEX 需启用虚拟化后按 lab/kind 与 lab/bench 脚本执行。
- 汇总：**7/7 PASS**（FAIL 0）

> **边界声明（必须随报告阅读）**：本验证为本机真实进程/真实 HTTP 效果级（`lab/mock_targets.py`，仅 127.0.0.1），**非 live K8s 集群**。KIND hostNetwork 绕过 NetworkPolicy 与 ARTEX（AGPL，黑盒对标）需启用虚拟化后，分别执行 `lab/kind/run-proof.sh` 与 `lab/bench/artex-bench.sh`；在虚拟化启用前，这两项不构成本报告的 PASS 结论。

| 项 | 验证内容 | 结果 | 证据摘要 |
|---|---|---|---|
| `admin-plane-failopen` | 未授权管理面利用：真实 HTTP 200 + 服务端状态文件变更 | PASS | {"http_status": 200, "route": "/pause", "state_file": "sglang/admin-state.json", "state_sha256_before": "5b377a070bfa3e011a6994667613cd33be1f9abed8c0a75e0547230dd4089318", "state_sha256_after": "8a3ef06953240e4018d07f2bf63f4ac80c304f94ade769d71d0c8f3f88a95ae3", "state_applied": true, "state_response_sha256": "077f4eda063d1c7ded456d5d6ab194080675a801232453875f6d736b945695bf"} |
| `weight-poison-write` | 权重投毒实效：文件副本 sha256 变化 + benign marker | PASS | {"http_status": 200, "file": "slime/checkpoints_victim-TRIDENT-effects-20261025-020413/model.safetensors", "sha256_before": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "sha256_after": "6147ff548866208f41f830e0dbc9fb87580b9c13024bb5fe0ff22336727d6530", "marker": "TRIDENT-effects-20261025-020413", "marker_present": true, "server_weights_sha256": "6147ff548866208f41f830e0dbc9fb87580b9c13024bb5… |
| `backup-rollback` | 备份回滚实效：快照 → 投毒 → rollback 后 sha256 与原始完全一致 | PASS | {"rollback_rows": 1, "sha256_original": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "sha256_after_rollback": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0", "exact_restore": true, "backup_receipt_sha256": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0"} |
| `rce-marker` | RCE 实效：AReaL 三步链触发 mock 侧真实 marker 文件（含 run 标记） | PASS | {"http_statuses": {"set_env": 200, "create_engine": 200, "call": 200}, "marker_file": "areal/call/engine-754c36cdc7984283bb50d515e51f71d2-CALL.marker", "env_marker_file": "areal/env/ENV-SET.marker", "marker": "TRIDENT-effects-20261025-020413", "marker_present": true, "engine_id": "engine-754c36cdc7984283bb50d515e51f71d2"} |
| `data-leak-redaction` | 数据泄露实效：fixture 假密钥仅尾4位进入报告 | PASS | {"finding_count": 5, "tail4": "wxyz", "redacted_sample": "****wxyz", "full_token_absent": true, "report_full_token_absent": true, "report_redacted_sample": "****wxyz"} |
| `rules-detection` | 检测规则实效：规则引擎对本次靶场重放 ≥1 条命中 | PASS | {"rules_evaluated": 56, "rules_detected": 34, "rules_blocked": 18, "rules_missed": 0, "hits": 52, "sample_hit": "flat-network-admin-plane-weight-poison · alert-combo-signature · 拦截", "matrix_ok": true, "coverage_file": "rules-coverage-matrix.json"} |
| `chain-e2e` | 端到端链：dry-run → execute（全影响演示级 + 备份 + 三层证据） | PASS | {"chain": "flat-network-admin-plane-weight-poison", "verdict": "部分成立", "missing": ["findings('framework-port-matching').reachable.any(port == 30000)"], "ok": true, "steps": {"admin-failopen-probe": "success", "weight-pull-poison": "success"}, "backup_receipts": 1, "weights_sha256_before": "3b3c43cbb5b6a9223cc39aea3d4f86a9ffe5bc3c25bb9162d9363dd950d012cb", "weights_sha256_after": "8b78ff6b6aa5e9ee7faeb71b3eeb4cff02… |

## 逐项证据

### admin-plane-failopen — PASS

```json
{
  "http_status": 200,
  "route": "/pause",
  "state_file": "sglang/admin-state.json",
  "state_sha256_before": "5b377a070bfa3e011a6994667613cd33be1f9abed8c0a75e0547230dd4089318",
  "state_sha256_after": "8a3ef06953240e4018d07f2bf63f4ac80c304f94ade769d71d0c8f3f88a95ae3",
  "state_applied": true,
  "state_response_sha256": "077f4eda063d1c7ded456d5d6ab194080675a801232453875f6d736b945695bf"
}
```

### weight-poison-write — PASS

```json
{
  "http_status": 200,
  "file": "slime/checkpoints_victim-TRIDENT-effects-20261025-020413/model.safetensors",
  "sha256_before": "8127ad31f844aa2495a3e251f38263b6540cb39325c54f775db29604f6eb41e0",
  "sha256_after": "6147ff548866208f41f830e0dbc9fb87580b9c13024bb5fe0ff22336727d6530",
  "marker": "TRIDENT-effects-20261025-020413",
  "marker_present": true,
  "server_weights_sha256": "6147ff548866208f41f830e0dbc9fb87580b9c13024bb5fe0ff22336727d6530"
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
  "marker_file": "areal/call/engine-754c36cdc7984283bb50d515e51f71d2-CALL.marker",
  "env_marker_file": "areal/env/ENV-SET.marker",
  "marker": "TRIDENT-effects-20261025-020413",
  "marker_present": true,
  "engine_id": "engine-754c36cdc7984283bb50d515e51f71d2"
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
  "rules_evaluated": 56,
  "rules_detected": 34,
  "rules_blocked": 18,
  "rules_missed": 0,
  "hits": 52,
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
  "weights_sha256_after": "8b78ff6b6aa5e9ee7faeb71b3eeb4cff02181e4390838220ad1c0cfa5f962295",
  "marker_present": true,
  "layers": {
    "context": true,
    "database": true,
    "archives": 2,
    "manifest": true
  },
  "run": "effects-chain-20261025-020413"
}
```

## 环境与限制

- python: `3.12.15`
- platform: `win32`
- mock_mode: `vulnerable`
- mock_host: `127.0.0.1`
- 限制：靶场为 lab/mock_targets.py 单进程仿真（仅 127.0.0.1），非真实 K8s API/容器运行时。
- 限制：sglang/areal/slime 的写面以 mock server 侧真实文件落盘为证据，不是远端生产文件系统。
- 限制：KIND hostNetwork 绕过 NetworkPolicy 实证需启用 WSL2/虚拟化后执行 lab/kind/run-proof.sh。
- 限制：ARTEX（AGPL）仅作外部黑盒对标，本仓库不复用其代码；对标需虚拟化环境执行 lab/bench/artex-bench.sh。

## 复现命令

```bash
python -m trident.verify-effects --out reports/samples/effects/
python -m unittest tests.test_verify_effects -v
```
