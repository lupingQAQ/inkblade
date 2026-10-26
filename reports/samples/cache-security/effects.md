# 多租户缓存安全实效（Cache Security Effects）

- 生成时间：2026-10-26T05:33:42Z
- 姿态：`vulnerable`（仅 127.0.0.1，标准库 HTTP）
- 汇总：**4/4 PASS**

| 实效 | 状态 | 证据摘要 |
|---|---|---|
| `approx-cache-false-hit-readback` | PASS | {"http_status": 200, "marker": "TRIDENT-BENIGN-APPROX-VICTIM", "marker_present": true, "matched_tenant": "tenant-b", "requester_tenant": "tenant-a", "response_excerpt": "tenant-b confidential guidance: 42.7M USD, growth 18 percent [TRIDENT-BENIGN-APPROX-VICTIM]", "route": "/approx/lookup", "similarity": 0.8824, "thresh |
| `cache-timing-membership-delta` | PASS | {"alpha": 0.05, "control_ttft_range_ms": [186.0, 268.0], "delta_ms": 194.333, "df": 29.81, "mean_control_ttft_ms": 222.233, "mean_member_ttft_ms": 27.9, "member_ttft_range_ms": [22.0, 31.0], "n_control": 30, "n_member": 30, "n_total": 60, "p_value": 1.0481709153641327e-28, "route": "/v1/chat/completions", "significant" |
| `cache-eviction-residue-readback` | PASS | {"evictions_after": 65, "evictions_before": 0, "evictions_delta": 65, "marker": "TRIDENT-BENIGN-RESIDUE-VICTIM", "marker_present": true, "prefix_preview": "tenant-b residue corpus marker TRIDENT-BENIGN-RESIDUE-VICTIM quarterly close data pack appendix", "residue_status": 200, "residue_tenant": "tenant-b", "route": "/ca |
| `remote-kv-pool-namespace-bypass` | PASS | {"block_id": "tenant-b/ctx/seed-001", "block_tenant": "tenant-b", "http_status": 200, "marker": "TRIDENT-BENIGN-POOL-VICTIM", "marker_present": true, "requester_tenant": "tenant-a", "route": "/kvpool/blocks/{block}", "value_excerpt": "{\"benign\": true, \"marker\": \"TRIDENT-BENIGN-POOL-VICTIM\", \"tenant\": \"tenant-b |
