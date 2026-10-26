# 企业黄项本地补验结果（Enterprise local checks）

- 生成时间：2026-10-26T09:06:56Z
- 汇总：**11/11 PASS**
- 边界：本机 mock/临时目录；不是客户 registry/SIEM/GPU/合规环境验收。

| 检查 | 结果 | 耗时 | 证据摘要 |
|---|---:|---:|---|
| `er-08-registry-auth-digest` 私有 registry：Bearer 认证链 + manifest digest + tag-only 策略 | PASS | 233.5 ms | {"reference": "127.0.0.1:51296/demo/app@sha256:7031b2ca4fb21f39676938959d2033d192f2bac4c57d94e4df26ee097fe36431", "pinned": true, "auth": "bearer", "digest_match": true, "bad_digest_match": false, "bad_status": 200, "tag |
| `er-08-proxy-absolute-uri` 代理路径：绝对 URI 经本地 HTTP 代理转发 | PASS | 26.8 ms | {"proxy": "htt<local-path>", "absolute_uri": "htt<local-path>", "status": 200, "body": "{\"proxied\": true}", "bypass_localhost": true} |
| `er-27-retention-execution` 保留/删除执行：dry-run/legal hold/双角色/越界拒绝/审计 JSONL | PASS | 29.9 ms | {"dry_run": {"keep": 1, "archive": 0, "purge": 1, "hold": 0, "missing": 0, "skipped": 0}, "held": {"keep": 0, "archive": 0, "purge": 0, "hold": 2, "missing": 0, "skipped": 0}, "executed": {"keep": 1, "archive": 0, "purge |
| `er-26-change-freeze` 变更窗口：冻结期重叠拒绝 + ICS 导出 | PASS | 2.2 ms | {"freeze": [{"name": "quarter-end", "start": 1793002000.7689412, "end": 1793009200.7689412, "reason": "财报", "ticket": "CAB-100", "owner": "ops", "created_at": 1793005600.7689412, "start_iso": "2026-10-26T08:06:40Z", "end |
| `er-34-vendor-exception-policy` 云厂商 DaemonSet 例外：digest/ns/SA/审批/到期 | PASS | 0.2 ms | {"allowed": {"allowed": true, "reason": "exception matched", "exception_id": "exc-001", "approver": "security-owner"}, "tag_only": {"allowed": false, "reason": "tag-only image"}, "expired": {"allowed": false, "reason": " |
| `er-40-rule-regression` 规则升级回归：覆盖降级/规则删除即拒绝 | PASS | 0.1 ms | {"good_ok": true, "bad_rejected": true} |
| `er-39-siem-dedupe-dlq` SIEM 闭环：去重/重试/死信 JSONL | PASS | 2.4 ms | {"first": {"sent": 1, "duplicates": 0, "failed": 0, "attempts": 2, "dead_letters": 0}, "second": {"sent": 0, "duplicates": 1, "failed": 0, "attempts": 0, "dead_letters": 0}, "dead": {"sent": 0, "duplicates": 0, "failed": |
| `er-50-siem-egress-policy` SIEM 出网：allowlist + 非回环强制 TLS + CA/代理 | PASS | 0.1 ms | {"loopback": {"ok": true, "scheme": "http", "host": "127.0.0.1", "port": 8088, "loopback": true, "tls_required": false, "ca_bundle": false}, "http_rejected": true, "host_rejected": true} |
| `er-57-evidence-pack` 等保/ISO 证据包：manifest + 控制项索引 + 哈希校验 | PASS | 22.4 ms | {"built": {"schema": "inkblade-evidence-pack/1", "path": "<local-path>", "files": 3, "controls": 7, "covered": 3, "framework": "djbh", "manifest_sha256": "1f6d4d44e69374e465f1883c8b52dc6239a583ec9786be5667afac3da320d99b"} |
| `er-16-audit-stream-scale` 审计事件流：20 万合成事件写入/读回/容量外推 | PASS | 15440.8 ms | {"scale": {"schema": "inkblade-audit-scale/1", "requested": 200000, "inserted": 200000, "duplicates": 0, "rows": 200000, "denied": 11765, "by_verb": {"create": 33334, "delete": 33333, "exec": 33333, "get": 33333, "list":  |
| `er-06-gpu-contract` GPU Operator/device plugin/DRA 契约（本地 schema/版本矩阵） | PASS | 0.3 ms | {"device_plugin_findings": 4, "dra_findings": 4, "matrix": {"ok": true, "findings": [], "gpu_operator": "25.3.0", "driver": "580.65.06", "cuda": "12.4", "container_runtime": "containerd", "note": "本地版本规则；真实兼容需 GPU 节点 + d |

复跑：`python -m inkblade.enterprise.localcheck` 或 `inkblade enterprise local-checks`。
