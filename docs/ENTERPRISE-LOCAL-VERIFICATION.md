# 企业黄项本地补验结果（2026-10-26）

> 本文回答：`docs/ENTERPRISE-READINESS.md` 中 12 个黄项，哪些可以**在本机**补到
> 可复现证据，哪些必须等客户。结论：**9 项转绿、3 项仍黄、21 项红不变**
> （绿 36 · 黄 3 · 红 21，共 60）。绿色只表示本地有可复现证据，不表示客户环境验收。

## 1. 统一执行器与结果

```bash
python -m trident.enterprise.localcheck --out reports/samples/enterprise-local
```

- 结果：**11/11 PASS**（2026-10-26T09:03:08Z）
- JSON：`reports/samples/enterprise-local/local-checks.json`
- Markdown：`reports/samples/enterprise-local/local-checks.md`
- 规模专项：`reports/samples/enterprise-local/audit-scale-1m.json`
- 全部在本机 127.0.0.1 mock / 临时目录运行；无客户网络、账号、数据。

| 检查 | 对应 ER | 结果 | 关键证据 |
|---|---|---|---|
| `er-08-registry-auth-digest` | ER-08 | PASS | Bearer challenge → token → manifest 200；`Docker-Content-Digest` 匹配；错误 digest 返回 200 但 `digest_match=false`；tag-only 标记 high |
| `er-08-proxy-absolute-uri` | ER-08 | PASS | 本地 HTTP 代理收到绝对 URI `http://registry.invalid/v2/`，返回 200；`no_proxy=localhost` 正确 bypass |
| `er-27-retention-execution` | ER-27 | PASS | dry-run purge=1 不删除；legal hold 全 hold；单角色审批拒绝；双角色执行删除并写 `retention-audit.jsonl`；root 外路径拒绝 |
| `er-26-change-freeze` | ER-26 | PASS | 冻结窗口与变更窗口重叠即拒绝；ICS 可导出；窗口持久化 |
| `er-34-vendor-exception-policy` | ER-34 | PASS | digest+精确 ns/SA+审批人+到期匹配才允许；tag-only/过期/通配 ns 拒绝 |
| `er-40-rule-regression` | ER-40 | PASS | 覆盖从“拦截/检测”降为“漏过”即回归；规则删除即回归 |
| `er-39-siem-dedupe-dlq` | ER-39 | PASS | 首次 503 后重试成功（attempts=2）；同租户同指纹第二次 duplicate；持续失败落死信 JSONL |
| `er-50-siem-egress-policy` | ER-50 | PASS | loopback HTTP 允许；非回环 HTTP 拒绝；非 allowlist host 拒绝 |
| `er-57-evidence-pack` | ER-57 | PASS | 3 文件 / 7 控制项（等保）/ 3 项有证据；zip manifest 校验通过；篡改后 `verify_pack.ok=false` |
| `er-16-audit-stream-scale` | ER-16 | PASS | 20 万合成事件 12.06s、读回 20 万；100 万事件另测 98.54s / 10,148 事件每秒 |
| `er-06-gpu-contract` | ER-06（仍黄） | PASS | device plugin 4 条契约问题、DRA 4 条；25.3.0/580.65.06/CUDA12.4/containerd 矩阵通过 |

## 2. ER-16 百万事件实测

`trident/enterprise/scale.py` 合成 100 万条审计事件（无真实数据），SQLite WAL +
每批 5,000 写入 + `UNIQUE(raw_sha256)` 去重：

| 指标 | 值 |
|---|---:|
| 事件数 | 1,000,000 |
| 写入/读回 | 1,000,000 / 1,000,000 |
| 耗时 | 98.54 s |
| 吞吐 | 10,148.1 事件/s |
| 线性日容量 | 876,795,840（8.77 亿/日） |
| DB 大小 | 191,655,936 B（约 183 MiB） |
| 峰值 traced 内存 | 1,713,433 B（约 1.6 MiB） |
| 拒绝事件 | 58,824（5.9%） |

**边界**：单机单进程合成流；不代表客户日均百万真实事件、峰值突发、HA、跨 AZ
或长稳。线性外推只用于容量规划，客户验收仍需按 `docs/ENTERPRISE-READINESS.md`
的 Pilot 门槛实测。

## 3. 仍未转黄的 3 项

| ER | 为什么仍黄 | 已做的本地部分 |
|---|---|---|
| ER-06 | 需要真实 GPU 节点 + kubelet device plugin 注册 + DRA driver；本地不能替代 | `gpu_contract.py` 校验 device plugin v1beta1/DRA schema/版本矩阵（4+4 条反例） |
| ER-25 | 需要客户数据分级/DLP 样本与 owner 流程 | Pilot 已有 snapshot/ground-truth 格式；本轮未新增分类器 |
| ER-35 | 需要客户标注真值/盲测样本 | 本地 fixture FP/FN 方法可复现，但不能冒充客户样本 |

## 4. 三态计数与文档同步

- `docs/ENTERPRISE-READINESS.md` 计数行：**绿 36 · 黄 3 · 红 21（共 60 项）**。
- ER-08/16/26/27/34/39/40/50/57 证据列改为本地可复现路径；ER-06 保持黄但补本地
  契约证据；ER-25/ER-35 保持黄。
- 测试：`tests/test_enterprise_local_gaps.py`（11 项，含 localcheck 11/11 与文档计数）。
- 边界声明：本机 registry/SIEM/证据包 mock 不等于客户 Harbor/Splunk/ServiceNow/
  等保测评；绿色项在投标/验收材料中必须附“本地验证”来源，不能写“客户已通过”。
