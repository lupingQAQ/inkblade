# Trident 交付包结构（DELIVERY）

> 版本 v0.1.0（2026-10-25）· 双语报告与规则包样张由 `python trident/e2e-check.py` 一键再生（15 项验收全 PASS）。

## 1. 样张根：`reports/samples/`

| 路径 | 内容 | 说明 |
|---|---|---|
| `e2e/e2e-check.json` / `.md` | 端到端验收清单（15 项 PASS/FAIL + 明细 + 耗时） | 对应 设计基线 §18 可本机闭环条目 |
| `pentest-report-bi.md` | **双语渗透测试报告样张** | PTES 七段 + 五专节（组合层风险/训练数据泄露面/核心代码问题/网络分层威胁模型/混合云边界）；标准条款映射（NIST SP 800-115 / 等保 GB/T 22239-2019 / GB/T 20984）；CVSS 3.1 实时计算图例 + 中文习惯定级；攻击链步骤表；证据锚（步骤 · sha256 前 16 位）；**零日级漏洞模块（已公开）细节默认展示** |
| `pentest-report-bi-redacted.md` | **可选脱敏开关样张** | `render_pentest(..., redact_zeroday=True)`：零日级发现仅输出「影响已验证 + 证据哈希」，供未来真私有发现使用 |
| `remediation-report-bi.md` | **双语修复报告样张** | 立即/短期/中期修复基线分组 + 逐发现基线命中建议 + 复测计划（规则包紫队验证联动） |
| `rules-pack/` | **defense bundle** | 见 §2 |
| `effects/effects.json` / `.md` | **实效验证报告** | 7 项本机真实 HTTP 效果验证（管理面/权重投毒/回滚/RCE/数据泄露/规则命中/端到端链）+ 证据摘要；边界声明「非 live K8s」 |
| `effects/rules-coverage-matrix.json` / `.md` | 本次实效验证的紫队覆盖率矩阵 | 规则引擎对本次靶场重放的命中/拦截/漏过明细 |
| `static-export/index.html` | 六视图离线兜底 | `window.TRIDENT_DATA` 内嵌 run 全量数据（steps/findings/graph/manifest），file:// 免服务打开 |
| `kill-chain/` | **真实 k3s 最高权限 PROOF 样张** | 7 阶段夺权链（入口→SA token→cluster-admin→特权 Pod→节点 root→集群级证明→清理）；`proof.json` + 双语 `report.md` + `proof.png` + kubectl transcript；清理校验 `residue=[]`，节点 `/root` marker 已删除 |

## 2. defense bundle：`reports/samples/rules-pack/`

- `kyverno/` ClusterPolicy ×5（禁特权/敏感 hostPath/automount/RoleBinding 创建告警/组合签名告警）与 `gatekeeper/` 同语义 ConstraintTemplate+Constraint（dryrun）。
- `network/` **三 CNI 变体**（`native/` NetworkPolicy、`calico/` GlobalNetworkPolicy、`cilium/` CiliumNetworkPolicy）默认拒绝分区 + `vpc-native/` 安全组补充 + `rdma-sriov-uncovered.md`（RDMA/SR-IOV 不受 NetworkPolicy 覆盖声明）+ `ib-partition-advice.yaml`（IB Partition/SM 隔离建议）。
- `sigma/`、`falco/`、`suricata/` 检测规则（Suricata 含 NCCL TCPStore/KV 传输端口 29400-29512/45678 与 IMDS 出网签名）。
- `rbac-convergence.yaml` 三 operator 集群级角色 → namespace 最小化改写参考。
- `mapping.json` **规则↔攻击链/模块映射矩阵**：22 规则 × 20 链全覆盖（每链 ≥1 规则硬校验）、零日行为化签名登记（规则文本零利用细节）、monitor 模式 + 中英调参建议。
- `coverage-matrix.json` / `.md` **紫队验证覆盖率矩阵**：mock 靶场重放各链探针 + 内置简化 sigma/falco/suricata 匹配器 → 20 链全部「拦截/检测/拦截+检测」，**0 漏过**。

## 3. 证据三层（每次 run）

`evidence/<workspace>/<run>/`：

1. **归档层** `steps/<module>.tar.gz|zst` + `manifest.sha256`（逐文件 sha256；篡改必检出）
2. **数据库层** `evidence.db`（runs/steps/prompts/env/findings/evidence/actions/backups/rollbacks/roe/combos/graph_nodes/graph_edges）
3. **上下文摘要层** `context.jsonl.gz`（每步一行 digest + 双指针：db rowid / archive 路径；run 收尾追加重写摘要）

报告证据锚引用 manifest 清单；`verify_manifest` 校验结果注入报告不可篡改声明。

## 4. 映射矩阵与可追溯性

- 规则→链/模块：`rules-pack/mapping.json`（`blocks_chains` + 演练发现 `finding_links` 追溯线）。
- 发现→证据：findings 表 `evidence_path` = 步骤归档（manifest sha 锚）。
- 审计线：actions 表全量动作（主体/工作区/目标/参数/结果/回滚指针；零日级 `is_zeroday=1`）。
- 零日级：6 个已公开模块（dify-*/open-webui-*）正常打包与展示细节；`zeroday.py` 保留为默认关闭的可选加密扩展，仅对显式 `private: true` 的未来模块生效；行为化规则仍不含利用细节特征串。

## 5. 实验室边界（显式声明）

- 本机交付：mock 靶场（vulnerable/fixed 双态）全链自测 + 紫队重放矩阵 + 静态导出。
- 待 WSL 恢复后实跑（脚本已备）：`lab/kind/run-proof.sh`（hostNetwork 旁路实证）、KIND 内规则实际拦截重放、`lab/bench/artex-bench.sh`（ARTEX 对比）；IB/RDMA/IMEX 无硬件面以 fixture 推演 + 人工核验清单交付。
