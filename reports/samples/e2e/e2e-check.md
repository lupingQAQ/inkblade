# Trident 端到端验收清单（e2e-check）

- 运行 Run：`e2e-acceptance`
- 生成时间：<timestamp>
- 结果：**全部通过**（15/15 PASS）
- 模块族覆盖：侦察×2、权限链×2、核心代码×2、横向利用×2、混合云×2、窃取与数据泄露×2、网络架构×2、防护绕过×2、零日×2

| 检查项 | 标题 | 状态 | 明细 | 耗时(ms) |
|---|---|---|---|---|
| lab-mock-vulnerable | lab mock 靶场（vulnerable）启动且路由清单可达 | PASS | 25 条路由 @ http://127.0.0.1:<port>/ | <elapsed> |
| consent-lock-runner | consent 未签署：runner 执行路径拒绝（ExecutionLocked） | PASS |  | <elapsed> |
| consent-lock-api | consent 未签署：API /api/execute 返回 423 | PASS | HTTP 423: 工作区授权未完成（consent 未签署） | <elapsed> |
| backup-gate-exit-code-91 | 写类模块无备份回执：BackupGateRefused 且退出码语义 91、模块未执行 | PASS | 写类模块缺少备份回执（backup_targets 为空或不可用） | <elapsed> |
| module-family-subset | 九族代表性子集（每族 ≥2 模块）全部执行且产出发现；写类 backup-write 演示可回滚还原 | PASS | 侦察×2 / 权限链×2 / 核心代码×2 / 横向利用×2 / 混合云×2 / 窃取与数据泄露×2 / 网络架构×2 / 防护绕过×2；写类演示已回滚还原 | <elapsed> |
| chain-catalog-dryrun | 链目录齐全（经典/云侧/网络/零日）且 dry-run 输出可读计划（备份动作+写面） | PASS | 29 链 / 5 类；flat-network-admin-plane-weight-poison 判定=部分成立（缺失 1 条前置） | <elapsed> |
| chain-execute-weight-poison | 完整链执行（平网→管理面→权重投毒）：全部步骤成功 + 备份回执在库 | PASS | 步骤 admin-failopen-probe:success、weight-pull-poison:success | <elapsed> |
| evidence-three-layers-manifest | 三层证据齐备（上下文摘要/SQLite/归档 tar+SHA256）且 manifest 校验通过、篡改可检出 | PASS | 19 步骤 / 19 归档 / 篡改检出✓ | <elapsed> |
| zeroday-public-no-gate | 零日级漏洞模块（已公开）无需零日闸门：默认可见、可直接执行，发现带 is_zeroday 审计标记 | PASS | 公开✓ / private=false✓ / 无需 enable✓ / is_zeroday 落库 2 条 | <elapsed> |
| report-bilingual-public-details | 双语渗透+修复报告渲染：PTES/专节/标准映射/CVSS/证据锚齐备；已公开零日级细节默认展示，可选脱敏开关生效 | PASS | 渗透 72620 字符 / 修复 69045 字符；默认展示✓ / 可选脱敏 71044 字符✓ | <elapsed> |
| rules-pack-coverage | 规则包 generate_all：每链 ≥1 规则，三 CNI 变体 + Sigma/Falco/Suricata 产物齐备 | PASS | 121 规则 / 29 链全覆盖 / 三变体+四引擎✓ | <elapsed> |
| purple-coverage-matrix | 紫队验证：mock 靶场重放 + 简化匹配器 → 覆盖率矩阵零漏过 | PASS | 28 链 / 0 漏过 / 态集合 ['拦截', '拦截+检测', '检测'] | <elapsed> |
| export-static-offline | export_static 免服务产物：index.html 内嵌 TRIDENT_DATA（file:// 可开六视图） | PASS | static-export\index.html | <elapsed> |
| roles-and-workspace-isolation | 四角色动作矩阵符合规格；auditor 跨工作区访问被拒、无执行权 | PASS | admin*/lead/tester/auditor 矩阵✓；跨工作区拒✓；auditor 执行拒✓ | <elapsed> |
| samples-written | 样张清单全部落盘 reports/samples/ | PASS | 9+ 项样张在库（e2e 清单收尾写入；rules-pack 全树另计） | <elapsed> |

> 对应 设计基线第 18 节验收标准中可本机闭环条目；KIND/WSL 边界项（规则实际拦截重放、
> hostNetwork 实证、bench 对比）见 `docs/RUNBOOK.md` 实验室边界章节与 `lab/bench/BENCH-RESULT.md`。
