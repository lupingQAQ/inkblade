# SONiC / 白盒交换机 OS 安全公告 — Dell Enterprise SONiC CVE 记录

- 分类：paper（论文/第三方分析源）
- 组织 / 系统：Dell（Enterprise SONiC OS）/ 开放白盒 NOS 生态（SONiC、Cumulus）
- 核验日期：2026-10-25；核验状态：verified（ZeroPath CVE 评析直读 + DSA 检索命中；
  Dell KB 与 NVD 在本网络 403/空响应，缺口已记录，摘要以公告引用为准）

## 来源
- https://zeropath.com/blog/cve-2025-38741-dell-sonic-ssh-key-vulnerability（CVE-2025-38741，DSA-2025-275）
- 检索命中：DSA-2025-057 / CVE-2025-23374（Dell Enterprise SONiC 日志敏感信息写入）：
  https://www.dell.com/support/kbdoc/en-us/000278568/ ；https://nvd.nist.gov/vuln/detail/CVE-2025-38741

## 万卡证据（原文摘录）
- ➖（本源为规范/漏洞/机制证据，非万卡规模实证；wanka_evidence=false）

## 网络要素
- ops-fault-surface / isolation

## 架构要素
- 白盒 NOS（SONiC/Cumulus）是 AI fabric 的开放控制面：Spectrum-X 明确运行 SONiC/Cumulus；
  Meta FBOSS 同类自研栈
- CVE-2025-38741：Dell Enterprise SONiC OS 4.5.0 SSH 服务硬编码/可预测密钥（CWE-321），
  **未认证远程攻击者**可 compromise SSH 管理通信（CVSS 3.1 AV:N/AC:L/PR:N/UI:N C:H）；
  修复 4.5.0a+（`crypto ssh-keygen` 重生成密钥）
- CVE-2025-23374（DSA-2025-057）：日志写入敏感信息（信息泄露类）
- 交换机 OS 一旦失陷：SNMP/telemetry/配置 API 全部随后暴露

## 安全问题点（放大前提 × 模块机器键）
- 交换机管理面 = fabric 控制面入口：SSH/REST 可达即 PFC 档位、Partition、路由策略可写 → `roce-pfc-storm`、`ib-subnet-manager-hijack`
- 日志敏感信息（CVE-2025-23374）：拓扑/凭据入日志即测绘面 → `fabric-topology-isolation`
- 供应链：白盒 NOS 版本碎片化，集群级固件下发窗口（Meta：100k GPU 数小时）即回滚窗口 → `driver-reset-trigger`

## 横向思路
- 一台白盒 leaf 的 OS RCE/密钥失陷 → 上行注入配置 → 楼栋/区域 fabric 行为被改写（两条 fabric 链的实体前提）
