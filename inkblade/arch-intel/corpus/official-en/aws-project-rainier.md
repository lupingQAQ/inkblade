# AWS — Project Rainier：近 50 万 Trainium2 芯片 AI 计算集群

- 分类：official-en（外文官方源）
- 组织 / 系统：AWS × Anthropic / Project Rainier（UltraCluster）
- 源类型：newsroom（aboutamazon.com 官方新闻，2025-06 发布/2025-10 全量运营更新）
- 核验日期：2026-10-25；核验状态：verified（webfetch aboutamazon.com 官方新闻直读，原句摘录）

## 来源
- https://www.aboutamazon.com/news/aws/aws-project-rainier-ai-trainium-chips-compute-cluster
- https://aws.amazon.com/ai/machine-learning/trainium/customers/（Anthropic 官方证言页）

## 万卡证据（原文摘录）
- ✅ "Project Rainier is now in use, featuring one of the world's largest AI compute clusters with nearly half a million Trainium2 chips."
- ✅ "Anthropic is actively using Project Rainier to build and deploy its industry-leading AI model, Claude, now on more than 1 million Trainium2 chips."
- ✅ "When you connect tens of thousands of these UltraServers and point them all at the same problem, you get Project Rainier—a mega 'UltraCluster.'"

## 网络要素
- 两级互联原句："the NeuronLinks provide high-bandwidth connections within UltraServers, while Elastic Fabric Adapter (EFA) networking technology (identified by its yellow cables) connects UltraServers inside and across data centers."
- UltraServer=4 台 64 芯片物理服务器组合；跨 DC EFA 互联

## 架构要素
- 组网：NeuronLink（蓝线）柜内/超节点域 + EFA（黄线）跨 UltraServer/跨 DC；多站点（Indiana 等）
- 多租户形态：Anthropic 专属容量、AWS 运营

## 安全问题点（放大前提 × 模块机器键）
- 跨 DC EFA 互联=站点间平网段 → `hybrid-cloud-egress-pivot`
- 专属租户+云运营双身份：IAM 边界即攻击面 → `cloud-role-overprivilege`、`metadata-egress`

## 横向思路
- 站内 EFA 域探测 → NeuronLink 域边界类比 NVLink domain → fabric 面预留条目复用
