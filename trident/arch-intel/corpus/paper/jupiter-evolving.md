# Jupiter Evolving — Google 数据中心网络的 OCS/SDN 演进（SIGCOMM'22）

- 分类：paper（论文/技术报告）
- 组织 / 系统：Google / Jupiter 数据中心网络（OCS + SDN）
- 源类型：paper（SIGCOMM 2022）
- 核验日期：2026-10-25；核验状态：verified-partial（dl.acm.org webfetch 403（Cloudflare 拒连）；以 websearch 快照（ACM/斯坦福镜像 PDF）佐证摘要原句）

## 来源
- https://dl.acm.org/doi/10.1145/3544216.3544471
- https://web.stanford.edu/class/cs244/papers/poutievski-sigcomm22.pdf（课程镜像 PDF）

## 万卡证据（原文摘录）
- ❌ 论文为 DCN 体系（非 GPU 集群计数）：万卡级 TPU/OCS 证据另见 corpus/paper/google-tpu-oci.md 与 Google Cloud Next'26 口径（80k GPU/DC）

## 网络要素
- optical-switching（核心）：OCS（光路交换）+ SDN 重构 Jupiter 拓扑（Clos → 动态重构）；"Jupiter has delivered 5x higher speed and capacity, 30% reduction in capex, 41% reduction in power"（快照摘要口径）
- topology：incremental deployment/in-service 升级能力

## 架构要素
- 组网：OCS 交换矩阵 + 电路/分组混合；Palomar OCS
- 管理面：SDN 集中控制拓扑重构

## 安全问题点（放大前提 × 模块机器键）
- OCS 控制面：重构指令通道被劫持=拓扑级攻击（切断/重连任意链路）→ `fabric-topology-isolation`
- SDN 控制器单点：拓扑即隔离的体系下控制器凭据=全部可达性 → `rbac-mapping`

## 横向思路
- 光交换面探测（OCS 管理协议/端口指纹）→ 拓扑扰动 DoS/窃听定向化；与 google-tpu-oci 条目联动（重构即改变可达集合）
