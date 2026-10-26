# AWS Trainium2 UltraServer / UltraCluster — NeuronLink + EFAv3

- 分类：official-en（外文官方源）
- 组织 / 系统：Amazon AWS / EC2 Trn2、Trn2 UltraServer、EC2 UltraClusters
- 核验日期：2026-10-25；核验状态：verified（aws.amazon.com 实例页直读，2026-10-16 更新）

## 来源
- https://aws.amazon.com/ec2/instance-types/trn2/
- https://aws.amazon.com/ec2/ultraservers/

## 万卡证据（原文摘录）
- ✅ "tens of thousands of Trainium2 chips on a single petabit-scale, non-blocking network"

## 网络要素
- multi-tenancy

## 架构要素
- Trn2 实例：16× Trainium2（20.8 FP8 PFLOPS、1.5TB HBM3、46TB/s）；EFAv3 3.2 Tbps/实例
- **Trn2 UltraServer：4 实例 NeuronLink 互联 64 片**（83.2 FP8 PFLOPS、6TB 共享内存、185TB/s、32TB NVMe）；UltraServer EFAv3 12.8 Tbps
- EC2 UltraClusters：数万 Trainium2 片、P 比特级无阻塞网络；EFA 基于 Nitro，传输加密无性能损耗
- 下一代 Trn3 UltraServer 已宣布（144 片 Trainium3，362 MXFP8 PFLOPS）

## 安全问题点（放大前提 × 模块机器键）
- NeuronLink scale-up 域 64 片：节点内集合通信与健康面共享宿主侧 → `driver-reset-trigger`（等价健康注入面）
- EFAv3 传输加密是链路级而非作业级身份：跨作业 rendezvous 仍可枚举 → `nccl-port-exhaustion`
- UltraCluster 共享无阻塞网：单租户 I/O/端口行为可外溢到邻居作业 → `checkpoint-io-storm`、`api-server-flood-surface`

## 横向思路
- 云上「无阻塞共享」放大耗尽类攻击的爆炸半径：配额缺失即集群级 DoS（`fabric-exhaustion-chain`）
