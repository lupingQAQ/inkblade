# 华为云 CCE — Standard / Turbo / Autopilot

- 分类：云商 K8s GPU/加速器集群
- 云商 / 系统：Huawei Cloud / 云容器引擎 CCE
- 核验日期：2026-10-25；核验状态：verified（华为云国际站产品页）

## 来源
- https://www.huaweicloud.com/intl/en-us/product/cce.html

## 架构要素
- 组网：CCE Standard=VPC 叠加容器网；CCE Turbo=云原生 2.0（VPC 直通、软硬协同）；Autopilot=Serverless 容器
- 隔离边界：VPC/安全组；Turbo 容器网与 VPC 网络一体
- 身份：IAM（ Agency/委托）+ 节点授权
- 存储：OBS/SFS Turbo（AI 常配）
- 通信：Ascend NPU 集合通信（HCCL/RC 集合库，对应 MindCluster）
- 管理面：CCE 控制面 + Huawei Volcano 调度（官方产品页明示 Volcano 支撑调度策略）
- 多租户：企业项目/namespace
- 云集成点：ECS/CCE 元数据、OBS、ModelArts 联动

## 安全问题点（放大前提 × 模块机器键）
- Volcano 调度面（gang/公平share）跨 namespace 提交面：队列权限错配=挤占或投毒 → `scheduler-network-semantics`
- Turbo VPC 直通：容器网=VPC 网，安全组语义必须与 K8s 策略双核对 → `cni-stack-capability`
- 节点委托过权 → OBS 权重桶 → `cloud-role-overprivilege`、`multi-cloud-imds-credentials`

## 横向思路
- 元数据（华为 ECS/CCE 元数据端点）→ 委托凭据 → OBS/SFS 权重面；或 Volcano 队列滥用横向到其他租户作业

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：CCE Turbo 文档
## 网络要素
- （本源为控制面/组件语义类，不直接承载 8 项 fabric 要素）
- 分类迁移：corpus 扁平目录 → corpus/official-cn（中文官方源）
