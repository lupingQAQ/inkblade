# Google Cloud — AI on GKE（官方样例库）

- 分类：云商 K8s GPU/加速器集群
- 云商 / 系统：Google Cloud / GKE + AI on GKE（GoogleCloudPlatform 官方仓，已归档只读）
- 核验日期：2026-10-25；核验状态：verified（官方仓 README；注：仓库归档，GKE 文档站 cloud.google.com 在本实验网络超时不可达，缺口已记录）

## 来源
- https://raw.githubusercontent.com/GoogleCloudPlatform/ai-on-gke/main/README.md

## 架构要素
- 组网：GKE VPC-native（alias IP）；多网卡/高性能网络选项；TPU slice 拓扑（另见 google-tpu-oci）
- 隔离边界：VPC 服务边界 + GKE 网络策略
- 身份：Workload Identity Federation（KSA↔GSA，免秘钥）
- 存储：GCS/Parallelstore/Fastfile
- 通信：GPUDirect/TPU ICI；DCN 走 VPC
- 管理面：GKE 托管控制面
- 多租户：namespace+团队项目分层
- 云集成点：元数据服务器（需 token）、GCS

## 安全问题点（放大前提 × 模块机器键）
- Workload Identity 联邦过权 → GCS 权重桶 → `cloud-role-overprivilege`、`multi-cloud-imds-credentials`
- TPU slice 相邻性：slice 间共享 DCN → `cni-aware-reachability-graph`
- 元数据 v1 语义（旧实例默认可用）→ SSRF 直接取 GSA token → `ssrf-imds-credential`

## 横向思路
- SSRF → GCP 元数据 → GSA 凭据 → GCS/TPU 控制面 → 作业投放/权重桶

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：GKE AI 文档
## 网络要素
- multi-tenancy
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
