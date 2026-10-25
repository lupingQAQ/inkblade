# Google Cloud — TPU 软件栈（PyTorch/XLA → TorchTPU）

- 分类：云商 K8s GPU/加速器集群（TPU 软件面）
- 云商 / 系统：Google Cloud TPU / PyTorch/XLA（Google 云 TPU 团队维护；宣布弃用，2026-11-15 归档，官方迁移路径 TorchTPU）
- 核验日期：2026-10-25；核验状态：verified（官方 README + 弃用公告）

## 来源
- https://raw.githubusercontent.com/pytorch/xla/master/README.md

## 架构要素
- 组网：TPU Pod = 多台 TPU VM 主机（每主机多芯片）；ICI 节点内/跨节点全互联，DCN 出 Pod
- 隔离边界：slice 边界；Pod 内共享 fabric
- 身份：GCP IAM/WIF
- 存储：GCS 直接读训练数据（GCS FUSE 常态）
- 通信：集合通信经 ICI；多进程 PJRT 运行时统一编排
- 管理面：GKE TPU 节点池/独立 TPU API
- 多租户：项目级
- 云集成点：GCS、元数据服务器

## 安全问题点（放大前提 × 模块机器键）
- 多主机进程模型：任一主机立足即可与全 slice 通信 → `collective-communication-surface`
- GCS 直读训练数据：token 过权=数据集全量泄露 → `training-data-leak`
- checkpoint 桶=权重面 → `shared-volume-weight-copy`（云侧变体）

## 横向思路
- Pod 内进程/端口侦察 → 跨主机 ICI 尝试 → 或直取 GCS（凭据面）
