# 六云免费/最小集群 Runbook（2026-10-25）

> **执行状态**：本机没有 Docker，也没有任何云账号/凭据。已执行的是
> `lab/cloud_free/` 的 **Python mock 端点 + 真实 SigV4/SharedKey 适配器语义**
> （AWS/Azure/GCP），以及 `lab/cloud_six_sim.py` 对阿里/腾讯的**契约仿真**。
> 下面 AWS/Azure/GCP 的免费额度与命令是**交付待跑**，不是本机实测；金额/额度随官网
> 变化，执行前必须以厂商价格页/免费额度页为准。
>
> 结论：SOTA 矩阵行「六云商真实/模拟环境」记 **模拟验证**；其中「真实云账号/集群」
> 部分仍为 **仍未达成**。本批次只把 AWS/Azure/GCP 对象存储语义推进到模拟验证。

## 0. 已执行证据

| 证据 | 路径 |
|---|---|
| 三云适配器语义（CRUD/错误码/ETag/元数据） | `reports/samples/cloud-free/semantics.json` |
| 阿里/腾讯契约（8/8 vulnerable、8/8 fixed） | `reports/samples/cloud-free/aliyun-tencent-contract.json` |
| 测试 | `tests/test_cloud_free.py`（14 项） |
| Docker 栈（待跑） | `lab/cloud_free/docker-compose.yml` |

本机验证的是 **API 契约**（签名算法、错误码、ETag/元数据形状），不包含真实 IAM、
VPC、GPU Operator、网络策略、计费与配额行为。

## 1. 通用成本护栏（先做再开集群）

1. 设预算告警（AWS Budgets / Azure Cost Management / GCP Budgets）+ 50%/80%/100% 三档。
2. 只用 **单 AZ、单节点、无 GPU、无 NAT Gateway、无公网 LoadBalancer** 的最小拓扑；
   需要出网时用节点公网 IP + 安全组白名单，不用 NAT。
3. 所有资源打 `owner=trident-lab`、`ttl=YYYY-MM-DD` 标签；用 TTL 脚本/定时删除。
4. 开完立即记录：集群名、region、实例 ID、磁盘 ID、公网 IP、创建时间。
5. 收尾检查：控制面、节点、磁盘、快照、负载均衡、公网 IP、日志桶逐项删除；
   `aws ec2 describe-instances` / `az resource list -g` / `gcloud compute instances list`
   必须为空（或只剩白名单）。

## 2. AWS（EKS 或单机 k3s）

### 2.1 免费额度边界（以官网为准）

- AWS Free Tier（新账号 12 个月）通常含 750 h/月 `t3.micro`（部分 region 为 `t2.micro`）、
  30 GB EBS、少量 S3；**EKS 控制面不在免费额度内**（约 $0.10/h）。
- 因此“最小 EKS”不是 0 元：控制面 + 1 台 `t3.medium` + 20 GB EBS + 公网 IPv4，
  按需约 $0.15–0.20/h（不含 NAT/负载均衡/跨 AZ 流量）。跑 2 小时约 $0.3–0.4。
- 想压到接近 0 元：用一台免费额度内 `t3.micro` 跑 **k3s**（仅 API/策略语义，
  跑不动 GPU/ML 工作负载），或直接用本仓库 mock；不要开 EKS + NAT。

### 2.2 最小 EKS（可选，非免费）

```bash
# 未在本机执行；需 AWS CLI v2 + eksctl + 已配置凭据
export AWS_REGION=us-east-1
export CLUSTER=trident-free-lab
eksctl create cluster \
  --name "$CLUSTER" --region "$AWS_REGION" \
  --version 1.33 --without-nodegroup
eksctl create nodegroup \
  --cluster "$CLUSTER" --region "$AWS_REGION" \
  --name ng-1 --node-type t3.medium --nodes 1 --nodes-min 1 --nodes-max 1 \
  --node-volume-size 20 --node-ami-family AmazonLinux2023
# 只为本次实验放行本机 IP；不要 0.0.0.0/0
aws eks update-kubeconfig --name "$CLUSTER" --region "$AWS_REGION"
kubectl get nodes -o wide
# 收尾（必须）
eksctl delete cluster --name "$CLUSTER" --region "$AWS_REGION" --wait
```

成本开关：`--without-nodegroup` 先建控制面再决定是否加节点；不要建 NAT Gateway；
不要建 `Service type=LoadBalancer`；EBS 默认 20 GB；用完删集群会删节点但**确认 EBS/ENI/日志组**
没有残留。

### 2.3 单机 k3s（免费额度内，推荐做 API 语义）

```bash
# 未在本机执行；Amazon Linux 2023 t3.micro（免费额度内，2 vCPU/1 GB 仅够 k3s 空跑）
aws ec2 run-instances \
  --image-id resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --instance-type t3.micro --count 1 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=owner,Value=trident-lab},{Key=ttl,Value=2026-10-26}]' \
  --user-data '#!/bin/bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable traefik" sh -
'
# 取公网 IP / 实例 ID 后，用 SSM 或 SSH 取 kubeconfig；只放行本机 /32
aws ec2 terminate-instances --instance-ids <INSTANCE_ID>
```

## 3. Azure（AKS Free tier）

### 3.1 免费额度边界

- AKS **Free** 控制面层不收控制面费用；节点 VM、磁盘、公网 IP、LoadBalancer 仍计费。
- 最小 `Standard_B2s`（2 vCPU/4 GB）按需约 $0.04/h + 32 GB 磁盘；单节点 2 小时
  约 $0.1–0.2。新账号可能有 $200/30 天额度，但不要假设一定有。
- 不要用 `Standard LoadBalancer` + 公网 IP（额外费用）；实验用 `--load-balancer-sku basic`
  或直接 `kubectl port-forward`。

```bash
# 未在本机执行；az login 后
RG=trident-free-rg
az group create -n "$RG" -l eastus
az aks create -g "$RG" -n trident-free-aks \
  --tier free --node-count 1 --node-vm-size Standard_B2s \
  --node-osdisk-size 32 --generate-ssh-keys --network-plugin azure \
  --enable-managed-identity
az aks get-credentials -g "$RG" -n trident-free-aks --overwrite-existing
kubectl get nodes -o wide
# 收尾（删整个资源组，含 MC_* 节点资源组）
az group delete -n "$RG" --yes --no-wait
az group show -n "$RG" 2>/dev/null || echo "deleted"
```

## 4. GCP（GKE 或单机 k3s）

### 4.1 免费额度边界

- GCP 新账号通常有 $300/90 天试用；Always Free 含 1 台 `e2-micro`（限
  `us-west1`/`us-central1`/`us-east1`）、30 GB 标准磁盘、少量出网。
- GKE 有 **一个 zonal 集群的免费管理额度**（Regional/Autopilot 超出部分计费），
  但节点/磁盘/负载均衡仍计费。最小 `e2-small`（2 vCPU/2 GB）约 $0.02/h。
- 不要开 Autopilot（会按 Pod 资源计费，边界更难控）；用 zonal standard + 1 节点。

```bash
# 未在本机执行；gcloud auth login 后
gcloud config set project <PROJECT_ID>
gcloud config set compute/zone us-central1-a
gcloud container clusters create trident-free-gke \
  --zone us-central1-a --num-nodes 1 --machine-type e2-small \
  --disk-size 30 --no-enable-autoscaling --enable-network-policy \
  --labels owner=trident-lab,ttl=2026-10-26
gcloud container clusters get-credentials trident-free-gke --zone us-central1-a
kubectl get nodes -o wide
# 收尾
gcloud container clusters delete trident-free-gke --zone us-central1-a --quiet
gcloud compute disks list --filter="labels.owner=trident-lab"
```

## 5. 阿里云 ACK / 腾讯云 TKE

- 两家没有面向所有人的“永久免费 K8s 控制面 + 节点”套餐；常见是新用户试用金/
  代金券/按量折扣。ACK 托管版控制面、TKE 集群与 CVM/ECS 节点、云盘、EIP、CLB
  均可能计费；GPU 机型不在试用范围。
- 本次**没有**申请账号，也没有跑真实集群；`lab/cloud_six_sim.py` 的阿里/腾讯
  契约仿真（RAM/CAM、OSS/COS、快照共享、安全组/IMDS）是唯一证据。
- 若后续要做：优先用按量付费 + 单 AZ + 1 台最低配 ECS/CVM + 自建 k3s，
  设置 1 小时 TTL；ACK/TKE 托管集群先确认控制面是否计费，再决定是否开。
- 官方入口（自行核对当前活动）：
  - 阿里云 ACK：<https://www.aliyun.com/product/kubernetes>
  - 阿里云免费试用：<https://free.aliyun.com/>
  - 腾讯云 TKE：<https://cloud.tencent.com/product/tke>
  - 腾讯云免费体验：<https://cloud.tencent.com/act/free>

## 6. 跑什么、不跑什么

在最小集群上只跑本仓库的**只读侦察**与 NetworkPolicy 语义验证：

```bash
python -m trident run --module k8s-cluster-recon --params '{"snapshot":"..."}' ...
# 或按 docs/RUNBOOK.md 的 lab 快照模式；不要在生产集群执行写类模块
```

不要在免费额度集群上跑：GPU Operator + 大镜像、分布式训练、10K 对象压测、
ARTEX/LLM 全量扫描、长时间 soak。它们会触发流量/磁盘/时长费用，且免费额度机型
资源不足。

## 7. 状态与证据边界

| 云 | 本次执行 | 状态 |
|---|---|---|
| AWS S3 语义 | Python mock + 真实 SigV4 | 模拟验证 |
| Azure Blob 语义 | Python mock + 真实 SharedKey | 模拟验证 |
| GCP Storage 语义 | Python mock + JSON API | 模拟验证 |
| AWS/Azure/GCP 真实集群 | 未执行（无账号/无凭据） | 仍未达成 |
| 阿里/腾讯 | 契约仿真 8/8×2 | 模拟验证 |
| 六云真实账号 + GPU 节点 | 未执行 | 仍未达成 |

> 本 runbook 的命令是**最小化模板**，不是成本承诺。执行者必须在开资源前用厂商
> 价格计算器核对，并在实验结束后逐项确认资源已删除。
