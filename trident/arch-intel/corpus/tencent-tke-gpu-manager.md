# 腾讯云 TKE — GPU Manager（vCUDA 共享调度）

- 分类：云商 K8s GPU/加速器集群（GPU 共享/虚拟化）
- 云商 / 系统：Tencent / TKE GPU Manager（开源 tkestack 组件）
- 核验日期：2026-10-25；核验状态：verified（GitHub README）

## 来源
- https://raw.githubusercontent.com/tkestack/gpu-manager/master/README.md

## 架构要素
- 组网：常规 VPC-CNI（TKE 侧）；本组件关注 GPU 切分
- 隔离边界：vcuda-core/vcuda-memory 配额式隔离（利用率上限走注解 tencent.com/vcuda-core-limit）
- 身份：gpu-manager 以 kube-system 内绑定 cluster-admin 的 SA 运行（README 明示）
- 存储：不涉及
- 通信：设备插件 gRPC（kubelet）
- 管理面：DaemonSet + gpu-admission 调度扩展
- 多租户：同卡多 Pod 共享（共享显存=共享显存内容风险）
- 云集成点：TKE 产品化即 GPU share/vGPU

## 安全问题点（放大前提 × 模块机器键）
- **cluster-admin SA DaemonSet**：节点 RCE 即集群接管 → `runtime-socket-escape`、`rbac-mapping`
- 显存共享无加密隔离：同卡邻居可尝试读取残留显存（跨租户残留）→ `training-data-leak`
- 调度扩展（gpu-admission）被伪造请求可操纵分配 → `scheduler-network-semantics`

## 横向思路
- 逃逸/接管 gpu-manager Pod（特权+cluster-admin）→ 集群级横向 → 节点池任意 GPU 负载注入
