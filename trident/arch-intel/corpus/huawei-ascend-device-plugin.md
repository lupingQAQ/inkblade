# 华为昇腾 — Ascend Device Plugin（K8s NPU 接入）

- 分类：云商 K8s GPU/加速器集群（NPU 设备面）
- 云商 / 系统：Huawei / 昇腾 Ascend（Gitee 官方社区仓，文首注明仓库迁移）
- 核验日期：2026-10-25；核验状态：verified（Gitee raw README）

## 来源
- https://gitee.com/ascend/ascend-device-plugin/raw/master/README.md

## 架构要素
- 组网：NPU 通过设备插件暴露 `huawei.com/ascend910` 等扩展资源；容器以设备直通方式使用
- 隔离边界：设备级分配；MindX DL 套件（含 Ascend Docker Runtime、node-diagnostics、volcano 适配）
- 身份：K8s SA（设备插件常规宽权限部署）
- 存储：SFS/OBS 训练数据
- 通信：HCCL 集合通信走 RoCE 网络（星池/高速池）
- 管理面：MindCluster/MindX DL 组件栈（多 DaemonSet）
- 多租户：虚拟化实例（vNPU 切分）共享
- 云集成点：华为云 CCE/ModelArts 产品化

## 安全问题点（放大前提 × 模块机器键）
- 设备直通容器：/dev/davinci* 直通=接近宿主硬件面 → `escape-primitives`、`privileged-gpu-pod-escape`
- MindX DL 多特权 DaemonSet：任一被攻陷即节点沦陷 → `gpu-network-operator-posture`
- vNPU 切分残留：切分实例间显存/通道残留风险 → `training-data-leak`

## 横向思路
- 申请 NPU 资源 → 直通设备探测宿主 → daemon 面逃逸；或 HCCL 平网入组（与 NCCL 同理）
