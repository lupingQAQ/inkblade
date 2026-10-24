# RDMA / SR-IOV 不受 NetworkPolicy 覆盖 — 显式声明

显式声明：RDMA / SR-IOV VF / IB / macvlan 与 hostNetwork/hostDevice 路径不经 CNI 转发，任何 NetworkPolicy（原生 / Calico / Cilium）与 VPC 安全组均不覆盖该面；集合通信隔离必须依赖 IB Partition（PKey）/ Subnet Manager 隔离与 rail/plane 分区，另见 network/ib-partition-advice.yaml 与 network/rdma-sriov-uncovered.md。

## 适用范围
- SR-IOV VF / RDMA shared device / IB device plugin 直挂的 Pod 多网卡路径
- hostNetwork / hostDevice 工作负载（GPU 驱动容器、NCCL bootstrap 直连）
- GPUDirect RDMA / IB / RoCEv2 集合通信平面；GB200 NVL72 / IMEX ComputeDomain 跨节点 GPU 内存域

## 判定口径（对齐设计约束）
任何「网络可达」结论必须注明层级与判定方式；本声明意味着：上述路径上不存在 NetworkPolicy
（原生 / Calico / Cilium / VPC 安全组）语义的隔离结论，不得把「有 NetworkPolicy」等同于「隔离有效」。

## 补充控制（另见 ib-partition-advice.yaml）
- IB Partition（PKey）+ Subnet Manager 隔离为该平面的唯一隔离手段
- 预填充-解码 KV 传输（NIXL/Mooncake）按端口域与身份双向校验补强
- hostNetwork 收敛清单：
  - 逐 DaemonSet 审计 hostNetwork=true 必要性（GPU 驱动、SR-IOV device plugin、ib-kubernetes），能收敛即收敛
  - hostNetwork Pod 出网仅放行到显式白名单 CIDR（监控/registry/时间同步）
  - hostDevice / SR-IOV 附件统一走专用命名空间并登记到例外通道

English declaration: Explicit declaration: RDMA / SR-IOV VF / IB / macvlan and hostNetwork/hostDevice paths bypass the CNI forwarding plane and are NOT covered by any NetworkPolicy (native / Calico / Cilium) nor by VPC security groups; collective-communication isolation must rely on IB Partition (PKey) / Subnet Manager isolation and rail/plane partitioning - see network/ib-partition-advice.yaml and network/rdma-sriov-uncovered.md.
