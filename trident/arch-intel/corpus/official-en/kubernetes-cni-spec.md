# CNI 规范 — 容器网络接口 v1.1.0

- 分类：网络架构专源
- 组织 / 系统：CNCF containernetworking / CNI SPEC
- 核验日期：2026-10-25；核验状态：verified（SPEC.md 全文抓取）

## 来源
- https://raw.githubusercontent.com/containernetworking/cni/main/SPEC.md

## 架构要素
- 组网：runtime→插件执行模型（环境变量+stdin JSON）；接口/链式/委托（IPAM）三类插件
- 隔离边界：**规范不含隔离**——无策略语义；命名空间即隔离域定义
- 身份：无
- 存储：无
- 通信：插件自定（bridge/vlan/vxlan/sriov…）
- 管理面：runtime（kubelet）驱动
- 多租户：不涉及
- 云集成点：所有 VPC-native CNI 的底座规范

## 安全问题点（放大前提 × 模块机器键）
- “有 CNI ≠ 有隔离”：策略能力完全取决于具体插件 → `cni-stack-capability`
- GC/STATUS 等新操作扩展宿主侧执行面（插件二进制路径可控=宿主 RCE 面）→ `escape-primitives`
- 多网络（multus 链）时 runtimeConfig 透传：策略旁路面倍增 → `multus-sriov-rdma-bypass`

## 横向思路
- 侦察节点 CNI 二进制与配置可写性 → 链中注入插件（宿主执行）→ 或仅利用“无策略默认”横向

---
## 万卡证据（2026-10-25 重收批注）
- ❌ 未达 ≥10k 口径：无 ≥10k 披露：CNI 规范仓
## 网络要素
- isolation
- 分类迁移：corpus 扁平目录 → corpus/official-en（外文官方源）
