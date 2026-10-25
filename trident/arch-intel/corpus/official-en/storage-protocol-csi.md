# 存储协议与 CSI — NFS AUTH_SYS 与 CSI 特权面

- 分类：网络架构专源（存储数据面）
- 组织 / 系统：Kubernetes CSI 社区 + IETF NFSv4.1（RFC 8881）
- 核验日期：2026-10-25；核验状态：verified（CSI 文档站 + RFC 全文）

## 来源
- https://kubernetes-csi.github.io/docs/（CSI 开发/部署权威）
- https://www.rfc-editor.org/rfc/rfc8881.html（NFSv4.1 协议）

## 架构要素
- 组网：CSI node plugin（每节点，特权挂宿主）+ controller plugin；RWX（ReadWriteMany）=多 Pod 共享
- 隔离边界：NFS 导出表 + AUTH_SYS（uid 数字身份）
- 身份：**AUTH_SYS=客户端自报 uid/gid**（无验证）；强认证需 RPCSEC_GSS/Kerberos（部署少见）
- 存储：NFS/JuiceFS/CephFS/Lustre 共享卷=权重与数据集面
- 通信：NFS over TCP/RDMA
- 管理面：StorageClass/PV/PVC
- 多租户：共享卷 uid 切分（可伪造）
- 云集成点：云文件存储（EFS/FSx/NAS/Files）同语义

## 安全问题点（放大前提 × 模块机器键）
- **AUTH_SYS uid 可伪造**：任意 Pod 以 uid=0 读写他人导出 → `storage-protocol-csi`、`shared-volume-weight-copy`
- CSI node plugin 特权宿主挂载：插件容器失陷=节点 → `escape-primitives`
- RWX + HF 缓存目录：偷换一体（写恶意权重/模型代码）→ `trust-remote-code-supply-chain`

## 横向思路
- 枚举挂载/NFS 导出 → 伪造 uid 读训练数据集/权重 → 投放污染权重或 trust_remote_code 模型 → 等待加载者执行
