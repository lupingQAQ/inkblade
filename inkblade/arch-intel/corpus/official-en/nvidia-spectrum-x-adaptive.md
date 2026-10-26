# NVIDIA Spectrum-X 以太网平台 — 自适应路由与确定性性能

- 分类：official-en（外文官方源）
- 组织 / 系统：NVIDIA / Spectrum-X（Spectrum-4 交换机 + SuperNIC + SONiC/Cumulus）
- 核验日期：2026-10-25；核验状态：verified（nvidia.com 平台页 + 白皮书入口直读）

## 来源
- https://www.nvidia.com/en-us/networking/spectrumx/
- https://resources.nvidia.com/en-us-networking-ai/nvidia-spectrum-x

## 万卡证据（原文摘录）
- ✅ "up to 128K GPUs in two tiers (64x more than single-plane networks)"

## 网络要素
- multi-plane / congestion-control / isolation

## 架构要素
- 交换机 + SuperNIC 紧耦合：比 OTS 以太网 1.6× AI 网络性能；RoCE 扩展 for 可扩展 AI 通信
- 自适应路由：交换机与 SuperNIC 协同动态改道，避开拥塞（区别于静态 ECMP）
- Spectrum-XGS：拓扑感知拥塞控制 + 精确时延管理 + 端到端遥测，跨 DC 1.9× NCCL 性能
- 多租户：deterministic performance 与 performance isolation 为一等卖点
- Spectrum-X Multiplane：两层 128K GPU（比单平面网络多 64×）；运行 SONiC/Cumulus 开放 NOS
- NVIDIA 官方页面明确「加速 xAI 建造的世界最大 AI 超算」的 Spectrum-X 以太网

## 安全问题点（放大前提 × 模块机器键）
- 自适应路由控制面被写 = 集群流量工程武器化 → `rail-mismatch-forcing`
- 「性能隔离」依赖控制器正确性：多租户共享 fabric 的配额/租期若无鉴权 → `gang-scheduler-abuse`
- SONiC/Cumulus 开放 NOS：白盒交换机 OS 供应链与配置面（见 sonic-whitebox-security）

## 横向思路
- 适配路由/多平面控制器无鉴权 → 定向把某租户流量推入劣化路径（步时劣化不报警）
