# Gateway API Inference Extension — 推理网关与 EPP

- 分类：网络架构专源（推理网关）
- 组织 / 系统：Kubernetes SIG / gateway-api-inference-extension（GA）
- 核验日期：2026-10-25；核验状态：verified（README 全文）

## 来源
- https://raw.githubusercontent.com/kubernetes-sigs/gateway-api-inference-extension/main/README.md

## 架构要素
- 组网：Envoy ext-proc 扩展网关（Envoy Gateway/kgateway/GKE GW）；InferencePool 抽象后端池
- 隔离边界：EPP 为数据面组件（按请求路由）；LWEPP 供一致性测试
- 身份：ext-proc 通道信任（网关↔EPP）
- 存储：无
- 通信：HTTP/2 ext-proc + 模型服务指标（prefix cache/LoRA 可用性）
- 管理面：InferencePool CR + EPP 部署
- 多租户：池共享 + 流量分层（失败语义 failureMode 属 API 规范，FailOpen 时网关故障域放大）
- 云集成点：llm-d 路由器同源（EPP 主力开发已迁 llm-d/llm-d-router）

## 安全问题点（放大前提 × 模块机器键）
- **failureMode=FailOpen**：EPP 异常时路由退化=旁路智能调度（故障域放大）→ `inference-gateway-pd`
- KV-cache 状态参与路由：缓存信息面泄露（可推断他人提示前缀）→ `training-data-leak`
- EPP 可路由 LoRA：请求侧 lora 可达性=注入面入口 → `lora-adapter-injection`

## 横向思路
- 打点/劫持 EPP（或利用 FailOpen）→ 定向路由/请求内容观测 → 递进至解码池管理面（权重拉取/更新）
