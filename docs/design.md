# InkBlade（墨刃零）设计基线 / Design Baseline

本文档是模块 `knowledge` 字段的中性引用基线，汇总 InkBlade 的漏洞研究分类与授权边界。它不包含任何未披露利用细节、真实凭据或内部工作区路径。

## 1. 总览与授权边界

InkBlade 仅用于**获得书面授权**的安全测试。所有模块按 `min_level`（只读侦察 / 主动探测 / 利用验证 / 全影响演示）分级；写类模块必须提供 `backup_targets` 并通过备份闸门。默认靶场为 `lab/mock_targets.py`（仅 `127.0.0.1`）。

## 2. 推理引擎管理面

SGLang / vLLM / sglang-omni 等推理引擎的管理路由（`/pause`、`/freeze`、`/resume`、`/update_weights_from_disk`、`/plugins/*`）在默认部署中可能缺少鉴权或网络隔离，形成管理面 fail-open 与插件路由绕过。

## 3. 训练框架与控制面

AReaL、slime、SkyRL、verl、TRL 等训练/RL 框架的控制面（环境注入、引擎创建、权重拉取、检查点加载、dev 模式）可能暴露未鉴权的高权限原语；反序列化（pickle）与动态导入需要作为供应链与 RCE 风险单独评估。

## 4. 服务化与网关

djev / OpenAI 兼容中继、Ray Dashboard、Jupyter、MLflow、Triton 等服务面可能存在默认无鉴权、开放代理、任意作业提交或路径穿越。

## 5. 横向利用原语

跨 Pod / 节点 / 命名空间的横向移动原语：管理面直连、服务发现、DNS、集群内开放代理、SSRF、IMDS 凭据获取与跨租户服务调用。

## 6. 数据面与共享存储

共享 PVC / RWX 卷 / 对象桶 / 数据集缓存 / 训练日志 / RL 轨迹的未授权读写；权重文件可读即可换（偷换一体），需要在报告与产物中做凭据与 PII 脱敏（仅保留尾 4 位指纹）。

## 7. 网络与 CNI / RDMA

NetworkPolicy 覆盖盲区：hostNetwork / hostPort、Multus 多网卡、SR-IOV VF、IB/RDMA、VPC-native CNI 与安全组双控制面错配；集合通信（NCCL）与 KV 传输端口需要单独建模。

## 8. 云与混合边界

AWS / Azure / GCP / 阿里云 / 腾讯云 IMDS 与临时凭据、跨账号角色假定、对象存储权重桶、云互联 / 专线 / PrivateLink 暴露面。

## 9. 智能体平台

Dify、Open WebUI 等智能体/对话平台的控制面、绑定、快照、共享沙箱与代码执行面；间接提示注入可驱动服务端代码解释器。

## 10. 权限链

RBAC / ClusterRole / RoleBinding / ServiceAccount / Operator 权限收敛与提权路径；宽 SA、通配符权限、跨命名空间绑定与 admission 豁免。

## 11. 特权部署与宿主逃逸

privileged / hostPID / hostIPC / hostPath / 容器运行时 socket / GPU 设备直通等组合原语；默认应使用 Pod Security Standards 与准入策略收敛。

## 12. 防护绕过

Falco / Tetragon / KubeArmor / Elkeid / AgentSmith / NetObserv / veinmind / 准入控制与 WAF 的覆盖盲区、规则缺口与硬化建议；结果反哺规则包与配置建议。

## 13. 零日漏洞模块（已公开）

当前 6 个 `dify-*` / `open-webui-*` 模块为**已公开**的零日漏洞模块（`private: false`），正常打包、展示与报告细节。`inkblade/core/zeroday.py` 保留为默认关闭的可选加密扩展，仅对显式 `private: true` 的未来模块生效；报告可用 `redact_zeroday=True` 可选脱敏。

## 14. 研究伦理与披露

- 仅使用实验室 fixture / mock 样值（`MOCK*` / `FAKE*`），不内置真实凭据。
- 新发现的未披露漏洞遵循 [`SECURITY.md`](../SECURITY.md) 的私密披露流程（90 天协调期）。
- 公开规则包中的零日规则采用行为化描述，不含利用细节特征串。
