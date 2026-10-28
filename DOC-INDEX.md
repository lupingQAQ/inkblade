# 文档索引 / Documentation Index

> 对外产品文档。按“产品 → 使用 → 架构与探针 → 运行与交付 → 技术参考”排列。

## 1. 产品与使用

| 文档 | 说明 |
|---|---|
| [`docs/PRODUCT.md`](PRODUCT.md) | 产品定位、适用对象、十层检测的“能做什么 / 检测什么 / 产出什么”、防护绕过输出、交付物 |
| [`docs/FEATURES.md`](FEATURES.md) | 功能清单：十层、in-pod 探针与通道、框架矩阵、平台功能、可选集成 |
| [`docs/WORKFLOW.md`](WORKFLOW.md) | 九阶段工作流：立足 → 探针 → 通道 → 检测 → 逃逸 → 横向 → 多探针 → 跨集群 → 报告/规则/控制台 |
| [`docs/DETECTION-LAYERS.md`](DETECTION-LAYERS.md) | 十层检测详解：每层的能做什么、检测什么、产出什么、代表模板 |
| [`docs/USAGE.md`](USAGE.md) | 接入、会话、探针、通道、检测、多探针、跨集群、报告、规则、结果阅读、退出码、排障 |
| [`docs/QUICKSTART.md`](QUICKSTART.md) | 一条命令启动（`pip install inkblade && inkblade up`）、浏览器打开→签授权→开始、up/down/status |
| [`docs/INSTALL.md`](INSTALL.md) | 控制器与探针安装、容器/Helm、离线、工作区布局、首次接入 |
| [`docs/FAQ.md`](FAQ.md) | 接入、探针、检测、授权、写操作、交付与许可的常见问题 |
| [`docs/DOC-INDEX.md`](DOC-INDEX.md) | 本索引 |

## 2. 架构与探针

| 文档 | 说明 |
|---|---|
| [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) | 控制端组件架构：治理、编排、模块、证据、报告、可视化、规则 |
| [`docs/ARCHITECTURE-PROBE.md`](ARCHITECTURE-PROBE.md) | 唯一执行路径：模板面、探针面、控制面；父子树与零解释器边界 |
| [`docs/PROBE-CHANNEL.md`](PROBE-CHANNEL.md) | 入口会话与 `kubectl exec -i` 通道：投放、SOCKS/端口转发、权限边界 |
| [`docs/PROBE-PROTOCOL.md`](PROBE-PROTOCOL.md) | 长度前缀 JSON 帧、认证、任务/结果、预算、文件分块、清理与错误码 |
| [`docs/PROBE-DEPLOY.md`](PROBE-DEPLOY.md) | RCE/memfd、kubectl、ServiceAccount token、EphemeralContainer、共享卷、写权限校验 |
| [`docs/PROBE-BUILD.md`](PROBE-BUILD.md) | Rust 探针构建：musl amd64/arm64、SHA-256、发布校验 |
| [`docs/MODULES.md`](MODULES.md) | 模块目录、系列、级别与键 |
| [`docs/PLUGIN-SDK.md`](PLUGIN-SDK.md) | 插件/模板 SDK、manifest、信任与校验 |

## 3. 技术参考

| 文档 | 说明 |
|---|---|
| [`docs/VULNERABILITY-LAYERS.md`](VULNERABILITY-LAYERS.md) | 十层漏洞逐层详解：原理、代码、攻击演示、危害与修复 |

## 仓库政策

`LICENSE`、`NOTICE`、`SECURITY.md`、`CONTRIBUTING.md`、`CODE_OF_CONDUCT.md` 位于仓库根目录，随源码分发。
