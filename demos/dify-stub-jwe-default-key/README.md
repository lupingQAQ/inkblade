# dify-stub-jwe-default-key

- 组件：dify
- 版本：v1.17.1
- 风险：Dify Agent Stub JWE root key hardcoded public default -> offline token forgery
- 入口：HTTP POST /agent-stub/*
- 可控参数：token
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：默认 JWE 密钥伪造 token 通过
- 标记：`INKBLADE-BENIGN-dify-stub-jwe-default-key`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
