# vllm-jev-plugin-auth-bypass

- 组件：vllm-jev
- 版本：v0.31.0 + vllm-jev 57226d4
- 风险：vLLM --api-key does not guard /plugins/vllm-jev/* (auth bypass)
- 入口：POST /plugins/vllm-jev/choice (8000/tcp)
- 可控参数：choice
- 认证前置：无（/v1 需 key 对照）
- 网络位置：ClusterIP
- 预期效果：200 + 插件响应 marker
- 标记：`INKBLADE-BENIGN-vllm-jev-plugin-auth-bypass`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
