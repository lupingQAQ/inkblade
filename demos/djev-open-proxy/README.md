# djev-open-proxy

- 组件：djev
- 版本：e5841cf
- 风险：djev default-open proxy: no key + /v1/* relay + GET bypass when key configured
- 入口：POST /v1/chat/completions (8081/tcp)
- 可控参数：model, messages
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：200 + 上游响应 marker
- 标记：`INKBLADE-BENIGN-djev-open-proxy`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
