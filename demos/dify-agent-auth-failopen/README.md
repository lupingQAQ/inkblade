# dify-agent-auth-failopen

- 组件：dify
- 版本：v1.17.1 / bbfac7a
- 风险：dify-agent backend auth fail-open (token None -> allow all) + public dev token in compose
- 入口：POST /agent-stub/v1/chat (8080/tcp)
- 可控参数：token, messages
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：200 + 控制面 marker
- 标记：`INKBLADE-BENIGN-dify-agent-auth-failopen`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
