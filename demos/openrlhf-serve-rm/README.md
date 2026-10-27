# openrlhf-serve-rm

- 组件：openrlhf
- 版本：0.11.2 / dc2a7ad
- 风险：OpenRLHF serve_rm binds 0.0.0.0:5000 without authentication
- 入口：POST /v1/score (5000/tcp)
- 可控参数：messages
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：200 + 评分响应 marker
- 标记：`INKBLADE-BENIGN-openrlhf-serve-rm`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
