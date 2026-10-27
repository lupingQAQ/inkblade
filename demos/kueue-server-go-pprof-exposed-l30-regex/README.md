# kueue-server-go-pprof-exposed-l30-regex

- 组件：kueue
- 版本：v0.20.3
- 风险：kueue kueueviz: pprof-exposed-go + default-disabled auth @ backend/config/server.go:30
- 入口：GET /debug/pprof/cmdline (9100/tcp)
- 可控参数：n/a
- 认证前置：无
- 网络位置：ClusterIP/宿主
- 预期效果：200 + profile marker
- 标记：`INKBLADE-BENIGN-kueue-server-go-pprof-exposed-l30-regex`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
