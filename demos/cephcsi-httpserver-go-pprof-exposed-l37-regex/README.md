# cephcsi-httpserver-go-pprof-exposed-l37-regex

- 组件：cephcsi
- 版本：v3.18.1
- 风险：ceph-csi: pprof-exposed-go @ internal/util/httpserver.go:37
- 入口：GET /debug/pprof/cmdline (9100/tcp)
- 可控参数：n/a
- 认证前置：无
- 网络位置：ClusterIP/宿主
- 预期效果：200 + profile marker
- 标记：`INKBLADE-BENIGN-cephcsi-httpserver-go-pprof-exposed-l37-regex`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
