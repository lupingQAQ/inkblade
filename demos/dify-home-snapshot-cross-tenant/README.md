# dify-home-snapshot-cross-tenant

- 组件：dify
- 版本：v1.17.1
- 风险：Dify local runtime: snapshot/control-lease root is common ancestor -> cross-tenant home snapshot theft
- 入口：HTTP GET /console/api/workspaces/current/snapshot
- 可控参数：snapshot_id
- 认证前置：需 key
- 网络位置：ClusterIP
- 预期效果：跨租户快照 marker
- 标记：`INKBLADE-BENIGN-dify-home-snapshot-cross-tenant`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
