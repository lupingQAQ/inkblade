# sglang-omni-admin-failopen

- 组件：sglang-omni
- 版本：HEAD 204ba29
- 风险：sglang-omni admin dependency is a no-op without SGLANG_OMNI_ADMIN_KEY; profiler event_dir is request-controlled
- 入口：POST /api/v1/profile (30000/tcp)
- 可控参数：event_dir
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：200 + profiler 目录 marker
- 标记：`INKBLADE-BENIGN-sglang-omni-admin-failopen`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
