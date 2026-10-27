# skyrl-fetch-weights

- 组件：skyrl
- 版本：a1e34db
- 风险：SkyRL /fetch_weights payload_files path traversal write + weight poisoning
- 入口：HTTP GET /fetch_weights
- 可控参数：cache_dir, payload_file
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：任意写 marker
- 标记：`INKBLADE-BENIGN-skyrl-fetch-weights`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
