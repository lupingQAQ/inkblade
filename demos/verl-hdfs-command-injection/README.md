# verl-hdfs-command-injection

- 组件：verl
- 版本：76e837e
- 风险：verl HDFS path is interpolated into os.system (command injection)
- 入口：CLI: HDFS path -> os.system
- 可控参数：hdfs path
- 认证前置：需调用
- 网络位置：训练进程
- 预期效果：命令执行 -> marker
- 标记：`INKBLADE-BENIGN-verl-hdfs-command-injection`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
