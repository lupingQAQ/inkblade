# slime-pull-weights

- 组件：slime
- 版本：slime 05e3b01 / SGLang v0.5.15.post1
- 风险：slime private /pull_weights patch: ADMIN_OPTIONAL + request-controlled source_dir/local_checkpoint_dir
- 入口：HTTP POST /pull_weights
- 可控参数：source_dir, local_checkpoint_dir
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：权重目录 marker
- 标记：`INKBLADE-BENIGN-slime-pull-weights`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
