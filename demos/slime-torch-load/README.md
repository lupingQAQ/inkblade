# slime-torch-load

- 组件：slime
- 版本：05e3b01
- 风险：slime debug/resume data torch.load(weights_only=False) in multiple sinks
- 入口：文件: torch.load checkpoint
- 可控参数：checkpoint dir
- 认证前置：需本地文件写
- 网络位置：PVC/宿主
- 预期效果：torch.load -> marker
- 标记：`INKBLADE-BENIGN-slime-torch-load`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
