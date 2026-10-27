# llamafactory-checkpoint-py-torch-load-unsafe-l334-ast

- 组件：llamafactory
- 版本：v0.9.5
- 风险：llamafactory: torch-load-unsafe @ v1/core/utils/checkpoint.py:334
- 入口：文件: checkpoint.py:136/334
- 可控参数：checkpoint dir, rng_state/dataloader
- 认证前置：需本地文件写
- 网络位置：PVC/宿主
- 预期效果：torch.load -> marker
- 标记：`INKBLADE-BENIGN-llamafactory-checkpoint-py-torch-load-unsafe-l33`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
