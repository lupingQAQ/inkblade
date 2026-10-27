# areal-awex

- 组件：areal
- 版本：448de52
- 风险：AReaL SGLang /awex/* unauthenticated: arbitrary torch.save + join arbitrary NCCL group
- 入口：POST /awex (9000/tcp)
- 可控参数：save path, NCCL world/rank
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：200 + NCCL 入组 marker
- 标记：`INKBLADE-BENIGN-areal-awex`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
