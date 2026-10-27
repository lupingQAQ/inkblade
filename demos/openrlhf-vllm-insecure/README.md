# openrlhf-vllm-insecure

- 组件：openrlhf
- 版本：0.11.2 / dc2a7ad
- 风险：OpenRLHF unconditionally sets VLLM_ALLOW_INSECURE_SERIALIZATION=1
- 入口：环境变量: VLLM_ALLOW_INSECURE_SERIALIZATION
- 可控参数：env, payload
- 认证前置：需进程环境
- 网络位置：训练进程
- 预期效果：pickle -> marker
- 标记：`INKBLADE-BENIGN-openrlhf-vllm-insecure`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
