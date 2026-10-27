# transformers-dynamic-module-utils-py-dynamic-import-l248-ast

- 组件：transformers
- 版本：4.57.1
- 风险：transformers: dynamic-import @ transformers/dynamic_module_utils.py:248
- 入口：模型仓库: dynamic_module_utils.py:248
- 可控参数：trust_remote_code
- 认证前置：需模型仓库可控
- 网络位置：服务进程
- 预期效果：import-time marker
- 标记：`INKBLADE-BENIGN-transformers-dynamic-module-utils-py-dynamic-imp`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
