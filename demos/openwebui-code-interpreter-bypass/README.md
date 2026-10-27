# openwebui-code-interpreter-bypass

- 组件：open-webui
- 版本：v0.12.3 / 91ea4e3
- 风险：Open WebUI code_interpreter guard: BLOCKED_MODULES empty + __import__ patch only top-level __main__
- 入口：HTTP POST /code/execute (8080/tcp)
- 可控参数：code
- 认证前置：需登录
- 网络位置：ClusterIP
- 预期效果：exec -> marker
- 标记：`INKBLADE-BENIGN-openwebui-code-interpreter-bypass`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
