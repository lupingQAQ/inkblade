# dify-shellctl-unauth-rce

- 组件：dify
- 版本：v1.17.1
- 风险：Dify 1.17.1 shellctl sandbox daemon: no auth -> zero-precondition host RCE + all tenant homes
- 入口：HTTP POST /v1/execute (5004/tcp)
- 可控参数：code
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：sandbox exec -> marker
- 标记：`INKBLADE-BENIGN-dify-shellctl-unauth-rce`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
