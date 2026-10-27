# msswift-trust-remote-code

- 组件：msswift
- 版本：4.5.3 / fbc61cf
- 风险：ms-swift default_trust_remote_code=True + WebUI/deploy fail-open -> malicious model RCE
- 入口：模型仓库: ms-swift custom module
- 可控参数：trust_remote_code
- 认证前置：需模型仓库可控
- 网络位置：服务进程
- 预期效果：import-time marker
- 标记：`INKBLADE-BENIGN-msswift-trust-remote-code`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
