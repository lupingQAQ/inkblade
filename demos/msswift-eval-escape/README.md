# msswift-eval-escape

- 组件：msswift
- 版本：4.5.3 / fbc61cf
- 风险：ms-swift --device_groups ranks restricted eval() escape; WebUI more_params reachable
- 入口：配置: device_groups eval
- 可控参数：device_groups
- 认证前置：需配置/请求
- 网络位置：服务进程
- 预期效果：eval 逃逸 -> marker
- 标记：`INKBLADE-BENIGN-msswift-eval-escape`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
