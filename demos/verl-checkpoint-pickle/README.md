# verl-checkpoint-pickle

- 组件：verl
- 版本：76e837e
- 风险：verl checkpoint engine recv_pyobj: pickle over TCP/ZMQ without auth
- 入口：TCP/ZMQ: recv_pyobj
- 可控参数：pickle payload
- 认证前置：无（通道可达）
- 网络位置：Pod 内/ClusterIP
- 预期效果：pickle.loads -> marker
- 标记：`INKBLADE-BENIGN-verl-checkpoint-pickle`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
