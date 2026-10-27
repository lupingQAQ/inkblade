# areal-v2-worker

- 组件：areal
- 版本：448de52
- 风险：AReaL v2 worker /load -> torch.load(weights_only=False) without auth (+/save, /data, /awex)
- 入口：文件: data worker payload
- 可控参数：pickle payload
- 认证前置：无（worker 可达）
- 网络位置：Pod 内
- 预期效果：pickle.loads -> marker
- 标记：`INKBLADE-BENIGN-areal-v2-worker`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
