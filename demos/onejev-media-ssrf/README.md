# onejev-media-ssrf

- 组件：onejev
- 版本：6122519
- 风险：OneJev qev/media.py urlopen without policy -> SSRF
- 入口：GET /media (8000/tcp)
- 可控参数：url
- 认证前置：无/需 key
- 网络位置：ClusterIP
- 预期效果：回环内部服务 marker
- 标记：`INKBLADE-BENIGN-onejev-media-ssrf`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
