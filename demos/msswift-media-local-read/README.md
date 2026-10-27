# msswift-media-local-read

- 组件：msswift
- 版本：v4.6.0
- 风险：ms-swift 4.6.0 deploy media path reads arbitrary host files by default
- 入口：HTTP POST /v1/chat/completions (media path)
- 可控参数：media path
- 认证前置：无
- 网络位置：ClusterIP
- 预期效果：本地文件 marker 读回
- 标记：`INKBLADE-BENIGN-msswift-media-local-read`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
