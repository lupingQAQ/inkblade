# msswift-indexed-dataset-py-pickle-loads-l129-regex

- 组件：msswift
- 版本：v4.6.0
- 风险：msswift: pickle-loads @ swift/dataset/indexed_dataset.py:129
- 入口：文件: IndexedDataset data.idx
- 可控参数：data.idx / pickle
- 认证前置：需本地文件写
- 网络位置：PVC/宿主
- 预期效果：pickle.loads -> marker
- 标记：`INKBLADE-BENIGN-msswift-indexed-dataset-py-pickle-loads-l129-reg`
- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）
- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`
- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`
- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。
