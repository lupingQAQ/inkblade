# sample-vuln-repo

实验室样本树：为 Trident 核心代码检测模块族提供已知 sink 的静态目标（全部为编造代码，
对应 `trident/core/data/sink-rules.json` 各规则案例锚）。禁止用于真实部署。

| 文件 | 内嵌 sink 类别 |
|---|---|
| serve.py | eval / exec / 0.0.0.0 绑定 / key fail-open |
| load_weights.py | torch.load(weights_only=False) / pickle / 动态导入 |
| hdfs_utils.py | os.system 拼接 |
| model_fetch.py | trust_remote_code 硬编码 / revision 缺失 / file:// 接受 |
