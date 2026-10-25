# Trident 提权检测规则包

由 `trident privesc detections` 生成。每个提权向量至少 1 条 Sigma/Falco 规则；
另有 6 条 Kyverno ClusterPolicy（Audit 模式）。

- 向量 47；规则 47；紫队命中 47/47
- Sigma：K8s audit 字段路径；Falco：行为化签名（monitor 标签）
- 先以 monitor/Audit 观察基线，再按主体白名单切 Enforce/Block

复现：`trident privesc detections --out reports/rules-pack`；`trident rules validate --pack reports/rules-pack` 会附带 `privesc` 覆盖结果。
