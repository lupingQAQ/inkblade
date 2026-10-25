# KubeTrail 移植说明（Apache-2.0 最小闭环）

上游：[`ekkoo-z/KubeTrail`](https://github.com/ekkoo-z/KubeTrail) — Apache License 2.0，
Copyright the KubeTrail Authors（仓库 README footer 写 MIT，但 LICENSE 文件为权威
Apache-2.0 文本，差异在此如实记录）。

本仓库 **不包含、不复制、不链接 KubeTrail 的 Go 源码**；`trident/kubetrail/` 是对其
公开行为与文档的 **独立 Python 重写**（仅标准库，控制台侧只读分析）。Apache-2.0 的
署名/NOTICE/许可副本义务由 `NOTICE`、本文件与每个源文件头共同满足，并由
`tools/check-notices.py` 自动校验。

## 移植范围（6 个闭环项）

| 上游能力 | 本仓库实现 | 说明 |
|---|---|---|
| in-pod collectors（18 collector/19 scan 类别） | `trident/kubetrail/collector.py` + 模块 `kubetrail-collector` | 13 个可快照判定 bucket（safe/full 标注）；支持容器根只读副本（`root`）与快照 `inpod` view；路径解析禁越界、单文件 ≤64KiB |
| legacy SA token 逐 token 审计（CM-05） | `token_audit.py` + 模块 `kubetrail-token-audit` | JWT **只解码不验签**；风险：legacy/bound、有效期、audience、通配符/高危权限、default SA；输出仅 sha256 前 16 + 长度 |
| 敏感值 raw/redact/metadata 三态（CM-06） | `redact3.py` | raw 必须显式绑定受控目录（0600）；默认只产出 redact + metadata；引用式 `secret:<id>` |
| manifest 云密钥扫描（CM-34） | `manifestscan.py` + 模块 `kubetrail-manifest-secrets` / `secret-scanner` | AWS/GCP/Azure/私钥/kubeconfig/dockerconfig/OpenAI/HF/Slack/GitHub + 高熵；命中值脱敏 |
| 16 条内核 LPE CVE 表 | `lpe.py` + 模块 `kubetrail-lpe` | 版本区间 + 配置前置，`confidence=heuristic`；**只判定不利用**，无 exploit 代码 |
| 七类权限维持模板（K8） | `persistence.py` + 模块 `kubetrail-persistence` | 仅检测侧：SA/CRB、CronJob/DaemonSet、影子 kubeconfig、TokenRequest、pull secret、webhook；不生成植入模板 |

## 明确未移植（Ruling 维持）

- C2 / 自主执行 / 后渗透工作台 / 持久化模板 **生成**：与「可审计交付」定位冲突；
- 16 条 LPE 的 **利用代码**：只保留判定与证据；
- Wails 桌面绑定 / Vue 视图 / dbus.json 全量 schema：控制台侧以 WebUI/报告替代
  （`core/auditlog.py::adapt_kubetrail` 已支持 dbus.json 导入）。

## 验证

```bash
python -m unittest tests.test_kubetrail tests.test_modules_attack_surface tests.test_kubetrail_license
python tools/check-notices.py
```

测试覆盖：三态脱敏（raw 隔离/redact/metadata 不可逆）、manifest 规则与脱敏、
token JWT 解码与风险分级、容器根采集与路径越界拒绝、LPE 版本区间、持久化七模板、
署名/NOTICE/许可检查。

## 变更记录

- 2026-10-25：最小闭环落地（6 项能力 + 5 个模块 + 署名/许可门禁）。
