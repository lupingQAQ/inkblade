# lab/defense-deploy — 防护产品绕过实验室（部署 · 采集 · 重放）

紫队闭环（Trident 规格 5.2「防护产品绕过模块（v7）」）：KIND/WSL 实验室内部署
防护产品 → 采集部署面快照 → `defense-bypass-*` 模块两态评估 → 重放良性探针 →
验证「检出断言」与硬化规则有效性。

## 安全边界（硬约束）

- **benign-only**：全部探针为技术类别级 marker（写入被监控路径类别的良性文件、
  改名工具执行 echo、分层镜像 benign 样本、编码变体 benign 请求），
  **不含任何真实恶意载荷/rootkit**；marker 一律 `TRIDENT-BENIGN:` 前缀。
- **遏制**：探针物化只允许写 `--scratch` 目录，引擎
  `trident/core/defenseprobe.py::materialize_probes` 以 `ProbeContainmentError`
  强制（绝对路径/盘符/`..` 一律拒绝）。
- 本目录脚本**只生成文本与 JSON**：部署命令由人工审阅后在授权实验室执行；
  重放清单 `replay-<product>.txt` 由人工逐条执行。

## 目录

| 文件 | 用途 |
|---|---|
| `gen_fixtures.py` | 生成 `fixtures/<product>-{deployed,degraded,absent}.json`（纯本地文件生成） |
| `deploy_products.py` | 生成各产品 KIND 部署命令文本（`--product X --out out/`，不执行） |
| `collect_snapshot.py` | 把人工导出的 kubectl 文本 dump 折叠为 `deploy_snapshot` JSON（只读输入） |
| `replay_probes.py` | 物化良性探针到 scratch + 生成重放清单文本（不执行） |
| `fixtures/` | 两态评估快照 fixture（模块默认数据源：`<product>-deployed.json`） |

## 流程

```bash
# 1) 生成 fixture（幂等）
python lab/defense-deploy/gen_fixtures.py

# 2) 生成部署命令文本 → 人工审阅 → 授权实验室执行（本目录脚本不代跑）
python lab/defense-deploy/deploy_products.py --product elkeid --out out/

# 3) 采集部署面快照（人工导出 dump 后折叠）
python lab/defense-deploy/collect_snapshot.py --dump-dir out/dump/ --out out/snapshot.json

# 4) 模块两态评估（快照直传 / fixture / 默认 lab fixture 三种数据源）
#    run params: {"deploy_snapshot": {...}} 或 {"fixture": ".../elkeid-deployed.json"} 或 {}

# 5) 良性探针重放准备（物化 + 清单；检出断言对照模块矩阵）
python lab/defense-deploy/replay_probes.py --product elkeid --scratch out/scratch
```

## 指纹命名口径（公开仓库）

- **Elkeid**（bytedance/Elkeid）：`elkeid-agent` DS、内核模块 `elkeid.ko`、
  `elkeid-server/manager/hub`；`olehid` 为任务口径别名，保守兼容。
- **AgentSmith-HIDS**（bytedance/AgentSmith-HIDS）：agent + LKM `smith.ko`（driver/LKM make 产物）。
- **veinmind-tools**（公开仓库 chaitin/veinmind-tools，规格口径归字节系重点）：
  扫描器名 `veinmind-backdoor / veinmind-weakpass / …`。
- Falco（falco.ko/falco_ebpf）、Tetragon（TracingPolicy + BPF LSM）、KubeArmor、
  Kyverno/Gatekeeper、Trivy/grype、Wazuh/Osquery、ModSecurity/Coraza/雷池(safeline)、
  Cilium Hubble/Calico flows 同理取自各官方仓库命名。

## 检出断言与硬化闭环

`fixtures/*-deployed.json` + 模块矩阵中的 `detected` 集合即**检出断言**；
实验室重放后逐条对照：命中 → 断言成立；未命中 → 更新 fixture/引擎覆盖表并回填
`hardening` 规则（`rule:product=…:technique=…` 前缀，供规则转化引擎消费）。
