# 对标反思：XBow × ARTEX × KubeTrail（2026-10-25）

> 本文是 XBow 产品差距对标的逐项结论（已对齐 / 待补 / 不补+理由），并给出与
> ARTEX / KubeTrail 的三方定位。ARTEX 与 KubeTrail 的源码级深潜见姊妹篇
> [`REFLECTION-ARTEX-KUBETRAIL.md`](REFLECTION-ARTEX-KUBETRAIL.md)（本文不重复其证据链）。
> XBow 为商业自主渗透产品（xbow.com），无开源代码可克隆——对标基线 = 其公开材料
> （产品页/博客/首届 AI 红队 Pwn2Own 战绩公开报道）宣称的能力面，逐项映射到本仓库实现。

## 0. 三方定位（一句话）

| 产品 | 形态 | 核心循环 | 与 InkBlade 的关系 |
|---|---|---|---|
| **XBow** | 商业 SaaS 自主渗透 agent | 扫描→自主利用→验证→报告，VAPT 自动化 | 能力面对标（本文）；形态不追（见 §3 不补项） |
| **ARTEX** | 开源多 agent 自主渗透系统（AGPL） | LLM 规划→工具执行→人工审批 | 同靶场黑盒基准（37.85s 冷启动/169.8MiB 空闲 RSS，见 `docs/ARTEX-BENCH-RESULT.md`） |
| **KubeTrail / MKAT** | 容器内红队采集器 / EKS 审计工具箱 | 点时快照采集→启发式 findings | 采集器与 InkBlade「链式验证执行器」互补；auditlog 分析见姊妹篇 |

**InkBlade 的差异化核心（一句话）：确定性执行内核 + 全链审批校验——自主性只作用于
「提议」，不作用于「执行」。** XBow/ARTEX 把 LLM 放在执行回路的内环（模型决定下一步并
直接执行）；InkBlade 把 LLM（可选）与规则引擎放在提议环，执行环永远是确定性模块 +
授权（ROE）+ 备份 + 审计四校验。渗透测试的交付物是**可复核的证据**而非攻击成功率，
任何「模型决定了但人无法复现」的步骤都是证据链断裂——这是我们不把自主性放进执行环的
根本理由，也是获客面（合规/审计）的差异化。

## 1. XBow 能力面逐项对标（已对齐）

| # | XBow 公开宣称能力 | InkBlade 实现（2026-10-25） | 状态 | 证据 |
|---|---|---|---|---|
| 1 | 自动资产发现与攻击面枚举 | `inkblade/core/discovery.py`：种子（ns/服务清单/kubeconfig 快照）→ 增量资产库（`assets.db` 新表 `assets`：added/updated/removed 软删除 + 产品推断）；模块经 `resolve_targets/bind_params` 消费资产而非散装 params | **已对齐** | `tests/test_discovery.py` 12 用例 |
| 2 | 自主探索（agent 决定下一步） | `inkblade/core/explorer.py`：LLM 可选（OpenAI 兼容 env `INKBLADE_LLM_*`，失败一律降级）+ 规则兜底（资产产品 ∪ 链前置三态 → 确定性排序）；**逐动作 dry-run 预览 → lead 批准 → 人触发执行** | **已对齐（审批制形态）** | `tests/test_explorer.py` 9 用例；`tests/test_api_xbow.py` explorer 生命周期 |
| 3 | 持续化重测（回归/漂移） | `inkblade/core/scheduler.py`：cron（5 字段白名单解析）/interval 计划 → 到期跑链子集 → 与上次 findings 逐键差异（new/fixed/unchanged）→ `drift.json` 报告 | **已对齐** | `tests/test_scheduler.py` 12 用例 |
| 4 | 流量录制与重放 | `inkblade/core/traffic.py` + `evidence.py` 新表 `traffic`：模块 HTTP 全量录制（请求/响应/sha256）幂等入库；`replay` dry=断言计划 / live=真实重放+status 断言+审计 | **已对齐** | `tests/test_traffic.py` 8 用例 |
| 5 | 验证级 PoC（每个发现可复验） | `inkblade/core/poc.py`：写类 finding 自动附「验证步骤+预期证据」（steps/expected_evidence/result_sha256/回滚一致性）；`reverify` 重放比对；工作区级 `poc.auto_reverify` 开关 | **已对齐** | `tests/test_poc.py` 8 用例（runner 钩子实测） |
| 6 | API-first（全量 REST + 生态集成） | `/api/v1/*`：assets/discover、explorer propose/approve/reject/execute、scheduler add/remove/run-due、traffic/replay、consent/sign、zeroday/enable、rules、poc/reverify；MCP 同步暴露 5 个新只读工具（get_assets/get_explorer_queue/get_schedules/get_traffic/get_drift，共 10 工具） | **已对齐** | `tests/test_api_xbow.py` 16 用例；`tests/test_mcp_xbow.py` 8 用例 |
| 7 | 可视化（资产图/差异/审批/计划） | SPA 六视图 → **十视图**：⑦资产图（namespace→service 层级+产品着色+缺失灰显）⑧差异视图（新增/已修复/未变）⑨审批队列（提议/模式/写面/状态）⑩计划任务（cron/到期/上次 run）；沿用现有渲染栈，静态导出内嵌新数据 | **已对齐** | `tests/test_spa_xbow.py` 5 用例 |
| 8 | 弹药库（指纹→版本→变体） | `inkblade/core/data/version-matrix.json`（42 条横向利用条目：指纹/受影响区间/已修复版本/≥2 变体/来源）+ `core/version_matrix.py`（区间判定白名单文法）+ `core/payloads.py`（参数化变体物化：路径/大小写/点段/百分号编码/方法/头） | **已对齐（本仓库口径）** | `tests/test_version_matrix.py` 14 用例 + `tests/test_payloads.py` 16 用例 |

### 1.1 版本矩阵与挖掘流水线的诚实性口径

- **来源双轨**：每条目 `sources[]` 同时注明（a）本仓库审计轮次（模块探针/lab 两态仿真/真
  k3s 实测）与（b）官方 release notes 抽查（12 源逐条 webfetch 核验，2026-10-25：
  vLLM/SGLang/Ray/KubeRay/HAMi/LiteLLM/Dify/open-webui/AReaL/verl/TRL/slime）。
- **不臆造修复版本**：未见证官方修复的条目 `fixed=null` 且 `fixed_note` 必填
  （如 SGLang 管理路由 fail-open 至 v0.5.22 仍无鉴权修复记录——这本身就是武器情报）。
- **候选 ≠ 漏洞**：挖掘流水线（`inkblade/mining.py`）对 vLLM/SGLang/KubeRay/HAMi/LiteLLM
  各跑一轮「模板验证（14 sink 规则全部锚定样本树）→ 最新 tag 差异复核（lab/mining-fixture/
  上游源码快照 vs 已提交基线）→ 登记册候选」；候选 `status=pending-manual-review` 写入
  `zeroday/registry/candidates/`，**绝不自动入库**（测试断言候选 id 不进模块注册表）。
  首轮产出 9 候选（sglang×1 auth-fail-open / hami×3 pprof / litellm×5 dynamic-import+auth-fail-open），
  样张 `reports/samples/mining/`。

## 2. 待补（诚实缺口，含追赶路径）

| # | 缺口 | 为什么现在不算对齐 | 追赶路径 |
|---|---|---|---|
| 1 | LLM 自主环的实战战绩 | XBow 的卖点是 Pwn2Own 级自主利用战绩；InkBlade 的 LLM 路径仅排序择由（且默认 rules），无自主多步循环 | 在 explorer 上叠加「执行结果→再提议」闭环（仍逐动作审批）；积累授权客户战例后发布对比报告 |
| 2 | 真实目标连续重测数据 | scheduler/drift 全链有测试，但无跨周/跨版本真实租户漂移数据 | 固定 mock+真 k3s 双环境各挂一个 cron 计划跑 4 周，发布 drift 曲线 |
| 3 | SaaS 多租户形态 | REST/MCP 已 API-first，但单机进程内执行（无队列/配额/租户加密隔离） | 任务队列+worker 池+按租户加密证据库（SOTA 矩阵已有该项，口径不变） |
| 4 | 版本矩阵的自动化保鲜 | 矩阵 verified_at=2026-10-25 为快照；latest_tag 靠人工 webfetch | `inkblade mine --refresh-tags`（GitHub API 拉 latest release）+ CI 周任务比对 |

## 3. 不补 + 理由（差异化声明）

| # | XBow/竞品做法 | 我们不做的点 | 理由 |
|---|---|---|---|
| 1 | LLM 直接执行（自主环内执行动作） | **执行环永不确定性化**：LLM 只到「提议」为止，执行=确定性模块+ROE+备份+审计四校验 | 交付物是可复核证据链。「模型决定了但人无法复现」的渗透步骤在合规审计中等于无效证据；这也是 ARTEX `intercept/` 人工审批模块与我们殊途同归的原因——但他们的审批在 agent 内环，我们在执行器外环，校验不可绕过性由 runner 代码路径保证（tests 锁定 423/91/PermissionError 三态） |
| 2 | 全自动绕过验证（绕过即结论） | payload 变体仅做**指纹稳健性/绕过面差分取证**，变体命中写 finding detail 而非「绕过成功」结论 | 变体命中 ≠ 产品失效（可能是路由别名）；结论必须走 defenseprobe 两态评估（deployed/degraded/absent） |
| 3 | 漏洞自动登记/自动武器化 | 挖掘候选强制 `pending-manual-review`，不自动建模块 | 规则命中≠可利用性；误报武器化会污染弹药库可信度（本仓库的护城河恰是 42 条目逐条可溯源） |
| 4 | 黑盒闭源弹药 | 版本矩阵逐条公开来源（审计轮次+官方 notes） | 开源合规审计工具的弹药必须可复核；闭源弹药无法过客户的供应链审查 |
| 5 | 通用 Web 渗透面（XBow 横向面广） | 聚焦 ML 集群九族面（推理引擎/RL 框架/GPU 池化/网关/云） | 通用面已有成熟商业与开源方案；ML 面的技术纵深（KV/PD/NCCL/checkpoint/权重供应链）是我们的不可替代性 |

## 4. SOTA 矩阵更新

`docs/SOTA-2026-10.md` 本次新增/更新 8 行（详见该文档）：资产自动发现、审批制自主探索器、
周期重测与漂移、流量录制与回放、验证级 PoC、API-first REST+MCP 同步、版本矩阵与 payload
变体库（以上**已达成**）；漏洞挖掘流水线（**部分**——候选待人工确认、负责任披露流程未跑）。
计数：22 已达成 / 7 部分 / 6 未达成（原 15/6/6 + KubeTrail 审计分析行）。

## 5. 结论

XBow 的「产品能力面」七项（发现/自主/持续/回放/验证/API/UX）已在本仓库以**审批制 +
证据链优先**的形态对齐；未对齐的是战绩、保鲜自动化与 SaaS 形态（§2）。
执行环的确定性不是落后，而是面向合规审计客户的结构性差异：**自主性提议，确定性执行，
全链可复核。**
