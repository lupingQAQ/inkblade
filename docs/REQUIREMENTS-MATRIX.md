# 需求矩阵（唯一事实源）/ Requirements Matrix

> 建立日期：2026-10-27。依据：仓库文件 + git 历史（`git rev-list --count HEAD`），**不依赖对话记忆**。
> 本文件是全仓需求的唯一事实源；其他文档的计数与状态若与之冲突，以本文件第 1 节为准，并在第 4 节登记修正。
>
> 状态词（四态，互斥）：
>
> - `done`：需求原文要求的交付物存在，且有可复跑的测试或落盘证据。
> - `partial`：已交付但存在实质缺口（口径更弱、覆盖不足、仅参考实现、或专项证据在迁移中被移除）。
> - `not-done`：未交付。
> - `blocked-resource`：设计/脚本已就绪，但缺外部资源（真实 GPU/IB/交换机、云账号、客户环境、厂商回执、OIDC 身份）无法验证。
>
> 责任线：`probe`（目标端探针与模板）／`migration`（run.py→模板收尾与测试合并）／`agent`（规划、自主、记忆、评测）／`defense`（规则、紫队、防护绕过）／`docs`（口径与文档）／`enterprise`（企业集成、试点、发布）。

## 0. 口径声明（先读这一段）

1. **执行载体已换代**：模块 = `module.json` + `template.json`，由目标 Pod 内静态 Rust 探针执行；Python `run.py` 在**工作树与 HEAD 都是 0 个**（删除已提交）。因此「Python 模块 = 成品」的旧口径作废；Rust 运行时两态证据见第 3 节（286/286 `runtime=rust`，每态 3 次一致）。
2. **两套验证口径必须分开写**：`runtime=reference`（参考评估器两态）与 `runtime=rust`（真探针两态）。当前 Rust 侧 **286/286**（二进制 `c8d2f118…`，源码 `1f0f57c`，每态 3 次一致，0 失败）；参考评估器只保留作无 Linux 运行器时的本地回归。
3. **层级只有一套**：检测模型为**十层**（1–9 业务面 + 10 防护绕过）。历史上的「七层控制端架构」只描述控制端组件，不再作为产品层数；「九层」为第 10 层加入前的旧称。
4. **数字只从 JSON/目录/registry 取值**，不从散文取值。第 1 节每一行给出计算方式。

## 1. 权威数字（对账基线，2026-10-27 工作树）

| # | 指标 | 权威值 | 计算/来源 | 旧口径（作废） |
|---:|---|---|---|---|
| 1 | 模块目录 | **287** | `inkblade/modules/*/module.json` 计数 | 275（SOTA 终版块）、264（SURFACE-REALISM 分母）、138（DEV-LOG C.3） |
| 2 | 默认启用/隔离 | **276 / 11** | `default_enabled=false` 计数 | 264 / 11；「12 个全无面、9 个隔离」 |
| 3 | 模板 / bootstrap | **286 / 1** | `template.json` 计数；`probe-bootstrap` | 「模板迁移进行中」未给数 |
| 4 | 旧 `run.py` | **0（工作树）／0（HEAD，已提交删除）** | 目录扫描 vs `git ls-tree HEAD` | README/动态验证「286 个 run.py 仍保留」 |
| 5 | 按系列 | 侦察 68·横向 66·网络 52·权限 43·代码 22·窃取 19·混合云 11·情报 6 | module.json `series` | 九族「各 2 个代表模块」 |
| 6 | 写类模块 | **67** | `writes=true` 计数 | — |
| 7 | 攻击链 | **29**（经典 9·云 5·网络 12·零日 2·AI 网关 1） | `inkblade/chains/*.json` `category` | spec「7+4+5+2=18」；SOTA「29」已对 |
| 8 | 规则 | **121**（Sigma 94·Falco 11·Suricata 8·准入 5·netpol 1·vpc-sg 1·ib 1） | `reports/samples/rules-pack/mapping.json` | 21（首版）·35·52·101·56 CVE 规则等历史阶段值 |
| 9 | 紫队覆盖 | **28/29 链·0 漏过**（98 次规则评估 = 拦截 21 + 检测 73 + 建议 4） | `reports/samples/rules-pack/coverage-matrix.json` | 「全链覆盖」未注明 1 条链（CVE 链）未重放 |
| 10 | 可利用性核验 | **152 = 37 verified + 6 exposure-verified + 87 static-only + 22 unsupported** | `inkblade/core/exploit-registry.json` `summary.total` | 「37/93/22」（把 6 条 exposure 并入 static） |
| 11 | 部署面分类 | **11 default-exposed · 27 needs-config · 91 function-level · 23 hardware-only** | registry `deployment.counts` | 「默认 PoC = 2」 |
| 12 | 零日清单 | **169**（candidate 109 · novelty-checked 47 · public 13） | `inkblade/core/zeroday-registry.json` `entries` | 「6 条私有零日」「首批 6 条未披露」 |
| 13 | 零日储备 | **reserve-eligible 46 · 去重 39** | `summary.reserve` / `summary.reserve_unique` | 「47 条储备」 |
| 14 | 武器包 | **47 包 / 33 模块 / 99 变体** | `inkblade/core/data/weapon-packs.json` | 「47 条全部武器化」未区分 reserve 46 |
| 15 | 版本矩阵 | **103 条** | `inkblade/core/data/version-matrix.json` `entries` | 「42 条」（CVE 扩表前） |
| 16 | 架构语料 | **80 源**（official-cn 24 · official-en 42 · paper 14；verified 75 + partial 5；万卡证据 32；本轮新增 32） | `inkblade/arch-intel/coverage-matrix.json` + `check.py` | 35（SOTA 头部）·34/35（SDD 台账）·official-cn 28·official-en 41·wanka 23 |
| 17 | 画像覆盖（production） | airgapped **70.65%** · bare-k8s-gpu **67.39%** · gpu-pooling **59.78%** · managed-ack-tke **67.75%** · ray-vllm **68.48%** · slurm-hpc **25.00%** | `inkblade.core.surface.matrix()`（分母=默认启用 276） | 73.48/70.08/62.12/70.45/71.21/25.76（275 模块时代） |
| 18 | 默认可利用 PoC/画像 | **3 / 2 / 3 / 2 / 4 / 0**（全局 default-exposed 11） | registry `deployment.by_profile` | 1/1/2/0/2/0 |
| 19 | 全画像无面 | **19** 个（11 已隔离 + 8 待 owner 决定） | `surface.matrix()` 六画像交集 | 「12 个全无面、9 已隔离、3 保留」 |
| 20 | 实效验证 | **53/53 PASS** | `reports/samples/effects/effects.json` `checks` | 17/17·20/20·22/22·25/25·31/31·34/34·47/47（历史阶段） |
| 21 | LLM 探针 | **87 探针 / 13 类** | `inkblade/probes/library/` + `docs/PROBE-PARITY.md` | garak 对比只写「87」未写占比 60% |
| 22 | CIS / LPE | **CIS 161 / LPE 52** | `inkblade/cis/catalog.py` `CATALOG`；`inkblade/lpe/catalog.py` | 专项单测 `test_cis_benchmark.py`、`test_kernel_lpe.py` 已在迁移中删除 |
| 23 | 对比工具数 | **竞品 23 · 缺口 31 · OSS 34 · 腾讯 8** | `COMPETITIVE-MATRIX.md`、`docs/gap-matrix.json`、`docs/oss-ml-cluster-tools.json`、`SECTION3` | OSS「32 个工具」（同文档正文） |
| 24 | 缺口行数 | **260 = 功能 122 + 攻击面 82 + payload 56**；已有 36+35+21=92、部分 47+29+18=94、缺失 39+18+17=74 | `docs/gap-matrix.json` | — |
| 25 | 测试总数 | **Ran 1936 tests / OK (skipped=13)**（agent 运行时/文件审计/绕过路径并入后的稳定快照；1288.533s） | `python -m unittest discover -s tests`（§3.4、§5） | 1841（探针收口快照）·2128（迁移在途红测）·2003·1974·1934·1933·1278·1260·1140（历史快照） |

## 2. 需求矩阵

### 2.1 初始平台需求（来源：spec 2026-10-24 v2–v7 + plan 2026-10-25）

| ID | 需求（原文摘要） | 来源锚点 | 状态 | 证据路径 | 缺口（一句话） | 责任线 |
|---|---|---|---|---|---|---|
| INIT-01 | 以 K8s 内网为作业面：授权后在集群内采集，而非仅外部扫描 | spec §1.1、§5.2；plan 侦察任务 | done | `inkblade/collect/{k8s,http,files,hardware}.py`；`inkblade/modules/probe-bootstrap/`；`session`/`probe`/`channel` CLI；`docs/SURFACE-REALISM.md` | 投放与通道已有命令面，但 Rust 二进制未入库，实机投放未验证 | probe |
| INIT-02 | 侦察模块族 11 类（暴露面/网络策略/Ray/特权/RBAC/存储/观测/框架端口/元数据/逃逸/云指纹） | spec §5.2 侦察表；plan 侦察任务 | done | `inkblade/modules/`（侦察 68）；`tests/test_probe_templates.py`；`reports/probe-coverage/evidence.json` | 两态证据为 `runtime=rust`（负控边界见 PROBE-COVERAGE §6） | probe |
| INIT-03 | 把已复现 RL/推理引擎漏洞（40+，含 file:line）产品化为横向利用模块 | spec §1.1-1、§5.2 横向表 | done | 横向 66 模块；`docs/EXPLOIT-VERIFICATION.md`；`inkblade/core/data/version-matrix.json` | 动态复现 37/152，其余为 static/unsupported | probe |
| INIT-04 | 权限过大配置产品化为权限链模块（6 条原语） | spec §1.1-2、§5.2 权限链表 | done | 权限链 43 模块；`docs/PRIVESC-MATRIX.md`；`tests/test_privesc_matrix.py` | 47 向量中多数靠 fixture 判定，真实集群仅 4 项 | probe |
| INIT-05 | 窃取与数据泄露模块（蒸馏/凭据/共享卷/训练数据） | spec §5.2 窃取表 | done | 窃取 19 模块；`inkblade/core/redact.py`；`docs/CACHE-SECURITY.md` | 抽样为 fixture 数据集，非客户真实数据面 | probe |
| INIT-06 | 核心代码静态审计（sink/鉴权/供应链/SSRF/组合签名，输出 file:line） | spec §5.2 代码表 | done | 核心代码 22 模块；`inkblade/core/codescan.py`；`inkblade/core/data/sink-rules.json` | 规则库为抽样 sink，不是全语言数据流分析 | probe |
| INIT-07 | 网络架构十模块（fabric/CNI/Multus/集合通信/operator/网关/存储/DNS/可达性/调度） | spec §5.2 网络表、§5.6 七层模型 | done | 网络 52 模块；`inkblade/core/reachability.py`、`graph.py`；`docs/DETECTION-LAYERS.md` | IB/SR-IOV/IMEX 仅 fixture 推演，无硬件实证 | probe |
| INIT-08 | 混合云三模块（多云 IMDS/云角色过权/混合出网回旋） | spec §5.2 混合云表 | done | 混合云 11 模块；`lab/cloud_six_sim.py`；`docs/SIX-CLOUD-MATRIX.md` | 契约级仿真，无真实账号/IAM 求值 | probe |
| INIT-09 | 情报模块（架构语料导入、要素→检查项映射） | spec §5.2 情报表、§12 | done | 情报 6 模块；`inkblade/arch-intel/`；`docs/RESEARCH-COVERAGE.md` | 语料为文档级，未转为可执行资产模型 | probe |
| INIT-10 | 私有零日内置（6 条，加密武器库、默认关闭、报告脱敏） | spec §1.1-12、§5.7 | done | 6 个 `dify-*`/`open-webui-*` 模块；`inkblade/core/zeroday.py`（默认关）；`docs/0DAY-PUBLIC.md` | 口径已更正为「公开漏洞模块」：`private=false`、正常展示；加密库降为可选扩展 | docs |
| INIT-11 | 零日挖掘流水线与披露生命周期 | spec §5.7、§18-16 | done | `inkblade/mining.py`；`tools/novelty-check.py`；`corpus/zeroday/inventory.json`（169）；`docs/0DAY-DISCLOSURE.md` | 披露仅到「包已生成未外发」，无厂商回执/CVE 分配 | docs |
| INIT-12 | 防护产品绕过 11 模块（字节系为重点，良性 marker，检出/盲区/硬化） | spec §1.1-13、§5.2 绕过表 | done | 11 个 `defense-bypass-*`；`inkblade/core/defenseprobe.py`；`docs/DEFENSE-LAB-RESULTS.md`（QEMU k3s 真机回放 4 产品）；`tests/test_probe_defense_bypass.py` | Kyverno/Falco/Trivy/ModSecurity 已真机回放；Elkeid/AgentSmith/veinmind/Tetragon/KubeArmor/Wazuh/Hubble 因内核头/BPF-LSM/CNI 明确 N/A | defense |
| INIT-13 | 攻击链目录齐全（经典 7 + 云侧 4 + 网络 5 + 零日 2） | spec §6.3；plan 链任务 | done | `inkblade/chains/` 29 条（超集） | 零日 2 条与 CVE 1 条依赖外部条件，紫队未重放 CVE 链 | defense |
| INIT-14 | 链前置三态判定 + dry-run 计划（模块/参数/备份动作/写面） | spec §6.2；§18-4 | done | `inkblade/core/chains.py`；`tests/test_chains.py`；`docs/RUNBOOK.md` | 表达式为自定义子集，复杂布尔需拆分 | docs |
| INIT-15 | 写类模块强制备份校验，无回执拒绝执行（退出码 91） | spec §4.3；§18-2 | done | `inkblade/core/backup.py`、`runner.py`；`tests/test_backup.py`、`test_runner.py` | 回滚对远端不可逆动作只能标记 unsupported | docs |
| INIT-16 | 授权向导 + 要素哈希签存 + 分级校验 + 范围校验（未签→423/拒绝） | spec §4.2；§18-1 | done | `inkblade/core/roe.py`；`tests/test_roe.py`、`test_consent_signature.py`、`test_runner_scope_audit.py` | 签名为工作区 HMAC，不是 CA 证书链 | docs |
| INIT-17 | 多用户四角色（admin/lead/tester/auditor）+ 多工作区硬隔离 | spec §4.1；§18-7 | done | `inkblade/core/users.py`；`tests/test_users.py`；`tests/test_e2e.py`（跨工作区拒绝） | 无 LDAP/OIDC 真实联调（仅契约 mock） | enterprise |
| INIT-18 | 三层证据（上下文摘要/SQLite/归档 tar+SHA256）+ manifest 篡改检测 | spec §7；§18-3 | done | `inkblade/core/evidence.py`；`tests/test_evidence.py`、`test_sample_determinism.py` | 归档层在 Windows 无 zstd 时降级 gzip（已声明） | docs |
| INIT-19 | 双语渗透报告（PTES 七段 + NIST 800-115 + 等保 2.0 + GB/T 20984 + CVSS 3.1 + ATT&CK/ATLAS） | spec §8；§18-5 | done | `inkblade/reports/render.py`、`cvss.py`、`standards.json`；`tests/test_reports.py`；`reports/samples/pentest-report-bi.md` | 等保/20984 为条款映射，不是测评机构结论 | docs |
| INIT-20 | 五个 ML 专节（组合层/数据泄露/核心代码 file:line/网络分层/混合云边界） | spec §8.2 | done | `tests/test_reports_network_layers.py`；`reports/samples/pentest-report-bi.md` | 混合云节内容来自仿真证据 | docs |
| INIT-21 | 修复报告 + 规则包交付文档，同批交付 | spec §8.1、§10.4 | done | `inkblade/reports/render.py`（remediation）；`docs/DELIVERY.md` | 复测计划为模板化，未接客户工单 | enterprise |
| INIT-22 | 可视化六视图（DAG/攻击链/时间线/证据浏览器/报告/规则），全离线 | spec §9；§18-6 | done | `inkblade/webui/`、`export_static.py`；`tests/test_spa.py`；`reports/samples/static-export/` | 后端 API 与前端数据绑定有 e2e，但无真实浏览器自动化 | docs |
| INIT-23 | 规则转化三件套（Kyverno/Gatekeeper、per-CNI NetworkPolicy、Sigma/Falco/Suricata） | spec §10；§18-8 | done | `inkblade/rules/generate.py`；`reports/samples/rules-pack/`（121 规则） | 全部 monitor 模式，未在客户集群 enforce | defense |
| INIT-24 | 规则↔攻击映射 + 紫队验证闭环（覆盖率矩阵） | spec §10.3 | done | `inkblade/rules/validate.py`；`coverage-matrix.json` | 28/29 链重放；CVE 链未纳入 | defense |
| INIT-25 | 全量公开架构基线 + 覆盖矩阵（自建≥8、六云各≥2、混合≥3、网络专源≥8） | spec §12；§18-10 | done | `inkblade/arch-intel/coverage-matrix.json`（80 源）；`check.py` ALL GATES ok | 门槛为文档源数量，不是架构指纹覆盖率 | docs |
| INIT-26 | 命名规范：禁止「字母+数字」条目编号，机器键纯单词 kebab-case | spec 卷首 v5；plan Global Constraints | done | `inkblade/core/registry.py` `_KEY_RE`；287 键扫描 | 2 个键含语义数字（`kubelet-10250-exec`、`llm2jev-file-read`），无序号式编号 | docs |
| INIT-27 | 超越 ARTEX：资源占用、攻击速率、多用户/多工作区 | spec §11；§18-9 | partial | `docs/PERFORMANCE-COMPARISON.md`；`docs/ARTEX-BENCH-RESULT.md`；`reports/samples/artex-bench/` | ARTEX 跑在 QEMU TCG，缺裸机同口径与 30 分钟稳定性；「≥10 倍」不可作产品倍率 | docs |
| INIT-28 | 实验室：mock 靶场 + fake-kubectl + KIND 场景 + bench | spec §13 | done | `lab/mock_targets.py`；`lab/fixtures/`；`lab/qemu-k3s/`；`lab/bench/` | KIND 因本机 HCS 不可用未跑；用 QEMU k3s 等价替代 | docs |
| INIT-29 | 技术选型：运行时仅标准库、离线可用、Windows+WSL 双运行时 | spec §15；plan 约束 | done | `pyproject.toml`（无运行时三方依赖）；`tests/test_env_compat.py`；`docs/INSTALL.md` | 可选依赖（zstd/cryptography）缺省降级，性能不同 | docs |
| INIT-30 | 检测焦点之一：组合签名矩阵（单组件不报、组合才成立） | spec §5.4；plan 组合任务 | done | `inkblade/core/combo.py`、`data/combo-matrix.json`；`tests/test_combo.py` | 组合条目 20+，未覆盖全部 287 模块交互 | defense |
| INIT-31 | 安全默认：先探测后动作、写类带运行标记、凭据默认脱敏尾 4 位 | spec §5.3 | done | `inkblade/core/redact.py`；`tests/test_modules_theft.py`（迁移中删除，模板断言替代）；`docs/EFFECT-VERIFICATION.md` | 迁移删除了部分专项测试，脱敏断言改由模板证据覆盖 | migration |
| INIT-32 | 验收基线 17 条（授权锁/备份闸/三层证据/链目录/双语样张/六视图/四角色/规则/bench/情报/混合云/网络/per-CNI/网络链/零日/挖掘/绕过） | spec §18 | partial | `inkblade/e2e-check.py`；`reports/samples/e2e/e2e-check.md`（15 项 PASS） | e2e 只覆盖 9 族代表子集 18 模块；验收 9（bench 10×）与 11（云 chain dry-run）未形成断言 | docs |

小计：INIT 32 条。

### 2.2 后续追加需求（来源：progress.md / DEV-LOG 任务台账 + 专项 docs）

| ID | 需求（原文摘要） | 来源锚点 | 状态 | 证据路径 | 缺口（一句话） | 责任线 |
|---|---|---|---|---|---|---|
| ADD-01 | 长上下文/大规模训练 8 模块（窗口耗尽/前缀缓存跨租户/KV 投毒/PD 通道/集合通信/分片投毒/内存放大/限额绕过） | progress 行 13；`docs/LONG-CONTEXT.md` | done | 8 模板；`lab/longctx_sim.py`；`tests/test_probe_longctx.py` | 仿真计时，非 GPU 实测 | probe |
| ADD-02 | 长上下文链接入规则引擎（cache-leak / pd-kv-poison） | progress 行 14 | done | 2 链；`reports/samples/rules-pack/mapping.json` | 规则评估含 4 条「建议」不计拦截 | defense |
| ADD-03 | AI 网关与配套基建 10 模块（LiteLLM/Higress/缓存/配额/日志/护栏/注册表/向量库） | progress 行 15；`docs/AI-GATEWAY.md` | done | 10 模板；`lab/ai_gateway_sim.py`；`tests/test_probe_cache_gateway.py` | 上游 key 仅 mock 值，无真实 provider 泄露验证 | probe |
| ADD-04 | AI 网关链 + Sigma×2/Falco/Suricata 规则 | progress 行 16 | done | `ai-gateway-key-exfil`；`reports/samples/rules-pack/` | 紫队重放为 HTTP 差分 | defense |
| ADD-05 | GPU 组卡/池化与云平台跨租户 10 模块 | progress 行 17；`docs/GPU-CLOUD-TENANCY.md` | done | 10 模板；`lab/gpu_cloud_sim.py`；`tests/test_probe_templates.py` | MIG/MPS 残留以 marker 表达，无真实显存 | probe |
| ADD-06 | GPU/云跨租户 2 链 + 5 规则 | progress 行 18 | done | `gpu-tenant-residue-chain`、`cloud-cross-tenant-role-assume` | 云侧为身份契约仿真 | defense |
| ADD-07 | CVE 武器库（50 CVE + 6 advisory 入库，含可利用性） | progress 行 54；`docs/CVE-CATALOG.md` | done | `inkblade/core/cve-catalog.json`（56 条）；`tests/test_cve_catalog.py` | CVE 条目 56 中 verified 15 | probe |
| ADD-08 | CVE 适用性三件套：版本区间 × 前置条件 × 实测证据，四态 | progress 行 61；`docs/CVE-APPLICABILITY.md` | done | `inkblade/core/applicability.py`；`inkblade/assess/inventory.py`；`tests/test_applicability.py` | unknown 保持 unknown，不自动升级（正确但覆盖率受限） | probe |
| ADD-09 | 内网入口→集群最高权限夺权链（7 阶段，真实 k3s 全链） | progress 行 63；`docs/KILL-CHAIN.md` | done | `inkblade/core/objective.py`；`tests/test_objective.py`、`test_kill_chain_artifacts.py`；`reports/samples/` | 真实环境为 QEMU TCG 单节点 | probe |
| ADD-10 | 全量提权矩阵 47 向量 + 提权图 + 自动选路 | progress 行 56；`docs/PRIVESC-MATRIX.md` | done | `inkblade/core/privesc.py`；`tests/test_privesc_graph.py`、`test_privesc_real.py` | 真实集群 4/47 向量实测 | probe |
| ADD-11 | 提权检测规则（47 Sigma/Falco + 6 Kyverno）与报告章节 | progress 行 57 | done | `inkblade/rules/privesc.py`；`tests/test_privesc_rules.py` | 规则为生成式，未逐条客户日志验证 | defense |
| ADD-12 | 企业就绪 60 项三态 + 四阶段准入门槛 | progress 行 47；`docs/ENTERPRISE-READINESS.md` | partial | `inkblade/enterprise/`；`tests/test_enterprise_lab.py`、`test_enterprise_local_gaps.py`；SOTA 表：绿 36 / 黄 3 / 红 21 | 21 项红项必须客户环境；本仓库无 SLA/认证 | enterprise |
| ADD-13 | 试点模式：多 kubeconfig 合并→只读画像/热图/计划/审批清单 | progress 行 47；`docs/PILOT-KIT.md` | done | `inkblade pilot`；`tests/test_pilot.py` | 仅单节点 k3s 实跑 | enterprise |
| ADD-14 | 企业集成契约：OIDC/LDAP、Splunk/Elastic/Webhook/Jira/ServiceNow、双签审批 | progress 行 47；`docs/OPERATIONS.md` | partial | `inkblade/enterprise/`；`tests/test_enterprise_integrations.py` | 全部本地契约/mock，未联调客户 IdP/SIEM/ITSM | enterprise |
| ADD-15 | 零摩擦上手：doctor/demo/quickstart + 10 类错误三行式 + README 5 分钟 | progress 行 49 | done | `inkblade doctor`、`demo`、`quickstart`；`tests/test_onboarding.py` | demo 已被产品口径收紧为「模板验证」 | docs |
| ADD-16 | 陌生用户走查实测（基线 7 命令/3 失败 → 2 命令/0 失败） | progress 行 50；`docs/ONBOARDING-EVALUATION.md` | done | `docs/ONBOARDING-EVALUATION.md` | 单次走查，非多用户统计 | docs |
| ADD-17 | 2026 Agent 架构研究（30 源，12 落伍点 G01–G12，16 设计点 A01–A16） | `docs/AGENT-ARCHITECTURE-2026.md`；progress 行 34 | done | `docs/AGENT-ARCHITECTURE-2026.md`；`tests/test_agent_architecture_docs.py` | 研究结论未全部落地（见 ADD-19～25） | agent |
| ADD-18 | supervisor-worker + 队列 + journal + 三层记忆 + 技能库 + reflexion + A2A + 沙箱 | `docs/AGENT-ARCHITECTURE-2026.md` §4；progress 行 35 | partial | `inkblade/core/{journal,supervisor,memory,skills,reflexion,a2a,sandbox}.py`；`tests/test_{journal,supervisor,memory,skills,reflexion,a2a,sandbox}.py` | 组件齐备但为单进程/本地实现，durable 队列与 microVM 未做 | agent |
| ADD-19 | Durable journal：每步前后落一条，崩溃可恢复、写类不重复副作用 | `AGENT-ARCHITECTURE-2026.md` A01（P0） | partial | `inkblade/core/journal.py`；`tests/test_journal.py` | 仅本地 SQLite journal，无 cross-process lease/恢复演练 | agent |
| ADD-20 | 任务队列 + worker 池（claim/lease/heartbeat/优先级/死信） | A02（P0） | partial | `inkblade/core/supervisor.py`；`tests/test_supervisor.py` | 进程内队列，无 broker/跨副本租约 | agent |
| ADD-21 | 三层记忆（working/episodic/semantic） | A03（P0） | partial | `inkblade/core/memory.py`；`tests/test_memory.py` | episodic 跨 run 检索为本地文件，无向量/图检索 | agent |
| ADD-22 | 技能库（SKILL.md + scripts + allowed-tools，签名/版本） | A04（P0） | partial | `inkblade/core/skills.py`；`tests/test_skills.py` | 无独立 `skills/` 分发目录与签名晋升流程 | agent |
| ADD-23 | Reflexion 复盘（run 结束生成 reflection，下轮 propose 读取） | A09（P1） | partial | `inkblade/core/reflexion.py`；`tests/test_reflexion.py` | reflection 仅文本，无效果度量 | agent |
| ADD-24 | A2A 只读网关（recon/plan/verify 三能力，写能力不暴露） | A11（P1） | partial | `inkblade/core/a2a.py`；`tests/test_a2a.py` | 无 agent card 注册与跨组织联调 | agent |
| ADD-25 | 沙箱执行器（默认无网、只读根、一次性工作目录） | A05（P0） | partial | `inkblade/core/sandbox.py`；`tests/test_sandbox.py` | 子进程/目录级隔离，非 microVM；无 egress allowlist 内核强制 | agent |
| ADD-26 | L3 自主：token 预授权 + 工作区 HMAC + 预算硬顶 + 异常即停 + 可回放 | progress 行 78；`docs/AUTONOMY.md` | done | `inkblade/core/autonomy.py`；`tests/test_autonomy.py`；`docs/AUTONOMY.md` | 真实 LLM 端点不在 CI 调用，端到端演练留客户环境 | agent |
| ADD-27 | 角色化多进程 swarm（recon/exploit/verify/report） | progress 行 78；`docs/SWARM-EVAL.md` | done | `inkblade/core/swarm.py`；`tests/test_swarm.py`、`test_swarm_eval.py` | 数字来自 simulate 执行器，不冒充真实模块 SLA | agent |
| ADD-28 | Agent 评测基座（15 任务 6 类，deterministic vs supervisor-worker） | `docs/AGENT-EVAL-RESULTS.md` | done | `lab/agent-eval/`；`reports/samples/agent-eval/agent-eval.json`；`tests/test_agent_eval.py` | 15 任务规模，非 AgentDojo/CyberGym 级 | agent |
| ADD-29 | 腾讯 8 任务 OFF/ON 微评测（成功率/时延/token/干预/证据覆盖） | `docs/SECTION3-METRICS.md` | done | `lab/tencent-compare/`；`reports/samples/tencent-compare/`；`tests/test_tencent_compare.py` | 不调用外部 LLM，不能替代冻结模型真实靶场跑分 | agent |
| ADD-30 | Rust 探针：单静态二进制，目标端零解释器（发布 `probe-v0.1.1`，源码 `1f0f57c`） | `docs/ARCHITECTURE-PROBE.md`；README；`docs/PROBE-BUILD.md` | done | `probe/src/*.rs`（21 文件已入库）；`probe/Cargo.toml`；tag `probe-v0.1.1`（CI run 40430384961，两次独立构建字节一致）：linux-amd64 `c8d2f118…` 2,066,112 B、linux-arm64 `6d480367…` 1,775,584 B；`.github/workflows/probe-release.yml` | 本机 cargo 被 WDAC/SAC 拦截，二进制只能走 CI；`dist/` 不入 git；`exec`/`scan` 简写未实现 | probe |
| ADD-31 | 探针协议：长度前缀 JSON 帧、认证、任务/结果、预算、文件分块、清理、错误码 | `docs/PROBE-PROTOCOL.md` | done | `probe/src/protocol.rs`、`server.rs`；`inkblade/channel.py`；`tests/test_probe_channel.py`（11 项） | challenge-HMAC 而非 mTLS；依赖 `kubectl exec -i` 通道 | probe |
| ADD-32 | 多探针父子树（probe_id/parent_id、per-child token、depth/fan-out、child-first cleanup） | README「Probe trees」；`docs/ARCHITECTURE-PROBE.md` | done | `inkblade/core/probes.py`（SQLite parent_id/children/cleanup）；`tests/test_session_probe_entry.py`（parent_child_tree、controller_spawn_and_cleanup_tree） | 未在真集群做多探针跨节点演练 | probe |
| ADD-33 | 全量探针化：287 模块全部改为 JSON 模板 | progress 行 110/113/115/118；`docs/PROBE-COVERAGE.md` | partial | 286 `template.json`；`tests/test_probe_templates.py`；`docs/PROBE-COVERAGE.md` | Rust 运行态 286/286 已通；等价模板 48 / 降级 238（降级语义未补齐） | migration |
| ADD-34 | 模板 schema + 表达式引擎 + 工具链（lint/run/generate/coverage） | `probe/schema/probe-template.schema.json`；`inkblade/tpl/`；`tools/template-*.py` | done | `tests/test_probe_lowering.py`、`test_probe_templates_dynamic.py` | 参考评估器与 Rust 实现存在语义漂移风险（无差分测试） | probe |
| ADD-35 | Rust 运行时动态验证（每模板 vulnerable/fixed 两态、3 次一致、证据含 probe 版本） | `docs/DYNAMIC-VERIFICATION.md` §2、§4、§8 | done | `reports/probe-coverage/evidence.json`（286 条 `runtime=rust`，probe `0.1.1`，binary `c8d2f118…`，source `1f0f57c`，`repeat=3`，`consistent=286`，802s，0 失败）；`reports/probe-coverage/evidence-native.json`；`docs/PROBE-COVERAGE.md` | 负控：fixed `status=ok` 仅 **35/286**，`same_finding=false` **49/286**；其余模板两态共用 fixture 输入，只算执行验证（`PROBE-COVERAGE.md` §6） | migration |
| ADD-36 | 迁移收尾：删除 286 个旧 `run.py`，注册表只认模板 | `docs/PROBE-MIGRATION-BRIEF.md`；README 证据节 | done | `git ls-tree HEAD`：工作树 0 / HEAD 0；`inkblade/core/registry.py` 只接受 `template.json`；`tests/test_probe_templates.py` | 32 个模块专项测试随 `run.py` 删除，改由 `tests/test_probe_*.py` 模板断言覆盖（覆盖不等价） | migration |
| ADD-37 | 项目改名 InkBlade（包/命令/环境变量/标记/schema），旧名兼容一版 | progress 行 101；`CHANGELOG.md` | done | `inkblade/`；`pyproject.toml` 0.2.0；`tests/test_public_tree.py` | 历史台账仍含旧名（已声明不计残留） | docs |
| ADD-38 | 开源发布工程：CI（Win+Linux×py3.10–3.13）、Docker、Helm、cosign、SBOM | progress 行 105 | done | `.github/workflows/{ci,release,docker}.yml`；`Dockerfile`；`deploy/helm/inkblade`；`build/` | 发布步骤 opt-in，未真实发版到 PyPI/GHCR | enterprise |
| ADD-39 | 插件 SDK（manifest、entrypoint 约束、指纹+信任库、结果 schema） | progress 行 106；`docs/PLUGIN-SDK.md` | done | `inkblade/sdk/`；`tests/test_sdk.py` | 第三方生态为零（仅 `examples/hello-surface`） | enterprise |
| ADD-40 | 公开文档站（中英）+ AI 相似度扫描 + 链接检查 | progress 行 111；`docs/AI-SCAN-RESULT.md` | done | `docs/{index,en/index,zh/index}.html`；`scripts/check-docs-links.py`；`tests/test_docs_site.py` | 扫描阈值为启发式，非作者归属证明 | docs |
| ADD-41 | 供应链：CycloneDX ML-BOM、cosign 风格 provenance、TEE 证明策略断言 | progress 行 19；`docs/KEYLESS-VERIFICATION.md`、`TEE-VERIFICATION.md` | partial | `inkblade/supplychain.py`；`inkblade/sigstore_keyless.py`；`inkblade/tee/`；`tests/test_supplychain.py`、`test_tee.py`、`test_tee_online.py` | 自有产物无公共 Fulcio 身份；硬件 TEE 无实机 quote | enterprise |
| ADD-42 | MCP 只读工具（10 个）+ Agent 规划器（只读、lead 审批） | progress 行 19/32；`docs/SOTA-2026-10.md` | done | `inkblade/mcp_server.py`；`inkblade/agent_planner.py`；`tests/test_mcp.py`、`test_mcp_xbow.py` | 零写工具是设计约束，不提供执行能力 | agent |
| ADD-43 | 机器可读导出 SARIF 2.1.0 / OCSF 1.5 / OpenVEX | progress 行 19 | done | `inkblade/export.py`；`tests/test_export.py` | 无真实 SIEM 投递 | enterprise |
| ADD-44 | 混沌编排 18 实验 + 编排器 + 自动回滚 + SLO 度量 | progress 行 75；`docs/CHAOS-PARITY.md` | done | `inkblade/chaos/`；`tests/test_chaos.py` | 实跑仅延迟/断连/PFC 三实验 | probe |
| ADD-45 | 多租户缓存安全 7 模块 + 2 链 + 5 规则 | progress 行 73；`docs/CACHE-SECURITY.md` | done | 7 模板；`lab/cache_sim.py`；`tests/test_probe_cache_gateway.py` | TTFT 为确定性仿真，非 GPU 计时 | probe |
| ADD-46 | 开源 ML 集群工具全景（34 工具 × 15 维）与本机实测 10 项 | progress 行 69；`docs/OSS-BENCH.md` | done | `docs/oss-ml-cluster-tools.json`；`docs/OSS-ML-CLUSTER-TOOLS.md`；`tests/test_oss_landscape.py` | 14 项跑不了已逐条记原因 | docs |
| ADD-47 | 2026 安全会议 infra 覆盖（20 会议/65 议题→16 模块） | progress 行 83；`docs/CONFERENCE-2026-GAPS.md` | done | 16 模板；`lab/infra2026_sim.py`；`tests/test_infra2026_docs.py` | 隔离效果仅 3/3 实测 | probe |
| ADD-48 | R01–R07 残余缺口 7 模块 + 必要性标注 | progress 行 91；`docs/RESIDUAL-GAPS-2026.md` | done | 7 模板；`tests/test_modules_residual2026.py`（迁移中已删，模板断言替代） | 4 个默认关闭、无面 | probe |
| ADD-49 | Slurm HPC 12 模块 + 17 域覆盖 88.2% | progress 行 92；`docs/SLURM-HPC-COVERAGE.md` | done | 12 模板；`tests/test_slurm_docs.py` | 画像 production coverage 仍 25% | probe |
| ADD-50 | 硬件与交换机 9 模块（GPU/固件/BMC/NVSwitch/DPU/SONiC/IB-SM/SHARP/遥测/供应链） | progress 行 51；`docs/HARDWARE-SWITCH-COVERAGE.md` | partial | 9 模板；`lab/hardware_sim.py`；`tests/test_hardware_docs.py` | 无真实 GPU/BMC/交换机；BMC 默认凭据命中即停 | probe |
| ADD-51 | 加速器芯片 8 模块（A/B/C 分级，C 默认关） | progress 行 88；`docs/CHIP-SECURITY-SCOPE.md` | partial | 8 模板；`lab/chipsec_sim.py`；`tests/test_chipsec_sim.py` | 无硅片/物理故障注入；C 级不计能力 | probe |
| ADD-52 | 预训练/SFT/RL 训练栈 10 模块 + 29 路由双态 | progress 行 58；`docs/PRETRAIN-SFT-RL-COVERAGE.md` | done | 10 模板；`lab/trainstack_sim.py`；`tests/test_trainstack_sim.py` | 版本矩阵未扩 Megatron/DeepSpeed/LLaMA-Factory | probe |
| ADD-53 | XBow 对标七项（资产发现/审批探索器/调度/流量/PoC/API-first/十视图） | progress 行 32；`docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md` | done | `core/{discovery,explorer,scheduler,traffic,poc}.py`；`tests/test_api_xbow.py`、`test_spa_xbow.py` | 自主性保持「提议+审批」，刻意不做无人执行 | agent |
| ADD-54 | 0day 真实查新与储备状态机（OSV/NVD/GHSA/vendor 四路） | progress 行 97/99；`docs/0DAY-RESERVE.md` | done | `tools/novelty-check.py`；`inkblade/core/reserve.py`；`tests/test_novelty_check.py`、`test_zeroday_reserve.py` | 无自动披露；候选需人工复核 | docs |
| ADD-55 | CVE 就绪披露包（30 包 + CVE 5.1 请求体 + 90 天时间线） | progress 行 100；`docs/DISCLOSURE-RELEASE-PLAN.md` | partial | `disclosure/`（30 目录）；`tests/test_disclosure_packages.py` | 0 已发送 / 0 CVE 申请，缺厂商回执 | docs |
| ADD-56 | 武器化就绪度：152 条部署面证据化 + 47 武器包 + 99 变体 | progress 行 103；`docs/WEAPON-READINESS.md` | done | `inkblade/core/data/weapon-packs.json`；`inkblade exploit`；`tests/test_weaponization.py` | 一键 78/152，74 条无模块 | probe |
| ADD-57 | 研究级深度复核（vLLM/准入/eBPF/GPU/fabric/身份，383 用例） | progress 行 81；`docs/DEPTH-REVIEW.md` | done | `docs/DEPTH-REVIEW.md`；`tests/test_depth_docs.py` | 专项测试在迁移中删除，证据以文档+模板保留 | migration |
| ADD-58 | CIS 基准 161 项 + 内核 LPE 52 条检测库 | progress 行 80；`docs/CIS-PARITY.md`、`LPE-PARITY.md` | partial | `inkblade/cis/catalog.py`；`inkblade/lpe/catalog.py` | `test_cis_benchmark.py`/`test_kernel_lpe.py` 迁移中删除，无直接单测 | migration |
| ADD-59 | LLM 行为探针 87 探针 / 13 类（OWASP LLM 10/10 + ASI 10/10） | progress 行 77；`docs/PROBE-PARITY.md` | partial | `inkblade/probes/library/`；`tests/test_llm_probes.py` | 87 vs garak 146（60%），不是「garak 级广度」 | probe |
| ADD-60 | FP/FN 调优（合计 FP 12.5%/FN 7.14%）与基线抑制 | progress 行 78；`docs/ENTERPRISE-LAB-RESULTS.md` | done | `inkblade/core/baseline.py`；`tests/test_baseline.py` | 单场景仍 33.33%，未压到 0（有意保留） | defense |
| ADD-61 | 干净室 ARTEX 功能族 8 项（llmpool/notify/templates/calendar/threads/graph/blackboard/并发） | progress 行 37/38；`docs/ARTEX-PARITY.md` | done | `core/{llmpool,notify,templates,calendar,threads,graphsnap,blackboard}.py`；`tests/test_llmpool.py` 等 | 默认关或只读；零代码复用（AGPL 边界） | agent |
| ADD-62 | 生产规模压测（100/1k/5k/10k 对象，三处 O(n²) 修复） | progress 行 22；`docs/SCALE-RESULTS.md` | done | `lab/bench/scale-bench.py`；`tests/test_scale_bench.py` | 合成对象，不是 10k GPU | docs |
| ADD-63 | 真集群验证（QEMU TCG + k3s 单节点，6 模块 16 findings，hostNetwork 旁路实证） | progress 行 21；`docs/REAL-CLUSTER-VERIFICATION.md` | done | `lab/qemu-k3s/`；`reports/samples/real-cluster/`；`tests/test_real_cluster_artifacts.py` | 单节点 TCG，非多节点真实 CNI | docs |
| ADD-64 | 免费资源补齐（Sigstore 公共验证 / TEE 公共 PKI / 三云 mock / fabric 仿真 / SaaS 压测） | progress 行 44；`docs/SOTA-2026-10.md` §免费资源 | done | `lab/{cloud_free,fabric-sim,saas}`；`tests/test_{cloud_free,fabric_sim,saas}.py` | 全部标注模拟，不冒充真实账号/硬件/SLA | docs |
| ADD-65 | 真实 10K+ GPU / 裸机性能实测 | `docs/SOTA-2026-10.md` 剩余硬缺口 1；`MASTER-REPORT` §7.1 | blocked-resource | 仿真侧：`lab/fabric-sim/`；`docs/SCALE-RESULTS.md` | 无 ≥1,024 GPU 集群、真实 NIC/交换机计数器 | docs |
| ADD-66 | 硬件 TEE 实测（TDX / SEV-SNP / NVIDIA CC） | SOTA 剩余硬缺口 2；`MASTER-REPORT` §7.2 | blocked-resource | 解析器：`inkblade/tee/`；公共 PKI：`inkblade/tee/online.py`；`docs/TEE-ONLINE-VERIFICATION.md` | 无实机 quote/report 与「证明→密钥释放」 | docs |
| ADD-67 | 六云商真实环境实测（EKS/AKS/ACK/TKE/GKE/CCE） | SOTA 剩余硬缺口 3；`docs/SIX-CLOUD-MATRIX.md` | blocked-resource | 契约仿真：`lab/cloud_six_sim.py`；三云 mock：`lab/cloud_free/` | 无账号、IAM 求值、真实日志与 GPU 节点 | docs |
| ADD-68 | 防护产品真实部署态回放（Elkeid/Falco/Kyverno） | spec §18-17；`docs/DYNAMIC-VERIFICATION.md` §8 | partial | `docs/DEFENSE-LAB-RESULTS.md`（QEMU k3s 真机 4 产品）；`docs/DEFENSE-BYPASS-PATH.md` + `reports/samples/defense-bypass-path/`（`ee42f1d` 执行路径：6 技术 5 bypass-confirmed / 1 detected / 0 失败）；`lab/defense-lab/` | 已部署并回放 Kyverno 1.19.2 / Falco 0.45.1 / Trivy 0.76.1 / ModSecurity+CRS；其余 7 个因内核头缺失、无 BPF-LSM、CNI 为 flannel 明确 N/A；绕过结论只覆盖该规则集与作用域 | defense |
| ADD-69 | 自主 runtime 端到端（真实 LLM 驱动 plan→execute→report） | `docs/AUTONOMY.md`；SOTA「自主 agent 渗透闭环」 | blocked-resource | `core/{explorer,autonomy,supervisor}.py`；`lab/tencent-compare/`、`lab/agent-eval/` | CI 无外网/密钥，端到端演练需客户环境 | agent |
| ADD-70 | 自有产物 cosign keyless 签发（公共 Fulcio + OIDC） | SOTA 剩余硬缺口 4；`docs/KEYLESS-VERIFICATION.md` | blocked-resource | `inkblade/sigstore_keyless.py`；公共样本验证 `reports/samples/sigstore/` | 无 OIDC 身份，未向公共 Fulcio 申请证书 | enterprise |
| ADD-71 | 跨副本分布式 SaaS（队列/HA/租户 KMS） | SOTA 剩余硬缺口 5；`docs/SAAS-LOAD-RESULTS.md` | blocked-resource | 单机模拟：`lab/saas/`；`tests/test_saas.py` | 无 broker/跨副本租约/租户加密/100 并发故障恢复 | enterprise |
| ADD-72 | 跨集群中继：多 kubeconfig/context 注册、复用既有 dial/SOCKS5 到达、kubectl/sa-token/exec 三种投放、cluster/parent_id 防环、每集群独立 RoE 与预算、失败按 transport 回退 | `3c84696`；`docs/AGENT-COVERAGE.md` §6 | partial | `inkblade/agent/relay.py`；`inkblade/agent/cli.py`（`agent relay add/list/status`）；`tests/test_agent_relay.py`（10 项） | 两集群为 fake kubectl + fake API + fake SOCKS5；真实 kubeconfig 客户端证书链、生产 SOCKS5、跨云网络策略与深层中继时延未验证 | agent |
| ADD-73 | 覆盖闭包 4+1 判据：可达资产已检查、可利用权限边已尝试（成功带证据/失败带原因）、探针已注册且有基线、frontier 无未收敛意图，外加 objective 证据门控；未闭包不得返回 `success` | `3c84696`；`docs/COVERAGE-CLOSURE.md`；`docs/AGENT-COVERAGE.md` §3 | done | `inkblade/agent/coverage.py`；`tests/test_agent_coverage.py`（10 项）；`reports/samples/coverage-closure/coverage-proof.json`（4 可达资产/3 权限边/2 探针，`closed=true`、0 缺口） | 只证明「已声明的可达面已处理」，资产发现遗漏不在证明范围；样例为 mock 两集群，非生产集群结论 | agent |
| ADD-74 | 文件与操作审计时间线：探针 `audit-exec`/`read-file`/`list-files` 采集、evidence.db `file_ops` 表、统一 `timeline.json`、WebUI 台账/证据浏览器联动、报告台账节与 SOC 审计键 | `687824e`；`docs/FILE-AUDIT.md` | done | `probe/src/auditops.rs`；`inkblade/core/{fileaudit,timeline}.py`；`tests/test_file_audit.py`（17 项）；`reports/samples/static-export/timeline.json` | fd 采样为进程存活窗口（5ms）+ argv 回退，不是 eBPF/ptrace 全量跟踪；非 Linux 主机仅 argv；`file_ops` 按 run 分库 | probe |
| ADD-75 | 防护感知绕过执行路径：`collect` 返回 `security_posture` → `defense:<product>` 事实 → 产品到技术选型 → 攻击意图必须带 `bypass.technique_id`，无已实现原语即 `policy-refused` 且不执行 | `ee42f1d`；`docs/DEFENSE-BYPASS-PATH.md` | done | `inkblade/core/defense_policy.py`；`probe/src/{posture,bypass}.rs`；`lab/defense-bypass/`；`reports/samples/defense-bypass-path/`；`tests/test_defense_policy.py`（23 项）+`tests/test_defense_bypass_artifacts.py`（9 项） | QEMU k3s 真机 Kyverno 1.19.2+Falco 0.45.1：6 技术中 5 bypass-confirmed、1 detected（SA 选择被 API-contact 规则看见）、0 失败；imagescan/veinmind/WAF/netobserv 无原语记 `policy-refused`；Kyverno 为命名空间作用域绕过而非引擎绕过 | defense |
| ADD-76 | 自动 agent 事件溯源运行时：append-only EventLog（hash chain/checkpoint/resume/replay）+ PlanGraph 证据门控 + frontier 调度（lease/retry/DLQ/四维预算）+ recon/exploit/verify/report 角色 worker，探针为唯一执行路径 | `5244259`；`docs/AGENT-AUTONOMY.md` | partial | `inkblade/agent/`（当前 24 文件 7594 行；`5244259` 首批 22 文件含 `workers/`）；`tests/test_agent_{runtime,graph,scheduler,supervisor,cli,protocols,memory_skills,eval_2026,runtime_docs}.py`（68 项） | 端到端只在 mock range 的 `runtime=reference` 上跑，本机无 cargo/kubectl；真实 k3s + 真实 LLM 的自主闭环见 ADD-69 | agent |

小计：ADD 76 条。

### 2.3 对比类需求（来源：COMPETITIVE-MATRIX / GAP-*.md / OSS / SECTION3 / feature-matrix）

| ID | 需求（原文摘要） | 来源锚点 | 状态 | 证据路径 | 缺口（一句话） | 责任线 |
|---|---|---|---|---|---|---|
| CMP-01 | ARTEX 逐功能矩阵（515 行）并逐行处置 180 条 missing | `docs/FEATURE-BY-FEATURE-ARTEX.md`；`docs/feature-matrix.json`；`tests/test_feature_matrix.py` | done | `feature-matrix.json`：ARTEX 515 行；处置 70 实现/6 不可行/104 不适用/0 未分类 | 201 行仍为 partial，不等于功能全有 | docs |
| CMP-02 | ARTEX 同靶场与性能对标（冷启/内存/延迟/吞吐/扫描） | `docs/ARTEX-BENCH-RESULT.md`；`docs/PERFORMANCE-COMPARISON.md` | partial | `reports/samples/artex-bench/same-target.json`；`reports/samples/perf/grid/`；`tests/test_artex_same_target.py` | ARTEX 在 QEMU TCG，无裸机同口径；30 分钟稳定性未测 | docs |
| CMP-03 | ARTEX clean-room 功能族对齐（8 族，默认关/只读） | `docs/ARTEX-PARITY.md`；progress 行 37 | done | `docs/ARTEX-PARITY.md` 功能×实现×测试表；`tests/test_artex_parity.py` | 仅黑盒对标，零代码复用 | agent |
| CMP-04 | KubeTrail 逐功能矩阵（286 行）与 6 项移植 | `docs/FEATURE-BY-FEATURE-KUBETRAIL.md`；`docs/KUBETRAIL-PORT.md` | done | `feature-matrix.json` KubeTrail 286 行；`inkblade/kubetrail/`；`tests/test_kubetrail.py`、`test_kubetrail_license.py` | KubeTrail 构建未完成，性能 N/A | docs |
| CMP-05 | KubeHound 攻击边与最短路径对齐（26 边） | `docs/COMPETITIVE-MATRIX.md` §3.2；progress 行 35 | done | `inkblade/core/pathcalc.py`；`tests/test_backlog_m.py` | 图为离线推演，未接 Gremlin 后端 | docs |
| CMP-06 | kube-hunter 47 检查对齐 29 项 + VID KB | `docs/GAP-ATTACK-SURFACE.md`；`COMPETITIVE-MATRIX` | partial | `inkblade/core/kb.py`；VID 条目；`tests/test_backlog_s.py` | 18 项未对齐；官方已停更 | docs |
| CMP-07 | XBow 能力面对标（资产发现/自主规划/案卷/复测/护栏/持续化） | `docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md`；`COMPETITIVE-MATRIX` §3.1 | partial | `core/{discovery,explorer,scheduler,retest}.py` | 无多 agent 大规模并行；无 SaaS 多驻留；无 ticketing 真实投递 | agent |
| CMP-08 | 23 工具 × 18 维竞品矩阵（只采信官方源，? 不臆断） | `docs/COMPETITIVE-MATRIX.md` §1–3；`tests/test_competitive_matrix.py` | done | `docs/COMPETITIVE-MATRIX.md`；`inkblade/arch-intel/competitive.py` | 商业产品无二进制实测 | docs |
| CMP-09 | 31 工具功能缺口 122 条（已有 36/部分 47/缺失 39） | `docs/GAP-FEATURES.md`；`docs/gap-matrix.json` | done | `gap-matrix.json` `tools` 31；`tests/test_gap_matrix.py` | 39 条缺失多为通用 Web/AD/浏览器等非 ML 面 | docs |
| CMP-10 | 31 工具攻击面缺口 82 条（已有 35/部分 29/缺失 18） | `docs/GAP-ATTACK-SURFACE.md` | done | 同上 | K8s 通用广度仍不如 KubeHound/KubeTrail | docs |
| CMP-11 | 31 工具 payload 缺口 56 条（已有 21/部分 18/缺失 17） | `docs/GAP-PAYLOADS.md` | done | 同上；`tests/test_payload_gap_variants.py` | 模型行为探针与密钥规则库是短板（CM-32/34） | docs |
| CMP-12 | OSS ML 集群工具全景 34 工具 × 15 维 + 本机实测 | `docs/OSS-ML-CLUSTER-TOOLS.md`；`docs/oss-ml-cluster-tools.json` | done | 34 工具；`docs/OSS-BENCH.md`；`reports/samples/oss-bench/`；`tests/test_oss_landscape.py` | 正文一句「32 个工具」为笔误，已登记修正 | docs |
| CMP-13 | 腾讯 Agent 大赛 8 项目对比 + 14 条差距（G1–G14） | `docs/SECTION3-TENCENT-AGENT-CONTEST.md` | done | 逐项目表 + 12 维矩阵 + G1–G14；`tests/`（SECTION3 相关） | 名次/成本来自官方与项目自述，未独立复核 | agent |
| CMP-14 | 腾讯 8 任务 OFF/ON 实测（成功 0.5→1.0 等 6 指标） | `docs/SECTION3-METRICS.md` | done | `reports/samples/tencent-compare/`；`tests/test_tencent_compare.py` | 不调用外部 LLM | agent |
| CMP-15 | 腾讯 G1–G14 落地（分级审批/成本预算/结构化观察/死胡同记忆/工具粒度） | `SECTION3` §7 已落地清单 | partial | `core/{agent_policy,observation,cost}.py`；`tests/test_{agent_policy,observation,cost}.py` | G10/G13（专家经验产品化/UX 心流）仍为方案 | agent |
| CMP-16 | 竞品 backlog 33 项（S13/M17/L3）逐项状态 | `COMPETITIVE-MATRIX` §5 | partial | §5 表；`tests/test_backlog_s.py`、`test_backlog_m.py` | CM-31 仍 open；CM-32/33 已实现但表内仍写 open（口径错） | docs |
| CMP-17 | LLM 探针对标（garak 149/PyRIT 114/promptfoo 54+32） | `docs/PROBE-PARITY.md` | partial | 87 探针 / 13 类；`tests/test_llm_probes.py` | 87/146≈60%，探针广度仍落后 | probe |
| CMP-18 | CIS 与 kube-bench、LPE 与 KubeTrail 对照 | `docs/CIS-PARITY.md`、`docs/LPE-PARITY.md` | done | CIS 161（kube-bench 130 超集）；LPE 52（KubeTrail 16 超集） | 对照为条目级，非执行结果逐条对齐 | defense |
| CMP-19 | ARTEX×KubeTrail 反思（gap 8/对齐 6/不做 6） | `docs/REFLECTION-ARTEX-KUBETRAIL.md` | done | 反思文档 + `tests/test_artex_parity.py` | 结论为定性判断 | docs |
| CMP-20 | XBow×ARTEX×KubeTrail 反思（已对齐 8/待补 4/不补 5） | `docs/REFLECTION-XBOW-ARTEX-KUBETRAIL.md` | done | 反思文档 + 确定性执行差异化声明 | 「待补 4」未全部关闭 | docs |
| CMP-21 | ARTEX 裸机/真实集群同口径复跑与 30 分钟稳定性 | `docs/PERFORMANCE-COMPARISON.md` 未测项；SOTA「真实 ARTEX 对比数据」 | blocked-resource | `lab/qemu-k3s/artex-bench.*`；`reports/samples/artex-bench/` | 无裸机；ARTEX 仅在 QEMU TCG 内实测 | docs |

小计：CMP 21 条。

**合计：32 + 76 + 21 = 129 条需求。**

### 2.4 状态统计

| 状态 | INIT | ADD | CMP | 合计 |
|---|---:|---:|---:|---:|
| done | 30 | 50 | 14 | **94** |
| partial | 2 | 20 | 6 | **28** |
| not-done | 0 | 0 | 0 | **0** |
| blocked-resource | 0 | 6 | 1 | **7** |
| 合计 | 32 | 76 | 21 | **129** |

> `not-done` 0 条：原第 1 条（Rust 运行时动态验证，ADD-35）已由 2026-10-27 原生重跑关闭——286 模板 × vulnerable/fixed 两态 × 每态 3 次一致，0 失败，证据含 probe 版本与二进制哈希。
> `blocked-resource` 7 条：真实 GPU/fabric（ADD-65、CMP-21）、硬件 TEE（ADD-66）、真实六云（ADD-67）、真实 LLM 自主 runtime（ADD-69）、公共 Fulcio 身份（ADD-70）、跨副本 SaaS（ADD-71）。防护产品回放已由 QEMU k3s 真机推进为 partial（ADD-68），不再计入 blocked。
> 2026-10-27 并入四个提交后新增 ADD-72～ADD-76：`3c84696`（跨集群中继 partial／覆盖闭包 done）、`687824e`（文件与操作审计时间线 done）、`ee42f1d`（防护感知绕过执行路径 done）、`5244259`（agent 事件溯源运行时 partial）。**done 94 / partial 28 / not-done 0 / blocked-resource 7，共 129 条；仍未完成项逐类见 §3.5。**

## 3. 未完成清单与依赖

### 3.1 阻断项（必须先解决，否则后续无法收口）

| # | 未完成项 | 现状 | 依赖 | 责任线 | 验收标准 |
|---:|---|---|---|---|---|
| 1 | **S5：模板等价化收尾** | 286 模板中 equivalent 48 / reduced 238；Rust 运行态已全量通过（286/286），但降级语义未补齐 | 需要逐模块把降级语义补齐（`docs/PROBE-COVERAGE.md` fidelity 列） | migration | reduced 归零，或每条 reduced 有书面等价性说明 |
| 2 | **`exec`/`scan` 简写与 README 不一致** | `session`/`probe`/`channel` 已实现，README 快速开始已改为 `session run`/`template`；`exec`/`scan` 仍不存在 | 命令面补齐或长期标注为未实现 | docs | README 快速开始命令逐条可执行 |
| 3 | **防护产品实测缺口** | Kyverno/Falco/Trivy/ModSecurity 已在 QEMU k3s 真机回放；Elkeid/AgentSmith/veinmind/Tetragon/KubeArmor/Wazuh/Hubble 因内核头缺失/无 BPF-LSM/flannel CNI 明确 N/A | 可加载内核模块的节点 或 支持 BPF-LSM 的内核；替换 CNI 需重建集群 | defense | 11 个模块各自给出 detected/bypass/N/A + 证据文件 |
| 4 | **自主 runtime 端到端** | L3/explorer 的自动批准为 token 预授权；CI 不调用真实 LLM | 真实 LLM 端点 + 客户授权环境 | agent | 端到端演练：plan→approve→execute→report 全部留痕 |
| 5 | **真实 10K+ GPU / 裸机** | 仅 1,024–10,000 节点离散事件仿真 + QEMU TCG | GPU 集群（≥1,024）+ 真实 NIC/交换机 | docs | 原始计数器与可复现 BENCH |
| 6 | **硬件 TEE 实测** | 公共 PKI 真实验证；无 TDX/SEV-SNP/H100-CC 实机 quote | 实机 | docs | nonce/measurement/TCB/debug 负例 + 证明→密钥释放 |
| 7 | **真实六云** | 契约仿真 + 三云 mock | 六云账号与最小集群 | docs | 每云只读侦察 + 网络策略矩阵 |
| 8 | **自有 Fulcio keyless 签发** | 第三方公共样本验证通过 | OIDC 身份 | enterprise | CI OIDC 签发 + Rekor + 轮换/吊销 |
| 9 | **跨副本分布式 SaaS** | 单机 8 租户压测 | 队列/HA/租户 KMS | enterprise | 100 并发链 + 故障恢复 |
| 10 | **披露闭环** | 30 包已生成未外发 | 厂商回执 / CVE 分配 | docs | 至少 1 条收到厂商回复或 CVE 号 |
| 11 | **跨集群中继真实环境** | 两集群闭环跑在 fake kubectl + fake API + fake SOCKS5 上；真实 kubeconfig 客户端证书链、生产 SOCKS5、跨云策略未验证 | 两套真实集群 + 客户端证书 + SOCKS5 出口 | agent | `relay add/deploy/collect` 跨两集群留证，覆盖 proof 0 缺口；TLS 不可用须显式拒绝而非静默降级 |

矩阵映射：S5 → ADD-33／ADD-36；Rust 编译与动态验证 → ADD-30／ADD-31／ADD-32／ADD-35（已关闭）；
CLI 一致性 → ADD-30；防护实测 → ADD-68／ADD-75；自主 runtime → ADD-69；agent 运行时 → ADD-76；
覆盖闭包 → ADD-73；跨集群中继 → ADD-72；文件审计 → ADD-74；真实 10K GPU → ADD-65；硬件 TEE → ADD-66；
六云 → ADD-67；Fulcio → ADD-70；跨副本 SaaS → ADD-71；披露闭环 → ADD-55；ARTEX 裸机 → CMP-21。

### 3.2 迁移收口记录（原「在途红测」，已关闭）

| 现象 | 证据 | 处置 |
|---|---|---|
| 286 个 `run.py` 的删除曾在工作树完成但未提交 | `git ls-tree HEAD -- inkblade/modules` 计数 0；工作树 0 | 已随 `9bdfa55 feat: probe execution S5` 提交，ADD-36 转 done |
| 32 个模块专项测试随 `run.py` 删除 | `test_modules_*`、`test_depth_*`、`test_cis_benchmark`、`test_kernel_lpe`、`test_chip_modules` 等 | 由 `tests/test_probe_*.py` 的模板两态断言替代；覆盖不等价，已在 ADD-48/57/58 的缺口列保留 |
| 删除进行中执行全量 `unittest discover` 会大量 ERROR（旧测试仍按 `run.py` 契约调用） | 2026-10-27 在途快照 Ran 2128 / failures 99 / errors 513（`reports/samples/requirements/suite-summary.txt` 历史段） | 以迁移后的稳定快照重跑，见 §3.4 与 §5 |

### 3.3 仅「参考实现」的验证（不得对外称已验证）

| 能力 | 参考证据 | 缺什么 |
|---|---|---|
| 全部 286 模板两态（执行面） | `reports/probe-coverage/evidence.json`（`runtime=rust`，二进制 `c8d2f118…`，源码 `1f0f57c`，每态 3 次一致，0 失败） | 无：执行与重复一致性已成立 |
| 全部 286 模板两态（负控） | 同上；`docs/PROBE-COVERAGE.md` §6 | fixed 态负控只在输入来自 mock 靶场时成立（`same_finding` 为真者不计 full two-state verified）；需逐个补 mock 输入 |
| 11 个防护绕过模块 | 4 个产品真机回放 + 7 个明确 N/A（`docs/DEFENSE-LAB-RESULTS.md`） | 7 个产品的可部署内核/CNI 环境（§3.1-3） |
| 47 值提权矩阵 | fixture + 4 项真集群 | 真实环境逐向量验证 |
| 云/GPU 跨租户 | 契约仿真 | 真实云账号 |
| fabric/PFC/SHARP | 离散事件仿真 + 计数器语义 | 真实交换机计数器 |

### 3.4 测试实测（2026-10-27）

- 命令：`python -m unittest discover -s tests`；摘要证据 `reports/samples/requirements/suite-summary.txt`。
- 结果：**Ran 1936 tests in 1288.533s — OK (skipped=13)**（无并发、稳定树复跑；比探针收口快照 1841 条多 95 条，其中本轮新增 agent 运行时 68 + 文件审计 17 + 覆盖/中继 20，其余为既有测试文件的增删）。
- 跳过项：13 条均为环境门槛（宿主机无 Rust 工具链时的 cargo 门控、可选外部件、平台差异），不是隐藏失败。
- 回归对照：迁移在途快照为 **Ran 2128 / FAILED (failures=99, errors=513, skipped=4)**——那是在删除 286 个 `run.py` 与旧模块测试的同时跑出的「移动靶」，已在 §3.2 归因；本次为删除落盘后的稳定树。
- 一次带并发的快照出现 1 条 `ConnectionAbortedError: WinError 10053`（`tests.test_hardware_sim.test_post_not_allowed_and_invalid_mode`，本机 socket 被外部中止）；该模块单独复跑 12/12 OK，以本节的无线程干扰复跑为准，不计为回归。

### 3.5 仍未完成项（按类复算；共 35 条 = partial 28 + blocked-resource 7）

#### 3.5.1 partial 28 条（逐类，不得计入 done）

| 类别 | 条目 | 条数 | 缺口的性质 |
|---|---|---:|---|
| 模板等价（S5） | ADD-33 | 1 | 48 条等价、**238 条降级**；Rust 运行态已全过，但降级语义未补齐，也无逐条等价性说明 |
| 真实硬件/设备未实测 | ADD-50、ADD-51、ADD-68 | 3 | 无真实 GPU/BMC/交换机/硅片；防护产品仍有 7 个因内核头/BPF-LSM/CNI 记 N/A |
| 企业集成与准入 | ADD-12、ADD-14 | 2 | 60 项准入仍有 21 项红项；OIDC/LDAP/SIEM/ITSM 全为本地契约 |
| Agent 组件为单进程/本地实现 | ADD-18、ADD-19、ADD-20、ADD-21、ADD-22、ADD-23、ADD-24、ADD-25、ADD-76 | 9 | 无 durable 跨进程队列/租约、无 microVM、无向量记忆、无技能分发签名；运行时端到端仅在 mock range |
| 供应链自有身份/TEE | ADD-41 | 1 | 自有产物无公共 Fulcio 身份；硬件 TEE 无实机 quote |
| 披露外发 | ADD-55 | 1 | 30 包已生成、0 已发送、0 CVE 申请 |
| 基准与探针广度 | ADD-58、ADD-59、CMP-17 | 3 | CIS/LPE 专项单测随迁移删除；LLM 探针 87/146≈60% |
| 跨集群中继真实环境 | ADD-72 | 1 | 两集群为 fake kubectl/API/SOCKS5；真实证书链与生产 SOCKS5 未验证 |
| 对比类未收口 | INIT-27、INIT-32、CMP-02、CMP-06、CMP-07、CMP-15、CMP-16 | 7 | ARTEX 仅 QEMU TCG 同口径；e2e 验收 9/11 未成断言；kube-hunter 18 项、XBow/腾讯 G10/G13、CM-31 仍开 |

合计：1+3+2+9+1+1+3+1+7 = **28**。

#### 3.5.2 blocked-resource 7 条（缺外部资源，脚本/设计已就绪）

| 条目 | 缺的外部资源 | 现有替代证据 |
|---|---|---|
| ADD-65 真实 10K+ GPU / 裸机 | ≥1,024 GPU 集群、真实 NIC/交换机计数器 | `lab/fabric-sim/` 离散事件仿真、`docs/SCALE-RESULTS.md` |
| ADD-66 硬件 TEE 实测 | TDX / SEV-SNP / H100-CC 实机与证明→密钥释放 | `inkblade/tee/` 解析器、公共 PKI 验证 `docs/TEE-ONLINE-VERIFICATION.md` |
| ADD-67 六云真实环境 | 六云账号、IAM 求值、真实日志与 GPU 节点 | `lab/cloud_six_sim.py`、`lab/cloud_free/` 三云 mock |
| ADD-69 真实 LLM 自主闭环 | 真实 LLM 端点 + 客户授权环境 | `inkblade/agent/`（ADD-76）、`lab/agent-eval/`、`lab/tencent-compare/` |
| ADD-70 自有 cosign keyless | OIDC 身份、公共 Fulcio/Rekor 签发 | 第三方公共样本验证 `reports/samples/sigstore/` |
| ADD-71 跨副本分布式 SaaS | broker/HA/租户 KMS、100 并发故障恢复 | `lab/saas/` 单机 8 租户压测 |
| CMP-21 ARTEX 裸机同口径 | 裸机/真实集群与 30 分钟稳定性窗口 | QEMU TCG 同靶场数据 `reports/samples/artex-bench/` |

#### 3.5.3 负向对照与模板分档（不得写成「全部两态验证」）

| 口径 | 数值 | 含义 |
|---|---:|---|
| 严格两态 verified（fixed 态 `status=ok`） | **35/286** | 满足 `DYNAMIC-VERIFICATION.md` §8 的严格定义 |
| fixed 态无相同 finding | 49/286 | 含上组 35；另 14 条 fixed 有 finding 但非同一 finding |
| 两态相同 finding（仅执行验证） | 237/286 | 两态共用 fixture 输入，不能作为负向对照 |
| 未达严格 verified | **251/286** | 286 − 35；补 per-template mock 输入后才可升级 |
| 模板等价 / 降级 | **48 / 238** | 238 条降级语义未补齐（S5，§3.1-1） |

结论：可以说「286/286 在 Rust 运行时两态各跑 3 次一致、0 失败」；**不可以说**「286/286 负向对照已验证」或「238 条降级模板已等价」。

## 4. 文档口径修正记录（旧 → 新）

| 文档 | 旧口径 | 新口径 | 处置 |
|---|---|---|---|
| `docs/SOTA-2026-10.md` | 模块 275 / 默认 264 / 隔离 11 | 287 / 276 / 11 | 已改 |
| `docs/SOTA-2026-10.md` | 测试 Ran 2003 OK | 见 §5 实测 | 已改 |
| `docs/SOTA-2026-10.md` | 37 verified / 93 static / 22 unsupported | 37 / 6 exposure / 87 static / 22 | 已改 |
| `docs/SOTA-2026-10.md` | 画像 73.48/70.08/62.12/70.45/71.21/25.76 | 70.65/67.39/59.78/67.75/68.48/25.00 | 已改 |
| `docs/SOTA-2026-10.md` | 默认 PoC 2；画像 1/1/2/0/2/0 | 全局 11；画像 3/2/3/2/4/0 | 已改 |
| `docs/SOTA-2026-10.md` | 语料 35 源 | 80 源（cn24/en42/paper14） | 已改 |
| `docs/SOTA-2026-10.md` | 38 项：25 真实/10 模拟/3 未达成 | 39 项：25/10/4（新增「Rust 探针运行时」未达成） | 已改 |
| `docs/SURFACE-REALISM.md` | 264 默认模块、旧覆盖率、1/1/2/0/2/0 | 276 默认、新覆盖率、3/2/3/2/4/0 | 已用 `tools/render-surface-docs.py` 重生成 |
| `docs/MASTER-REPORT.md` | 实效 47/47 | 53/53 | 已改 |
| `docs/MASTER-REPORT.md` | 「37 verified / 93 static-only / 22 unsupported」 | 37/6/87/22 | 已改 |
| `docs/MASTER-REPORT.md` | 版本矩阵 42 条 | 103 条 | 已改 |
| `docs/MASTER-REPORT.md` | 0day「47 条储备」 | novelty-checked 47 / reserve 46 / unique 39 / packs 47 | 已改 |
| `docs/MASTER-REPORT.md` | 未达成 11 项含「12 个无面、9 隔离」「画像 62.12–73.48」 | 19 无面（11 隔离 + 8 待定）；画像 59.78–70.65 | 已改 |
| `README.md` / `README.zh-CN.md` | 「286 legacy run.py remain」 | 工作树 0 / HEAD 0（删除已提交） | 已改 |
| `README.md` / `README.zh-CN.md` | 快速开始 `session/probe/exec/scan` 直用 | 标注「0.2.0 未提供，当前用 module/run/execute/template」 | 已改 |
| `docs/DYNAMIC-VERIFICATION.md` | 286 run.py 仍保留 | 工作树 0 / HEAD 0；删除已提交 | 已改 |
| `docs/WEAPON-READINESS.md` | one-click=「有 run.py 的模块」；47 条储备 | one-click=「有模块（模板）」；reserve 46 / packs 47 | 已改 |
| `docs/COMPETITIVE-MATRIX.md` | CM-32/CM-33 open；L3 未动 | CM-32 partial（87/146）、CM-33 done（161 项） | 已改 |
| `docs/OSS-ML-CLUSTER-TOOLS.md` | 正文「32 个工具」 | 34（JSON 与标题一致） | 已改 |
| `docs/DETECTION-LAYERS.md` / `DOC-INDEX.md` / `ARCHITECTURE.md` / `FEATURES.md` | 「九层」「七层」并列 | 检测模型统一十层；控制端改称「七组件」 | 已改（`FEATURES.md` 由 9c74fc9 一并落盘） |
| `docs/ARCHITECTURE-PROBE.md` / `AGENT-ARCHITECTURE-2026.md` | 「七层架构」作为产品层数 | 同上 | 已改 |
| `docs/SOTA-2026-10.md` / `docs/MASTER-REPORT.md` | Rust 运行时 `runtime=rust` 为 0、未达成 12 条 | 286/286 `runtime=rust`（3 次一致）；未达成 11 条 | 已改 |
| `docs/SOTA-2026-10.md` | 25 真实 / 10 模拟 / 4 未达成 | 26 / 10 / 3（39 项不变） | 已改（`tests/test_sota_doc.py` 同步） |
| `README.md` / `README.zh-CN.md` / `docs/FAQ.md` / `docs/PRODUCT.md` | run.py「HEAD 286、迁移在途」、动态验证「仍为 0」 | 工作树 0 / HEAD 0；286/286 原生两态 | 已改 |
| `docs/DYNAMIC-VERIFICATION.md` | 参考评估器 286/286、rust 为 0 | 原生 286/286、`probe 0.1.1`、802s；负控边界 §6 | 已改 |
| `docs/PROBE-COVERAGE.md` / `docs/PROBE-BUILD.md` | 旧二进制 `7348deb0…` / 源码 `bb58f9f` | `c8d2f118…` / `1f0f57c` / probe 0.1.1 / CI run 40430384961 | 已用 `tools/template-coverage.py --write` 重生成 |
| `docs/PROGRESS.md` / `docs/MASTER-REPORT.md` / `docs/DOC-INDEX.md` | 需求 **124** 条（done 91 / partial 26 / blocked 7） | **129** 条（done 94 / partial 28 / blocked 7），并入 `3c84696`/`687824e`/`ee42f1d`/`5244259` | 已改 |
| `docs/SOTA-2026-10.md` / `docs/MASTER-REPORT.md` | 层数表述分散（十层、七组件出现在不同节，易被误读为两套分层） | 统一写「检测十层（1–9 业务面 + 10 防护绕过）+ 控制端七组件」 | 已改 |
| `docs/PROGRESS.md` | 反向对照「remaining 251」等旧句 | 35/286 严格 verified、49/286 无相同 finding、237/286 仅执行验证、238 降级模板（§3.5.3） | 已改 |

## 5. 实测回填（测试与关键命令）

| 项 | 命令 | 结果 |
|---|---|---|
| 全量单测 | `python -m unittest discover -s tests` | 见下方结果块 |
| 模板契约 | `python -m unittest tests.test_probe_templates` | PASS |
| 模板两态（原生） | `python tools/native-verify.py --repeat 3` | 286/286 `runtime=rust`，0 失败，802s |
| 模板两态（参考） | `python tools/template-run.py --range` | 286/286（仅本地回归，不计证据） |
| 模板覆盖率 | `python tools/template-coverage.py` | 286/286 native（`c8d2f118…` / `1f0f57c`） |
| 覆盖闭包判据 | `python -m unittest tests.test_agent_coverage` | 10 项 PASS（4+1 判据、证据/原因强制、proof 渲染） |
| 跨集群中继 | `python -m unittest tests.test_agent_relay` | 10 项 PASS（fake kubectl/API/SOCKS5、防环、每集群预算、失败回退） |
| 文件与操作审计 | `python -m unittest tests.test_file_audit` | 17 项 PASS（`audit-exec`/`read-file`/`list-files`、时间线、API、报告台账） |
| 防护感知绕过 | `python -m unittest tests.test_defense_policy tests.test_defense_bypass_artifacts` | 32 项 PASS（23 + 9） |
| agent 事件溯源运行时 | `python -m unittest tests.test_agent_runtime tests.test_agent_graph tests.test_agent_scheduler tests.test_agent_supervisor` | 41 项 PASS（6 + 15 + 6 + 14） |
| 架构语料门槛 | `python inkblade/arch-intel/check.py` | ALL GATES ok |
| 核验编排 | `python tools/verify-exploits.py` | green（37 verified） |

**全量单测结果块**

```
python -m unittest discover -s tests
Ran 1936 tests in 1288.533s
OK (skipped=13)
```

对照（已被取代）：探针收口快照 `Ran 1841 / OK (skipped=13)`；迁移在途快照 `Ran 2128 tests / FAILED (failures=99, errors=513, skipped=4)`，归因见 §3.2、§3.4 与 `reports/samples/requirements/suite-summary.txt`。
本轮自检：`tests.test_requirements_matrix`（24 项）、`tests.test_sota_doc`、`tests.test_docs_master`、`tests.test_docs_index`、`tests.test_agent_runtime_docs` 共 53 项复跑为绿。

## 6. 证据索引

- 计数来源：`inkblade/core/exploit-registry.json`、`inkblade/core/zeroday-registry.json`、`inkblade/core/data/{version-matrix,weapon-packs}.json`、`inkblade/arch-intel/coverage-matrix.json`、`reports/samples/rules-pack/{mapping,coverage-matrix}.json`、`reports/probe-coverage/evidence.json`、`reports/samples/effects/effects.json`。
- 覆盖与画像：`docs/PROBE-COVERAGE.md`、`docs/SURFACE-REALISM.md`、`docs/DYNAMIC-VERIFICATION.md`。
- Agent：`docs/AGENT-AUTONOMY.md`（事件溯源运行时）、`docs/AGENT-COVERAGE.md`（覆盖图/中继）、`docs/COVERAGE-CLOSURE.md` + `reports/samples/coverage-closure/coverage-proof.json`（两集群闭包证明）。
- 防护与审计：`docs/DEFENSE-LAB-RESULTS.md`、`docs/DEFENSE-BYPASS-PATH.md` + `reports/samples/defense-bypass-path/`、`docs/FILE-AUDIT.md` + `reports/samples/static-export/timeline.json`。
- 规格与计划：`docs/superpowers/specs/2026-10-24-trident-ml-cluster-pentest-design.md`、`docs/superpowers/plans/2026-10-25-trident-platform.md`（仓库外，工作区 `docs/`）。
- 历史台账：`progress.md`、`docs/DEV-LOG.md`、`.superpowers/sdd/2026-10-25-inkblade-platform/progress.md`、`git log --oneline`。
