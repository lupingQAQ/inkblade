# Payload 缺失全量表（逐工具）

来源：docs/gap-matrix.json（生成于 2026-10-25）；状态口径：{"we-have": "已有对等能力（maps_to 给出模块/功能键）", "partial": "部分覆盖（missing 字段说明缺什么）", "missing": "未覆盖"}

| 工具 | 类别 | 条目 | 来源 | 我们的状态 | 缺失内容 | 行动项 |
|---|---|---|---|---|---|---|
| XBow | 自主渗透（商业） | Chrome 全链 exploit（V8+WebP+Crashpad 3 洞链） | https://xbow.com/blog | missing | 无浏览器/内核利用原语 | 类别外 |
| XBow | 自主渗透（商业） | MSRC 3 个严重 CVE（自主发现+自证） | https://xbow.com/ | partial | 我们有 is_zeroday 登记与行为化零日规则，但无对外 CVE 级研究产出 | 维持零日登记口径 |
| XBow | 自主渗透（商业） | exploit 级 PoC 附带于每个 finding | https://xbow.com/ | we-have | - | 已对齐 |
| ARTEX | 自主渗透（开源） | 工具注入式探测（GET /__routes__→POST /pause→/pull_weights 链） | docs/ARTEX-BENCH-RESULT.md 同靶场实测（worker 固定探测序列） | we-have | - | 已对齐并有对比数据 |
| ARTEX | 自主渗透（开源） | add_intent/prove_goal 报告口径 payload | agent/goals.go schema | partial | 无对应意图工厂概念（我们不驱动自主意图） | 不入 backlog |
| NodeZero | 自主渗透（商业） | AD 密码 7 种 crack 方法 + blast radius 相似度分析 | https://horizon3.ai/nodezero/ad-password-audit/ | missing | AD 面类别外 | 不入 backlog（类别外） |
| NodeZero | 自主渗透（商业） | 非破坏性利用链（弱点链式组合演示影响） | https://horizon3.ai/nodezero/ | we-have | - | 已对齐 |
| Pentera | 自主渗透（商业） | AD 域管枚举+破解链 | https://pentera.io/pentera-platform/（客户证言） | missing | AD 类别外 | 不入 backlog |
| Pentera | 自主渗透（商业） | 泄露凭据有效性验证（暴露凭据→验证可用性） | https://pentera.io/pentera-platform/ | partial | 凭据集→租户内有效性判定模块 | CM-21 |
| KubeTrail | K8s 攻防（克隆） | 16 个内核 LPE CVE 检测（Dirty Pipe/PwnKit/nf_tables/DirtyCOW 等） | README.en.md Linux LPE / K8s Container Vulnerabilities 表 | missing | 内核 LPE CVE 库（平台定位 Ruling 刻意不补，见 COMPETITIVE-MATRIX §4 KubeTrail 行） | 不入 backlog（Ruling 维持） |
| KubeTrail | K8s 攻防（克隆） | legacy SA token 逐 token 审计（--secretoutput） | README.en.md Server Options --secretoutput | missing | 逐 token 权限审计 | CM-05 |
| KubeTrail | K8s 攻防（克隆） | 19 类 scan 采集 payload（identity/serviceaccount/credential_sweep/dns_services...） | internal/command/command.go | we-have | - | 已对齐（控制台侧等价） |
| KubeHound | K8s 攻防（克隆） | EXPLOIT_HOST_READ/WRITE/TRAVERSE（敏感挂载读写遍历） | docs/reference/attacks/EXPLOIT_HOST_*.md | partial | 挂载面检测有（storage-protocol-csi/privileged-workloads），利用原语未按边类型显式产出 | CM-23 落地时补边 payload |
| KubeHound | K8s 攻防（克隆） | TOKEN_STEAL/LIST/BRUTEFORCE（SA token 窃取/枚举/爆破） | docs/reference/attacks/TOKEN_*.md | partial | token 采集有（rbac-mapping secrets 盘点），brute-force secret 名未设 | CM-08 扩展面（与 KubeletCTL 同源） |
| KubeHound | K8s 攻防（克隆） | POD_CREATE 特权 Pod 创建边 | docs/reference/attacks/POD_CREATE.md | we-have | - | 已对齐 |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | 47 个 Vuln 检查项（含 MITRE 映射与 evidence 采集） | kube_hunter/modules/hunting/*.py 全枚举 | partial | 等价检查分散于 117 模块（rbac-mapping/escape-primitives 等）；缺 K8s 控制面组件级检查清单化 | CM-35 + CM-07 |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | 发现模块（apiserver/dashboard/etcd/hosts/kubectl/kubelet/kubernetes_client/ports/proxy 10 模块） | kube_hunter/modules/discovery/ | we-have | - | 已对齐 |
| Peirates | K8s 攻防（官方 README） | 37 条命令原语（sa-menu/ns-menu/get-pods/dump-pod-info/find-volume-mounts/list-secrets/scan-configmaps/secret-to-sa...） | docs/commands/README.md 全表 | partial | RBAC/secrets 采集面由 rbac-mapping+kube-audit-trail-analysis 覆盖；configmap 错置凭据扫描（scan-configmaps）未专设 | 并入 CM-34（凭据扫描面含 configmap） |
| Peirates | K8s 攻防（官方 README） | kubectl-can-i 身份反查（谁有权做 X） | docs/commands/kubectl-can-i.md | partial | 我们有 can-i 矩阵（正向）；身份反向枚举缺 | CM-36（risky 实体反查） |
| Peirates | K8s 攻防（官方 README） | exec-via-kubelet（kubelet API 执行） | docs/commands/exec-via-kubelet.md | missing | kubelet 执行面 | CM-08 |
| kdigger | K8s 攻防（官方 README） | admission 探测 payload（privileged/priv-escalation/hostnetwork/hostpath/runasroot/hostpid 六模板） | README.md Admission 节 | missing | 同上 | CM-24 |
| kdigger | K8s 攻防（官方 README） | gen 特权 Pod 模板生成器（--all/--privileged/--hostpath/--hostpid/--hostnetwork/--tolerations） | README.md Generating 节 | partial | 演示模板生成有（lab 层），产品化 gen 命令无 | 并入 CM-24 |
| kdigger | K8s 攻防（官方 README） | CoreDNS wildcard 服务发现 payload | README.md Services 节（注明 CoreDNS≥1.9.0 已移除该特性） | we-have | - | 已对齐 |
| CDK | K8s 攻防（官方 README） | 30 个 EXP 名单（runc-pwn/shim-pwn/docker-sock-pwn/mount-disk/lxcfs-rw/mount-cgroup/abuse-unpriv-userns/mount-procfs/check-ptrace/rewrite-cgroup-devices/cap-dac-read-search/...） | README.md Exploit 表 | partial | 我们有 escape-primitives 检测面 + version-matrix 46 指纹，无逐 EXP 可执行原语库（控制台定位） | CM-35（原语库登记而非执行） |
| CDK | K8s 攻防（官方 README） | 6 个 CVE exploit（CVE-2019-5736/2020-15257/2022-0492/2020-8554/2020-8558/2026-31431） | README.md Exploit/Evaluate 表 | partial | CVE 检测登记进 version-matrix 的路径未系统化 | CM-35 |
| CDK | K8s 攻防（官方 README） | 11 个内网工具（nc/ps/netstat/ifconfig/vi/ectl/kcurl/dcurl/ucurl/probe/rcurl） | README.md Tool 表 | we-have | - | 已对齐（形态差异） |
| KubeletCTL | K8s 攻防（官方 README） | /run /exec /cri 三通道容器执行 payload | API_TABLE.md | missing | 执行原语刻意不产品化（ROE 边界：检测+验证面优先） | CM-08 落地时以检测/取证面实现 |
| KubeletCTL | K8s 攻防（官方 README） | pid2pod 进程映射侦察 | README.md Usage pid2pod | partial | 进程↔pod 映射侦察未专设 | 并入 CM-22 |
| Falco | 运行时/准入（官方文档） | 99 条默认规则（Disallowed SSH/Write below etc|root|dev|rpm/bin dir/Non sudo setuid/Privileged container started/CVE-2024-3094 liblzma/...） | default-rules 页全量 | partial | 我们 Falco 目标 5 条（面向 ML 面）；基线广度差距即 CM-37 | CM-37 |
| Falco | 运行时/准入（官方文档） | 用户可调 whitelist/exception 模式（user_known_* 宏） | default-rules 页条件字段 | partial | 规则模板无用户白名单宏机制 | CM-09 并入 |
| Tetragon | 运行时/准入（官方文档） | 官方示例 TracingPolicy 集（仓库 quickstart/examples） | tetragon.io/docs/overview/（examples 声明） | partial | 未系统化为规则生成目标模板库 | CM-25 |
| KubeArmor | 运行时/准入（官方 README+官网） | 4 类策略规范（security/cluster/host/network host） | README 四条 Spec 链接 | missing | 规则目标缺 KubeArmor 全部 4 类 | CM-26 |
| KubeArmor | 运行时/准入（官方 README+官网） | 进程/网络白名单策略原语（Allow/Audit/Block action） | README Least Permissive Access 表 | partial | 我们的 NetworkPolicy/Kyverno 目标无白名单 action 语义 | CM-26 并入 |
| Kyverno | 运行时/准入（官方 docs+政策库） | 政策库模板条目（disallow-privileged/run-as-non-root/require-labels 等按类别目录） | kyverno/policies 各类别目录 | partial | 模板目录广度 | CM-37 |
| Kyverno | 运行时/准入（官方 docs+政策库） | PSP 迁移政策集（psp-migration 类别） | kyverno/policies/psp-migration-mpol | partial | PSP 已废弃，仅历史迁移价值 | 记录不做 |
| Gatekeeper | 运行时/准入（官方库） | rego 模板 payload（30 general + PSP 类别逐条） | 同上 | partial | 模板级广度 | CM-37 |
| garak | AI/LLM 安全（克隆） | 41 族/170 类探针 payload（adaptive/ansiescape/audio/av_spam_scanning/badchars/encoding×20/goat/goodside/visual_jailbreak...） | garak/probes/ 全目录枚举 | missing | 探针 payload 库本体 | CM-32（L 级广度） |
| PyRIT | AI/LLM 安全（克隆） | 9 种策略链 payload（crescendo/pair/tap/skeleton_key/many_shot/red_teaming/sequential/simulated_conversation/barge_in） | executor/attack/ 全枚举 | missing | 策略链模板 | CM-29 |
| PyRIT | AI/LLM 安全（克隆） | ~90 个 prompt 转换器 payload（atbash/bijection/braille/caesar/ecoji/zalgo/zero_width/policy_puppetry...） | converter/ 全枚举 | missing | 文本转换器库 | CM-29（子集落地，L 级标注） |
| promptfoo | AI/LLM 安全（克隆） | 49 插件 payload（pii/harmbench/pliny/sqlInjection/shellInjection/promptExtraction/dataExfil/asciiSmuggling/divergentRepetition/...） | src/redteam/plugins/*.ts 枚举 | missing | 插件级 payload 集 | CM-32 并入 |
| promptfoo | AI/LLM 安全（克隆） | ~35 策略 payload（crescendo/gcg/goat/hydra/simba/iterative/bestOfN/rot13/base64/leetspeak/homoglyph/multilingual/...） | src/redteam/strategies/*.ts 枚举 | missing | 策略级 payload 集 | CM-29 并入 |
| AgentDojo | AI/LLM 安全（克隆） | important_instructions 注入 payload 族（injection variations） | attacks/important_instructions_attacks.py | partial | 注入 payload 变体集（模型行为域） | CM-30 并入 |
| AgentDojo | AI/LLM 安全（克隆） | 5 套件用户任务+注入任务对（user_tasks/injection_tasks） | default_suites/v1/*/（每套件成对） | missing | 基准任务对 | CM-30 |
| Trivy | 其他（官方 README） | KBOM/镜像清单导出 payload | trivy k8s --report summary（kube-hunter 停更承接口径） | partial | AI SBOM 已有（模型/权重级）；集群 BOM 缺 | 并入 CM-13 |
| Trivy | 其他（官方 README） | CIS 基线扫描（kube-bench 承接） | kube-bench README 交叉声明 | missing | CIS 检查族 | CM-33 |
| Syft | 其他（官方 README） | SBOM 格式族 payload（CycloneDX/SPDX/Syft JSON） | README Features | partial | 格式转换矩阵 | CM-13 并入 |
| kube-bench | 其他（官方 README+cfg 枚举） | CIS 条目级检查 payload（YAML 声明式测试配置） | README（Tests are configured with YAML files） | missing | 检查条目库 | CM-33 |
| KubiScan | K8s 攻防（新克隆） | 40 条 K8s CVE 检测条目（CVE-2018-1002105 至 CVE-2022-3172 等） | CVE.json 唯一 CVE 计数 | missing | K8s CVE 条目库 | CM-35 |
| KubiScan | K8s 攻防（新克隆） | risky 静态角色库（static_risky_roles.py 预置危险角色定义） | static_risky_roles.py | partial | 危险角色模式库（我们以 can-i 矩阵+通配符检测等价覆盖核心） | CM-36 并入 |
| DeepCE | K8s 攻防（新克隆） | 5 类 payload（reverse TCP/读 /etc/shadow/加 root 用户/自定义命令/自定义二进制） | README Payloads | missing | post-exploit payload 刻意不产品化（授权边界+可审计定位） | 不入 backlog（执行原语） |
| trufflehog | 密钥扫描（新克隆） | 892 detector 规则 payload（AWS accesskey.go GetCallerIdentity 验证式等） | pkg/detectors/ 逐目录 | missing | 规则库本体 | CM-34（S/M 级起步，类型面裁剪到 ML 栈常用云凭据） |
| gitleaks | 密钥扫描（新克隆） | 222 条规则 payload（逐规则 regex+entropy+allowlist） | config/gitleaks.toml | missing | 规则库本体 | CM-34 |
| Giskard | AI/LLM 安全（新克隆） | 注入语料 payload（prompt_injection.jsonl 数据集） | generators/data/ | missing | 语料集 | CM-32 子项 |
| Lakera Guard | AI/LLM 安全（商业，官方 docs） | 5 类防御的检测 payload 集（prompt_attack 分级阈值等） | docs.lakera.ai 公开示例（l1_confident/l2_very_likely 分级） | partial | 阈值分级判定体系（我们 findings 为 severity 分级，语义近） | 域内记录 |
| MKAT | K8s 攻防（既有克隆转正） | 信任图边 payload（role assumption chain 推导） | role_relationships 分析输出 | partial | 图级信任链推导 | CM-38 |
| grype | 其他（官方 README） | 漏洞匹配 DB payload（grype DB） | grype db 体系 | missing | 漏洞库自建不做（导入侧 CM-13） | CM-13 |

**总计：56 条**（工具 31 个）

## 完备性声明

- XBow: mode=official-site-pages, completeness=doc-level-limited（闭源，公开页级）
- ARTEX: mode=clone-source, completeness=list-level-exhaustive（源码+协议逆向，另见 docs/ARTEX-BENCH-RESULT.md 与 progress.md 同靶场任务）
- NodeZero: mode=official-site-pages, completeness=doc-level-limited（闭源）
- Pentera: mode=official-site-pages, completeness=doc-level-limited（闭源，单页能力面已逐条核验）
- KubeTrail: mode=clone-source, completeness=list-level-exhaustive（collectors/scan 类别/LPE CVE 表全枚举）
- KubeHound: mode=clone-source, completeness=list-level-exhaustive（attack 边官方 index 全表枚举）
- kube-hunter: mode=clone-source, completeness=list-level-exhaustive（hunting/discovery 模块 Vuln 类全枚举）
- Peirates: mode=official-docs, completeness=list-level-exhaustive（命令参考全表枚举）
- kdigger: mode=official-docs, completeness=list-level-exhaustive（bucket 全清单）
- CDK: mode=official-docs, completeness=list-level-exhaustive（evaluate/exploit/tool 三表全枚举）
- KubeletCTL: mode=official-docs, completeness=list-level-exhaustive（命令+API 表全枚举）
- Falco: mode=official-docs, completeness=list-level-exhaustive（默认规则页全量解析：99 规则逐条）
- Tetragon: mode=official-docs, completeness=doc-level-limited（overview 单页；策略目录无官方计数页）
- KubeArmor: mode=official-docs, completeness=list-level-exhaustive（README 规范链接全枚举）
- Kyverno: mode=official-docs, completeness=list-level-exhaustive（政策库目录类别全枚举；总数官方未声明）
- Gatekeeper: mode=official-docs, completeness=list-level-exhaustive（general 目录模板全枚举 + PSP 类别登记）
- garak: mode=clone-source, completeness=list-level-exhaustive（probes 目录族+类全枚举）
- PyRIT: mode=clone-source, completeness=list-level-exhaustive（executor/attack 策略全枚举）
- promptfoo: mode=clone-source, completeness=list-level-exhaustive（redteam plugins/strategies 全枚举）
- AgentDojo: mode=clone-source, completeness=list-level-exhaustive（default_suites/attacks 全枚举）
- Trivy: mode=official-docs, completeness=list-level-exhaustive（targets×scanners 官方清单）
- Syft: mode=official-docs, completeness=list-level-exhaustive（Features 官方清单）
- kube-bench: mode=official-docs, completeness=list-level-exhaustive（cfg profile 目录全枚举）
- KubiScan: mode=clone-source, completeness=list-level-exhaustive（CLI flag 全枚举 + CVE.json 计数）
- DeepCE: mode=clone-source, completeness=list-level-exhaustive（README 枚举/exploit/payload 三清单）
- trufflehog: mode=clone-source, completeness=list-level-exhaustive（detectors 目录计数 + README 声明双源）
- gitleaks: mode=clone-source, completeness=list-level-exhaustive（config 规则计数）
- Giskard: mode=clone-source, completeness=list-level-exhaustive（scan generators + 集成枚举；2.x monorepo 检测器移至 docs 面）
- Lakera Guard: mode=official-docs-pages, completeness=doc-level-limited（商业 docs 站；已并入 Check Point AI Security 体系）
- MKAT: mode=clone-source, completeness=list-level-exhaustive（pkg 三模块全枚举）
- grype: mode=official-docs, completeness=list-level-exhaustive（Features 官方清单）

## 不可核验/不存在的工具

- KubeCF: 不存在：github.com/cloudfoundry/kubecf 与 GitHub API 双路 404（2026-10-25 核验）；即便存在亦为 Cloud Foundry 部署项目而非安全工具（https://github.com/cloudfoundry/kubecf → 404）
- fuzzwad: 任务指示跳过（任务口径）
