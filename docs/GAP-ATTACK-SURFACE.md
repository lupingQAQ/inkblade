# 攻击面缺失全量表（逐工具）

来源：docs/gap-matrix.json（生成于 2026-10-25）；状态口径：{"we-have": "已有对等能力（maps_to 给出模块/功能键）", "partial": "部分覆盖（missing 字段说明缺什么）", "missing": "未覆盖"}

| 工具 | 类别 | 条目 | 来源 | 我们的状态 | 缺失内容 | 行动项 |
|---|---|---|---|---|---|---|
| XBow | 自主渗透（商业） | Web 应用/API 自主渗透（链式组合缺陷） | https://xbow.com/ | partial | 我们是 ML 基础设施面专项（管理端点/网关/权重），无通用 Web App 漏洞挖掘（SQLi/XSS 等） | 类别差异记录（通用 Web 面刻意不做） |
| XBow | 自主渗透（商业） | 浏览器/内核级零日研究面（V8/解码器/沙箱逃逸） | https://xbow.com/ | missing | 无二进制/内核零日挖掘 | 类别外（刻意不做） |
| XBow | 自主渗透（商业） | 认证合规面（SOC2 等审计） | https://xbow.com/ | missing | 无第三方认证 | 不入 backlog |
| ARTEX | 自主渗透（开源） | Web 靶场自主扫描（curl/nmap/playwright 工具面） | agent/toolcatalog.go 工具注入（40 工具） | partial | 同 XBow：通用 Web 面非我们范围；同靶场对比见 reports/samples/artex-bench/same-target.json | 已做同靶场对比（105.6ms vs 13.5s） |
| ARTEX | 自主渗透（开源） | LLM 网关依赖面（自有 mock 可替换） | agent/provider.go | we-have | - | 我们超出（网关语义攻击面） |
| NodeZero | 自主渗透（商业） | AD/身份域（密码审计/凭据复用/域提权） | https://horizon3.ai/nodezero/ad-password-audit/ | missing | AD 域面类别外；凭据验证面已有 fixture 级 | CM-21（凭据验证面，crack 方法不跟进） |
| NodeZero | 自主渗透（商业） | 内网横向 pivoting（网络 pivot 链） | https://horizon3.ai/nodezero/ | partial | 有 hybrid-cloud-egress-pivot + 可达性图，无通用内网 pivot 扫描 | 域内已对齐（ML 集群横向面） |
| NodeZero | 自主渗透（商业） | 云凭据暴露（泄露凭据→跨面利用） | https://horizon3.ai/nodezero/ | we-have | - | 已对齐 |
| Pentera | 自主渗透（商业） | 内网 kill chain（绕防御/横向/提权/达关键资产） | https://pentera.io/pentera-platform/ | partial | ML 集群横向面已对齐，通用企业内网（AD/SMB 等）不做 | 域内对齐 |
| Pentera | 自主渗透（商业） | 云原生攻击（身份+错配→云资源陷落） | https://pentera.io/pentera-platform/ | we-have | - | 已对齐（契约级，非真实环境口径） |
| Pentera | 自主渗透（商业） | 勒索仿真（EDR 检验） | https://pentera.io/pentera-platform/ | missing | 类别外（破坏性仿真不做，fabric DOS 仅仿真器计数器级） | 不入 backlog |
| KubeTrail | K8s 攻防（克隆） | 容器本地态势（/proc /sys cgroup socket 挂载） | internal/collectors/{proc,filesystem,runtime_local,node_local}.go | we-have | - | 已对齐（CM-22） |
| KubeTrail | K8s 攻防（克隆） | RBAC 高价值权限面（secrets list/pods exec/bind/escalate/impersonate/token create/webhook write/nodes proxy） | README.en.md Common Red-Team Workflow 高价值信号清单 | we-have | - | 已对齐 |
| KubeTrail | K8s 攻防（克隆） | 云元数据面（169.254.169.254） | README evidence 列（cloud metadata signals） | we-have | - | 已对齐 |
| KubeTrail | K8s 攻防（克隆） | admission dry-run 探测面 | internal/command/command.go admission_dryrun 类别 | we-have | - | 已对齐（CM-24） |
| KubeHound | K8s 攻防（克隆） | 26 类攻击边（CE×6/EXPLOIT×4/IDENTITY×2/POD×4+ROLE_BIND/TOKEN×3/VOLUME×2/SHARE_PS/CONTAINER_ATTACH/PERMISSION_DISCOVER） | docs/reference/attacks/index.md | we-have | - | 已对齐（CM-23） |
| KubeHound | K8s 攻防（克隆） | container escape 面枚举（模块加载/nsenter/特权挂载/ptrace/core_pattern） | docs/reference/attacks/CE_*.md ×6 | we-have | - | 已对齐（原语级） |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | API Server 面（14 项：HTTP/匿名访问/info 泄露/命名空间与 RBAC 对象增删改/特权 Pod） | kube_hunter/modules/hunting/apiserver.py | partial | apiserver 面有 api-server-flood-surface（DoS），RBAC 对象操作面由 rbac-mapping+权限链覆盖 fixture 级 | 域内对齐（fixture 驱动） |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | kubelet 面（14 项：pods/runningpods/exec/run/attach/portforward/healthz/logs/匿名/特权容器） | kube_hunter/modules/hunting/kubelet.py | we-have | - | 已对齐（CM-08） |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | etcd 远程面（读/写/版本泄露/无认证 4 项） | kube_hunter/modules/hunting/etcd.py | we-have | - | 已对齐（CM-08） |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | dashboard/proxy/certificates/AKS 特有面 | kube_hunter/modules/hunting/{dashboard,proxy,certificates,aks}.py | we-have | - | 已对齐（CM-08） |
| kube-hunter | K8s 攻防（克隆，官方声明停更） | CVE hunting（7 项：API 版本端点 PE/DoS、HTTP/2 Ping/Reset Flood、cluster-scoped 访问、kubectl cp 两代） | kube_hunter/modules/hunting/cves.py | we-have | - | 已对齐（CM-35） |
| Peirates | K8s 攻防（官方 README） | 云凭据收割（AWS/GCP/Azure token + kops 数据 + S3 列举） | docs/commands/README.md Cloud credential 表 | we-have | - | 已对齐（CM-21） |
| Peirates | K8s 攻防（官方 README） | 容器逃逸扫描与实施（hostPath/hostPID/docker sock/core_pattern/ptrace/host log symlink） | docs/commands/README.md Compromise 表 | we-have | - | 已对齐（检测面） |
| Peirates | K8s 攻防（官方 README） | CVE-2024-21626 leaky vessels（runc 工作目录逃逸） | docs/commands/leakyvessels.md | we-have | - | 已对齐（CM-35） |
| Peirates | K8s 攻防（官方 README） | 节点文件系统凭据窃取（nodefs-steal-secrets） | docs/commands/nodefs-steal-secrets.md | we-have | - | 已对齐（CM-22） |
| kdigger | K8s 攻防（官方 README） | 20 个采集 bucket（admission/apiresources/authorization/capabilities/cgroups/cloudmetadata/containerdetect/devices/environment/mount/node/pidnamespace/processes/runtime/services/syscalls/token/userid/usernamespace/version） | README.md Buckets 表 | partial | 大部分由 recon 族覆盖（控制台侧）；admission 扫描与 syscall 扫描缺 | syscall 面并入 CM-22；admission→CM-24 |
| kdigger | K8s 攻防（官方 README） | admission 链扫描（6 类特权 Pod dry-run 创建） | README.md Admission 节 | we-have | - | 已对齐（CM-24） |
| CDK | K8s 攻防（官方 README） | 容器逃逸 13 类（runc/containerd-shim/docker.sock/DIND/设备挂载/LXCFS/cgroup/userns/procfs/ptrace/CAP_DAC_READ_SEARCH） | README.md Exploit 表 Escaping 行 | we-have | - | 已对齐（面级） |
| CDK | K8s 攻防（官方 README） | K8s 凭据与配置面（registry 爆破/AK 扫描/etcd token/secret/configmap dump） | README.md Exploit 表 Credential Access 行 | partial | registry 爆破未执行（仅只读凭据发现）；etcd token dump 由 kubehunter/kubernetes-cve-catalog 覆盖 | 域内对齐（CM-34） |
| CDK | K8s 攻防（官方 README） | K8s 持久化面（webshell/后门 daemonset/影子 apiserver/CronJob/MITM ClusterIP） | README.md Exploit 表 Persistence 行 | missing | 持久化 payload 刻意不设（授权演练边界） | 不入 backlog |
| CDK | K8s 攻防（官方 README） | istio sidecar 元数据/PSP dump 探测 | README.md Exploit 表 Discovery 行 | partial | PSP 已废弃（K8s 1.25），istio 面未专设 | 记录不做（PSP 过时；istio 面低优先） |
| KubeletCTL | K8s 攻防（官方 README） | kubelet 10250 全 API 面（15 组：stats/metrics/logs/spec/pods/healthz/configz/containerLogs/run/exec/cri/attach/portForward/runningpods/debug） | API_TABLE.md | we-have | - | 已对齐（CM-08，检测优先） |
| KubeletCTL | K8s 攻防（官方 README） | kubelet 只读 10255 面（kube-hunter 交叉印证） | kube-hunter kubelet.py Exposed*Handler | we-have | - | 已对齐（CM-08） |
| Falco | 运行时/准入（官方文档） | 容器/主机行为面（进程/文件/网络/用户/软件管理 5 大类） | default-rules 页 Tags 分类 | partial | 我们生成 Falco 规则面向 ML 基础设施行为（pickle/权重/NCCL），主机通用行为面属规则目录广度问题 | CM-37（基线规则目录） |
| Falco | 运行时/准入（官方文档） | 云元数据出网检测（169.254.169.254） | default-rules 页 Contact EC2/cloud metadata service 规则 | we-have | - | 已对齐 |
| Falco | 运行时/准入（官方文档） | 容器逃逸行为检测（setns/unshare/特权容器启动/特权容器 mount） | default-rules 页 Change thread namespace/unshare/Launch Privileged Container/Mount in Privileged Container | we-have | - | 已对齐（攻防对偶） |
| Tetragon | 运行时/准入（官方文档） | 进程执行/系统调用/IO（网络+文件）行为面 | tetragon.io/docs/overview/ | partial | 我们的 Tetragon 靶面（defense-bypass-tetragon）已有；规则生成目标缺 | CM-25 |
| Tetragon | 运行时/准入（官方文档） | 零日行为传感器（非签名化策略检测） | tetragon.io/docs/overview/ | we-have | - | 已对齐（行为化口径） |
| KubeArmor | 运行时/准入（官方 README+官网） | 进程/文件/网络三维行为约束面（pods/containers/nodes） | README 首段 | we-have | - | 已对齐（攻防对偶） |
| KubeArmor | 运行时/准入（官方 README+官网） | MITRE/STIG/CIS 基线规则面 | README Harden Infrastructure 表 | partial | CIS 基线检查族（CM-33）；STIG 不做 | CM-33 + 不做项记录 |
| Kyverno | 运行时/准入（官方 docs+政策库） | 20 类政策面（pod-security/psp-migration/best-practices/生态专用...） | kyverno/policies 目录 | partial | 我们输出 ClusterPolicy×5 面向 ML 面；类别广度差距记 CM-37 | CM-37 |
| Kyverno | 运行时/准入（官方 docs+政策库） | 供应链镜像面（verifyImages 签名验证） | kyverno.io/docs/policy-types/verify-image | partial | 我们有 cosign 风格 provenance 校验（supplychain.py），无准入侧 verifyImages 规则生成 | CM-27 |
| Gatekeeper | 运行时/准入（官方库） | 30 general 模板面（allowedrepos/containerlimits/requiredlabels/uniqueingresshost/verifydeprecatedapi...） | gatekeeper-library library/general 30 目录 | partial | 我们的 Gatekeeper 输出面向 ML 面；模板广度记 CM-37 | CM-37 |
| Gatekeeper | 运行时/准入（官方库） | PSP 等价面（pod-security-policy 类别） | library/pod-security-policy 目录 | partial | 同上 | CM-37 并入 |
| garak | AI/LLM 安全（克隆） | 提示注入/越狱面（promptinject/dan×20/grandma×5/suffix/tap...） | garak/probes/{promptinject,dan,grandma,suffix,tap}.py | missing | 模型行为面探针族 | CM-32 |
| garak | AI/LLM 安全（克隆） | 数据泄露面（leakreplay×16/apikey/sysprompt_extraction/lmrc×8） | garak/probes/{leakreplay,apikey,sysprompt_extraction,lmrc}.py | partial | 我们有 aigateway-log-pii-leak/prefix-cache-cross-tenant-leak（基础设施级）；模型级泄露探针缺 | CM-32 |
| garak | AI/LLM 安全（克隆） | 隐性注入面（latentinjection×17/web_injection×8/smuggling） | garak/probes/{latentinjection,web_injection,smuggling}.py | partial | 有 open-webui-indirect-injection-exec（单点）；族级广度缺 | CM-32 并入 |
| garak | AI/LLM 安全（克隆） | 供应链幻觉面（packagehallucination×8） | garak/probes/packagehallucination.py | missing | 包幻觉探针（代码生成域） | 并入 CM-32（探针族子项） |
| PyRIT | AI/LLM 安全（克隆） | 多轮越狱面（逐步升级对话） | multi_turn/crescendo.py+tree_of_attacks.py | missing | 升级链模板 | CM-29 |
| PyRIT | AI/LLM 安全（克隆） | 多模态攻击面（音频/图像转换器） | converter/audio_*.py + image_*.py | missing | 多模态 payload 转换（类别外：纯文本基础设施面） | 记录不做（域外） |
| PyRIT | AI/LLM 安全（克隆） | 编码混淆面（base64/rot13/leetspeak/morse/unicode×N 转换器 ~90） | converter/*.py 枚举 | partial | 我们有 http_variants 路径/方法变体（基础设施级 payload 变形）；模型文本混淆转换器缺 | CM-29（转换器框架） |
| promptfoo | AI/LLM 安全（克隆） | 业务红线面（13 行业插件：金融/医疗/保险/药房/房地产/电信/teen safety/agentic/codingAgent/compliance/ecommerce/policy/harmful） | src/redteam/plugins/ 13 目录 | missing | 行业合规红线探针集 | 并入 CM-32（探针族扩展） |
| promptfoo | AI/LLM 安全（克隆） | Agent/工具滥用面（excessiveAgency/hijacking/mcp/rbac/bola/bfla） | src/redteam/plugins/{excessiveAgency,hijacking,mcp,rbac,bola,bfla}.ts | partial | agent 工具面基准（CM-30 同源） | CM-30 |
| promptfoo | AI/LLM 安全（克隆） | RAG 面文档泄露（ragDocumentExfiltration/ragSourceAttribution/crossSessionLeak） | src/redteam/plugins/rag*.ts+crossSessionLeak.ts | partial | 向量库暴露面已有（vector-db-exposure）；RAG 内容级泄露探针缺 | 并入 CM-32 |
| AgentDojo | AI/LLM 安全（克隆） | agent 工具环境间接注入面（injection_tasks 注入→工具执行） | default_suites/*/injection_tasks.py | partial | 工具环境内间接注入→执行的套件化场景 | CM-30 |
| AgentDojo | AI/LLM 安全（克隆） | DoS 攻击族 | attacks/dos_attacks.py | we-have | - | 已对齐（基础设施级） |
| Trivy | 其他（官方 README） | 镜像 CVE 面（OS+语言包漏洞） | README Scanners | partial | 外部扫描器导入（CM-13）；镜像 CVE 库自建不做 | CM-13 |
| Trivy | 其他（官方 README） | IaC/K8s 错配面（misconfig） | README Scanners | we-have | - | 已对齐（域内） |
| Trivy | 其他（官方 README） | 密钥泄露面（secret scanner） | README Scanners | missing | 通用 secret 规则库 | CM-34 |
| Syft | 其他（官方 README） | 软件包依赖面（数十生态） | README Features | partial | AI SBOM 覆盖模型/数据集/license；通用包生态面经 CM-13 适配器补 | CM-13 |
| kube-bench | 其他（官方 README+cfg 枚举） | 控制面安全配置面（API Server/Controller Manager/Scheduler/etcd 分区） | README 输出示例 1 Master Node Security Configuration | we-have | - | 已对齐（CM-33） |
| kube-bench | 其他（官方 README+cfg 枚举） | 节点安全配置面（kubelet/config 分区） | cfg 分区结构 | we-have | - | 已对齐（CM-33） |
| kube-bench | 其他（官方 README+cfg 枚举） | 51 个发行版/版本 profile（EKS/GKE/AKS/ACK/RKE/k3s/RH 专属） | cfg 目录枚举 | partial | 我们六云为契约级跨租户面；发行版基线 profile 缺 | CM-33（profile 数量按落地范围裁剪） |
| KubiScan | K8s 攻防（新克隆） | 特权 Pod/容器面（--risky-pods/--privileged-pods） | KubiScan.py flag | we-have | - | 已对齐 |
| KubiScan | K8s 攻防（新克隆） | Secret 挂载面（pods-secrets-volume/-env 逐 Pod） | KubiScan.py flag | we-have | - | 已对齐（CM-36） |
| KubiScan | K8s 攻防（新克隆） | token dump（-dt 从 Pod dump token） | KubiScan.py --dump-tokens | partial | token 实际导出动作不产品化（ROE 采集边界） | 已部分对齐（检测面） |
| DeepCE | K8s 攻防（新克隆） | Docker 枚举面（版本/挂载/设备/sock/组权限/敏感文件/环境变量/密码哈希） | README Enumerations 11 项 | partial | 等价面由 escape-primitives+privileged-workloads+runtime-socket-escape 覆盖检测；逐项 in-pod 枚举在 CM-22 | CM-22（子集） |
| DeepCE | K8s 攻防（新克隆） | 容器逃逸面（DOCKER 组/PRIVILEGED/SOCK 三 exploit） | README Exploits | we-have | - | 已对齐（面级） |
| DeepCE | K8s 攻防（新克隆） | CVE-2019-5746/2019-5021/2025-9074 检测 | deepce.sh CVE 字符串 | missing | 容器 CVE 检测条目 | CM-35 |
| trufflehog | 密钥扫描（新克隆） | 版本历史密钥泄露面（git 全历史扫描） | pkg/sources/git | missing | git 历史扫描 | CM-34 |
| trufflehog | 密钥扫描（新克隆） | 云凭据面（AWS/GCP/Azure/Stripe/... 892 类） | pkg/detectors/ 目录族 | partial | ML 基础设施凭据面已有（上游 key/API key/token）；通用云密钥库缺 | CM-34 |
| gitleaks | 密钥扫描（新克隆） | git 全历史+diff 密钥面 | detect 命令语义 | missing | 同 trufflehog | CM-34 |
| gitleaks | 密钥扫描（新克隆） | 222 类密钥正则面（api key/token/password/证书等） | config/gitleaks.toml 规则族 | missing | 正则规则库 | CM-34 |
| Giskard | AI/LLM 安全（新克隆） | 注入/越狱面（prompt_injection/crescendo/gcg/goat generator） | generators/*.py | missing | 同 garak 面 | CM-32 |
| Giskard | AI/LLM 安全（新克隆） | 表格/ML 模型质量面（huggingface dataset 检测） | generators/huggingface.py | missing | 模型质量扫描类别外（我们专注安全面） | 记录不做（域外） |
| Lakera Guard | AI/LLM 安全（商业，官方 docs） | 提示注入/越狱检测面（instruction override/混淆/间接注入） | docs.lakera.ai/docs/prompt-defense | partial | 我们无模型行为面探针；但对 guardrail 产品的绕过靶面已有 waf-inference 版（Lakera 产品指纹未设） | CM-39（AI 防火墙靶面扩展） |
| Lakera Guard | AI/LLM 安全（商业，官方 docs） | 数据泄露防护面（PII/敏感输出） | docs.lakera.ai/docs/data-leakage-prevention | we-have | - | 已对齐（域内） |
| Lakera Guard | AI/LLM 安全（商业，官方 docs） | RAG 引用文档投毒筛查（离线文档筛查） | docs.lakera.ai/docs/api/guard（batch document screening） | missing | 文档投毒离线筛查面 | 并入 CM-32（探针族扩展） |
| MKAT | K8s 攻防（既有克隆转正） | IMDS 可达性面（Pod→169.254.169.254） | pkg/.../imds/ | we-have | - | 已对齐 |
| MKAT | K8s 攻防（既有克隆转正） | EKS 专属信任链面（ServiceAccount→IAM Role assume） | pkg/.../role_relationships/ | we-have | - | 已对齐（契约级） |
| grype | 其他（官方 README） | 镜像/FS 漏洞面（OS+语言包） | README Features | partial | 外部 CVE 扫描经 CM-13 导入；自建不做 | CM-13 |

**总计：82 条**（工具 31 个）

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
