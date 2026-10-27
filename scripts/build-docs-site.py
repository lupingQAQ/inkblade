#!/usr/bin/env python3
"""Render the static documentation site and the public 0-day ledger.

Content lives here so the English site, the Chinese site and the bilingual
landing page cannot drift apart. Output is plain HTML plus two local assets:
no build toolchain, no webfonts, no CDN, no analytics, no external links.

    python scripts/build-docs-site.py           # write docs/ pages + 0DAY-PUBLIC.md
    python scripts/build-docs-site.py --check   # fail when committed output is stale
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

VERSION = "0.2.0"
DISCLOSURE_START = "2026-10-27"
DISCLOSURE_TARGET = "2027-01-25"

# --------------------------------------------------------------------------
# shared data
# --------------------------------------------------------------------------

MODULE_SERIES = [
    ("侦察", "Reconnaissance", 67, "Control plane, schedulers, gateways, storage, identity — enumeration only."),
    ("横向利用", "Lateral movement", 66, "Service-to-service pivots, gateway abuse, worker takeover, token reuse."),
    ("网络架构", "Network architecture", 52, "CNI semantics, policy coverage, service mesh, multi-NIC and fabric reach."),
    ("权限链", "Privilege chains", 43, "RBAC escalation, admission gaps, service-account trust, operator permissions."),
    ("核心代码", "Core code paths", 22, "Deserialisation, template injection, eval sinks, checkpoint loaders."),
    ("窃取与数据泄露", "Exfiltration", 19, "Dataset, checkpoint and credential exposure across tenant boundaries."),
    ("混合云", "Hybrid cloud", 11, "Instance metadata reachability, workload identity, cloud storage trust edges."),
    ("情报", "Intelligence", 6, "Version and advisory correlation that turns inventory into applicability."),
]

MODULE_LEVELS = [
    ("只读侦察", "Read-only recon", 119),
    ("主动探测", "Active probing", 72),
    ("利用验证", "Exploit verification", 80),
    ("全影响演示", "Full-impact demo", 15),
]

CHAIN_FAMILIES = [
    ("网络利用链", "Network exploitation", 12),
    ("经典攻击链", "Classic kill chain", 9),
    ("云侧权重桶链", "Cloud weight buckets", 5),
    ("零日链", "Zero-day chains", 2),
    ("AI 网关链", "AI gateway chains", 1),
]

WORKFLOW = [
    ("01", "Authorization", "授权", "Signed consent with scope, window, level and emergency contact. The hash rides along in every run.", "consent record + hash"),
    ("02", "Assets", "资产", "Seeds grow into an incremental asset table; imported scanner results are normalised into the same inventory.", "assets table, collection snapshot"),
    ("03", "Reconnaissance", "侦察", "Read-only modules look at what is really deployed. The surface matrix says what is testable here.", "findings, surface matrix"),
    ("04", "Combination", "组合", "Declared combination signatures pull out findings that only matter together, preconditions attached.", "ranked combinations"),
    ("05", "Chain planning", "链编排", "Chains are ordered graphs. Dry-run resolves the topology and prints every write before it happens.", "plan, write surface"),
    ("06", "Approval", "审批", "High-impact steps wait for a human, or for a bounded pre-authorisation with an explicit level.", "approval record, window"),
    ("07", "Execution", "执行", "Only the approved scope runs. Write modules pass the backup gate first; refusals exit 91.", "action log, backups"),
    ("08", "Evidence", "证据", "Context journal, SQLite audit tables, one archive per step with a SHA-256 manifest.", "context.jsonl.gz, evidence.db, steps/"),
    ("09", "Report", "报告", "Pentest narrative and remediation checklist from the same evidence, in Chinese and English.", "reports, SARIF, OCSF, VEX"),
    ("10", "Rules", "规则", "Each chain becomes admission, network, detection and convergence rules, then gets replayed.", "rule packs, replay matrix"),
    ("11", "Retest", "复测", "Scheduled re-runs are diffed against the baseline. Drift is a finding; silence is not a pass.", "drift report, pipeline verdict"),
]

PROFILES = [
    ("airgapped", "Air-gapped K8s", "70.91", "89.09"),
    ("bare-k8s-gpu", "Self-managed K8s + GPU", "67.64", "81.09"),
    ("gpu-pooling", "GPU pooling", "60.00", "77.09"),
    ("managed-ack-tke", "Managed ACK / TKE", "68.00", "81.45"),
    ("ray-vllm", "KubeRay + vLLM", "68.73", "82.18"),
    ("slurm-hpc", "Bare-metal Slurm", "25.09", "52.36"),
]

# component, class (en), class (zh), affected versions
ZERO_ROWS = [
    ("vllm-jev", "Authentication bypass", "认证绕过", "v0.31.0 · 57226d4"),
    ("djev", "Authentication bypass, open relay", "认证绕过、开放中继", "e5841cf"),
    ("slime", "Path traversal", "路径穿越", "05e3b01 · SGLang 0.5.15.post1"),
    ("sglang-omni", "Auth fail-open", "鉴权失效（fail-open）", "204ba29"),
    ("skyrl", "Unsafe deserialisation", "不安全反序列化", "a1e34db"),
    ("skyrl", "Missing authentication", "缺少鉴权", "a1e34db"),
    ("trl", "Missing authentication", "缺少鉴权", "1.15.0"),
    ("areal", "Unauthenticated code execution", "未授权代码执行", "448de52"),
    ("areal", "Deserialisation", "反序列化", "448de52"),
    ("openrlhf", "Missing authentication", "缺少鉴权", "0.11.2 · dc2a7ad"),
    ("msswift", "Unsafe model loading", "不安全模型加载", "4.5.3 · fbc61cf"),
    ("verl", "Code execution (eval/exec)", "代码执行（eval/exec）", "76e837e"),
    ("verl", "Deserialisation over TCP", "TCP 反序列化", "76e837e"),
    ("skyrl", "Path traversal", "路径穿越", "a1e34db"),
    ("openrlhf", "Insecure serialisation", "不安全序列化", "0.11.2 · dc2a7ad"),
    ("areal", "Unsafe deserialisation", "不安全反序列化", "448de52"),
    ("slime", "Unsafe deserialisation", "不安全反序列化", "05e3b01"),
    ("openjev", "Code execution via release hook", "发布钩子代码执行", "b4339c6"),
    ("msswift", "Sandbox escape", "沙箱逃逸", "4.5.3 · fbc61cf"),
    ("areal", "Unauthenticated control plane", "未授权控制面", "448de52"),
    ("onejev", "Server-side request forgery", "服务端请求伪造", "6122519"),
    ("llm2jev", "Local file read", "本地文件读取", "f2bdad6"),
    ("siliconlab", "Credential exposure", "凭据泄露", "a08e969"),
    ("verl", "Command injection", "命令注入", "76e837e"),
    ("dify", "Unauthenticated RCE", "未授权 RCE", "v1.17.1"),
    ("dify", "Auth fail-open", "鉴权失效（fail-open）", "v1.17.1 · bbfac7a"),
    ("dify", "Hardcoded key", "硬编码密钥", "v1.17.1"),
    ("dify", "Cross-tenant access", "跨租户访问", "v1.17.1"),
    ("open-webui", "Sandbox escape", "沙箱逃逸", "v0.12.3 · 91ea4e3"),
    ("vllm", "Authentication bypass", "认证绕过", "v0.32.0"),
    ("deepspeed", "Unsafe deserialisation", "不安全反序列化", "v0.19.8"),
    ("msswift", "Local file read", "本地文件读取", "v4.6.0"),
    ("deepspeed", "Unsafe deserialisation", "不安全反序列化", "v0.19.8"),
    ("deepspeed", "Unsafe deserialisation", "不安全反序列化", "v0.19.8"),
    ("llamafactory", "Unsafe deserialisation", "不安全反序列化", "v0.9.5"),
    ("megatron", "Unsafe deserialisation", "不安全反序列化", "core_v0.19.2"),
    ("msswift", "Deserialisation", "反序列化", "v4.6.0"),
    ("msswift", "Deserialisation", "反序列化", "v4.6.0"),
    ("msswift", "Deserialisation", "反序列化", "v4.6.0"),
]

assert len(ZERO_ROWS) == 39, len(ZERO_ROWS)

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def figures(items: list[tuple[str, str]]) -> str:
    cells = "".join(f'<div class="figure"><b>{v}</b><span>{k}</span></div>' for v, k in items)
    return f'<div class="figures">{cells}</div>'


def table(headers: list[tuple[str, str]], rows: list[str]) -> str:
    th = "".join(f'<th class="{cls}">{label}</th>' for label, cls in headers)
    return f'<div class="tbl"><table><thead><tr>{th}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def series_table(lang: str) -> str:
    pick = (lambda zh, en, n, d: (en, zh)) if lang == "en" else (lambda zh, en, n, d: (zh, en))
    rows = [
        f'<tr><td>{pick(zh, en, n, d)[0]}<br><span class="dim">{pick(zh, en, n, d)[1]}</span></td>'
        f'<td class="num">{n}</td><td>{d}</td></tr>'
        for zh, en, n, d in MODULE_SERIES
    ]
    head = [("Series", ""), ("Modules", "num"), ("Surface it covers", "")] if lang == "en" else [
        ("模块族", ""), ("数量", "num"), ("覆盖的部署面", "")]
    return table(head, rows)


def level_table(lang: str) -> str:
    rows = []
    for zh, en, n in MODULE_LEVELS:
        first, second = (en, zh) if lang == "en" else (zh, en)
        rows.append(f'<tr><td>{first}<br><span class="dim">{second}</span></td><td class="num">{n}</td></tr>')
    head = [("Technical level", ""), ("Modules", "num")] if lang == "en" else [("技术级别", ""), ("数量", "num")]
    return table(head, rows)


def chain_table(lang: str) -> str:
    rows = []
    for zh, en, n in CHAIN_FAMILIES:
        first, second = (en, zh) if lang == "en" else (zh, en)
        rows.append(f'<tr><td>{first}<br><span class="dim">{second}</span></td><td class="num">{n}</td></tr>')
    head = [("Chain family", ""), ("Chains", "num")] if lang == "en" else [("链族", ""), ("条数", "num")]
    return table(head, rows)


def profile_table(lang: str) -> str:
    rows = [
        f'<tr><td><code>{key}</code></td><td>{name}</td><td class="num">{cov}%</td><td class="num">{op}%</td></tr>'
        for key, name, cov, op in PROFILES
    ]
    head = (
        [("Profile", ""), ("Deployment shape", ""), ("Production", "num"), ("Operable", "num")]
        if lang == "en"
        else [("画像", ""), ("部署形态", ""), ("生产可测", "num"), ("可操作", "num")]
    )
    return table(head, rows)


def reserve_table(lang: str) -> str:
    rows = []
    for component, cls_en, cls_zh, versions in ZERO_ROWS:
        cls = cls_en if lang == "en" else cls_zh
        status = "Reported" if lang == "en" else "已上报"
        window = f"{DISCLOSURE_START} → {DISCLOSURE_TARGET}" if lang == "en" else f"{DISCLOSURE_START} → {DISCLOSURE_TARGET}（90 天）"
        rows.append(
            f'<tr><td><code>{component}</code></td><td>{cls}</td><td>{versions}</td>'
            f'<td class="num">{status}</td><td class="num">{window}</td></tr>'
        )
    head = (
        [("Component", ""), ("Class", ""), ("Affected versions", ""), ("Status", "num"), ("Timeline", "num")]
        if lang == "en"
        else [("组件", ""), ("漏洞类别", ""), ("受影响版本", ""), ("状态", "num"), ("披露时间线", "num")]
    )
    return table(head, rows)


RESERVE_INVENTORY = [
    ("Vulnerability entries", "漏洞条目", 184),
    ("Runnable demos", "可运行 demo", 68),
    ("Zero-day candidates", "零日候选", 169),
    ("Novelty-checked", "查新通过", 47),
    ("Reserve-eligible", "储备可用", 46),
    ("Unique reserve primitives", "去重后独立储备原语", 39),
    ("Version matrix rows", "版本矩阵条目", 103),
    ("Weapon packs", "weapon pack", 47),
    ("Detection rules", "检测规则", 121),
    ("Attack chains", "攻击链", 29),
]


def reserve_inventory_table(lang: str) -> str:
    head = [("Inventory", ""), ("Count", "num")] if lang == "en" else [("库存", ""), ("数量", "num")]
    rows = [
        f'<tr><td>{en if lang == "en" else zh}</td><td class="num">{count}</td></tr>'
        for en, zh, count in RESERVE_INVENTORY
    ]
    return table(head, rows)


# --------------------------------------------------------------------------
# prose
# --------------------------------------------------------------------------

SECTIONS: list[dict] = []


def section(sid, nav_en, nav_zh, title_en, title_zh, sub_en, sub_zh, en, zh) -> None:
    SECTIONS.append({
        "id": sid,
        "nav": {"en": nav_en, "zh": nav_zh},
        "title": {"en": title_en, "zh": title_zh},
        "sub": {"en": sub_en, "zh": sub_zh},
        "body": {"en": en, "zh": zh},
    })


LAYERS = [
    ("1", "Architecture", "架构层",
     "Audit rail and multi-plane alignment, PD-split KV channels, IMEX domains, MoE/EP collectives, long-context KV lifetime and federation.",
     "审计 rail 与多平面错配、PD 分离 KV 通道、IMEX 域、MoE/EP 集合通信、长上下文 KV 生命周期与联邦。",
     "rail-mismatch-forcing, prefill-decode-kv-channel-unauth, nvlink-imex-isolation"),
    ("2", "Product / framework", "产品 / 框架层",
     "Enumerate admin and control surfaces of vLLM, SGLang, TRL, verl, AReaL, SkyRL, OpenRLHF, slime, LLaMA-Factory, ms-swift, Megatron-LM, DeepSpeed, transformers, gateways and agent platforms.",
     "枚举 vLLM、SGLang、TRL、verl、AReaL、SkyRL、OpenRLHF、slime、LLaMA-Factory、ms-swift、Megatron-LM、DeepSpeed、transformers、网关与 Agent 平台的管理面与控制面。",
     "vllm-plugin-auth-bypass, sglang-admin-failopen, verl-prime-code-exec"),
    ("3", "Component / operator", "组件 / Operator 层",
     "Inspect Ray and LWS control planes, GPU Operator and driver containers, DRA policy, CSI node plugins, BMC/Redfish and DPU offload.",
     "检查 Ray 与 LWS 控制面、GPU Operator 与驱动容器、DRA 策略、CSI 节点插件、BMC/Redfish 与 DPU offload。",
     "ray-dashboard-job, gpu-operator-driver-audit, gpu-dra-mig-policy"),
    ("4", "Network / fabric", "网络 / fabric 层",
     "Test policy bypass on hostNetwork, SR-IOV and macvlan, dual CNI planes, IB subnet manager, RoCE PFC/ECN, SHARP, NCCL bootstrap and DNS.",
     "验证 hostNetwork、SR-IOV、macvlan 上的策略旁路，CNI 双控制面、IB 子网管理器、RoCE PFC/ECN、SHARP、NCCL bootstrap 与 DNS。",
     "multus-sriov-rdma-bypass, ib-sm-partition-audit, sharp-in-network-poison"),
    ("5", "Data / weights", "数据 / 权重层",
     "Check checkpoint and optimizer shards, dataset pipelines, HF cache, weight buckets, model registries and KV/prefix caches.",
     "检查 checkpoint 与优化器分片、数据集管道、HF 缓存、权重桶、模型注册表与 KV/前缀缓存。",
     "checkpoint-shard-poison, skyrl-fetch-weights-traversal, model-registry-exposure"),
    ("6", "Tenant / isolation", "租户 / 隔离层",
     "Measure MIG and MPS residue, GPU pooling schedulers, cache_salt policy and routing metric leakage.",
     "度量 MIG 与 MPS 残留、GPU 池化调度器、cache_salt 策略与路由指标泄露。",
     "gpu-tenant-residue, hami-scheduler-auth-gap, cache-salt-policy-audit"),
    ("7", "Supply chain / identity", "供应链 / 身份层",
     "Verify trust_remote_code, revision pinning, attestation chains, SBOM, IRSA/workload identity, IMDS and credential exposure.",
     "核验 trust_remote_code、revision 固定、证明链、SBOM、IRSA/工作负载身份、IMDS 与凭据暴露。",
     "trust-remote-code-supply-chain, gpu-cc-attestation-chain, cloud-irsa-trust-wildcard"),
    ("8", "Cache security", "缓存安全层",
     "Test cross-tenant prefix cache, semantic false hits, eviction residue, remote KV pools, EPP metrics and TTFT timing.",
     "测试跨租户前缀缓存、语义缓存误命中、逐出残留、远程 KV 池、EPP 指标与 TTFT 时序。",
     "prefix-cache-cross-tenant-leak, remote-kv-pool-isolation, cache-timing-sidechannel"),
    ("9", "Cross-combination", "跨组合层",
     "Report findings that only exist when two or three components meet, once at the combination, with component notes folded in.",
     "只在两个或三个组件相遇时才成立的发现，只报一次，并把组件级记录并入组合。",
     "sglang-weight-exfil, imex-computedomain-gpu-memory-crossing, long-context-cache-leak"),
    ("10", "Defense bypass", "防护绕过层",
     "Measure whether HIDS, runtime eBPF, admission, image scan, host agents, WAF and flow telemetry see benign authorized activity.",
     "度量 HIDS、运行时 eBPF、准入、镜像扫描、主机代理、WAF 与流量可视化是否看得见良性授权行为。",
     "defense-bypass-elkeid, defense-bypass-falco, defense-bypass-admission"),
]

WORKFLOW9 = [
    ("1", "Foothold", "立足", "session open records the entry vector, target, namespace, Pod and credential fingerprint.",
     "session open 记录入口方式、目标、命名空间、Pod 与凭据指纹。", "session record", "会话记录"),
    ("2", "Rust probe", "Rust 探针", "probe deploy delivers the static binary and registers its identity and hash.",
     "probe deploy 投放静态二进制并登记身份与哈希。", "probe identity", "探针身份"),
    ("3", "Channel", "通道", "channel listen accepts the probe's reverse connection; a stdio channel is available when a local transport exists.",
     "channel listen 接收探针主动回连；存在本地命令通道时也可用 stdio 通道。", "channel state", "通道状态"),
    ("4", "Detection", "检测", "session run, run and agent run execute templates across the ten layers.",
     "session run、run 与 agent run 按十层执行模板。", "findings, evidence", "发现、证据"),
    ("5", "Escape", "逃逸", "execute resolves a chain; write steps pass the backup gate first.",
     "execute 解析链；写步骤先过备份闸门。", "escape path", "逃逸路径"),
    ("6", "Lateral", "横向", "channel forwards, child probes and agent graph edges map internal reachability.",
     "通道转发、子探针与 agent 图边测绘内部可达性。", "reachability graph", "可达图"),
    ("7", "Multi-probe", "多探针", "probe spawn extends the tree; children inherit a stricter budget and allow-list.",
     "probe spawn 扩展探针树；子探针继承更严格的预算与白名单。", "probe tree", "探针树"),
    ("8", "Cross-cluster", "跨集群", "agent relay connects clusters; agent coverage writes the closure proof.",
     "agent relay 连接集群；agent coverage 写出闭合证明。", "relay status, coverage proof", "中继状态、覆盖证明"),
    ("9", "Report / rules / console", "报告 / 规则 / 控制台", "report, export, rules generate and ui close the engagement.",
     "report、export、rules generate 与 ui 收束项目。", "report, rule packs, console", "报告、规则包、控制台"),
]

COMMANDS = [
    ("Onboarding", "接入向导", "inkblade up"),
    ("Authorization", "授权记录", "inkblade quickstart · inkblade roe"),
    ("Session", "会话", "inkblade session open|status|close|run"),
    ("Probe", "探针", "inkblade probe deploy|list|collect|exec|read-file|list-files|upload|download|spawn|cleanup"),
    ("Channel", "通道", "inkblade channel listen|start|status|stop"),
    ("One template", "单模板", "inkblade session run --id <session> --module <key> · inkblade run --module <key>"),
    ("Chain", "链", "inkblade execute --chain <id> [--dry-run]"),
    ("Agent", "Agent", "inkblade agent run|status|trace|resume|replay|stop"),
    ("Cross-cluster", "跨集群", "inkblade agent relay add|list|status · inkblade agent coverage status|proof"),
    ("Report", "报告", "inkblade report --run <id> --lang bi"),
    ("Export", "导出", "inkblade export --run <id> --format sarif|ocsf|vex"),
    ("Rules", "规则", "inkblade rules generate · inkblade rules validate"),
    ("Console", "控制台", "inkblade ui"),
    ("Docs site", "文档站点", "inkblade docs --port 8766 --bind 127.0.0.1"),
    ("Templates", "模板", "inkblade template list|get|plan|validate"),
]

FAQ_ITEMS = [
    ("Does the target Pod need Python?",
     "No. The probe is a static Rust binary and templates are JSON. The Pod needs a Linux kernel, a writable temporary directory or memfd_create, and the probe process inherits the Pod's namespaces and service account.",
     "目标 Pod 要装 Python 吗？",
     "不要。探针是静态 Rust 二进制，模板是 JSON。目标只需要 Linux 内核、可写临时目录或 memfd_create，探针进程继承 Pod 的命名空间与 ServiceAccount。"),
    ("How does the probe get into the Pod?",
     "kubectl, a ServiceAccount token, a shared volume, an EphemeralContainer manifest or an authorized RCE callback. Each path has prerequisites and leaves traces.",
     "探针怎么进 Pod？",
     "kubectl、ServiceAccount token、共享卷、EphemeralContainer 清单或授权 RCE 回调。每种方式都有前置条件，也会留下痕迹。"),
    ("Is the probe a backdoor?",
     "No. It does not persist, modify startup, patch images or call a fixed C2. It runs inside an authorized session, executes registered templates, defaults to read-only, gates writes and cleans up.",
     "探针是不是后门？",
     "不是。它不持久化、不改启动项、不改镜像、不回连固定 C2。它只在授权会话内运行，执行已注册模板，默认只读，写操作过闸门，退出时清理。"),
    ("How are writes controlled?",
     "Five gates: signed authorization covering target/level/window, --allow-write, meta.writes with a write step, backup-write mode and a backup receipt. A write reads back the hash and rolls back on failure.",
     "写操作怎么保证安全？",
     "五道闸门：授权覆盖目标/级别/时间窗、--allow-write、meta.writes 与写步骤、backup-write 模式、备份回执。写后回读哈希，失败回滚。"),
    ("Can it run air-gapped?",
     "Yes. The controller needs no network, the probe needs no package index, and templates and rule packs ship with the release.",
     "能离线吗？",
     "能。控制端不需要外网，探针不需要包索引，模板与规则包随发布物带入。"),
    ("Can I use it commercially?",
     "Apache-2.0 permits commercial use and forks. Keep LICENSE and NOTICE, and do not use the InkBlade trademark for a fork.",
     "能商用或 fork 吗？",
     "Apache-2.0 允许商用与 fork。保留 LICENSE 与 NOTICE，不要用 InkBlade 商标命名 fork。"),
]


def layers_table(lang: str) -> str:
    head = (
        [("Layer", ""), ("What you can do", ""), ("Representative templates", "")]
        if lang == "en"
        else [("层", ""), ("能做什么", ""), ("代表模板", "")]
    )
    rows = []
    for num, en_name, zh_name, en_what, zh_what, keys in LAYERS:
        name, what = (en_name, en_what) if lang == "en" else (zh_name, zh_what)
        rows.append(
            f'<tr><td><span class="mono-n">{num}</span>{name}</td>'
            f'<td>{what}</td><td><code>{keys}</code></td></tr>'
        )
    return table(head, rows)


def workflow_flow(lang: str) -> str:
    items = []
    for num, en_name, zh_name, en_desc, zh_desc, en_artifact, zh_artifact in WORKFLOW9:
        name, desc, artifact = (en_name, en_desc, en_artifact) if lang == "en" else (zh_name, zh_desc, zh_artifact)
        items.append(
            f'<li><span class="n">{num}</span><span class="t">{name}</span>'
            f'<span class="d">{desc}<br><span class="note">→ {artifact}</span></span></li>'
        )
    return f'<ul class="flow">{"".join(items)}</ul>'


def command_table(lang: str) -> str:
    head = [("Task", ""), ("Command", "")] if lang == "en" else [("任务", ""), ("命令", "")]
    rows = [
        f'<tr><td>{en_task if lang == "en" else zh_task}</td><td><code>{command}</code></td></tr>'
        for en_task, zh_task, command in COMMANDS
    ]
    return table(head, rows)


def faq_block(lang: str) -> str:
    parts = []
    for en_q, en_a, zh_q, zh_a in FAQ_ITEMS:
        q, a = (en_q, en_a) if lang == "en" else (zh_q, zh_a)
        parts.append(f"<h3>{q}</h3><p>{a}</p>")
    return "".join(parts)


section(
    "capabilities", "Capabilities", "核心能力",
    "Ten detection layers", "十层检测",
    "What the probe looks at, layer by layer", "探针逐层看什么",
    en="""<p>Each layer is a set of templates you can run on its own. A template declares inputs, steps, checks, findings and artifacts; the probe executes it and returns evidence.</p>
""" + figures([("10", "detection layers"), ("286", "templates"), ("29", "chains"), ("11", "defense-bypass modules")]) + """
<h3>Ten detection layers</h3>
""" + layers_table("en") + """
<p class="note">Layer detail, detection points and evidence produced: <a href="DETECTION-LAYERS.md">DETECTION-LAYERS.md</a> · <a href="PRODUCT.md">PRODUCT.md</a></p>
<h3>Platform capabilities</h3>
<ul>
  <li><b>One execution path.</b> Foothold, Rust probe, framed channel, in-pod task, child probe, evidence.</li>
  <li><b>Zero target-side interpreter.</b> A static binary runs the same templates on distroless, scratch and Python images.</li>
  <li><b>Probe trees.</b> probe_id and parent_id, per-child tokens, stricter inheritance, bounded depth and fan-out, child-first cleanup.</li>
  <li><b>Agent runtime.</b> A budgeted objective graph with decision trace, journal resume and zero-execution replay.</li>
  <li><b>Cross-cluster relay.</b> The same framed protocol between clusters, with a closure proof.</li>
  <li><b>Evidence at the boundary.</b> Task results, step logs, artifacts, SHA-256 manifests, traffic tables and cleanup receipts.</li>
  <li><b>Rules you can replay.</b> Admission, runtime and network packs with blocked / detected / missed matrices.</li>
  <li><b>Report and console.</b> Bilingual pentest and remediation reports, SARIF / OCSF / VEX export, local console.</li>
</ul>""",
    zh="""<p>每一层都是一组可独立执行的模板。模板声明输入、步骤、检查项、发现和产物；探针执行模板并回传证据。</p>
""" + figures([("10", "检测层"), ("286", "模板"), ("29", "条链"), ("11", "防护绕过模块")]) + """
<h3>十层检测</h3>
""" + layers_table("zh") + """
<p class="note">逐层检测点与证据产出：<a href="DETECTION-LAYERS.md">DETECTION-LAYERS.md</a> · <a href="PRODUCT.md">PRODUCT.md</a></p>
<h3>平台能力</h3>
<ul>
  <li><b>一条执行路径。</b> 立足、Rust 探针、帧通道、Pod 内任务、子探针、证据。</li>
  <li><b>目标侧零解释器。</b> 静态二进制在 distroless、scratch 与 Python 镜像上跑同一套模板。</li>
  <li><b>探针树。</b> probe_id 与 parent_id、独立子 token、更严格的继承、有界的深度与扇出、先子后父清理。</li>
  <li><b>Agent 运行时。</b> 带预算的目标图，含决策轨迹、journal 恢复与零执行回放。</li>
  <li><b>跨集群中继。</b> 集群间用同一套帧协议，并留下覆盖证明。</li>
  <li><b>证据在边界产生。</b> 任务结果、步骤日志、产物、SHA-256 manifest、流量表与清理回执。</li>
  <li><b>规则可重放。</b> 准入、运行时、网络三类规则包，输出拦截 / 检出 / 漏过矩阵。</li>
  <li><b>报告与控制台。</b> 双语渗透与修复报告、SARIF / OCSF / VEX 导出、本地控制台。</li>
</ul>""",
)

section(
    "architecture", "Architecture", "架构",
    "One execution path", "一条执行路径",
    "Three planes, one probe tree", "三个平面，一棵探针树",
    en="""<p>The controller never executes target-side logic. It authorizes, renders templates, enforces budgets and archives evidence. The probe is the only code that runs inside the Pod.</p>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">execution path</span></div>
<pre><code>foothold ──▶ Rust probe ──▶ framed channel ──▶ in-pod task
                                              │
                                              ├─▶ child probe ──▶ child probe
                                              └─▶ evidence ──▶ report / rules / console</code></pre>
</div>
<h3>Three planes</h3>
<ul>
  <li><b>Template plane.</b> template.json declares inputs, payloads, steps, computed state, checks, findings and artifacts.</li>
  <li><b>Probe plane.</b> A static Rust binary speaks an HMAC-authenticated framed protocol and executes http, tcp, exec, fs, k8s, socks and spawn ops.</li>
  <li><b>Control plane.</b> Python enforces consent, scope, level, backup and audit, then folds probe evidence into findings.</li>
</ul>
<h3>Probe tree</h3>
<p>Every probe has a probe_id and a parent_id. Children inherit the parent's read-only state, command allow-list and budget, and can only be stricter. Cleanup is child-first, so no orphan keeps a token alive.</p>
<p class="note"><a href="ARCHITECTURE.md">ARCHITECTURE.md</a> · <a href="ARCHITECTURE-PROBE.md">ARCHITECTURE-PROBE.md</a> · <a href="PROBE-PROTOCOL.md">PROBE-PROTOCOL.md</a></p>""",
    zh="""<p>控制端不在目标侧执行任何逻辑。它负责授权、渲染模板、执行预算和归档证据。探针是 Pod 内唯一运行的代码。</p>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">执行路径</span></div>
<pre><code>立足 ──▶ Rust 探针 ──▶ 帧通道 ──▶ Pod 内任务
                                   │
                                   ├─▶ 子探针 ──▶ 子探针
                                   └─▶ 证据 ──▶ 报告 / 规则 / 控制台</code></pre>
</div>
<h3>三个平面</h3>
<ul>
  <li><b>模板面。</b> template.json 声明输入、载荷、步骤、computed 状态、检查项、发现与产物。</li>
  <li><b>探针面。</b> 静态 Rust 二进制使用 HMAC 认证的帧协议，执行 http、tcp、exec、fs、k8s、socks 与 spawn。</li>
  <li><b>控制面。</b> Python 执行授权、范围、级别、备份与审计闸门，并把探针证据折成发现。</li>
</ul>
<h3>探针树</h3>
<p>每颗探针都有 probe_id 与 parent_id。子探针继承父探针的只读状态、命令白名单与预算，且只能更严格。清理先子后父，避免留下仍持有 token 的孤儿。</p>
<p class="note"><a href="ARCHITECTURE.md">ARCHITECTURE.md</a> · <a href="ARCHITECTURE-PROBE.md">ARCHITECTURE-PROBE.md</a> · <a href="PROBE-PROTOCOL.md">PROBE-PROTOCOL.md</a></p>""",
)

section(
    "probe", "Rust probe", "Rust 探针",
    "Static Rust probe", "静态 Rust 探针",
    "One binary, 286 templates, no target-side interpreter", "一个二进制、286 个模板、目标侧无解释器",
    en="""<p>The probe is a single static musl binary for linux/amd64 and linux/arm64. Templates are JSON data; the target Pod needs no Python, shell, curl or other interpreter.</p>
""" + figures([("286", "templates"), ("2", "musl architectures"), ("12", "probe operations")]) + """
<h3>Probe operations</h3>
""" + table(
        [("Operation", ""), ("What it does", "")],
        [
            '<tr><td><code>collect</code></td><td>Host, Pod, process, network and Kubernetes context.</td></tr>',
            '<tr><td><code>exec</code></td><td>Run an allow-listed command with a bounded budget.</td></tr>',
            '<tr><td><code>audit-exec</code></td><td>Run a command with the audit trail and timing record.</td></tr>',
            '<tr><td><code>read-file</code></td><td>Read a file with size caps and a SHA-256 hash.</td></tr>',
            '<tr><td><code>list-files</code></td><td>List a directory tree with metadata.</td></tr>',
            '<tr><td><code>upload</code></td><td>Write a file through the authorized write gate.</td></tr>',
            '<tr><td><code>download</code></td><td>Stream a file back in chunks.</td></tr>',
            '<tr><td><code>spawn</code></td><td>Start a child probe with its own token and a stricter budget.</td></tr>',
            '<tr><td><code>dial</code></td><td>Open a TCP or UDP connection to an in-scope target.</td></tr>',
            '<tr><td><code>socks</code></td><td>Expose a loopback SOCKS5 listener for local tool compatibility.</td></tr>',
            '<tr><td><code>beacon</code></td><td>Send heartbeat and posture updates over the framed channel.</td></tr>',
            '<tr><td><code>cleanup</code></td><td>Remove artifacts and confirm the probe tree is empty.</td></tr>',
        ],
    ) + """
<p class="note">Every operation is budgeted, scoped and recorded in the evidence store; the probe tree cleans up child-first.</p>
<p class="note"><a href="ARCHITECTURE-PROBE.md">ARCHITECTURE-PROBE.md</a> · <a href="PROBE-PROTOCOL.md">PROBE-PROTOCOL.md</a> · <a href="PROBE-BUILD.md">PROBE-BUILD.md</a></p>""",
    zh="""<p>探针是 linux/amd64 与 linux/arm64 各一个静态 musl 二进制。模板是 JSON 数据；目标 Pod 不需要 Python、shell、curl 或其他解释器。</p>
""" + figures([("286", "模板"), ("2", "musl 架构"), ("12", "探针操作")]) + """
<h3>探针操作</h3>
""" + table(
        [("操作", ""), ("做什么", "")],
        [
            '<tr><td><code>collect</code></td><td>采集主机、Pod、进程、网络与 Kubernetes 上下文。</td></tr>',
            '<tr><td><code>exec</code></td><td>在预算内执行白名单命令。</td></tr>',
            '<tr><td><code>audit-exec</code></td><td>执行命令并留下审计轨迹与时序记录。</td></tr>',
            '<tr><td><code>read-file</code></td><td>读取文件，带大小上限与 SHA-256 哈希。</td></tr>',
            '<tr><td><code>list-files</code></td><td>列出目录树与元数据。</td></tr>',
            '<tr><td><code>upload</code></td><td>经授权写闸门写入文件。</td></tr>',
            '<tr><td><code>download</code></td><td>分块流式回传文件。</td></tr>',
            '<tr><td><code>spawn</code></td><td>启动子探针，独立 token、更严格预算。</td></tr>',
            '<tr><td><code>dial</code></td><td>向范围内目标建立 TCP 或 UDP 连接。</td></tr>',
            '<tr><td><code>socks</code></td><td>暴露回环 SOCKS5 监听，兼容本地工具。</td></tr>',
            '<tr><td><code>beacon</code></td><td>经帧通道发送心跳与姿态更新。</td></tr>',
            '<tr><td><code>cleanup</code></td><td>移除产物并确认探针树已清空。</td></tr>',
        ],
    ) + """
<p class="note">每个操作都受预算与范围约束，并写入证据库；探针树先子后父清理。</p>
<p class="note"><a href="ARCHITECTURE-PROBE.md">ARCHITECTURE-PROBE.md</a> · <a href="PROBE-PROTOCOL.md">PROBE-PROTOCOL.md</a> · <a href="PROBE-BUILD.md">PROBE-BUILD.md</a></p>""",
)

section(
    "protocols", "Protocols", "协议支持",
    "Proxy protocol support", "代理协议支持",
    "Reverse transports and ML service proxies", "回连传输与 ML 服务代理",
    en="""<p>The reverse channel and the ML proxies are separate layers: the channel carries frames between controller and probe, the proxies carry a service protocol between the probe and an in-scope target.</p>
""" + table(
        [("Layer", ""), ("Supported", "")],
        [
            '<tr><td>Reverse channel</td><td>TLS · WSS · HTTPS · QUIC · WebTransport (experimental) · MASQUE</td></tr>',
            '<tr><td>ML service proxy</td><td>gRPC · Redis · TCPStore · NCCL · UCX · ZMTP (experimental)</td></tr>',
            '<tr><td>SOCKS5</td><td>Loopback compatibility only (<code>127.0.0.1</code>)</td></tr>',
        ],
    ) + """
<h3>Authentication and encryption</h3>
<ul>
  <li>Every framed message carries a token and an HMAC; a wrong token or MAC closes the channel.</li>
  <li>TLS, WSS, HTTPS, QUIC and WebTransport validate the controller certificate against a pinned SHA-256 fingerprint and an optional CA file.</li>
  <li>gRPC, Redis, TCPStore, NCCL and UCX proxies are TLS-wrapped; ZMTP uses CURVE with Z85 keys when enabled.</li>
  <li>SOCKS5 stays on loopback and is a compatibility path for local tooling, not a network-wide proxy.</li>
</ul>
<p class="note"><a href="PROBE-CHANNEL.md">PROBE-CHANNEL.md</a> · <a href="PROBE-PROTOCOL.md">PROBE-PROTOCOL.md</a> · <a href="USAGE.md">USAGE.md</a></p>""",
    zh="""<p>回连通道与 ML 代理是两层：通道在控制端与探针之间承载帧，代理在探针与范围内目标之间承载服务协议。</p>
""" + table(
        [("层", ""), ("支持", "")],
        [
            '<tr><td>回连通道</td><td>TLS · WSS · HTTPS · QUIC · WebTransport（experimental）· MASQUE</td></tr>',
            '<tr><td>ML 服务代理</td><td>gRPC · Redis · TCPStore · NCCL · UCX · ZMTP（experimental）</td></tr>',
            '<tr><td>SOCKS5</td><td>仅回环兼容（<code>127.0.0.1</code>）</td></tr>',
        ],
    ) + """
<h3>认证与加密</h3>
<ul>
  <li>每个帧都带 token 与 HMAC；token 或 MAC 不对即断开。</li>
  <li>TLS、WSS、HTTPS、QUIC 与 WebTransport 用 SHA-256 pin 校验控制端证书，可选 CA 文件。</li>
  <li>gRPC、Redis、TCPStore、NCCL 与 UCX 代理走 TLS；ZMTP 启用时使用 CURVE 与 Z85 密钥。</li>
  <li>SOCKS5 只留在回环，是本地工具的兼容路径，不是全网代理。</li>
</ul>
<p class="note"><a href="PROBE-CHANNEL.md">PROBE-CHANNEL.md</a> · <a href="PROBE-PROTOCOL.md">PROBE-PROTOCOL.md</a> · <a href="USAGE.md">USAGE.md</a></p>""",
)

section(
    "reserve", "Vulnerability research", "漏洞研究",
    "Vulnerability research", "漏洞研究",
    "The research behind the template catalogue", "模板目录背后的漏洞研究",
    en="""<p>The catalogue is backed by 184 vulnerability write-ups, each recording the component, affected versions, root cause, impact and detection. 68 have runnable PoCs. The research queue contains 169 zero-day candidates: 47 were reviewed and confirmed novel, 46 are ready for coordinated disclosure, and 39 are distinct exploit primitives. A 103-record affected-version matrix and 121 detection rules feed 29 attack chains. The public ledger lists component, class, affected versions and disclosure status; exploit details stay private.</p>
<p class="note"><a href="0DAY-PUBLIC.md">0DAY-PUBLIC.md</a> · <a href="VULNERABILITY-LAYERS.md">VULNERABILITY-LAYERS.md</a> · <a href="DETECTION-LAYERS.md">DETECTION-LAYERS.md</a></p>""",
    zh="""<p>模板目录背后有 184 条漏洞记录，每条写清组件、受影响版本、根因、影响与检测方式；其中 68 条有可运行 PoC。研究队列包含 169 个零日候选，47 个经查新确认新颖，46 个可进入协调披露，39 个是独立的利用原语。103 条受影响版本记录与 121 条检测规则支撑 29 条攻击链。公开台账只列组件、类别、受影响版本与披露状态，利用细节不公开。</p>
<p class="note"><a href="0DAY-PUBLIC.md">0DAY-PUBLIC.md</a> · <a href="VULNERABILITY-LAYERS.md">VULNERABILITY-LAYERS.md</a> · <a href="DETECTION-LAYERS.md">DETECTION-LAYERS.md</a></p>""",
)

section(
    "workflow", "Workflow", "工作流",
    "From foothold to report", "从立足到报告",
    "Nine stages, each leaves something the next can check", "九个阶段，每步都留下下一步能校验的东西",
    en="""<p>The order is the product. Any stage can refuse; a refusal stops the run.</p>
""" + workflow_flow("en") + """
<h3>Gate behaviour</h3>
""" + table(
        [("Gate", ""), ("Refuses when", ""), ("Signal", "num")],
        [
            '<tr><td>Consent</td><td>No record, expired window, out-of-scope asset.</td><td class="num">exit 91</td></tr>',
            '<tr><td>Level</td><td>Template level above the record.</td><td class="num">exit 91</td></tr>',
            '<tr><td>Backup</td><td>Write step without a backup target.</td><td class="num">exit 91</td></tr>',
            '<tr><td>Scope</td><td>Target or namespace outside the session.</td><td class="num">refused</td></tr>',
            '<tr><td>Rollback</td><td>A step cannot be restored.</td><td class="num">exit 3</td></tr>',
        ],
    ) + """
<p class="note"><a href="WORKFLOW.md">Stage reference</a></p>""",
    zh="""<p>顺序就是产品。任何阶段都可以拒绝；拒绝就地停下。</p>
""" + workflow_flow("zh") + """
<h3>闸门行为</h3>
""" + table(
        [("闸门", ""), ("拒绝条件", ""), ("信号", "num")],
        [
            '<tr><td>授权</td><td>没记录、窗口过期、资产越界。</td><td class="num">exit 91</td></tr>',
            '<tr><td>级别</td><td>模板级别高于记录。</td><td class="num">exit 91</td></tr>',
            '<tr><td>备份</td><td>写步骤没有备份目标。</td><td class="num">exit 91</td></tr>',
            '<tr><td>范围</td><td>目标或命名空间不在会话内。</td><td class="num">拒绝</td></tr>',
            '<tr><td>回滚</td><td>有步骤无法恢复。</td><td class="num">exit 3</td></tr>',
        ],
    ) + """
<p class="note"><a href="WORKFLOW.md">逐阶段参考</a></p>""",
)

section(
    "quickstart", "Quick start", "快速开始",
    "Probe-first onboarding", "探针优先接入",
    "Install, attach, deliver, run, report", "安装、接入、投放、运行、报告",
    en="""<p>Start from the console and attach the probe or foothold you already hold. The default foothold is a least-privilege Pod: non-root, no hostPath or privileged mode, no kubeconfig, outbound TCP only.</p>
<ol class="steps">
  <li><b>python -m pip install -e .</b><span>Install the controller. Python 3.10 – 3.13, no compiler.</span></li>
  <li><b>python -m inkblade up</b><span>Start the console, sign in, sign the authorization record.</span></li>
  <li><b>python -m inkblade probe list</b><span>Attach an existing probe; the controller listens and the probe connects back.</span></li>
  <li><b>python -m inkblade session open --mode foothold ...</b><span>First delivery from the shell, SA token or RCE you already hold.</span></li>
  <li><b>python -m inkblade agent run --probe &lt;probe-id&gt; ...</b><span>Run detection through the probe channel, then report.</span></li>
</ol>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">terminal · probe-first</span></div>
<pre><code><span class="p">$</span> python -m inkblade up
<span class="p">$</span> python -m inkblade quickstart
<span class="p">$</span> python -m inkblade probe list
<span class="p">$</span> python -m inkblade channel listen
<span class="p">$</span> python -m inkblade session open --mode foothold --target &lt;target&gt; \
    --credential-source pod-shell --namespace &lt;namespace&gt; --pod &lt;pod&gt;
<span class="p">$</span> python -m inkblade probe deploy --session &lt;session-id&gt; --via rce \
    --binary ./inkblade-probe-linux-amd64 --probe-token-file ./probe.token --allow-write
<span class="p">$</span> inkblade-probe reverse --host &lt;controller&gt; --port &lt;port&gt;
<span class="p">$</span> python -m inkblade agent run --probe &lt;probe-id&gt; --objective read-only-recon --workspace ./work
<span class="p">$</span> python -m inkblade report --run &lt;run-id&gt; --lang bi</code></pre>
</div>
<p class="note">Child probes are delivered from the parent with probe upload + probe spawn and call back the same way. A stdio channel (channel start) is available when a local command transport exists. A kubeconfig is optional, only for a first batch bootstrap of several Pods. The documentation site is local: python -m inkblade docs serves docs/ on 127.0.0.1:8766 and opens the browser; --no-browser keeps it headless.</p>
<p class="note"><a href="QUICKSTART.md">Quick start</a> · <a href="INSTALL.md">Install</a> · <a href="USAGE.md">Usage</a></p>""",
    zh="""<p>从控制台开始，接入你已有的探针或立足点。默认立足点是普通、最低权限的 Pod：非 root、无 hostPath/privileged、无 kubeconfig，只有出站 TCP。</p>
<ol class="steps">
  <li><b>python -m pip install -e .</b><span>安装控制端。Python 3.10 – 3.13，不需要编译器。</span></li>
  <li><b>python -m inkblade up</b><span>启动控制台、浏览器登录、签授权记录。</span></li>
  <li><b>python -m inkblade probe list</b><span>接入已有探针；控制端监听，探针主动回连。</span></li>
  <li><b>python -m inkblade session open --mode foothold ...</b><span>用已有 shell、SA token 或 RCE 完成首次投放。</span></li>
  <li><b>python -m inkblade agent run --probe &lt;probe-id&gt; ...</b><span>通过探针通道执行检测，再出报告。</span></li>
</ol>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">终端 · 探针优先</span></div>
<pre><code><span class="p">$</span> python -m inkblade up
<span class="p">$</span> python -m inkblade quickstart
<span class="p">$</span> python -m inkblade probe list
<span class="p">$</span> python -m inkblade channel listen
<span class="p">$</span> python -m inkblade session open --mode foothold --target &lt;target&gt; \
    --credential-source pod-shell --namespace &lt;namespace&gt; --pod &lt;pod&gt;
<span class="p">$</span> python -m inkblade probe deploy --session &lt;session-id&gt; --via rce \
    --binary ./inkblade-probe-linux-amd64 --probe-token-file ./probe.token --allow-write
<span class="p">$</span> inkblade-probe reverse --host &lt;controller&gt; --port &lt;port&gt;
<span class="p">$</span> python -m inkblade agent run --probe &lt;probe-id&gt; --objective read-only-recon --workspace ./work
<span class="p">$</span> python -m inkblade report --run &lt;run-id&gt; --lang bi</code></pre>
</div>
<p class="note">子探针由父探针用 probe upload + probe spawn 投放，并以同样方式回连。存在本地命令通道时可用 stdio 通道（channel start）。kubeconfig 是可选的，只用于首次批量 bootstrap。文档站点在本地：python -m inkblade docs 在 127.0.0.1:8766 服务 docs/ 并打开浏览器；--no-browser 不打开浏览器。</p>
<p class="note"><a href="QUICKSTART.md">快速开始</a> · <a href="INSTALL.md">安装</a> · <a href="USAGE.md">使用</a></p>""",
)

section(
    "commands", "Commands", "命令",
    "Command map", "命令表",
    "The surface you actually type", "实际输入的命令面",
    en="""<p>Every command below runs offline except the ones that talk to a cluster through a session or probe.</p>
""" + command_table("en") + """
<p class="note"><a href="USAGE.md">Full usage reference</a></p>""",
    zh="""<p>除经会话或探针访问集群的命令外，下列命令都可离线运行。</p>
""" + command_table("zh") + """
<p class="note"><a href="USAGE.md">完整使用手册</a></p>""",
)

section(
    "deploy", "Deployment", "部署",
    "Wheel, container, Helm", "Wheel、容器、Helm",
    "One controller, any of three delivery paths", "一个控制端，三种交付方式",
    en="""<p>The controller is a Python package with no third-party dependency. The probe is a separate static binary.</p>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">wheel</span></div>
<pre><code>python -m pip wheel . --no-deps -w dist/
python -m pip install --no-index --find-links dist/ inkblade</code></pre>
</div>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">container</span></div>
<pre><code>docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 up</code></pre>
</div>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">helm · read-only by default</span></div>
<pre><code>helm install inkblade deploy/helm/inkblade \
  --namespace inkblade --create-namespace</code></pre>
</div>
<p class="note">uid 10001, read-only root, a PVC for evidence. Read verbs by default; writes need readOnly=false, rbac.allowWrite=true and a signed record. Uninstall keeps the PVC.</p>
<p class="note"><a href="INSTALL.md">Install guide</a> · <a href="PROBE-DEPLOY.md">Probe delivery</a></p>""",
    zh="""<p>控制端是一个无第三方依赖的 Python 包；探针是独立的静态二进制。</p>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">wheel</span></div>
<pre><code>python -m pip wheel . --no-deps -w dist/
python -m pip install --no-index --find-links dist/ inkblade</code></pre>
</div>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">容器</span></div>
<pre><code>docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 up</code></pre>
</div>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">helm · 默认只读</span></div>
<pre><code>helm install inkblade deploy/helm/inkblade \
  --namespace inkblade --create-namespace</code></pre>
</div>
<p class="note">uid 10001、根只读、证据落在 PVC。默认只给读动词；写操作要 readOnly=false、rbac.allowWrite=true 与签署记录。卸载保留 PVC。</p>
<p class="note"><a href="INSTALL.md">安装指南</a> · <a href="PROBE-DEPLOY.md">探针投放</a></p>""",
)

section(
    "security", "Security", "安全与授权",
    "Security and authorization", "安全与授权",
    "Authorization is a prerequisite, not a feature toggle", "授权是使用前提，不是功能开关",
    en="""<p>InkBlade refuses to run without a signed record. Every stage keeps its own gate.</p>
<ol class="steps">
  <li><b>RoE record</b><span>Target, scope, level, window and emergency contact. Hash-pinned and carried by every run.</span></li>
  <li><b>Read-only default</b><span>Collection, probes, file reads and read-only templates need no extra flag.</span></li>
  <li><b>Five write gates</b><span>Session level, --allow-write, meta.writes, backup-write mode, backup receipt.</span></li>
  <li><b>Backup and rollback</b><span>Snapshot before the write, record both, restore one step at a time.</span></li>
  <li><b>Audit and evidence</b><span>Every probe action and file access lands in the evidence store with a SHA-256 manifest.</span></li>
  <li><b>Kill switch</b><span>inkblade abort stops the workspace; agent stop stops one run.</span></li>
</ol>
""" + table(
        [("Control", ""), ("What it guarantees", "")],
        [
            '<tr><td>Consent hash</td><td>The authority for a run is one file, not a meeting.</td></tr>',
            '<tr><td>Scope and level</td><td>Out-of-scope or above-level actions are refused before execution.</td></tr>',
            '<tr><td>Backup receipt</td><td>No write without a restorable snapshot.</td></tr>',
            '<tr><td>Evidence manifest</td><td>Every finding resolves to a task, step, artifact, probe or manifest hash.</td></tr>',
        ],
    ) + """
<div class="cut warn">
  <p><strong>Authorized use only.</strong> Written authorization or nothing. Testing systems you do not own is a crime in most jurisdictions. The software refuses without a signed record.</p>
  <p>Report security issues through the private channel in <code>SECURITY.md</code>. Do not open a public issue with exploit detail.</p>
</div>""",
    zh="""<p>没有签署记录，InkBlade 拒绝运行。每个阶段都有自己的闸门。</p>
<ol class="steps">
  <li><b>RoE 记录</b><span>目标、范围、级别、时间窗与应急联系人；哈希钉存，跟着每次 run 走。</span></li>
  <li><b>默认只读</b><span>采集、探测、读文件与只读模板不需要额外开关。</span></li>
  <li><b>五道写闸门</b><span>会话级别、--allow-write、meta.writes、backup-write 模式、备份回执。</span></li>
  <li><b>备份与回滚</b><span>写前快照，两者都记录，逐步恢复。</span></li>
  <li><b>审计与证据</b><span>每次探针动作与文件访问进入证据库，带 SHA-256 manifest。</span></li>
  <li><b>急停</b><span>inkblade abort 停工作区；agent stop 停单个 run。</span></li>
</ol>
""" + table(
        [("控制", ""), ("保证什么", "")],
        [
            '<tr><td>授权哈希</td><td>一次 run 的授权是一个文件，不是一场会。</td></tr>',
            '<tr><td>范围与级别</td><td>越界或超级别的动作在执行前拒绝。</td></tr>',
            '<tr><td>备份回执</td><td>没有可恢复快照就没有写操作。</td></tr>',
            '<tr><td>证据 manifest</td><td>每条发现都能落到 task、step、artifact、probe 或 manifest 哈希。</td></tr>',
        ],
    ) + """
<div class="cut warn">
  <p><strong>仅限授权使用。</strong>没有书面授权就不做。对不归你所有的系统动手，在多数司法辖区属于违法。没有签署记录，软件会拒绝。</p>
  <p>安全问题走 <code>SECURITY.md</code> 的私密渠道；公开 issue 不要贴利用细节。</p>
</div>""",
)

section(
    "faq", "FAQ", "常见问题",
    "FAQ", "常见问题",
    "Access, probe, detection, authorization, delivery", "接入、探针、检测、授权、交付",
    en=faq_block("en") + """
<p class="note">More: <a href="FAQ.md">FAQ.md</a></p>""",
    zh=faq_block("zh") + """
<p class="note">更多：<a href="FAQ.md">FAQ.md</a></p>""",
)

section(
    "license", "License", "许可",
    "License", "许可",
    "Apache-2.0, repository policies", "Apache-2.0、仓库政策",
    en="""<p>Apache-2.0. Commercial use, forks and embedding are permitted; keep the notices.</p>
""" + table(
        [("Item", ""), ("Details", "")],
        [
            '<tr><td>License</td><td><strong>Apache-2.0</strong>. Keep <code>LICENSE</code> and <code>NOTICE</code>.</td></tr>',
            '<tr><td>Trademark</td><td>Do not name a fork InkBlade.</td></tr>',
            '<tr><td>Policies</td><td><code>SECURITY.md</code>, <code>CONTRIBUTING.md</code>, <code>CODE_OF_CONDUCT.md</code>.</td></tr>',
        ],
    ) + """
<p class="note">Documentation index: <a href="DOC-INDEX.md">DOC-INDEX.md</a></p>""",
    zh="""<p>Apache-2.0。允许商用、fork 与嵌入服务；保留声明。</p>
""" + table(
        [("项目", ""), ("说明", "")],
        [
            '<tr><td>许可证</td><td><strong>Apache-2.0</strong>。保留 <code>LICENSE</code> 与 <code>NOTICE</code>。</td></tr>',
            '<tr><td>商标</td><td>fork 不要使用 InkBlade 名称。</td></tr>',
            '<tr><td>政策</td><td><code>SECURITY.md</code>、<code>CONTRIBUTING.md</code>、<code>CODE_OF_CONDUCT.md</code>。</td></tr>',
        ],
    ) + """
<p class="note">文档索引：<a href="DOC-INDEX.md">DOC-INDEX.md</a></p>""",
)

# --------------------------------------------------------------------------
# markdown ledger (generated from the same rows)
# --------------------------------------------------------------------------


def render_markdown_ledger() -> str:
    en_rows = "\n".join(
        f"| `{c}` | {cls_en} | {versions} | Reported | {DISCLOSURE_START} → {DISCLOSURE_TARGET} |"
        for c, cls_en, cls_zh, versions in ZERO_ROWS
    )
    zh_rows = "\n".join(
        f"| `{c}` | {cls_zh} | {versions} | 已上报 | {DISCLOSURE_START} → {DISCLOSURE_TARGET}（90 天） |"
        for c, cls_en, cls_zh, versions in ZERO_ROWS
    )
    return f"""<!-- generated by scripts/build-docs-site.py — edit the generator, not this file -->
# 0Day reserve — public ledger / 0day 储备公开台账

**Version {VERSION} · last generated 2026-10-27**

## English

### How an entry gets counted

One rule, applied without exceptions: an entry enters the reserve only when dynamic reproduction succeeded *and* the
novelty check returned “confirmed unpublished”. A finding that turns out to be public later is downgraded, and the
downgrade is recorded. The same sink is not counted twice.

| Inventory | Dynamically verified | Confirmed unpublished | Reserve rows | Unique primitives | Components | Inconclusive |
|---:|---:|---:|---:|---:|---:|---:|
| 169 | 60 | 47 | 46 | 39 | 21 | 0 |

The table below lists the 39 unique primitives. It is deliberately limited to component, class, affected versions,
status and the disclosure window. It does **not** contain runnable code, exploit steps, request bodies or
root-cause locations.

### Reserve list

| Component | Class | Affected versions | Status | Disclosure window |
|---|---|---|---|---|
{en_rows}

### Disclosure

Vendors were notified through the coordinated-disclosure process. Exploit details stay private until the fix window
closes and are then published with the advisory.

- Policy: vendor first; 90-day window; national CERT only if the vendor does not respond.
- Prepared: 30 CVE-ready packages and 6 hardening-only notes. Advisory text is not public until the window closes.
- Dates above are targets. A vendor that asks for more time gets it, in writing, and the table is updated.
- Status values: `Reported` = vendor notified; `Advisory` = published after the window.

### What is withheld, and why

A version string and a class are enough for a defender to check exposure. An exploit is not. Withholding the second
while publishing the first is the whole point of coordinated disclosure: defenders can act, attackers get no head
start.

---

## 中文

### 计数规则

只有一条，没有例外：动态复现成功、且查新结论为“确认未公开”的条目才能进入储备。事后发现已公开的，降级并留痕。
同一个 sink 不重复计数。

| 库存 | 动态验证 | 确认未公开 | 储备行 | 独立原语 | 组件 | 存疑 |
|---:|---:|---:|---:|---:|---:|---:|
| 169 | 60 | 47 | 46 | 39 | 21 | 0 |

下表列出 39 条独立原语，只包含组件、类别、受影响版本、状态与披露窗口。**不包含** 可执行代码、利用步骤、请求内容或根因位置。

### 储备清单

| 组件 | 漏洞类别 | 受影响版本 | 状态 | 披露时间线 |
|---|---|---|---|---|
{zh_rows}

### 披露说明

已按协调披露流程通知厂商。利用细节在修复窗口结束前保持非公开，窗口结束后随 advisory 一并发布。

- 政策：厂商优先；90 天窗口；厂商不回应才转国家级 CERT。
- 已准备：30 份 CVE 就绪包、6 份加固建议。窗口结束前 advisory 正文不公开。
- 表中的日期是目标值。厂商书面申请延期会给，并同步更新表格。
- 状态取值：`已上报` = 已通知厂商；`Advisory` = 窗口结束后已发布。

### 为什么不公开细节

版本号加类别，足够防守方判断暴露面；利用代码不够。公开前者、扣住后者，正是协调披露的意义：防守方可以行动，
攻击者拿不到先手。
"""


# --------------------------------------------------------------------------
# shell
# --------------------------------------------------------------------------

CRITICAL_CSS = """
:root{--bg:#0a0b0d;--panel:#111318;--line:#1e2229;--text:#d7dbe0;--dim:#98a1ab;--cyan:#59d3c8;--orange:#e0733d;
--serif:ui-serif,"Iowan Old Style","Palatino Linotype",Georgia,serif;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.72 system-ui,-apple-system,"Segoe UI",Roboto,"PingFang SC",sans-serif}
.wrap{width:min(100% - 48px,1180px);margin-inline:auto}
h1,h2{font-family:var(--serif);font-weight:500;letter-spacing:-.02em}
a{color:var(--cyan);text-decoration:none;border-bottom:1px solid rgba(89,211,200,.28)}
code,pre{font-family:var(--mono)}
pre{background:#060708;border:1px solid #262b34;padding:15px 16px;overflow:auto;color:#cfd6dc}
""".strip()

BOOTSTRAP = """
(function () {
  try {
    var m = location.search.match(/[?&]lang=(en|zh)\\b/);
    var s = null;
    try { s = localStorage.getItem("inkblade.lang"); } catch (e) {}
    var nav = (navigator.languages && navigator.languages[0]) || navigator.language || "en";
    var pick = (m && m[1]) || s || (String(nav).toLowerCase().indexOf("zh") === 0 ? "zh" : "en");
    document.documentElement.setAttribute("data-lang", pick);
    document.documentElement.setAttribute("lang", pick === "zh" ? "zh-Hans" : "en");
  } catch (e) {}
})();
""".strip()

LOGO = (
    '<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" focusable="false" '
    'style="vertical-align:-2px"><path d="M3 1.6c4 .6 6.6 3.2 6.6 6.4 0 2.6-1.6 4.6-4.4 5.6 3.4-.6 5.8-3 5.8-6.3 '
    '0-2.6-1.6-4.6-4.4-5.6 2.9 1 4.6 3.2 4.6 5.9 0 3.6-2.6 6.2-6.2 6.7Z" fill="#59d3c8"/>'
    '<path d="M2.4 14.6 12.6 3" stroke="#d7dbe0" stroke-width="1" stroke-linecap="round"/></svg>'
)

HERO = {
    "en": {
        "kicker": "Training &amp; inference infrastructure",
        "positioning": "Training &amp; Inference Cluster Penetration Testing Platform",
        "docstate": "Product documentation <i>/</i> 2026-10",
        "lead": "A static Rust probe inside the authorized Pod, ten detection layers, bilingual reports, replayable rules and a local console. The controller never ships code into the cluster.",
        "links": [("Install", "INSTALL.md"), ("Usage", "USAGE.md"), ("Architecture", "ARCHITECTURE.md")],
        "spec": [
            ("license", "Apache-2.0"), ("controller", "Python 3.10 – 3.13"),
            ("target", "static Rust probe"), ("modules", "286"), ("chains", "29"),
            ("posture", "read-only by default"),
        ],
        "spec_note": "Authorized testing only. Scope, level and time window come from the signed record.",
    },
    "zh": {
        "kicker": "训练与推理基础设施",
        "positioning": "训练与推理集群渗透测试平台",
        "docstate": "产品文档 <i>/</i> 2026-10",
        "lead": "把静态 Rust 探针放进已授权的 Pod，覆盖十层检测，产出双语报告、可重放规则与本地控制台。控制端不向集群下发代码。",
        "links": [("安装", "INSTALL.md"), ("使用", "USAGE.md"), ("架构", "ARCHITECTURE.md")],
        "spec": [
            ("许可证", "Apache-2.0"), ("控制端", "Python 3.10 – 3.13"),
            ("目标端", "静态 Rust 探针"), ("模板", "286"), ("链", "29"),
        ],
        "spec_note": "仅限授权测试。范围、级别与时间窗来自签署记录。",
    },
}

FOOT = {
    "en": {
        "blurb": "Product documentation for InkBlade. Plain HTML and two local assets; no fonts, scripts or styles are fetched from anywhere.",
        "cols": [
            ("Guides", [("Usage", "USAGE.md"), ("Features", "FEATURES.md"), ("Workflow", "WORKFLOW.md"), ("Install", "INSTALL.md")]),
            ("Reference", [("Product", "PRODUCT.md"), ("Detection layers", "DETECTION-LAYERS.md"), ("FAQ", "FAQ.md"), ("Doc index", "DOC-INDEX.md")]),
            ("Project", [("Capabilities", "#capabilities"), ("Security", "#security"), ("License", "#license")]),
        ],
        "bar": ["InkBlade", "Apache-2.0", "Authorized testing only"],
    },
    "zh": {
        "blurb": "InkBlade 产品文档。纯 HTML 加两个本地资源；不从任何地方加载字体、脚本或样式。",
        "cols": [
            ("指南", [("使用", "USAGE.md"), ("特性", "FEATURES.md"), ("流程", "WORKFLOW.md"), ("安装", "INSTALL.md")]),
            ("参考", [("产品定义", "PRODUCT.md"), ("检测分层", "DETECTION-LAYERS.md"), ("常见问题", "FAQ.md"), ("文档索引", "DOC-INDEX.md")]),
            ("项目", [("核心能力", "#capabilities"), ("安全与授权", "#security"), ("许可", "#license")]),
        ],
        "bar": ["InkBlade", "Apache-2.0", "仅限授权测试"],
    },
}


def render_lang_switch(mode: str) -> str:
    if mode == "dual":
        return (
            '<div class="lang" role="group" aria-label="Language">'
            '<button type="button" data-set-lang="en" aria-pressed="true">EN</button>'
            '<button type="button" data-set-lang="zh" aria-pressed="false">中文</button></div>'
        )
    if mode == "zh":
        return (
            '<div class="lang" aria-label="Language">'
            '<a href="../en/index.html" hreflang="en" lang="en">EN</a>'
            '<a href="../zh/index.html" hreflang="zh-Hans" aria-current="page">中文</a></div>'
        )
    return (
        '<div class="lang" aria-label="Language">'
        '<a href="../en/index.html" hreflang="en" aria-current="page">EN</a>'
        '<a href="../zh/index.html" hreflang="zh-Hans" lang="zh-Hans">中文</a></div>'
    )


def render_hero(mode: str, langs: list[str]) -> str:
    blocks = []
    for lang in langs:
        h = HERO[lang]
        prefix = "../" if mode != "dual" else ""
        parts = []
        for i, (label, target) in enumerate(h["links"]):
            cls = ' class="primary"' if i == 0 else ""
            parts.append(f'<a{cls} href="{prefix + target}">{label}</a>')
        links = "".join(parts)
        spec_rows = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in h["spec"])
        blocks.append(f"""
<div class="lang-block" data-lang="{lang}">
  <div class="hero-grid">
    <div>
      <p class="kicker">{h["kicker"]}</p>
      <h1>InkBlade<span class="stroke">墨刃零</span></h1>
      <p class="positioning">{h["positioning"]}</p>
      <p class="docstate">{h["docstate"]}</p>
      <nav class="quick" aria-label="Quick links">{links}</nav>
      <p class="lead-note note" style="margin-top:18px;max-width:44ch">{h["lead"]}</p>
    </div>
    <aside class="spec">
      <h2>build sheet</h2>
      <dl>{spec_rows}</dl>
      <div class="rule"></div>
      <p>{h["spec_note"]}</p>
    </aside>
  </div>
</div>""")
    return f'<section class="hero"><div class="wrap">{"".join(blocks)}</div></section>'


def render_top_links(mode: str, langs: list[str]) -> str:
    out = ""
    for lang in langs:
        h = HERO[lang]
        prefix = "../" if mode != "dual" else ""
        inner = ""
        for label, target in [(x[0], x[1]) for x in h["links"]]:
            cls = ' class="dl"' if target.startswith("INSTALL") else ""
            inner += f'<a{cls} href="{prefix + target}">{label}</a>'
        if mode == "dual":
            inner = f'<div class="lang-block" data-lang="{lang}" style="display:contents">{inner}</div>'
        out += inner
    return f'<nav class="top-links" aria-label="Quick links">{out}</nav>'


def render_sections(mode: str, langs: list[str]) -> str:
    prefix = "../" if mode != "dual" else ""

    def rebase(markup: str) -> str:
        if not prefix:
            return markup

        def repl(match: re.Match) -> str:
            target = match.group(2)
            if target.startswith(("#", "../")) or re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", target):
                return match.group(0)
            return f'{match.group(1)}{prefix}{target}"'

        return re.sub(r'(href=")([^"]+)"', repl, markup)

    out = []
    for index, s in enumerate(SECTIONS, 1):
        heads = "".join(
            f'<div class="lang-block" data-lang="{lang}"><div class="sec-head">'
            f'<span class="sec-no">{index:02d}</span><h2>{s["title"][lang]}</h2>'
            f'<p class="sub">{s["sub"][lang]}</p></div>{rebase(s["body"][lang])}</div>'
            for lang in langs
        )
        out.append(f'<section class="sec" id="{s["id"]}">{heads}</section>')
    return "\n".join(out)


def render_rail(langs: list[str]) -> str:
    blocks = []
    for lang in langs:
        items = "".join(f'<li><a href="#{s["id"]}">{s["nav"][lang]}</a></li>' for s in SECTIONS)
        label = "Contents" if lang == "en" else "目录"
        note = "Generated from docs/ at build time." if lang == "en" else "构建时从 docs/ 生成。"
        blocks.append(
            f'<div class="lang-block" data-lang="{lang}"><p>{label}</p><ol>{items}</ol>'
            f'<p class="railnote">{note}</p></div>'
        )
    return f'<nav class="rail" aria-label="Contents">{"".join(blocks)}</nav>'


def render_jump(langs: list[str]) -> str:
    blocks = []
    for lang in langs:
        items = "".join(f'<a href="#{s["id"]}">{s["nav"][lang]}</a>' for s in SECTIONS)
        blocks.append(f'<div class="lang-block" data-lang="{lang}" style="display:contents">{items}</div>')
    return f'<nav class="jump" aria-label="Contents">{"".join(blocks)}</nav>'


def render_footer(mode: str, langs: list[str]) -> str:
    prefix = "../" if mode != "dual" else ""
    blocks = []
    for lang in langs:
        f = FOOT[lang]
        cols = ""
        for title, links in f["cols"]:
            items = "".join(
                f'<li><a href="{target if target.startswith("#") else prefix + target}">{label}</a></li>'
                for label, target in links
            )
            cols += f"<div><h4>{title}</h4><ul>{items}</ul></div>"
        bar = "".join(f"<span>{x}</span>" for x in f["bar"])
        blocks.append(
            f'<div class="lang-block" data-lang="{lang}"><div class="foot-grid">'
            f'<div><p>{f["blurb"]}</p><p class="note">© <span data-year>2026</span> The InkBlade Authors</p></div>'
            f'{cols}</div><div class="foot-bar">{bar}</div></div>'
        )
    return f'<footer class="foot"><div class="wrap">{"".join(blocks)}</div></footer>'


def render_page(*, mode: str, langs: list[str], title: str, description: str) -> str:
    css = ("../" if mode != "dual" else "") + "assets/style.css"
    js = ("../" if mode != "dual" else "") + "assets/app.js"
    home = "../" if mode != "dual" else "./"
    html_lang = "zh-Hans" if mode == "zh" else "en"
    data_lang = "zh" if mode == "zh" else "en"
    alternates = ""
    if mode == "dual":
        alternates = (
            '<link rel="alternate" hreflang="en" href="en/index.html">'
            '<link rel="alternate" hreflang="zh-Hans" href="zh/index.html">'
        )
    return f"""<!doctype html>
<html lang="{html_lang}" data-lang="{data_lang}"
      data-title-en="InkBlade — Training &amp; Inference Cluster Penetration Testing Platform"
      data-title-zh="InkBlade（墨刃零）— 训练与推理集群渗透测试平台">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<meta name="color-scheme" content="dark">
<meta name="robots" content="index,follow">
<meta name="generator" content="scripts/build-docs-site.py">
{alternates}<link rel="stylesheet" href="{css}">
<style>{CRITICAL_CSS}</style>
<script>{BOOTSTRAP}</script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
  <div class="wrap topbar-in">
    <a class="brand" href="{home}"><span class="tick">//</span>{LOGO}<span>InkBlade</span><span class="cn" lang="zh-Hans">墨刃零</span></a>
    {render_top_links(mode, langs)}
    {render_lang_switch(mode)}
  </div>
</header>
<main id="main">
{render_hero(mode, langs)}
<div class="wrap shell">
{render_rail(langs)}
<div class="content">
{render_jump(langs)}
{render_sections(mode, langs)}
</div>
</div>
</main>
{render_footer(mode, langs)}
<script src="{js}" defer></script>
</body>
</html>
"""


PAGES = {
    DOCS / "index.html": dict(
        mode="dual", langs=["en", "zh"],
        title="InkBlade — Training &amp; Inference Cluster Penetration Testing Platform",
        description="InkBlade is an authorized penetration-testing product for ML training and inference clusters: a static Rust probe in the target Pod, ten detection layers, bilingual reports, replayable rules and a local console.",
    ),
    DOCS / "en" / "index.html": dict(
        mode="en", langs=["en"],
        title="InkBlade — Training &amp; Inference Cluster Penetration Testing Platform",
        description="InkBlade is an authorized penetration-testing product for ML training and inference clusters: a static Rust probe in the target Pod, ten detection layers, bilingual reports, replayable rules and a local console.",
    ),
    DOCS / "zh" / "index.html": dict(
        mode="zh", langs=["zh"],
        title="InkBlade（墨刃零）— 训练与推理集群渗透测试平台",
        description="InkBlade 是面向 ML 训练与推理集群的授权渗透测试产品：静态 Rust 探针进入目标 Pod，覆盖十层检测，产出双语报告、可重放规则与本地控制台。",
    ),
}

MD_LEDGER = DOCS / "0DAY-PUBLIC.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render the InkBlade documentation site")
    parser.add_argument("--check", action="store_true", help="fail if committed output is stale")
    args = parser.parse_args(argv)

    outputs: dict[Path, str] = {path: render_page(**config) for path, config in PAGES.items()}
    outputs[MD_LEDGER] = render_markdown_ledger()

    stale: list[Path] = []
    for path, rendered in outputs.items():
        if args.check:
            current = path.read_text(encoding="utf-8") if path.is_file() else ""
            if current != rendered:
                stale.append(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT).as_posix()} ({len(rendered)} bytes)")

    if args.check:
        for path in stale:
            print(f"out of date: {path.relative_to(ROOT).as_posix()}", file=sys.stderr)
        if stale:
            return 1
        print("docs site: up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
