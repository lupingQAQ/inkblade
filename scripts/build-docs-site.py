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


section(
    "find-a-module", "Find a module", "找模块",
    "Find a module", "找模块",
    "Browse 286 modules and 29 chains", "浏览 286 个模块、29 条链",
    en=f"""<p>Modules are grouped by the surface they attack, not by product name. Nine layers cover the places where ML infrastructure differs from ordinary Kubernetes: fabric, weights, KV cache, tenancy. Plus the combinations that only show up when a framework, an operator and a network plugin meet.</p>
<div class="figures"><div class="figure"><b>9</b><span>detection layers</span></div><div class="figure"><b>16</b><span>frameworks</span></div><div class="figure"><b>286</b><span>modules</span></div><div class="figure"><b>29</b><span>chains</span></div></div>
<h3>Nine detection layers</h3>
<div class="tbl"><table><thead><tr><th>Layer</th><th>What we look for</th><th>Representative keys</th></tr></thead><tbody><tr><td><span class="mono-n">1</span>Architecture</td><td>Rail and multi-plane mismatch, PD-split KV channel, IMEX domains, MoE/EP collectives, long-context KV lifetime, federation</td><td><code>rail-mismatch-forcing, prefill-decode-kv-channel-unauth, nvlink-imex-isolation</code></td></tr><tr><td><span class="mono-n">2</span>Product / framework</td><td>16 stacks with handlers: plugin routes, admin fail-open, dev modes, RL control planes, WebUI, checkpoint loaders</td><td><code>vllm-plugin-auth-bypass, sglang-admin-failopen, verl-prime-code-exec</code></td></tr><tr><td><span class="mono-n">3</span>Component / operator</td><td>Ray and LWS control, GPU Operator, DRA, CSI, BMC/Redfish, DPU</td><td><code>ray-dashboard-job, gpu-operator-driver-audit, gpu-dra-mig-policy</code></td></tr><tr><td><span class="mono-n">4</span>Network / fabric</td><td>Policy bypass on hostNetwork/SR-IOV/macvlan, dual CNI control planes, IB SM, RoCE PFC/ECN, SHARP, NCCL bootstrap</td><td><code>multus-sriov-rdma-bypass, ib-sm-partition-audit, sharp-in-network-poison</code></td></tr><tr><td><span class="mono-n">5</span>Data / weights</td><td>Checkpoint and optimizer shards, dataset pipelines, HF cache, weight buckets, model registry</td><td><code>checkpoint-shard-poison, skyrl-fetch-weights-traversal, model-registry-exposure</code></td></tr><tr><td><span class="mono-n">6</span>Tenant / isolation</td><td>MIG and MPS residue, GPU pooling schedulers, cache_salt, routing metric leakage</td><td><code>gpu-tenant-residue, hami-scheduler-auth-gap, cache-salt-policy-audit</code></td></tr><tr><td><span class="mono-n">7</span>Supply chain / identity</td><td>trust_remote_code, revision pinning, signatures and attestation, SBOM, IRSA wildcards, IMDS</td><td><code>trust-remote-code-supply-chain, gpu-cc-attestation-chain, cloud-irsa-trust-wildcard</code></td></tr><tr><td><span class="mono-n">8</span>Cache security</td><td>Cross-tenant prefix cache, semantic cache false hits, eviction residue, remote KV pools, PD channel, EPP metrics, TTFT timing</td><td><code>prefix-cache-cross-tenant-leak, remote-kv-pool-isolation, cache-timing-sidechannel</code></td></tr><tr><td><span class="mono-n">9</span>Cross-combination</td><td>14 declared signatures; the finding only exists when two or three components meet</td><td><code>sglang-weight-exfil, imex-computedomain-gpu-memory-crossing, long-context-cache-leak</code></td></tr></tbody></table></div>
<p class="note">Four-column detail per layer — detection point, why it is ML-specific, keys and chains, evidence produced: <a href="DETECTION-LAYERS.md">DETECTION-LAYERS.md</a>.</p>
<h3>Framework coverage</h3>
<div class="tbl"><table><thead><tr><th>Framework</th><th>Checks</th><th>Keys</th></tr></thead><tbody><tr><td><code>vLLM</code></td><td>Plugin route bypass, RL router, dev endpoints, prefix timing</td><td><span class="dim">vllm-plugin-auth-bypass · vllm-timing-oracle</span></td></tr><tr><td><code>SGLang</code></td><td>Admin fail-open, profiler write, ZMQ pickle, weight export</td><td><span class="dim">sglang-admin-failopen · sglang-weight-exfil</span></td></tr><tr><td><code>TRL</code></td><td>vllm-serve dev mode on 0.0.0.0</td><td><span class="dim">trl-serve-dev-mode</span></td></tr><tr><td><code>verl</code></td><td>prime_math eval, prime_code exec, checkpoint recv_pyobj, HDFS injection</td><td><span class="dim">verl-prime-code-exec · verl-hdfs-command-injection</span></td></tr><tr><td><code>AReaL</code></td><td>set_env to create_engine to call, unsafe /load, /awex NCCL join</td><td><span class="dim">areal-setenv-engine-rce · areal-awex-nccl-injection</span></td></tr><tr><td><code>SkyRL</code></td><td>Dev-mode weights, fetch traversal, Tinker control plane</td><td><span class="dim">skyrl-dev-pickle-rce · skyrl-tinker-hijack</span></td></tr><tr><td><code>OpenRLHF</code></td><td>Unauthenticated reward scoring, forced insecure serialization</td><td><span class="dim">openrlhf-serve-rm · openrlhf-vllm-env-force</span></td></tr><tr><td><code>slime</code></td><td>Cross-tenant weight pull, debug/resume load</td><td><span class="dim">slime-weight-pull-poison</span></td></tr><tr><td><code>LLaMA-Factory</code></td><td>Checkpoint load, WebUI exposure</td><td><span class="dim">llamafactory-checkpoint-rce</span></td></tr><tr><td><code>ms-swift</code></td><td>trust_remote_code, eval escape, dataset pickle, media read</td><td><span class="dim">msswift-trust-remote-code · msswift-eval-escape</span></td></tr><tr><td><code>Megatron-LM</code></td><td>Checkpointing load, optimizer shard trust</td><td><span class="dim">megatron-checkpoint-rce</span></td></tr><tr><td><code>DeepSpeed</code></td><td>Stage3 load sinks, AutoEP conversion</td><td><span class="dim">deepspeed-checkpoint-rce</span></td></tr><tr><td><code>transformers</code></td><td>Dynamic module import, revision drift</td><td><span class="dim">trust-remote-code-supply-chain</span></td></tr><tr><td><code>djev / vllm-jev</code></td><td>Open relay, plugin route bypass</td><td><span class="dim">djev-open-proxy · vllm-plugin-auth-bypass</span></td></tr><tr><td><code>Agent platforms</code></td><td>Sandbox escape, fail-open auth, default JWE key, cross-tenant snapshot</td><td><span class="dim">dify-local-sandbox-unauth-rce · open-webui-code-execute-rce</span></td></tr><tr><td><code>Gateways</code></td><td>Default key, config RCE, upstream key, cache isolation</td><td><span class="dim">litellm-default-key-exfil · aigateway-upstream-key-exfil</span></td></tr></tbody></table></div>
<h3>Module families</h3>
{series_table("en")}
<h3>Chains and levels</h3>
{chain_table("en")}
{level_table("en")}
<div class="cut">
  <p>Modules sit in layer three of seven. Consent is above them, evidence below. What each layer refuses: <a href="ARCHITECTURE.md">ARCHITECTURE.md</a>.</p>
  <p><a href="MODULES.md">Module catalogue</a> · <a href="FEATURES.md">Feature inventory</a> · <a href="DETECTION-LAYERS.md">Detection layers</a></p>
</div>
""",
    zh=f"""<p>模块按攻击面分组，不按产品名。九层覆盖 ML 基础设施与普通 Kubernetes 的差异：fabric、权重、KV 缓存、租户；再加上只有框架、Operator、网络插件凑在一起才出现的组合。</p>
<div class="figures"><div class="figure"><b>9</b><span>检测层</span></div><div class="figure"><b>16</b><span>框架</span></div><div class="figure"><b>286</b><span>模块</span></div><div class="figure"><b>29</b><span>条链</span></div></div>
<h3>九层检测</h3>
<div class="tbl"><table><thead><tr><th>层</th><th>看什么</th><th>代表模块键</th></tr></thead><tbody><tr><td><span class="mono-n">1</span>架构层</td><td>rail 与多平面错配、PD 分离 KV 通道、IMEX 域、MoE/EP 集合通信、长上下文 KV 生命周期、联邦</td><td><code>rail-mismatch-forcing、prefill-decode-kv-channel-unauth、nvlink-imex-isolation</code></td></tr><tr><td><span class="mono-n">2</span>产品 / 框架层</td><td>16 个栈有处理器：插件路由、管理面 fail-open、dev 模式、RL 控制面、WebUI、checkpoint loader</td><td><code>vllm-plugin-auth-bypass、sglang-admin-failopen、verl-prime-code-exec</code></td></tr><tr><td><span class="mono-n">3</span>组件 / Operator 层</td><td>Ray 与 LWS 控制面、GPU Operator、DRA、CSI、BMC/Redfish、DPU</td><td><code>ray-dashboard-job、gpu-operator-driver-audit、gpu-dra-mig-policy</code></td></tr><tr><td><span class="mono-n">4</span>网络 / fabric 层</td><td>hostNetwork/SR-IOV/macvlan 策略旁路、CNI 双控制面、IB SM、RoCE PFC/ECN、SHARP、NCCL bootstrap</td><td><code>multus-sriov-rdma-bypass、ib-sm-partition-audit、sharp-in-network-poison</code></td></tr><tr><td><span class="mono-n">5</span>数据 / 权重层</td><td>checkpoint 与优化器分片、数据集管道、HF 缓存、权重桶、模型注册表</td><td><code>checkpoint-shard-poison、skyrl-fetch-weights-traversal、model-registry-exposure</code></td></tr><tr><td><span class="mono-n">6</span>租户 / 隔离层</td><td>MIG 与 MPS 残留、GPU 池化调度、cache_salt、路由指标泄露</td><td><code>gpu-tenant-residue、hami-scheduler-auth-gap、cache-salt-policy-audit</code></td></tr><tr><td><span class="mono-n">7</span>供应链 / 身份层</td><td>trust_remote_code、revision 固定、签名与证明、SBOM、IRSA 通配、IMDS</td><td><code>trust-remote-code-supply-chain、gpu-cc-attestation-chain、cloud-irsa-trust-wildcard</code></td></tr><tr><td><span class="mono-n">8</span>缓存安全层</td><td>跨租户前缀缓存、语义缓存误命中、逐出残留、远程 KV 池、PD 通道、EPP 指标、TTFT 时序</td><td><code>prefix-cache-cross-tenant-leak、remote-kv-pool-isolation、cache-timing-sidechannel</code></td></tr><tr><td><span class="mono-n">9</span>跨组合层</td><td>14 条已声明签名；只有两三个组件相遇才成立</td><td><code>sglang-weight-exfil、imex-computedomain-gpu-memory-crossing、long-context-cache-leak</code></td></tr></tbody></table></div>
<p class="note">逐层四列表——检测点、为何独有、模块键与链、证据产出：<a href="DETECTION-LAYERS.md">DETECTION-LAYERS.md</a>。</p>
<h3>框架覆盖</h3>
<div class="tbl"><table><thead><tr><th>框架</th><th>检查</th><th>模块键</th></tr></thead><tbody><tr><td><code>vLLM</code></td><td>插件路由绕过、RL 路由、dev 端点、前缀时序</td><td><span class="dim">vllm-plugin-auth-bypass · vllm-timing-oracle</span></td></tr><tr><td><code>SGLang</code></td><td>管理面 fail-open、profiler 写入、ZMQ pickle、权重导出</td><td><span class="dim">sglang-admin-failopen · sglang-weight-exfil</span></td></tr><tr><td><code>TRL</code></td><td>vllm-serve 在 0.0.0.0 上开 dev</td><td><span class="dim">trl-serve-dev-mode</span></td></tr><tr><td><code>verl</code></td><td>prime_math eval、prime_code exec、checkpoint recv_pyobj、HDFS 注入</td><td><span class="dim">verl-prime-code-exec · verl-hdfs-command-injection</span></td></tr><tr><td><code>AReaL</code></td><td>set_env 到 create_engine 到 call、不安全 /load、/awex NCCL 入组</td><td><span class="dim">areal-setenv-engine-rce · areal-awex-nccl-injection</span></td></tr><tr><td><code>SkyRL</code></td><td>dev 权重、fetch 穿越、Tinker 控制面</td><td><span class="dim">skyrl-dev-pickle-rce · skyrl-tinker-hijack</span></td></tr><tr><td><code>OpenRLHF</code></td><td>无鉴权打分、强制不安全序列化</td><td><span class="dim">openrlhf-serve-rm · openrlhf-vllm-env-force</span></td></tr><tr><td><code>slime</code></td><td>跨租户权重拉取、debug/resume 加载</td><td><span class="dim">slime-weight-pull-poison</span></td></tr><tr><td><code>LLaMA-Factory</code></td><td>checkpoint 加载、WebUI 暴露</td><td><span class="dim">llamafactory-checkpoint-rce</span></td></tr><tr><td><code>ms-swift</code></td><td>trust_remote_code、eval 逃逸、数据集 pickle、media 读取</td><td><span class="dim">msswift-trust-remote-code · msswift-eval-escape</span></td></tr><tr><td><code>Megatron-LM</code></td><td>checkpointing 加载、优化器分片信任</td><td><span class="dim">megatron-checkpoint-rce</span></td></tr><tr><td><code>DeepSpeed</code></td><td>stage3 加载 sink、AutoEP 转换</td><td><span class="dim">deepspeed-checkpoint-rce</span></td></tr><tr><td><code>transformers</code></td><td>动态模块导入、revision 漂移</td><td><span class="dim">trust-remote-code-supply-chain</span></td></tr><tr><td><code>djev / vllm-jev</code></td><td>开放中继、插件路由绕过</td><td><span class="dim">djev-open-proxy · vllm-plugin-auth-bypass</span></td></tr><tr><td><code>Agent platforms</code></td><td>沙箱逃逸、fail-open 鉴权、默认 JWE 密钥、跨租户快照</td><td><span class="dim">dify-local-sandbox-unauth-rce · open-webui-code-execute-rce</span></td></tr><tr><td><code>Gateways</code></td><td>默认密钥、配置 RCE、上游密钥、缓存隔离</td><td><span class="dim">litellm-default-key-exfil · aigateway-upstream-key-exfil</span></td></tr></tbody></table></div>
<h3>模块族</h3>
{series_table("zh")}
<h3>链与级别</h3>
{chain_table("zh")}
{level_table("zh")}
<div class="cut">
  <p>模块在七层里排第三：上面是授权，下面是证据。每层拒绝什么：<a href="ARCHITECTURE.md">ARCHITECTURE.md</a>。</p>
  <p><a href="MODULES.md">模块目录</a> · <a href="FEATURES.md">特性清单</a> · <a href="DETECTION-LAYERS.md">检测分层</a></p>
</div>
""",
)

section(
    "install", "Install and run", "安装与运行",
    "Install and run", "安装与运行",
    "Requirements, then four commands", "先看要求，再跑四条命令",
    en=f"""<p>No cluster. No kubeconfig. No API key. Mock targets bind to loopback. Writes stay in the output directory.</p>
<h3>Requirements</h3>
<ul>
  <li><strong>Python 3.10 – 3.13</strong> on <code>PATH</code>. No compiler, no virtualenv, no third-party package.</li>
  <li><strong>200 MB disk</strong> for demo workspace, reports, console.</li>
  <li><strong>Optional:</strong> Docker 24+, Helm 3, a kubeconfig for later.</li>
</ul>
<h3>Four commands</h3>
<ol class="steps">
  <li><b>python -m pip install -e .</b><span>Entry point. Or use <code>python -m inkblade ...</code>.</span></li>
  <li><b>python -m inkblade doctor</b><span>Python, writes, ports, deps, cluster reachability. Under a second.</span></li>
  <li><b>python -m inkblade demo</b><span>Workspace, consent, mock lab, 2 modules, 1 chain, reports. 4–5 s.</span></li>
  <li><b>python -m inkblade trial</b><span>Same run, shorter output, plus next steps.</span></li>
</ol>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">terminal · offline demo</span></div>
<pre><code><span class="p">$</span> python -m inkblade doctor
<span class="p">$</span> python -m inkblade demo
<span class="p">$</span> python -m inkblade trial</code></pre>
</div>
<h3>Other ways in</h3>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">container</span></div>
<pre><code>docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 trial</code></pre>
</div>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">helm · read-only by default</span></div>
<pre><code>helm install inkblade deploy/helm/inkblade --namespace inkblade --create-namespace</code></pre>
</div>
<p class="note">uid 10001, read-only root, <code>/data</code> writable. Chart grants <code>get/list/watch</code>. Writes need two switches and a signed record; otherwise HTTP 423.</p>
<p class="note"><a href="INSTALL.md">Install page</a> · <a href="USAGE.md#quick-reference">quick reference</a></p>
""",
    zh=f"""<p>不要集群、不要 kubeconfig、不要 API key。mock 靶场只绑回环，写入落在输出目录。</p>
<h3>要求</h3>
<ul>
  <li><strong>Python 3.10 – 3.13</strong> 在 <code>PATH</code> 里。不用编译器、不强制虚拟环境、不装第三方包。</li>
  <li><strong>200 MB 磁盘</strong>：demo 工作区、报告、控制台。</li>
  <li><strong>可选：</strong>Docker 24+、Helm 3、之后的 kubeconfig。</li>
</ul>
<h3>四条命令</h3>
<ol class="steps">
  <li><b>python -m pip install -e .</b><span>装入口。也可以直接 <code>python -m inkblade ...</code>。</span></li>
  <li><b>python -m inkblade doctor</b><span>Python、写权限、端口、依赖、集群可达。不到一秒。</span></li>
  <li><b>python -m inkblade demo</b><span>工作区、授权、mock、2 模块、1 链、报告。4–5 秒。</span></li>
  <li><b>python -m inkblade trial</b><span>同样流程，输出更短，附下一步。</span></li>
</ol>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">终端 · 离线 demo</span></div>
<pre><code><span class="p">$</span> python -m inkblade doctor
<span class="p">$</span> python -m inkblade demo
<span class="p">$</span> python -m inkblade trial</code></pre>
</div>
<h3>其他入口</h3>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">容器</span></div>
<pre><code>docker build -t inkblade:0.2.0 .
docker run --rm -v inkblade-data:/data inkblade:0.2.0 trial</code></pre>
</div>
<div class="term">
  <div class="term-bar"><span class="dot"></span><span class="dot"></span><span class="dot"></span><span class="label">helm · 默认只读</span></div>
<pre><code>helm install inkblade deploy/helm/inkblade --namespace inkblade --create-namespace</code></pre>
</div>
<p class="note">uid 10001、根只读、只有 <code>/data</code> 可写。Chart 只给 <code>get/list/watch</code>。要写需两个开关加签署记录，否则 HTTP 423。</p>
<p class="note"><a href="INSTALL.md">安装页</a> · <a href="USAGE.md#quick-reference">快速参考</a></p>
""",
)

section(
    "safe", "Test a cluster safely", "安全测试集群",
    "Test a cluster safely", "安全地测试集群",
    "Pilot first, read-only by default, backup before writes", "先试点，默认只读，写前必备份",
    en=f"""<p>Gates, in order. Each one stops the run. First pass is read-only.</p>
<ol class="steps">
  <li><b>inkblade pilot</b><span>Read-only inventory: namespaces, workloads, GPU capacity, gateways, storage. Profile, heat map, approval list.</span></li>
  <li><b>inkblade roe / quickstart</b><span>Scope, level, window, signed. No record, no run.</span></li>
  <li><b>Read-only modules</b><span>191 of 286. Enumerate and confirm. No state change.</span></li>
  <li><b>execute --dry-run</b><span>Graph, preconditions, every write. Nothing runs.</span></li>
  <li><b>Approve and back up</b><span>Write modules need both. Missing one exits 91.</span></li>
  <li><b>inkblade rollback</b><span>Step back, report what will not return. Failed restore is a finding.</span></li>
</ol>
{table(
    [("Gate", ""), ("Refuses when", ""), ("Signal", "num")],
    [
        '<tr><td>Consent</td><td>No record, expired window, out-of-scope asset.</td><td class="num">exit 91 / HTTP 423</td></tr>',
        '<tr><td>Level</td><td>Module level above the record.</td><td class="num">exit 91</td></tr>',
        '<tr><td>Backup</td><td>Write module, no writable target.</td><td class="num">exit 91</td></tr>',
        '<tr><td>Surface</td><td>Missing surface, no <code>--probe</code>.</td><td class="num">skipped, recorded</td></tr>',
        '<tr><td>Rollback</td><td>A step cannot be restored.</td><td class="num">exit 3</td></tr>',
    ],
)}
<div class="cut warn">
  <p><strong>Demo stays on loopback.</strong> Writes stay in the workspace. Real clusters need a signed record and a kubeconfig.</p>
  <p>Emergency stop: <code>inkblade abort</code>. Release with <code>--clear</code>.</p>
</div>
""",
    zh=f"""<p>闸门按顺序来。每一道都能停住 run。第一轮只读。</p>
<ol class="steps">
  <li><b>inkblade pilot</b><span>只读清点：命名空间、工作负载、GPU、网关、存储。画像、热图、审批清单。</span></li>
  <li><b>inkblade roe / quickstart</b><span>范围、级别、窗口，签字。没记录不跑。</span></li>
  <li><b>只读模块</b><span>286 里的 191 个。只枚举、只确认，不改状态。</span></li>
  <li><b>execute --dry-run</b><span>链图、前置、每一处写入。什么都不执行。</span></li>
  <li><b>审批并备份</b><span>写类模块两样都要。缺一个退出 91。</span></li>
  <li><b>inkblade rollback</b><span>逐步回退，报告哪些回不来。恢复失败是发现。</span></li>
</ol>
{table(
    [("闸门", ""), ("拒绝条件", ""), ("信号", "num")],
    [
        '<tr><td>授权</td><td>没记录、窗口过期、资产越界。</td><td class="num">exit 91 / HTTP 423</td></tr>',
        '<tr><td>级别</td><td>模块级别高于记录。</td><td class="num">exit 91</td></tr>',
        '<tr><td>备份</td><td>写类模块没有可写目标。</td><td class="num">exit 91</td></tr>',
        '<tr><td>部署面</td><td>缺面且未 <code>--probe</code>。</td><td class="num">跳过并记录</td></tr>',
        '<tr><td>回滚</td><td>有步骤无法恢复。</td><td class="num">exit 3</td></tr>',
    ],
)}
<div class="cut warn">
  <p><strong>demo 只在回环。</strong>写入留在工作区。真实集群要签署记录和 kubeconfig。</p>
  <p>急停 <code>inkblade abort</code>，解除用 <code>--clear</code>。</p>
</div>
""",
)

section(
    "workflow", "Full workflow", "完整流程",
    "Full workflow", "完整流程",
    "Eleven stages, from signature to retest", "十一步，从签字到复测",
    en=f"""<p>Eleven stages. Each leaves something the next can check.</p>
{figures([("11", "stages"), ("3", "evidence layers per step"), ("2", "report languages"), ("0", "actions without a record")])}
<ul class="flow">
{"".join(f'<li><span class="n">{n}</span><span class="t">{en_name}</span><span class="d">{desc}<br><span class="note">→ {artifact}</span></span></li>' for n, en_name, zh_name, desc, artifact in WORKFLOW)}
</ul>
<p class="note">Stage five is where most tools start. Here it needs a record, inventory, surface matrix and plan first. A refusal stops the run.</p>
<p><a href="WORKFLOW.md">Stage reference</a></p>
""",
    zh=f"""<p>十一步。每步都留下下一步能校验的东西。</p>
{figures([("11", "个阶段"), ("3", "层证据 / 步"), ("2", "种报告语言"), ("0", "无记录的越权动作")])}
<ul class="flow">
{"".join(f'<li><span class="n">{n}</span><span class="t">{zh_name}</span><span class="d">{desc}<br><span class="note">→ {artifact}</span></span></li>' for n, en_name, zh_name, desc, artifact in WORKFLOW)}
</ul>
<p class="note">多数工具从第五步开始。这里要先有记录、清单、部署面矩阵和计划。拒绝就地停下。</p>
<p><a href="WORKFLOW.md">逐阶段参考</a></p>
""",
)

section(
    "reserve", "0Day reserve", "0day 储备",
    "0Day reserve", "0day 储备",
    "39 unique primitives · 21 components · reported to vendors", "39 条独立原语 · 21 个组件 · 已上报厂商",
    en=f"""<p>One counting rule. Dynamic reproduction succeeded, and the novelty check said “confirmed unpublished”. A finding that turns out to be public later gets downgraded, and the downgrade stays on the record. Nothing is counted twice.</p>
{figures([("169", "inventory entries"), ("60", "dynamically verified"), ("47", "confirmed unpublished"), ("39", "unique primitives"), ("21", "components"), ("0", "inconclusive")])}
<p>Here is the whole reserve. One row per unique primitive: component, class, affected versions, status, disclosure window. That is enough for a defender to check a version string. It is not enough to run anything, and that is the point.</p>
{reserve_table("en")}
<div class="cut warn">
  <p><strong>Reported through the coordinated-disclosure process.</strong> Vendors were notified under the policy below. Exploit details, runnable code and request bodies stay private until the fix window closes, then ship with the advisory.</p>
  <p>Policy: vendor first. 90-day window. National CERT if the vendor never answers. 30 CVE-ready packages and 6 hardening-only notes are prepared. Dates in the table are targets. A vendor who asks for more time in writing gets it.</p>
</div>
<p><a href="0DAY-PUBLIC.md">Ledger, counting rules and per-row notes</a></p>
""",
    zh=f"""
<p>计数规则只有一条，没有例外：动态复现成功、且查新结论为“确认未公开”的条目才能进入储备。事后发现已公开的，降级并留痕。同一条不重复计数。</p>
{figures([("169", "库存条目"), ("60", "动态验证"), ("47", "确认未公开"), ("39", "独立原语"), ("21", "组件"), ("0", "存疑")])}
<p>下面是完整储备，一条独立原语一行：组件、类别、受影响版本、状态、披露窗口。这是有意的安排。防守方应该能自己对着版本号判断，而不必来问我们要简报——也不必从我们这里拿到利用代码。</p>
{reserve_table("zh")}
<div class="cut warn">
  <p><strong>已按协调披露流程通知厂商。</strong>通知按下面的政策执行；利用细节、可执行代码和请求内容在修复窗口结束前保持非公开，之后随 advisory 一并发布。</p>
  <p>政策：厂商优先，90 天窗口，厂商不回应再转国家级 CERT。已准备 30 份 CVE 就绪包与 6 份加固建议。表中的日期是目标值，不是承诺——厂商书面申请延期，会给。</p>
</div>
<p><a href="0DAY-PUBLIC.md">台账、计数规则与逐条说明</a></p>
""",
)

section(
    "research", "Research", "语料与研究",
    "Research with the corpus", "与语料一起做研究",
    "80 sources, 38 capability rows, reproducible checks", "80 个源、38 行能力矩阵、可复现的校验",
    en=f"""<p>Claims should be traceable. The corpus holds <strong>80 sources</strong>: vendor docs in Chinese and English, plus papers. A coverage matrix enforces counts and composition.</p>
{figures([("80", "corpus sources"), ("38", "capability rows"), ("25", "verified real"), ("10", "simulated"), ("3", "not achieved")])}
{table(
    [("Artifact", ""), ("Question", "")],
    [
        '<tr><td><a href="RESEARCH-COVERAGE.md">Corpus coverage</a></td><td>Which vendors and papers back the claims. Where the gaps are.</td></tr>',
        '<tr><td>Capability matrix</td><td>Verified, simulated, or not achieved. 38 rows.</td></tr>',
        '<tr><td><a href="COMPETITIVE-MATRIX.md">Competitive matrix</a></td><td>What comparable tools do.</td></tr>',
        '<tr><td><a href="OSS-BENCH.md">OSS benchmark</a></td><td>How far off-the-shelf scanners get on the same lab.</td></tr>',
        '<tr><td><a href="EFFECT-VERIFICATION.md">Effect verification</a></td><td>Real effect, or exposed endpoint?</td></tr>',
    ],
)}
<p>25 verified on real software. 10 in simulation. 3 not achieved. The last column names the blocker.</p>
<p class="note">Clean-room comparisons: public descriptions and protocol knowledge. No AGPL source read. Statement in <code>NOTICE</code>.</p>
""",
    zh=f"""<p>结论要能追溯。语料库 <strong>80 个源</strong>：中英文厂商文档加论文。覆盖矩阵约束数量与构成。</p>
{figures([("80", "语料源"), ("38", "能力行"), ("25", "真实验证"), ("10", "模拟验证"), ("3", "仍未达成")])}
{table(
    [("材料", ""), ("回答什么", "")],
    [
        '<tr><td><a href="RESEARCH-COVERAGE.md">语料覆盖</a></td><td>哪些厂商与论文支撑判断，缺口在哪。</td></tr>',
        '<tr><td>能力矩阵</td><td>真实验证、模拟验证、仍未达成。38 行。</td></tr>',
        '<tr><td><a href="COMPETITIVE-MATRIX.md">竞品矩阵</a></td><td>同类工具做到什么。</td></tr>',
        '<tr><td><a href="OSS-BENCH.md">开源基准</a></td><td>现成扫描器在同一实验环境能走多远。</td></tr>',
        '<tr><td><a href="EFFECT-VERIFICATION.md">效果验证</a></td><td>真实效果，还是只暴露了端点？</td></tr>',
    ],
)}
<p>25 项在真实软件上验证，10 项只在模拟里，3 项仍未达成。最后一列写明阻塞原因。</p>
<p class="note">对比是 clean-room 的：公开描述与协议常识。没有读 AGPL 源码。声明在 <code>NOTICE</code>。</p>
""",
)

section(
    "limits", "Limits", "边界",
    "Limits and responsible use", "边界与责任",
    "What this is not, and where authorization is not negotiable", "它不是什么，以及授权为什么不可协商",
    en=f"""<div class="split">
  <div><h3>Coverage is uneven</h3><p>Kubernetes 60–71%. Slurm 25%. Missing modules listed per profile.</p></div>
  <div><h3>Verification is partial</h3><p>37 of 152 entries have a dynamic run. 6 more exposure-verified. Rest are hypotheses.</p></div>
  <div><h3>Reserve row is a lead</h3><p>One commit, one config. Patch level decides exposure.</p></div>
  <div><h3>Autonomy is bounded</h3><p>Planner and explorer exist. Default: propose and wait.</p></div>
  <div><h3>No telemetry</h3><p>No outbound calls unless enabled. No licence server.</p></div>
  <div><h3>Pre-1.0</h3><p>Interfaces move. Pin a version for a regulated pilot.</p></div>
</div>
<div class="cut warn">
  <p><strong>Authorized use only.</strong> Written authorization or nothing. Testing systems you do not own is a crime in most jurisdictions. The software refuses without a signed record.</p>
  <p>Issues in InkBlade: private vulnerability reporting, 90-day target. No public issues with exploit detail.</p>
</div>
<p class="note">Missing capability? The gap register names it. <a href="FAQ.md">FAQ</a></p>
""",
    zh=f"""<div class="split">
  <div><h3>覆盖不齐</h3><p>Kubernetes 60–71%，Slurm 25%。缺的模块按画像列。</p></div>
  <div><h3>验证是部分的</h3><p>152 条里 37 条动态验证，6 条暴露面验证，其余是假设。</p></div>
  <div><h3>储备行是线索</h3><p>一个 commit、一种配置。补丁级别决定暴露。</p></div>
  <div><h3>自治有边界</h3><p>有规划器和探索器，默认提议并等待。</p></div>
  <div><h3>无遥测</h3><p>不开启就没有外发调用。没有授权服务器。</p></div>
  <div><h3>pre-1.0</h3><p>接口会动。合规试点请钉版本。</p></div>
</div>
<div class="cut warn">
  <p><strong>仅限授权使用。</strong>没有书面授权就不做。对不归你所有的系统动手，在多数司法辖区属于违法。软件会拒绝。</p>
  <p>InkBlade 自身的问题：私密报告，90 天目标。公开 issue 别贴利用细节。</p>
</div>
<p class="note">缺什么能力，缺口台账写明。<a href="FAQ.md">常见问题</a></p>
""",
)

section(
    "support", "Support &amp; license", "支持与许可",
    "Support and license", "支持与许可",
    "Apache-2.0, a security policy, and an empty sponsor slot", "Apache-2.0、安全政策，以及一个空的赞助位",
    en=f"""{table(
    [("Item", ""), ("Details", "")],
    [
        '<tr><td>License</td><td><strong>Apache-2.0</strong>. Commercial use, forks, embedding: fine. Keep the notices.</td></tr>',
        '<tr><td>Clean-room</td><td><code>NOTICE</code> records which parity features came from public descriptions only.</td></tr>',
        '<tr><td>Security</td><td>0.2.x supported. Private reporting. 90-day coordinated disclosure. No public issues with exploit detail.</td></tr>',
        '<tr><td>Contributing</td><td>Issues and pull requests welcome. A module needs a manifest, a dry-run path and tests.</td></tr>',
        '<tr><td>Versioning</td><td>Pre-1.0: one active minor line. The previous line gets security fixes for 90 days.</td></tr>',
        '<tr><td>Sponsor</td><td>Slot reserved. No funding account published yet. The repository will carry it when there is one.</td></tr>',
    ],
)}
<p class="note">Repository policies live in the source tree: <code>SECURITY.md</code>, <code>CONTRIBUTING.md</code>, <code>CODE_OF_CONDUCT.md</code>, <code>docs/VERSIONING.md</code>. The site is generated from <code>docs/</code>. Internal audit material is not part of the published site.</p>
""",
    zh=f"""
{table(
    [("项目", ""), ("说明", "")],
    [
        '<tr><td>许可证</td><td><strong>Apache-2.0</strong>。可以商用、fork、嵌进服务；保留声明即可。</td></tr>',
        '<tr><td>Clean-room</td><td><code>NOTICE</code> 记录了哪些对标特性只依据公开功能描述实现。</td></tr>',
        '<tr><td>安全</td><td>支持 0.2.x，走私密报告，协调披露 90 天，不接受公开贴利用细节的 issue。</td></tr>',
        '<tr><td>贡献</td><td>欢迎 issue 与 PR。模块提交需要 manifest、dry-run 路径和测试。</td></tr>',
        '<tr><td>版本</td><td>pre-1.0：同时维护一条次版本线，上一条线提供 90 天安全修复。</td></tr>',
        '<tr><td>赞助</td><td>位置保留。暂无公开的资助账号，有了会写在仓库里。</td></tr>',
    ],
)}
<p class="note">仓库政策在源码树里：<code>SECURITY.md</code>、<code>CONTRIBUTING.md</code>、<code>CODE_OF_CONDUCT.md</code>、<code>docs/VERSIONING.md</code>。本站由 <code>docs/</code> 生成；内部审计材料不随站点发布。</p>
""",
)

section(
    "ai-disclosure", "AI disclosure", "AI 披露",
    "AI-generated content disclosure", "AI 生成内容披露",
    "How these pages were written", "这些页面是怎么写出来的",
    en=f"""<p>Parts of this site and the READMEs were drafted with AI assistance. A human maintainer ran the commands, checked the numbers against code and reports, and cut claims that would not reproduce.</p>
<p>Detectors disagree with each other and with people. No detection rate is quoted. Sentences that read like a machine wrote them probably started that way. Numbers that look wrong are bugs.</p>
<p class="note">Code, manifests, rule packs and evidence come from the software. This covers prose.</p>
""",
    zh=f"""<p>本站与 README 的部分段落由 AI 辅助起草。人工维护者跑了命令、对着代码与报告核了数字，删掉了复现不了的说法。</p>
<p>检测器彼此不一致，也和人类判断不一致。这里不引用检测率。读着像机器写的句子，多半最初就是那么写的。数字不对就是 bug。</p>
<p class="note">代码、manifest、规则包与证据来自软件本身。以上只针对文字。</p>
""",
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
        "docstate": "Development documentation <i>/</i> v" + VERSION,
        "lead": "Consent gates, three evidence layers per step, bilingual reports. Python standard library only — nothing gets installed inside your cluster.",
        "links": [("Download", "INSTALL.md"), ("Quick reference", "USAGE.md#quick-reference"), ("Architecture", "ARCHITECTURE.md")],
        "spec": [
            ("version", VERSION), ("license", "Apache-2.0"), ("runtime", "Python 3.10 – 3.13"),
            ("dependencies", "none"), ("modules", "286 (275 default)"), ("chains", "29"),
            ("posture", "read-only by default"), ("telemetry", "none"),
        ],
        "spec_note": "Pre-1.0. Interfaces can move between minor versions; pin a version for a regulated pilot.",
    },
    "zh": {
        "kicker": "训练与推理基础设施",
        "positioning": "训练与推理集群渗透测试平台",
        "docstate": "开发文档 <i>/</i> v" + VERSION,
        "lead": "授权闸门、每步三层证据、双语报告。只依赖 Python 标准库——集群里不需要装任何东西。",
        "links": [("下载", "INSTALL.md"), ("快速参考", "USAGE.md#quick-reference"), ("架构", "ARCHITECTURE.md")],
        "spec": [
            ("版本", VERSION), ("许可证", "Apache-2.0"), ("运行时", "Python 3.10 – 3.13"),
            ("依赖", "无"), ("模块", "286（默认 275）"), ("链", "29"),
            ("默认姿态", "只读"), ("遥测", "无"),
        ],
        "spec_note": "pre-1.0。接口可能在次版本间变化；合规试点请钉死版本。",
    },
}

FOOT = {
    "en": {
        "blurb": "Documentation for InkBlade, generated from the repository. Plain HTML and two local assets; no fonts, scripts or styles are fetched from anywhere.",
        "cols": [
            ("Guides", [("Usage", "USAGE.md"), ("Features", "FEATURES.md"), ("Workflow", "WORKFLOW.md"), ("Install", "INSTALL.md")]),
            ("Reference", [("Module catalogue", "MODULES.md"), ("0Day ledger", "0DAY-PUBLIC.md"), ("FAQ", "FAQ.md"), ("Architecture", "ARCHITECTURE.md")]),
            ("Project", [("Find a module", "#find-a-module"), ("Limits", "#limits"), ("Support &amp; license", "#support")]),
        ],
        "bar": ["InkBlade " + VERSION, "Apache-2.0", "Authorized testing only", "Docs written with AI assistance, human-reviewed"],
    },
    "zh": {
        "blurb": "InkBlade 文档，从仓库内容生成。纯 HTML 加两个本地资源；不从任何地方加载字体、脚本或样式。",
        "cols": [
            ("指南", [("使用", "USAGE.md"), ("特性", "FEATURES.md"), ("流程", "WORKFLOW.md"), ("安装", "INSTALL.md")]),
            ("参考", [("模块目录", "MODULES.md"), ("0day 台账", "0DAY-PUBLIC.md"), ("常见问题", "FAQ.md"), ("架构", "ARCHITECTURE.md")]),
            ("项目", [("找模块", "#find-a-module"), ("边界", "#limits"), ("支持与许可", "#support")]),
        ],
        "bar": ["InkBlade " + VERSION, "Apache-2.0", "仅限授权测试", "文档由 AI 辅助撰写，经人工校对"],
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
        description="InkBlade is an authorized penetration-testing platform for Kubernetes and ML training/inference clusters: consent gates, three evidence layers, bilingual reports, no runtime dependencies.",
    ),
    DOCS / "en" / "index.html": dict(
        mode="en", langs=["en"],
        title="InkBlade — Training &amp; Inference Cluster Penetration Testing Platform",
        description="InkBlade is an authorized penetration-testing platform for Kubernetes and ML training/inference clusters: consent gates, three evidence layers, bilingual reports, no runtime dependencies.",
    ),
    DOCS / "zh" / "index.html": dict(
        mode="zh", langs=["zh"],
        title="InkBlade（墨刃零）— 训练与推理集群渗透测试平台",
        description="InkBlade 是面向 Kubernetes 与 ML 训练/推理集群的授权渗透测试平台：授权闸门、三层证据、双语报告，零运行时依赖。",
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
