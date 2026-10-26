"""防护产品绕过引擎（规格 5.2「防护产品绕过模块（v7）」）。

两个正交能力：
1. 产品指纹：输入=部署面快照 dict（daemonsets/pods/rules/configs/kernel_modules…），
   指标规则公开仓库命名（elkeid-agent/elkeid.ko（别名 olehid）、smith.ko、veinmind-* 等）。
2. 良性覆盖探针：技术类别级 benign marker（受监控路径类别良性写入、改名工具执行 echo、
   分层镜像 benign 样本、编码变体 benign 请求），**不含任何恶意载荷**；物化只允许写
   授权 scratch 目录（ContainmentError 强制）。

两态评估：「已部署(带规则集 fixture)」 vs 「未部署/降级」→
{product, state, detected, blindspots, hardening}；硬化文本带 rule: 前缀供规则引擎消费。
"""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any

SAFE_MARKER_PREFIX = "INKBLADE-BENIGN"
SCRATCH_DIR = "inkblade-benign-scratch"
MODULE_PREFIX = "defense-bypass-"
STATES = ("deployed", "degraded", "absent")

# 良性探针自检禁用串：任何 marker/模板命中即拒绝（无害性硬边界）
FORBIDDEN_PAYLOAD_PATTERNS = (
    "/etc/shadow", "/etc/passwd", "/dev/tcp/", "nc -e", "| sh", "|sh",
    "msfvenom", "rootkit", "chmod 4755", "wget http", "curl http",
    "base64 -d", "mkfifo", "shellcode", "eval(", "exec(/bin/sh",
)

_DRIVE_RE = re.compile(r"^[a-zA-Z]:")


class ProbeContainmentError(Exception):
    """良性探针试图写出授权 scratch 目录（无害性边界被突破）。"""


# --------------------------------------------------------------------------
# 产品规格（指纹指标 + 技术 + 默认规则集 fixture 覆盖）
# --------------------------------------------------------------------------
def _t(tid, name, category, detected, needs_driver, gap):
    return {
        "id": tid, "name": name, "category": category,
        "detected": detected, "needs_driver": needs_driver, "gap": gap,
    }


PRODUCT_SPECS: dict[str, dict] = {
    # ---------------- 字节系（Elkeid：bytedance/Elkeid） ----------------
    "elkeid": {
        "module": "defense-bypass-elkeid",
        "display": "Elkeid HIDS",
        "vendor": "bytedance",
        "sub_products": ["elkeid"],
        "indicators": {
            "core": [
                {"id": "elkeid-agent", "pattern": r"elkeid[-_/ ]?agent"},
                {"id": "elkeid-server", "pattern": r"elkeid[-_/ ]?server"},
                {"id": "elkeid-manager", "pattern": r"elkeid[-_/ ]?manager"},
                {"id": "elkeid-hub", "pattern": r"elkeid[-_/ ]?hub"},
                {"id": "elkeid-rules", "pattern": r"elkeid[-_/ ]?rule"},
                {"id": "elkeid-generic", "pattern": r"elkeid"},
            ],
            # 内核态：elkeid.ko（公开仓库命名）；olehid 为任务口径别名，保守兼容
            "driver": [
                {"id": "elkeid-ko", "pattern": r"^(elkeid|olehid)(\.ko)?$",
                 "field": "kernel_modules"},
                {"id": "elkeid-driver", "pattern": r"elkeid[-_/ ]?driver"},
            ],
        },
        "techniques": [
            _t("monitored-path-write", "受监控路径类别良性写入", "monitored-path-write", True, True,
               "保持 LKM 采集→规则告警链路覆盖 /tmp、/dev/shm 类别写入"),
            _t("container-benign-write", "容器内良性标记写入", "monitored-path-write", True, True,
               "容器场景规则（runtime/namespace 维度）与主机规则同权维护"),
            _t("whitelist-path-write", "白名单路径类别良性写入", "whitelist-path-write", False, False,
               "收窄 elkeid-agent 自身/升级目录白名单，白名单路径写事件送 hub 二次研判"),
            _t("tool-rename-exec", "改名工具执行 echo", "tool-rename-exec", False, True,
               "execve 事件增加『常见工具改名执行』启发式（echo/busybox 副本哈希比对）"),
            _t("encoded-command-variant", "编码变体良性命令", "encoded-command-variant", False, False,
               "脚本包装执行（bash -c/编码串）解码后再入规则匹配"),
        ],
    },
    # ---------------- 字节系（AgentSmith-HIDS：bytedance/AgentSmith-HIDS） ----------------
    "agentsmith": {
        "module": "defense-bypass-agentsmith",
        "display": "AgentSmith-HIDS",
        "vendor": "bytedance",
        "sub_products": ["agentsmith"],
        "indicators": {
            "core": [
                {"id": "agentsmith", "pattern": r"agentsmith"},
                {"id": "smith-agent", "pattern": r"smith[-_/ ]?agent"},
            ],
            # 内核态 LKM：driver/LKM 编译产物 smith.ko（公开仓库命名）
            "driver": [
                {"id": "smith-ko", "pattern": r"^smith(\.ko)?$",
                 "field": "kernel_modules"},
            ],
        },
        "techniques": [
            _t("monitored-path-write", "受监控路径类别良性写入", "monitored-path-write", True, True,
               "file create kprobe 事件接入规则链路，覆盖 /tmp、/dev/shm 类别"),
            _t("whitelist-path-write", "白名单路径类别良性写入", "whitelist-path-write", False, False,
               "监控代理自身目录写入应二次研判而非直接放行"),
            _t("tool-rename-exec", "改名工具执行 echo", "tool-rename-exec", False, True,
               "execve kprobe 事件增加改名执行启发式"),
            _t("benign-dns-query", "良性标记域解析", "dns-query-benign", False, True,
               "DNS query hook 事件入规则（标记域可查）"),
        ],
    },
    # ---------------- veinmind-tools（公开仓库 chaitin/veinmind-tools；规格口径归字节系重点） ----------------
    "veinmind": {
        "module": "defense-bypass-veinmind",
        "display": "veinmind-tools 容器扫描",
        "vendor": "chaitin(公开仓库)——规格口径：字节系重点",
        "sub_products": ["veinmind"],
        "indicators": {
            "core": [
                {"id": "veinmind", "pattern": r"veinmind"},
                {"id": "veinmind-scanner", "pattern":
                    r"veinmind[-_](backdoor|virus|weakpass|sensitive|history|webshell|log4j|cve|malicious|trojan)"},
                {"id": "veinmind-tools", "pattern": r"veinmind[-_/ ]?tools"},
            ],
            "driver": [],
        },
        "techniques": [
            _t("plain-layer-sample", "常规分层 benign 样本", "layered-image-sample", True, False,
               "保持全层解析与内容匹配（不因层数降级）"),
            _t("deep-layer-benign", "深层覆盖 benign 样本", "layered-image-sample", False, False,
               "深层/被覆盖文件同样纳入内容特征匹配（benign 前缀样本名不豁免）"),
            _t("renamed-benign-tool-layer", "改名 benign 工具层", "tool-rename-image-layer", False, False,
               "层内工具按内容/哈希特征检测，不依赖文件名"),
            _t("compressed-benign-sample", "压缩 benign 样本", "compressed-image-sample", False, False,
               "压缩内容解包后递归扫描"),
            _t("whitelist-sample-name", "白名单样本名", "whitelist-sample-name", False, False,
               "收窄扫描排除清单，禁止以样本名前缀豁免"),
        ],
    },
    # ---------------- Falco（falcosecurity/falco） ----------------
    "falco": {
        "module": "defense-bypass-falco",
        "display": "Falco",
        "vendor": "cloud-native",
        "sub_products": ["falco"],
        "indicators": {
            "core": [
                {"id": "falco", "pattern": r"falco"},
            ],
            "driver": [
                {"id": "falco-ko", "pattern": r"^falco(\.ko)?$",
                 "field": "kernel_modules"},
                {"id": "falco-ebpf", "pattern": r"falco[_-]ebpf"},
            ],
            "degraded_markers": [
                {"id": "falco-no-driver", "pattern": r"falco[-_]no[-_]driver"},
            ],
        },
        "techniques": [
            _t("sensitive-path-access", "容器内敏感路径访问良性标记", "sensitive-path-access", True, True,
               "保留默认规则对敏感路径类别读写的告警"),
            _t("monitored-path-write", "受监控路径类别良性写入", "monitored-path-write", True, True,
               "保持 /tmp、/dev/shm 类别写入事件告警"),
            _t("ephemeral-container-marker", "ephemeral 容器良性标记", "ephemeral-container-marker", False, False,
               "默认规则补充 ephemeral_container=true 宏与事件覆盖"),
            _t("ruleset-gap-syntax", "规则集语法缺口路径", "ruleset-gap-syntax", False, False,
               "规则加载校验：宏/字段缺失时显式告警而非静默跳过整条规则"),
            _t("tool-rename-exec", "改名工具执行 echo", "tool-rename-exec", False, True,
               "spawned_process 事件增加改名执行启发式"),
        ],
    },
    # ---------------- Tetragon（cilium/tetragon） ----------------
    "tetragon": {
        "module": "defense-bypass-tetragon",
        "display": "Tetragon",
        "vendor": "cilium",
        "sub_products": ["tetragon"],
        "indicators": {
            "core": [
                {"id": "tetragon", "pattern": r"tetragon"},
                {"id": "tracing-policy", "pattern": r"tracingpolic"},
            ],
            # BPF LSM 可用性（kernel.lsm 含 bpf）
            "driver": [
                {"id": "bpf-lsm", "pattern": r"lsm=\S*bpf|bpf\S*lsm", "field": "kernel_params"},
            ],
        },
        "techniques": [
            _t("lsm-hook-path", "LSM 钩子路径良性标记", "lsm-hook-path", True, True,
               "BPF LSM 策略保持对敏感操作类别的覆盖"),
            _t("exec-marker", "exec 事件良性标记", "tool-rename-exec", True, True,
               "policy match exec 保持启用并覆盖改名执行"),
            _t("policy-unmounted-ns", "策略未挂载命名空间", "namespace-uncovered", False, False,
               "TracingPolicy 命名空间选择器全覆盖，新增 ns 默认继承基线策略"),
            _t("hostnetwork-path", "hostNetwork 路径良性标记", "hostnetwork-path", False, False,
               "补充 hostNetwork=true 工作负载的事件策略"),
        ],
    },
    # ---------------- KubeArmor（kubearmor/kubearmor） ----------------
    "kubearmor": {
        "module": "defense-bypass-kubearmor",
        "display": "KubeArmor",
        "vendor": "kubearmor",
        "sub_products": ["kubearmor"],
        "indicators": {
            "core": [
                {"id": "kubearmor", "pattern": r"kubearmor"},
                {"id": "ka-crd", "pattern": r"kubearmor(host)?polic"},
            ],
            "driver": [],
        },
        "techniques": [
            _t("posture-audit-path", "posture 已覆盖路径良性标记", "posture-audit-path", True, False,
               "namespace annotation posture 保持 audit/block 并接告警"),
            _t("uncovered-namespace", "未覆盖命名空间良性标记", "namespace-uncovered", False, False,
               "部署默认兜底策略，未打 posture 注解的 ns 视为 block"),
            _t("hostnetwork-path", "hostNetwork 路径良性标记", "hostnetwork-path", False, False,
               "KubeArmorHostPolicy 覆盖 hostNetwork 工作负载"),
            _t("default-allow-path", "默认放行路径良性标记", "default-allow-path", False, False,
               "默认 allow 语义改为显式 posture 声明，未命中策略即告警"),
        ],
    },
    # ---------------- 准入（Kyverno / Gatekeeper） ----------------
    "admission": {
        "module": "defense-bypass-admission",
        "display": "准入策略(Kyverno/Gatekeeper)",
        "vendor": "multi",
        "sub_products": ["kyverno", "gatekeeper"],
        "indicators": {
            "core": [
                {"id": "kyverno", "pattern": r"kyverno"},
                {"id": "gatekeeper", "pattern": r"gatekeeper"},
                {"id": "constraint-template", "pattern": r"constrainttemplates?"},
            ],
            "driver": [],
        },
        "techniques": [
            _t("enforced-path", "已 enforce 策略路径良性提交", "enforced-path", True, False,
               "关键策略保持 Enforce 并锁定豁免面"),
            _t("exempt-namespace-path", "豁免命名空间路径", "exempt-namespace-path", False, False,
               "豁免 ns 清单最小化并定期审计（kyverno-config/exemptNamespaceLabels）"),
            _t("audit-mode-path", "Audit 模式路径", "audit-mode-path", False, False,
               "validationFailureAction/enforcementAction 强制 Enforce；Audit 仅允许迁移期并告警"),
            _t("annotation-bypass", "绕过模式/注解路径", "annotation-bypass", False, False,
               "清除可绕过策略的注解（如 pod-resolution 豁免类），webhook 拒绝携带"),
            _t("mutation-order-path", "mutation 顺序路径", "mutation-order-path", False, False,
               "mutate→validate 顺序审计，防止 mutate 规避后续校验"),
        ],
    },
    # ---------------- 镜像扫描（Trivy / grype / veinmind） ----------------
    "imagescan": {
        "module": "defense-bypass-imagescan",
        "display": "镜像扫描(Trivy/grype/veinmind)",
        "vendor": "multi",
        "sub_products": ["trivy", "grype", "veinmind"],
        "indicators": {
            "core": [
                {"id": "trivy", "pattern": r"\btrivy\b"},
                {"id": "grype", "pattern": r"\bgrype\b"},
                {"id": "veinmind", "pattern": r"veinmind"},
                {"id": "syft", "pattern": r"\bsyft\b"},
            ],
            "driver": [],
        },
        "techniques": [
            _t("plain-layer-sample", "常规分层 benign 样本", "layered-image-sample", True, False,
               "全层解析保持（Trivy/grype/veinmind 对齐）"),
            _t("deep-layer-benign", "深层覆盖 benign 样本", "layered-image-sample", False, False,
               "深层/被覆盖文件纳入内容匹配"),
            _t("renamed-benign-tool-layer", "改名 benign 工具层", "tool-rename-image-layer", False, False,
               "按内容/哈希检测层内改名工具"),
            _t("whitelist-sample-name", "白名单样本名", "whitelist-sample-name", False, False,
               "收窄排除清单，禁止样本名豁免"),
            _t("compressed-benign-sample", "压缩 benign 样本", "compressed-image-sample", False, False,
               "压缩内容解包递归扫描"),
        ],
    },
    # ---------------- 主机代理（Wazuh / Osquery） ----------------
    "hostagent": {
        "module": "defense-bypass-hostagent",
        "display": "主机代理(Wazuh/Osquery)",
        "vendor": "multi",
        "sub_products": ["wazuh", "osquery"],
        "indicators": {
            "core": [
                {"id": "wazuh", "pattern": r"wazuh"},
                {"id": "ossec", "pattern": r"ossec"},
                {"id": "osquery", "pattern": r"osquery"},
            ],
            # 健康位：agent 在线（agent_status 名单）
            "driver": [
                {"id": "agent-online", "pattern": r"^online$", "field": "agent_status"},
            ],
        },
        "techniques": [
            _t("monitored-path-write", "受监控路径类别良性写入", "monitored-path-write", True, True,
               "syscheck/监控目录覆盖 /tmp、/dev/shm 类别并保持 agent 在线"),
            _t("ruleset-coverage-gap", "规则集覆盖缺口", "ruleset-coverage-gap", False, False,
               "规则集缺口评估常态化（decoders/rules 对照矩阵）"),
            _t("stopped-agent-window", "agent 停用窗口", "stopped-agent-window", False, False,
               "agent 离线即告警，停用窗口视为盲区并计入 SLA"),
            _t("tool-rename-exec", "改名工具执行 echo", "tool-rename-exec", False, True,
               "命令审计增加改名执行启发式"),
        ],
    },
    # ---------------- 推理面 WAF（ModSecurity / Coraza / 雷池 SafeLine） ----------------
    "waf-inference": {
        "module": "defense-bypass-waf-inference",
        "display": "WAF(ModSecurity/Coraza/雷池)",
        "vendor": "multi",
        "sub_products": ["modsecurity", "coraza", "safeline"],
        "indicators": {
            "core": [
                {"id": "modsecurity", "pattern": r"modsecurity"},
                {"id": "coraza", "pattern": r"coraza"},
                {"id": "safeline", "pattern": r"safeline|ce-waf|雷池"},
                {"id": "crs", "pattern": r"owasp-crs|coreruleset"},
            ],
            "driver": [],
        },
        "techniques": [
            _t("plain-benign-request", "明文 benign 请求", "plain-benign-request", True, False,
               "推理端点保持 CRS 基线与请求观测（与无限查询蒸馏链联动）"),
            _t("encoded-request-variant", "编码变体 benign 请求", "encoded-request-variant", False, False,
               "URL/hex 解码后再入规则匹配"),
            _t("chunked-request-variant", "分块 benign 请求", "chunked-request-variant", False, False,
               "反分块缓冲（拒绝 chunked 拆解绕过）"),
            _t("unicode-request-variant", "Unicode 变体 benign 请求", "unicode-request-variant", False, False,
               "输入规范化（Unicode/大小写折叠）后匹配"),
            _t("oversized-benign-variant", "超长 benign 变体", "oversized-benign-variant", False, False,
               "限制异常头/参数长度，超限直接拒绝而非跳过检查"),
        ],
    },
    # ---------------- 网络可视化（Cilium Hubble / Calico flows） ----------------
    "netobserv": {
        "module": "defense-bypass-netobserv",
        "display": "网络可视化(Hubble/Calico flows)",
        "vendor": "multi",
        "sub_products": ["hubble", "calico"],
        "indicators": {
            "core": [
                {"id": "hubble", "pattern": r"hubble"},
                {"id": "typha", "pattern": r"typha"},
                {"id": "flowlogs", "pattern": r"flow[-_]?logs?"},
            ],
            "driver": [],
        },
        "techniques": [
            _t("pod-path-flow", "常规 pod 路径良性流", "pod-path-flow", True, False,
               "保持 pod↔pod flows 可观测基线"),
            _t("hostnetwork-path", "hostNetwork 路径良性流", "hostnetwork-path", False, False,
               "hostNetwork 流量纳入 Hubble/flows 采集"),
            _t("multi-nic-path", "多网卡路径良性流", "multi-nic-path", False, False,
               "多网卡（SR-IOV/RDMA Multus 附件）接口纳入采集（与多网卡 RDMA 旁路模块互证）"),
            _t("short-lived-flow", "短生命周期良性流", "short-lived-flow", False, False,
               "缩短采样/聚合窗口，短流不丢"),
        ],
    },
}


# --------------------------------------------------------------------------
# 快照语料与指纹
# --------------------------------------------------------------------------
def _corpus(snapshot: dict | None) -> list[tuple[str, str]]:
    """快照 → (顶层字段, 值) 语料；支持 str / list[str|dict] / dict[str,str]。"""
    pairs: list[tuple[str, str]] = []
    for key, val in (snapshot or {}).items():
        if isinstance(val, str):
            pairs.append((key, val))
        elif isinstance(val, (list, tuple)):
            for item in val:
                if isinstance(item, str):
                    pairs.append((key, item))
                elif isinstance(item, dict):
                    hit = False
                    for sub in ("name", "image", "kind", "path", "rule", "id", "status"):
                        sv = item.get(sub)
                        if isinstance(sv, str):
                            pairs.append((key, sv))
                            hit = True
                    if not hit:
                        pairs.append((key, json.dumps(item, ensure_ascii=False)))
        elif isinstance(val, dict):
            for k2, v2 in val.items():
                if isinstance(v2, str):
                    pairs.append((key, f"{k2}={v2}"))
    return pairs


def _ind_match(ind: dict, pairs: list[tuple[str, str]]) -> str | None:
    rx = re.compile(ind["pattern"], re.IGNORECASE)
    field = ind.get("field")
    for top, val in pairs:
        if field is not None and top != field:
            continue
        if rx.search(val):
            return val
    return None


def fingerprint(snapshot: dict | None) -> dict[str, dict]:
    """全产品指纹：{product: {hit, matched, missing_driver, degraded, forced_degraded}}。"""
    pairs = _corpus(snapshot)
    out: dict[str, dict] = {}
    for key, spec in PRODUCT_SPECS.items():
        inds = spec["indicators"]
        matched = [i["id"] for i in inds.get("core", []) if _ind_match(i, pairs)]
        # 内核态/健康指标为「可互相替代的充分信号」：任一命中即非降级
        matched_driver = [i["id"] for i in inds.get("driver", []) if _ind_match(i, pairs)]
        missing_driver = [i["id"] for i in inds.get("driver", []) if i["id"] not in matched_driver]
        driver_down = bool(inds.get("driver")) and not matched_driver
        forced = [i["id"] for i in inds.get("degraded_markers", []) if _ind_match(i, pairs)]
        hit = bool(matched)
        out[key] = {
            "hit": hit,
            "matched": matched,
            "missing_driver": missing_driver if hit else [],
            "forced_degraded": bool(forced),
            "degraded": hit and (driver_down or bool(forced)),
        }
    return out


def indicator_patterns(product_key: str) -> list[str]:
    spec = PRODUCT_SPECS[product_key]
    return [i["pattern"] for grp in ("core", "driver") for i in spec["indicators"].get(grp, [])]


# --------------------------------------------------------------------------
# 良性探针（技术类别级 marker）
# --------------------------------------------------------------------------
_PATH_WRITE_CATS = {
    "monitored-path-write", "whitelist-path-write", "sensitive-path-access",
    "ephemeral-container-marker", "ruleset-gap-syntax", "namespace-uncovered",
    "default-allow-path", "posture-audit-path", "hostnetwork-path",
    "multi-nic-path", "short-lived-flow", "pod-path-flow", "enforced-path",
    "exempt-namespace-path", "audit-mode-path", "annotation-bypass",
    "mutation-order-path", "ruleset-coverage-gap", "stopped-agent-window",
    "lsm-hook-path",
}
_IMAGE_CATS = {
    "layered-image-sample", "tool-rename-image-layer",
    "compressed-image-sample", "whitelist-sample-name",
}
_REQUEST_CATS = {
    "plain-benign-request", "encoded-request-variant", "chunked-request-variant",
    "unicode-request-variant", "oversized-benign-variant", "dns-query-benign",
}


def _request_template(marker: str, category: str) -> dict:
    tpl: dict[str, Any] = {"method": "POST", "url": "/v1/completions", "marker_plain": marker}
    if category == "encoded-request-variant":
        tpl["body_hint"] = urllib.parse.quote(marker, safe="")
    elif category == "unicode-request-variant":
        tpl["body_hint"] = "".join("%%%04X" % ord(c) for c in marker[:24])
    elif category == "chunked-request-variant":
        tpl["body_hint"] = marker[:16] + "\r\n" + marker[16:]
    elif category == "oversized-benign-variant":
        tpl["body_hint"] = marker + "-" + "b" * 2048
    elif category == "dns-query-benign":
        tpl = {"query": "inkblade-benign.marker.invalid", "marker_plain": marker}
    else:
        tpl["body_hint"] = marker
    return tpl


def benign_probe(product_key: str, technique: dict) -> dict:
    marker = f"{SAFE_MARKER_PREFIX}:{product_key}:{technique['id']}"
    cat = technique["category"]
    probe: dict[str, Any] = {
        "technique": technique["id"],
        "category": cat,
        "marker": marker,
        "benign": True,
        "action": f"{technique['name']}（技术类别级 benign marker，仅在授权实验室重放）",
        "write_target": f"{SCRATCH_DIR}/{product_key}-{technique['id']}.marker",
        "exec_template": None,
        "request_template": None,
        "sample_name": None,
    }
    if cat == "tool-rename-exec":
        probe["write_target"] = f"{SCRATCH_DIR}/{technique['id']}-echo"
        probe["exec_template"] = (
            f"cp $(command -v echo) ./{{scratch}}/{technique['id']}-echo"
            f" && ./{{scratch}}/{technique['id']}-echo '{marker}'"
        )
    elif cat == "encoded-command-variant":
        probe["exec_template"] = f"bash -c 'echo {marker}'"
    elif cat in _IMAGE_CATS:
        probe["sample_name"] = f"inkblade-benign/{technique['id']}:lab"
        probe["write_target"] = f"{SCRATCH_DIR}/{technique['id']}-dockerfile"
    elif cat in _REQUEST_CATS:
        probe["request_template"] = _request_template(marker, cat)
    return probe


def benign_probes(product_key: str) -> list[dict]:
    return [benign_probe(product_key, t) for t in PRODUCT_SPECS[product_key]["techniques"]]


# --------------------------------------------------------------------------
# 无害性强制（自检 + 物化遏制）
# --------------------------------------------------------------------------
def _validate_relative(rel: str) -> PurePosixPath:
    if not isinstance(rel, str) or not rel:
        raise ProbeContainmentError(f"非法 write_target: {rel!r}")
    if _DRIVE_RE.match(rel) or rel.startswith(("/", "\\")):
        raise ProbeContainmentError(f"write_target 禁止绝对路径: {rel!r}")
    p = PurePosixPath(rel.replace("\\", "/"))
    if any(part in ("..", "") for part in p.parts if part != "/") or ".." in p.parts:
        raise ProbeContainmentError(f"write_target 禁止路径穿越: {rel!r}")
    return p


def audit_benign(probes: list[dict]) -> list[str]:
    """良性自检：返回问题清单（空 = 无害）。"""
    problems: list[str] = []
    for p in probes:
        tid = p.get("technique", "?")
        marker = str(p.get("marker", ""))
        if not marker.startswith(SAFE_MARKER_PREFIX):
            problems.append(f"{tid}: marker 未带 {SAFE_MARKER_PREFIX} 前缀")
        if not p.get("benign"):
            problems.append(f"{tid}: benign 标志缺失")
        blob = json.dumps(p, ensure_ascii=False).lower()
        for bad in FORBIDDEN_PAYLOAD_PATTERNS:
            if bad.lower() in blob:
                problems.append(f"{tid}: 疑似载荷串 {bad!r}")
        wt = p.get("write_target")
        if wt:
            try:
                _validate_relative(wt)
            except ProbeContainmentError as exc:
                problems.append(f"{tid}: {exc}")
        et = p.get("exec_template")
        if et is not None and ("echo" not in et or SAFE_MARKER_PREFIX not in et):
            problems.append(f"{tid}: exec 模板仅允许 echo benign marker")
        sn = p.get("sample_name")
        if sn is not None and not sn.startswith("inkblade-benign/"):
            problems.append(f"{tid}: 样本名必须 inkblade-benign/ 前缀")
    return problems


def materialize_probes(probes: list[dict], root: Path | str) -> list[Path]:
    """把良性 marker 物化到授权 scratch 目录；越界即抛 ProbeContainmentError。"""
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for p in probes:
        rel = p.get("write_target")
        if not rel:
            continue
        _validate_relative(rel)
        target = (root / rel).resolve()
        if root != target and root not in target.parents:
            raise ProbeContainmentError(f"探针越界: {rel} → {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = p.get("marker", SAFE_MARKER_PREFIX)
        target.write_text(payload + "\n", encoding="utf-8")
        if p.get("exec_template"):
            (target.parent / f"{p['technique']}-replay.txt").write_text(
                p["exec_template"] + "\n", encoding="utf-8")
        if p.get("sample_name"):
            (target.parent / f"{p['technique']}-sample.txt").write_text(
                f"FROM scratch\nCOPY {p['technique']}-dockerfile /{p['sample_name']}\n#{payload}\n",
                encoding="utf-8")
        written.append(target)
    return written


# --------------------------------------------------------------------------
# 两态评估
# --------------------------------------------------------------------------
def _hardening_rule(product: str, state: str, technique: dict) -> str:
    return (f"rule:product={product}:technique={technique['id']}:state={state}"
            f":category={technique['category']}:建议={technique['gap']}")


def assess(product_key: str, snapshot: dict | None = None, state: str | None = None) -> dict:
    spec = PRODUCT_SPECS[product_key]
    fp = fingerprint(snapshot).get(product_key, {})
    if state is None:
        state = "deployed" if fp.get("hit") and not fp.get("degraded") else (
            "degraded" if fp.get("hit") else "absent")
    if state not in STATES:
        raise ValueError(f"未知评估态 {state!r}（可选 {STATES}）")

    techniques = spec["techniques"]
    has_driver_spec = bool(spec["indicators"].get("driver"))
    if state == "deployed":
        detected = [t["id"] for t in techniques if t["detected"]]
    elif state == "degraded":
        detected = [t["id"] for t in techniques if t["detected"] and not t.get("needs_driver")]
    else:
        detected = []
    blindspots = [t["id"] for t in techniques if t["id"] not in detected]

    hardening: list[str] = []
    if state == "absent":
        hardening.append(
            f"rule:product={product_key}:state=absent:category=deployment"
            f":建议=未检出 {spec['display']}——确认是否需要部署；当前技术类别矩阵全盲区")
    elif state == "degraded":
        missing = ",".join(fp.get("missing_driver") or ["driver"])
        hardening.append(
            f"rule:product={product_key}:state=degraded:category=kernel-state"
            f":建议=恢复内核态/健康组件（缺失: {missing}）；降级期间内核态依赖技术全部视为盲区")
    for t in techniques:
        if t["id"] in blindspots and state != "absent":
            hardening.append(_hardening_rule(product_key, state, t))

    matrix = {
        "product": product_key,
        "display": spec["display"],
        "vendor": spec["vendor"],
        "sub_products": spec["sub_products"],
        "state": state,
        "matched_indicators": fp.get("matched", []),
        "missing_driver": fp.get("missing_driver", []) if fp.get("hit") else [],
        "detected": detected,
        "blindspots": blindspots,
        "techniques": [
            {"id": t["id"], "name": t["name"], "category": t["category"],
             "needs_driver": bool(t.get("needs_driver"))}
            for t in techniques
        ],
        "hardening": hardening,
        "benign_only": True,
        "notes": "检出=该技术类别的良性 marker 会被默认规则集识别；盲区=不会；均为实验室可重放断言",
    }
    return {
        "product": product_key,
        "display": spec["display"],
        "module": spec["module"],
        "state": state,
        "detected": detected,
        "blindspots": blindspots,
        "hardening": hardening,
        "probes": benign_probes(product_key),
        "matrix": matrix,
        "has_driver_spec": has_driver_spec,
    }


# --------------------------------------------------------------------------
# 模块入口适配（module run.py 委托）
# --------------------------------------------------------------------------
def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_fixture(product_key: str) -> Path:
    return _repo_root() / "lab" / "defense-deploy" / "fixtures" / f"{product_key}-deployed.json"


def _resolve_snapshot(product_key: str, params: dict) -> dict:
    snap = params.get("deploy_snapshot")
    if isinstance(snap, dict):
        return snap
    fx = params.get("fixture")
    if fx:
        return json.loads(Path(fx).read_text(encoding="utf-8"))
    default = _default_fixture(product_key)
    if default.exists():
        return json.loads(default.read_text(encoding="utf-8"))
    return {}


def run_module_assessment(product_key: str, ctx: dict, params: dict) -> dict:
    """defense-bypass-* 模块通用入口：快照解析→两态评估→{summary, artifacts, findings}。"""
    spec = PRODUCT_SPECS[product_key]
    snapshot = _resolve_snapshot(product_key, params or {})
    report = assess(product_key, snapshot, (params or {}).get("state"))

    artifacts: list[str] = []
    adir = (params or {}).get("artifact_dir")
    if adir is None:
        run_obj = (ctx or {}).get("run")
        if getattr(run_obj, "dir", None) is not None:
            adir = run_obj.dir
    if adir is not None:
        adir = Path(adir)
        adir.mkdir(parents=True, exist_ok=True)
        art = adir / f"defense-bypass-{product_key}-matrix.json"
        art.write_text(json.dumps(report["matrix"], ensure_ascii=False, indent=2), encoding="utf-8")
        artifacts.append(str(art))

    module_key = spec["module"]
    findings = [
        {
            "sev": "info",
            "title": f"[{module_key}] 指纹: {report['display']} = {report['state']}",
            "detail": (f"matched={report['matrix']['matched_indicators']}; "
                       f"missing_driver={report['matrix']['missing_driver']}"),
        },
        {
            "sev": "medium",
            "title": f"[{module_key}] 覆盖矩阵: detected={len(report['detected'])} "
                     f"blindspots={len(report['blindspots'])}",
            "detail": f"detected={report['detected']}; blindspots={report['blindspots']}",
        },
        {
            "sev": "low",
            "title": f"[{module_key}] 硬化建议 ({len(report['hardening'])} 条)",
            "detail": "\n".join(report["hardening"]),
            "hardening": report["hardening"],
        },
    ]
    summary = (f"{report['display']}: state={report['state']} "
               f"detected={len(report['detected'])} blindspots={len(report['blindspots'])} "
               f"hardening={len(report['hardening'])} (benign-only)")
    return {"summary": summary, "artifacts": artifacts, "findings": findings, "report": report}
