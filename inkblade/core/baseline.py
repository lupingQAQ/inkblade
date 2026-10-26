# -*- coding: utf-8 -*-
"""core/baseline.py — 主体/实体基线 + 学习模式 + 抑制规则（FP 调优的 triage 层）。

定位（与 docs/ENTERPRISE-LAB-RESULTS.md 的调优建议 1/2 对应）：
- **检测保持纯净**：基线不修改检测器；命中的发现被**抑制并留痕**（provenance：
  哪条基线/哪条规则、命中样例），可审计、可撤销、可过期——不是把告警删掉。
- **主体基线四类清单**：CI 服务账号 / 安全扫描器 / 平台控制器与调度器 /
  系统绑定与平台命名空间（常规运维噪声的「谁」）。
- **平台工作负载三元组**：(namespace, serviceAccount, image 前缀) 审批式例外，
  对应「按 digest+ns+SA 三元组审批，不按标题静默」的原则；三元组不全匹配不抑制。
- **学习模式**：从历史审计事件流 / 历史 run 发现中按频次 + 仅 2xx 成功动作学习
  allowlist（provenance 带出现次数与时间窗）；**高危动作模式永不学习**
 （防攻击者在学习窗口内高频刷行为把自己「基线化」）。
- **抑制规则三类**：时间窗（维护窗）/ 标签（例外清单 k8s labels）/ 注释
  （annotation 逐例外确认）；规则必须带 reason + created_by 才生效。

边界：基线默认清单是**通用平台形态**，不是客户例外清单；客户环境必须用学习模式
从客户历史重新生成并走审批（docs/ENTERPRISE-LAB-RESULTS.md「未达成」第 4 条）。
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Iterable

# ---------------------------------------------------------------- 默认清单

DEFAULT_CI_SERVICE_ACCOUNTS = (
    "system:serviceaccount:ci:ci-runner",
    "system:serviceaccount:ci:gitlab-runner",
    "system:serviceaccount:jenkins:jenkins",
    "system:serviceaccount:tekton-pipelines:tekton-pipelines-controller",
    "system:serviceaccount:argocd:argocd-application-controller",
)

DEFAULT_SCANNER_SUBJECTS = (
    "system:serviceaccount:security:scanner",
    "system:serviceaccount:security:trivy",
    "system:serviceaccount:security:kube-bench",
    "system:serviceaccount:security:popeye",
)

DEFAULT_CONTROLLER_SUBJECTS = (
    "system:serviceaccount:ml-training:platform-scheduler",
    "system:serviceaccount:ml-platform:platform-operator",
    "system:serviceaccount:kube-system:storage-operator",
    "system:serviceaccount:kube-system:generic-garbage-collector",
    "system:serviceaccount:monitoring:prometheus",
)

# 通配符 ClusterRole 基线（常规平台 operator；客户环境需重审）
DEFAULT_CONTROLLER_ROLES = (
    "platform-operator",
)

# cluster-admin 绑定基线：系统组/系统控制器绑定（system:*），不含任何用户/租户主体
DEFAULT_SYSTEM_BINDINGS = (
    "system:masters",
    "system:kube-scheduler",
    "system:volume-scheduler",
    "system:kube-controller-manager",
)

# 平台命名空间基线：这些命名空间无默认拒绝 NetworkPolicy 属常规形态
DEFAULT_PLATFORM_NAMESPACES = (
    "kube-system", "kube-public", "kube-node-lease",
    "security", "monitoring", "ingress-nginx", "gatekeeper-system",
)

# 平台工作负载三元组：(namespace, serviceAccount, image 前缀)
DEFAULT_PLATFORM_WORKLOADS = (
    {"namespace": "kube-system", "service_account": "aws-node",
     "image_prefix": "602401143452.dkr.ecr", "name_prefix": "aws-node"},
    {"namespace": "kube-system", "service_account": "kube-proxy",
     "image_prefix": "registry.k8s.io/kube-proxy", "name_prefix": "kube-proxy"},
    {"namespace": "kube-system", "service_account": "ebs-csi-node",
     "image_prefix": "public.ecr.aws/ebs-csi-driver", "name_prefix": "ebs-csi-node"},
    {"namespace": "kube-system", "service_account": "azure-cni-agent",
     "image_prefix": "mcr.microsoft.com", "name_prefix": "azure-cni"},
    {"namespace": "security", "service_account": "falco",
     "image_prefix": "falcosecurity/falco", "name_prefix": "falco"},
    {"namespace": "monitoring", "service_account": "node-exporter",
     "image_prefix": "quay.io/prometheus/node-exporter", "name_prefix": "node-exporter"},
    {"namespace": "monitoring", "service_account": "prometheus",
     "image_prefix": "quay.io/prometheus/prometheus", "name_prefix": "prometheus"},
    {"namespace": "ingress-nginx", "service_account": "ingress-nginx",
     "image_prefix": "registry.k8s.io/ingress-nginx", "name_prefix": "controller"},
)

# 学习模式永不放行的动作模式（与 core/auditlog.py 检测器同源）：
# RBAC 绑定铸造 / SA token 铸造 / portforward / 权重 PVC claim 写——即使在学习窗口内
# 高频出现也不得进入 allowlist（防攻击者高频刷行为把自己「基线化」）。
# pods/exec 与 Secret 读**可学习**（CI/扫描器经典噪声形态），但学习产物只是候选，
# 须经 lead 审批 merge 才生效，且抑制留痕可回溯。
NEVER_LEARN_PATTERNS = (
    "create clusterrolebindings", "create rolebindings",
    "create serviceaccounts/token", "create pods/portforward",
    "patch persistentvolumeclaims", "update persistentvolumeclaims",
    "create clusterroles", "create roles",
)


class BaselineError(ValueError):
    """基线/抑制规则配置非法。"""


# ---------------------------------------------------------------- 发现的实体抽取

_KV_RE = re.compile(r"(\w[\w/.:\-]*)=([^\s]+)")
# 标题形态（run 落库只保留 title/detail，evidence 进归档——从 title 提取实体）
_TITLE_PATTERNS = (
    (re.compile(r"^(?P<pod>[\w][\w.\-]*/[\w][\w.\-]*)："), "pod"),
    (re.compile(r"SA 逃逸矩阵：(?P<subject>\S+)\s"), "subject"),
    (re.compile(r"can-i：(?P<subject>\S+)\s"), "subject"),
    (re.compile(r"通配符(?:ClusterRole|Role)：(?P<role>\S+)"), "role"),
    (re.compile(r"cluster-admin 绑定：(?P<binding>\S+)\s*→"), "binding"),
    (re.compile(r"命名空间 (?P<ns>\S+) 的"), "ns"),
)


def finding_entity(finding: dict) -> dict:
    """从 finding 的 evidence（key=value 词法）与 title（标题形态）抽取实体。

    返回 dict：kind → id（如 ``{"subject": "...", "pod": "ns/name"}``）；
    优先级：显式 ``subject`` 字段 > evidence/detail 的 ``subject`` 全量 ID > title 短名。
    run 落库的 finding 只有 title/detail（evidence 进归档），故 title 解析是兜底路径。
    """
    out: dict[str, str] = {}
    subject = str(finding.get("subject") or "")
    if subject:
        out["subject"] = subject
    for holder in (finding.get("evidence") or "", finding.get("detail") or ""):
        for key, value in _KV_RE.findall(str(holder)):
            if key in ("subject", "pod", "ns", "binding", "ClusterRole", "Role"):
                out.setdefault(key, value)
    title = str(finding.get("title") or "")
    for pattern, kind in _TITLE_PATTERNS:
        m = pattern.search(title)
        if m and m.group(kind):
            if kind == "role":
                scope = "ClusterRole" if "ClusterRole" in title[:title.index("：")] else "Role"
                out.setdefault(scope, m.group(kind))
            else:
                out.setdefault(kind, m.group(kind))
    return out


class SuppressionLog:
    """抑制留痕：provenance 逐条记录（source/rule/matched/sample），可审计。"""

    def __init__(self) -> None:
        self.provenance: list[dict] = []

    def add(self, *, source: str, matched: str, rule: str = "", sample: str = "") -> None:
        self.provenance.append({"source": source, "rule": rule or source,
                                "matched": matched, "sample": sample[:160]})

    @property
    def suppressed(self) -> int:
        return sum(int(p["matched"]) for p in self.provenance)

    def entries(self) -> list[dict]:
        return list(self.provenance)

    def summary(self) -> dict:
        by_source: dict[str, int] = {}
        for p in self.provenance:
            by_source[p["source"]] = by_source.get(p["source"], 0) + int(p["matched"])
        return {"suppressed": self.suppressed, "by_source": by_source,
                "provenance": self.entries()}


# ---------------------------------------------------------------- 实体基线

class EntityBaseline:
    """主体/实体基线：默认清单 + 可合并（学习产物/客户审批清单）。"""

    def __init__(self, *, ci_service_accounts: Iterable[str] = (),
                 scanner_subjects: Iterable[str] = (),
                 controller_subjects: Iterable[str] = (),
                 controller_roles: Iterable[str] = (),
                 system_bindings: Iterable[str] = (),
                 platform_namespaces: Iterable[str] = (),
                 platform_workloads: Iterable[dict] = (),
                 system_role_prefixes: Iterable[str] = ("system:controller:",)):
        self.ci_service_accounts = tuple(ci_service_accounts)
        self.scanner_subjects = tuple(scanner_subjects)
        self.controller_subjects = tuple(controller_subjects)
        self.controller_roles = tuple(controller_roles)
        self.system_bindings = tuple(system_bindings)
        self.platform_namespaces = tuple(platform_namespaces)
        self.platform_workloads = tuple(dict(t) for t in platform_workloads)
        self.system_role_prefixes = tuple(system_role_prefixes)

    @classmethod
    def defaults(cls) -> "EntityBaseline":
        return cls(
            ci_service_accounts=DEFAULT_CI_SERVICE_ACCOUNTS,
            scanner_subjects=DEFAULT_SCANNER_SUBJECTS,
            controller_subjects=DEFAULT_CONTROLLER_SUBJECTS,
            controller_roles=DEFAULT_CONTROLLER_ROLES,
            system_bindings=DEFAULT_SYSTEM_BINDINGS,
            platform_namespaces=DEFAULT_PLATFORM_NAMESPACES,
            platform_workloads=DEFAULT_PLATFORM_WORKLOADS,
        )

    # ---------- 序列化 ----------
    def to_doc(self) -> dict:
        return {
            "schema": "trident-entity-baseline/1",
            "ci_service_accounts": list(self.ci_service_accounts),
            "scanner_subjects": list(self.scanner_subjects),
            "controller_subjects": list(self.controller_subjects),
            "controller_roles": list(self.controller_roles),
            "system_bindings": list(self.system_bindings),
            "platform_namespaces": list(self.platform_namespaces),
            "platform_workloads": [dict(t) for t in self.platform_workloads],
        }

    @classmethod
    def from_doc(cls, doc: dict) -> "EntityBaseline":
        if not isinstance(doc, dict):
            raise BaselineError("基线文档须为 dict")
        return cls(
            ci_service_accounts=doc.get("ci_service_accounts") or (),
            scanner_subjects=doc.get("scanner_subjects") or (),
            controller_subjects=doc.get("controller_subjects") or (),
            controller_roles=doc.get("controller_roles") or (),
            system_bindings=doc.get("system_bindings") or (),
            platform_namespaces=doc.get("platform_namespaces") or (),
            platform_workloads=doc.get("platform_workloads") or (),
        )

    def merge(self, learned: dict) -> "EntityBaseline":
        """合并学习/审批产物（list 追加去重；三元组整条追加）。"""
        def _cat(current: tuple, extra: Iterable[str]) -> tuple:
            seen = set(current)
            return current + tuple(s for s in extra if not (s in seen or seen.add(s)))

        self.ci_service_accounts = _cat(self.ci_service_accounts,
                                        learned.get("ci_service_accounts") or [])
        self.controller_subjects = _cat(self.controller_subjects,
                                        learned.get("subjects") or [])
        self.controller_subjects = _cat(self.controller_subjects,
                                        learned.get("controller_subjects") or [])
        self.scanner_subjects = _cat(self.scanner_subjects,
                                     learned.get("scanner_subjects") or [])
        self.controller_roles = _cat(self.controller_roles, learned.get("roles") or [])
        self.system_bindings = _cat(self.system_bindings, learned.get("bindings") or [])
        self.platform_namespaces = _cat(self.platform_namespaces,
                                        learned.get("namespaces") or [])
        workloads = {tuple(sorted(t.items())) for t in self.platform_workloads}
        for t in learned.get("platform_workloads") or []:
            key = tuple(sorted((dict(t)).items()))
            if key not in workloads:
                workloads.add(key)
        self.platform_workloads = tuple(dict(k) for k in workloads)
        return self

    # ---------- 审计主体视图 ----------
    def audit_subjects(self) -> tuple:
        """供 core/auditlog.analyze_events(baseline_subjects=...) 的主体白名单。"""
        return tuple(dict.fromkeys(self.ci_service_accounts + self.scanner_subjects +
                                   self.controller_subjects))

    def all_subjects(self) -> tuple:
        return tuple(dict.fromkeys(self.audit_subjects()))

    # ---------- 抑制 ----------
    def _workload_hit(self, ns: str, name: str, ctx: dict) -> bool:
        info = (ctx.get("pods") or {}).get(f"{ns}/{name}") if ctx else None
        if not info:
            return False
        sa = str(info.get("service_account") or info.get("serviceAccountName") or "")
        image = str(info.get("image") or "")
        for triple in self.platform_workloads:
            if triple.get("namespace") != ns or triple.get("service_account") != sa:
                continue
            prefix = str(triple.get("image_prefix") or "")
            if prefix and not image.startswith(prefix):
                continue
            name_prefix = str(triple.get("name_prefix") or "")
            if name_prefix and not name.startswith(name_prefix):
                continue
            return True
        return False

    def suppress_findings(self, findings: list[dict], ctx: dict | None = None):
        """按基线抑制发现；返回 (kept, SuppressionLog)。检测本身不动。

        语义分层（防止「行为基线」误吞「权限测绘」）：
        - **能力面发现**（can-i 矩阵，evidence 含 ``allowed=``）：只有 CI/扫描器主体
          可抑制——CI 管道合法需要 exec；平台调度器/控制器的宽权限本身仍是风险，
          不得因「它平时就这么跑」而静默。
        - **行为面发现**（审计/逃逸矩阵等其余形态）：全部基线主体可抑制
          （已知主体的例行行为）。
        """
        ctx = ctx or {}
        log = SuppressionLog()
        ci_like = set(self.ci_service_accounts) | set(self.scanner_subjects)
        all_subjects = set(self.audit_subjects())
        role_baseline = set(self.controller_roles)
        kept: list[dict] = []
        counts: dict[tuple, int] = {}
        samples: dict[tuple, str] = {}
        for f in findings:
            ent = finding_entity(f)
            evidence = str(f.get("evidence") or "")
            title = str(f.get("title") or "")
            capability_finding = ("allowed=" in evidence
                                  or title.startswith("can-i：")
                                  or title.startswith("can-i:"))
            subject_hit = (ent.get("subject") in ci_like if capability_finding
                           else ent.get("subject") in all_subjects)
            source = None
            if ent.get("subject") and subject_hit:
                source = "subject-baseline"
            elif ent.get("pod"):
                ns, _, name = ent["pod"].partition("/")
                if self._workload_hit(ns, name, ctx):
                    source = "platform-workload"
            elif (ent.get("ClusterRole") or ent.get("Role")):
                role = ent.get("ClusterRole") or ent.get("Role") or ""
                if role in role_baseline or any(role.startswith(p) for p in self.system_role_prefixes):
                    source = "controller-role-baseline"
            elif ent.get("binding") and ent["binding"] in self.system_bindings:
                source = "system-binding-baseline"
            elif ent.get("ns") and ent["ns"] in self.platform_namespaces:
                source = "platform-namespace-baseline"
            if source is None:
                kept.append(f)
                continue
            key = (source,)
            counts[key] = counts.get(key, 0) + 1
            samples.setdefault(key, str(f.get("title") or f.get("evidence") or ""))
        for (source,), n in sorted(counts.items()):
            log.add(source=source, matched=n, sample=samples.get((source,), ""))
        return kept, log


# ---------------------------------------------------------------- 学习模式

def _succeeded(event: dict) -> bool:
    code = (event.get("responseStatus") or {}).get("code")
    return code is None or (200 <= int(code) < 300)


def _pattern_of(event: dict) -> str:
    ref = event.get("objectRef") or {}
    parts = [str(event.get("verb") or "?").lower(), str(ref.get("resource") or "?")]
    if ref.get("subresource"):
        parts[1] += "/" + str(ref["subresource"])
    return " ".join(parts)


def learn_from_events(events: Iterable[dict], *, min_occurrences: int = 20,
                      ) -> list[dict]:
    """历史审计事件流 → allowlist 候选（按主体×动作形态频次；仅 2xx）。

    - 高危动作模式（NEVER_LEARN_PATTERNS）永不学习；
    - 返回条目带 provenance：occurrences / pattern / source=audit-events，
      供审批后 merge 进 EntityBaseline。
    """
    buckets: dict[tuple[str, str], dict] = {}
    for event in events:
        if not isinstance(event, dict) or not _succeeded(event):
            continue
        pattern = _pattern_of(event)
        if pattern in NEVER_LEARN_PATTERNS:
            continue
        subject = str((event.get("user") or {}).get("username") or
                      event.get("subject_sa") or "")
        if not subject or subject in ("unknown",):
            continue
        entry = buckets.setdefault((subject, pattern),
                                   {"subject": subject, "pattern": pattern,
                                    "occurrences": 0, "source": "audit-events",
                                    "first_seen": "", "last_seen": ""})
        entry["occurrences"] += 1
        ts = str(event.get("stageTimestamp") or "")
        if ts and (not entry["first_seen"] or ts < entry["first_seen"]):
            entry["first_seen"] = ts
        if ts and ts > entry["last_seen"]:
            entry["last_seen"] = ts
    out = [e for e in buckets.values() if e["occurrences"] >= max(1, min_occurrences)]
    return sorted(out, key=lambda e: (-e["occurrences"], e["subject"], e["pattern"]))


def learn_from_runs(runs: Iterable[Any], *, min_runs: int = 2) -> list[dict]:
    """历史 run 的发现 → allowlist 候选（主体在 ≥min_runs 个 run 中重复出现）。

    与事件流学习一样只看「谁」（subject），不看标签；审批由 lead 复核。
    """
    per_subject: dict[str, dict] = {}
    for run in runs:
        run_name = getattr(run, "name", "") or ""
        for f in getattr(run, "findings", None) or []:
            ent = finding_entity(f if isinstance(f, dict) else {})
            subject = ent.get("subject") or ""
            if not subject:
                continue
            entry = per_subject.setdefault(
                subject, {"subject": subject, "runs": 0, "run_names": [],
                          "source": "historical-runs", "pattern": "", "occurrences": 0})
            if run_name and run_name not in entry["run_names"]:
                entry["run_names"].append(run_name)
                entry["runs"] += 1
            entry["occurrences"] += 1
    out = [e for e in per_subject.values() if e["runs"] >= max(2, min_runs)]
    for e in out:
        e["run_names"] = e["run_names"][:20]
    return sorted(out, key=lambda e: (-e["runs"], e["subject"]))


# ---------------------------------------------------------------- 抑制规则

def _parse_ts(value: str) -> float | None:
    try:
        return _dt.datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=_dt.timezone.utc).timestamp()
    except ValueError:
        return None


class SuppressionRule:
    """抑制规则：时间窗 / 标签 / 注释。必须带 reason + created_by（可审计）。"""

    KINDS = ("time_window", "label", "annotation")

    def __init__(self, rule_id: str, kind: str, *, reason: str, created_by: str,
                 match: dict, note: str = ""):
        if kind not in self.KINDS:
            raise BaselineError(f"未知抑制规则类型 {kind}")
        if not str(rule_id).strip() or not str(reason).strip() or not str(created_by).strip():
            raise BaselineError("抑制规则必须带 id/reason/created_by（可审计）")
        self.id = str(rule_id)
        self.kind = kind
        self.reason = str(reason)
        self.created_by = str(created_by)
        self.match = dict(match)
        self.note = str(note)

    # ---------- 构造器 ----------
    @classmethod
    def time_window(cls, rule_id: str, *, start: str, end: str, reason: str,
                    created_by: str, note: str = "") -> "SuppressionRule":
        if _parse_ts(start) is None or _parse_ts(end) is None:
            raise BaselineError("时间窗须为 ISO8601 Z 形态（如 2026-10-25T10:00:00Z）")
        return cls(rule_id, "time_window", reason=reason, created_by=created_by,
                   match={"start": str(start), "end": str(end)}, note=note)

    @classmethod
    def label(cls, rule_id: str, selector: dict, *, reason: str, created_by: str,
              note: str = "") -> "SuppressionRule":
        if not selector:
            raise BaselineError("label 选择器不能为空")
        return cls(rule_id, "label", reason=reason, created_by=created_by,
                   match={"selector": dict(selector)}, note=note)

    @classmethod
    def annotation(cls, rule_id: str, key: str, *, value: str = "", reason: str,
                   created_by: str, until: str = "", note: str = "") -> "SuppressionRule":
        if not key:
            raise BaselineError("annotation 键不能为空")
        match = {"key": str(key), "value": str(value)}
        if until:
            if _parse_ts(until) is None:
                raise BaselineError("until 须为 ISO8601 Z 形态")
            match["until"] = str(until)
        return cls(rule_id, "annotation", reason=reason, created_by=created_by,
                   match=match, note=note)

    # ---------- 匹配 ----------
    def _window_open(self, now: float | None = None) -> bool:
        start = _parse_ts(self.match["start"])
        end = _parse_ts(self.match["end"])
        ref = now if now is not None else _dt.datetime.now(_dt.timezone.utc).timestamp()
        return bool(start is not None and end is not None and start <= ref <= end)

    def matches(self, finding: dict, ctx: dict) -> bool:
        if self.kind == "time_window":
            ts = _parse_ts(str(finding.get("time") or ""))
            if ts is None:
                return False
            start = _parse_ts(self.match["start"])
            end = _parse_ts(self.match["end"])
            return bool(start is not None and end is not None and start <= ts <= end)
        ent = finding_entity(finding)
        pod = ent.get("pod") or ""
        if self.kind == "label":
            labels = ((ctx.get("labels") or {}).get(pod) or {}) if pod else {}
            selector = self.match["selector"]
            return all(str(labels.get(k)) == str(v) for k, v in selector.items()) \
                if labels else False
        if self.kind == "annotation":
            anns = ((ctx.get("annotations") or {}).get(pod) or {}) if pod else {}
            if not anns:
                return False
            if self.match.get("until"):
                until = _parse_ts(self.match["until"])
                now = _dt.datetime.now(_dt.timezone.utc).timestamp()
                if until is not None and now > until:
                    return False
            value = anns.get(self.match["key"])
            if value is None:
                return False
            want = self.match.get("value") or ""
            return str(value).startswith(want) if want else True
        return False

    def to_doc(self) -> dict:
        return {"id": self.id, "kind": self.kind, "reason": self.reason,
                "created_by": self.created_by, "match": self.match, "note": self.note}


class SuppressionEngine:
    """规则集合 → 对发现流做可审计抑制（与 EntityBaseline 正交，可叠加）。"""

    def __init__(self, rules: Iterable[SuppressionRule]):
        self.rules = list(rules)

    @classmethod
    def from_docs(cls, docs: Iterable[dict]) -> "SuppressionEngine":
        rules = []
        for d in docs:
            rules.append(SuppressionRule(d.get("id", ""), d.get("kind", ""),
                                         reason=d.get("reason", ""),
                                         created_by=d.get("created_by", ""),
                                         match=d.get("match") or {},
                                         note=d.get("note", "")))
        return cls(rules)

    def apply(self, findings: list[dict], ctx: dict | None = None):
        ctx = ctx or {}
        log = SuppressionLog()
        kept: list[dict] = []
        hits: dict[str, int] = {}
        samples: dict[str, str] = {}
        for f in findings:
            matched = None
            for rule in self.rules:
                if rule.matches(f, ctx):
                    matched = rule
                    break
            if matched is None:
                kept.append(f)
                continue
            hits[matched.id] = hits.get(matched.id, 0) + 1
            samples.setdefault(matched.id, str(f.get("title") or f.get("evidence") or ""))
        for rule_id, n in sorted(hits.items()):
            log.add(source=f"rule:{rule_id}", matched=n, rule=rule_id,
                    sample=samples.get(rule_id, ""))
        return kept, log
