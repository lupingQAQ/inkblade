# -*- coding: utf-8 -*-
"""`trident pilot` 试点模式：客户 kubeconfig → 只读清点 → 环境画像 + 风险热图 +
分阶段测试计划（窗口/回滚预案）+ pilot-report 与审批清单。

安全边界（硬约束）：
- 默认只读；采集中只允许 ``kubectl get``（verification 面另由模块/链执行）。
- pilot 自身**不执行任何写操作**；``--allow-write`` 只解锁「P2 受控写验证计划」，
  且必须同时通过三闸门：ROE/consent（含范围与窗口）、级别/角色、备份/回滚预案。
- 写动作的实际执行仍走既有 ``trident run`` / ``trident execute``（runner 的
  BackupGate + 逐步回滚），pilot 不提供绕过通道。
- 所有结论标注来源（fixture / live-kubectl）与「非生产规模」边界。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "trident-pilot/1"
PROFILE_SCHEMA = "trident-pilot-profile/1"
PLAN_SCHEMA = "trident-pilot-plan/1"
READ_ONLY_VERBS = ("get", "list", "watch")


class PilotError(ValueError):
    """kubeconfig / snapshot / 参数错误。"""


class PilotGateRefused(Exception):
    """--allow-write 的三闸门拒绝（CLI 退出码 91）。"""

    exit_code = 91


# ------------------------------------------------------------------ YAML subset

def _strip_comment(text: str) -> str:
    out: list[str] = []
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            out.append(ch)
            if ch == quote and (i == 0 or text[i - 1] != "\\"):
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or text[i - 1].isspace()):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(text: str) -> Any:
    s = text.strip()
    if s == "":
        return None
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        body = s[1:-1]
        if s[0] == '"':
            try:
                return json.loads(s)
            except ValueError:
                return body
        return body.replace("''", "'")
    low = s.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    if s.startswith("{") or s.startswith("["):
        try:
            return json.loads(s)
        except ValueError:
            return s
    if re.fullmatch(r"-?\d+", s):
        try:
            return int(s)
        except ValueError:
            pass
    if re.fullmatch(r"-?\d+\.\d+", s):
        try:
            return float(s)
        except ValueError:
            pass
    return s


def _split_key(text: str) -> tuple[str, str] | None:
    quote = ""
    for i, ch in enumerate(text):
        if quote:
            if ch == quote and (i == 0 or text[i - 1] != "\\"):
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].strip(), text[i + 1:].strip()
    return None


def _yaml_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for raw in text.replace("\t", "  ").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#") or raw.strip() in ("---", "..."):
            continue
        content = _strip_comment(raw)
        if not content.strip():
            continue
        indent = len(content) - len(content.lstrip(" "))
        lines.append((indent, content.strip()))
    return lines


def _parse_yaml_subset(text: str) -> Any:
    """kubeconfig 所需的最小 YAML 子集：嵌套 mapping/list、标量、inline {}[]。

    不支持的 YAML 高级特性（锚点/多文档/flow 复杂嵌套）会显式报错，而不是猜。
    """
    lines = _yaml_lines(text)
    if not lines:
        return {}
    if lines[0][1].startswith("- "):
        value, idx = _parse_list(lines, 0, lines[0][0])
    else:
        value, idx = _parse_map(lines, 0, lines[0][0])
    if idx != len(lines):
        raise PilotError(f"YAML 解析未消费完（第 {idx + 1} 行附近）")
    return value


def _parse_block(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[Any, int]:
    if i >= len(lines):
        return None, i
    if lines[i][1].startswith("-") and lines[i][0] == indent:
        return _parse_list(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_map(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[dict, int]:
    out: dict[str, Any] = {}
    while i < len(lines):
        cur_indent, content = lines[i]
        if cur_indent < indent or (cur_indent == indent and content.startswith("-")):
            break
        if cur_indent > indent:
            raise PilotError(f"YAML 缩进异常（line {i + 1}: {content!r}）")
        pair = _split_key(content)
        if pair is None:
            raise PilotError(f"YAML 期望 key: value（line {i + 1}: {content!r}）")
        key, value = pair
        i += 1
        if value:
            out[key] = _scalar(value)
            continue
        if i < len(lines) and lines[i][0] > cur_indent:
            child, i = _parse_block(lines, i, lines[i][0])
            out[key] = child
        elif i < len(lines) and lines[i][0] == cur_indent and lines[i][1].startswith("-"):
            child, i = _parse_list(lines, i, cur_indent)
            out[key] = child
        else:
            out[key] = None
    return out, i


def _parse_list(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[list, int]:
    out: list[Any] = []
    while i < len(lines):
        cur_indent, content = lines[i]
        if cur_indent != indent or not content.startswith("-"):
            break
        rest = content[1:].strip()
        i += 1
        if not rest:
            if i < len(lines) and lines[i][0] > cur_indent:
                item, i = _parse_block(lines, i, lines[i][0])
            else:
                item = None
            out.append(item)
            continue
        pair = _split_key(rest)
        if pair is None:
            out.append(_scalar(rest))
            continue
        item: dict[str, Any] = {}
        key, value = pair
        if value:
            item[key] = _scalar(value)
        elif i < len(lines) and lines[i][0] > cur_indent + 1:
            child, i = _parse_block(lines, i, lines[i][0])
            item[key] = child
        else:
            item[key] = None
        # 列表项内同一 mapping 的后续键（缩进 = list indent + 2）
        item_indent = cur_indent + 2
        while i < len(lines) and lines[i][0] == item_indent and not lines[i][1].startswith("-"):
            pair2 = _split_key(lines[i][1])
            if pair2 is None:
                break
            k2, v2 = pair2
            i += 1
            if v2:
                item[k2] = _scalar(v2)
            elif i < len(lines) and lines[i][0] > item_indent:
                child, i = _parse_block(lines, i, lines[i][0])
                item[k2] = child
            else:
                item[k2] = None
        out.append(item)
    return out, i


# ------------------------------------------------------------------ kubeconfig

def parse_kubeconfig(path: str | Path, *, stdlib_only: bool = False) -> dict:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PilotError(f"读取 kubeconfig 失败：{p}（{exc}）") from exc
    if p.suffix.lower() == ".json" or text.lstrip().startswith("{"):
        try:
            doc = json.loads(text)
        except ValueError as exc:
            raise PilotError(f"kubeconfig JSON 非法：{p}") from exc
    elif not stdlib_only:
        try:
            import yaml  # type: ignore

            doc = yaml.safe_load(text)
        except ImportError:
            doc = _parse_yaml_subset(text)
        except Exception as exc:  # noqa: BLE001 - YAML 语法错误统一转 PilotError
            raise PilotError(f"kubeconfig YAML 非法：{p}（{exc}）") from exc
    else:
        doc = _parse_yaml_subset(text)
    if not isinstance(doc, dict):
        raise PilotError(f"kubeconfig 顶层不是 mapping：{p}")
    for key in ("clusters", "contexts", "users"):
        if doc.get(key) is not None and not isinstance(doc[key], list):
            raise PilotError(f"kubeconfig {key} 不是列表：{p}")
    return doc


def _auth_kind(user: dict) -> str:
    user = user or {}
    if user.get("token") or user.get("tokenFile"):
        return "token"
    if user.get("client-certificate") or user.get("client-certificate-data"):
        return "client-cert"
    if user.get("exec"):
        return "exec"
    if user.get("auth-provider"):
        return "auth-provider"
    if user.get("username") or user.get("password"):
        return "basic"
    return "none"


def merge_kubeconfigs(paths: Iterable[str | Path], *, stdlib_only: bool = False) -> dict:
    paths = [Path(p) for p in paths]
    if not paths:
        raise PilotError("至少需要一个 kubeconfig")
    clusters: dict[str, dict] = {}
    users: dict[str, dict] = {}
    contexts: dict[str, dict] = {}
    conflicts: list[dict] = []
    warnings: list[str] = []
    duplicate_context_names: list[str] = []

    for path in paths:
        doc = parse_kubeconfig(path, stdlib_only=stdlib_only)
        source = path.name
        for entry in doc.get("clusters") or []:
            name = str((entry or {}).get("name") or "")
            cluster = (entry or {}).get("cluster") or {}
            if not name:
                warnings.append(f"{source}: 忽略无 name 的 cluster")
                continue
            record = {
                "name": name,
                "server": str(cluster.get("server") or ""),
                "insecure_skip_tls_verify": bool(cluster.get("insecure-skip-tls-verify")),
                "source": source,
            }
            old = clusters.get(name)
            if old and old["server"] != record["server"]:
                conflicts.append({
                    "kind": "cluster", "name": name,
                    "servers": sorted({old["server"], record["server"]}),
                    "sources": sorted({old["source"], source}),
                    "chosen": record["server"],
                })
            clusters[name] = record
        for entry in doc.get("users") or []:
            name = str((entry or {}).get("name") or "")
            if not name:
                continue
            user = (entry or {}).get("user") or {}
            auth = _auth_kind(user)
            old = users.get(name)
            if old and old["auth"] != auth:
                conflicts.append({
                    "kind": "user", "name": name,
                    "auth": sorted({old["auth"], auth}),
                    "sources": sorted({old["source"], source}),
                    "chosen": auth,
                })
            users[name] = {"name": name, "auth": auth, "source": source}
        for entry in doc.get("contexts") or []:
            name = str((entry or {}).get("name") or "")
            ctx = (entry or {}).get("context") or {}
            if not name:
                warnings.append(f"{source}: 忽略无 name 的 context")
                continue
            cluster_name = str(ctx.get("cluster") or "")
            user_name = str(ctx.get("user") or "")
            cluster = clusters.get(cluster_name) or {}
            record = {
                "name": name,
                "cluster": cluster_name,
                "user": user_name,
                "namespace": str(ctx.get("namespace") or "default"),
                "server": cluster.get("server", ""),
                "auth": (users.get(user_name) or {}).get("auth", "none"),
                "source": source,
            }
            old = contexts.get(name)
            if old:
                duplicate_context_names.append(name)
                if old["cluster"] != record["cluster"] or old["server"] != record["server"]:
                    conflicts.append({
                        "kind": "context", "name": name,
                        "clusters": sorted({old["cluster"], record["cluster"]}),
                        "sources": sorted({old["source"], source}),
                        "chosen": f"{record['cluster']}@{record['server']}",
                    })
                if old.get("current") and not record.get("current"):
                    record["current"] = True
            record["current"] = name == str(doc.get("current-context") or "")
            if old and old.get("current"):
                record["current"] = True
            contexts[name] = record

    if not contexts:
        raise PilotError("kubeconfig 合并后没有 context")
    if conflicts:
        warnings.append(f"发现 {len(conflicts)} 个同名资源冲突；扫描按后加载文件为准")
    if duplicate_context_names:
        warnings.append("重复 context 名：" + ", ".join(sorted(set(duplicate_context_names))))
    return {
        "schema": "trident-kubeconfig-inventory/1",
        "source_files": [p.name for p in paths],
        "context_count": len(contexts),
        "cluster_count": len(clusters),
        "user_count": len(users),
        "contexts": sorted(contexts.values(), key=lambda c: c["name"]),
        "clusters": sorted(clusters.values(), key=lambda c: c["name"]),
        "users": sorted(users.values(), key=lambda u: u["name"]),
        "conflicts": conflicts,
        "warnings": warnings,
    }


# ------------------------------------------------------------------ snapshots

_SNAPSHOT_KEYS = (
    "pods", "services", "networkpolicies", "roles", "rolebindings", "clusterroles",
    "clusterrolebindings", "ingresses", "nodes", "serviceaccounts", "cani", "pvs",
    "secrets", "namespaces", "deployments", "statefulsets", "daemonsets",
)


def normalize_snapshot(raw: dict, *, context: str = "", source: str = "fixture") -> dict:
    if not isinstance(raw, dict):
        raise PilotError("snapshot 不是 JSON object")
    snap = {key: raw.get(key) or [] for key in _SNAPSHOT_KEYS}
    snap["source"] = str(raw.get("source") or source)
    snap["context"] = str(raw.get("context") or context)
    snap["collected_at"] = str(raw.get("collected_at") or "")
    for key in ("defenses", "metadata", "provider", "k8s_version"):
        if key in raw:
            snap[key] = raw[key]
    if isinstance(raw.get("defenses"), dict):
        snap["defenses"] = raw["defenses"]
    return snap


def load_snapshot_bundle(paths: Iterable[str | Path]) -> list[dict]:
    bundle: list[dict] = []
    for item in paths:
        p = Path(item)
        if p.is_dir():
            files = sorted(p.glob("*.json"))
            for f in files:
                if f.name in ("ground-truth.json", "defenses.json"):
                    continue
                bundle.extend(load_snapshot_bundle([f]))
            continue
        if not p.is_file():
            raise PilotError(f"snapshot 不存在：{p}")
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise PilotError(f"snapshot JSON 非法：{p}") from exc
        if isinstance(doc, dict) and isinstance(doc.get("clusters"), list):
            for entry in doc["clusters"]:
                ctx = str(entry.get("context") or entry.get("name") or "")
                snap = normalize_snapshot(entry.get("snapshot") or {}, context=ctx,
                                          source=str(entry.get("source") or "fixture"))
                bundle.append({"context": ctx or snap["context"] or p.stem,
                               "snapshot": snap, "source": snap["source"]})
            continue
        if isinstance(doc, dict) and isinstance(doc.get("snapshot"), dict):
            ctx = str(doc.get("context") or p.stem)
            snap = normalize_snapshot(doc["snapshot"], context=ctx,
                                      source=str(doc.get("source") or "fixture"))
            bundle.append({"context": ctx, "snapshot": snap, "source": snap["source"]})
            continue
        ctx = str(doc.get("context") or p.stem) if isinstance(doc, dict) else p.stem
        snap = normalize_snapshot(doc, context=ctx, source=str((doc or {}).get("source") or "fixture"))
        bundle.append({"context": ctx, "snapshot": snap, "source": snap["source"]})
    if not bundle:
        raise PilotError("没有可用 snapshot")
    return bundle


# ------------------------------------------------------------------ kubectl read-only collector

class KubectlCollector:
    """只读 kubectl 采集器：命令白名单固定为 ``get``，不接收任意 verb。"""

    def __init__(self, kubectl: str | list[str] = "kubectl", *, timeout: int = 30):
        self.kubectl = [kubectl] if isinstance(kubectl, str) else list(kubectl)
        self.timeout = timeout
        self.calls: list[dict] = []

    def _get(self, kubeconfig: str | Path, context: str, *args: str) -> dict:
        cmd = [*self.kubectl, "--kubeconfig", str(kubeconfig), "--context", context,
               "get", *args, "-o", "json"]
        started = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=self.timeout)
        self.calls.append({"argv": cmd[1:], "rc": proc.returncode,
                           "ms": round((time.time() - started) * 1000, 1)})
        if proc.returncode != 0:
            raise PilotError(f"kubectl {' '.join(args)} 失败（{proc.returncode}）：{proc.stderr.strip()[:300]}")
        try:
            return json.loads(proc.stdout or "{}")
        except ValueError as exc:
            raise PilotError(f"kubectl {' '.join(args)} 输出非 JSON") from exc

    @staticmethod
    def _items(doc: dict) -> list[dict]:
        return doc.get("items", []) if isinstance(doc, dict) else []

    def collect(self, kubeconfig: str | Path, context: str) -> dict:
        ns = ["--all-namespaces"]
        get = lambda *args: self._get(kubeconfig, context, *args)
        pods = []
        for p in self._items(get("pods", *ns)):
            meta, spec, status = p.get("metadata", {}), p.get("spec", {}), p.get("status", {})
            pods.append({
                "namespace": meta.get("namespace", "default"), "name": meta.get("name"),
                "labels": meta.get("labels", {}), "nodeName": spec.get("nodeName"),
                "hostNetwork": bool(spec.get("hostNetwork")), "hostPID": bool(spec.get("hostPID")),
                "hostIPC": bool(spec.get("hostIPC")),
                "serviceAccountName": spec.get("serviceAccountName"),
                "phase": status.get("phase"), "podIP": status.get("podIP"),
                "containers": [{
                    "name": c.get("name"), "image": c.get("image"),
                    "securityContext": c.get("securityContext", {}),
                    "volumeMounts": c.get("volumeMounts", []),
                    "command": c.get("command", []), "args": c.get("args", []),
                } for c in spec.get("containers", [])],
                "volumes": [{
                    "name": v.get("name"), "hostPath": v.get("hostPath"),
                    "configMap": v.get("configMap"), "secret": v.get("secret"),
                    "emptyDir": v.get("emptyDir"),
                    "persistentVolumeClaim": v.get("persistentVolumeClaim"),
                } for v in spec.get("volumes", [])],
                "tolerations": spec.get("tolerations", []),
            })
        services = []
        for s in self._items(get("services", *ns)):
            meta, spec = s.get("metadata", {}), s.get("spec", {})
            services.append({
                "namespace": meta.get("namespace", "default"), "name": meta.get("name"),
                "type": spec.get("type", "ClusterIP"), "clusterIP": spec.get("clusterIP"),
                "externalIPs": spec.get("externalIPs") or [], "selector": spec.get("selector") or {},
                "labels": meta.get("labels", {}),
                "ports": [{"name": p.get("name"), "port": p.get("port"),
                           "targetPort": p.get("targetPort"), "nodePort": p.get("nodePort"),
                           "protocol": p.get("protocol", "TCP")} for p in spec.get("ports", [])],
            })
        netpols = []
        for n in self._items(get("networkpolicies", *ns)):
            meta, spec = n.get("metadata", {}), n.get("spec", {})
            netpols.append({
                "namespace": meta.get("namespace", "default"), "name": meta.get("name"),
                "podSelector": spec.get("podSelector") or {},
                "policyTypes": spec.get("policyTypes", []),
                "ingress": spec.get("ingress") or [], "egress": spec.get("egress") or [],
            })
        def roles(key: str, cluster_scoped: bool) -> list[dict]:
            out = []
            for r in self._items(get(key, *( [] if cluster_scoped else ns))):
                meta = r.get("metadata", {})
                out.append({"namespace": None if cluster_scoped else meta.get("namespace", "default"),
                            "name": meta.get("name"), "rules": r.get("rules", [])})
            return out
        def bindings(key: str, cluster_scoped: bool) -> list[dict]:
            out = []
            for b in self._items(get(key, *( [] if cluster_scoped else ns))):
                meta, ref = b.get("metadata", {}), b.get("roleRef", {})
                out.append({"namespace": None if cluster_scoped else meta.get("namespace", "default"),
                            "name": meta.get("name"), "role": ref.get("name"),
                            "roleKind": ref.get("kind"), "subjects": b.get("subjects", [])})
            return out
        ingresses = []
        for ing in self._items(get("ingresses", *ns)):
            meta, spec = ing.get("metadata", {}), ing.get("spec", {})
            for rule in spec.get("rules", []) or [{"host": None}]:
                for path in rule.get("http", {}).get("paths", []) or [{}]:
                    svc = path.get("backend", {}).get("service", {})
                    ingresses.append({"namespace": meta.get("namespace", "default"),
                                      "name": meta.get("name"), "host": rule.get("host") or "*",
                                      "path": path.get("path", "/"), "service": svc.get("name"),
                                      "port": (svc.get("port") or {}).get("number")})
        nodes = []
        for n in self._items(get("nodes")):
            meta, status = n.get("metadata", {}), n.get("status", {})
            nodes.append({"name": meta.get("name"), "labels": meta.get("labels", {}),
                          "capacity": status.get("capacity", {}),
                          "conditions": [c.get("type") for c in status.get("conditions", [])
                                         if c.get("status") == "True"]})
        pvs = []
        for pv in self._items(get("pv")):
            meta, spec = pv.get("metadata", {}), pv.get("spec", {})
            pvs.append({"name": meta.get("name"), "capacity": spec.get("capacity", {}),
                        "claim": (spec.get("claimRef") or {}).get("name"),
                        "namespace": (spec.get("claimRef") or {}).get("namespace")})
        return normalize_snapshot({
            "source": "live-kubectl", "context": context,
            "pods": pods, "services": services, "networkpolicies": netpols,
            "roles": roles("roles", False), "rolebindings": bindings("rolebindings", False),
            "clusterroles": roles("clusterroles", True),
            "clusterrolebindings": bindings("clusterrolebindings", True),
            "ingresses": ingresses, "nodes": nodes, "pvs": pvs,
            "serviceaccounts": [{"namespace": i.get("metadata", {}).get("namespace", "default"),
                                 "name": i.get("metadata", {}).get("name")}
                                for i in self._items(get("serviceaccounts", *ns))],
            "secrets": [{"namespace": i.get("metadata", {}).get("namespace", "default"),
                         "name": i.get("metadata", {}).get("name")}
                        for i in self._items(get("secrets", *ns))],
            "deployments": self._items(get("deployments", *ns)),
            "statefulsets": self._items(get("statefulsets", *ns)),
            "daemonsets": self._items(get("daemonsets", *ns)),
            "cani": [],
        }, context=context, source="live-kubectl")


# ------------------------------------------------------------------ profile

_WEIGHT_RE = re.compile(r"(weight|weights|model[-_]?weights|hf[-_]?cache|checkpoint|ckpt)", re.I)
_GPU_KEYS = ("nvidia.com/gpu", "amd.com/gpu", "gpu.intel.com/i915")


def _pod_is_privileged(pod: dict) -> bool:
    return any((c.get("securityContext") or {}).get("privileged") for c in pod.get("containers", []))


def _pod_host_paths(pod: dict) -> list[str]:
    return [str((v.get("hostPath") or {}).get("path")) for v in pod.get("volumes", [])
            if (v.get("hostPath") or {}).get("path")]


def _ns_has_netpol(snapshot: dict, ns: str) -> bool:
    return any(p.get("namespace") == ns and not p.get("podSelector") and
               "Ingress" in (p.get("policyTypes") or ["Ingress"])
               for p in snapshot.get("networkpolicies", []))


def _cluster_stats(record: dict) -> dict:
    snap = record["snapshot"]
    pods = snap.get("pods", [])
    nodes = snap.get("nodes", [])
    services = snap.get("services", [])
    namespaces = sorted({p.get("namespace", "default") for p in pods})
    gpu_nodes = 0
    gpu_total = 0
    for node in nodes:
        cap = node.get("capacity") or {}
        found = 0
        for key in _GPU_KEYS:
            try:
                found += int(float(cap.get(key) or 0))
            except (TypeError, ValueError):
                pass
        if found:
            gpu_nodes += 1
            gpu_total += found
    privileged = [p for p in pods if _pod_is_privileged(p)]
    host_paths = [p for p in pods if _pod_host_paths(p)]
    host_network = [p for p in pods if p.get("hostNetwork")]
    node_ports = [s for s in services if s.get("type") == "NodePort"]
    load_balancers = [s for s in services if s.get("type") == "LoadBalancer"]
    wildcard_roles = []
    for role in snap.get("clusterroles", []) + snap.get("roles", []):
        if any("*" in (r.get("verbs") or []) or "*" in (r.get("resources") or [])
               or "*" in (r.get("apiGroups") or []) for r in role.get("rules", [])):
            wildcard_roles.append(role)
    admin_bindings = [b for b in snap.get("clusterrolebindings", []) + snap.get("rolebindings", [])
                      if b.get("role") == "cluster-admin"]
    weight_pvs = [pv for pv in snap.get("pvs", []) if _WEIGHT_RE.search(str(pv.get("name") or ""))]
    weight_claims = [p for p in pods if any(_WEIGHT_RE.search(str((v.get("persistentVolumeClaim") or {}).get("claimName") or ""))
                                           for v in p.get("volumes", []))]
    unisolated = [ns for ns in namespaces if not _ns_has_netpol(snap, ns)]
    defenses = snap.get("defenses") or {}
    kyverno_policies = (defenses.get("kyverno") or {}).get("policies") or []
    falco_rules = (defenses.get("falco") or {}).get("rules") or []
    provider = str(snap.get("provider") or "")
    if not provider:
        labels = {}
        for node in nodes:
            labels.update(node.get("labels") or {})
        if "eks.amazonaws.com/nodegroup" in labels:
            provider = "aws-eks"
        elif "cloud.google.com/gke-nodepool" in labels:
            provider = "gcp-gke"
        elif "kubernetes.azure.com/agentpool" in labels:
            provider = "azure-aks"
        elif "node.kubernetes.io/instance-type" in labels:
            provider = "self-managed"
        else:
            provider = "unknown"
    return {
        "context": record["context"],
        "source": record.get("source", "fixture"),
        "provider": provider,
        "k8s_version": str(snap.get("k8s_version") or ""),
        "nodes": len(nodes),
        "gpu_nodes": gpu_nodes,
        "gpus": gpu_total,
        "namespaces": namespaces,
        "namespace_count": len(namespaces),
        "pods": len(pods),
        "services": len(services),
        "privileged_pods": len(privileged),
        "host_path_pods": len(host_paths),
        "host_network_pods": len(host_network),
        "node_ports": len(node_ports),
        "load_balancers": len(load_balancers),
        "wildcard_roles": len(wildcard_roles),
        "cluster_admin_bindings": len(admin_bindings),
        "netpol_namespaces": sum(1 for ns in namespaces if _ns_has_netpol(snap, ns)),
        "unisolated_namespaces": unisolated,
        "weight_pvs": len(weight_pvs),
        "weight_claim_pods": len(weight_claims),
        "secrets": len(snap.get("secrets", [])),
        "inference_services": [s.get("name") for s in services
                               if re.search(r"(vllm|sglang|triton|ray|inference|gateway|llm)",
                                            str(s.get("name") or ""), re.I)],
        "kyverno_policies": len(kyverno_policies),
        "kyverno_enforced": sum(1 for p in kyverno_policies
                                if str(p.get("status") or "").lower() in ("enforced", "enforce")),
        "falco_rules": len(falco_rules),
        "falco_loaded": sum(1 for r in falco_rules if r.get("loaded")),
        "cani_entries": len(snap.get("cani", [])),
        "findings": 0,
    }


def _risk_findings(records: list[dict]) -> list[dict]:
    out: list[dict] = []
    for record in records:
        snap = record["snapshot"]
        ctx = record["context"]
        for pod in snap.get("pods", []):
            ns = pod.get("namespace", "default")
            name = pod.get("name", "?")
            if _pod_is_privileged(pod):
                out.append({"severity": "high", "category": "工作负载逃逸面",
                            "title": f"特权容器：{ns}/{name}",
                            "evidence": f"context={ctx} pod={ns}/{name} privileged=true"})
            for hp in _pod_host_paths(pod):
                sev = "critical" if any(x in hp for x in ("docker.sock", "containerd.sock", "/proc", "/sys")) else "medium"
                out.append({"severity": sev, "category": "工作负载逃逸面",
                            "title": f"hostPath 挂载：{ns}/{name} → {hp}",
                            "evidence": f"context={ctx} pod={ns}/{name} hostPath={hp}"})
            if pod.get("hostPID"):
                out.append({"severity": "high", "category": "工作负载逃逸面",
                            "title": f"hostPID：{ns}/{name}",
                            "evidence": f"context={ctx} pod={ns}/{name} hostPID=true"})
        for role in snap.get("clusterroles", []) + snap.get("roles", []):
            if any("*" in (r.get("verbs") or []) or "*" in (r.get("resources") or [])
                   for r in role.get("rules", [])):
                out.append({"severity": "critical", "category": "身份与 RBAC",
                            "title": f"通配符角色：{role.get('name')}",
                            "evidence": f"context={ctx} role={role.get('name')}"})
        for b in snap.get("clusterrolebindings", []) + snap.get("rolebindings", []):
            if b.get("role") == "cluster-admin":
                subjects = ", ".join(str(s.get("name")) for s in b.get("subjects", []))
                if "system:masters" not in subjects:
                    out.append({"severity": "critical", "category": "身份与 RBAC",
                                "title": f"cluster-admin 非系统绑定：{b.get('name')} → {subjects}",
                                "evidence": f"context={ctx} binding={b.get('name')}"})
        for svc in snap.get("services", []):
            if svc.get("type") in ("NodePort", "LoadBalancer"):
                out.append({"severity": "medium" if svc.get("type") == "NodePort" else "high",
                            "category": "暴露面",
                            "title": f"{svc.get('type')}：{svc.get('namespace')}/{svc.get('name')}",
                            "evidence": f"context={ctx} ports=" +
                                        ",".join(str(p.get("port")) for p in svc.get("ports", []))})
        pods_by_ns: dict[str, int] = {}
        for pod in snap.get("pods", []):
            pods_by_ns[pod.get("namespace", "default")] = pods_by_ns.get(pod.get("namespace", "default"), 0) + 1
        for ns in sorted(pods_by_ns):
            if not _ns_has_netpol(snap, ns):
                out.append({"severity": "high", "category": "网络分区",
                            "title": f"命名空间无默认拒绝 NetworkPolicy：{ns}",
                            "evidence": f"context={ctx} ns={ns} pods={pods_by_ns[ns]}"})
        defenses = snap.get("defenses") or {}
        kyverno = (defenses.get("kyverno") or {}).get("policies") or []
        missing_kyverno = [p for p in kyverno if str(p.get("status") or "").lower() not in ("enforced", "enforce")]
        if missing_kyverno:
            out.append({"severity": "high", "category": "检测与准入",
                        "title": f"Kyverno 未全部 Enforce（{len(missing_kyverno)}/{len(kyverno)} 非强制）",
                        "evidence": f"context={ctx} policies=" +
                                    ",".join(f"{p.get('name')}:{p.get('status')}" for p in missing_kyverno)})
        falco = (defenses.get("falco") or {}).get("rules") or []
        missing_falco = [r for r in falco if not r.get("loaded")]
        if missing_falco:
            out.append({"severity": "medium", "category": "检测与准入",
                        "title": f"Falco 规则未加载（{len(missing_falco)}/{len(falco)}）",
                        "evidence": f"context={ctx} rules=" +
                                    ",".join(str(r.get("name")) for r in missing_falco)})
        for pv in snap.get("pvs", []):
            if _WEIGHT_RE.search(str(pv.get("name") or "")):
                out.append({"severity": "medium", "category": "模型与数据面",
                            "title": f"权重/检查点 PVC：{pv.get('name')}",
                            "evidence": f"context={ctx} pv={pv.get('name')}"})
    return out


def build_profile(inventory: dict, snapshots: list[dict]) -> dict:
    records = []
    for item in snapshots:
        record = dict(item)
        record["snapshot"] = normalize_snapshot(record.get("snapshot") or {},
                                                context=record.get("context", ""),
                                                source=str(record.get("source") or "fixture"))
        records.append(record)
    if not records:
        raise PilotError("没有 snapshot 可画像")
    clusters = [_cluster_stats(r) for r in records]
    findings = _risk_findings(records)
    for cluster in clusters:
        cluster["findings"] = sum(1 for f in findings
                                  if f["evidence"].startswith(f"context={cluster['context']}"))
    totals = {
        "clusters": len(clusters),
        "contexts": inventory.get("context_count", len(clusters)),
        "nodes": sum(c["nodes"] for c in clusters),
        "gpu_nodes": sum(c["gpu_nodes"] for c in clusters),
        "gpus": sum(c["gpus"] for c in clusters),
        "namespaces": sum(c["namespace_count"] for c in clusters),
        "pods": sum(c["pods"] for c in clusters),
        "secrets": sum(c["secrets"] for c in clusters),
        "findings": len(findings),
        "providers": sorted({c["provider"] for c in clusters}),
    }
    signals: dict[str, list[str]] = {k: [] for k in (
        "身份与 RBAC", "网络分区", "工作负载逃逸面", "模型与数据面",
        "检测与准入", "暴露面", "多租户隔离",
    )}
    for f in findings:
        cat = f["category"]
        if cat in signals:
            signals[cat].append(f["title"])
    # 多租户隔离：tenant-* 命名空间是否被默认拒绝策略覆盖
    for c in clusters:
        for ns in c["namespaces"]:
            if ns.startswith("tenant-") and ns in c["unisolated_namespaces"]:
                signals["多租户隔离"].append(f"context={c['context']} 租户命名空间 {ns} 未被默认拒绝覆盖")
    scores = {
        "身份与 RBAC": min(100, sum(c["wildcard_roles"] for c in clusters) * 20
                          + sum(c["cluster_admin_bindings"] for c in clusters) * 12),
        "网络分区": min(100, sum(len(c["unisolated_namespaces"]) for c in clusters) * 14),
        "工作负载逃逸面": min(100, sum(c["privileged_pods"] + c["host_path_pods"] * 2 +
                                      c["host_network_pods"] for c in clusters) * 8),
        "模型与数据面": min(100, sum(c["weight_pvs"] + c["weight_claim_pods"] for c in clusters) * 12
                          + sum(c["secrets"] for c in clusters)),
        "检测与准入": min(100, (sum(c["kyverno_policies"] - c["kyverno_enforced"] for c in clusters)
                               + sum(c["falco_rules"] - c["falco_loaded"] for c in clusters)) * 16),
        "暴露面": min(100, sum(c["node_ports"] * 10 + c["load_balancers"] * 18 for c in clusters)),
        "多租户隔离": min(100, sum(1 for c in clusters for ns in c["namespaces"]
                                    if ns.startswith("tenant-") and ns in c["unisolated_namespaces"]) * 30),
    }
    heatmap = []
    for cat in ("身份与 RBAC", "网络分区", "工作负载逃逸面", "模型与数据面",
                "检测与准入", "暴露面", "多租户隔离"):
        score = scores[cat]
        level = ("critical" if score >= 85 else "high" if score >= 60
                 else "medium" if score >= 30 else "low")
        heatmap.append({"category": cat, "score": score, "level": level,
                        "signals": signals[cat][:12], "signal_count": len(signals[cat])})
    return {
        "schema": PROFILE_SCHEMA,
        "generated_at": _now(),
        "clusters": clusters,
        "totals": totals,
        "heatmap": heatmap,
        "findings": findings,
        "data_sensitivity": {
            "weight_pvs": [pv.get("name") for r in records for pv in r["snapshot"].get("pvs", [])
                           if _WEIGHT_RE.search(str(pv.get("name") or ""))],
            "tenant_namespaces": sorted({ns for c in clusters for ns in c["namespaces"]
                                         if ns.startswith("tenant-")}),
            "inference_services": sorted({s for c in clusters for s in c["inference_services"]}),
        },
        "boundary": "只读清点；fixture/live-kubectl 来源分列；非生产规模，不等同容量/性能结论。",
    }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ------------------------------------------------------------------ plan / gates

def _p2_actions(profile: dict) -> list[dict]:
    actions = []
    for f in profile["findings"]:
        if f["severity"] in ("critical", "high"):
            actions.append({
                "finding": f["title"],
                "action": "在客户窗口内做受控验证/复现（写操作仅走既有链，需备份回执）",
                "risk": f["severity"], "rollback": "按 rollback_plan 恢复资源快照并复测",
            })
    if not actions:
        actions.append({"finding": "无高危发现", "action": "保持只读复测", "risk": "low",
                        "rollback": "无需写操作"})
    return actions[:20]


def build_plan(profile: dict, inventory: dict, *, allow_write: bool = False,
               gate_receipts: dict | None = None) -> dict:
    receipts = gate_receipts or {}
    write_authorized = bool(allow_write and receipts and all(
        bool(v.get("ok")) for v in receipts.values()))
    p2 = {
        "id": "P2",
        "name": "受控写验证（条件执行）",
        "mode": "write",
        "blocked": not write_authorized,
        "requires": ["--allow-write", "ROE/consent 完整", "级别=利用验证或更高",
                     "lead/tester 角色", "备份/回滚预案"],
        "window": "客户变更窗口内（建议业务低峰；训练作业暂停/排空后）",
        "duration_min": 60,
        "actions": _p2_actions(profile) if write_authorized else [
            {"finding": "P2 未授权", "action": "仅生成计划；不执行任何写操作", "risk": "n/a",
             "rollback": "n/a"}],
        "exit_criteria": [
            "每个写动作有备份回执 + 回滚演练记录",
            "回滚成功率 100%（失败即停止并升级）",
            "写窗口内 P95 时延不超过客户阈值",
        ],
    }
    plan = {
        "schema": PLAN_SCHEMA,
        "generated_at": _now(),
        "read_only": True,
        "allow_write": bool(allow_write),
        "write_authorized": write_authorized,
        "collector_mode": "read-only",
        "mutations": [],
        "phases": [
            {
                "id": "P0", "name": "只读清点与环境画像", "mode": "read-only",
                "window": "任意时间（仅 kubectl get）", "duration_min": 20,
                "actions": ["多 context/cluster 合并", "pods/services/netpol/RBAC/PVC/Secret 元数据清点",
                            "Kyverno/Falco/NetworkPolicy 生效状态读取"],
                "exit_criteria": ["只读通过率 >= 95%", "无写动作", "环境画像与冲突清单完整"],
            },
            {
                "id": "P1", "name": "低影响验证", "mode": "read-only",
                "window": "业务低峰；只读 API/快照分析", "duration_min": 45,
                "actions": ["证据驱动链推荐（不执行）", "误报/漏报基线（客户标注样本）",
                            "告警/SIEM 连通性干跑"],
                "exit_criteria": ["误报率 <= 20%（Pilot 门槛）", "漏报率 <= 10%",
                                  "扫描窗口 <= 客户约定时长"],
            },
            p2,
            {
                "id": "P3", "name": "复测、报告与签核", "mode": "read-only",
                "window": "写验证后 24h 内", "duration_min": 30,
                "actions": ["回归复测", "pilot-report/证据 manifest 哈希", "双签与保留策略登记"],
                "exit_criteria": ["报告签核项 6/6", "证据 manifest 校验通过", "客户安全负责人签字"],
            },
        ],
        "recommended_window": {
            "read_only": "任意（仍建议通知 SOC）",
            "write": "客户变更窗口；避开训练/推理高峰；单次 <= 2h",
            "freeze": "训练作业 checkpoint / 推理扩缩容 / 发布冻结期不执行写验证",
        },
        "stop_conditions": [
            "客户 SOC/值班要求立即停止",
            "出现非预期生产影响或 SLO 越界",
            "授权/范围/时间窗任一失效",
            "回滚失败或备份回执缺失",
        ],
        "rollback_plan": {
            "steps": [
                "执行前导出目标命名空间资源 YAML + PVC/RBAC 元数据并计算 sha256",
                "每个写动作登记 backup_targets 与回滚命令（沿用 core/backup.py）",
                "异常时按步骤逆序回滚并校验资源哈希",
                "回滚后只读复测并记录回执",
            ],
            "success_criteria": "回滚成功率 100%；失败项为 0；资源哈希一致",
        },
        "approvals": [
            {"role": "lead", "required": True, "scope": "测试范围/窗口/停止条件"},
            {"role": "security-owner", "required": True, "scope": "双签；数据敏感与变更窗口"},
            {"role": "platform-owner", "required": False, "scope": "集群/GPU 平台影响确认"},
            {"role": "data-owner", "required": False, "scope": "训练数据/模型权重接触确认"},
        ],
        "gate_receipts": receipts,
        "metrics": {
            "read_only_pass_rate_target": ">=95%",
            "false_positive_rate_target": "<=20%",
            "false_negative_rate_target": "<=10%",
            "scan_window_target": "<=客户约定窗口（默认 2h）",
            "rollback_success_target": "100%",
            "report_signoff_target": "6/6",
        },
    }
    return plan


def authorize_write(store, session, plan: dict) -> dict:
    """三闸门：ROE/consent（含范围/窗口）+ 级别/角色 + 备份/回滚预案。"""
    if _plan_missing_p2(plan):
        raise PilotGateRefused("P2 计划缺少写动作/回滚预案")
    if session is None or not session.can("execute"):
        raise PilotGateRefused("角色无 execute 权限，拒绝 --allow-write")
    from .core.abort import assert_not_aborted
    from .core.roe import ExecutionLocked, assert_execution_allowed, roe_status

    if roe_status(store) != "complete":
        raise PilotGateRefused("授权未完成（consent 未签署或签名校验失败），拒绝 --allow-write")
    try:
        assert_execution_allowed(store, {"min_level": "利用验证"})
        assert_not_aborted(store)
    except ExecutionLocked as exc:
        raise PilotGateRefused(f"授权闸门拒绝：{exc}") from exc
    rollback = plan.get("rollback_plan") or {}
    if not rollback.get("steps"):
        raise PilotGateRefused("备份/回滚闸门拒绝：rollback_plan.steps 为空")
    p2 = next((p for p in plan.get("phases", []) if p["id"] == "P2"), {})
    if not p2.get("actions"):
        raise PilotGateRefused("备份/回滚闸门拒绝：P2 无动作")
    return {
        "consent": {"ok": True, "detail": "ROE/consent 完整，范围/窗口由既有 roe.py 校验"},
        "level": {"ok": True, "detail": f"角色 {session.role} 有 execute 权限；级别 >= 利用验证"},
        "backup": {"ok": True, "detail": f"回滚预案 {len(rollback.get('steps', []))} 步；执行前需备份回执"},
        "abort": {"ok": True, "detail": "工作区未处于紧急停止"},
    }


def _plan_missing_p2(plan: dict) -> bool:
    return not plan.get("phases") or not any(p.get("id") == "P2" for p in plan["phases"])


# ------------------------------------------------------------------ outputs

def render_markdown(result: dict) -> str:
    profile = result["profile"]
    plan = result["plan"]
    inv = result["inventory"]
    lines = [
        "# Trident Pilot Report（试点只读报告）",
        "",
        f"> 生成时间：`{result['generated_at']}` · 模式：**{'只读' if result['read_only'] else '未知'}** · "
        f"写验证：**{'已授权（计划）' if plan['write_authorized'] else '未授权'}**",
        ">",
        "> 边界：pilot 只生成清点/计划，不执行写操作；不代表生产容量、SLA 或合规认证。",
        "",
        "## 1. 环境画像",
        "",
        f"- kubeconfig 文件：{', '.join(inv.get('source_files', [])) or '-'}",
        f"- context：{inv.get('context_count', 0)} · cluster：{inv.get('cluster_count', 0)} · "
        f"节点：{profile['totals']['nodes']} · GPU 节点：{profile['totals']['gpu_nodes']} · "
        f"GPU：{profile['totals']['gpus']}",
        f"- 命名空间：{profile['totals']['namespaces']} · Pod：{profile['totals']['pods']} · "
        f"Secret 元数据：{profile['totals']['secrets']}",
        f"- 云/平台：{', '.join(profile['totals']['providers']) or 'unknown'}",
        "",
        "| context | provider | nodes | GPU | ns | pods | 特权 Pod | hostPath | 无 netpol ns |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for c in profile["clusters"]:
        lines.append(f"| {c['context']} | {c['provider']} | {c['nodes']} | {c['gpu_nodes']} | "
                     f"{c['namespace_count']} | {c['pods']} | {c['privileged_pods']} | "
                     f"{c['host_path_pods']} | {', '.join(c['unisolated_namespaces']) or '-'} |")
    lines += ["", "## 2. 风险热图", "",
              "| 类别 | 分数 | 等级 | 信号（截断） |",
              "|---|---:|---|---|"]
    for row in profile["heatmap"]:
        signals = "；".join(row["signals"][:4]) or "无"
        lines.append(f"| {row['category']} | {row['score']} | {row['level']} | {signals} |")
    lines += ["", "> 热图是只读启发式评分，不是漏洞定级；真实定级以模块证据与人工复核为准。", ""]
    lines += ["## 3. 只读发现（Top 20）", "",
              "| 严重度 | 类别 | 发现 | 证据 |", "|---|---|---|---|"]
    for f in profile["findings"][:20]:
        lines.append(f"| {f['severity']} | {f['category']} | {f['title']} | `{f['evidence']}` |")
    if not profile["findings"]:
        lines.append("| info | - | 未发现只读信号 | - |")
    lines += ["", "## 4. 建议测试计划", "",
              "| 阶段 | 模式 | 窗口 | 时长 | 动作 | 退出标准 |",
              "|---|---|---|---:|---|---|"]
    for p in plan["phases"]:
        blocked = "（未授权/已阻断）" if p.get("blocked") else ""
        raw_actions = p.get("actions", [])
        if isinstance(raw_actions, list):
            actions = "；".join(
                (f"{a.get('action')}（{a.get('finding')}）" if isinstance(a, dict) else str(a))
                for a in raw_actions)
        else:
            actions = str(raw_actions)
        exits = "；".join(p.get("exit_criteria", []))
        lines.append(f"| {p['id']} {p['name']}{blocked} | {p['mode']} | {p['window']} | "
                     f"{p['duration_min']} | {actions} | {exits} |")
    lines += ["", f"**推荐窗口**：{plan['recommended_window']['write']}",
              "", "**停止条件**："]
    lines += [f"- {s}" for s in plan["stop_conditions"]]
    lines += ["", "## 5. 回滚预案", ""]
    lines += [f"{i}. {s}" for i, s in enumerate(plan["rollback_plan"]["steps"], 1)]
    lines += ["", f"成功标准：{plan['rollback_plan']['success_criteria']}", ""]
    lines += ["## 6. 审批清单（双签开关）", "",
              "| 角色 | 必需 | 审批范围 | 签字 | 时间 |", "|---|---|---|---|---|"]
    for a in plan["approvals"]:
        lines.append(f"| {a['role']} | {'是' if a['required'] else '建议'} | {a['scope']} | ☐ | ____ |")
    lines += ["", "> 双签：lead → 安全负责人；单签模式仅限只读/低风险试点，需在 ROE 中显式登记。", ""]
    lines += ["## 7. 量化门槛与签核", "",
              "| 指标 | 目标 |", "|---|---|"]
    for k, v in plan["metrics"].items():
        lines.append(f"| {k} | {v} |")
    lines += ["", "报告签核项（6/6 方可交付）：",
              "- [ ] 范围与授权一致", "- [ ] 证据 manifest 校验通过",
              "- [ ] 发现经人工复核", "- [ ] 误报/漏报已复核",
              "- [ ] 数据敏感与保留策略确认", "- [ ] 回滚演练通过", ""]
    if inv.get("conflicts"):
        lines += ["## 8. kubeconfig 冲突", "", "| 类型 | 名称 | 来源 | 选择 |", "|---|---|---|---|"]
        for c in inv["conflicts"]:
            lines.append(f"| {c['kind']} | {c['name']} | {', '.join(c['sources'])} | {c.get('chosen')} |")
        lines.append("")
    if inv.get("warnings"):
        lines += ["## 9. 警告", ""] + [f"- {w}" for w in inv["warnings"]] + [""]
    lines += ["---", "",
              "本报告由 `trident pilot` 生成；默认只读。若需写验证，必须客户显式 `--allow-write` "
              "并完成 lead→安全负责人双签与备份回执；禁止把本报告当作生产 SLA、合规认证或全量覆盖证明。", ""]
    return "\n".join(lines)


def _write_atomic(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, path)


def write_outputs(result: dict, out_dir: str | Path) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report_md = render_markdown(result)
    report_sha256 = hashlib.sha256(report_md.encode("utf-8")).hexdigest()
    _write_atomic(out / "pilot-report.json", json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    _write_atomic(out / "pilot-report.md", report_md)
    approvals = {
        "schema": "trident-pilot-approvals/1",
        "generated_at": result["generated_at"],
        "workspace": result.get("workspace", ""),
        "read_only": True,
        "write_authorized": result["plan"]["write_authorized"],
        "report_sha256": report_sha256,
        "approvals": result["plan"]["approvals"],
        "signoff_items": ["scope", "evidence_manifest", "findings_reviewed",
                          "fp_fn_reviewed", "data_handling", "rollback_verified"],
        "signed": [],
        "note": "双签：lead → 安全负责人；签字必须绑定报告 sha256 与时间戳。",
    }
    _write_atomic(out / "approvals.json", json.dumps(approvals, ensure_ascii=False, indent=2) + "\n")
    files = ["pilot-report.json", "pilot-report.md", "approvals.json"]
    lines = []
    for rel in files:
        data = (out / rel).read_bytes()
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {rel}")
    manifest_sha = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    _write_atomic(out / "manifest.sha256", "\n".join(lines) + "\n")
    signature = {
        "schema": "trident-pilot-signature/1",
        "generated_at": result["generated_at"],
        "manifest_sha256": manifest_sha,
        "report_sha256": hashlib.sha256((out / "pilot-report.md").read_bytes()).hexdigest(),
        "timestamp": {"source": "local-clock", "epoch": int(time.time()),
                      "note": "本机时间戳；生产交付需客户 TSA/RFC3161 或 HSM 签名"},
        "signed_by": result.get("actor", ""),
    }
    _write_atomic(out / "pilot-signature.json", json.dumps(signature, ensure_ascii=False, indent=2) + "\n")
    return {"out_dir": str(out), "files": files + ["manifest.sha256", "pilot-signature.json"],
            "manifest_sha256": manifest_sha}


def _inventory_from_bundle(bundle: list[dict]) -> dict:
    contexts = []
    for b in bundle:
        contexts.append({"name": b["context"], "cluster": b["context"],
                         "user": "", "namespace": "", "server": "", "auth": "unknown",
                         "source": b.get("source", "fixture"), "current": False})
    return {"schema": "trident-kubeconfig-inventory/1", "source_files": [],
            "context_count": len(contexts), "cluster_count": len(contexts),
            "user_count": 0, "contexts": contexts,
            "clusters": [{"name": c["name"], "server": "", "source": c["source"],
                          "insecure_skip_tls_verify": False} for c in contexts],
            "users": [], "conflicts": [], "warnings": ["未提供 kubeconfig；仅按 fixture snapshot 画像"]}


def run_pilot(
    *,
    kubeconfigs: Iterable[str | Path] = (),
    snapshot_paths: Iterable[str | Path] = (),
    out_dir: str | Path | None = None,
    workspace: str = "pilot",
    actor: str = "pilot",
    role: str = "auditor",
    allow_write: bool = False,
    store=None,
    session=None,
    contexts: Iterable[str] | None = None,
    collector: KubectlCollector | None = None,
) -> dict:
    kubeconfigs = list(kubeconfigs)
    snapshot_paths = list(snapshot_paths)
    if not kubeconfigs and not snapshot_paths:
        raise PilotError("需要 --kubeconfig 或 --snapshot 至少一个")
    if kubeconfigs:
        inventory = merge_kubeconfigs(kubeconfigs)
    else:
        inventory = None
    if snapshot_paths:
        bundle = load_snapshot_bundle(snapshot_paths)
    else:
        if not kubeconfigs:
            raise PilotError("没有 snapshot")
        if collector is None:
            raise PilotError("live 采集需要 KubectlCollector（CLI 由 --kubectl 提供）")
        bundle = []
        for ctx in inventory["contexts"]:
            kube = next((k for k in kubeconfigs if Path(k).name == ctx["source"]), kubeconfigs[0])
            bundle.append({"context": ctx["name"],
                           "snapshot": collector.collect(kube, ctx["name"]),
                           "source": "live-kubectl"})
    if inventory is None:
        inventory = _inventory_from_bundle(bundle)
    wanted = set(contexts or [])
    if wanted:
        bundle = [b for b in bundle if b["context"] in wanted]
        if not bundle:
            raise PilotError(f"--context 过滤后为空：{sorted(wanted)}")
    profile = build_profile(inventory, bundle)
    plan = build_plan(profile, inventory, allow_write=allow_write)
    if allow_write:
        if store is None or session is None:
            raise PilotGateRefused("--allow-write 需要工作区 store 与已登录 session（三闸门）")
        receipts = authorize_write(store, session, plan)
        plan = build_plan(profile, inventory, allow_write=True, gate_receipts=receipts)
        plan["phases"][2]["blocked"] = False
        plan["phases"][2]["actions"] = _p2_actions(profile)
    result = {
        "schema": SCHEMA,
        "generated_at": _now(),
        "tool": "trident",
        "workspace": workspace,
        "actor": actor,
        "role": role,
        "read_only": True,
        "collector_mode": "read-only (kubectl get)" if not snapshot_paths else "fixture-read-only",
        "mutations": [],
        "inventory": inventory,
        "profile": profile,
        "plan": plan,
        "boundary": [
            "pilot 只读清点，不执行利用/写操作",
            "fixture/live-kubectl 来源分列；fixture 不等于客户生产环境",
            "非生产规模；不构成 SLA、合规认证或全量覆盖承诺",
        ],
        "summary": {
            "contexts": profile["totals"]["clusters"],
            "clusters": inventory.get("cluster_count", profile["totals"]["clusters"]),
            "nodes": profile["totals"]["nodes"],
            "gpu_nodes": profile["totals"]["gpu_nodes"],
            "findings": profile["totals"]["findings"],
            "top_risk": max((r["score"] for r in profile["heatmap"]), default=0),
            "write_authorized": plan["write_authorized"],
        },
    }
    if out_dir is not None:
        result["outputs"] = write_outputs(result, out_dir)
    return result
