"""fake-kubectl 提权闭环：不依赖真实集群，确定性地验证 escalate/bind/SA token/webhook 四个原语。

用途：
- ``lab.privesc_sim.run_fake_closure()`` → verify-effects 的 4 项效果级检查；
- 与 ``lab/privesc_verify.py``（QEMU k3s 真实集群）形成“真实 + fake-kubectl”双证据；
- 仅内存态，token 值不进入结果/报告（只记录 issued/长度/主体）。

语义边界：简化 RBAC（verbs/resources/resourceNames + 绑定），不覆盖 aggregation、
priority、NotResource 等全部 Kubernetes 语义；真实集群验证以 privesc_verify.py 为准。
"""

from __future__ import annotations

import hashlib
from typing import Any

SCENARIOS = ("escalate", "bind", "sa-token", "webhook")


class FakeKubeError(PermissionError):
    """fake-kubectl 拒绝（权限不足）。"""


def _rule(verbs, resources, resource_names=None):
    r = {"apiGroups": ["*"], "verbs": list(verbs), "resources": list(resources)}
    if resource_names:
        r["resourceNames"] = list(resource_names)
    return r


class FakeKubeAPI:
    def __init__(self):
        self.roles: dict[str, list[dict]] = {
            "esc-editable": [_rule(["get", "list"], ["pods"])],
            "escalator": [
                _rule(["escalate"], ["clusterroles"]),
                _rule(["update", "patch"], ["clusterroles"], ["esc-editable"]),
            ],
            "binder": [
                _rule(["bind"], ["clusterroles"], ["cluster-admin"]),
                _rule(["create"], ["clusterrolebindings"]),
            ],
            "token-requester": [_rule(["create"], ["serviceaccounts/token"], ["privesc-admin"])],
            "webhook-writer": [_rule(["create", "update"], ["mutatingwebhookconfigurations"])],
        }
        self.bindings: dict[str, dict[str, Any]] = {
            "esc-editable-binding": {"role": "esc-editable", "subjects": ["system:serviceaccount:lab:esc-sa"]},
            "escalator-binding": {"role": "escalator", "subjects": ["system:serviceaccount:lab:esc-sa"]},
            "binder-binding": {"role": "binder", "subjects": ["system:serviceaccount:lab:bind-sa"]},
            "token-requester-binding": {"role": "token-requester", "subjects": ["system:serviceaccount:lab:token-sa"]},
            "webhook-writer-binding": {"role": "webhook-writer", "subjects": ["system:serviceaccount:lab:webhook-sa"]},
            "privesc-admin-binding": {"role": "cluster-admin", "subjects": ["system:serviceaccount:lab:privesc-admin"]},
        }
        self.service_accounts = {"esc-sa", "bind-sa", "token-sa", "webhook-sa", "privesc-admin", "default"}
        self.webhooks: dict[str, dict] = {}
        self.tokens: dict[str, str] = {}
        self.pods: dict[str, dict] = {}
        self.actions: list[dict] = []

    # ---------------------------------------------------------------- RBAC
    def effective_rules(self, subject: str) -> list[dict]:
        if any(b["role"] == "cluster-admin" and subject in b["subjects"] for b in self.bindings.values()):
            return [_rule(["*"], ["*"])]
        rules: list[dict] = []
        for b in self.bindings.values():
            if subject in b["subjects"]:
                rules += self.roles.get(b["role"], [])
        return rules

    def can_i(self, subject: str, verb: str, resource: str, resource_name: str = "") -> bool:
        for rule in self.effective_rules(subject):
            verbs = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))
            if "*" not in verbs and verb not in verbs:
                continue
            if "*" not in resources and resource not in resources:
                continue
            names = rule.get("resourceNames")
            if names and resource_name and resource_name not in names:
                continue
            if names and not resource_name:
                continue
            return True
        return False

    def patch_clusterrole(self, subject: str, role: str, rules: list[dict]) -> None:
        if not self.can_i(subject, "update", "clusterroles", role):
            raise FakeKubeError(f"{subject} 无 update clusterroles/{role}")
        if not self.can_i(subject, "escalate", "clusterroles", role):
            raise FakeKubeError(f"{subject} 无 escalate clusterroles/{role}")
        self.roles[role] = list(rules)
        self.actions.append({"verb": "patch", "resource": "clusterrole", "name": role, "by": subject})

    def create_clusterrolebinding(self, subject: str, name: str, role: str,
                                  service_account: str) -> None:
        if not self.can_i(subject, "bind", "clusterroles", role):
            raise FakeKubeError(f"{subject} 无 bind clusterroles/{role}")
        if not self.can_i(subject, "create", "clusterrolebindings"):
            raise FakeKubeError(f"{subject} 无 create clusterrolebindings")
        self.bindings[name] = {"role": role,
                               "subjects": [f"system:serviceaccount:lab:{service_account}"]}
        self.actions.append({"verb": "create", "resource": "clusterrolebinding",
                             "name": name, "by": subject})

    # ---------------------------------------------------------------- 身份
    def impersonate(self, subject: str, user: str) -> str:
        if not self.can_i(subject, "impersonate", "users", user):
            raise FakeKubeError(f"{subject} 无 impersonate users/{user}")
        self.actions.append({"verb": "impersonate", "resource": "user", "name": user, "by": subject})
        return f"user:{user}"

    def create_token(self, subject: str, service_account: str) -> str:
        if service_account not in self.service_accounts:
            raise FakeKubeError(f"ServiceAccount 不存在: {service_account}")
        if not self.can_i(subject, "create", "serviceaccounts/token", service_account):
            raise FakeKubeError(f"{subject} 无 create serviceaccounts/token/{service_account}")
        raw = f"{subject}|{service_account}|inkblade-fake"
        token = "fake-token-" + hashlib.sha256(raw.encode()).hexdigest()[:24]
        self.tokens[token] = f"system:serviceaccount:lab:{service_account}"
        self.actions.append({"verb": "create", "resource": "serviceaccounts/token",
                             "name": service_account, "by": subject})
        return token

    def subject_of_token(self, token: str) -> str:
        return self.tokens.get(token, "")

    def is_cluster_admin(self, subject: str) -> bool:
        return self.can_i(subject, "*", "*")

    # ---------------------------------------------------------------- 准入
    def write_webhook(self, subject: str, name: str = "inkblade-injector") -> dict:
        if not self.can_i(subject, "create", "mutatingwebhookconfigurations"):
            raise FakeKubeError(f"{subject} 无 create mutatingwebhookconfigurations")
        wh = {
            "name": name,
            "failurePolicy": "Ignore",
            "rules": [{"operations": ["CREATE"], "resources": ["pods"]}],
            "patch": {
                "privileged": True,
                "hostPath": "/",
                "hostPID": True,
            },
        }
        self.webhooks[name] = wh
        self.actions.append({"verb": "create", "resource": "mutatingwebhookconfiguration",
                             "name": name, "by": subject})
        return wh

    def admit_pod(self, pod: dict) -> dict:
        out = {**pod, "spec": dict(pod.get("spec") or {})}
        if self.webhooks:
            out["spec"]["containers"] = [dict(c) for c in out["spec"].get("containers", [])]
            out["spec"]["hostPID"] = True
            out["spec"]["volumes"] = list(out["spec"].get("volumes", [])) + [
                {"name": "hostroot", "hostPath": {"path": "/"}}
            ]
            for c in out["spec"]["containers"]:
                c["securityContext"] = {**c.get("securityContext", {}), "privileged": True}
            out["mutated_by"] = sorted(self.webhooks)
        self.pods[pod.get("name", "pod")] = out
        return out

    @staticmethod
    def pod_escape_primitive(pod: dict) -> bool:
        spec = pod.get("spec") or {}
        privileged = any((c.get("securityContext") or {}).get("privileged") for c in spec.get("containers", []))
        host_root = any((v.get("hostPath") or {}).get("path") == "/" for v in spec.get("volumes", []))
        return bool(privileged and host_root)


def run_fake_closure() -> dict:
    api = FakeKubeAPI()
    checks: list[dict] = []

    # 1) escalate：改写已绑定的 ClusterRole 为 *
    subject = "system:serviceaccount:lab:esc-sa"
    before = api.is_cluster_admin(subject)
    api.patch_clusterrole(subject, "esc-editable", [_rule(["*"], ["*"])])
    after = api.is_cluster_admin(subject)
    checks.append({
        "id": "escalate", "status": "PASS" if (not before and after) else "FAIL",
        "title": "escalate 动词改写已绑定角色 → cluster-admin",
        "evidence": {"subject": subject, "before_admin": before, "after_admin": after,
                     "escalate_allowed": api.can_i(subject, "escalate", "clusterroles"),
                     "role_rules": api.roles["esc-editable"]},
    })

    # 2) bind：创建指向 cluster-admin 的 CRB
    subject = "system:serviceaccount:lab:bind-sa"
    before = api.is_cluster_admin(subject)
    api.create_clusterrolebinding(subject, "bind-pwn", "cluster-admin", "bind-sa")
    after = api.is_cluster_admin(subject)
    checks.append({
        "id": "bind", "status": "PASS" if (not before and after) else "FAIL",
        "title": "bind cluster-admin + create CRB → cluster-admin",
        "evidence": {"subject": subject, "before_admin": before, "after_admin": after,
                     "binding_created": "bind-pwn" in api.bindings,
                     "role": "cluster-admin"},
    })

    # 3) SA token：TokenRequest 借用高权 SA
    subject = "system:serviceaccount:lab:token-sa"
    before = api.is_cluster_admin(subject)
    token = api.create_token(subject, "privesc-admin")
    token_subject = api.subject_of_token(token)
    after = api.is_cluster_admin(token_subject)
    checks.append({
        "id": "sa-token", "status": "PASS" if (not before and after) else "FAIL",
        "title": "create serviceaccounts/token → 高权 SA 身份",
        "evidence": {"subject": subject, "target_sa": "privesc-admin",
                     "before_admin": before, "token_issued": bool(token),
                     "token_sha256_8": hashlib.sha256(token.encode()).hexdigest()[:8],
                     "authenticated_subject": token_subject,
                     "after_admin": after},
    })

    # 4) Webhook：写入 fail-open mutating webhook → Pod 被注入特权 + hostPath
    subject = "system:serviceaccount:lab:webhook-sa"
    before_can_pod = api.can_i(subject, "create", "pods")
    api.write_webhook(subject)
    pod = api.admit_pod({"name": "webhook-victim", "spec": {
        "containers": [{"name": "app", "image": "busybox", "securityContext": {}}]}})
    spec = pod["spec"]
    privileged = any((c.get("securityContext") or {}).get("privileged") for c in spec["containers"])
    host_root = any((v.get("hostPath") or {}).get("path") == "/" for v in spec["volumes"])
    checks.append({
        "id": "webhook", "status": "PASS" if (not before_can_pod and privileged and host_root) else "FAIL",
        "title": "写入准入 Webhook → Pod 注入 privileged/hostPath",
        "evidence": {"subject": subject, "before_can_create_pods": before_can_pod,
                     "webhook_written": bool(api.webhooks),
                     "failure_policy": "Ignore",
                     "pod_privileged": privileged, "host_root_mounted": host_root,
                     "escape_primitive": api.pod_escape_primitive(pod),
                     "mutated_by": pod.get("mutated_by", [])},
    })

    passed = sum(1 for c in checks if c["status"] == "PASS")
    return {
        "schema": "inkblade-privesc-fake-kubectl-v1",
        "backend": "fake-kubectl (in-memory, deterministic)",
        "checks": checks,
        "summary": {"total": len(checks), "passed": passed,
                    "failed": len(checks) - passed, "ok": passed == len(checks)},
        "api_actions": api.actions,
        "state": {"roles": sorted(api.roles), "bindings": sorted(api.bindings),
                  "webhooks": sorted(api.webhooks), "tokens_issued": len(api.tokens),
                  "pods": sorted(api.pods)},
    }
