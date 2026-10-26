"""metadata-egress — 元数据与出网面：SA token 自动挂载、凭据环境变量名称、出网缺口。

凭据值一律不入证据（只记环境变量名）；出网判定 = 命名空间内是否存在选择该 Pod 的 Egress 策略（静态推演层）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon

CRED_ENV_KEYS = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALIBABA_CLOUD_SECURITY_TOKEN",
    "TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS", "HF_TOKEN",
)


def _egress_covered(policies: list[dict], ns: str) -> bool:
    for policy in policies:
        if policy.get("namespace", "default") != ns:
            continue
        if policy.get("podSelector"):
            continue  # 只按空选择器（全选）判定；带标签选择的覆盖细节交给可达性图
        if "Egress" in policy.get("policyTypes", []):
            return True
    return False


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []
    policies = snapshot.get("networkpolicies", [])
    service_accounts = snapshot.get("serviceaccounts", [])
    # 一次性索引：空选择器 Egress 覆盖的命名空间集合 + (ns,name)→automount。
    # 把每 Pod 重扫策略表（O(pods×policies)）与逐 Pod 线性找 SA（O(pods×SAs)）降为线性。
    egress_covered_ns = {
        policy.get("namespace", "default")
        for policy in policies
        if not policy.get("podSelector") and "Egress" in policy.get("policyTypes", [])
    }
    sa_automount = {(s.get("namespace", "default"), s.get("name")): s.get("automount")
                    for s in service_accounts}

    for pod in snapshot.get("pods", []):
        ns = pod.get("namespace", "default")
        pid = f"{ns}/{pod.get('name', '?')}"
        sa_name = pod.get("serviceAccount", "default")
        env_names = [e.get("name") for c in pod.get("containers", []) for e in c.get("env", [])]
        creds = sorted(set(n for n in env_names if n in CRED_ENV_KEYS))
        if creds:
            findings.append(finding(
                "high", f"云/HF 凭据环境变量：{pid} → {creds}",
                detail="环境变量明文承载长期凭据：任意读取（日志回显/漏洞面/SSRF）即达私有仓库与权重桶。仅记变量名，值不入证据。",
                evidence=f"pod={pid} env_keys={creds}",
                mapping="链「SSRF / SA Token → 云元数据」；supply-chain-credential-theft；云侧权重桶链",
                fix="改用 Secret 卷挂载或 IRSA/Workload Identity 短时效凭据；日志与环境回显过滤",
            ))
        sa_automount_value = sa_automount.get((ns, sa_name))
        automount = pod.get("automountServiceAccountToken",
                           sa_automount_value if sa_automount_value is not None else True)
        if automount is not False:
            findings.append(finding(
                "medium", f"SA token 自动挂载：{pid}（SA {ns}/{sa_name}）",
                detail="API 凭据随 Pod 自动下发：漏洞面/沙箱逃逸即可换取集群身份，配合宽 RBAC 成提权起点。",
                evidence=f"pod={pid} sa={ns}/{sa_name} automount={automount}",
                mapping="元数据与出网面；链「Ray Dashboard → 集群控制」token 段",
                fix="默认 automountServiceAccountToken: false（SA 与 Pod 双层显式关闭），按需最小授权",
            ))
        if ns not in egress_covered_ns:
            if pod.get("hostNetwork"):
                findings.append(finding(
                    "medium", f"hostNetwork Pod 出网绕过 NetworkPolicy：{pid}",
                    detail="hostNetwork 流量不经 CNI/NetworkPolicy：出网面（含云元数据 169.254.169.254）对其实际无约束。",
                    evidence=f"pod={pid} hostNetwork=true egress_policy=absent",
                    mapping="网络分层「主机网络层」旁路；链「SSRF / SA Token → 云元数据」",
                    fix="hostNetwork 收敛清单化；该类 Pod 以主机防火墙/安全组单独限出网",
                ))
            else:
                findings.append(finding(
                    "medium", f"出网不受限（无 Egress 策略）：{pid}",
                    detail="无 Egress 策略覆盖即可任意出网：云元数据、外部回连与数据外传通道全部敞开。",
                    evidence=f"pod={pid} egress_policy=absent ns={ns}",
                    mapping="混合云出网与回旋；多云元数据凭据面前置",
                    fix="默认拒绝 Egress 后按域放行（镜像源/对象存储/必需 API）；元数据端点单独拒出",
                ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="元数据与出网面")
