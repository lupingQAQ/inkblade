# -*- coding: utf-8 -*-
"""KIND 实验室防护产品部署清单生成器（只生成清单与命令文本，绝不执行 kubectl）。

紫队闭环（规格 5.2）：实验室 KIND/WSL 内部署对应产品 → 重放良性探针 →
验证 defense-bypass-* 模块的「检出断言」与硬化规则有效性。

用法（人工执行）：
    python lab/defense-deploy/deploy_products.py --product elkeid --out out/
    # 生成的 out/<product>-deploy.txt 内是逐条 kubectl/helm 命令，由人工审阅后在实验室执行
"""
import argparse
from pathlib import Path

# 每产品：部署命令模板（人工审阅后执行）与部署后采集项（供 collect_snapshot.py）
DEPLOY_CMDS = {
    "elkeid": [
        "# bytedance/Elkeid：elkeidup 部署（agent DS + manager + server）",
        "git clone https://github.com/bytedance/Elkeid.git && cd Elkeid",
        "bash elkeidup/deploy/elkeidup_install.sh",
        "# 内核模块（driver）：agent driver 插件自动加载 elkeid.ko；验证: lsmod | grep -E 'elkeid|olehid'",
    ],
    "agentsmith": [
        "# bytedance/AgentSmith-HIDS：driver/LKM 编译 smith.ko + agent",
        "git clone https://github.com/bytedance/AgentSmith-HIDS.git && cd AgentSmith-HIDS",
        "cd driver/LKM && make && sudo insmod smith.ko",
        "cd agent && make && ./agentsmith-agent -c config.json",
    ],
    "veinmind": [
        "# chaitin/veinmind-tools（公开仓库命名；规格口径归字节系重点）",
        "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock chaitin/veinmind-tools:v2.0 scan-host",
    ],
    "falco": [
        "# falcosecurity/falco（含 ebpf 探针；无 driver 降级用 falco-no-driver 标记）",
        "helm install falco falcosecurity/falco -n kube-system --set driver.kind=modern_ebpf",
        "kubectl -n kube-system get ds falco && lsmod | grep falco",
    ],
    "tetragon": [
        "# cilium/tetragon（BPF LSM 需 kernel.lsm 含 bpf）",
        "helm install tetragon cilium/tetragon -n kube-system",
        "cat /sys/kernel/security/lsm   # 期望包含 bpf，否则为降级态",
    ],
    "kubearmor": [
        "# kubearmor/kubearmor",
        "helm install kubearmor kubearmor/kubearmor-operator -n kubearmor --create-namespace",
        "kubectl annotate ns train kubearmor-file-posture=audit",
    ],
    "admission": [
        "# kyverno + gatekeeper（豁免 ns / Audit 模式面）",
        "helm install kyverno kyverno/kyverno -n kyverno --create-namespace",
        "helm install gatekeeper gatekeeper/gatekeeper -n gatekeeper-system --create-namespace",
    ],
    "imagescan": [
        "# aquasecurity/trivy + anchore/grype + chaitin/veinmind-tools",
        "kubectl run trivy-scan --image aquasecurity/trivy:0.50.0 --restart=Never -- trivy image --scanners vuln <benign-image>",
        "kubectl run grype-scan --image anchore/grype:v0.74.0 --restart=Never -- grype <benign-image>",
    ],
    "hostagent": [
        "# wazuh + osquery",
        "helm install wazuh wazuh/wazuh -n wazuh --create-namespace",
        "kubectl -n wazuh get ds wazuh-agent   # agent 在线态=online",
    ],
    "waf-inference": [
        "# chaitin/safeline(雷池) + coraza + modsecurity（推理入口前 WAF）",
        "helm install safeline <safeline-chart> -n waf --create-namespace",
        "kubectl -n waf set env deploy/coraza-spoa CORAZA_CONFIG=/etc/coraza/coraza.conf",
    ],
    "netobserv": [
        "# cilium hubble + calico flows（hostNetwork/多网卡观测面）",
        "helm install cilium cilium/cilium -n kube-system --set hubble.relay.enabled=true --set hubble.ui.enabled=true",
        "helm install calico projectcalico/tigera-operator -n calico-system --create-namespace",
    ],
}

COLLECT_HINTS = {
    "elkeid": ["kubectl get ds,deploy -A | grep elkeid", "lsmod | grep -E 'elkeid|olehid'"],
    "agentsmith": ["kubectl get ds -A | grep -i smith", "lsmod | grep smith"],
    "veinmind": ["kubectl get pods -A -o wide | grep veinmind", "docker images | grep veinmind"],
    "falco": ["kubectl get ds -A | grep falco", "lsmod | grep falco"],
    "tetragon": ["kubectl get ds,deploy -A | grep tetragon", "cat /sys/kernel/security/lsm"],
    "kubearmor": ["kubectl get ds,deploy,crd -A | grep -i kubearmor"],
    "admission": ["kubectl get deploy,ds,webhookcfg -A | grep -E 'kyverno|gatekeeper'"],
    "imagescan": ["kubectl get pods,images -A | grep -E 'trivy|grype|veinmind'"],
    "hostagent": ["kubectl get ds,deploy -A | grep -E 'wazuh|osquery'", "agent_status 采集"],
    "waf-inference": ["kubectl get deploy,ingress -A | grep -E 'safeline|coraza|modsecurity'"],
    "netobserv": ["kubectl get ds,deploy -A | grep -E 'hubble|calico'"],
}


def main() -> None:
    ap = argparse.ArgumentParser(description="生成实验室部署命令文本（不执行）")
    ap.add_argument("--product", required=True, choices=sorted(DEPLOY_CMDS))
    ap.add_argument("--out", default="out", help="输出目录")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# INKBLADE lab deploy plan: {args.product}",
        "# 本文件仅为命令文本；必须人工审阅后于授权 KIND 实验室执行",
        "",
        *DEPLOY_CMDS[args.product],
        "",
        "# 部署后采集（喂给 collect_snapshot.py → deploy_snapshot）：",
        *COLLECT_HINTS[args.product],
        "",
    ]
    p = out / f"{args.product}-deploy.txt"
    p.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {p} (commands NOT executed)")


if __name__ == "__main__":
    main()
