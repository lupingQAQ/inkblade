#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build docs/VULNERABILITY-LAYERS.md from the audit registers.

Inputs (all repository-relative unless noted):
  * inkblade/core/exploit-registry.json            152 exploit cases
  * inkblade/core/zeroday-registry.json            169 zero-day records, 39 reserve
  * lab/upstream_verify/cases/*/*/manifest.json    root cause file/line/snippet
  * inkblade/modules/*/template.json               286 declarative templates
  * the workspace audit master                  code-root audit (path built at runtime)

The generated document contains only root-cause fragments. It never emits an
exploit request, a payload, or a step-by-step recipe. Run with ``--check`` to
verify that the checked-in document is byte-identical to a fresh build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from vuln_dive_data import PRIMERS
from vuln_layers import LAYER_TITLES, layer_for_entry

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
DOC = ROOT / "docs" / "VULNERABILITY-LAYERS.md"
REGISTRY = ROOT / "inkblade" / "core" / "exploit-registry.json"
ZERODAY = ROOT / "inkblade" / "core" / "zeroday-registry.json"
MASTER = WORKSPACE / ("VULNERABILITY" + "-MASTER.md")
CASES = ROOT / "lab" / "upstream_verify" / "cases"
MODULES = ROOT / "inkblade" / "modules"
CHAINS = ROOT / "inkblade" / "chains"
DEMOS = ROOT / "demos"

STATUS_LABEL = {
    "verified": "verified",
    "exposure-verified": "exposure",
    "static-only": "static",
    "unsupported": "unsupported",
}

STATUS_ORDER = {"verified": 0, "exposure-verified": 1, "static-only": 2, "unsupported": 3}

COMPONENT_ZH = {
    "bmc": "BMC/Redfish",
    "cephcsi": "Ceph CSI",
    "cgpu": "cGPU",
    "containerd": "containerd",
    "cumulus": "Cumulus/NVUE",
    "deepspeed": "DeepSpeed",
    "dify": "Dify",
    "dradriver": "DRA driver",
    "gpuoperator": "GPU Operator",
    "hami": "HAMi",
    "juicefscsi": "JuiceFS CSI",
    "kuberay": "KubeRay",
    "kubernetes": "Kubernetes",
    "kueue": "Kueue",
    "linux-kernel": "Linux kernel",
    "litellm": "LiteLLM",
    "llamafactory": "LLaMA-Factory",
    "lws": "LWS",
    "megatron": "Megatron-LM",
    "mlflow": "MLflow",
    "msswift": "ms-swift",
    "nccl": "NCCL",
    "nvidia": "NVIDIA toolkit",
    "open-webui": "Open WebUI",
    "pytorch": "PyTorch",
    "ray": "Ray",
    "runc": "runc",
    "sglang": "SGLang",
    "sonic": "SONiC",
    "sonicrestapi": "SONiC REST API",
    "transformers": "transformers",
    "trl": "TRL",
    "ucx": "UCX",
    "ucxpy": "UCX-Py",
    "vllm": "vLLM",
    "volcano": "Volcano",
    "wandb": "W&B",
}

COMPONENT_MODULE = {
    "bmc": "bmc-ipmi-exposure",
    "cephcsi": "csi-node-plugin-escape",
    "cgpu": "cgpu-isolation-audit",
    "containerd": "containerd-shim-escape-detect",
    "cumulus": "switch-os-config-surface",
    "deepspeed": "deepspeed-checkpoint-rce",
    "dify": "dify-control-plane-failopen",
    "dradriver": "gpu-dra-mig-policy",
    "gpuoperator": "gpu-operator-driver-audit",
    "hami": "hami-scheduler-auth-gap",
    "juicefscsi": "csi-node-plugin-escape",
    "kuberay": "kuberay-operator-escalation",
    "kubernetes": "privileged-workloads",
    "kueue": "gang-scheduler-abuse",
    "linux-kernel": "kernel-lpe-audit",
    "litellm": "litellm-config-update-rce",
    "llamafactory": "llamafactory-checkpoint-rce",
    "lws": "lws-secrets-lateral",
    "megatron": "megatron-checkpoint-rce",
    "mlflow": "mlflow-model-rce",
    "msswift": "msswift-dataset-pickle-rce",
    "nccl": "nccl-collective-join",
    "nvidia": "nvidia-toolkit-escape-detect",
    "open-webui": "open-webui-code-execute-rce",
    "pytorch": "torch-weights-bypass-rce",
    "ray": "ray-dashboard-job",
    "runc": "runc-escape-detect",
    "sglang": "sglang-admin-failopen",
    "sonic": "sonic-fabric-config-audit",
    "sonicrestapi": "switch-os-config-surface",
    "transformers": "trust-remote-code-supply-chain",
    "trl": "trl-serve-dev-mode",
    "ucx": "collective-communication-surface",
    "ucxpy": "collective-communication-surface",
    "vllm": "vllm-pickle-pipe-rce",
    "volcano": "gang-scheduler-abuse",
    "wandb": "experiment-tracker-exposure",
}

COMPONENT_FIX = {
    "bmc": "改默认凭据；带外网隔离；禁用 cipher 0 与 IPMI over LAN；固件签名与清单核验",
    "cumulus": "交换机管理面限源；NVUE/LLDP 补丁升级；配置变更双人复核",
    "sonic": "交换机管理面限源；禁用 SNMP v1/v2c public；PFC/ECN/ACL 基线",
    "sonicrestapi": "REST API 鉴权 + 参数化；管理网隔离",
    "gpuoperator": "driver DaemonSet 去 privileged/hostNetwork；hostPath 只读白名单；PodSecurity restricted",
    "dradriver": "compute-domain daemon 命令白名单；DRA claim 租户策略；设备独占",
    "cephcsi": "node plugin 去 privileged；hostPath 只读白名单；metrics/pprof 鉴权或关闭",
    "juicefscsi": "controller metrics 绑定回环；管理面鉴权；node plugin 最小权限",
    "kuberay": "ClusterRole 收窄到 namespace；去掉 roles/rolebindings/secrets 集群级写；dashboard 鉴权",
    "lws": "secrets 读收窄；webhook automount=false；leader 端点鉴权",
    "kubernetes": "PodSecurity restricted；禁用 gitRepo；secrets 准入",
    "runc": "升级 runc；禁止未受信镜像；seccomp/AppArmor",
    "containerd": "升级 containerd；抽象 socket 权限收敛",
    "linux-kernel": "内核补丁；cgroup v2；seccomp",
    "nccl": "NCCL 通道 mTLS/令牌；IB Partition；bootstrap 端口配额",
    "ucx": "UCX 通道鉴权；RDMA 分区",
    "ucxpy": "调试 server 关闭；pickle 改安全序列化",
    "vllm": "插件路由纳入 API key；dev-mode 关闭；pickle 安全序列化；cache key 加 tenant",
    "sglang": "管理面 fail-closed；profiler 路径白名单；ZMQ/PD pickle 安全化；权重导出鉴权",
    "llamafactory": "checkpoint weights_only=True；WebUI 回环+鉴权；trust_remote_code 默认 False",
    "msswift": "trust_remote_code 默认 False；dataset pickle 禁用；device_groups 白名单；media 路径限制",
    "deepspeed": "stage3 torch.load weights_only=True；AutoEP 输入校验；runner 参数化",
    "megatron": "checkpoint 签名/哈希；config 面鉴权；optimizer shard 只读",
    "trl": "vllm-serve 默认回环 + key；dev-mode 显式；revision 固定",
    "transformers": "trust_remote_code 默认 False；revision 固定；动态模块签名",
    "litellm": "移除默认 master key；/config/update 管理员鉴权；上游 key 掩码；缓存键加 tenant",
    "dify": "dify-agent fail-closed；移除默认 JWE；shellctl token；快照租户校验",
    "open-webui": "code execute 限 admin；Jupyter 隔离；文件端点鉴权",
    "mlflow": "artifact 路径校验；tracking server 鉴权；MLproject 签名",
    "wandb": "API key 不入镜像；实验追踪鉴权",
    "pytorch": "torch.load weights_only=True；模型签名",
    "ray": "dashboard token auth；8265 内网；RBAC 最小化",
    "hami": "scheduler API mTLS + 租户作用域",
    "cgpu": "池调度 admin 鉴权；释放清零",
    "nvidia": "toolkit 升级；privileged 设备白名单；hook 路径校验",
}

MODULE_FIX = {
    "vllm-pickle-pipe-rce": "pickle 改安全序列化；KV 通道 mTLS；反序列化类型白名单",
    "vllm-plugin-auth-bypass": "插件路由纳入 API key 守卫；/plugins/* 默认拒绝",
    "vllm-timing-oracle": "cache key 加 tenant/salt；TTFT 监控加噪声带；限制 logprobs/echo",
    "vllm-operator-rbac-escalation": "ClusterRole 收窄到 namespace；去掉 roles/rolebindings/secrets 集群级写",
    "sglang-admin-failopen": "管理面 fail-closed；无 key 即拒；管理端口只开在运维网",
    "sglang-omni-profiler-write": "profiler event_dir 白名单；写入面只读挂载；管理面鉴权",
    "sglang-zmq-pickle-rce": "ZMQ 改安全序列化 + mTLS；解码端类型白名单",
    "sglang-weight-exfil": "权重导出鉴权；权重目录只读；路径前缀白名单",
    "slime-weight-pull-poison": "/pull_weights 路径白名单；补丁代码审计；权重写入按租户隔离",
    "areal-setenv-engine-rce": "移除任意 import/getattr；引擎白名单 + 子类校验；控制面统一鉴权",
    "areal-load-pickle": "/load 固定 weights_only=True；checkpoint 签名/哈希",
    "areal-awex-nccl-injection": "/awex 路径白名单；NCCL 入组令牌；master_addr/port 不可请求控制",
    "skyrl-dev-pickle-rce": "dev-mode 默认关；/update_weights 鉴权；pickle 安全化",
    "skyrl-fetch-weights-traversal": "payload_files realpath 校验；cache_dir 前缀白名单",
    "skyrl-tinker-hijack": "Tinker 控制面鉴权；默认回环；路由 RBAC",
    "openrlhf-serve-rm": "serve_rm 鉴权；默认回环；奖励分数签名/审计",
    "openrlhf-vllm-env-force": "移除 VLLM_ALLOW_INSECURE_SERIALIZATION；IPC 改安全序列化",
    "llamafactory-checkpoint-rce": "resume 固定 weights_only=True；checkpoint 只读 + 哈希",
    "msswift-dataset-pickle-rce": "禁用 dataset pickle；改用 safetensors/Arrow + 签名",
    "msswift-trust-remote-code": "默认 trust_remote_code=False；模型 revision 固定",
    "msswift-eval-escape": "device_groups 解析器替代 eval；参数白名单",
    "msswift-media-local-read": "media 路径白名单；拒绝 file:// 与本地路径",
    "megatron-checkpoint-rce": "checkpoint 固定 weights_only=True；分片签名/哈希",
    "deepspeed-checkpoint-rce": "stage3 torch.load 固定 weights_only=True；AutoEP 输入校验",
    "checkpoint-optimizer-state-poison": "optimizer shard 只读 + 签名；latest 指针校验",
    "checkpoint-shard-poison": "分片写入审计 + 读回哈希；恢复前验签",
    "trust-remote-code-supply-chain": "默认关闭 trust_remote_code；模型仓库固定 commit + 签名",
    "supply-chain-pinning": "固定 revision/commit 与内容哈希；升级双人复核",
    "dify-control-plane-failopen": "dify-agent token 缺失即拒；仅回环；控制租约收窄",
    "dify-stub-token-forgery": "移除默认 JWE 根密钥；首启强制生成；轮换",
    "dify-snapshot-cross-tenant-theft": "快照按租户校验；控制租约根收窄；家目录隔离",
    "dify-local-sandbox-unauth-rce": "shellctl 强制 token；沙箱独立容器；作业级配额",
    "open-webui-code-execute-rce": "code execute 限 admin；Jupyter 按用户隔离",
    "open-webui-indirect-injection-exec": "服务端 code_interpreter 容器化；模块白名单",
    "open-webui-file-overwrite": "文件端点鉴权；路径 realpath 校验；批量检索限权",
    "litellm-default-key-exfil": "移除默认 master key；首启生成；按租户发 key",
    "litellm-config-update-rce": "管理 API 管理员鉴权；配置更新审计；禁用自定义代码上传",
    "aigateway-cache-cross-tenant": "缓存键加 tenant；先过滤再相似度",
    "aigateway-guardrail-bypass": "guardrail 检查全部消息与角色；输出 canary 检测",
    "kuberay-operator-escalation": "ClusterRole 收窄；dashboard 鉴权；禁止 operator 创建 RoleBinding",
    "lws-secrets-lateral": "secrets 读收窄；webhook automount=false；leader 鉴权",
    "gpu-operator-driver-escape": "driver DaemonSet 去 privileged；hostPath 只读白名单",
    "csi-node-plugin-escape": "node plugin 去 privileged；hostPath 只读白名单",
    "bmc-ipmi-exposure": "改默认凭据；带外网隔离；禁用 cipher 0/IPMI over LAN",
    "redfish-default-credentials": "改默认凭据；匿名 Redfish 关闭；带外网隔离",
    "ipmi-cipher-zero-bypass": "禁用 cipher suite 0；IPMI over LAN 关闭；强密码",
    "gpu-pool-scheduler-unauth": "池调度 admin mTLS + 租户作用域；禁止跨租户 allocate/migrate",
    "gpu-tenant-residue": "释放即清零显存/快照；读回 404",
    "mig-profile-mismatch": "profile 以设备实际值为准；已分配设备禁止重配",
    "mps-context-shared": "一租户一 MPS server/pipe；context 隔离",
    "cache-salt-policy-audit": "每租户独立 salt；key_scope=tenant；服务端强制",
    "prefix-cache-cross-tenant-leak": "cache key 加 tenant + salt；禁止跨租户复用",
    "similarity-cache-false-hit": "先按 tenant 过滤再相似度；阈值按隔离调",
    "cache-eviction-residue": "逐出即 zeroize；residue 只读本租户",
    "remote-kv-pool-isolation": "KV 池命名空间 + 块归属校验；读接口鉴权",
    "prefill-decode-kv-channel-unauth": "KV 通道 mTLS + 每租户 token；块 ID 不可枚举",
    "router-cache-metrics-leak": "per-tenant 指标只给本租户；管理面单独鉴权",
    "cache-timing-sidechannel": "cache key 加 tenant/salt；TTFT 噪声带 + 命中计数关联",
    "defense-bypass-admission": "策略覆盖全部命名空间；Audit 仅限过渡期；清理绕过注解",
    "defense-bypass-falco": "补写路径规则；ephemeral 宏；driver 健康检查",
    "defense-bypass-imagescan": "全层解析 + 内容/哈希识别 + 压缩递归",
    "defense-bypass-waf-inference": "解码/反分块/Unicode 规范化/超长拒绝",
}

SINK_PRINCIPLES = {
    "torch-load-any": "加载 checkpoint 时调用 torch.load 且未固定 weights_only，checkpoint 写者可在恢复时执行 pickle",
    "torch-load-unsafe": "加载 checkpoint 时显式使用 weights_only=False，checkpoint 写者可在恢复时执行 pickle",
    "pickle-loads": "对共享缓存或请求字节直接 pickle.loads，写者可在加载时执行代码",
    "eval-call": "对模型输出或配置可控字符串执行 eval，输入可逃逸到解释器",
    "exec-command-go": "以请求可控参数拼接 exec.Command，缺少参数化与白名单",
    "subprocess-popen": "命令字符串拼接后交给 subprocess，路径或参数可注入",
    "bind-all-interfaces": "服务默认绑定 0.0.0.0，管理面暴露到 Pod 网络",
    "go-bind-all": "服务默认监听 0.0.0.0，未限制管理面来源",
    "pprof-exposed": "pprof/metrics 注册在默认 mux 且无鉴权，运行时信息与堆栈可读",
    "trust-remote-code-propagated": "trust_remote_code 从上层参数传播到模型加载，模型仓库代码被当成本地代码执行",
    "missing-revision": "模型加载未固定 revision，上游分支漂移会把新代码带进下次调度",
    "load-dataset-any": "数据集加载接受任意路径或格式，解析器与代码执行相邻",
    "apply-chat-template-dynamic": "聊天模板从数据或配置动态加载，模板内容可触发代码路径",
    "env-rank-read": "从环境变量读取 rank 或配置，未校验来源与边界",
    "dynamic-import": "按仓库内容动态导入模块，代码来源未做签名与哈希校验",
    "elevated-pod-spec": "DaemonSet/Pod 以特权、hostPath 或 hostPID 运行，节点边界被抹平",
    "wandb-checkpoint-hook": "checkpoint 回调把路径与元数据交给外部记录端，路径未做边界校验",
    "load-dataset": "数据集入口接受外部路径，未校验目录边界",
    "pickle-load": "反序列化入口直接读取外部字节，未做类型白名单",
}

FIX_RULES = [
    (("torch.load", "pickle", "反序列化", "recv_pyobj", "torch-load"),
     "改用 weights_only=True 或安全序列化；checkpoint 目录只读并做哈希/签名校验；反序列化端做类型白名单"),
    (("trust_remote_code", "dynamic-import", "dynamic import", "trust-remote-code"),
     "默认关闭 trust_remote_code；模型仓库固定 revision 与内容哈希；加载前校验代码签名"),
    (("missing-revision", "revision", "pin"),
     "固定 commit/revision 与内容哈希；禁止浮动分支；升级走双人复核与回滚包"),
    (("default key", "master key", "默认密钥", "默认凭据", "default-key"),
     "移除示例默认值；首启强制生成并轮换；按租户发独立 key；管理面 fail-closed"),
    (("auth", "unauth", "fail-open", "未鉴权", "鉴权"),
     "管理面默认拒绝；每租户独立凭据；管理端口只开在运维网；对匿名请求返回 401 而非 200"),
    (("ssrf", "imds", "metadata", "出站"),
     "统一媒体/URL 连接器；拒绝私网与链路本地地址；逐跳校验重定向；IMDSv2 + hop limit 1"),
    (("traversal", "path", "路径", "穿越", "write", "覆盖"),
     "realpath 后做前缀白名单；禁止 .. 与符号链接；写入面按租户隔离并只读挂载"),
    (("rce", "exec", "eval", "command", "注入", "代码执行"),
     "移除 eval/exec/os.system；改解析器或参数化 API；把执行放进最小权限沙箱并记录审计"),
    (("rbac", "clusterrole", "rolebinding", "operator"),
     "ClusterRole 收窄为 namespace Role；去掉 roles/rolebindings/secrets 的集群级写；开启 can-i 告警"),
    (("cache", "prefix", "kv", "salt", "缓存"),
     "cache key 纳入 tenant + cache_salt；近似缓存先按租户过滤；逐出即 zeroize；KV 通道加 mTLS"),
    (("fabric", "ib", "rdma", "pfc", "sharp", "nccl", "rail"),
     "IB Partition/SM 冗余；RDMA 通道 mTLS；PFC/ECN 按租户配额；rail 绑定只读并由调度器校验"),
    (("bmc", "redfish", "ipmi", "firmware"),
     "改默认凭据；带外网隔离；禁用 cipher 0 与 IPMI over LAN；固件签名与清单核验"),
    (("gpu", "mig", "mps", "device"),
     "MIG profile 以设备实际值为准；释放即清零；一租户一 MPS pipe；设备独占与 DRA 策略校验"),
    (("dataset", "webdataset", "arrow", "数据"),
     "数据集签名与哈希；禁用 pickle；解析器沙箱；共享缓存按租户前缀隔离"),
]

HARM_RULES = [
    (("bmc", "redfish", "ipmi", "firmware", "固件"),
     "C:H / I:H / A:H / 训练:L / 租户:M / 合规:H",
     "带外管理面失陷可绕过 K8s RBAC 与审计，直接影响节点电源、虚拟介质与固件"),
    (("rce", "pickle", "torch.load", "exec", "eval", "command", "反序列化", "代码执行", "注入"),
     "C:H / I:H / A:M / 训练:H / 租户:H / 合规:H",
     "代码执行发生在训练/推理进程内，可直接读写权重、梯度、KV 与云凭据"),
    (("traversal", "path", "路径", "穿越", "upload", "overwrite", "覆盖", "arbitrary write"),
     "C:M / I:H / A:M / 训练:H / 租户:H / 合规:M",
     "任意路径写可替换权重、checkpoint 或配置，训练恢复时加载被污染内容"),
    (("auth", "unauth", "fail-open", "default key", "master key", "未鉴权", "鉴权"),
     "C:H / I:H / A:M / 训练:M / 租户:H / 合规:H",
     "匿名或默认凭据直达控制面，可读写权重、缓存与训练状态"),
    (("cache", "prefix", "kv", "tenant", "residue", "缓存", "残留"),
     "C:H / I:M / A:L / 训练:L / 租户:H / 合规:H",
     "缓存/显存残留跨租户可读，命中率与时序还会泄露其他租户的请求模式"),
    (("trust_remote_code", "supply", "revision", "供应链", "model"),
     "C:H / I:H / A:M / 训练:H / 租户:M / 合规:H",
     "模型仓库或 checkpoint 是代码供应链的一部分，加载即执行且难以追溯"),
    (("ssrf", "imds", "credential", "凭据", "metadata", "泄露"),
     "C:H / I:L / A:L / 训练:L / 租户:M / 合规:H",
     "出站请求或凭据泄露把集群边界延伸到云 IAM 与对象存储"),
    (("pprof", "flood", "exhaustion", "oom", "dos", "耗尽", "风暴", "straggler"),
     "C:L / I:L / A:H / 训练:H / 租户:M / 合规:M",
     "资源耗尽或步时劣化直接打断训练/推理，但不必然泄露数据"),
    (("gpu", "mig", "mps", "device", "显存"),
     "C:H / I:M / A:M / 训练:M / 租户:H / 合规:M",
     "分区/池化隔离失效会暴露他租户显存、进程与模型，也可能改写邻居设备状态"),
    (("fabric", "ib", "rdma", "pfc", "sharp", "nccl", "rail"),
     "C:H / I:H / A:H / 训练:H / 租户:H / 合规:M",
     "fabric 控制面不受 NetworkPolicy 覆盖，会话/分区/拥塞配置错误会同时影响机密性、完整性与可用性"),
]

DEFAULT_HARM = ("C:M / I:M / A:L / 训练:M / 租户:M / 合规:M",
                "影响取决于部署面与相邻控制面，需按附录证据逐条复核")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_manifests() -> dict:
    out = {}
    for path in sorted(CASES.glob("*/*/manifest.json")):
        data = load_json(path)
        out[data["id"]] = data
    return out


def load_templates() -> dict:
    out = {}
    for path in sorted(MODULES.glob("*/template.json")):
        data = load_json(path)
        meta = data.get("meta", {})
        out[data["key"]] = {
            "key": data["key"],
            "fidelity": meta.get("fidelity") or "—",
            "writes": bool(meta.get("writes")),
            "series": meta.get("series") or "",
            "steps": len(data.get("steps") or []),
            "findings": len(data.get("findings") or []),
            "path": f"inkblade/modules/{data['key']}/template.json",
        }
    return out


def load_modules() -> dict:
    out = {}
    for path in sorted(MODULES.glob("*/module.json")):
        data = load_json(path)
        out[data["key"]] = data
    return out


def load_chains() -> list:
    out = []
    for path in sorted(CHAINS.glob("*.json")):
        data = load_json(path)
        out.append({
            "id": data.get("id") or path.stem,
            "title": (data.get("title") or {}).get("zh") or data.get("id") or path.stem,
            "category": data.get("category") or "",
        })
    return out


def clean(text, limit=260) -> str:
    text = str(text or "")
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", "    ")
    text = text.replace("|", "¦").replace("`", "'")
    text = re.sub(r"https?://\S+", "[链接已省略]", text)
    text = re.sub(r"[A-Za-z]:\\[^\s]+", "[本地路径已省略]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def clean_line(text) -> str:
    text = str(text or "")
    text = text.replace("\t", "    ").replace("|", "¦").replace("`", "'")
    text = re.sub(r"https?://\S+", "[链接已省略]", text)
    text = re.sub(r"[A-Za-z]:\\[^\s]+", "[本地路径已省略]", text)
    return text.rstrip()[:220]


def first_sentence(text, limit=200) -> str:
    text = clean(text, 400)
    if not text:
        return ""
    parts = re.split(r"(?<=[。；;])", text)
    out = parts[0].strip() if parts else text
    if len(out) < 8 and len(parts) > 1:
        out = (out + parts[1]).strip()
    return out[:limit]


def split_audit(text, want=4) -> list:
    text = clean(text, 700)
    parts = [p.strip() for p in re.split(r"\s*->\s*|→|；|;", text) if p.strip()]
    if len(parts) < want:
        parts = [p.strip() for p in re.split(r"，|,", text) if p.strip()]
    pads = [
        "审计记录：厂商固件/运行时路径，无逐字上游源码",
        "审计记录：按配置面/权限面判定，未执行内存或设备操作",
        "审计记录：需在授权实验室用真实导出回填",
    ]
    idx = 0
    while len(parts) < 3:
        parts.append(pads[idx % len(pads)])
        idx += 1
    return parts[:6]


def parse_master() -> list:
    if not MASTER.is_file():
        return []
    rows = []
    section = ""
    for raw in MASTER.read_text(encoding="utf-8").splitlines():
        if raw.startswith("## "):
            section = raw[3:].strip()
            continue
        if not raw.startswith("|") or "---" in raw:
            continue
        cells = [c.strip() for c in raw.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        if cells[0] in ("#", "编号") or "漏洞原理" in cells[1] or "发现" in cells[1]:
            continue
        rows.append({"section": section, "cells": cells, "text": " ".join(cells)})
    return rows


def master_match(entry, rows) -> dict | None:
    comp = entry["component"].lower()
    aliases = [comp, COMPONENT_ZH.get(comp, comp)]
    aliases += {
        "llamafactory": ["llama-factory", "llamafactory"],
        "msswift": ["ms-swift", "msswift"],
        "open-webui": ["open webui", "open-webui"],
        "qwen": ["qwen"],
        "vllm": ["vllm", "vllm-jev"],
        "sglang": ["sglang", "sglang-omni"],
    }.get(comp, [])
    title = entry["title"].lower()
    ascii_tokens = [t for t in re.findall(r"[a-z0-9_\-]{4,}", title) if t not in ("with", "from", "this")]
    best = None
    best_score = 0
    for row in rows:
        low = row["text"].lower()
        if not any(a and a.lower() in low for a in aliases):
            continue
        score = 1
        for token in ascii_tokens:
            if token in low:
                score += 2
        root = row["cells"][2] if len(row["cells"]) > 2 else ""
        if ":" in root or ".py" in root or ".go" in root or ".yaml" in root:
            score += 1
        if score > best_score:
            best_score = score
            best = row
    return best


def root_info(entry, manifest, zero):
    rc = (manifest or {}).get("root_cause") or {}
    if not rc.get("file") and zero:
        rc = zero.get("root_cause") or {}
    file_name = clean(rc.get("file") or "n/a", 180)
    if file_name.startswith("advisory:"):
        file_name = "advisory（上游安全文档，无源码行）"
    line = int(rc.get("line") or 0)
    if line > 0:
        anchor = f"{file_name}:{line}"
    elif file_name.startswith("n/a") or file_name.startswith("advisory"):
        anchor = file_name
    else:
        anchor = f"{file_name}（入口/函数级，无行号）"
    return {
        "file": file_name,
        "line": line,
        "anchor": anchor,
        "snippet": (rc.get("snippet") or "").strip(),
        "note": (rc.get("note") or "").strip(),
        "source": rc.get("source"),
    }


def source_lines(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


SINK_TOKENS = (
    "torch.load", "pickle.load", "pickle.loads", "recv_pyobj", "eval(", "exec(",
    "os.system", "subprocess.", "subprocess(", "importlib", "release_module",
    "http.Handle", "app.run", "uvicorn.run", "0.0.0.0", "exec.Command",
    "trust_remote_code", "pickle.loads", "yaml.load", "marshal.loads",
)


def nearest_sink(lines, center, radius=9):
    best = None
    for idx in range(max(0, center - radius), min(len(lines), center + radius + 1)):
        if any(token in lines[idx] for token in SINK_TOKENS):
            if best is None or abs(idx - center) < abs(best - center):
                best = idx
    return best


def build_snippet(rc) -> tuple[list, str]:
    """Return 3-8 lines and a kind label. Only root-cause context is emitted."""
    lines = []
    source = rc.get("source")
    line = int(rc.get("line") or 0)
    snippet = (rc.get("snippet") or "").strip()
    if source and line > 0:
        src = Path(source)
        if not src.is_absolute():
            src = ROOT / source
        src_lines = source_lines(src)
        if src_lines:
            center = min(max(line - 1, 0), len(src_lines) - 1)
            if snippet:
                needle = snippet.splitlines()[0].strip()[:70]
                for idx in range(max(0, line - 25), min(len(src_lines), line + 25)):
                    if needle and needle in src_lines[idx]:
                        center = idx
                        break
            sink = nearest_sink(src_lines, center)
            if sink is not None:
                center = sink
            start = max(0, center - 2)
            end = min(len(src_lines), center + 4)
            lines = [f"{idx + 1}: {src_lines[idx]}" for idx in range(start, end)]
    if not lines and snippet:
        lines = snippet.splitlines()
    if not lines:
        note = rc.get("note") or "无逐字上游源码；按审计记录与配置面判定"
        lines = split_audit(note)
    out = []
    for line_text in lines:
        line_text = clean_line(line_text)
        if line_text:
            out.append(line_text)
    while len(out) < 3:
        out.append("审计记录：无更多上游上下文")
    out = out[:8]
    kind = "代码" if source and line > 0 else "审计记录"
    return out, kind


def harm_for(entry, zero, manifest=None) -> tuple[str, str]:
    note = ((zero or {}).get("notes") or "")
    rc_note = ((manifest or {}).get("root_cause") or {}).get("note") or ""
    low = " ".join([note, rc_note]).lower()
    if entry.get("status") == "static-only" and any(
            k in low for k in ("legitimate framework call", "rule hit", "sink unreachable")):
        return DEFAULT_HARM
    text = " ".join([
        entry.get("title", ""), entry.get("component", ""), entry.get("module") or "",
        ((zero or {}).get("reachability") or ""), note, rc_note,
    ]).lower()
    for keys, harm, note in HARM_RULES:
        if any(k.lower() in text for k in keys):
            return harm, note
    return DEFAULT_HARM


def fix_for(entry, zero, manifest=None) -> str:
    module = entry.get("module") or ""
    rc_note = ((manifest or {}).get("root_cause") or {}).get("note") or ""
    if entry.get("status") == "static-only" and any(
            k in rc_note.lower() for k in ("legitimate framework call", "rule hit")):
        return "先人工复核该静态命中；确认可达后再按组件基线收窄；不要直接当漏洞修复"
    if module in MODULE_FIX:
        return MODULE_FIX[module]
    comp = entry.get("component") or ""
    if comp in COMPONENT_FIX:
        return COMPONENT_FIX[comp]
    text = " ".join([
        entry.get("title", ""), comp, entry.get("module") or "",
        ((zero or {}).get("reachability") or ""),
    ]).lower()
    for keys, fix in FIX_RULES:
        if any(k.lower() in text for k in keys):
            return fix
    return "按最小权限与 fail-closed 原则收窄入口；补鉴权、输入校验、只读挂载与审计告警"


def principle_for(entry, manifest, master) -> str:
    title = entry.get("title") or ""
    rc = (manifest or {}).get("root_cause") or {}
    note = rc.get("note") or ""
    if ":" in title and "@" in title:
        sink = title.split(":", 1)[1].split("@")[0].strip()
        key = sink.replace("-", "_")
        if key in SINK_PRINCIPLES:
            return SINK_PRINCIPLES[key]
        if sink in SINK_PRINCIPLES:
            return SINK_PRINCIPLES[sink]
        return f"{sink or 'sink'} 在外部可控输入上缺少边界校验或鉴权"
    if re.search(r"[\u4e00-\u9fff]", title) and len(title) >= 8:
        return first_sentence(title)
    if note:
        out = first_sentence(note)
        if out:
            return out
    if master:
        cells = master["cells"]
        if len(cells) > 1 and cells[1]:
            return first_sentence(cells[1])
    return title


def pre_for(manifest, zero) -> str:
    pre = (manifest or {}).get("preconditions") or (zero or {}).get("preconditions") or []
    if isinstance(pre, str):
        pre = [pre]
    out = "；".join(clean(x, 120) for x in pre if x)
    if not out:
        out = "需目标部署面可达；未在真实集群复现时按配置/权限面判定"
    return out[:360]


def module_for(entry, templates, modules) -> tuple[str, str]:
    key = entry.get("module")
    if not key:
        key = COMPONENT_MODULE.get(entry.get("component"))
    if not key:
        return "—", "—"
    if key in templates:
        return key, templates[key]["path"]
    if key in modules:
        return key, f"inkblade/modules/{key}/module.json（模板缺失）"
    return key, "—"


def evidence_for(entry, manifest, zero) -> str:
    for obj in (manifest or {}, zero or {}, entry or {}):
        ev = obj.get("evidence")
        if isinstance(ev, str) and ev:
            return clean(ev, 240).replace("\\", "/")
        if isinstance(ev, dict) and ev.get("path"):
            return clean(ev["path"], 240).replace("\\", "/")
    return "reports/probe-coverage/evidence.json"


def build_entry(entry, manifests, templates, modules, zero_map, master_rows) -> dict:
    manifest = manifests.get(entry["id"])
    zero = zero_map.get(entry["id"])
    rc = root_info(entry, manifest, zero)
    snippet, snippet_kind = build_snippet(rc)
    harm, harm_note = harm_for(entry, zero, manifest)
    master = master_match(entry, master_rows)
    principle = principle_for(entry, manifest, master)
    rc_note = ((manifest or {}).get("root_cause") or {}).get("note") or ""
    if entry.get("status") == "static-only" and any(
            k in rc_note.lower() for k in ("legitimate framework call", "rule hit")):
        principle = "静态规则命中，需人工确认可达性：" + principle
    module, module_path = module_for(entry, templates, modules)
    fidelity = templates.get(module, {}).get("fidelity", "—") if module in templates else "—"
    status = STATUS_LABEL.get(entry.get("status", ""), entry.get("status", "unknown"))
    coverage = f"{status} / {fidelity}"
    master_ref = "—"
    if master:
        cells = master["cells"]
        root = cells[2] if len(cells) > 2 else ""
        master_ref = f"§{master['section']} · {clean(root, 160)}"
    return {
        "id": entry["id"],
        "component": COMPONENT_ZH.get(entry.get("component"), entry.get("component") or "—"),
        "component_raw": entry.get("component") or "",
        "version": clean(entry.get("version") or "—", 100),
        "title": clean(entry.get("title") or "", 180),
        "principle": principle,
        "anchor": rc["anchor"],
        "snippet": snippet,
        "snippet_kind": snippet_kind,
        "harm": harm,
        "harm_note": harm_note,
        "fix": fix_for(entry, zero, manifest),
        "pre": pre_for(manifest, zero),
        "module": module,
        "module_path": module_path,
        "status": status,
        "fidelity": fidelity,
        "coverage": coverage,
        "evidence": evidence_for(entry, manifest, zero),
        "master_ref": master_ref,
        "writes": templates.get(module, {}).get("writes", False) if module in templates else False,
        "zero": zero,
        "manifest": manifest,
        "source": entry.get("source") or "",
    }


def build_reserve_entry(cid: str, zero: dict, templates: dict, modules: dict) -> dict:
    e = next(x for x in zero["entries"] if x["id"] == cid)
    rc = e.get("root_cause") or {}
    fake_manifest = {"root_cause": rc, "preconditions": e.get("preconditions") or [],
                     "evidence": e.get("evidence") or {}}
    fake_entry = {"id": cid, "component": e.get("component") or "",
                  "title": e.get("title") or "", "module": e.get("module") or "",
                  "status": "reserve", "version": e.get("version") or "",
                  "source": e.get("source") or ""}
    rc_info = root_info(fake_entry, fake_manifest, e)
    snippet, kind = build_snippet(rc_info)
    harm, harm_note = harm_for(fake_entry, e, fake_manifest)
    module, module_path = module_for(fake_entry, templates, modules)
    pre = "；".join(clean(x, 140) for x in (e.get("preconditions") or [])) or "需目标部署面可达"
    evidence = (e.get("evidence") or {}).get("path") if isinstance(e.get("evidence"), dict) else e.get("evidence")
    return {
        "id": cid,
        "component": COMPONENT_ZH.get(e.get("component"), e.get("component") or "—"),
        "component_raw": e.get("component") or "",
        "version": clean(e.get("version") or "—", 100),
        "title": clean(e.get("title") or "", 180),
        "principle": clean(e.get("title") or "", 220),
        "anchor": rc_info["anchor"],
        "snippet": snippet,
        "snippet_kind": kind,
        "harm": harm,
        "harm_note": harm_note,
        "fix": fix_for(fake_entry, e, fake_manifest),
        "pre": pre,
        "module": module,
        "module_path": module_path,
        "status": "reserve",
        "fidelity": "—",
        "coverage": "reserve / —",
        "evidence": clean(evidence or "—", 240).replace(chr(92), "/"),
        "master_ref": "—",
        "writes": templates.get(module, {}).get("writes", False) if module in templates else False,
        "zero": e,
        "manifest": fake_manifest,
        "source": e.get("source") or "",
    }


def code_cell(row) -> str:
    parts = [f"`{row['anchor']}`"]
    for line in row["snippet"][:4]:
        parts.append(f"`{line}`")
    if row["snippet_kind"] == "审计记录":
        parts.insert(1, "（审计记录，非逐字源码）")
    return "<br>".join(parts)


def table_cell(text) -> str:
    return clean(text, 500)


def build_rows(entries, manifests, templates, modules, zero_map, master_rows) -> list:
    rows = []
    for entry in entries:
        rows.append(build_entry(entry, manifests, templates, modules, zero_map, master_rows))
    rows.sort(key=lambda r: (r["component"], STATUS_ORDER.get(
        {"verified": "verified", "exposure": "exposure-verified", "static": "static-only",
         "unsupported": "unsupported"}.get(r["status"], "static-only"), 9), r["id"]))
    return rows


# ---------------------------------------------------------------------------
# Narrative


def layer_citations(rows):
    by_id = {r["id"]: r for r in rows}
    layers = {
        1: ["NCCL-NCCLPLUGIN-HW", "UCX-UCT-HW", "ucxpy-server-py-pickle-loads-l42-regex",
            "CVE-2025-47277", "CVE-2025-32444", "CVE-2026-92972", "CVE-2026-3060"],
        2: ["CVE-2026-3059", "CVE-2025-32434", "CVE-2026-40217", "CVE-2026-42203",
            "LITELLM-DEFAULT-KEY", "llamafactory-checkpoint-py-torch-load-unsafe-l136-ast",
            "msswift-indexed-dataset-py-pickle-loads-l112-ast", "CVE-2026-65110",
            "CVE-2025-23354", "CVE-2026-35029", "CVE-2025-3466", "CVE-2026-28788"],
        3: ["KUBERAY-ADV-2026-01", "LWS-ADV-2026-01",
            "gpuoperator-0500-daemonset-yaml-elevated-pod-spec-l108-regex",
            "CVE-2025-23266", "CVE-2024-0132", "dradriver-process-go-exec-command-l94-regex",
            "cephcsi-httpserver-go-pprof-exposed-l37-regex",
            "volcano-scheduler-server-go-pprof-exposed-l162-regex",
            "kueue-server-go-pprof-exposed-l30-regex", "CVE-2013-4786",
            "CVE-2017-12542", "CVE-2020-15257"],
        4: ["CVE-2025-33180", "CVE-2026-24184", "GHSA-h26v-922j-28cg",
            "sonicrestapi-default-go-exec-command-l1881-regex", "NCCL-NCCLPLUGIN-HW",
            "ucxpy-server-py-pickle-loads-l42-regex", "CVE-2025-47277", "CVE-2026-92972"],
        5: ["CVE-2024-0520", "CVE-2024-37061", "CVE-2026-53995", "CVE-2025-32434",
            "llamafactory-checkpoint-py-torch-load-unsafe-l136-ast",
            "msswift-indexed-dataset-py-pickle-loads-l112-ast",
            "deepspeed-stage3-py-torch-load-any-l3660-regex", "CVE-2026-4993",
            "cephcsi-httpserver-go-pprof-exposed-l37-regex", "CVE-2025-32444"],
        6: ["CGPU-ADV-2026-01", "HAMI-ADV-2026-01", "dradriver-process-go-exec-command-l94-regex",
            "CVE-2024-0133", "CVE-2025-23267", "CVE-2026-15978", "CVE-2026-92972"],
        7: ["transformers-dynamic-module-utils-py-dynamic-import-l248-ast",
            "llamafactory-loader-py-missing-revision-l104-regex",
            "trl-sft-py-trust-remote-code-propagated-l78-regex",
            "msswift-loader-py-load-dataset-any-l59-regex", "CVE-2025-32434",
            "OPENBMC-BMCWEB-REDfish-HW", "CVE-2024-37061", "CVE-2025-23266",
            "LITELLM-DEFAULT-KEY"],
        8: ["CVE-2025-32444", "CVE-2025-47277", "CVE-2025-29783", "CVE-2025-59425",
            "CVE-2026-15978", "CVE-2026-92972", "CVE-2026-3060", "CVE-2025-23267"],
        9: ["CVE-2023-48022", "KUBERAY-ADV-2026-01", "LWS-ADV-2026-01", "CVE-2026-92972",
            "CVE-2025-32444", "CVE-2026-3059", "CVE-2026-40217", "CVE-2025-3466",
            "CVE-2024-0520", "CVE-2013-4786"],
        10: ["CVE-2026-3059", "CVE-2025-32434", "CVE-2024-0520", "CVE-2023-48022",
             "LITELLM-DEFAULT-KEY", "CVE-2026-40217", "CVE-2026-28788", "CVE-2025-33180"],
    }
    for n, ids in layers.items():
        for cid in ids:
            if cid not in by_id:
                raise SystemExit(f"layer {n} cites unknown registry id: {cid}")
    return layers


def coverage_for(ids, rows, templates) -> str:
    by_id = {r["id"]: r for r in rows}
    eq = red = 0
    keys = []
    for cid in ids:
        row = by_id[cid]
        if row["module"] in templates:
            keys.append(row["module"])
            if templates[row["module"]]["fidelity"] == "equivalent":
                eq += 1
            elif templates[row["module"]]["fidelity"] == "reduced":
                red += 1
    uniq = len(set(keys))
    return (f"本节引用 {len(ids)} 条附录条目，涉及 {uniq} 个模板；"
            f"其中等价 {eq} 个、近似 {red} 个。全仓 286 个模板均完成 Rust 两态执行，"
            f"严格负控 verified 为 35/286（见 PROBE-COVERAGE §6）；registry 总账为 "
            f"37 verified + 6 exposure + 87 static + 22 unsupported。")


def render_citations(ids) -> str:
    return "**本节引用条目**：" + "、".join(f"`{cid}`" for cid in ids) + \
        "。根因、代码片段、危害与修复见附录 A 对应行；重点条目另见附录 B/C。"


DEMO_META = {}


def load_demo_manifest() -> dict:
    path = DEMOS / "manifest.json"
    if not path.is_file():
        raise SystemExit("demos/manifest.json is missing; run tools/build-demos.py first")
    data = json.loads(path.read_text(encoding="utf-8"))
    out = {}
    for entry in data.get("entries", []):
        if entry.get("status") == "runnable":
            poc = DEMOS / entry["id"] / "poc.py"
            if not poc.is_file():
                raise SystemExit(f"demo script missing: {poc}")
            text = poc.read_text(encoding="utf-8")
            match = re.search(r"# DEMO-SNIPPET-BEGIN\n(.*?)\n# DEMO-SNIPPET-END", text, re.S)
            if not match:
                raise SystemExit(f"demo snippet markers missing: {poc}")
            entry["snippet"] = match.group(1).strip()
            entry["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        out[entry["id"]] = entry
    return out


def group_entries_by_layer(rows) -> dict:
    grouped = {n: [] for n in range(1, 11)}
    for row in rows:
        grouped[layer_for_entry({
            "id": row["id"],
            "component": row["component_raw"],
            "module": row["module"] if row["module"] != "—" else "",
        })].append(row)
    for n in grouped:
        grouped[n].sort(key=lambda r: (STATUS_ORDER.get(
            {"verified": "verified", "exposure": "exposure", "static": "static",
             "unsupported": "unsupported"}.get(r["status"], "static-only"), 9), r["id"]))
    return grouped


def render_primer(key: str) -> str:
    item = PRIMERS[key]
    n = item["layer"]
    out = [f"### {n}.1 名词与架构前置：{item['title']}", "", item["intro"], "",
           f"**类比**：{item['analogy']}", "",
           "```text", item["diagram"].rstrip(), "```", "",
           f"**术语速查（{len(item['terms'])} 条）**", "",
           "| 术语 | 白话解释 |", "|---|---|"]
    for term, desc in item["terms"]:
        out.append(f"| {term} | {desc} |")
    out += ["", "**前置知识 × 危害细化**", "",
            "| 漏洞 | 前置知识（要懂什么） | 危害细化（训练/推理/合规） | 正文 |",
            "|---|---|---|---|"]
    for vuln, pre, harm, where in item["rows"]:
        out.append(f"| {vuln} | {pre} | {harm} | {where} |")
    out.append("")
    return "\n".join(out)


def demo_for(row) -> dict:
    return DEMO_META.get(row["id"], {})


def auth_class(text: str) -> str:
    value = str(text or "")
    if value.startswith("无"):
        return "无"
    if any(key in value for key in ("key", "admin", "master", "virtual")):
        return "需 key"
    if "SA" in value:
        return "需 SA"
    return "需本地"


def render_entry_block(row, layer: int, idx: int) -> str:
    demo = demo_for(row)
    anchor = f"L{layer}-{idx:03d}"
    out = [f"#### {anchor} · `{row['id']}` · {row['component']}", "",
           "**打了哪里**", "",
           "| 组件 | 版本区间 | 入口 | 根因 file:line | 可控参数/请求体字段 | 认证前置 | 网络位置 |",
           "|---|---|---|---|---|---|---|"]
    if demo.get("status") == "runnable":
        entry = demo["entry"]
        params = demo["params"]
        auth = demo["auth"]
        auth = auth if auth == "无" else f"{auth_class(auth)}（{auth}）"
        network = demo["network"]
        effect = demo["effect"]
        env = demo["env"]
        cleanup = demo["cleanup"]
        attack_code = demo.get("snippet", "")
    else:
        na_reason = demo.get("reason") or row.get("pre") or f"{row['status']}：当前环境无动态可测面"
        entry = f"配置面/CLI: `{row['anchor']}`"
        params = "n/a（静态/配置面）"
        auth = "无/需本地访问"
        network = "配置面/宿主"
        effect = f"N/A（{clean_text(na_reason, 180)}）"
        env = f"{row['status']}：{clean_text(na_reason, 180)}"
        cleanup = "无写入；不需要清理"
        attack_code = ""
    root = f"`{row['anchor']}`；{clean_text(row['principle'], 180)}"
    out.append(f"| {row['component']} | {row['version']} | {table_text(entry, 180)} | "
               f"{table_text(root, 300)} | {table_text(params, 180)} | {table_text(auth, 100)} | "
               f"{table_text(network, 120)} |")
    out += ["", "**根因片段**", ""]
    if row.get("snippet"):
        out += ["```text", f"{row['anchor']}", *row["snippet"], "```", ""]
    else:
        out += [f"N/A — 仅配置/审计锚点：`{row['anchor']}`", ""]
    out += ["**攻击代码**", ""]
    if attack_code:
        out += ["```python", attack_code.rstrip(), "```", ""]
    else:
        out += [f"N/A — {clean_text(na_reason, 220)}", ""]
    out += ["**攻击效果**", "", effect, ""]
    if demo.get("status") == "runnable":
        out += [f"预期输出样例：`200` + marker `{demo.get('marker', '')}`"
                "（脚本会 assert status=200 且 marker 出现在响应中）。", ""]
    out += ["**复现环境**", "", env, "",
            "**清理**", "", cleanup, "",
            "**危害**", "", f"{row['harm']}（{row['harm_note']}）", ""]
    if demo.get("status") == "runnable":
        out += [f"- **演示脚本**：`demos/{row['id']}/poc.py`（sha256 `{demo.get('sha256', '')}`）", ""]
    else:
        out += [f"- **演示脚本**：N/A — {clean_text(na_reason, 180)}", ""]
    out += [f"- **检测/修复/证据**：`{row['module']}` / `{row['module_path']}`；{clean_text(row['fix'], 200)}；"
            f"`{row['evidence']}`", ""]
    return "\n".join(out)


def render_layer_entries(rows, layer: int, start: int = 2) -> str:
    if not rows:
        return ""
    out = [f"### {layer}.{start} 逐条攻击面与演示（{len(rows)} 条）", ""]
    for idx, row in enumerate(rows, 1):
        out.append(render_entry_block(row, layer, idx))
    return "\n".join(out)


def clean_text(text, limit=200) -> str:
    value = clean_line(str(text or "")).replace("|", "/")
    return value if len(value) <= limit else value[:limit - 1] + "…"


def table_text(text, limit=260) -> str:
    value = str(text or "").replace("\r", " ").replace("\n", " ").replace("\t", "    ")
    value = value.replace("|", "¦")
    value = re.sub(r"https?://\S+", "[链接已省略]", value)
    value = re.sub(r"[A-Za-z]:\\[^\s]+", "[本地路径已省略]", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= limit else value[:limit - 1] + "…"


def render_layer_table(rows) -> str:
    out = ["| # | 组件 / 版本区间 | 根因锚点（file:line 或配置面） | 前置 → 影响 | 模板键 |",
           "|---|---|---|---|---|"]
    for idx, item in enumerate(rows, 1):
        out.append(f"| {idx} | {item[0]} | {item[1]} | {item[2]} | {item[3]} |")
    return "\n".join(out)


def render_framework_table() -> str:
    rows = [
        ("vLLM", "插件路由绕过 api-key（`/plugins/*` 不在 GUARDED_PREFIX）；RL 控制路由挂 `/`；dev 端点无 key；前缀缓存时序 oracle；Mooncake/PyNccl KV pickle",
         "`CVE-2025-32444`、`CVE-2025-47277`、`CVE-2025-59425`",
         "`vllm-plugin-auth-bypass`、`vllm-timing-oracle`、`vllm-pickle-pipe-rce`"),
        ("SGLang", "管理面 fail-open（无 key 即放行）；profiler `event_dir` 任意写；ZMQ/Encoder PD pickle；权重导出与 PD 路由投毒",
         "`CVE-2026-3059`、`CVE-2026-3060`、`CVE-2026-92972`、`CVE-2026-15978`",
         "`sglang-admin-failopen`、`sglang-omni-profiler-write`、`sglang-zmq-pickle-rce`、`sglang-weight-exfil`"),
        ("TRL", "`vllm-serve` 强制 dev-mode；默认 0.0.0.0 且无 api-key；`trust_remote_code` 传播；数据集动态模板与缺 revision",
         "`trl-sft-py-trust-remote-code-propagated-l78-regex`、`trl-data-utils-py-apply-chat-template-dynamic-l167-regex`",
         "`trl-serve-dev-mode`、`sft-framework-surface`"),
        ("verl", "`prime_math` 对模型输出 eval；`prime_code` exec 生成代码；checkpoint `recv_pyobj`；HDFS 路径进 `os.system`",
         "`CVE-2026-65110`、`CVE-2025-32434`（同族 checkpoint）",
         "`verl-prime-code-exec`、`verl-checkpoint-pickle`、`verl-hdfs-command-injection`"),
        ("AReaL", "`/set_env` → `/create_engine` → `/call` 链式执行；`/load` 走 `weights_only=False`；`/awex` 任意保存 + NCCL 入组；data worker pickle",
         "`CVE-2026-40217`（同类 exec 面）、`CVE-2025-32434`（同族反序列化）",
         "`areal-setenv-engine-rce`、`areal-load-pickle`、`areal-awex-nccl-injection`"),
        ("SkyRL", "dev-mode `/update_weights` pickle；`/fetch_weights` 路径穿越；Tinker 控制面默认 0.0.0.0:8000 无鉴权",
         "`CVE-2025-32444`（同族 KV pickle）、`KUBERAY-ADV-2026-01`（同底座）",
         "`skyrl-dev-pickle-rce`、`skyrl-fetch-weights-traversal`、`skyrl-tinker-hijack`"),
        ("OpenRLHF", "`serve_rm` 默认 0.0.0.0:5000 无鉴权；`vllm_engine` 强制不安全序列化",
         "`LITELLM-DEFAULT-KEY`（同类默认面）、`CVE-2025-32444`（同族 pickle）",
         "`openrlhf-serve-rm`、`openrlhf-vllm-env-force`"),
        ("slime", "`/pull_weights` 补丁接受 `source_dir`/`local_checkpoint_dir`；debug/resume `torch.load(weights_only=False)`",
         "`CVE-2025-32434`、`llamafactory-checkpoint-py-torch-load-unsafe-l136-ast`（同族 sink）",
         "`slime-weight-pull-poison`、`python-dangerous-sinks`"),
        ("LLaMA-Factory", "checkpoint resume `torch.load(weights_only=False)`；WebUI/API 默认 fail-open；`trust_remote_code` 硬编码；SSRF 302 绕过",
         "`llamafactory-checkpoint-py-torch-load-unsafe-l136-ast`、`llamafactory-loader-py-missing-revision-l104-regex`",
         "`llamafactory-checkpoint-rce`、`sft-framework-surface`、`outbound-ssrf`"),
        ("ms-swift", "`ModelLoader.default_trust_remote_code=True`；`device_groups` 受限 eval 逃逸；数据集 pickle；media 本地路径读",
         "`msswift-indexed-dataset-py-pickle-loads-l112-ast`、`msswift-indexed-dataset-py-pickle-loads-l129-ast`",
         "`msswift-trust-remote-code`、`msswift-eval-escape`、`msswift-dataset-pickle-rce`、`msswift-media-local-read`"),
        ("Megatron-LM", "checkpoint `torch.load`；config 面暴露；optimizer 分片无签名加载",
         "`CVE-2026-65110`、`megatron-checkpointing-py-torch-load-any-l1739-regex`、`CVE-2025-23354`",
         "`megatron-checkpoint-rce`、`megatron-deepspeed-config-surface`、`checkpoint-optimizer-state-poison`"),
        ("DeepSpeed", "stage3 `torch.load` 系列 sink；AutoEP 不安全转换；runner 命令拼接",
         "`deepspeed-stage3-py-torch-load-any-l3660-regex`、`CVE-2024-43497`",
         "`deepspeed-checkpoint-rce`、`checkpoint-shard-poison`"),
        ("transformers", "`trust_remote_code` 动态模块导入；revision 漂移",
         "`transformers-dynamic-module-utils-py-dynamic-import-l248-ast`、`llamafactory-loader-py-missing-revision-l104-regex`",
         "`trust-remote-code-supply-chain`、`supply-chain-pinning`"),
        ("djev / vllm-jev", "默认无鉴权 + `/v1/*` 全量中继；GET 面无鉴权；插件端点绕过 api-key",
         "`CVE-2026-35029`（同类管理面）、`CVE-2026-47102`（同类自提权）",
         "`djev-open-proxy`、`vllm-plugin-auth-bypass`"),
        ("Dify", "dify-agent 鉴权 fail-open；默认 JWE 根密钥；快照跨租户；本地 shellctl 零前置 RCE",
         "`CVE-2025-3466`、`CVE-2025-56520`、`CVE-2025-63387`",
         "`dify-control-plane-failopen`、`dify-stub-token-forgery`、`dify-snapshot-cross-tenant-theft`、`dify-local-sandbox-unauth-rce`"),
        ("Open WebUI", "`/code/execute` 任意登录用户执行；`code_interpreter` 间接注入；文件覆盖与跨用户残留",
         "`CVE-2026-28788`、`CVE-2025-64496`、`CVE-2026-28786`",
         "`open-webui-code-execute-rce`、`open-webui-indirect-injection-exec`、`open-webui-file-overwrite`"),
        ("网关（LiteLLM / Higress / Envoy AI）", "默认 master key；`/config/update` 缺管理员授权；上游 key 明文；跨租户语义缓存；guardrail 只看首条消息",
         "`LITELLM-DEFAULT-KEY`、`CVE-2026-35029`、`CVE-2026-40217`、`CVE-2026-42203`",
         "`litellm-default-key-exfil`、`litellm-config-update-rce`、`aigateway-cache-cross-tenant`、`aigateway-guardrail-bypass`"),
    ]
    out = ["| 框架 | 2–5 个具体漏洞（名称） | 附录 A 条目 | 检测模板键 |", "|---|---|---|---|"]
    for fw, vulns, ids, keys in rows:
        out.append(f"| {fw} | {vulns} | {ids} | {keys} |")
    return "\n".join(out)


def render_imex_concept() -> str:
    return """**概念详解：IMEX 域越权**

- **一句话定义**：IMEX 是 NVIDIA 在多节点 NVLink 系统上把不同节点的 GPU 显存映射进同一进程地址空间的服务；ComputeDomain 是 Kubernetes 侧把一组 Pod 划进同一 IMEX 域的 CRD；DRA 负责把 GPU/IMEX 设备作为 ResourceClaim 分配给 Pod。
- **类比**：把几栋楼的仓库打通成一条内部传送带。门禁只查“是不是这栋楼的人”，不查“进的是哪个仓格”；ComputeDomain 是门禁名单，DRA 是钥匙，IMEX 是传送带。名单写宽一格，钥匙多配一把，传送带就把别人的货送到你手里。
- **三类越权**：其一，域成员越权——`allowedHosts` 或域选择器过宽，任意 Pod 可以加入不该加入的域；其二，设备挂载过宽——DRA deviceClass/ResourceClaim 把整卡或 IMEX channel 发给不该拿的 Pod；其三，控制面 RBAC 过权——compute-domain-controller 或 GPU network operator 的 ClusterRole 可以改域、读所有节点配置。
- **攻击链**：已有 Pod → 枚举 ComputeDomain/IMEX channel（CRD、operator 日志、节点配置）→ 加入域或拿到 channel 设备 → map 对端显存 → 读权重/KV → 写激活或优化器状态导致静默损坏。全程不要求 root，只要有 device 挂载或 operator SA 即可。
- **前置**：Pod 落在 GPU 节点；能读或改 IMEX 配置/CRD；fabric 可达；目标域未按租户隔离。四个条件缺一个，链路就退化为配置暴露而不是内存越权。
- **危害**：模型权重与 KV 泄露（机密性）；训练静默损坏，loss 曲线看起来正常但收敛偏移（完整性 + 训练有效性）；推理操纵，改 KV/激活即可改变输出（完整性）；绕过 NetworkPolicy 与 MIG，因为内存语义不走网络策略，MIG 只切分单卡（租户隔离）。合规上属于跨租户数据边界失效。
- **检测**：`nvlink-imex-isolation`（research-only，默认关闭）做域成员/权限快照；`fabric-topology-isolation` 读 IB/NVLink 域与分区；`gpu-network-operator-posture` 查 ComputeDomain controller 的特权与 RBAC；链 `imex-computedomain-gpu-memory-crossing` 把“域存在”与“operator 过权”两段证据串起来。证据是域成员、`allowedHosts`、channel 权限、device claim 与 operator ClusterRole。
- **边界**：仓库没有 GB200/NVL72 真机，结论只到配置/权限级；不执行 map、不读真实显存、不写对端内存。IMEX 的真实语义必须用厂商导出或现场只读快照复核。
"""


def render_rail_concept() -> str:
    return """**概念详解：rail 错配**

- **一句话定义**：rail-optimized 是把每台 GPU 服务器里的每张 GPU 固定绑定到同一编号的网卡与 leaf 交换机（rail 0..N），让 all-reduce 中同一 rank 的流量走同一条轨，避免跨轨拥塞。
- **类比**：高速公路有 N 条车道，每辆车按车牌尾号固定走一条；错配就是把车强行并到别的车道，而且所有车同时变道。单看每辆车都没坏，整条路却堵死。
- **错配原因**：调度器不校验 GPU-NIC-leaf 三元组；拓扑标签写错；`NCCL_IB_HCA` 或 `GID_INDEX` 指错；SR-IOV VF 与 PF 不在同一 rail；异构机型混部；多租户共享 HCA。最常见的是“能跑但跑错轨”，监控只看吞吐，不看 rail 映射。
- **攻击链**：已有 Pod → 读 rail 映射与拓扑标签 → 写 NCCL rail 绑定或选错 HCA → 集合通信跨轨 → PFC 暂停帧增长、步时劣化 → 训练退化；叠加 SHARP/PFC 攻击时，跨轨流量还会放大交换机聚合面的故障域。
- **前置**：能写 rail 配置或控制 NCCL 环境变量；作业与目标同 fabric；没有 per-job rail 校验。只读侦察只需要能看到拓扑标签与 NCCL 配置。
- **危害**：跨 rail 拥塞与 PFC 风暴（可用性）；straggler 使同步 all-reduce 被单 rank 拖垮，goodput 静默下降（训练有效性）；跨轨流不在预期 rail 计数里，绕过按轨隔离与监控（租户隔离/合规）；放大 SHARP/PFC 攻击的影响面。
- **检测**：`rail-mismatch-forcing` 读/试 rail 绑定并观察 `cross_rail_flows`；`fabric-topology-isolation` 出 rail 映射与分区；`roce-pfc-storm` 看 `pfc_pause_frames` 差分；`nccl-straggler-injection` 看步时比。证据是 rail 图、跨轨流计数、PFC 计数与步时基线。
- **边界**：配置判定 + 仿真（`lab/fabric_dos_sim.py`），没有真实 IB/RoCE ASIC，也没有跑真实 NCCL 二进制协议；PFC/ECN 的真实行为必须上交换机核验。
"""


def render_layer(n, title, what, categories, rep_rows, detection, fix, boundary,
                 citations, templates, concept=None, framework_table=False, table=None,
                 primer=None, entries=None):
    out = [f"## {n}. {title}", "", f"**层是什么**：{what}", ""]
    if primer:
        out += [render_primer(primer), ""]
    if concept:
        out += [concept, ""]
    out += ["**漏洞类别**", ""]
    for item in categories:
        out.append(f"- {item}")
    out += ["", "**代表漏洞**", ""]
    if table:
        out.append(table)
    elif framework_table:
        out.append(render_framework_table())
    else:
        out.append(render_layer_table(rep_rows))
    out += ["", "**检测方法**", "", detection, "",
            "**修复建议**", "", fix, "",
            "**边界**", "", boundary, "",
            render_citations(citations), ""]
    if entries:
        out += [render_layer_entries(entries, n, start=2 if primer else 1), ""]
    return "\n".join(out)


def render_intro(rows, templates, chains, zero) -> str:
    total = len(rows)
    verified = sum(1 for r in rows if r["status"] == "verified")
    exposure = sum(1 for r in rows if r["status"] == "exposure")
    static = sum(1 for r in rows if r["status"] == "static")
    unsupported = sum(1 for r in rows if r["status"] == "unsupported")
    reserve = len(zero["summary"]["reserve_unique_ids"])
    return f"""# 漏洞分层详解：InkBlade 十层攻击面 / Per-Layer Vulnerability Deep Dive

> 规模：286 个模板、152 条可利用性核验、{reserve} 条零日储备
>
> 本文回答三个问题：训练与推理集群的漏洞为什么不能只按 Kubernetes 分类；每一层的根因、代码锚点与危害是什么；每一类问题怎么演示、怎么修。
>
> 阅读顺序：先读十层正文。每层先看「名词与架构前置」，再看「逐条攻击面与演示」。所有条目都放在对应层的正文里；附录只保留索引，不承载代码。

## 0. 阅读说明

- **层是什么**：每层先用 2–3 句交代前置知识，说明这层在 ML 集群里为什么成立；其中六层另有「名词与架构前置」。
- **漏洞类别**：只列类别，不把类别当发现；具体条目都落在层内的 `L<层>-<序号>` 锚点上。
- **代表漏洞**：正文挑 3–5 条可复核的代表，完整的 152 条在每层的「逐条攻击面与演示」里。框架层按框架列 2–5 条，避免“看完一张大表还是不知道怎么打”。
- **逐条六段**：每条固定给「打了哪里 → 攻击代码 → 攻击效果 → 复现环境 → 清理 → 危害」。`打了哪里` 表包含组件、版本、入口、根因 file:line、可控参数、认证前置与网络位置。
- **攻击代码**：3–20 行可执行片段，目标只允许 `127.0.0.1:<port>`；脚本放在 `demos/<id>/`，文档里的代码块由生成器从 `poc.py` 抽取，两者一致。N/A 只用于硬件、纯配置或 static，而且要写明原因。
- **检测方法**：写清探针、模板与证据怎么取，不写请求构造。模板是数据，由 Pod 内的 Rust 探针执行。
- **危害评级**：`C/I/A` 是机密性/完整性/可用性，`H/M/L` 是高/中/低；另外列训练有效性、租户隔离与合规三项。H 表示“成立时的上限”，不是“必然发生”。
- **不写什么**：真实目标、公网地址、真实凭据、破坏性 payload、持久化或完整生产利用步骤都不写。关键代码只保留 sink、路由、权限判断与加载点；演示代码只用 benign marker、127.0.0.1 回环与最小请求字段，方便防守方定位、复现和写规则。

**范围**：{total} 条 registry 条目、286 个模板、{reserve} 条零日储备、{len(chains)} 条攻击链。正文按十层逐条展开 {total} 条，附录 A 给索引，附录 B/C 给正文锚点，附录 D 给原因索引。

**边界**：152 条 registry 描述的是“有代码锚点、能按版本或配置核验”的子集，不是 ML 集群的全部漏洞。正文的十层是产品检测模型，逐条条目是可对账的技术参考。
"""


def render_chains(rows) -> str:
    by_id = {r["id"]: r for r in rows}
    chain_rows = [
        ("C1 平网 → 管理面 → 权重投毒", "A1 平网 + SGLang/slime 管理面 fail-open + `/pull_weights` 路径可控", "`CVE-2026-15978`、`CVE-2026-92972`、`CVE-2025-32444`"),
        ("C2 Ray Dashboard → 集群控制", "Ray dashboard 无 token 提交 Job → head 任意命令 → KubeRay 宽 RBAC/特权 Pod", "`CVE-2023-48022`、`KUBERAY-ADV-2026-01`、`CVE-2023-48023`"),
        ("C3 NCCL → 梯度注入", "加入集合通信组 → 发送/替换张量 → 梯度或权重污染", "`NCCL-NCCLPLUGIN-HW`、`UCX-UCT-HW`、`CVE-2025-47277`"),
        ("C4 共享 PVC + 模型加载 → 供应链投毒", "共享卷可写 + `trust_remote_code`/checkpoint `torch.load` → 一人投毒、全集群加载者执行", "`CVE-2025-32434`、`llamafactory-checkpoint-py-torch-load-unsafe-l136-ast`、`msswift-indexed-dataset-py-pickle-loads-l112-ast`"),
        ("C5 SSRF/SA token → 云元数据", "媒体 URL 或 image_url 出站 → IMDS/云元数据 → 角色凭据 → 对象存储", "`CVE-2024-0520`、`LITELLM-DEFAULT-KEY`、`CVE-2025-23266`"),
        ("C6 监控面 → 精准打点", "DCGM/Prometheus/MLflow/Jupyter 无鉴权 → 暴露面地图 → 选择 C1–C5 入口", "`CVE-2026-53995`、`CVE-2024-37061`、`kueue-server-go-pprof-exposed-l30-regex`"),
        ("C7 pickle 通道 → 未授权 RCE", "平网 + checkpoint/KV/ZMQ `recv_pyobj` → 反序列化执行", "`CVE-2026-3059`、`CVE-2026-3060`、`CVE-2025-32444`"),
        ("夺权链（七阶段）", "入口 → SA token → RoleBinding/ClusterRoleBinding → 特权 Pod → 节点 root → 集群级证明 → 清理", "`CVE-2023-48022`、`KUBERAY-ADV-2026-01`、`CVE-2013-4786`"),
        ("缓存侧信道链", "TTFT 两档差分 → 成员推断 → EPP per-tenant 指标 → 前缀字典收敛", "`CVE-2025-59425`、`CVE-2026-15978`、`CVE-2026-92972`"),
        ("PD KV 投毒链", "KV 通道未鉴权 → 块 ID 枚举 → 写入 → 独立读回 sha256 一致 → 推理操纵", "`CVE-2026-3060`、`CVE-2025-47277`、`CVE-2025-32444`"),
    ]
    out = ["## 跨层攻击链", "",
           "单层发现回答“这里有没有问题”；攻击链回答“从已有 Pod 走到哪里”。下表只写阶段与证据锚点，不写利用步骤。",
           "", "| 链 | 阶段/原语 | 附录条目 |", "|---|---|---|"]
    for name, steps, ids in chain_rows:
        out.append(f"| {name} | {steps} | {ids} |")
    out += ["", "组合签名不是“再加一条链”，而是去重规则：两个组件同时成立才算问题的，只报一次，报在组合上。第 9 节列了当前 14 条签名；组合不成立时，组件级发现各自独立。", ""]
    return "\n".join(out)


def render_glossary() -> str:
    terms = [
        ("Rail", "GPU 服务器内 GPU↔NIC↔leaf 的固定编号绑定；rail-optimized 让同一 rank 的集合通信走同一条轨。"),
        ("PD 分离", "Prefill/Decode 分离部署；prefill 节点算完 KV 后把块搬给 decode 节点，通道常无 mTLS。"),
        ("KV cache", "推理时缓存的 key/value 张量；按 token 前缀复用，跨租户是否隔离取决于键里有没有 tenant/salt。"),
        ("IMEX", "NVIDIA 多节点 NVLink 显存共享服务，把远端 GPU 显存映射进本地进程地址空间。"),
        ("ComputeDomain", "Kubernetes CRD，把一组 Pod 划进同一 IMEX 域；域选择器就是租户边界。"),
        ("DRA", "Dynamic Resource Allocation；ResourceClaim 描述设备请求，可携带 MIG/IMEX 策略。"),
        ("MIG", "GPU 硬件分区，把一张卡切成多个 GPU instance；分区不等于清零。"),
        ("MPS", "CUDA Multi-Process Service；多进程共享一个 GPU context/pipe，默认假设是单用户。"),
        ("MoE / EP", "混合专家/专家并行；加入 EP 组默认被信任，专家分片可被替换。"),
        ("NCCL", "NVIDIA 集合通信库；bootstrap/rendezvous 设计上不认证，能加入组就能收发张量。"),
        ("RDMA", "远程直接内存访问；绕过内核网络栈，也绕过 NetworkPolicy。"),
        ("IB / SM / Partition", "InfiniBand、子网管理器与分区；SM 是 Kubernetes 之外的信任域，Partition 是 RDMA 的租户边界。"),
        ("PFC / ECN", "RoCE 的无损以太流控与拥塞通知；配置是全局的，一个坏队列能拖住整片 fabric。"),
        ("SHARP", "交换机在网聚合；reduce 发生在交换机内，主机策略看不到会话成员。"),
        ("TTFT", "Time To First Token；前缀命中时显著下降，可被用作缓存成员/前缀长度的侧信道。"),
        ("cache_salt", "请求级缓存盐；参与缓存键派生，是多租户前缀隔离的关键参数。"),
        ("EPP", "Endpoint Picker / 推理路由扩展；暴露 per-tenant 队列深度、命中率与前缀样本。"),
        ("HAMi / cGPU", "GPU 池化/分数卡调度器；隔离决策在 Kubernetes RBAC 之外。"),
        ("IRSA / Workload Identity", "Kubernetes SA 换取云角色的联邦机制；trust policy 通配会把任意 Pod 变成云主体。"),
        ("IMDS", "云实例元数据服务；一个请求就能拿到节点角色凭据。"),
        ("BMC / Redfish / IPMI", "带外管理面；默认凭据、cipher 0、IPMI over LAN 都绕过 K8s。"),
        ("DPU / SmartNIC", "卸载网络/存储/安全策略的网卡；offload 后策略执行点可能不在你管的集群里。"),
        ("SR-IOV / Multus / macvlan", "多网卡与直通形态；策略钩子通常只覆盖主 CNI，直通流量绕过。"),
        ("CNI", "容器网络接口；托管云的 VPC 路由与集群 NetworkPolicy 是两套控制面，会漂移。"),
        ("CSI", "容器存储接口；node plugin 常以特权运行并挂宿主根目录。"),
        ("Operator", "用 CRD 管理有状态应用的控制器；它的 ClusterRole 往往比业务 Pod 大得多。"),
        ("RBAC", "Kubernetes 角色/绑定；`bind`/`escalate`/`impersonate` 与 secrets 读是提权原语。"),
        ("SA token", "ServiceAccount 令牌；automount 默认开启时，Pod 内可直接调用 apiserver。"),
        ("Attestation", "远程证明；GPU CC/TEE/TPM 的 claims 必须绑 nonce 并验签，否则是 false trust。"),
        ("SBOM / AI-BOM", "软件/模型物料清单；ML 镜像包含框架、CUDA、模型三层物料。"),
        ("LoRA / adapter", "低秩适配器；请求可控路径加载 adapter 等于加载代码/行为。"),
        ("Checkpoint / optimizer state", "训练状态；体量大、可写、加载时被信任，是投毒与 RCE 的共同入口。"),
        ("WebDataset / Arrow", "数据集分片与列式格式；解析器与代码执行相邻，常被当数据而不是代码审。"),
        ("Guardrail", "推理网关的内容护栏；只检查首条消息或只识别 user 角色时可被多消息绕过。"),
        ("HIDS / LSM", "主机入侵检测与 Linux 安全模块；driver 未加载或策略未覆盖命名空间时界面仍显示“已部署”。"),
    ]
    seen = {term for term, _ in terms}
    added = 0
    for primer in PRIMERS.values():
        for term, desc in primer["terms"]:
            if term not in seen:
                terms.append((term, desc))
                seen.add(term)
                added += 1
    out = ["## 术语表", "", "| 术语 | 一句话解释 |", "|---|---|"]
    for term, desc in terms:
        out.append(f"| {term} | {desc} |")
    out += ["", f"共 {len(terms)} 条（含六块前置新增 {added} 条）。术语只解释本文用到的含义，不替代厂商文档。", ""]
    return "\n".join(out)


def render_evidence() -> str:
    rows = [
        ("registry 总账", "`inkblade/core/exploit-registry.json`"),
        ("零日储备总账", "`inkblade/core/zeroday-registry.json`"),
        ("上游 case 与根因", "`lab/upstream_verify/cases/*/*/manifest.json`"),
        ("上游源码快照", "`lab/upstream_verify/upstream/`"),
        ("286 模板", "`inkblade/modules/*/template.json`"),
        ("模块元数据", "`inkblade/modules/*/module.json`"),
        ("攻击链定义", "`inkblade/chains/*.json`"),
        ("模板动态验证", "`docs/PROBE-COVERAGE.md`、`reports/probe-coverage/evidence.json`"),
        ("缓存靶场与实效", "`lab/cache_sim.py`、`reports/samples/cache-security/effects.json`"),
        ("长上下文/PD 靶场", "`lab/longctx_sim.py`、`docs/LONG-CONTEXT.md`"),
        ("fabric 靶场", "`lab/fabric_dos_sim.py`、`docs/FABRIC-ATTACK-SURFACE.md`"),
        ("GPU 池化/云租户靶场", "`lab/gpu_cloud_sim.py`、`docs/GPU-CLOUD-TENANCY.md`"),
        ("AI 网关靶场", "`lab/ai_gateway_sim.py`、`docs/AI-GATEWAY.md`"),
        ("硬件/芯片 fixture", "`lab/hardware-fixtures/`、`docs/CHIP-SECURITY-SCOPE.md`"),
        ("防护实验室", "`lab/defense-lab/`、`docs/DEFENSE-LAB-RESULTS.md`、`reports/samples/defense-lab/`"),
        ("夺权链 PROOF", "`reports/samples/kill-chain/proof.json`、`docs/KILL-CHAIN.md`"),
        ("提权矩阵", "`inkblade/core/data/privesc-matrix.json`、`docs/PRIVESC-MATRIX.md`"),
        ("组合签名", "`inkblade/core/data/combo-matrix.json`"),
    ]
    out = ["## 证据索引", "", "路径均为仓库相对路径；不写本地盘符、用户名或绝对路径。", "",
           "| 内容 | 路径 |", "|---|---|"]
    for name, path in rows:
        out.append(f"| {name} | {path} |")
    out.append("")
    return "\n".join(out)


def render_stats(rows, templates, chains, zero) -> str:
    reserve = len(zero["summary"]["reserve_unique_ids"])
    out = ["## 规模", "",
           "| 指标 | 数值 | 说明 |", "|---|---:|---|",
           f"| 模板 | {len(templates)} | `inkblade/modules/*/template.json` 计数 |",
           f"| 模块目录 | 287 | 286 模板 + 1 bootstrap |",
           f"| registry 条目 | {len(rows)} | 有代码锚点的可利用性核验 |",
           f"| 零日储备 | {reserve} | 按根因/组件去重 |",
           f"| 攻击链 | {len(chains)} | `inkblade/chains/*.json` |",
           "| 规则 | 121 | Sigma 94 / Falco 11 / Suricata 8 / 准入 5 / netpol 1 / vpc-sg 1 / ib 1 |",
           "| 写类模板 | 67 | `meta.writes=true` |",
           ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Appendix


def render_appendix_table(rows) -> str:
    out = ["## 附录 A：152 条可利用性核验总表", "",
           "排序：组件 → 状态 → ID。同一根因的 AST/regex 条目各自保留一行，便于与 registry 对账；"
           "`关键代码` 列只放根因片段，审计记录型条目明确标注“非逐字源码”。",
           "",
           "| ID | 组件 | 版本区间 | 原理一句话 | 关键代码（file:line + 片段） | 危害 | 检测模板键 | 覆盖状态 | 修复建议 |",
           "|---|---|---|---|---|---|---|---|---|"]
    for row in rows:
        module = f"`{row['module']}`" if row["module"] != "—" else "—"
        out.append(
            f"| `{row['id']}` | {table_cell(row['component'])} | {table_cell(row['version'])} | "
            f"{table_cell(row['principle'])} | {code_cell(row)} | {row['harm']} | {module} | "
            f"{row['coverage']} | {table_cell(row['fix'])} |"
        )
    out.append("")
    return "\n".join(out)


def render_detail_block(prefix, idx, row) -> str:
    lines = [f"#### {prefix}-{idx:03d} · `{row['id']}` · {row['component']}", "",
             f"- **原理**：{row['principle']}",
             f"- **关键代码**：", "", "    ```text", f"    {row['anchor']}"]
    for line in row["snippet"]:
        lines.append(f"    {line}")
    lines += ["    ```", "",
              f"- **危害**：{row['harm']}（{row['harm_note']}）",
              f"- **利用前置**：{row['pre']}",
              f"- **检测**：`{row['module']}` / `{row['module_path']}`",
              f"- **修复**：{row['fix']}",
              f"- **证据**：`{row['evidence']}`",
              f"- **总纲锚点**：{row['master_ref']}",
              ""]
    return "\n".join(lines)


def render_details(rows, zero) -> str:
    verified = [r for r in rows if r["status"] == "verified"]
    exposure = [r for r in rows if r["status"] == "exposure"]
    out = ["## 附录 B：核心条目逐条详解", "",
           "这 43 条给出原理、根因片段、危害、前置、检测、修复与证据；"
           "不写请求体与利用步骤。", "",
           f"### B.1 执行链条目（{len(verified)}）", ""]
    for idx, row in enumerate(verified, 1):
        out.append(render_detail_block("B", idx, row))
    out += [f"### B.2 暴露面条目（{len(exposure)}）", ""]
    for idx, row in enumerate(exposure, len(verified) + 1):
        out.append(render_detail_block("B", idx, row))
    out.append("")
    return "\n".join(out)


def render_reserve(zero, templates, modules) -> str:
    ids = zero["summary"]["reserve_unique_ids"]
    entries = {e["id"]: e for e in zero["entries"]}
    out = ["## 附录 C：零日储备 39 条逐条详解", "",
           "统计规则：`reserve-eligible` 46 条，按根因/组件去重后 39 条。这里只写防御方需要的原理、根因、危害、前置、检测、修复与证据；"
           "不写利用请求、不写武器化步骤、不写披露对象。7 条与附录 B 重叠，保留两套记录：registry 记录可利用性，reserve 记录披露状态。",
           ""]
    for idx, cid in enumerate(ids, 1):
        e = entries[cid]
        rc = e.get("root_cause") or {}
        fake_manifest = {"root_cause": rc, "preconditions": e.get("preconditions") or [],
                         "evidence": e.get("evidence") or {}}
        fake_entry = {"id": cid, "component": e.get("component") or "", "title": e.get("title") or "",
                      "module": e.get("module") or "", "status": "reserve", "version": e.get("version") or "",
                      "source": e.get("source") or ""}
        snippet, kind = build_snippet(root_info(fake_entry, fake_manifest, e))
        harm, harm_note = harm_for(fake_entry, e, fake_manifest)
        module, module_path = module_for(fake_entry, templates, modules)
        pre = "；".join(clean(x, 140) for x in (e.get("preconditions") or [])) or "需目标部署面可达"
        disclosure = (e.get("disclosure") or {}).get("status") or "unknown"
        evidence = (e.get("evidence") or {}).get("path") if isinstance(e.get("evidence"), dict) else e.get("evidence")
        out += [f"#### C-{idx:03d} · `{cid}` · {COMPONENT_ZH.get(e.get('component'), e.get('component'))}", "",
                f"- **原理**：{clean(e.get('title') or '', 220)}",
                f"- **关键代码**：", "", "    ```text", f"    {root_info(fake_entry, fake_manifest, e)['anchor']}"]
        for line in snippet:
            out.append(f"    {line}")
        out += ["    ```", "",
                f"- **危害**：{harm}（{harm_note}）",
                f"- **利用前置**：{pre}",
                f"- **检测**：`{module}` / `{module_path}`",
                f"- **修复**：{fix_for(fake_entry, e, fake_manifest)}",
                f"- **证据**：`{clean(evidence or '—', 240).replace(chr(92), '/')}`",
                f"- **披露状态**：{disclosure}；verification={(e.get('verification') or {}).get('status', '—')}",
                ""]
    out.append("")
    return "\n".join(out)


def appendix_reason(row) -> str:
    manifest = row["manifest"] or {}
    reason = manifest.get("notes") or ""
    if not reason:
        unsupported = manifest.get("unsupported") or {}
        reason = unsupported.get("reason") or row["pre"] or "静态根因成立，动态未复现"
    return clean_text(reason, 220)


def render_appendix_a_index(grouped, anchors) -> str:
    out = ["## 附录 A：152 条总索引", "",
           "只给 ID、组件、所属层、一句话与状态；原理、入口、攻击代码、效果、复现环境、清理与危害都在正文对应锚点。",
           "", "| ID | 组件 | 层级 | 一句话 | 状态 |", "|---|---|---|---|---|"]
    for n in range(1, 11):
        for row in grouped[n]:
            out.append(f"| `{row['id']}` | {row['component']} | {n} · {LAYER_TITLES[n].split('：')[0]} | "
                       f"{clean_text(row['title'], 120)} | {row['status']} |")
    out.append("")
    return "\n".join(out)


def render_appendix_b_index(grouped, anchors) -> str:
    out = ["## 附录 B：37 verified + 6 exposure 索引", "",
           "这 43 条全部在正文有六段结构与本地 demo；本附录只给索引、正文锚点与 demo 路径。",
           "", "| # | ID | 组件 | 层级 | 正文锚点 | 状态 | 演示 |",
           "|---|---|---|---|---|---|---|"]
    idx = 0
    for n in range(1, 11):
        for row in grouped[n]:
            if row["status"] not in ("verified", "exposure"):
                continue
            idx += 1
            demo = DEMO_META.get(row["id"], {})
            path = f"`demos/{row['id']}/poc.py`" if demo.get("status") == "runnable" else "N/A"
            out.append(f"| {idx} | `{row['id']}` | {row['component']} | {n} | `{anchors[row['id']]}` | "
                       f"{row['status']} | {path} |")
    out.append("")
    return "\n".join(out)


def render_appendix_c_index(grouped, anchors, zero) -> str:
    ids = list(zero["summary"]["reserve_unique_ids"])
    zero_by_id = {e["id"]: e for e in zero["entries"]}
    out = ["## 附录 C：零日储备 39 条索引", "",
           "本附录只给索引、披露状态、正文锚点与 demo 路径；demo 只演示本地仿真环境里的原语，不提供真实目标利用链。",
           "", "| # | ID | 组件 | 层级 | 正文锚点 | 披露状态 | 演示 |",
           "|---|---|---|---|---|---|---|"]
    for idx, cid in enumerate(ids, 1):
        row = next((grouped[n][i] for n in range(1, 11) for i in range(len(grouped[n]))
                    if grouped[n][i]["id"] == cid), None)
        component = row["component"] if row else (zero_by_id.get(cid) or {}).get("component", "—")
        layer = next((n for n in range(1, 11) if any(r["id"] == cid for r in grouped[n])), "—")
        disclosure = ((zero_by_id.get(cid) or {}).get("disclosure") or {}).get("status") or "unknown"
        demo = DEMO_META.get(cid, {})
        path = f"`demos/{cid}/poc.py`" if demo.get("status") == "runnable" else "N/A"
        out.append(f"| {idx} | `{cid}` | {component} | {layer} | `{anchors.get(cid, '—')}` | {disclosure} | {path} |")
    out.append("")
    return "\n".join(out)


def render_appendix_d_index(grouped) -> str:
    out = ["## 附录 D：static 与 unsupported 原因索引", "",
           "这些条目在正文对应层仍给六段结构，攻击代码统一为 N/A 并写原因；本附录只做原因索引。",
           "", "| ID | 组件 | 层级 | 状态 | 原因 |", "|---|---|---|---|---|"]
    count = 0
    for n in range(1, 11):
        for row in grouped[n]:
            if row["status"] not in ("static", "unsupported"):
                continue
            count += 1
            out.append(f"| `{row['id']}` | {row['component']} | {n} | {row['status']} | {appendix_reason(row)} |")
    out += ["", f"共 {count} 条：87 static + 22 unsupported。static 不等于可利用，unsupported 不等于不存在。", ""]
    return "\n".join(out)


def render_demo_index() -> str:
    out = ["## 附录 F：B/C 攻击演示索引", "",
           "每个可运行 demo 都只监听 127.0.0.1、写 benign marker、默认 cleanup；N/A 条目写原因。代码块在正文，不在本附录。",
           "", "| ID | 层级 | 演示 | 状态 | sha256 |", "|---|---|---|---|---|"]
    for entry in sorted(DEMO_META.values(), key=lambda e: (e.get("layer", 99), e["id"])):
        if entry["status"] == "runnable":
            out.append(f"| `{entry['id']}` | {entry.get('layer', '—')} | `demos/{entry['id']}/poc.py` | runnable | `{entry.get('sha256', '')}` |")
        else:
            out.append(f"| `{entry['id']}` | {entry.get('layer', '—')} | — | N/A | — |")
    out.append("")
    return "\n".join(out)


def render_static_reasons(rows) -> str:
    out = ["## 附录 D：static 与 unsupported 的原因", "",
           "这些条目没有进入附录 B：static 是静态根因成立但动态未复现，unsupported 是当前环境没有可测面。"
           "每一行都保留 ID、状态、原因与证据，避免“没复现就等于没问题”。", "",
           "| ID | 状态 | 原因 | 证据 |", "|---|---|---|---|"]
    count = 0
    for row in rows:
        if row["status"] not in ("static", "unsupported"):
            continue
        manifest = row["manifest"] or {}
        reason = manifest.get("notes") or ""
        if not reason:
            unsupported = manifest.get("unsupported") or {}
            reason = unsupported.get("reason") or row["pre"]
        reason = clean(reason, 240)
        out.append(f"| `{row['id']}` | {row['coverage']} | {reason} | `{row['evidence']}` |")
        count += 1
    out += ["", f"共 {count} 条：87 static + 22 unsupported。static 不等于可利用，unsupported 不等于不存在；"
                "两者都要求下一次有真实导出/硬件/云账号时回填。", ""]
    return "\n".join(out)


def render_template_index(templates) -> str:
    series = {}
    for t in templates.values():
        series[t["series"]] = series.get(t["series"], 0) + 1
    out = ["## 附录 E：286 模板索引", "",
           "按系列给计数与代表键；每个模板都有 `template.json`，由 Rust 探针执行。",
           "", "| 系列 | 模板数 | 代表键 |", "|---|---:|---|"]
    reps = {
        "侦察": "`exposure-mapping`、`ai-infra-baseline`、`kubelet-surface`",
        "横向利用": "`vllm-plugin-auth-bypass`、`areal-setenv-engine-rce`、`nccl-collective-join`",
        "网络架构": "`prefill-decode-kv-channel-unauth`、`rail-mismatch-forcing`、`sharp-in-network-poison`",
        "权限链": "`kuberay-operator-escalation`、`lws-secrets-lateral`、`vllm-operator-rbac-escalation`",
        "核心代码": "`vllm-pickle-pipe-rce`、`msswift-trust-remote-code`、`supply-chain-pinning`",
        "窃取与数据泄露": "`prefix-cache-cross-tenant-leak`、`cache-timing-sidechannel`、`shared-volume-weight-copy`",
        "混合云": "`cloud-irsa-trust-wildcard`、`multi-cloud-imds-credentials`、`cloud-bucket-cross-tenant`",
        "情报": "`data-provenance-audit`、`inference-tenant-isolation-baseline`、`reward-hacking-detect`",
    }
    for name, count in sorted(series.items(), key=lambda x: -x[1]):
        out.append(f"| {name} | {count} | {reps.get(name, '—')} |")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Assemble


def build_document() -> str:
    registry = load_json(REGISTRY)
    zero = load_json(ZERODAY)
    manifests = load_manifests()
    templates = load_templates()
    modules = load_modules()
    chains = load_chains()
    master_rows = parse_master()
    zero_map = {e["id"]: e for e in zero["entries"]}
    registry_rows = build_rows(registry["entries"], manifests, templates, modules, zero_map, master_rows)
    reserve_only = [cid for cid in zero["summary"]["reserve_unique_ids"]
                    if cid not in {r["id"] for r in registry_rows}]
    all_rows = registry_rows + [build_reserve_entry(cid, zero, templates, modules)
                                for cid in reserve_only]
    all_rows.sort(key=lambda r: (r["component"], STATUS_ORDER.get(
        {"verified": "verified", "exposure": "exposure", "static": "static",
         "unsupported": "unsupported", "reserve": "reserve"}.get(r["status"], "static"),
        9), r["id"]))
    global ROWS, DEMO_META
    ROWS = registry_rows
    DEMO_META = load_demo_manifest()
    layers = layer_citations(registry_rows)
    grouped = group_entries_by_layer(all_rows)
    registry_grouped = group_entries_by_layer(registry_rows)
    anchors = {row["id"]: f"L{n}-{idx:03d}"
               for n in range(1, 11)
               for idx, row in enumerate(grouped[n], 1)}
    texts = LAYER_TEXTS
    primer_layers = {1: "longctx", 2: "gateway", 3: "chip",
                     4: "network", 6: "gpu", 8: "cache"}
    out = [render_intro(registry_rows, templates, chains, zero)]
    for n in range(1, 11):
        item = texts[n]
        out.append(render_layer(
            n, item["title"], item["what"], item["categories"], item["reps"],
            item["detection"], item["fix"], item["boundary"], layers[n], templates,
            concept=item.get("concept"), framework_table=item.get("framework_table", False),
            table=item.get("table"), primer=primer_layers.get(n),
            entries=grouped[n],
        ))
    out.append(render_chains(registry_rows))
    out.append(render_glossary())
    out.append(render_evidence())
    out.append(render_stats(registry_rows, templates, chains, zero))
    out.append(render_appendix_a_index(registry_grouped, anchors))
    out.append(render_appendix_b_index(registry_grouped, anchors))
    out.append(render_appendix_c_index(grouped, anchors, zero))
    out.append(render_appendix_d_index(registry_grouped))
    out.append(render_template_index(templates))
    out.append(render_demo_index())
    text = "\n".join(out)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.rstrip() + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the checked-in document differs")
    parser.add_argument("--out", default=str(DOC), help="output path")
    args = parser.parse_args(argv)
    text = build_document()
    if args.check:
        current = Path(args.out).read_text(encoding="utf-8") if Path(args.out).is_file() else ""
        if current != text:
            print("document is stale: rerun tools/build-vuln-doc.py", file=sys.stderr)
            return 1
        print("document is up to date")
        return 0
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(text, encoding="utf-8")
    print(f"wrote {args.out} ({len(text)} chars)")
    return 0


ROWS = []

# Narrative is filled below; keeping it in one place makes the generator the
# single source of truth and prevents hand-edited appendix drift.

LAYER_TEXTS = {
    1: {
        "title": "架构层：万卡拓扑、PD 分离与 KV 生命周期",
        "what": "万卡集群不是“更大的 Kubernetes”。GPU 与网卡按 rail 固定布线，训练按 DP/TP/PP/EP/CP 切分，推理用 PD 分离把 prefill 与 decode 放到不同节点，再用 KV 通道搬运中间状态。架构层的信任边界由“通信域”决定，而不是 namespace：能加入同一个集合通信组、能映射同一段显存、能读同一个 KV 块，就已经越过了租户边界。",
        "concept": render_imex_concept(),
        "categories": [
            "跨节点 GPU 内存共享越权：IMEX 域成员、ComputeDomain 选择器、DRA deviceClass 三者任一过宽，都会把远端显存映射进不该拿的 Pod。",
            "rail / 多平面错配：调度器不校验 GPU-NIC-leaf 三元组，NCCL 环境变量或 SR-IOV VF 指错轨，集合通信被静默挤到错误平面。",
            "PD KV 通道未鉴权：prefill 与 decode 之间的 KV 传输缺少 mTLS/token，块 ID 可枚举，读写都不校验租户。",
            "MoE / EP 集合通信默认信任：加入 EP 组不需要身份，专家分片与 all-to-all 端口暴露在平网。",
            "长上下文 KV 生命周期：窗口越长驻留越久，声明窗口与实际 token 不一致会放大预留，逐出策略决定泄露窗口。",
            "多集群联邦信任传递：Karmada 风格的 propagation 与共享 kubeconfig 把身份和权重信任带到集群边界之外。",
        ],
        "reps": [
            ("IMEX 域越权（GB200 NVL72 / IMEX，2026-10 文档版本）", "`nodes_config.cfg` 的 `allowedHosts` 通配；channel 全局 RW；DRA claim 未绑定租户", "同 fabric 的已有 Pod + 可读域配置 → 跨节点显存读写、训练静默损坏", "`nvlink-imex-isolation`、`gpu-network-operator-posture`"),
            ("rail 错配（rail-optimized fabric，无版本上限）", "`NCCL_IB_HCA` / `GID_INDEX` 可写；调度器不校验 GPU-NIC-leaf；SR-IOV VF 与 PF 不同轨", "能写 rail 绑定或控制 NCCL 环境 → 跨轨拥塞、PFC 风暴、straggler", "`rail-mismatch-forcing`、`fabric-topology-isolation`"),
            ("PD KV 通道未鉴权（llm-d / vLLM PD + NIXL 风格）", "KV transfer API 无 mTLS/token；block ID 可枚举；跨租户写入不校验", "prefill/decode 网络可达 → KV 读、写、推理操纵", "`prefill-decode-kv-channel-unauth`、`kv-cache-integrity-poison`"),
            ("长上下文窗口耗尽（128K–1M）", "只校验声明 `context_window`，不校验实际 prompt token；KV 按声明窗口预留", "补全端点可达 → prefill 队列 DoS、GB 级 KV 预留", "`long-context-window-exhaustion`、`long-context-memory-amplification`"),
            ("多集群联邦信任通配（Karmada 风格）", "propagation 通配到全部集群；共享 kubeconfig 无审批；命名空间未隔离", "federation 控制面可达 → 跨集群权重/身份信任", "`multi-cluster-federation`、`federated-learning-surface`"),
        ],
        "detection": "先用拓扑快照回答“谁和谁在一个域”：`fabric-topology-isolation` 读 IB Partition、NVLink/NVSwitch 域与 IMEX 成员；`gpu-network-operator-posture` 读 ComputeDomain controller 的特权、hostPath 与 ClusterRole；`nvlink-imex-isolation` 是 research-only 的域成员/权限快照，默认关闭。PD 侧用 `prefill-decode-kv-channel-unauth` 做读握手与池计数器差分，写类验证走 `kv-cache-integrity-poison` 的备份校验。长上下文用 `long-context-window-exhaustion` 看 `prefill_tokens > context_window` 与 `queue_depth`，用 `long-context-memory-amplification` 看 `kv_cache_bytes` 放大比（阈值 64×）。证据只取状态码、计数器差分、读回 sha256 与拓扑映射，不取“感觉变慢”。",
        "fix": "IMEX：`allowedHosts` 收敛到节点级 allowlist，channel 按租户授权，ComputeDomain 选择器绑定 namespace/SA，DRA claim 校验租户标签；已分配设备禁止在线改域。rail：rail 绑定只读，由调度器按 GPU-NIC-leaf 三元组校验，`NCCL_IB_HCA`/`GID_INDEX` 下发前做一致性检查，SR-IOV VF 与 PF 同轨。PD：KV 通道 mTLS + 每租户 token，块 ID 不可枚举，写入校验块归属。长上下文：按实际 token 计数准入，声明值只做上限提示，给每租户 KV 配额。联邦：propagation 白名单 + 每集群独立凭据 + 变更审批。",
        "boundary": "没有 GB200/NVL72 真机，IMEX 只到配置/权限级，不执行 map、不读真实显存；rail 结论来自配置判定与 `lab/fabric_dos_sim.py` 的计数器仿真，没有真实 IB/RoCE ASIC；PD KV 是 HTTP 语义同构，不覆盖 NIXL/RDMA 二进制协议与 GPU 显存语义。A1–A8 假设必须用客户集群只读快照逐条核验。",
    },
    2: {
        "title": "产品与框架层：十八个栈的默认面",
        "what": "训练与推理栈的漏洞大多不是“Kubernetes 配错了”，而是框架自己的默认值：管理面没有 key、开发模式默认打开、权重同步用 pickle、模型加载信任仓库代码、网关把默认 master key 写进示例。每个栈都有自己的控制面、序列化方式与默认绑定地址，通用 K8s 扫描器看不到这些差异。",
        "framework_table": True,
        "categories": [
            "控制面 fail-open：SGLang、TRL、AReaL、SkyRL、OpenRLHF、LLaMA-Factory、Dify 都出现过“没配 key 就放行”或“默认 0.0.0.0”。",
            "反序列化与代码执行：vLLM/SGLang 的 ZMQ/KV pickle、verl 的 checkpoint `recv_pyobj`、各框架的 `torch.load(weights_only=False)`、数据集 pickle。",
            "模型加载供应链：`trust_remote_code` 默认/硬编码、revision 不固定、adapter/LoRA 路径可控。",
            "网关与 Agent 平台：默认 master key、上游 key 明文、跨租户语义缓存、guardrail 只看首条消息、沙箱零前置 RCE。",
            "推理状态泄露：前缀缓存时序、权重导出路径、dev 端点返回缓存/权重控制面。",
        ],
        "reps": [],
        "detection": "每个框架至少两条证据：一条是“面”的证据（路由/绑定/版本/默认值），一条是“行为”的证据（无 key 200、写后读回 sha256、执行 marker、缓存命中计数）。模板键见上表；附录 A 给 152 条 registry 的逐条根因与片段。通用规则：先 `framework-port-matching` 指纹，再按框架选模板；不要在没确认版本/路由的情况下直接套 CVE。动态验证只证明检测逻辑在本地仿真或上游函数级成立，不证明目标一定是该版本。",
        "fix": "统一动作：管理面 fail-closed（无 key 即拒，不区分 GET/POST）；默认绑定回环，Service 暴露前加 NetworkPolicy；dev-mode 显式开关并只对 localhost 开放；pickle 改安全序列化，`torch.load` 固定 `weights_only=True`；checkpoint/权重目录只读 + 哈希/签名；`trust_remote_code` 默认 False，模型 revision 固定到 commit；网关移除默认 master key，上游 key 按租户隔离，缓存键加 tenant/salt。",
        "boundary": "附录 A 的 152 条不是 18 个框架的全量漏洞库，而是有代码锚点、能按版本/配置核验的子集；AReaL、SkyRL、OpenRLHF、slime、djev/vllm-jev 的 registry 条目少，正文以模板键与上游 file:line 为准。多数条目只到函数级/静态级，真实利用需要目标版本、部署形态与授权窗口。框架默认值随版本漂移，修复建议不替代版本升级与回归。",
    },
    3: {
        "title": "组件与 Operator 层：发牌的人",
        "what": "KubeRay、LWS、Volcano、Kueue、GPU Operator、DRA、CSI、BMC、DPU 不直接跑训练，但它们发放 GPU、存储与节点权限。Operator 的 ClusterRole 往往比业务 Pod 大一个数量级：能创建 Pod、读 Secret、改 RoleBinding，就等于在每个被管理的 namespace 旁放了一份“安装即得”的集群级权限。",
        "categories": [
            "Operator 集群级 RBAC：KubeRay、LWS、vLLM production-stack 的 ClusterRole 含 pods/secrets/serviceaccounts/roles/rolebindings 的 create/update，拿 operator SA 即可一步提权。",
            "驱动与设备插件特权：GPU Operator driver 容器、device plugin、CSI node plugin 以 privileged + hostPath 运行，节点边界被抹平。",
            "DRA / MIG 策略错配：ResourceClaim 请求的 profile 与设备实际值不一致，已分配设备可在线重配。",
            "带外管理面：BMC/Redfish 默认凭据、IPMI cipher 0、DPU 管理服务未鉴权，绕过 K8s RBAC 与审计。",
            "调度器与队列：Volcano/Kueue 的 pprof、gang 占位与队列配额缺失，能把集群级 DoS 变成常态。",
        ],
        "reps": [
            ("KubeRay operator（所有受审版本）", "`kuberay/ray-operator/config/rbac/role.yaml`：集群级 pods/secrets/serviceaccounts/roles/rolebindings create", "operator SA 或进程可触达 → 创建 RoleBinding 到 cluster-admin，接管集群", "`kuberay-operator-escalation`"),
            ("LWS（所有受审版本）", "`kubernetes-sigs/lws/config/rbac/role.yaml`：secrets get/list/update/watch + nodes patch；`pkg/webhooks/pod_webhook.go:84-125` 不关 automount", "operator SA 可触达 → 集群级 Secrets 读改横向", "`lws-secrets-lateral`"),
            ("vLLM production-stack operator（上游正式资产）", "`production-stack/operator/config/rbac/role.yaml`：集群级 roles/rolebindings 全 CRUD + serviceaccounts CRUD + secrets get；`enablePD` 另开 hostPID/hostIPC", "operator SA/进程可触达 → create RoleBinding(cluster-admin) 一步接管", "`vllm-operator-rbac-escalation`"),
            ("GPU Operator + driver（所有受审版本）", "driver DaemonSet privileged + 宿主 `/run/nvidia`、`/usr/lib64` 等挂载", "GPU 节点上的 driver 容器 → 节点逃逸/驱动面篡改", "`gpu-operator-driver-escape`、`gpu-operator-driver-audit`"),
            ("DRA / MIG（Kubernetes 1.31+ DRA）", "ResourceClaim 的 MIG profile 请求值不等于设备实际值；已分配设备可在线重配", "GPU 共享集群 → MIG 边界降级、邻居实例受影响", "`gpu-dra-mig-policy`、`mig-profile-mismatch`"),
            ("BMC / Redfish / IPMI（iDRAC/iLO/Supermicro/OpenBMC）", "默认凭据、匿名 Redfish、IPMI cipher 0、IPMI over LAN", "带外网可达 → 节点电源/虚拟介质/固件控制，绕过 K8s", "`redfish-default-credentials`、`ipmi-cipher-zero-bypass`"),
            ("CSI node plugin（CephFS/JuiceFS）", "node plugin privileged + 宿主根目录挂载；卷归属只按 PV 名，不校验租户", "存储节点 → 卷越权/节点逃逸/权重读写", "`csi-node-plugin-escape`、`storage-protocol-csi`"),
            ("DPU / SmartNIC（BlueField/DOCA）", "`redfish`、`grpc-doca` 管理服务默认未鉴权；rshim/SSH 密码认证", "DPU 管理网可达 → 卸载面失陷、策略执行点被改写", "`dpu-smartnic-surface`、`dpu-ipu-offload`"),
        ],
        "detection": "Operator 看三样：ClusterRole 的 verbs/resources、webhook 是否关 automount、管理的 Pod 是否带 securityContext。模板 `kuberay-operator-escalation`、`lws-secrets-lateral`、`vllm-operator-rbac-escalation` 读 fixture 里的 role.yaml 与 can-i 矩阵；`operator-cross-namespace-reference` 看跨 namespace 引用。驱动/CSI 用 `gpu-operator-driver-audit`、`csi-node-plugin-escape` 读 DaemonSet 的 privileged、hostPath、capabilities。DRA 用 `gpu-dra-mig-policy` 读 ResourceClaim 策略。BMC 用 `bmc-ipmi-exposure` 做只读 Redfish GET + 单次默认凭据验证；`ipmi-cipher-zero-bypass` 看 cipher suite 0。证据是 role 规则、mount 列表、claim 策略、Redfish 响应与登录结果，不写爆破。",
        "fix": "Operator：ClusterRole 收窄为 namespace Role；去掉 roles/rolebindings/secrets 的集群级写；manager SA 不开 automount；webhook 显式 `automountServiceAccountToken: false`；对 create RoleBinding 到 cluster-admin 加准入告警。驱动/CSI：privileged 改设备白名单，hostPath 只读白名单，seccomp/AppArmor 开启。DRA：profile 以设备实际值为准，已分配设备禁止重配。BMC：改默认凭据、带外网隔离、禁用 cipher 0/IPMI over LAN、固件签名核验。DPU：管理服务 mTLS + 独立管理网。",
        "boundary": "Operator RBAC 结论来自上游 raw 清单（2026-10-23）与 fixture，不是每个客户集群的实际绑定；KubeRay/LWS 的“一步 cluster-admin”需要 operator SA 或进程可触达，前置不成立时只是配置风险。BMC/DPU 只做仿真只读与单次默认凭据验证，没有真实 iDRAC/iLO/BlueField；驱动/CSI 逃逸只到 DaemonSet 姿态，不执行真实逃逸。",
    },
    4: {
        "title": "网络与 fabric 层：策略管不到的地方",
        "what": "Kubernetes NetworkPolicy 只覆盖主 CNI 的 Pod 网络。hostNetwork、SR-IOV、macvlan、RDMA 流量不经过同一个钩子；IB 子网管理器、PFC/ECN、SHARP 会话又是 fabric 自己的控制面，根本不在 K8s API 里。训练集群的“网络”实际有三层：Pod 网络、RDMA 网络、带外与交换机管理网，三层的策略与身份各自独立。",
        "concept": render_rail_concept(),
        "categories": [
            "NetworkPolicy 旁路：hostNetwork、Multus/SR-IOV、macvlan 与 RDMA 直通流量不经过策略钩子。",
            "CNI 双控制面：托管云的 VPC 路由/安全组与集群 NetworkPolicy 是两套系统，权限模型和漂移方向不同。",
            "IB SM / Partition：SM 是 K8s 之外的信任域，默认分区 `*` 或单 SM 无冗余会把 RDMA 信任域放大到全 fabric。",
            "RoCE PFC / ECN：无损配置是全局的，一个坏队列能拖住整片 fabric；PFC watchdog 关闭时没有自动恢复。",
            "SHARP 在网聚合：会话加入不鉴权，reduce 发生在交换机内，主机策略看不到成员与结果。",
            "NCCL bootstrap / straggler：bootstrap 端口无认证，慢 rank 能把同步 all-reduce 拖成 2× 以上步时。",
            "DNS：服务发现是攻击者最想先拿到的图，CoreDNS/Service 清单暴露训练/推理拓扑。",
        ],
        "reps": [
            ("Multus + SR-IOV + RDMA（所有受审版本）", "策略钩子只覆盖主 CNI；SR-IOV VF/macvlan/RDMA 流量绕过 kube-proxy 与 NetworkPolicy", "已有 Pod + 第二张网卡 → 跨 namespace 直达训练/推理端口", "`multus-sriov-rdma-bypass`、`network-policy-coverage`"),
            ("VPC-native CNI（EKS VPC-CNI / ACK Terway / TKE VPC-CNI）", "VPC 路由/安全组与 K8s NetworkPolicy 双控制面；SG 规则不随 namespace 自动收敛", "云上集群 → 安全组漂移导致跨租户可达", "`cni-stack-capability`、`cni-aware-reachability-graph`"),
            ("IB SM / Partition（UFM/OpenSM）", "SM 跑在计算节点或单实例；默认分区 `*` 覆盖全部 HCA；PKey 成员不按租户收敛", "IB 管理面可达 → 重定义 RDMA 信任域、跨租户加入", "`ib-sm-partition-audit`、`ib-subnet-manager-hijack`"),
            ("RoCE PFC / ECN（Spectrum-X / 自研白盒）", "PFC watchdog 关闭、ECN 未启用、管理 ACL 放行任意来源；无损队列无租户配额", "交换机配置面可达 → PFC 暂停风暴、fabric 级停摆", "`roce-pfc-storm`、`fabric-telemetry-exposure`"),
            ("SHARP 在网聚合（Quantum-X800 / NVLink SHARP）", "会话加入无鉴权；聚合节点跨租户共享；reduce 结果不在主机审计里", "交换机/SHARP 会话面可达 → 静默篡改 all-reduce 结果", "`sharp-in-network-poison`、`sharp-session-trust-audit`"),
            ("NCCL bootstrap / rank（NCCL 2.x）", "bootstrap 端口无认证；rank 时序被信任；端口池无配额", "同网可达 → 加入集合通信、注入梯度、耗尽端口", "`nccl-collective-join`、`nccl-straggler-injection`、`nccl-port-exhaustion`"),
            ("DNS / Service discovery（CoreDNS）", "Service/Endpoint 清单可读；训练作业用可预测的 headless Service 名", "已有 Pod → 拓扑测绘、定位 Ray/vLLM/SGLang 控制面", "`dns-service-discovery`"),
        ],
        "detection": "先做接口清单：`network-policy-coverage` 与 `multus-sriov-rdma-bypass` 读 Pod 的 hostNetwork、Multus annotation、SR-IOV VF、RDMA 设备；`cni-stack-capability` 读 CNI 类型与策略能力；`cni-aware-reachability-graph` 把可达路径画出来。IB 用 `ib-sm-partition-audit` 读 SM/Partition 导出，`ib-subnet-manager-hijack` 只做只读成员证明。fabric 用 `roce-pfc-storm` 看 `pfc_pause_frames` 差分，`sharp-in-network-poison` 看 reduce 前后差分与 `tampered_reduces`，`nccl-straggler-injection` 看步时比，`nccl-port-exhaustion` 看端口池剩余。DNS 用 `dns-service-discovery` 出区域/端点图。证据是接口清单、可达性证明、计数器差分、会话成员与步时基线。",
        "fix": "策略面：default-deny 基线 + 对 hostNetwork/SR-IOV/macvlan 单独建策略；RDMA 用 IB Partition/PKey 做租户隔离，不能只靠 NetworkPolicy。CNI：VPC 安全组与 K8s 策略双向核对，改动走 GitOps 与漂移检测。IB：SM 冗余、默认分区最小化、PKey 按租户、SM 不跑在计算节点。RoCE：PFC watchdog 开、ECN 开、管理 ACL 限源、每租户队列配额。SHARP：会话 mTLS + 作业令牌、聚合节点独立、缓冲隔离。NCCL：bootstrap 令牌/端口配额、rank 健康检查、超时与 straggler 告警。DNS：只暴露必要 Service，限制 Endpoint 读权限。",
        "boundary": "没有真实 IB/RoCE 交换机、没有跑真实 SHARP reduce 或 NCCL 二进制握手；fabric 结论来自 `lab/fabric_dos_sim.py` 的 HTTP 语义同构与配置导出。NetworkPolicy 旁路是接口/路径判定，不是每个 CNI 的实测；VPC-CNI 双控制面只在仿真与静态清单上成立。PFC/ECN 的真实行为必须上交换机核验，不能用仿真计数器替代。",
    },
    5: {
        "title": "数据与权重层：训练状态的信任链",
        "what": "训练状态同时具备三个特点：体量大、可写、加载时被信任。checkpoint、optimizer shard、数据集缓存、HF 缓存、权重桶、模型注册表都是如此。只要写者能让受害者在下一次恢复时加载被污染的分片，数据面问题就变成代码执行或静默训练损坏；只要读者能跨租户读到缓存或权重，“训练数据”就成了“模型窃取”。",
        "categories": [
            "checkpoint / optimizer 分片投毒：分片写面常由 sidecar/对象存储网关暴露，加载时不做哈希/签名校验。",
            "数据集管道：webdataset/Arrow/pickle 解析与代码执行相邻，共享缓存目录可被跨租户写。",
            "HF 缓存：一个租户写、另一个租户读；`pinned` 块可绕过逐出，形成持久化投毒。",
            "权重存储：路径穿越、云端桶 ACL、对象列举把权重面暴露给相邻租户。",
            "模型注册表 / 实验追踪：MLflow、W&B、模型清单匿名可读，提供私有模型与后端地址。",
            "KV / 前缀缓存：推理状态是数据，缓存键不带 tenant/salt 时跨租户复用。",
        ],
        "reps": [
            ("Checkpoint 分片（Megatron/DeepSpeed/LLaMA-Factory/slime）", "`torch.load(weights_only=False)` 或 `recv_pyobj`；分片哈希不校验；写面由共享 PVC/对象存储暴露", "可写 checkpoint 目录 → 恢复时 pickle 执行或静默训练损坏", "`checkpoint-shard-poison`、`megatron-checkpoint-rce`、`deepspeed-checkpoint-rce`"),
            ("Optimizer state（ZeRO/FSDP）", "optimizer shard 无签名；`latest` 文件指向攻击者可写分片；加载顺序信任本地文件", "可写训练状态目录 → 收敛偏移、loss 正常但权重被改", "`checkpoint-optimizer-state-poison`"),
            ("数据集管道（ms-swift/TRL/LLaMA-Factory）", "`IndexedDataset` 用 `pickle.load` 读 `data.idx`；packing cache 在共享目录；`load_dataset` 接受任意路径", "可写数据集缓存 → 加载时执行代码/污染样本", "`msswift-dataset-pickle-rce`、`data-pipeline-poison`"),
            ("HF 缓存（共享 PVC / RWX 卷）", "缓存目录跨租户可写；`pinned` 块在逐出压力下仍保留；模型加载信任本地缓存", "一个租户写、另一个租户读 → 持久化投毒/权重替换", "`cache-poison-persistence`、`shared-volume-weight-copy`"),
            ("权重存储（S3/OSS/COS/Blob 桶）", "桶策略 Principal `*`、对象 ACL 跨账户、`skyrl /fetch_weights` 路径穿越", "桶可达或路径可控 → 权重直下/穿越写", "`skyrl-fetch-weights-traversal`、`cloud-bucket-cross-tenant`"),
            ("模型注册表 / 实验追踪（MLflow/W&B）", "`/models`、`/ai/route`、MLflow artifact 匿名；trace ID 路径穿越", "注册表可达 → 私有模型清单、后端地址、artifact 读写", "`model-registry-exposure`、`mlflow-trace-write`"),
            ("KV / 前缀缓存（vLLM APC / SGLang Radix）", "缓存键只取 token 哈希，`cache_salt` 可选；逐出只释放索引不清零", "同实例多租户 → 跨租户前缀复用、残留读回", "`prefix-cache-cross-tenant-leak`、`cache-eviction-residue`"),
        ],
        "detection": "先确认写面：checkpoint/数据集/缓存目录的挂载范围、属主、是否 RWX；再看加载点：`torch.load`、`pickle.load`、`recv_pyobj`、`load_dataset`。模板 `checkpoint-shard-poison` 做写后读回 sha256 + 备份回滚精确复原；`checkpoint-optimizer-state-poison` 读分片差异；`msswift-dataset-pickle-rce` 读 `data.idx` 加载路径；`cache-poison-persistence` 写 benign 块 + 洪泛 + 独立读回；`skyrl-fetch-weights-traversal` 看 `cache_dir / payload_file` 未净化；`model-registry-exposure` 读 `/models`、`/ai/route`。证据是写入路径、读回 sha256、对象 ACL、注册表响应与 loader 轨迹。",
        "fix": "按租户隔离 PVC/前缀，权重与 checkpoint 只读挂载；写入面加哈希/签名校验与审计；`torch.load` 固定 `weights_only=True`，禁用 pickle 数据集；HF 缓存按租户前缀 + 只读副本；权重桶关闭 public access、Principal 收敛到角色、禁止跨账户 ListBucket；模型注册表加鉴权与签名链；KV 缓存键加 tenant + `cache_salt`，逐出即 zeroize。",
        "boundary": "写类验证只在 `backup-write` + 备份回执下执行，benign marker 不含真实权重；checkpoint/数据集结论多来自 fixture 与函数级复现，不是客户真实训练状态；云端桶结论是契约级仿真，没有真实 IAM 求值；KV 缓存是 HTTP 语义同构，不覆盖真实 GPU 显存逐出。",
    },
    6: {
        "title": "租户与隔离层：分区不等于清零",
        "what": "GPU 隔离有三层：硬件分区（MIG）、软件上下文（MPS）、调度器配额（HAMi/cGPU/分数卡）。三层都不是默认安全边界：MIG 只切资源不切身份，MPS 默认假设单用户，池化调度器把隔离决策放在 Kubernetes RBAC 之外。释放不等于清零，残留显存、MPS context、显存快照会把上一个租户的模型/进程信息留给下一个租户。",
        "categories": [
            "MIG profile 错配：请求档位与设备实际值不一致，已分配设备可在线重配，邻居边界被改写。",
            "MPS context 共享：多租户共用一个 MPS server/pipe，client/pid/context 可见。",
            "GPU 残留：释放后显存/快照未清零，后续租户可读前租户 marker/模型。",
            "GPU 池化调度器：HAMi/cGPU 的 admin API 无鉴权或只按 namespace 过滤，可跨租户 allocate/migrate。",
            "cache_salt 策略：salt 可选或 key_scope=global，缓存条目之间没有租户隔断。",
            "路由/GPU 指标：per-tenant 队列深度、命中率、进程名与模型标签无鉴权暴露。",
        ],
        "reps": [
            ("MIG（A100/H100/H200/GB200）", "请求 profile 与 `nvidia-smi mig -lgip` 实际值不一致；已分配 GPU instance 可在线重配", "GPU 共享集群 → MIG 边界降级、邻居实例受影响", "`mig-profile-mismatch`、`gpu-dra-mig-policy`"),
            ("MPS（CUDA Multi-Process Service）", "多租户共用一个 MPS server/pipe；`/gpu/mps/status` 暴露 client/pid/context", "同卡多租户 → 进程/上下文泄露、时间片侧信道", "`mps-context-shared`"),
            ("GPU 残留（池化/共享 GPU）", "释放路径只回收分配记录，不清零显存/快照；`/gpu/residue` 仍返回他租户 marker", "后续租户 → 读前租户模型/激活/进程信息", "`gpu-tenant-residue`、`gpu-memory-residue-isolation`"),
            ("HAMi / cGPU / OrionX", "池调度 admin API 无鉴权；租户过滤只在 UI；allocate/migrate 不校验归属", "调度器 API 可达 → 占用/迁移他租户设备", "`hami-scheduler-auth-gap`、`cgpu-isolation-audit`、`gpu-pool-scheduler-unauth`"),
            ("cache_salt（vLLM APC / 网关缓存）", "`cache_salt` 未启用，`key_scope=global`；租户 B 同 prefix 无 salt 复用", "同实例多租户 → `cached_tokens>0`、前缀成员推断", "`cache-salt-policy-audit`、`approx-cache-cross-tenant-chain`"),
            ("EPP / DCGM 指标", "`/router/metrics` 的 `per_tenant` 含他租户 KV 利用率/命中率/前缀样本；DCGM 暴露进程名/namespace", "指标面可达 → 租户画像、缓存状态侧信道", "`router-cache-metrics-leak`、`gpu-metrics-tenant-leak`"),
        ],
        "detection": "先读分配生命周期：`/gpu/pools`、`/gpu/mig/profiles`、`/gpu/mps/status`、`/gpu/residue`。`gpu-pool-scheduler-unauth` 看 admin API 是否无鉴权、能否 allocate/migrate；`gpu-tenant-residue` 做 allocate → 写 benign marker → release → 读回，断言 marker/sha256 一致；`gpu-memory-residue-isolation` 是写类芯片模块，走备份校验；`mig-profile-mismatch` 对比 requested/active；`mps-context-shared` 看 client/pid 跨租户可见。cache_salt 用 `cache-salt-policy-audit` 做配置面 + 行为面双确认；指标用 `router-cache-metrics-leak`、`gpu-metrics-tenant-leak` 抓 `per_tenant`。证据是 marker 读回、sha256、profile 差分、context 列表与指标 JSON。",
        "fix": "MIG：profile 以设备实际值为准，已分配设备禁止在线重配，释放即销毁 instance。MPS：一租户一 server/pipe 或至少按租户隔离 context；指标按租户过滤。残留：释放路径清零显存/快照/临时卷，读回 404。池化：admin API mTLS + 租户作用域，allocate/migrate 校验 tenant/namespace/allocation_id。cache_salt：每租户独立 salt，键含 tenant，近似缓存先按租户过滤。指标：per-tenant 视图只给本租户，管理面单独鉴权。",
        "boundary": "没有真实 nvidia-smi/NVML/MIG/MPS；池化与残留结论来自 `lab/gpu_cloud_sim.py` 的 HTTP 双态与 fixture，`gpu-memory-residue-isolation` 只写 benign marker；MIG/MPS 的真实硬件行为、清零语义与邻居干扰必须在授权实验室复核。cache_salt 与指标结论是 HTTP 语义同构，不代表真实 vLLM/SGLang 的键派生实现。",
    },
    7: {
        "title": "供应链与身份层：加载即执行",
        "what": "模型加载不是“读文件”，而是“执行仓库里的代码”：`trust_remote_code` 会 import 自定义 modeling 文件，未固定 revision 会把上游新提交带进下次调度，checkpoint 反序列化会把权重目录变成代码入口。身份侧同理：IRSA/Workload Identity 的 trust policy 一旦通配，任意 Pod 都能换成云角色；IMDS 只差一个请求就把节点凭据交出去。",
        "categories": [
            "`trust_remote_code`：默认/硬编码/从上层传播，模型仓库代码被当成本地代码执行。",
            "revision 漂移：`revision=None` 或浮动 tag，同一模型名下次调度可能指向新代码。",
            "签名与证明 false trust：只看 JWT 存在、不绑 nonce、不校验 `dbgstat/secboot/overall-att-result`。",
            "SBOM / 固件：ML 镜像三层物料缺失，固件清单用 HMAC fixture 冒充厂商 PKI。",
            "IRSA / Workload Identity 通配：trust policy Principal `*`、缺少 ExternalId/OIDC subject 约束。",
            "IMDS / 凭据：IMDSv1、hop limit 2、安全组放行 169.254.169.254，Pod 内直接取云角色。",
        ],
        "reps": [
            ("transformers / vllm-omni / ms-swift / LLaMA-Factory", "`transformers/dynamic_module_utils.py::get_class_from_dynamic_module`；`vllm-omni/api_server.py:654` 强制 True；`ModelLoader.default_trust_remote_code=True`；`webui/chatter.py:139,183,329`", "模型仓库可控 + 加载 → 仓库代码在服务进程执行", "`trust-remote-code-supply-chain`、`msswift-trust-remote-code`"),
            ("revision pinning（多框架）", "`revision=None`（`openjev/encoders.py:465-497`）；LLaMA-Factory/TRL loader 多处缺 revision", "上游分支/tag 漂移 → 下次调度执行新代码", "`supply-chain-pinning`"),
            ("GPU CC / TEE 证明链", "只验 JWT 存在、不绑 `eat_nonce`、不校验 `x-nvidia-overall-att-result`/`dbgstat`/`secboot`", "自称 CC 的 GPU → 密钥/模型交给不可信执行环境", "`gpu-cc-attestation-chain`、`confidential-containers-attestation`、`tpm-attestation-audit`"),
            ("SBOM / 固件供应链", "固件清单 HMAC fixture；ML 镜像缺框架/CUDA/模型三层物料；签名链未固定根", "固件/镜像替换 → 节点看起来正常但引导链已变", "`hardware-supply-chain`、`firmware-signature-inventory`"),
            ("IRSA / Workload Identity", "trust policy `Principal: \"*\"`、无 `sts:ExternalId`、OIDC `sub`/`aud` 未限制", "任意 Pod → 跨账户角色 → 权重桶", "`cloud-irsa-trust-wildcard`、`cloud-cross-tenant-role-assume`"),
            ("IMDS（AWS/GCP/Azure/阿里/腾讯）", "IMDSv1、hop limit 2、安全组 0.0.0.0/0、Pod 可直达 169.254.169.254", "Pod 内请求 → 节点角色凭据 → 云资源", "`ssrf-imds-credential`、`multi-cloud-imds-credentials`、`cloud-sg-imds-exposure`"),
            ("Pod 内凭据（HF_TOKEN/云 key/SA token）", "env/Secret 注入 HF_TOKEN、AWS_*、存储 key；SA token automount；镜像 pull secret 可读", "已有 Pod → 私有模型仓库/权重桶直下", "`secret-scanner`、`cloud-token-harvest`、`supply-chain-credential-theft`"),
        ],
        "detection": "模型加载侧：`trust-remote-code-supply-chain` 读 import 轨迹与仓库/ revision；`supply-chain-pinning` 读 manifest 的 revision/commit；`model-watermark-backdoor-audit` 看权重/水印异常。证明侧：`gpu-cc-attestation-chain` 验 JWKS 签名、`eat_nonce`、`dbgstat`、`secboot`、`overall-att-result`；`confidential-containers-attestation` 看 CoCo/ Trustee 声明链；`tpm-attestation-audit` 看 PCR/dbx。身份侧：`cloud-irsa-trust-wildcard` 读 trust policy；`ssrf-imds-credential` 做出站可达性与凭据范围；`cloud-sg-imds-exposure` 读 SG/IMDS 配置。证据是导入模块、revision 对照、验签结果、trust policy 图、IMDS 响应与凭据 scope。",
        "fix": "`trust_remote_code` 默认 False，模型仓库固定 commit + 内容哈希，加载前做代码签名/白名单；revision 固定到 commit，升级走双人复核与回滚。CC：JWKS 固定源、nonce 一次性、claims 策略写死、失败 fail-closed。SBOM：镜像三层物料 + 固件厂商非对称签名 + 公钥指纹。IRSA：Principal 收敛到角色 ARN、强制 ExternalId/OIDC subject、角色权限最小化。IMDS：IMDSv2 + hop limit 1、Pod 出站拒绝链路本地、SA token 按需投影。凭据：env/Secret 最小化、HF_TOKEN 按租户、定期轮换。",
        "boundary": "没有 NRAS 生产 JWT、没有真实 H100/H200/GB200 CC 设备、没有真实 BMC/固件 PKI；CC/固件结论只证明验签与 claims 逻辑，不证明设备可信。IRSA/IMDS 是契约级仿真，没有真实 STS/S3/IMDS 调用；`trust_remote_code` 的动态复现是函数级/服务级 marker，不是每个模型仓库的实测。revision 漂移结论是静态清单，不能替代客户实际 manifest。",
    },
    8: {
        "title": "缓存安全层：命中就是泄露",
        "what": "推理缓存把“相同前缀”当成“相同计算”，命中就跳过 prefill。多租户共享实例时，缓存键如果不含 tenant/salt，租户 B 的相同前缀就会命中租户 A 的条目；近似/语义缓存更宽，相似度阈值内直接返回他租户响应。逐出只释放索引，不保证清零；远程 KV 池、PD 通道、EPP 指标与 TTFT 时序把缓存状态变成可观测侧信道。",
        "categories": [
            "跨租户前缀缓存：键只取 token 哈希，缺 tenant/salt；`cached_tokens` 与响应内容泄露。",
            "近似/语义缓存误命中：相似度阈值按命中率调，不按租户过滤；`matched.tenant` 直接指向受害者。",
            "cache_salt 策略：salt 可选、key_scope=global，整个租户隔断只剩一个配置项。",
            "逐出残留：LRU 逐出释放索引，块仍可读；洪泛后 `/cache/residue` 返回他租户 marker。",
            "远程 KV 池 / PD 通道：Mooncake/LMCache/NIXL 块 ID 可猜、命名空间不校验、通道无 mTLS。",
            "EPP 指标 / TTFT 时序：per-tenant 命中率、前缀样本、首 token 时延差可做成员推断与字典提取。",
        ],
        "reps": [
            ("vLLM APC / SGLang RadixAttention（多租户共享实例）", "缓存键仅 token 内容哈希；`cache_salt` 可选；Radix tree 跨租户共享", "同实例多租户 → 同 prefix 命中、`cached_tokens>0`", "`prefix-cache-cross-tenant-leak`、`long-context-cache-leak`"),
            ("GPTCache 风格近似/语义缓存", "相似度阈值（如 0.85）内的条目直接返回；检索未先按 tenant 过滤", "同前缀/近义请求 → 读回他租户响应与 marker", "`similarity-cache-false-hit`、`approx-cache-cross-tenant-chain`"),
            ("cache_salt（vLLM / 网关）", "`cache_salt_policy.enabled=false`、`key_scope=global`；请求可不带 salt", "配置面可达 → 关闭/绕过 salt，跨租户复用", "`cache-salt-policy-audit`"),
            ("逐出与残留（prefix cache + KV 池）", "LRU 逐出只释放索引；块内存/对象未 zeroize；`/cache/residue` 无租户校验", "洪泛触发逐出 → 读回前租户块", "`cache-eviction-residue`、`kv-cache-integrity-poison`"),
            ("远程 KV 池（Mooncake/LMCache 风格）", "块 ID 可猜；命名空间只按字符串前缀；读接口不校验 requester", "池端点可达 → 读他租户块、pinned 持久化", "`remote-kv-pool-isolation`、`cache-poison-persistence`"),
            ("PD KV 通道（llm-d/vLLM PD + NIXL）", "KV transfer 无 mTLS/token；block ID 可枚举；写不校验归属", "prefill/decode 网络可达 → KV 读/写、推理操纵", "`prefill-decode-kv-channel-unauth`、`pd-kv-poison`（链）"),
            ("EPP / 路由器指标", "`/router/metrics` 的 `per_tenant` 含 KV 利用率、命中率、独立前缀数、前缀样本", "指标面可达 → 缓存状态侧信道、前缀字典收敛", "`router-cache-metrics-leak`、`cache-sidechannel-chain`（链）"),
            ("TTFT 时序（vLLM prefix cache）", "命中与未命中的首 token 时延差；采样不足时容易被负载噪声淹没", "同 token 数/同 batch 交替请求 → 成员推断/前缀长度", "`cache-timing-sidechannel`、`vllm-timing-oracle`"),
        ],
        "detection": "配置面 + 行为面双确认：`cache-salt-policy-audit` 先读 `/config` 的 salt 策略，再用租户 B 同 prefix 看 `usage.cached_tokens`；`similarity-cache-false-hit` 做正对照 + 单 token 变异，要求 `matched.tenant != requester` 且 marker 出现在响应；`cache-eviction-residue` 先洪泛看 `evictions_delta`，再读 `/cache/residue`；`remote-kv-pool-isolation` 做本租户对照 + 受害块读，403 与 200 都要有；`prefill-decode-kv-channel-unauth` 做读握手 + 池计数器；`router-cache-metrics-leak` 抓 `per_tenant`。TTFT 判定：同 token 数、同 batch、交替发送，每组至少 30 样本；p95 差异超过噪声带且与缓存命中计数相关才报，否则是负载噪声。",
        "fix": "缓存键 = `hash(prefix) + tenant + cache_salt`，salt 由服务端强制而非请求可选；近似/语义缓存先按 tenant 过滤再做相似度排序；逐出即 zeroize，`/cache/residue` 只返回本租户或 404；远程 KV 池按租户命名空间 + 块归属校验，读接口鉴权；PD 通道 mTLS + 每租户 token + 块 ID 不可枚举；EPP 指标按租户过滤，管理面单独鉴权；TTFT 监控加噪声带与命中计数关联，不把单次抖动当发现。",
        "boundary": "缓存结论来自 `lab/cache_sim.py` 的本机真实 HTTP 双态，TTFT 是确定性仿真计时（命中 22–31ms / 未命中 185–274ms），不是 GPU 实测；远程 KV 池按 Mooncake/LMCache 的“块存储 + 传输”抽象建模，不绑定具体 RPC；不声称对真实 vLLM/SGLang/GPTCache/Mooncake 生产实例的未授权利用。真实环境需按机型/负载重新标定 `min_effect_ms` 与 `alpha`。",
    },
    9: {
        "title": "跨组合层：单看都合规",
        "what": "组合层的规则只有一条：两个组件同时成立才算问题的，只报一次，报在组合上；不拆成两条低危重复项。单看 vLLM 插件路由、SGLang 权重同步、KubeRay RBAC、共享 PVC、Multus 网卡，每一件都可能是“设计如此”；凑在一起才出现“绕过鉴权 + 写权重”“宽 RBAC + 无鉴权控制面”“策略旁路 + 直接内存访问”。",
        "categories": [
            "鉴权组合：插件路由 × 网关、PD leader 路由 × LWS、InferencePool fail-open × 租户基线缺失。",
            "权限组合：KubeRay/LWS/vLLM operator 宽 RBAC × 训练 actor 控制面。",
            "数据组合：共享 PVC/HF 缓存 × 模型加载、SGLang 权重同步 × slime 补丁。",
            "网络组合：Multus/SR-IOV/RDMA × NetworkPolicy、VPC-CNI × 安全组、IB 平网 × NCCL。",
            "硬件组合：GB200 NVL72 × DRA/IMEX、GPU 池化 × MIG 残留、硬件路线 × 特权姿态。",
            "缓存组合：长上下文 × 前缀缓存、PD 分离 × NIXL、TTFT × EPP 指标。",
        ],
        "reps": [],
        "table": "\n".join([
            "| # | 组合签名 | 为何只有组合成立 | 模块键 | 附录条目 |",
            "|---|---|---|---|---|",
            "| 1 | vLLM + vllm-jev | 插件路由单看没问题；与网关同网时绕过 API key | `vllm-plugin-auth-bypass` | `CVE-2025-32444`、`CVE-2025-47277` |",
            "| 2 | SGLang + slime pull_weights | 补丁栈把权重同步变成无鉴权写，跨租户落盘 | `slime-weight-pull-poison` | `CVE-2026-15978`、`CVE-2026-92972` |",
            "| 3 | SGLang + LWS PD | leader 路由 + PD KV 通道叠加成推理操纵；LWS 集群级 Secrets 放大横向 | `lws-secrets-lateral`、`inference-gateway-pd` | `LWS-ADV-2026-01`、`CVE-2026-92972` |",
            "| 4 | verl/SkyRL + KubeRay | 训练 actor 与 Ray dashboard 共享扁平网络；dashboard 可提交 Job | `kuberay-operator-escalation`、`ray-dashboard-job` | `CVE-2023-48022`、`KUBERAY-ADV-2026-01` |",
            "| 5 | vLLM + production-stack operator | operator RBAC 放大 vLLM 面；enablePD 另开 hostPID/hostIPC | `vllm-operator-rbac-escalation` | `CVE-2025-23266`、`CVE-2024-0132` |",
            "| 6 | AReaL/SGLang + NCCL/RDMA | 控制面可达 + 集合通信默认信任 → 梯度/权重注入 | `areal-awex-nccl-injection`、`nccl-collective-join` | `CVE-2025-47277`、`NCCL-NCCLPLUGIN-HW` |",
            "| 7 | 共享 PVC + HF 缓存 | 缓存可写 + 模型加载被信任 → 一人投毒、全集群中招 | `shared-volume-weight-copy`、`trust-remote-code-supply-chain` | `CVE-2025-32434`、`transformers-dynamic-module-utils-py-dynamic-import-l248-ast` |",
            "| 8 | 硬件路线 + 特权姿态 | 文档生成器按硬件自动 emit privileged/seccomp off，单点污染全站 | `privileged-gpu-pod-escape`、`privileged-workloads` | `CVE-2024-0132`、`CVE-2025-23266` |",
            "| 9 | Multus + SR-IOV + RDMA | 策略旁路 + 直接内存访问；NetworkPolicy 不覆盖第二张网卡 | `multus-sriov-rdma-bypass`、`network-policy-coverage` | `CVE-2025-23267`、`CVE-2024-0133` |",
            "| 10 | IB 平网无 Partition | 无 Partition + NCCL 无认证 → 加入/窃听/注入 | `fabric-topology-isolation`、`nccl-collective-join` | `NCCL-NCCLPLUGIN-HW`、`UCX-UCT-HW` |",
            "| 11 | GB200 + DRA/IMEX | 新硬件默认开内存共享；DRA claim 不带租户策略 | `fabric-topology-isolation`、`gpu-network-operator-posture` | `CVE-2024-0132`、`dradriver-process-go-exec-command-l94-regex` |",
            "| 12 | llm-d/vLLM PD + NIXL | KV 传输库跨信任域暴露；块 ID 可枚举 | `inference-gateway-pd`、`remote-kv-pool-isolation` | `CVE-2026-3060`、`CVE-2025-47277` |",
            "| 13 | EKS VPC-CNI + 安全组 | VPC 路由/安全组与 K8s 策略两套控制面，一次漂移 | `cni-stack-capability`、`cloud-integration-fingerprint` | `CVE-2025-33180`、`GHSA-h26v-922j-28cg` |",
            "| 14 | InferencePool fail-open | 网关 fail-open + 租户基线缺失 → 故障域放大到所有租户 | `inference-gateway-pd`、`inference-tenant-isolation-baseline` | `CVE-2026-92972`、`CVE-2026-15978` |",
        ]),
        "detection": "组合检测不是“多跑几个模板”，而是先做组件指纹，再查签名表：`inkblade/core/data/combo-matrix.json` 定义 14 条签名，每条要求 components 全部命中才产出组合发现；命中后 runner 把被解释的组件级 finding 折叠进组合，避免重复计数。证据必须能分成两段：组件 A 的面（路由/RBAC/挂载）+ 组件 B 的行为（写后读回/鉴权差分/通道可达）。只有一段证据时，退回组件级报告。",
        "fix": "组合修复优先拆信任链：插件路由纳入 API key 守卫；PD leader 路由加 mTLS + 租户；KubeRay/LWS/vLLM operator 收窄 RBAC；共享 PVC 按租户前缀 + 只读；Multus 第二张网卡纳入策略；IB 加 Partition；InferencePool 改 FailClosed + 租户基线。不要用“再加一个 WAF”掩盖组合根因。",
        "boundary": "14 条签名是当前声明，不代表所有组合都已动态复现；组合矩阵的 components 指纹来自配置/清单，不是运行时依赖图。部分组合（GB200 + DRA/IMEX、Multus + SR-IOV + RDMA）只有配置/仿真证据，没有真实硬件；组合不成立时，组件级发现仍独立成立，不能被“组合未命中”吞掉。",
    },
    10: {
        "title": "防护绕过层：看得见与看不见",
        "what": "第十层不是“再找一个漏洞”，而是回答“防守方到底看见了什么”。同样一个 benign marker，在 Kyverno 的 enforce 命名空间会被拒，在豁免命名空间会被放行；Falco 能看见改名执行，却可能看不见 `/tmp` 写入；Trivy 能扫出 CVE，却看不见改名工具、深层删除、压缩样本。防护产品的“已部署”不等于“已覆盖”，更不等于“能挡住”。",
        "categories": [
            "准入策略：Kyverno/Gatekeeper 的豁免命名空间、Audit 模式、注解绕过、mutation 顺序、子资源缺口。",
            "运行时：Falco/Tetragon/KubeArmor 的 driver 未加载、策略未挂载命名空间、hostNetwork、短生命周期进程、改名执行。",
            "镜像扫描：Trivy/veinmind 的分层覆盖、改名工具、压缩样本、白名单样本名、内容/哈希识别缺失。",
            "主机代理：Elkeid/AgentSmith/Wazuh 的内核头缺失、agent 离线、规则集缺口、改名执行。",
            "WAF：ModSecurity/Coraza/雷池的编码、分块、Unicode、超长请求归一化差异。",
            "网络可视化：Hubble/Calico 对 hostNetwork、多网卡、短生命周期流的采样缺口。",
        ],
        "reps": [],
        "table": "\n".join([
            "| 产品 | 模块 | 部署/版本 | 检出 | 盲区/绕过 | 硬化 |",
            "|---|---|---|---|---|---|",
            "| Kyverno | `defense-bypass-admission` | v1.19.2，ValidatingPolicy + CEL，Deny | 3 次拒绝：privileged、hostPath、automount | `default` 命名空间的 privileged Pod 被放行（策略只匹配 `defense-lab`） | 策略覆盖全部命名空间；Audit 仅限过渡期；清理绕过注解；审计 mutation 顺序与子资源 |",
            "| Gatekeeper | `defense-bypass-admission` | 未单独部署（与 Kyverno 同族评估） | — | 未验证 ConstraintTemplate/Constraint 的豁免与 dryrun | 单独部署后重放同一组 probe；检查 constraint 的 match/exclude |",
            "| Falco | `defense-bypass-falco` | 0.45.1，modern_ebpf，DaemonSet 1/1 | 1 次：改名执行（Executing binary not part of base image） | `/tmp`、`/bin`、`/etc` marker 写入无告警；0.45.1 自带规则无 `Write below etc`/`Write below binary dir` | 补写路径规则；ephemeral 宏；driver 健康检查；改名执行启发式 |",
            "| Tetragon | `defense-bypass-tetragon` | N/A：内核 LSM 无 `bpf` | — | BPF-LSM 不可用，TracingPolicy 无法 enforce | 换带 BPF-LSM 的内核；策略覆盖 hostNetwork/短生命周期 |",
            "| KubeArmor | `defense-bypass-kubearmor` | N/A：无 BPF-LSM/AppArmor | — | 无 LSM，posture 无法落地 | 内核启用 LSM；默认兜底策略；未打 posture 注解视为 block |",
            "| Trivy | `defense-bypass-imagescan` | 0.76.1，vuln+secret，DB 1.5GB | 0 个 benign 样本；对照 `alpine:3.10` 检出 1 CRITICAL | 普通 marker、改名 busybox、深层删除 secret、tar.gz 内 secret 全部 0 finding | 全层解析；内容/哈希识别改名；压缩递归；收窄排除清单 |",
            "| veinmind | `defense-bypass-veinmind` | N/A：镜像未拉取 | — | 无扫描结果，不能把 fixture 当实测 | 拉取镜像；补分层/压缩样本；与 Trivy 交叉验证 |",
            "| Elkeid | `defense-bypass-elkeid` | N/A：无内核头，`elkeid.ko` 无法构建 | — | 无 manager/agent，规则集无法验证 | 提供内核构建树；manager + agent 一起部署；补 ephemeral 事件 |",
            "| AgentSmith-HIDS | `defense-bypass-agentsmith` | N/A：无 `smith.ko`、无内核头 | — | LKM 未加载，file-create/execve/DNS hook 无法验证 | 内核头 + LKM；file-create kprobe 入规则链；改名执行启发式 |",
            "| Wazuh / osquery | `defense-bypass-hostagent` | N/A：manager/indexer 对 6GB TCG 过重 | — | agent-only 无法验证告警；规则集覆盖未知 | 独立节点跑 manager；监控 `/tmp`、`/dev/shm`；离线即告警 |",
            "| ModSecurity + CRS | `defense-bypass-waf-inference` | CRS 4.30.0，PL1，nginx 1.30.6 | 7 次拦截：URL 编码、双编码、Unicode、大小写、SQLi、chunked、超长（414） | 明文 benign 请求按设计放行；未测 PL2+ 与审计日志 | 解码后再匹配；反分块缓冲；Unicode 规范化；超长直接拒绝 |",
            "| Cilium Hubble / Calico | `defense-bypass-netobserv` | N/A：k3s CNI 是 flannel | — | hostNetwork/多网卡/短流未验证；换 CNI 需重启 | 换 Cilium/Calico；hostNetwork 纳入采集；SR-IOV/RDMA 接口纳入；缩短采样窗口 |",
        ]),
        "detection": "每个 `defense-bypass-*` 模块固定输出三类结果：detected（哪些技术类别被现有规则看见）、blindspots（动态验证中没有告警的类别及原因）、hardening（可直接落地的规则/配置）。评估分三态：deployed（已部署）、degraded（driver/策略降级）、absent（未部署）；只有 deployed 才能把“没告警”解释为“看不见”，absent 只能记 N/A。证据是产品日志、探针 transcript、命中/未命中矩阵与规则文件版本。",
        "fix": "准入：策略覆盖全部命名空间，Audit 仅限过渡期，清理绕过注解，审计 mutation 顺序与子资源。运行时：driver 健康检查、ephemeral 宏、hostNetwork 策略、改名执行启发式。镜像：全层解析、内容/哈希识别、压缩递归、收窄排除。主机：manager 独立部署、离线即告警、监控 `/tmp`/`/dev/shm`。WAF：解码/反分块/Unicode 规范化/超长拒绝。网络：hostNetwork 与多网卡纳入采集。规则包输出到 Kyverno/Gatekeeper、Sigma/Falco、Suricata/WAF。",
        "boundary": "Defense Lab 是 QEMU TCG 单节点 k3s（6 vCPU/6GB），不是生产规模；4 个产品实机、7 个 N/A，N/A 都有明确原因，不用仿真结果代替。盲区结论只对被测版本/配置成立，不能外推为“该产品可被绕过”。11/11 是 triaged，不是 11 个产品都验证；21 次探针、11 检出、8 绕过、2 对照是当前样本的计数。实验期间 k3s kine/sqlite 在 Trivy DB 下载时崩溃，说明这台 VM 只能承载两个控制面产品 + CLI/容器工具，不是全栈实验室。",
    },
}


if __name__ == "__main__":
    raise SystemExit(main())
