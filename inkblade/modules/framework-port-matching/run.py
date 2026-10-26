"""framework-port-matching — 已复现漏洞端口 ↔ Service 端点匹配（清单驱动）。

核心清单（CORE_PORTS）内嵌自 docs/design.md 已复现条目：端口 × 框架 × 已知漏洞面 × 对应利用模块。
匹配规则：Service 任一 port/nodePort/targetPort 命中清单端口，且服务名含名称提示（避免 mlflow:5000 误报 openrlhf）。
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_recon_common", _PARENT / "_recon-common.py")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)

finding, run_recon = _COMMON.finding, _COMMON.run_recon

CORE_PORTS = [
    {
        "port": 30000,
        "framework": "sglang",
        "surface": "推理/管理面：/update_weights_from_disk、/pause、/freeze 等管理路由 fail-open + slime /pull_weights",
        "modules": ["sglang-admin-failopen", "slime-weight-pull-poison"],
        "sev": "high",
        "name_hints": ("sglang", "slime"),
    },
    {
        "port": 8265,
        "framework": "ray",
        "surface": "dashboard 无鉴权作业提交 → 头节点任意命令",
        "modules": ["ray-dashboard-job"],
        "sev": "high",
        "name_hints": ("ray",),
    },
    {
        "port": 8000,
        "framework": "vllm / skyrl-tinker",
        "surface": "vLLM /plugins/* 绕 api-key；SkyRL Tinker API 0.0.0.0 无鉴权（建模型/采样/删检查点）",
        "modules": ["vllm-plugin-auth-bypass", "skyrl-tinker-hijack"],
        "sev": "medium",
        "name_hints": ("vllm", "tinker", "plugin"),
    },
    {
        "port": 5000,
        "framework": "openrlhf",
        "surface": "serve_rm 默认 0.0.0.0 无鉴权 → 伪造训练信号（奖励模型打分面滥用）",
        "modules": ["reward-model-abuse"],
        "sev": "medium",
        "name_hints": ("openrlhf", "serve", "rm", "reward"),
    },
]


def _port_numbers(port_entry: dict) -> list[int]:
    return [v for v in (port_entry.get("port"), port_entry.get("nodePort"), port_entry.get("targetPort")) if isinstance(v, int)]


def analyze(snapshot: dict, params: dict) -> list[dict]:
    findings: list[dict] = []
    for svc in snapshot.get("services", []):
        ns = svc.get("namespace", "default")
        name = svc.get("name", "?")
        lname = name.lower()
        for port_entry in svc.get("ports", []):
            for core in CORE_PORTS:
                if core["port"] not in _port_numbers(port_entry):
                    continue
                if not any(hint in lname for hint in core["name_hints"]):
                    continue
                findings.append(finding(
                    core["sev"],
                    f"已复现漏洞端口匹配：{ns}/{name}:{core['port']} ↔ {core['framework']} {core['surface'].split('：')[0]}",
                    detail=f"端口 {core['port']} 承载 {core['framework']} 已复现漏洞面：{core['surface']}。可达即满足对应利用模块的入口前提。",
                    evidence=f"service={ns}/{name} port={core['port']} type={svc.get('type', 'ClusterIP')} framework={core['framework']}",
                    mapping="利用模块：" + ", ".join(core["modules"]),
                    fix="管理/控制端口仅系统网段可达 + 认证；推理数据面与管理面分端口分策略",
                    reachable=True, port=core["port"], framework=core["framework"],
                ))
    return findings


def run(ctx: dict, params: dict) -> dict:
    return run_recon(ctx, params, analyze, family="框架漏洞端口匹配")
