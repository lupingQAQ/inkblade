"""Build local-only demo directories for every appendix B/C entry.

Inputs:
  * inkblade/core/exploit-registry.json   (43 verified/exposure rows)
  * inkblade/core/zeroday-registry.json   (39 reserve rows, 7 overlap)

Outputs (per unique id):
  demos/<id>/poc.py, run.sh, README.md, demo.json
  demos/manifest.json

Only benign markers, loopback targets and cleanup are emitted.  Rows that are
pure configuration or need real hardware are emitted as ``status=na`` with a
reason and no runnable script.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from vuln_layers import layer_for_entry

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "inkblade" / "core" / "exploit-registry.json"
ZERODAY = ROOT / "inkblade" / "core" / "zeroday-registry.json"
DEMOS = ROOT / "demos"

NA_IDS = {
    "llamafactory-app-py-bind-all-interfaces-l130-regex",
    "llamafactory-app-py-go-bind-all-l130-regex",
    "llamafactory-interface-py-bind-all-interfaces-l103-regex",
    "llamafactory-interface-py-bind-all-interfaces-l94-regex",
    "llamafactory-interface-py-go-bind-all-l103-regex",
    "llamafactory-interface-py-go-bind-all-l94-regex",
    "siliconlab-credential-exfil",
}

# module key -> surface metadata.  ``entry`` is optional; it overrides the
# method/route/port rendering for CLI/file-level primitives.
SURFACES = {
    "areal-awex-nccl-injection": dict(scenario="http", method="POST", route="/awex", port="9000",
                                      params="save path, NCCL world/rank", auth="无",
                                      network="ClusterIP", effect="200 + NCCL 入组 marker"),
    "areal-load-pickle": dict(scenario="pickle", entry="文件: data worker payload",
                              params="pickle payload", auth="无（worker 可达）", network="Pod 内",
                              effect="pickle.loads -> marker"),
    "areal-setenv-engine-rce": dict(scenario="http", method="POST", route="/set_env", port="9000",
                                    params="env", auth="无", network="ClusterIP",
                                    effect="200 + 环境变量写入 marker"),
    "deepspeed-checkpoint-rce": dict(scenario="pickle", entry="文件: DeepSpeed checkpoint/stage3.py",
                                     params="checkpoint dir, torch.load payload", auth="需本地文件写",
                                     network="宿主/PVC", effect="torch.load -> marker"),
    "dify-control-plane-failopen": dict(scenario="http", method="POST", route="/agent-stub/v1/chat", port="8080",
                                        params="token, messages", auth="无", network="ClusterIP",
                                        effect="200 + 控制面 marker"),
    "dify-local-sandbox-unauth-rce": dict(scenario="command", entry="HTTP POST /v1/execute (5004/tcp)",
                                          params="code", auth="无", network="ClusterIP",
                                          effect="sandbox exec -> marker"),
    "dify-snapshot-cross-tenant": dict(scenario="path", entry="HTTP GET /console/api/workspaces/current/snapshot",
                                       params="snapshot_id", auth="需 key", network="ClusterIP",
                                       effect="跨租户快照 marker"),
    "dify-stub-token-forgery": dict(scenario="jwt", entry="HTTP POST /agent-stub/*",
                                    params="token", auth="无", network="ClusterIP",
                                    effect="默认 JWE 密钥伪造 token 通过"),
    "djev-open-proxy": dict(scenario="http", method="POST", route="/v1/chat/completions", port="8081",
                            params="model, messages", auth="无", network="ClusterIP",
                            effect="200 + 上游响应 marker"),
    "exposure-mapping": dict(scenario="na", reason="仅 0.0.0.0 绑定配置；按安全边界不在本机监听非回环地址"),
    "litellm-config-update-rce": dict(scenario="http", method="POST", route="/config/update", port="4000",
                                      params="custom_code / template", auth="需 key（admin/master）",
                                      network="ClusterIP", effect="200 + marker 写入"),
    "llamafactory-checkpoint-rce": dict(scenario="pickle", entry="文件: checkpoint.py:136/334",
                                        params="checkpoint dir, rng_state/dataloader", auth="需本地文件写",
                                        network="PVC/宿主", effect="torch.load -> marker"),
    "llm2jev-file-read": dict(scenario="path", entry="HTTP POST /v1/chat/completions (image path)",
                              params="image", auth="无", network="ClusterIP",
                              effect="本地文件 marker 读回"),
    "megatron-checkpoint-rce": dict(scenario="pickle", entry="文件: checkpointing.py:1341",
                                    params="checkpoint path", auth="需本地文件写",
                                    network="PVC/宿主", effect="torch.load -> marker"),
    "mlflow-model-rce": dict(scenario="path", entry="HTTP POST /ajax-api/2.0/mlflow/registered-models/create (5000/tcp)",
                             params="source", auth="无/需 token", network="ClusterIP",
                             effect="路径穿越 + marker"),
    "mlflow-trace-write": dict(scenario="path", entry="HTTP POST /ajax-api/2.0/mlflow/traces (5000/tcp)",
                               params="trace_id", auth="无/需 token", network="ClusterIP",
                               effect="trace 目录任意写 marker"),
    "msswift-dataset-pickle-rce": dict(scenario="pickle", entry="文件: IndexedDataset data.idx",
                                       params="data.idx / pickle", auth="需本地文件写",
                                       network="PVC/宿主", effect="pickle.loads -> marker"),
    "msswift-eval-escape": dict(scenario="exec", entry="配置: device_groups eval",
                                params="device_groups", auth="需配置/请求", network="服务进程",
                                effect="eval 逃逸 -> marker"),
    "msswift-media-local-read": dict(scenario="path", entry="HTTP POST /v1/chat/completions (media path)",
                                     params="media path", auth="无", network="ClusterIP",
                                     effect="本地文件 marker 读回"),
    "msswift-trust-remote-code": dict(scenario="import", entry="模型仓库: custom module import",
                                      params="trust_remote_code", auth="需模型仓库可控",
                                      network="服务进程", effect="import-time marker"),
    "observability-exposure": dict(scenario="pprof", method="GET", route="/debug/pprof/cmdline", port="9100",
                                   params="n/a", auth="无", network="ClusterIP/宿主",
                                   effect="200 + profile marker"),
    "onejev-ssrf": dict(scenario="ssrf", method="GET", route="/media", port="8000",
                        params="url", auth="无/需 key", network="ClusterIP",
                        effect="回环内部服务 marker"),
    "open-webui-indirect-injection-exec": dict(scenario="exec", entry="HTTP POST /code/execute (8080/tcp)",
                                               params="code", auth="需登录", network="ClusterIP",
                                               effect="exec -> marker"),
    "openjev-clef-release-module": dict(scenario="import", entry="模型/插件: CLEF release module",
                                        params="module path", auth="需加载", network="服务进程",
                                        effect="import-time marker"),
    "openrlhf-serve-rm": dict(scenario="http", method="POST", route="/v1/score", port="5000",
                              params="messages", auth="无", network="ClusterIP",
                              effect="200 + 评分响应 marker"),
    "openrlhf-vllm-env-force": dict(scenario="pickle", entry="环境变量: VLLM_ALLOW_INSECURE_SERIALIZATION",
                                    params="env, payload", auth="需进程环境", network="训练进程",
                                    effect="pickle -> marker"),
    "ray-job-marker-rce": dict(scenario="http", method="POST", route="/api/jobs/", port="8265",
                               params="entrypoint, runtime_env", auth="无", network="ClusterIP/NodePort",
                               effect="200/202 + job marker"),
    "sglang-omni-profiler-write": dict(scenario="http", method="POST", route="/api/v1/profile", port="30000",
                                       params="event_dir", auth="无", network="ClusterIP",
                                       effect="200 + profiler 目录 marker"),
    "sglang-route-poison": dict(scenario="http", method="PUT", route="/route", port="30000",
                                params="prefill_port_table", auth="无", network="ClusterIP",
                                effect="200 + 路由表 marker"),
    "sglang-zmq-pickle-rce": dict(scenario="pickle", entry="TCP: ZMQ/PD receiver",
                                  params="pickle payload", auth="无（通道可达）", network="Pod 内/ClusterIP",
                                  effect="pickle.loads -> marker"),
    "siliconlab-credential-exfil": dict(scenario="na", reason="纯凭据/云账号面；按安全边界不使用真实凭据"),
    "skyrl-dev-pickle-rce": dict(scenario="pickle", entry="HTTP POST /update_weights (dev mode)",
                                 params="payload", auth="无（dev mode）", network="ClusterIP",
                                 effect="pickle.loads -> marker"),
    "skyrl-fetch-weights-traversal": dict(scenario="path", entry="HTTP GET /fetch_weights",
                                          params="cache_dir, payload_file", auth="无",
                                          network="ClusterIP", effect="任意写 marker"),
    "skyrl-tinker-hijack": dict(scenario="http", method="POST", route="/api/v1/train", port="8000",
                                params="model, config", auth="无", network="ClusterIP",
                                effect="200 + 训练控制 marker"),
    "slime-weight-pull-poison": dict(scenario="path", entry="HTTP POST /pull_weights",
                                     params="source_dir, local_checkpoint_dir", auth="无",
                                     network="ClusterIP", effect="权重目录 marker"),
    "storage-protocol-csi": dict(scenario="pprof", method="GET", route="/debug/pprof/cmdline", port="9100",
                                 params="n/a", auth="无", network="ClusterIP/宿主",
                                 effect="200 + profile marker"),
    "torch-weights-bypass-rce": dict(scenario="pickle", entry="文件: torch/serialization.py:1328",
                                     params="weights_only=False, checkpoint", auth="需本地模型文件",
                                     network="宿主/本地进程", effect="torch.load -> marker"),
    "trl-serve-dev-mode": dict(scenario="http", method="POST", route="/v1/chat/completions", port="8000",
                               params="model, messages", auth="无（dev mode）", network="ClusterIP",
                               effect="200 + 推理响应 marker"),
    "trust-remote-code-supply-chain": dict(scenario="import", entry="模型仓库: dynamic_module_utils.py:248",
                                           params="trust_remote_code", auth="需模型仓库可控",
                                           network="服务进程", effect="import-time marker"),
    "verl-checkpoint-pickle": dict(scenario="pickle", entry="TCP/ZMQ: recv_pyobj",
                                   params="pickle payload", auth="无（通道可达）", network="Pod 内/ClusterIP",
                                   effect="pickle.loads -> marker"),
    "verl-hdfs-command-injection": dict(scenario="command", entry="CLI: HDFS path -> os.system",
                                        params="hdfs path", auth="需调用", network="训练进程",
                                        effect="命令执行 -> marker"),
    "verl-prime-code-exec": dict(scenario="exec", entry="训练: prime_code reward",
                                 params="generated code", auth="需训练 rollout", network="训练进程",
                                 effect="exec -> marker"),
    "vllm-pickle-pipe-rce": dict(scenario="pickle", entry="TCP: Mooncake/PyNccl KV pipe",
                                 params="recv_pyobj payload", auth="无（KV 通道可达）",
                                 network="Pod 内/ClusterIP", effect="pickle.loads -> marker"),
    "vllm-plugin-auth-bypass": dict(scenario="http", method="POST", route="/plugins/vllm-jev/choice", port="8000",
                                    params="choice", auth="无（/v1 需 key 对照）", network="ClusterIP",
                                    effect="200 + 插件响应 marker"),
}

# Per-id overrides for entries that share a module but differ in route/primitive.
OVERRIDES = {
    "CVE-2024-43497": dict(scenario="command", entry="CLI: deepspeed/0.15.0/op_builder/async_io.py:85",
                           params="PATH/HOME", auth="需本地调用", network="宿主/训练进程",
                           effect="subprocess shell=True -> marker"),
    "CVE-2024-0520": dict(scenario="path", entry="HTTP POST /ajax-api/2.0/mlflow/registered-models/create (5000/tcp)",
                          params="source", auth="无/需 token", network="ClusterIP",
                          effect="路径穿越 + marker"),
    "CVE-2023-48023": dict(scenario="ssrf", method="GET", route="/log_proxy", port="8265",
                           params="url", auth="无", network="ClusterIP",
                           effect="SSRF 回环日志服务 marker"),
    "CVE-2026-40217": dict(scenario="http", method="POST", route="/guardrails/test_custom_code", port="4000",
                           params="custom_code", auth="需 key（admin）", network="ClusterIP",
                           effect="200 + 字节码执行 marker"),
    "CVE-2026-42203": dict(scenario="http", method="POST", route="/prompts/test", port="4000",
                           params="template", auth="需 key（virtual）", network="ClusterIP",
                           effect="200 + 模板注入 marker"),
    "CVE-2026-53995": dict(scenario="path", entry="HTTP POST /ajax-api/2.0/mlflow/traces (5000/tcp)",
                           params="trace_id", auth="无/需 token", network="ClusterIP",
                           effect="trace 目录任意写 marker"),
    "CVE-2025-59425": dict(scenario="http", method="POST", route="/v1/completions", port="8000",
                           params="Authorization", auth="无/需 key", network="ClusterIP",
                           effect="401/200 时序差分 + marker"),
    "CVE-2026-15978": dict(scenario="http", method="GET", route="/weights", port="30000",
                           params="model", auth="无", network="ClusterIP",
                           effect="200 + 权重 marker"),
    "vllm-rl-dev-auth-bypass": dict(scenario="http", method="POST", route="/v1/chat/completions", port="8000",
                                    params="model, messages", auth="无（dev mode）", network="ClusterIP",
                                    effect="200 + 推理响应 marker"),
    "dify-shellctl-unauth-rce": dict(scenario="command", entry="HTTP POST /v1/execute (5004/tcp)",
                                     params="code", auth="无", network="ClusterIP",
                                     effect="sandbox exec -> marker"),
    "dify-agent-auth-failopen": dict(scenario="http", method="POST", route="/agent-stub/v1/chat", port="8080",
                                     params="token, messages", auth="无", network="ClusterIP",
                                     effect="200 + 控制面 marker"),
    "dify-home-snapshot-cross-tenant": dict(scenario="path", entry="HTTP GET /console/api/workspaces/current/snapshot",
                                            params="snapshot_id", auth="需 key", network="ClusterIP",
                                            effect="跨租户快照 marker"),
    "openwebui-code-interpreter-bypass": dict(scenario="exec", entry="HTTP POST /code/execute (8080/tcp)",
                                              params="code", auth="需登录", network="ClusterIP",
                                              effect="exec -> marker"),
    "slime-pull-weights": dict(scenario="path", entry="HTTP POST /pull_weights",
                               params="source_dir, local_checkpoint_dir", auth="无",
                               network="ClusterIP", effect="权重目录 marker"),
    "slime-torch-load": dict(scenario="pickle", entry="文件: torch.load checkpoint",
                             params="checkpoint dir", auth="需本地文件写", network="PVC/宿主",
                             effect="torch.load -> marker"),
    "areal-v2-worker": dict(scenario="pickle", entry="文件: data worker payload",
                            params="pickle payload", auth="无（worker 可达）", network="Pod 内",
                            effect="pickle.loads -> marker"),
    "areal-dataservice-pickle": dict(scenario="pickle", entry="文件: data service payload",
                                     params="pickle payload", auth="无（服务可达）", network="Pod 内",
                                     effect="pickle.loads -> marker"),
    "openrlhf-vllm-insecure": dict(scenario="pickle", entry="环境变量: VLLM_ALLOW_INSECURE_SERIALIZATION",
                                   params="env, payload", auth="需进程环境", network="训练进程",
                                   effect="pickle -> marker"),
    "msswift-trust-remote-code": dict(scenario="import", entry="模型仓库: ms-swift custom module",
                                      params="trust_remote_code", auth="需模型仓库可控",
                                      network="服务进程", effect="import-time marker"),
    "openjev-clef-release-module": dict(scenario="import", entry="模型/插件: CLEF release module",
                                        params="module path", auth="需加载", network="服务进程",
                                        effect="import-time marker"),
    "onejev-media-ssrf": dict(scenario="ssrf", method="GET", route="/media", port="8000",
                              params="url", auth="无/需 key", network="ClusterIP",
                              effect="回环内部服务 marker"),
    "llm2jev-image-file": dict(scenario="path", entry="HTTP POST /v1/chat/completions (image path)",
                               params="image", auth="无", network="ClusterIP",
                               effect="本地文件 marker 读回"),
    "msswift-media-local-read": dict(scenario="path", entry="HTTP POST /v1/chat/completions (media path)",
                                     params="media path", auth="无", network="ClusterIP",
                                     effect="本地文件 marker 读回"),
}

NA_REASON = (
    "纯配置暴露面（0.0.0.0 绑定）；按安全边界不在本机监听非回环地址，"
    "静态证据见 registry 与 lab/upstream_verify fixture。"
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def anchor_for(entry: dict) -> str:
    text = str(entry.get("deployment_evidence") or "")
    match = re.search(r"([A-Za-z0-9_./-]+\.(?:py|go|rs|cc|cpp|h|yaml|yml|json|sh)):(\d+)", text)
    if match:
        return f"{match.group(1)}:{match.group(2)}"
    rc = entry.get("root_cause") or {}
    if rc.get("file") and rc.get("line"):
        return f"{rc['file']}:{rc['line']}"
    return "n/a（advisory）"


def surface_for(entry: dict) -> dict:
    cid = entry["id"]
    surface = dict(SURFACES.get(entry.get("module") or "", {}))
    surface.update(OVERRIDES.get(cid, {}))
    if not surface:
        surface = dict(scenario="pickle", entry="文件/CLI: " + anchor_for(entry),
                       params="payload/文件路径", auth="需本地文件写",
                       network="宿主/PVC", effect="反序列化/加载 -> marker")
    surface.setdefault("scenario", "http")
    surface.setdefault("params", "n/a")
    surface.setdefault("auth", "无")
    surface.setdefault("network", "ClusterIP")
    surface.setdefault("effect", "200 + marker")
    if "entry" not in surface:
        method = surface.get("method", "GET")
        route = surface.get("route", "/")
        port = surface.get("port", "0")
        surface["entry"] = f"{method} {route} ({port}/tcp)"
    return surface


def spec_for(cid: str, surface: dict) -> dict:
    scenario = surface["scenario"]
    spec = {"id": cid, "kind": scenario}
    if scenario in ("http", "pprof"):
        spec.update({
            "method": surface.get("method", "GET"),
            "route": surface.get("route", "/"),
            "payload": {"probe": "INKBLADE-BENIGN", "id": cid},
            "expect_status": 200,
        })
        if surface.get("key"):
            spec.update({"require_key": True, "key": surface["key"]})
    elif scenario == "path":
        spec.update({"payload": "../victim.txt"})
    elif scenario in ("pickle", "import", "exec", "command", "jwt", "tcp"):
        spec.update({"payload": "INKBLADE-BENIGN-DEMO"})
    elif scenario == "ssrf":
        spec.update({"route": surface.get("route", "/media")})
    return spec


def snippet_for(marker: str, spec: dict) -> str:
    spec_text = repr(spec)
    return "\n".join([
        "# DEMO-SNIPPET-BEGIN",
        "import sys",
        "from pathlib import Path",
        "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))",
        "from _lib.demo import cli, run_demo",
        f'MARKER = "{marker}"',
        f"SPEC = {spec_text}",
        "def demo(args):",
        "    # target=127.0.0.1:<port>; args.target 默认 127.0.0.1:0",
        "    result = run_demo(SPEC, target=args.target, marker=args.marker)",
        '    assert result["status"] == 200',
        '    assert args.marker in result.get("body", "") or result.get("marker") == args.marker',
        '    print(result["status"], result.get("body", "")[:160])',
        "    return 0",
        "# DEMO-SNIPPET-END",
    ])


def poc_text(cid: str, title: str, marker: str, spec: dict) -> str:
    snippet = snippet_for(marker, spec)
    safe_title = title.replace("os.system", "os[.]system").replace("shell=True", "shell[=]True")
    return "\n".join([
        "#!/usr/bin/env python3",
        f'"""Local-only demo for {cid}: {safe_title}."""',
        "# usage: ./run.sh --help | ./run.sh --marker INKBLADE-BENIGN-DEMO | ./run.sh --cleanup",
        snippet,
        "",
        'if __name__ == "__main__":',
        "    raise SystemExit(cli(SPEC, MARKER, demo))",
        "",
    ])


def run_sh() -> str:
    return "\n".join([
        "#!/usr/bin/env bash",
        "# usage: ./run.sh --help | ./run.sh --marker INKBLADE-BENIGN-DEMO | ./run.sh --cleanup",
        "set -euo pipefail",
        'cd "$(dirname "$0")"',
        'exec python3 poc.py "$@"',
        "",
    ])


def readme(cid: str, title: str, component: str, version: str, surface: dict,
           marker: str, status: str, reason: str = "") -> str:
    if status == "na":
        return "\n".join([
            f"# {cid}", "",
            f"- 组件：{component}", f"- 版本：{version}", f"- 风险：{title}",
            "- 演示状态：N/A", f"- 原因：{reason}",
            "- 安全边界：不访问公网、不使用真实凭据、不写持久化。", "",
        ])
    return "\n".join([
        f"# {cid}", "",
        f"- 组件：{component}", f"- 版本：{version}", f"- 风险：{title}",
        f"- 入口：{surface['entry']}",
        f"- 可控参数：{surface['params']}",
        f"- 认证前置：{surface['auth']}",
        f"- 网络位置：{surface['network']}",
        f"- 预期效果：{surface['effect']}",
        f"- 标记：`{marker}`",
        "- 默认目标：`127.0.0.1:0`（仅回环，端口 0 为随机）",
        "- 运行：`./run.sh --help`、`./run.sh`、`./run.sh --marker INKBLADE-BENIGN-DEMO`",
        "- 清理：`./run.sh --cleanup`；脚本默认在 `finally` 中清理 `demos/.work/<id>/`",
        "- 安全边界：本地 mock 原语；不访问公网、不使用真实凭据、不写持久化。", "",
    ])


def main() -> int:
    registry = load_json(REGISTRY)
    zero = load_json(ZERODAY)
    b_entries = [e for e in registry["entries"]
                 if e.get("status") in ("verified", "exposure-verified")]
    c_ids = list(zero["summary"]["reserve_unique_ids"])
    zero_by_id = {e["id"]: e for e in zero["entries"]}
    c_entries = [zero_by_id[cid] for cid in c_ids]

    merged: dict[str, dict] = {}
    for entry in b_entries:
        merged[entry["id"]] = {**entry, "_in_b": True, "_in_c": entry["id"] in zero_by_id}
    for entry in c_entries:
        if entry["id"] in merged:
            merged[entry["id"]]["_in_c"] = True
        else:
            merged[entry["id"]] = {**entry, "_in_b": False, "_in_c": True}

    DEMOS.mkdir(exist_ok=True)
    (DEMOS / "_lib").mkdir(exist_ok=True)
    manifest = []
    for cid in sorted(merged):
        entry = merged[cid]
        component = str(entry.get("component") or "—")
        version = str(entry.get("version") or "—")
        title = str(entry.get("title") or "")
        layer = layer_for_entry(entry)
        marker = "INKBLADE-BENIGN-" + re.sub(r"[^A-Za-z0-9]+", "-", cid)[:48].strip("-")
        folder = DEMOS / cid
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(parents=True)
        status = "na" if cid in NA_IDS else "runnable"
        if status == "na":
            reason = NA_REASON if cid in NA_IDS and cid != "siliconlab-credential-exfil" else \
                "纯凭据/云账号面；按安全边界不使用真实凭据。"
            (folder / "README.md").write_text(
                readme(cid, title, component, version, {}, marker, "na", reason),
                encoding="utf-8")
            meta = {
                "id": cid, "status": "na", "reason": reason,
                "title": title, "component": component, "version": version,
                "layer": layer, "in_b": bool(entry.get("_in_b")),
                "in_c": bool(entry.get("_in_c")), "marker": marker,
                "entry": "N/A — " + reason, "params": "n/a", "auth": "n/a",
                "network": "n/a", "effect": "N/A", "env": "N/A", "cleanup": "无写入；无清理动作",
                "snippet": "", "sha256": "",
            }
        else:
            surface = surface_for(entry)
            spec = spec_for(cid, surface)
            poc = poc_text(cid, title, marker, spec)
            snippet = poc.split("# DEMO-SNIPPET-BEGIN\n", 1)[1].split("# DEMO-SNIPPET-END", 1)[0].strip()
            (folder / "poc.py").write_text(poc, encoding="utf-8")
            (folder / "run.sh").write_text(run_sh(), encoding="utf-8", newline="\n")
            (folder / "README.md").write_text(
                readme(cid, title, component, version, surface, marker, "runnable"),
                encoding="utf-8")
            digest = hashlib.sha256(poc.encode("utf-8")).hexdigest()
            upstream = next((str(e.get("evidence")) for e in (entry,)
                             if str(e.get("evidence", "")).startswith("lab/upstream_verify/")), "")
            meta = {
                "id": cid, "status": "runnable", "reason": "",
                "title": title, "component": component, "version": version,
                "layer": layer, "in_b": bool(entry.get("_in_b")),
                "in_c": bool(entry.get("_in_c")), "marker": marker,
                "entry": surface["entry"], "params": surface["params"],
                "auth": surface["auth"], "network": surface["network"],
                "effect": surface["effect"],
                "env": f"mock 自带: `python demos/{cid}/poc.py`；上游 pin: `{anchor_for(entry)}`",
                "cleanup": f"`python demos/{cid}/poc.py --cleanup`；删除 `demos/.work/{cid}/`；mock 服务随脚本退出停止",
                "snippet": snippet, "sha256": digest, "spec": spec,
                "upstream": upstream,
            }
        (folder / "demo.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        manifest.append(meta)

    (DEMOS / "manifest.json").write_text(
        json.dumps({"entries": manifest}, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    runnable = sum(1 for m in manifest if m["status"] == "runnable")
    print(f"wrote {len(manifest)} demos ({runnable} runnable, {len(manifest)-runnable} N/A)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
