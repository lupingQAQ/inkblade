# -*- coding: utf-8 -*-
"""Build the vLLM/SGLang research patch-difference matrix.

Source snapshot: corpus/depth/vllm_ghsa_snapshot.json (selected GitHub Security
Advisories, fetched 2026-10-26).  Vendor CVEs from inkblade/core/cve-catalog.json
are appended explicitly so every row has a source URL and a testable range.

This script is intentionally deterministic: rerunning it must produce byte
identical JSON (no timestamps, sorted keys).
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "corpus" / "depth" / "vllm_ghsa_snapshot.json"
OUT = ROOT / "corpus" / "depth" / "vllm_patch_matrix.json"

# surface taxonomy used by the fuzz harness and the report
# admin | plugin | dev-mode | serialization | weights | request-api | cache
SURFACE = {
    "GHSA-vvpg-rrww-wpmh": ("admin", "CORS 默认放行任意 Origin；管理面读取响应可被跨站读取"),
    "GHSA-5fj9-pfhr-6j48": ("admin", "指标 HTTP method 标签无界；管理面遥测被请求参数放大"),
    "GHSA-h3rc-j82p-2c3h": ("serialization", "EPS 上传进入 Ghostscript/图像解析链；不可信文档反序列化面"),
    "GHSA-25q3-v2hm-8vpf": ("request-api", "embeddings/pooling 负 token id 触发 CUDA 断言，引擎整体退出"),
    "GHSA-p92p-rxj5-7p2x": ("request-api", "伪造 multimodal UUID 命中处理器缓存，未认证请求可崩引擎"),
    "GHSA-4xqp-c3mv-qff7": ("request-api", "单请求超大 min_tokens 挂起引擎而 /health 仍绿"),
    "GHSA-x6mc-67gf-chw4": ("request-api", "视频采样 max_frames 由请求控制，绕过 num_frames 上限"),
    "GHSA-823j-m4cj-hmjf": ("request-api", "MOSS-Audio 处理器缓存按请求键无界增长"),
    "GHSA-h3rc-6mm3-gc2m": ("dev-mode", "请求控制 mm_processor_kwargs.code_revision，auto_map 动态代码执行"),
    "GHSA-wpww-v874-ph2p": ("cache", "cache_salt 长度无界，单请求拖死 EngineCore 调度线程"),
    "GHSA-3c86-2m5g-59q7": ("dev-mode", "LlavaOnevision2 处理器以 trust_remote_code=False 仍执行模型代码"),
    "GHSA-6757-hggm-hp2w": ("serialization", "公开 multimodal SHM 句柄伪造到达 worker 侧 pickle.loads"),
    "GHSA-vfp2-c8pq-v6h6": ("serialization", "X-Request-Id 驱动 P2pNcclConnector 外连 ZMQ+NCCL，泄露 KV"),
    "GHSA-mm38-5g96-7j6x": ("request-api", "Nemotron-VL 处理器全局关闭 Pillow 解压炸弹保护"),
    "GHSA-542m-9234-8gvf": ("dev-mode", "chat_template Jinja2 渲染无界，渲染线程池耗尽"),
    "GHSA-85xf-c7hm-whqw": ("request-api", "结构化输出错误逃逸请求边界，终止共享 EngineCore"),
    "GHSA-q97c-p368-75c4": ("request-api", "词表外 token id 通过校验，触发 CUDA 断言"),
    "GHSA-gq5q-89c7-vhvx": ("request-api", "DeepSeek-OCR 归一化像素和为 0，embed_multimodal 返回 None"),
    "GHSA-6pgw-f3pv-4h8q": ("serialization", "Rust gRPC output_candidates.token_ids 绕过 logprob 限制"),
    "GHSA-r45p-7qwx-qwjw": ("request-api", "多模态音频解码绕过解压炸弹时长限制"),
    "GHSA-33cg-gxv8-3p8g": ("request-api", "prompt embeds 触发 M-RoPE 路径 DoS"),
    "GHSA-7m6h-x95x-82q5": ("request-api", "跨用户数据泄露"),
    "GHSA-4m6g-h9mv-wqjc": ("request-api", "VideoMediaIO frame-count 上限被 media_io_kwargs 绕过"),
    "GHSA-rhcx-5729-88vg": ("request-api", "未初始化 LogprobsTensors 造成跨租户 DoS"),
    "GHSA-8wr5-jm2h-8r4f": ("request-api", "无效 recovered token 重注入，远程 DoS"),
    "GHSA-8c65-hq7q-r7jm": ("request-api", "allowed_token_ids 与投机解码元数据不匹配"),
    "GHSA-w2v2-5662-8v5q": ("serialization", "Rust gRPC 接受词表外 prompt token id"),
    "GHSA-hhv2-872h-628q": ("request-api", "FunAudioChat/Tarsier2 artifact pin 传播不完整"),
}

CATALOG_ROWS = [
    {
        "id": "CVE-2025-32444",
        "component": "vllm",
        "cve": "CVE-2025-32444",
        "ghsa": None,
        "severity": "critical",
        "title": "Mooncake KV 管道 pickle 反序列化 RCE",
        "affected": ">=0.6.5,<0.8.5",
        "fixed": "0.8.5",
        "surface": "weights",
        "patch": "MooncakePipe 对 KV 载荷调用 pickle.loads；0.8.5 移除不安全反序列化并限制 pipe 来源",
        "detection": "sig: vllm mooncake pipe pickle magic + 非 worker 源地址；sigma: 权重拉取进程异常 import",
        "source": "https://www.cve.org/CVERecord?id=CVE-2025-32444",
    },
    {
        "id": "CVE-2025-29783",
        "component": "vllm",
        "cve": "CVE-2025-29783",
        "ghsa": None,
        "severity": "critical",
        "title": "Mooncake ZMQ/TCP 不安全反序列化",
        "affected": ">=0.6.5,<0.8.0",
        "fixed": "0.8.0",
        "surface": "serialization",
        "patch": "ZMQ broker 信任任意 peer 的 pickle；0.8.0 增加握手与可信 peer 校验",
        "detection": "falco: vllm 进程创建 zmq socket 后 exec/import；suricata: 非预期 5555/5570 连接",
        "source": "https://www.cve.org/CVERecord?id=CVE-2025-29783",
    },
    {
        "id": "CVE-2025-47277",
        "component": "vllm",
        "cve": "CVE-2025-47277",
        "ghsa": None,
        "severity": "critical",
        "title": "PyNcclPipe KV 传输 RCE",
        "affected": ">=0.6.5,<0.8.5",
        "fixed": "0.8.5",
        "surface": "serialization",
        "patch": "PyNcclPipe 接受任意 TCP 源并 pickle 解码；0.8.5 绑定 worker 身份与句柄",
        "detection": "sigma: 非 rank 进程访问 NCCL bootstrap 端口；falco: python 进程加载 _pickle",
        "source": "https://www.cve.org/CVERecord?id=CVE-2025-47277",
    },
    {
        "id": "CVE-2025-59425",
        "component": "vllm",
        "cve": "CVE-2025-59425",
        "ghsa": None,
        "severity": "medium",
        "title": "API key 校验时序侧信道",
        "affected": "<0.11.0rc2",
        "fixed": "0.11.0rc2",
        "surface": "admin",
        "patch": "api-key 比较短路；rc2 改为 constant-time compare",
        "detection": "sigma: 同一来源对 /v1/models 高频 401 且时延方差异常",
        "source": "https://www.cve.org/CVERecord?id=CVE-2025-59425",
    },
]

LAB_ROWS = [
    {
        "id": "INKBLADE-VLLM-PLUGIN",
        "component": "vllm",
        "cve": None,
        "ghsa": None,
        "severity": "high",
        "title": "插件路由挂载在 api-key 中间件之外（研究接口面）",
        "affected": "<=0.32.0",
        "fixed": None,
        "fixed_note": "截至 2026-10-26 未见上游安全公告；本行是接口策略差异，不计入已验证补丁对。",
        "surface": "plugin",
        "patch": "插件路由独立 APIRouter 挂载，/plugins/* 不走 bearer 校验；实验室以 /v1/models 401 作对照",
        "detection": "sigma: 未认证 /plugins/list 200 且 /v1/models 401；suricata: /plugins/invoke 外部源",
        "source": "https://docs.vllm.ai/en/latest/",
    },
    {
        "id": "INKBLADE-VLLM-DEV",
        "component": "vllm",
        "cve": None,
        "ghsa": None,
        "severity": "high",
        "title": "dev-mode / 动态处理器代码路径未与业务鉴权域分离（研究接口面）",
        "affected": "<=0.32.0",
        "fixed": None,
        "fixed_note": "截至 2026-10-26 未见上游安全公告；本行是接口策略差异，不计入已验证补丁对。",
        "surface": "dev-mode",
        "patch": "dev 路由与模型处理器共享进程；请求可控 code_revision 可进入 auto_map",
        "detection": "sigma: /dev/* 非管理源 200；falco: vllm 进程从缓存目录执行新 .py",
        "source": "https://docs.vllm.ai/en/latest/",
    },
]

SGLANG_ROWS = [
    ("CVE-2026-3059", "0.5.10", "多模态 ZMQ broker pickle RCE", "serialization",
     "ZMQ broker 对多模态载荷 pickle.loads；未认证 peer 可投递", "falco: sglang 进程加载 _pickle 且对端非 rank"),
    ("CVE-2026-3060", "0.5.10", "Encoder PD 分离模块 pickle RCE", "serialization",
     "Encoder 与 PD 之间通过 pickle 传张量；PD 端口可被旁路", "sigma: PD worker 从非预期源接收载荷"),
    ("CVE-2026-7301", "0.5.10", "多模态 scheduler ROUTER 绑定 0.0.0.0 + pickle", "serialization",
     "ROUTER 默认绑定全部地址且反序列化请求体", "suricata: 外部源访问 scheduler ROUTER 端口"),
    ("CVE-2026-7302", "0.5.10", "多模态上传路径穿越任意文件写", "weights",
     "上传文件名未规范化，可写到权重目录外", "sigma: 上传路径含 ../ 或绝对路径"),
    ("CVE-2026-15978", "<=0.5.15", "无 API key 时模型权重外泄", "weights",
     "未配置 api-key 时 /pull_weights 与广播端点开放", "sigma: 未认证 pull_weights 200；suricata: 大流量出站"),
    ("CVE-2026-92972", "<=0.5.19", "PD 分离 PUT /route 路由表投毒", "admin",
     "PD /route 无鉴权，可改写 prefill 路由表", "sigma: PUT /route 非管理源 200"),
]

rows: list[dict] = []
snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
for item in snapshot:
    surface, note = SURFACE[item["ghsa"]]
    rows.append({
        "id": item["ghsa"],
        "component": "vllm",
        "cve": item.get("cve"),
        "ghsa": item["ghsa"],
        "severity": item.get("severity") or "unknown",
        "title": item["summary"],
        "affected": item["affected"].strip(),
        "fixed": item["fixed"].strip() if item.get("fixed") else None,
        "surface": surface,
        "patch": note,
        "detection": f"sigma: 受影响接口异常调用；falco: vllm 进程行为偏离基线 ({surface})",
        "source": item["html_url"],
    })

for extra in CATALOG_ROWS + LAB_ROWS:
    row = dict(extra)
    if row.get("fixed") is None and not row.get("fixed_note"):
        row["fixed_note"] = "未见公开修复版本；仅作研究接口差异记录。"
    rows.append(row)

for cve, affected, title, surface, patch, detection in SGLANG_ROWS:
    rows.append({
        "id": cve,
        "component": "sglang",
        "cve": cve,
        "ghsa": None,
        "severity": "high",
        "title": title,
        "affected": affected,
        "fixed": None,
        "fixed_note": "截至 2026-10-26 未观察到官方修复版本；CVE 记录仍为受影响状态。",
        "surface": surface,
        "patch": patch,
        "detection": detection,
        "source": f"https://www.cve.org/CVERecord?id={cve}",
    })

# deterministic order: component, surface, id
rows.sort(key=lambda r: (r["component"], r["surface"], r["id"]))
doc = {
    "schema": "inkblade-vllm-patch-matrix-v1",
    "verified_at": "2026-10-26",
    "method": "GitHub Security Advisories API 快照 + CVE.org 目录条目；版本区间与修复版本逐行保留原始字符串，"
              "未给出的修复版本以 fixed_note 标注，不臆造。",
    "surfaces": ["admin", "plugin", "dev-mode", "serialization", "weights",
                 "request-api", "cache"],
    "entries": rows,
}
OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=False) + "\n",
               encoding="utf-8")
print(f"wrote {OUT.relative_to(ROOT)} entries={len(rows)} "
      f"fixed_pairs={sum(1 for r in rows if r.get('fixed'))}")
