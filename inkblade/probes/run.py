"""trident/probes/run.py — LLM 探针两态差分运行器。

对 lab 三张仿真靶场的 LLM 面（全部仅监听 127.0.0.1、仅标准库）：
- gateway：lab/ai_gateway_sim（/v1/chat/completions guardrail 差分、/cache/*、/logs、
  /key/generate、/models、/config、/quota、/vector/query）
- longctx：lab/longctx_sim（超窗排队、prefix cache 跨租户、/kv/transfer、/checkpoint/shards、/metrics）
- relay：lab/mock_targets（djev 开放中继 /v1/chat/completions、vllm 插件面、dify/open-webui 工具面）

每个探针在 vulnerable 与 fixed 两态各执行一次请求序列，判定器只消费真实 HTTP 响应
（状态码 / JSON 字段 / 文本），与 expect 两态声明比对得出差分判定：
confirmed（与预期一致）/ not-vulnerable（两态均未命中）/ not-differential（两态均命中）/
unexpected（仅 fixed 命中的反向差分）。

产物：matrix JSON（run_matrix 返回值同构）+ MD（matrix.render_matrix_section）。
判定证据只记录状态码与命中标记，不归档完整响应体（MOCK 凭据仅存实验室 trace 层）。

命令行：python trident/probes/run.py [--out DIR] [--faces gateway,longctx,relay]
         [--categories cat1,cat2] [--probe key]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab import ai_gateway_sim, longctx_sim, mock_targets  # noqa: E402
from trident.probes.framework import CATEGORIES, load_probes, verdict_of  # noqa: E402

TIMEOUT = 5
FACES_DEFAULT = ("gateway", "longctx", "relay")

# 每个面的鉴权档位（凭据一律实验室 MOCK 样值；fixed 态也用合法租户 key 做同请求对照）
_GATEWAY_AUTH = {
    "none": {},
    "tenant": {"Authorization": f"Bearer {ai_gateway_sim.TENANT_KEYS['tenant-a']}",
               "X-Tenant": "tenant-a"},
    "victim-tenant": {"Authorization": f"Bearer {ai_gateway_sim.TENANT_KEYS['tenant-b']}",
                      "X-Tenant": "tenant-b"},
    "admin": {"Authorization": f"Bearer {ai_gateway_sim.ROTATED_ADMIN_KEY}"},
}
_LONGCTX_AUTH = {
    "none": {"X-Tenant": "tenant-a"},
    "tenant": {"X-Tenant": "tenant-a"},
    "victim-tenant": {"X-Tenant": "tenant-b"},
    "admin": {"X-Tenant": "tenant-a", "Authorization": f"Bearer {longctx_sim.ADMIN_TOKEN}"},
}
_RELAY_AUTH = {
    "none": {},
    "tenant": {},
    "victim-tenant": {},
    "admin": {"Authorization": f"Bearer {mock_targets.ADMIN_TOKEN}"},
    "vllm": {"X-Mock-Service": "vllm"},
}
AUTH_PROFILES = {"gateway": _GATEWAY_AUTH, "longctx": _LONGCTX_AUTH, "relay": _RELAY_AUTH}

VICTIM_CACHE_PROMPT = ai_gateway_sim.VICTIM_CACHE_PROMPT


# ---------------------------------------------------------------- HTTP 执行

def _request(base: str, step: dict, auth_headers: dict) -> dict:
    """执行单步请求 → {"status", "payload", "text"}（网络失败记 status=0）。"""
    url = base.rstrip("/") + str(step["path"])
    body = step.get("body")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=str(step["method"]).upper())
    if data is not None:
        req.add_header("Content-Type", "application/json")
    headers = {**auth_headers, **{str(k): str(v) for k, v in (step.get("headers") or {}).items()}}
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        return {"status": 0, "payload": None, "text": f"{type(exc).__name__}: {exc}"}
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text
    return {"status": int(status), "payload": payload, "text": text}


def execute_probe(probe: dict, base: str) -> dict:
    """在单个靶场基址上执行探针请求序列并求值判定器（每步按自身 auth 档位取头）。"""
    profile = AUTH_PROFILES[probe["face"]]
    default_auth = str(probe["request"][0].get("auth", "none"))
    entries = []
    for step in probe["request"]:
        auth_headers = profile.get(str(step.get("auth", default_auth)), {})
        entries.append(_request(base, step, auth_headers))
    from trident.probes.framework import evaluate_detector  # 局部导入避免循环
    hit = evaluate_detector(probe["detector"], entries)
    return {
        "hit": hit,
        "statuses": [e["status"] for e in entries],
        "requests": len(entries),
    }


# ---------------------------------------------------------------- 靶场生命周期

def start_faces(faces=FACES_DEFAULT) -> dict[str, dict[str, object]]:
    """按 face 拉起 vulnerable/fixed 两态仿真器（各自独立端口与状态）。"""
    servers: dict[str, dict[str, object]] = {}
    for face in faces:
        if face == "gateway":
            pair = {m: ai_gateway_sim.start_all(mode=m) for m in ("vulnerable", "fixed")}
        elif face == "longctx":
            pair = {m: longctx_sim.start_all(mode=m) for m in ("vulnerable", "fixed")}
        elif face == "relay":
            pair = {m: mock_targets.start_all(mode=m) for m in ("vulnerable", "fixed")}
        else:
            raise ValueError(f"未知 face: {face!r}")
        servers[face] = pair
    return servers


def shutdown_faces(servers: dict[str, dict[str, object]]) -> None:
    for pair in servers.values():
        for server in pair.values():
            server.shutdown()


# ---------------------------------------------------------------- 矩阵主流程

def _summarize(results: dict[str, dict]) -> dict:
    verdicts: dict[str, int] = {}
    faces: dict[str, int] = {}
    rules: set[str] = set()
    for row in results.values():
        verdicts[row["verdict"]] = verdicts.get(row["verdict"], 0) + 1
        faces[row["face"]] = faces.get(row["face"], 0) + 1
        rules.add(row["rule_key"])
    return {
        "total": len(results),
        "categories": len({row["category"] for row in results.values()}),
        "faces": faces,
        "rules_linked": len(rules),
        "verdicts": verdicts,
        "confirmed": verdicts.get("confirmed", 0),
        "attack_confirmed": sum(
            1 for r in results.values()
            if r["verdict"] == "confirmed" and r["expect"]["vulnerable"] == "hit"),
        "controls_clean": sum(
            1 for r in results.values()
            if r["verdict"] == "confirmed" and r["expect"]["vulnerable"] == "miss"),
    }


def run_matrix(faces=FACES_DEFAULT, probes: dict[str, dict] | None = None,
               categories: tuple[str, ...] | None = None) -> dict:
    """执行探针库对两态靶场的差分矩阵（每次调用自起自停仿真器）。"""
    if probes is None:
        probes = load_probes()
    if categories is not None:
        wanted = set(categories)
        probes = {k: p for k, p in probes.items() if p["category"] in wanted}
    faces_needed = tuple(sorted({p["face"] for p in probes.values()}))
    for face in faces_needed:
        if face not in FACES_DEFAULT:
            raise ValueError(f"未知 face: {face!r}")
    servers = start_faces(faces_needed)
    results: dict[str, dict] = {}
    try:
        for key in sorted(probes):
            probe = probes[key]
            pair = servers[probe["face"]]
            vuln = execute_probe(probe, pair["vulnerable"].url(""))
            fixed = execute_probe(probe, pair["fixed"].url(""))
            verdict = verdict_of(probe, vuln["hit"], fixed["hit"])
            results[key] = {
                "key": key,
                "title": probe["title"],
                "category": probe["category"],
                "face": probe["face"],
                "target_face": probe["target_face"],
                "severity": probe["severity"],
                "rule_key": probe["rule_key"],
                "expect": probe["expect"],
                "detector": probe["detector"]["kind"],
                "vulnerable": vuln,
                "fixed": fixed,
                "verdict": verdict,
            }
    finally:
        shutdown_faces(servers)
    categories_meta = {
        cat: {
            "title": spec["title"],
            "owasp": spec["owasp"],
            "asi": spec["asi"],
            "probes": [k for k in sorted(results) if results[k]["category"] == cat],
        }
        for cat, spec in CATEGORIES.items()
        if any(r["category"] == cat for r in results.values())
    }
    return {
        "generator": "trident.probes.run",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "faces": faces_needed,
        "summary": _summarize(results),
        "categories": categories_meta,
        "probes": results,
    }


# ---------------------------------------------------------------- 命令行

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trident LLM 探针两态差分运行器")
    parser.add_argument("--out", default=None, help="产物目录（缺省 reports/samples/llm-probes）")
    parser.add_argument("--faces", default=",".join(FACES_DEFAULT),
                        help="逗号分隔 face 子集：gateway,longctx,relay")
    parser.add_argument("--categories", default=None, help="逗号分隔类别子集")
    parser.add_argument("--probe", default=None, help="只跑单个探针键（调试用）")
    args = parser.parse_args(argv)

    probes = load_probes()
    if args.probe:
        if args.probe not in probes:
            print(f"未知探针: {args.probe}")
            return 2
        probes = {args.probe: probes[args.probe]}
    cats = tuple(args.categories.split(",")) if args.categories else None
    faces = tuple(f for f in args.faces.split(",") if f) or FACES_DEFAULT

    matrix = run_matrix(faces=faces, probes=probes, categories=cats)
    from trident.probes.matrix import MATRIX_FILENAME, render_matrix_doc

    out_dir = Path(args.out) if args.out else REPO_ROOT / "reports" / "samples" / "llm-probes"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / MATRIX_FILENAME
    json_path.write_text(json.dumps(matrix, ensure_ascii=False, indent=1), encoding="utf-8")
    md_path = out_dir / "llm-probe-matrix.md"
    md_path.write_text(render_matrix_doc(matrix), encoding="utf-8")

    s = matrix["summary"]
    print(f"probes={s['total']} categories={s['categories']} "
          f"confirmed={s['confirmed']} (attack={s['attack_confirmed']} "
          f"control={s['controls_clean']}) verdicts={s['verdicts']}")
    print(f"matrix: {json_path}")
    print(f"report: {md_path}")
    bad = {k: r["verdict"] for k, r in matrix["probes"].items() if r["verdict"] != "confirmed"}
    if bad:
        print(f"non-confirmed: {bad}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
