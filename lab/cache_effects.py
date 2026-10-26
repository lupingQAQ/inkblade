"""lab/cache_effects.py — 多租户缓存安全实效验证（4 项，仅 127.0.0.1 真实 HTTP）。

四项实效与 ``docs/CACHE-SECURITY.md`` 第 7 节一一对应：

1. ``approx-cache-false-hit-readback``：tenant-a 用单 token 变异文本查询近似缓存，
   命中 tenant-b 条目并读回 ``TRIDENT-BENIGN-APPROX-VICTIM`` marker；
2. ``cache-timing-membership-delta``：30 条受害成员前缀 + 30 条未缓存对照前缀，
   N=60≥50，TTFT 两档分离（Welch t 检验 p<0.05 且 Δ≥30ms）；
3. ``cache-eviction-residue-readback``：唯一前缀洪泛触发 LRU 逐出后，
   tenant-a 从残留层读回 tenant-b 被逐出前缀与 ``TRIDENT-BENIGN-RESIDUE-VICTIM`` marker；
4. ``remote-kv-pool-namespace-bypass``：tenant-a 直接读回 tenant-b 的 KV 池块，
   值含 ``TRIDENT-BENIGN-POOL-VICTIM`` marker（无租户命名空间校验）。

命令行（生成报告 artifact）::

    python -m lab.cache_effects --out reports/samples/cache-security
"""
from __future__ import annotations

import argparse
import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from lab.cache_sim import (
    VICTIM_APPROX_TEXT,
    VICTIM_POOL_BLOCK_ID,
    VICTIM_RESIDUE_PREFIX,
    member_prefixes,
    start_all,
)

HOST = "127.0.0.1"
TENANT = "tenant-a"
VICTIM = "tenant-b"


def _http(url: str, method: str = "GET", body=None, headers: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text
    return {"status": status, "payload": payload, "text": text}


def _betacf(a: float, b: float, x: float) -> float:
    max_it, eps, fpmin = 300, 3e-12, 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, max_it + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def _betainc(a: float, b: float, x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_bt = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
             + a * math.log(x) + b * math.log(1.0 - x))
    bt = math.exp(ln_bt)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def welch_ttest(xs: list[float], ys: list[float]) -> dict:
    """Welch 双尾 t 检验（不完全 Beta 精确 p，纯标准库）。"""
    n1, n2 = len(xs), len(ys)
    m1, m2 = sum(xs) / n1, sum(ys) / n2
    v1 = sum((x - m1) ** 2 for x in xs) / max(1, n1 - 1)
    v2 = sum((y - m2) ** 2 for y in ys) / max(1, n2 - 1)
    se_sq = v1 / n1 + v2 / n2
    se = math.sqrt(se_sq)
    t = (m1 - m2) / se if se > 0 else 0.0
    if se_sq > 0:
        df = se_sq ** 2 / ((v1 / n1) ** 2 / (n1 - 1) + (v2 / n2) ** 2 / (n2 - 1))
    else:
        df = float(n1 + n2 - 2)
    if df <= 0 or se == 0:
        p = 1.0 if abs(t) < 1e-12 else 0.0
    else:
        p = _betainc(df / 2.0, 0.5, df / (df + t * t))
    return {"t": round(t, 4), "df": round(df, 2), "p": p,
            "mean_member_ms": round(m1, 3), "mean_control_ms": round(m2, 3),
            "delta_ms": round(m2 - m1, 3)}


def _check(cid: str, title: str, fn) -> dict:
    started = time.time()
    item = {"id": cid, "title": title, "status": "FAIL", "evidence": {}, "detail": ""}
    try:
        item["evidence"] = fn() or {}
        item["status"] = "PASS"
    except Exception as exc:  # noqa: BLE001 —— 断言失败记 FAIL，便于一次看全
        item["detail"] = f"{type(exc).__name__}: {exc}"
    item["elapsed_ms"] = round((time.time() - started) * 1000, 1)
    return item


def run_effects(mode: str = "vulnerable") -> dict:
    """执行 4 项缓存实效并返回清单（vulnerable 下 4/4 PASS）。"""
    checks: list[dict] = []

    def approx_false_hit() -> dict:
        with start_all(mode=mode) as lab:
            probe = VICTIM_APPROX_TEXT.replace("42.7M", "42.8M")
            lookup = _http(lab.url("/approx/lookup"), "POST", {"text": probe},
                           {"X-Tenant": TENANT})
            payload = lookup["payload"] if isinstance(lookup["payload"], dict) else {}
            matched = payload.get("matched") or {}
            if lookup["status"] != 200 or not payload.get("hit"):
                raise AssertionError(f"近似缓存未误命中：{lookup['status']} {payload}")
            if matched.get("tenant") != VICTIM:
                raise AssertionError(f"命中条目不属于受害租户：{matched.get('tenant')}")
            response = str(matched.get("response") or "")
            if "TRIDENT-BENIGN-APPROX-VICTIM" not in response:
                raise AssertionError("未读回受害租户 benign marker")
            return {
                "http_status": lookup["status"],
                "similarity": payload.get("best_similarity"),
                "threshold": payload.get("threshold"),
                "requester_tenant": TENANT,
                "matched_tenant": matched.get("tenant"),
                "marker": "TRIDENT-BENIGN-APPROX-VICTIM",
                "marker_present": True,
                "response_excerpt": response[:96],
                "route": "/approx/lookup",
            }

    checks.append(_check("approx-cache-false-hit-readback",
                         "近似缓存误命中：tenant-a 读回 tenant-b 响应与 benign marker",
                         approx_false_hit))

    def timing_membership() -> dict:
        with start_all(mode=mode) as lab:
            members = member_prefixes(30)
            controls = [f"trident-control-corpus {i:02d} unrelated analytics topic "
                        f"reference data pack" for i in range(30)]
            member_ttft, control_ttft = [], []
            for i in range(30):
                m = _http(lab.url("/v1/chat/completions"), "POST", {
                    "prompt_prefix": members[i], "prefix_tokens": 2048,
                    "max_tokens": 1}, {"X-Tenant": TENANT})
                c = _http(lab.url("/v1/chat/completions"), "POST", {
                    "prompt_prefix": controls[i], "prefix_tokens": 2048,
                    "max_tokens": 1}, {"X-Tenant": TENANT})
                if m["status"] != 200 or c["status"] != 200:
                    raise AssertionError(f"TTFT 采样失败：{m['status']}/{c['status']}")
                member_ttft.append(float(m["payload"]["ttft_ms"]))
                control_ttft.append(float(c["payload"]["ttft_ms"]))
            stats = welch_ttest(member_ttft, control_ttft)
            n_total = len(member_ttft) + len(control_ttft)
            if n_total < 50:
                raise AssertionError(f"样本不足：N={n_total}")
            if stats["delta_ms"] < 30 or stats["p"] >= 0.05:
                raise AssertionError(f"TTFT 差分不显著：{stats}")
            if max(member_ttft) >= min(control_ttft):
                raise AssertionError("命中档与未命中档发生重叠")
            return {
                "n_total": n_total,
                "n_member": len(member_ttft),
                "n_control": len(control_ttft),
                "mean_member_ttft_ms": stats["mean_member_ms"],
                "mean_control_ttft_ms": stats["mean_control_ms"],
                "delta_ms": stats["delta_ms"],
                "welch_t": stats["t"],
                "df": stats["df"],
                "p_value": stats["p"],
                "alpha": 0.05,
                "significant": True,
                "member_ttft_range_ms": [min(member_ttft), max(member_ttft)],
                "control_ttft_range_ms": [min(control_ttft), max(control_ttft)],
                "route": "/v1/chat/completions",
            }

    checks.append(_check("cache-timing-membership-delta",
                         "缓存时序侧信道：N=60≥50，TTFT 命中/未命中两档显著分离（Welch p<0.05）",
                         timing_membership))

    def eviction_residue() -> dict:
        with start_all(mode=mode) as lab:
            before = _http(lab.url("/router/metrics"), headers={"X-Tenant": TENANT})
            ev_before = int(((before["payload"] or {}).get("pool") or {})
                            .get("evictions_total") or 0)
            for i in range(160):
                resp = _http(lab.url("/v1/chat/completions"), "POST", {
                    "prompt_prefix": f"residue-effect-flood-{i:04d} unique corpus",
                    "prefix_tokens": 2048, "max_tokens": 1}, {"X-Tenant": TENANT})
                if resp["status"] != 200:
                    raise AssertionError(f"洪泛请求失败：{resp['status']}")
            after = _http(lab.url("/router/metrics"), headers={"X-Tenant": TENANT})
            ev_after = int(((after["payload"] or {}).get("pool") or {})
                           .get("evictions_total") or 0)
            if ev_after - ev_before < 1:
                raise AssertionError("洪泛未触发 LRU 逐出")
            url = (lab.url("/cache/residue") + "?prefix="
                   + urllib.parse.quote(VICTIM_RESIDUE_PREFIX, safe=""))
            residue = _http(url, headers={"X-Tenant": TENANT})
            payload = residue["payload"] if isinstance(residue["payload"], dict) else {}
            if residue["status"] != 200 or not payload.get("found"):
                raise AssertionError(f"残留不可读：{residue['status']} {payload}")
            if payload.get("tenant") != VICTIM:
                raise AssertionError(f"残留归属异常：{payload.get('tenant')}")
            preview = str(payload.get("prefix_preview") or "")
            if "TRIDENT-BENIGN-RESIDUE-VICTIM" not in preview:
                raise AssertionError("残留预览不含受害 marker")
            return {
                "evictions_before": ev_before,
                "evictions_after": ev_after,
                "evictions_delta": ev_after - ev_before,
                "residue_status": residue["status"],
                "residue_tenant": payload.get("tenant"),
                "marker": "TRIDENT-BENIGN-RESIDUE-VICTIM",
                "marker_present": True,
                "prefix_preview": preview[:96],
                "route": "/cache/residue",
            }

    checks.append(_check("cache-eviction-residue-readback",
                         "逐出残留：LRU 逐出后 tenant-a 读回 tenant-b 被逐出前缀（marker 命中）",
                         eviction_residue))

    def kv_pool_bypass() -> dict:
        with start_all(mode=mode) as lab:
            url = lab.url("/kvpool/blocks/" + urllib.parse.quote(VICTIM_POOL_BLOCK_ID, safe=""))
            read = _http(url, headers={"X-Tenant": TENANT})
            payload = read["payload"] if isinstance(read["payload"], dict) else {}
            if read["status"] != 200 or not payload.get("found"):
                raise AssertionError(f"KV 块不可读：{read['status']} {payload}")
            if payload.get("tenant") != VICTIM:
                raise AssertionError(f"块归属异常：{payload.get('tenant')}")
            value = str(payload.get("value") or "")
            if "TRIDENT-BENIGN-POOL-VICTIM" not in value:
                raise AssertionError("KV 块值不含受害 marker")
            return {
                "http_status": read["status"],
                "block_id": VICTIM_POOL_BLOCK_ID,
                "block_tenant": payload.get("tenant"),
                "requester_tenant": TENANT,
                "marker": "TRIDENT-BENIGN-POOL-VICTIM",
                "marker_present": True,
                "value_excerpt": value[:96],
                "route": "/kvpool/blocks/{block}",
            }

    checks.append(_check("remote-kv-pool-namespace-bypass",
                         "远程 KV 池命名空间绕过：tenant-a 直接读回 tenant-b 的 KV 块",
                         kv_pool_bypass))

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": mode,
        "host": HOST,
        "checks": checks,
        "summary": {
            "total": len(checks),
            "passed": sum(1 for c in checks if c["status"] == "PASS"),
            "failed": sum(1 for c in checks if c["status"] != "PASS"),
        },
    }


def write_report(result: dict, out_dir: Path | str) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "effects.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [
        "# 多租户缓存安全实效（Cache Security Effects）",
        "",
        f"- 生成时间：{result['generated_at']}",
        f"- 姿态：`{result['mode']}`（仅 {result['host']}，标准库 HTTP）",
        f"- 汇总：**{result['summary']['passed']}/{result['summary']['total']} PASS**",
        "",
        "| 实效 | 状态 | 证据摘要 |",
        "|---|---|---|",
    ]
    for item in result["checks"]:
        ev = json.dumps(item["evidence"], ensure_ascii=False, sort_keys=True)
        lines.append(f"| `{item['id']}` | {item['status']} | {ev[:320]} |")
    path = out / "effects.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trident 多租户缓存安全实效验证")
    parser.add_argument("--out", default="reports/samples/cache-security")
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), default="vulnerable")
    args = parser.parse_args(argv)
    result = run_effects(args.mode)
    path = write_report(result, args.out)
    print(f"cache effects: {result['summary']['passed']}/{result['summary']['total']} "
          f"PASS -> {path}")
    return 0 if result["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
