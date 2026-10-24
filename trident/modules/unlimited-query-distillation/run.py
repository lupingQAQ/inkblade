"""无限查询蒸馏面：查询留痕证明未鉴权 + 无配额 + 无审计。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
_DEFAULT_LOG = _REPO / "lab" / "fixtures" / "theft" / "access" / "query-log.json"


def run(ctx: dict, params: dict) -> dict:
    log_path = params.get("access_log") or str(_DEFAULT_LOG)
    doc = json.loads(Path(log_path).read_text(encoding="utf-8"))
    queries = doc.get("queries", [])
    auth = doc.get("auth", {})
    quota = doc.get("quota", {})
    audit = doc.get("audit", {})

    findings: list[dict[str, Any]] = []
    problems = []
    if not auth.get("required"):
        problems.append("端点未鉴权" + ("（api_key 可选）" if auth.get("api_key_optional") else ""))
    if not quota.get("enabled"):
        problems.append("查询配额未启用（rate_limit/cap 缺失）")
    if not audit.get("query_logging"):
        problems.append("查询审计日志未开启")
    if problems:
        findings.append({
            "sev": "high",
            "title": f"推理端点 {doc.get('endpoint', '?')} 蒸馏面开放：无鉴权且无配额",
            "detail": "；".join(problems)
                      + f"。留痕样本 {len(queries)} 次查询零拦截 → 可无限采样复刻模型能力"
                        "（总纲第 6 节查询滥用条目）",
        })

    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-proof.json"
    art.write_text(json.dumps({
        "endpoint": doc.get("endpoint"),
        "auth": auth, "quota": quota, "audit": audit,
        "query_count": len(queries),
        "query_digests": [q.get("prompt_digest") for q in queries],
        "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = f"留痕 {len(queries)} 次查询：鉴权={auth.get('required')}，配额={quota.get('enabled')}"
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
