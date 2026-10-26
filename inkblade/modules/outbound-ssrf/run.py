"""出站请求与 SSRF：file:// 方案接受等出站面检测（regex 通道）。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from inkblade.core.codescan import load_rules, scan_path  # noqa: E402

_DEFAULT_ROOT = _REPO / "lab" / "sample-vuln-repo"

RULES = {"file-url-accepted"}


def run(ctx: dict, params: dict) -> dict:
    root = Path(params.get("root") or _DEFAULT_ROOT)
    rules = [r for r in load_rules()["rules"] if r["id"] in RULES]
    hits = [h for h in scan_path(root) if h["rule"] in RULES]
    findings = [{
        "sev": "medium",
        "title": f"出站面风险 {h['rule']} @ {h['file']}:{h['line']}",
        "detail": f"{h['file']}:{h['line']} [{h['channel']}] {h['snippet']}"
                  "（file:// 与内网地址未拒绝 → SSRF/本地文件读取面）",
    } for h in hits]

    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-report.json"
    art.write_text(json.dumps({
        "root": str(root), "rules": sorted(RULES), "hits": hits,
        "hit_count": len(hits), "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = f"扫描 {root}：出站/SSRF 面命中 {len(hits)} 处"
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
