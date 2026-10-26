"""供应链固定：trust_remote_code 硬编码 + revision 缺失检测（regex 通道）。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from inkblade.core.codescan import load_rules, scan_path  # noqa: E402

_DEFAULT_ROOT = _REPO / "lab" / "sample-vuln-repo"

RULES = {"trust-remote-code", "missing-revision"}


def run(ctx: dict, params: dict) -> dict:
    root = Path(params.get("root") or _DEFAULT_ROOT)
    rules = [r for r in load_rules()["rules"] if r["id"] in RULES]
    sev_map = {r["id"]: r.get("sev", "medium") for r in rules}
    hits = [h for h in scan_path(root) if h["rule"] in RULES]
    findings = [{
        "sev": sev_map.get(h["rule"], "medium"),
        "title": f"供应链未固定 {h['rule']} @ {h['file']}:{h['line']}",
        "detail": f"{h['file']}:{h['line']} [{h['channel']}] {h['snippet']}",
    } for h in hits]

    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-report.json"
    art.write_text(json.dumps({
        "root": str(root), "rules": sorted(RULES), "hits": hits,
        "hit_count": len(hits), "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = f"扫描 {root}：供应链固定缺口命中 {len(hits)} 处"
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
