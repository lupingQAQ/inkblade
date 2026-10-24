"""组合签名静态检测：同文件内多条脆弱规则共存 → 组合签名成立（带 file:line 证据）。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from trident.core.codescan import load_rules, match_combos, scan_path  # noqa: E402

_DEFAULT_ROOT = _REPO / "lab" / "sample-vuln-repo"


def run(ctx: dict, params: dict) -> dict:
    root = Path(params.get("root") or _DEFAULT_ROOT)
    data = load_rules()
    hits = scan_path(root)
    combos = match_combos(hits, data["combos"])
    findings = [{
        "sev": "high",
        "title": f"组合签名 {c['id']} 成立 @ {c['file']}",
        "detail": f"{c['file']}: 证据 {', '.join(c['evidence'])}；{c['detail']}",
    } for c in combos]

    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-report.json"
    art.write_text(json.dumps({
        "root": str(root), "combos": combos,
        "underlying_hits": [h for h in hits if any(
            h["rule"] in c.get("requires", []) and h["file"] == c["file"] for c in combos)],
        "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = f"扫描 {root}：组合签名成立 {len(combos)} 组"
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
