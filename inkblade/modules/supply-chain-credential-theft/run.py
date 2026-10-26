"""供应链凭据直取：凭据残留扫描；任何输出仅保留尾4位指纹（redact.cred）。"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from trident.core.redact import CRED_VALUE_RE, cred, redact_line  # noqa: E402

_DEFAULT_ROOT = _REPO / "lab" / "fixtures" / "theft" / "credentials"

_SCAN_SUFFIXES = {".txt", ".sh", ".env", ".conf", ".cfg", ".ini", ".md", ".json", ".yaml", ".yml", ".netrc"}


def _scan(root: Path) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in _SCAN_SUFFIXES:
            continue
        for lineno, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            reasons = []
            for m in CRED_VALUE_RE.finditer(line):
                reasons.append(("token-value", cred(m.group(0))))
            red = redact_line(line)
            if red != line and ("=" in line or ":" in line):
                reasons.append(("assignment", red))
            if reasons:
                hits.append({
                    "file": p.relative_to(root).as_posix(), "line": lineno,
                    "kinds": [r[0] for r in reasons],
                    "redacted": red,
                })
    return hits


def run(ctx: dict, params: dict) -> dict:
    root = Path(params.get("scan_root") or _DEFAULT_ROOT)
    hits = _scan(root)
    findings = [{
        "sev": "high",
        "title": f"凭据残留：{h['file']}:{h['line']}（{', '.join(h['kinds'])}）",
        "detail": f"脱敏样张: {h['redacted']} → 私有模型仓库/对象桶可直取（尾4位指纹留证）",
    } for h in hits]
    if findings:
        findings.append({
            "sev": "high",
            "title": f"供应链凭据面共 {len(hits)} 处残留（{root}）",
            "detail": "以任一残留凭据即可拉取私有权重/数据集；建议轮换并改用投影卷挂载",
        })
    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-inventory.json"
    art.write_text(json.dumps({
        "scan_root": str(root), "hits": hits, "hit_count": len(hits),
        "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = f"扫描 {root}：凭据残留 {len(hits)} 处（全部脱敏）"
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
