"""训练数据泄露：数据集/缓存/日志 PII/RL 轨迹四类泄露面检出 + 脱敏样张。"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from inkblade.core.redact import cred, pii, redact_line  # noqa: E402

_DEFAULT_ROOT = _REPO / "lab" / "fixtures" / "theft"

DATASET_EXTS = {".parquet", ".arrow", ".tar", ".jsonl", ".csv"}
_PII_HINT_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
                          r"|(?<!\d)1[3-9]\d[- ]?\d{4}[- ]?\d{4}(?!\d)")
_SECRET_ASSIGN_RE = re.compile(
    r"(?im)^(?:export\s+)?([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|KEY|CREDENTIAL)[A-Z0-9_]*)=(\S{8,})\s*$"
)


def _scan_credentials(root: Path) -> list[dict[str, Any]]:
    """扫描 credentials/ 与 .env/.netrc：输出仅保留尾4位指纹（明文不入报告/产物）。"""
    hits: list[dict[str, Any]] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(root).parts
        if "credentials" not in rel_parts and p.suffix not in (".env", ".netrc"):
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        for lineno, line in enumerate(lines, 1):
            masked = redact_line(line)
            for m in _SECRET_ASSIGN_RE.finditer(line):
                masked = masked.replace(m.group(0), f"{m.group(1)}=****{cred(m.group(2))}")
            if masked != line:
                hits.append({"file": rel, "line": lineno, "redacted": masked})
    return hits


def _categorize(root: Path) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {
        "dataset": [], "cache": [], "log-pii": [], "trajectory": [], "credential": [],
    }
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        parts = p.relative_to(root).parts
        if p.suffix in DATASET_EXTS:
            out["dataset"].append({"file": rel})
        if "cache" in parts or "hf-cache" in p.stem:
            out["cache"].append({"file": rel})
        if p.suffix == ".log":
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if _PII_HINT_RE.search(line):
                    out["log-pii"].append({"file": rel, "line": i, "redacted": pii(line)})
        if p.suffix == ".jsonl" and "trajectories" in parts:
            out["trajectory"].append({"file": rel})
            for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if '"prompt"' in line:
                    out["trajectory"][-1]["redacted_sample"] = pii(line)
                    break
    out["credential"] = _scan_credentials(root)
    return out


def run(ctx: dict, params: dict) -> dict:
    root = Path(params.get("data_root") or _DEFAULT_ROOT)
    cats = _categorize(root)

    findings: list[dict[str, Any]] = []
    if cats["dataset"]:
        findings.append({
            "sev": "high",
            "title": f"共享数据集卷未授权读：{len(cats['dataset'])} 个数据集文件",
            "detail": "; ".join(d["file"] for d in cats["dataset"]) + "（RWX 共享 → 跨租户训练数据可取）",
        })
    if cats["cache"]:
        findings.append({
            "sev": "medium",
            "title": f"数据缓存残留：{len(cats['cache'])} 处",
            "detail": "; ".join(c["file"] for c in cats["cache"])
                      + "（webdataset/Arrow/HF 缓存可跨租户重建数据）",
        })
    if cats["log-pii"]:
        first = cats["log-pii"][0]
        findings.append({
            "sev": "high",
            "title": f"训练日志含 PII/prompt 残留：{len(cats['log-pii'])} 行",
            "detail": f"样例 {first['file']}:{first['line']}（脱敏后）: {first['redacted']}",
        })
    if cats["trajectory"]:
        t = cats["trajectory"][0]
        findings.append({
            "sev": "high",
            "title": f"RL 轨迹跨租户残留：{len(cats['trajectory'])} 个轨迹文件",
            "detail": f"{t['file']} 含 prompt/奖励信号"
                      + (f"，脱敏样张: {t['redacted_sample']}" if t.get("redacted_sample") else ""),
        })

    if cats["credential"]:
        first = cats["credential"][0]
        findings.append({
            "sev": "high",
            "title": f"训练/数据面凭据残留：{len(cats['credential'])} 处（仅尾4位）",
            "detail": f"样例 {first['file']}:{first['line']}（脱敏后）: {first['redacted']}"
                      " → 凭据明文不入报告/产物，仅保留尾4位指纹",
        })

    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-samples.json"
    art.write_text(json.dumps({
        "data_root": str(root), "categories": cats,
        "sample_count": {k: len(v) for k, v in cats.items()},
        "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = f"扫描 {root}：数据集 {len(cats['dataset'])}、缓存 {len(cats['cache'])}、" \
              f"日志PII {len(cats['log-pii'])}、轨迹 {len(cats['trajectory'])}、" \
              f"凭据 {len(cats['credential'])}（脱敏）"
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
