"""共享卷权重直读：枚举 + sha256 存证（产物作为 artifacts 归档）。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[3]
_DEFAULT_ROOT = _REPO / "lab" / "fixtures" / "theft" / "shared-volume"

WEIGHT_EXTS = {".pt", ".pth", ".safetensors", ".bin", ".ckpt"}
DATASET_EXTS = {".parquet", ".arrow", ".tar", ".jsonl", ".csv"}


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run(ctx: dict, params: dict) -> dict:
    root = Path(params.get("volume_root") or _DEFAULT_ROOT)
    entries: list[dict[str, Any]] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        kind = "weight" if p.suffix in WEIGHT_EXTS else (
            "dataset" if p.suffix in DATASET_EXTS else "file")
        entries.append({
            "file": p.relative_to(root).as_posix(), "kind": kind,
            "bytes": p.stat().st_size, "sha256": _sha256_file(p),
        })
    weights = [e for e in entries if e["kind"] == "weight"]
    datasets = [e for e in entries if e["kind"] == "dataset"]

    findings: list[dict[str, Any]] = []
    if weights:
        total = sum(e["bytes"] for e in weights)
        findings.append({
            "sev": "high",
            "title": f"共享卷权重可直接读取：{len(weights)} 个权重文件（{total} 字节）",
            "detail": "; ".join(f"{e['file']} sha256={e['sha256'][:16]}…" for e in weights)
                      + " → 可读即可换（偷换一体），建议 per-tenant 隔离卷 + 只读挂载",
        })
    if datasets:
        findings.append({
            "sev": "medium",
            "title": f"共享卷数据集可读：{len(datasets)} 个数据文件",
            "detail": "; ".join(e["file"] for e in datasets) + "（设计基线第 6 节共享卷条目）",
        })

    art_dir = ctx["run"].dir / "artifacts"
    art_dir.mkdir(exist_ok=True)
    art = art_dir / f"{ctx['meta']['key']}-inventory.json"
    art.write_text(json.dumps({
        "volume_root": str(root), "entries": entries,
        "weight_count": len(weights), "dataset_count": len(datasets),
        "marker": ctx["marker"],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = f"枚举 {root}：权重 {len(weights)}、数据集 {len(datasets)}、其他 {len(entries) - len(weights) - len(datasets)}"
    return {"summary": summary, "artifacts": [str(art)], "findings": findings}
