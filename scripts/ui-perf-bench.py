"""生成 10k findings 静态导出，供 UI 渲染基准与人工回归使用。

用法::

    python scripts/ui-perf-bench.py --findings 10000
    # 产物（默认）：lab/bench/out/ui-10k/index.html + metrics.json

基准用浏览器打开同一份静态导出：

    index.html            # 分页渲染（默认 200 行/页）
    index.html?perf=legacy  # 优化前口径：一次性全量渲染

边界：只写 `lab/bench/out/`（已在 .gitignore），不碰真实集群/证据；数据为合成
finding（标题/详情同构），不代表真实扫描结果的字段分布。
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from inkblade.core.evidence import EvidenceStore  # noqa: E402
from inkblade.webui.export_static import export_static  # noqa: E402

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _rel(path: str | Path) -> str:
    try:
        return Path(path).resolve().relative_to(REPO).as_posix()
    except ValueError:
        return "<abs-path>"


def build_fixture(root: Path, count: int = 10_000, run_name: str = "ui-10k") -> dict:
    """在 root 下生成 count 条 findings 的 run，并导出静态页面。"""
    root = Path(root)
    store = EvidenceStore(root / "workspace", workspace="ui-perf")
    run = store.create_run(run_name)
    run.add_step("scan-fixture", "synthetic 10k findings", {"fixture": "ui-perf"},
                 f"{count} synthetic findings")

    db = run.dir / "evidence.db"
    conn = sqlite3.connect(db)
    try:
        rows = []
        for i in range(count):
            sev = SEVERITIES[i % len(SEVERITIES)]
            rows.append((
                run_name, "scan-fixture", sev,
                f"[{sev.upper()}] synthetic finding #{i:05d}",
                "synthetic detail for render benchmark " * 2,
                f"steps/scan-fixture.tar.gz",
                1 if i % 997 == 0 else 0,
            ))
        conn.executemany(
            "INSERT INTO findings(run, step_key, severity, title, detail, evidence_path, is_zeroday)"
            " VALUES(?,?,?,?,?,?,?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()
    run.finalize_run()

    out = root / "export"
    if out.exists():
        shutil.rmtree(out)
    started = time.perf_counter()
    html_path = export_static(run.dir, out)
    export_s = time.perf_counter() - started
    html_bytes = html_path.stat().st_size
    db_bytes = db.stat().st_size
    return {
        "schema": "inkblade-ui-perf-fixture/1",
        "findings": count,
        "run_dir": _rel(run.dir),
        "index_html": _rel(html_path),
        "html_bytes": html_bytes,
        "db_bytes": db_bytes,
        "export_s": round(export_s, 3),
        "boundary": "synthetic findings only; local static export; no real cluster/evidence",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="10k findings UI 渲染基准 fixture")
    ap.add_argument("--findings", type=int, default=10_000)
    ap.add_argument("--out", default=str(REPO / "lab" / "bench" / "out" / "ui-10k"))
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)
    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    metrics = build_fixture(out, count=args.findings)
    metrics["out"] = _rel(out)
    json_out = Path(args.json_out) if args.json_out else out / "metrics.json"
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
