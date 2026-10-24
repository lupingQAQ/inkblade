"""静态导出器：把一次 run 的数据库层（steps/findings/graph 表）内嵌进离线 HTML。

用法（等价命令行入口由 cli 提供）::

    from trident.webui.export_static import export_static
    html_path = export_static(run_dir, out_dir)

- ``run_dir``：一次运行的目录（含 evidence.db），即 ``<workspace>/evidence/<run>`` 下的 run 目录
- ``out_dir``：输出目录（自动创建）；静态资产（app.js/style.css/vendor）随行拷贝，
  ``window.TRIDENT_DATA`` 注入 index.html，浏览器直接打开（file://）即可浏览六视图，无需服务。
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

_STATIC = Path(__file__).parent / "static"
_MARKER = "<!-- TRIDENT_DATA -->"


def _rows(conn: sqlite3.Connection, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    return [dict(r) for r in conn.execute(sql, args)]


def load_run_data(run_dir: Path | str) -> dict[str, Any]:
    """读取一次 run 的数据库层 → 视图数据模型（steps/findings/nodes/edges/manifest）。"""
    run_dir = Path(run_dir)
    db = run_dir / "evidence.db"
    if not db.exists():
        raise FileNotFoundError(f"run 数据库缺失: {db}")
    name = run_dir.name
    conn = sqlite3.connect(db)
    try:
        runs = _rows(conn, "SELECT name, created_at, status FROM runs WHERE name=?", (name,))
        run_meta = runs[0] if runs else {"name": name, "created_at": None, "status": "unknown"}

        steps_raw = _rows(
            conn,
            "SELECT id, step_key, started_at, finished_at, result_summary, archive, status"
            " FROM steps WHERE run=? ORDER BY id",
            (name,),
        )
        steps = []
        for s in steps_raw:
            sid = s["id"]
            s["prompts"] = _rows(conn, "SELECT kind, content FROM prompts WHERE step_id=?", (sid,))
            s["env"] = {r["key"]: r["value"] for r in _rows(conn, "SELECT key, value FROM env WHERE step_id=?", (sid,))}
            s["evidence"] = _rows(conn, "SELECT path, sha256, kind FROM evidence WHERE step_id=?", (sid,))
            steps.append(s)

        findings = _rows(
            conn,
            "SELECT step_key, severity, title, detail, evidence_path, is_zeroday"
            " FROM findings WHERE run=? ORDER BY id",
            (name,),
        )
        combos = _rows(conn, "SELECT signature, detail FROM combos WHERE run=?", (name,))
        nodes = _rows(conn, "SELECT node_id, kind, layer, attrs FROM graph_nodes")
        edges = _rows(conn, "SELECT src, dst, verdict, method, chain FROM graph_edges")
    finally:
        conn.close()

    manifest_path = run_dir / "manifest.sha256"
    manifest = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else ""

    return {
        "run": run_meta,
        "steps": steps,
        "findings": findings,
        "combos": combos,
        "nodes": nodes,
        "edges": edges,
        "manifest": manifest,
    }


def export_static(run_dir: Path | str, out: Path | str) -> Path:
    """导出一次 run 的免服务静态页面，返回写出的 index.html 路径。"""
    out = Path(out)
    data = load_run_data(run_dir)

    # 静态资产随行（vendor UMD / app.js / style.css / index.html 模板）
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(_STATIC, out)

    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    payload = json.dumps(data, ensure_ascii=False, default=str)
    payload = payload.replace("<", "\\u003c")  # 防 </script> 逃逸
    inject = "<script>window.TRIDENT_DATA = " + payload + ";</script>"
    if _MARKER not in html:
        raise ValueError("index.html 缺少注入点标记 TRIDENT_DATA")
    html = html.replace(_MARKER, inject)

    target = out / "index.html"
    target.write_text(html, encoding="utf-8")
    return target


if __name__ == "__main__":  # 手动：python -m trident.webui.export_static <run_dir> <out>
    import sys

    if len(sys.argv) != 3:
        print("usage: python -m trident.webui.export_static <run_dir> <out_dir>")
        raise SystemExit(2)
    print(export_static(sys.argv[1], sys.argv[2]))
