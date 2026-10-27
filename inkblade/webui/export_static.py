"""静态导出器：把一次 run 的数据库层（steps/findings/graph 表）内嵌进离线 HTML。

用法（等价命令行入口由 cli 提供）::

    from inkblade.webui.export_static import export_static
    html_path = export_static(run_dir, out_dir)

- ``run_dir``：一次运行的目录（含 evidence.db），即 ``<workspace>/evidence/<run>`` 下的 run 目录
- ``out_dir``：输出目录（自动创建）；静态资产（app.js/style.css/vendor）随行拷贝，
  ``window.INKBLADE_DATA`` 注入 index.html，浏览器直接打开（file://）即可浏览六视图，无需服务。
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

_STATIC = Path(__file__).parent / "static"
_MARKER = "<!-- INKBLADE_DATA -->"


def _rows(conn: sqlite3.Connection, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    return [dict(r) for r in conn.execute(sql, args)]


def load_run_data(run_dir: Path | str, redact_zeroday: bool = False) -> dict[str, Any]:
    """读取一次 run 的数据库层 → 视图数据模型（steps/findings/nodes/edges/manifest）。

    ``redact_zeroday=True`` 为可选脱敏开关（供未来真私有发现）：仅对 is_zeroday
    发现隐藏标题/细节文本，保留证据归档引用；默认关闭（已公开零日级模块正常展示）。
    """
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
        if redact_zeroday:
            for f in findings:
                if f.get("is_zeroday"):
                    f["title"] = "【脱敏】影响已验证（零日级，未展示细节）"
                    f["detail"] = ""
        combos = _rows(conn, "SELECT signature, detail FROM combos WHERE run=?", (name,))
        try:
            file_ops = _rows(
                conn,
                "SELECT id, run, step_id, step_key, task_id, ts, phase, op, technique,"
                " probe_id, cluster, namespace, pid, argv, cwd, env_digest, opened_files,"
                " path, mode, size_bytes, sha256, exit_code, stdout_hash, duration_ms,"
                " result, detail FROM file_ops WHERE run=? ORDER BY ts, id",
                (name,),
            )
        except sqlite3.Error:
            file_ops = []  # 老 run 没有 file_ops 表
        for row in file_ops:
            for key in ("argv", "opened_files"):
                raw = row.get(key)
                try:
                    row[key] = json.loads(raw) if raw else []
                except (TypeError, ValueError):
                    row[key] = []
        nodes = _rows(conn, "SELECT node_id, kind, layer, attrs FROM graph_nodes")
        edges = _rows(conn, "SELECT src, dst, verdict, method, chain FROM graph_edges")
        # 老 run 或非 agent 执行可能只有 steps 而无 graph_nodes。此时按执行顺序
        # 生成工作流 DAG，保证控制台仍可展示“做过什么、先后关系”，不伪造资产边。
        if not nodes and steps:
            prev_id = None
            for s in steps:
                node_id = f"step:{s['id']}"
                attrs = {
                    "label": s.get("step_key") or node_id,
                    "status": s.get("status"),
                    "summary": s.get("result_summary") or "",
                }
                nodes.append({
                    "node_id": node_id,
                    "kind": "step",
                    "layer": "workflow",
                    "attrs": json.dumps(attrs, ensure_ascii=False),
                })
                if prev_id is not None:
                    edges.append({
                        "src": prev_id,
                        "dst": node_id,
                        "verdict": "sequence",
                        "method": "step-order",
                        "chain": "",
                    })
                prev_id = node_id
    finally:
        conn.close()

    manifest_path = run_dir / "manifest.sha256"
    manifest = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else ""

    data = {
        "run": run_meta,
        "steps": steps,
        "findings": findings,
        "combos": combos,
        "nodes": nodes,
        "edges": edges,
        "file_ops": file_ops,
        "manifest": manifest,
    }
    # 统一时间线：优先用收尾时落盘的 timeline.json，缺失则按 DB 现建（老 run）。
    from ..core.timeline import load_timeline

    data["timeline"] = load_timeline(run_dir, build_if_missing=True) or {
        "schema": "inkblade-timeline-v1", "run": name, "events": [], "counts": {},
    }
    # 十视图补充数据（文件存在才内嵌；老 run 导出不受影响）：
    # drift.json（⑧差异视图）与工作区级 assets.db / explorer 队列 / schedules
    drift_path = run_dir / "drift.json"
    if drift_path.exists():
        try:
            data["drift"] = json.loads(drift_path.read_text(encoding="utf-8"))
        except ValueError:
            pass
    ws_dir = run_dir.parent
    assets_db = ws_dir / "assets.db"
    if assets_db.exists():
        try:
            aconn = sqlite3.connect(assets_db)
            aconn.row_factory = sqlite3.Row
            inv_rows = [dict(r) for r in aconn.execute(
                "SELECT asset_key, kind, product, name, namespace, addr, port, missing_since FROM assets")]
            aconn.close()
            nodes_a = [{"id": r["asset_key"], "kind": r["kind"], "label": r["name"],
                        "product": r["product"], "namespace": r["namespace"], "addr": r["addr"],
                        "port": r["port"], "missing": r["missing_since"] is not None} for r in inv_rows]
            keys = {n["id"] for n in nodes_a}
            edges_a = [{"src": f"namespace/{n['namespace']}/{n['namespace']}".replace("//", "/"),
                        "dst": n["id"], "relation": "contains"}
                       for n in nodes_a if n["kind"] == "service" and n["namespace"]
                       and f"namespace/{n['namespace']}/{n['namespace']}".replace("//", "/") in keys]
            data["assets"] = {"nodes": nodes_a, "edges": edges_a}
        except sqlite3.Error:
            pass
    queue_path = ws_dir / "explorer" / "queue.json"
    if queue_path.exists():
        try:
            data["proposals"] = json.loads(queue_path.read_text(encoding="utf-8"))
        except ValueError:
            pass
    sched_path = ws_dir / "schedules.json"
    if sched_path.exists():
        try:
            data["schedules"] = json.loads(sched_path.read_text(encoding="utf-8"))
        except ValueError:
            pass
    return data


def export_static(run_dir: Path | str, out: Path | str, redact_zeroday: bool = False) -> Path:
    """导出一次 run 的免服务静态页面，返回写出的 index.html 路径。"""
    out = Path(out)
    data = load_run_data(run_dir, redact_zeroday=redact_zeroday)

    # 静态资产随行（vendor UMD / app.js / style.css / index.html 模板）
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(_STATIC, out)
    # 时间线原始产物随行（机器可读；index.html 内已内嵌同一份数据）
    timeline_src = Path(run_dir) / "timeline.json"
    if timeline_src.is_file():
        shutil.copy2(timeline_src, out / "timeline.json")

    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    payload = json.dumps(data, ensure_ascii=False, default=str)
    payload = payload.replace("<", "\\u003c")  # 防 </script> 逃逸
    inject = "<script>window.INKBLADE_DATA = " + payload + ";</script>"
    if _MARKER not in html:
        raise ValueError("index.html 缺少注入点标记 INKBLADE_DATA")
    html = html.replace(_MARKER, inject)

    target = out / "index.html"
    target.write_text(html, encoding="utf-8")
    return target


if __name__ == "__main__":  # 手动：python -m inkblade.webui.export_static <run_dir> <out>
    import sys

    if len(sys.argv) != 3:
        print("usage: python -m inkblade.webui.export_static <run_dir> <out_dir>")
        raise SystemExit(2)
    print(export_static(sys.argv[1], sys.argv[2]))
