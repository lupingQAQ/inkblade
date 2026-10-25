# -*- coding: utf-8 -*-
"""确定性 SVG/HTML 可视化（无 JS/CDN、无时间戳、无绝对路径）。"""
from __future__ import annotations

from html import escape

try:
    from .sim import Telemetry
except ImportError:
    from sim import Telemetry

COLORS = {"info": "#2563eb", "medium": "#d97706", "high": "#dc2626"}


def render_svg(t: Telemetry, findings: list[dict] | None = None) -> str:
    findings = findings or []
    width, height = 1080, 760
    links = sorted(t.links, key=lambda x: x["bytes"], reverse=True)[:18]
    max_bytes = max([x["bytes"] for x in links] or [1])
    ranks = list(t.ranks.items())[:48]
    max_rank = max([v for _, v in ranks] or [1])
    rows = []
    y = 118
    rows.append(f'<text x="24" y="34" font-size="20" font-family="monospace">'
                f'Trident fabric sim — {escape(t.scenario)} (nodes={t.topology["nodes"]}, '
                f'ranks={len(t.ranks)}) — SIMULATED</text>')
    rows.append(f'<text x="24" y="60" font-size="13" font-family="monospace">'
                f'PFC={t.pfc_pause_frames} ECN={t.ecn_marks} drops={t.drops} '
                f'cross-rail={t.cross_rail_flows} goodput={t.goodput_gbps:.2f} Gbps</text>')
    rows.append(f'<text x="24" y="84" font-size="13" font-family="monospace">'
                f'worst={t.worst_rank} {t.worst_rank_ms:.2f}ms / median '
                f'{t.median_completion_ms:.2f}ms — simulated, not real hardware</text>')
    rows.append(f'<text x="24" y="110" font-size="14" font-family="monospace">Top links by bytes</text>')
    for item in links:
        pct = item["bytes"] / max_bytes
        color = "#dc2626" if item["pfc_pause_frames"] > 0 or item["drops"] else (
            "#d97706" if item["ecn_marks"] else "#2563eb")
        rows.append(f'<rect x="24" y="{y}" width="{int(480 * pct)}" height="14" fill="{color}"/>')
        rows.append(f'<text x="510" y="{y + 11}" font-size="11" font-family="monospace">'
                    f'{escape(item["id"])}</text>')
        y += 19
    # rank completion
    y2 = 118
    rows.append(f'<text x="24" y="{y2 + 300}" font-size="14" font-family="monospace">'
                f'Rank completion (ms)</text>')
    for i, (name, ms) in enumerate(ranks):
        bar = int(120 * ms / max_rank)
        x = 24 + i * 20
        rows.append(f'<rect x="{x}" y="{560 - bar}" width="14" height="{bar}" fill="#0f766e"/>')
        if i % 6 == 0:
            rows.append(f'<text x="{x}" y="578" font-size="9" font-family="monospace" '
                        f'transform="rotate(45 {x} 578)">{escape(name)}</text>')
    rows.append(f'<line x1="24" y1="560" x2="1000" y2="560" stroke="#334155"/>')
    # rail matrix
    leaves = sorted(t.rail_matrix)
    rows.append(f'<text x="600" y="118" font-size="14" font-family="monospace">Rail bytes by leaf</text>')
    for i, leaf in enumerate(leaves[:30]):
        for r in range(t.topology["rails"]):
            value = t.rail_matrix[leaf].get(f"rail-{r}", 0)
            if value:
                opacity = min(1.0, 0.25 + value / max(1, t.total_bytes) * 4)
                rows.append(f'<rect x="{600 + r * 12}" y="{132 + i * 14}" width="10" height="11" '
                            f'fill="#7c3aed" opacity="{opacity:.2f}"/>')
        rows.append(f'<text x="570" y="{142 + i * 14}" font-size="9" font-family="monospace">'
                    f'{escape(leaf)}</text>')
    # findings
    fy = 610
    for f in findings[:6]:
        rows.append(f'<text x="24" y="{fy}" font-size="11" font-family="monospace" '
                    f'fill="{COLORS.get(f["sev"], "#334155")}">[{f["sev"]}] {escape(f["rule"])} '
                    f'{escape(f["title"])}</text>')
        fy += 16
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
            'viewBox="0 0 %d %d" role="img" aria-label="Trident fabric simulation">'
            '<rect width="100%%" height="100%%" fill="#f8fafc"/>%s</svg>'
            % (width, height, width, height, "".join(rows)))


def render_html(t: Telemetry, findings: list[dict], svg: str | None = None) -> str:
    svg = svg or render_svg(t, findings)
    rows = "".join(
        f"<tr><td>{escape(f['sev'])}</td><td>{escape(f['rule'])}</td>"
        f"<td>{escape(f['title'])}</td></tr>" for f in findings)
    return ("<!doctype html><html lang='zh'><meta charset='utf-8'>"
            "<title>Trident fabric simulation</title>"
            "<style>body{font-family:monospace;margin:20px;background:#f8fafc}"
            "table{border-collapse:collapse;margin-top:16px}td,th{border:1px solid #cbd5e1;"
            "padding:4px 8px;text-align:left}th{background:#e2e8f0}</style>"
            "<h1>Trident fabric simulation</h1>"
            "<p><b>模拟，非真实硬件</b> — discrete-event model, not 10K GPU measurement.</p>"
            f"{svg}<table><tr><th>sev</th><th>rule</th><th>finding</th></tr>{rows}</table>"
            "</html>")
