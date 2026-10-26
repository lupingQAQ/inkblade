#!/usr/bin/env python3
"""Render the public documentation site from the Markdown guides.

    python scripts/build-docs-site.py            # regenerate docs/*.html
    python scripts/build-docs-site.py --check    # fail if committed output is stale

Design constraints: no external resources (no CDN, no fonts, no analytics), a
dark palette, and every page readable from a local folder without a server.
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

PAGES = [
    ("INSTALL.md", "Install", "安装"),
    ("USAGE.md", "Usage", "使用"),
    ("FEATURES.md", "Features", "特性"),
    ("WORKFLOW.md", "Workflow", "流程"),
    ("MODULES.md", "Modules", "模块"),
    ("ARCHITECTURE.md", "Architecture", "架构"),
    ("AGENT-LLM.md", "Agent & LLM", "Agent 与 LLM"),
    ("VULNERABILITY-COVERAGE.md", "Vulnerability coverage", "漏洞覆盖"),
    ("PILOT-KIT.md", "Pilot kit", "试点工具包"),
    ("PLUGIN-SDK.md", "Plugin SDK", "插件 SDK"),
    ("FAQ.md", "FAQ", "常见问题"),
    ("VERSIONING.md", "Versioning", "版本政策"),
]

HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
FENCE = re.compile(r"^```")
UL = re.compile(r"^[-*]\s+(.*)$")
OL = re.compile(r"^\d+\.\s+(.*)$")
TABLE_SEP = re.compile(r"^\|?\s*:?-{2,}")


def slug(text: str) -> str:
    text = re.sub(r"`", "", text)
    text = re.sub(r"[^\w\u4e00-\u9fff -]", "", text).strip().lower()
    return re.sub(r"\s+", "-", text) or "section"


def join_lines(parts: list[str]) -> str:
    """Join wrapped source lines. CJK text keeps no space at the break."""
    cjk = re.compile(r"[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]")
    out = ""
    for part in parts:
        if out and not (cjk.match(out[-1]) and cjk.match(part[:1])):
            out += " "
        out += part
    return out


def inline(text: str) -> str:
    out = html.escape(text)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", out)
    # relative Markdown links only; anything with a scheme is dropped by policy
    def link(m: re.Match[str]) -> str:
        label, target = m.group(1), m.group(2)
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("//"):
            return label
        target = re.sub(r"\.md(?=#|$)", ".html", target)
        return f'<a href="{target}">{label}</a>'

    out = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, out)
    return out


def render_markdown(text: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if FENCE.match(line):
            i += 1
            block = []
            while i < len(lines) and not FENCE.match(lines[i]):
                block.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>" + html.escape("\n".join(block)) + "</code></pre>")
            continue
        m = HEADING.match(line)
        if m:
            level = len(m.group(1))
            title = m.group(2).strip()
            out.append(f'<h{level} id="{slug(title)}">{inline(title)}</h{level}>')
            i += 1
            continue
        if line.strip().startswith("|") and i + 1 < len(lines) and TABLE_SEP.match(lines[i + 1].strip()):
            rows = [line]
            i += 1
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(lines[i])
                i += 1
            cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
            head, body = cells[0], cells[2:]
            t = ["<table><thead><tr>"]
            t += [f"<th>{inline(c)}</th>" for c in head]
            t.append("</tr></thead><tbody>")
            for row in body:
                t.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in row) + "</tr>")
            t.append("</tbody></table>")
            out.append("".join(t))
            continue
        if UL.match(line):
            items = []
            while i < len(lines) and UL.match(lines[i]):
                items.append(UL.match(lines[i]).group(1))
                i += 1
            out.append("<ul>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ul>")
            continue
        if OL.match(line):
            items = []
            while i < len(lines) and OL.match(lines[i]):
                items.append(OL.match(lines[i]).group(1))
                i += 1
            out.append("<ol>" + "".join(f"<li>{inline(x)}</li>" for x in items) + "</ol>")
            continue
        if line.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].startswith(">"):
                buf.append(lines[i].lstrip("> ").strip())
                i += 1
            out.append("<blockquote>" + inline(join_lines(buf)) + "</blockquote>")
            continue
        if line.strip() in ("---", "***"):
            out.append("<hr>")
            i += 1
            continue
        if not line.strip():
            i += 1
            continue
        buf = []
        while i < len(lines) and lines[i].strip() and not (
            HEADING.match(lines[i]) or FENCE.match(lines[i]) or UL.match(lines[i])
            or OL.match(lines[i]) or lines[i].startswith(">") or lines[i].startswith("|")
        ):
            buf.append(lines[i].strip())
            i += 1
        out.append("<p>" + inline(join_lines(buf)) + "</p>")
    return "\n".join(out)


CSS = """
:root {
  --bg: #0b0d10;
  --panel: #12161b;
  --edge: #232a33;
  --ink: #d7dde5;
  --muted: #8b96a5;
  --accent: #7dd3fc;
  --accent-2: #a78bfa;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 16px/1.65 ui-sans-serif, system-ui, "Segoe UI", "Noto Sans SC", sans-serif; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
header { border-bottom: 1px solid var(--edge); background: #0e1116; }
.wrap { max-width: 980px; margin: 0 auto; padding: 0 24px; }
.brand { display: flex; align-items: baseline; gap: 12px; padding: 18px 0; }
.brand b { font-size: 18px; letter-spacing: .3px; }
.brand span { color: var(--muted); font-size: 13px; }
nav.top { display: flex; flex-wrap: wrap; gap: 16px; padding: 0 0 14px; font-size: 14px; }
main { padding: 32px 0 64px; }
h1 { font-size: 30px; line-height: 1.25; margin: 0 0 12px; }
h2 { font-size: 21px; margin: 34px 0 10px; color: #e8eef5; }
h3 { font-size: 17px; margin: 26px 0 8px; color: #cbd5e1; }
p, li { color: var(--ink); }
code { background: #1a1f26; border: 1px solid var(--edge); border-radius: 4px;
  padding: 1px 5px; font-size: .9em; }
pre { background: #0f1419; border: 1px solid var(--edge); border-radius: 8px;
  padding: 14px 16px; overflow-x: auto; }
pre code { background: none; border: 0; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 16px 0; font-size: 14px; }
th, td { border: 1px solid var(--edge); padding: 8px 10px; text-align: left; vertical-align: top; }
th { background: #161b22; color: #e6edf3; }
tbody tr:nth-child(even) { background: #10141a; }
blockquote { margin: 16px 0; padding: 10px 16px; border-left: 3px solid var(--accent-2);
  background: #12161b; color: #c3ccd8; }
hr { border: 0; border-top: 1px solid var(--edge); margin: 28px 0; }
.hero { padding: 44px 0 8px; }
.hero p { color: var(--muted); max-width: 720px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin: 22px 0; }
.card { background: var(--panel); border: 1px solid var(--edge); border-radius: 10px; padding: 16px 18px; }
.card h3 { margin: 0 0 6px; font-size: 15px; color: #e8eef5; }
.card p { margin: 0; color: var(--muted); font-size: 14px; }
footer { border-top: 1px solid var(--edge); color: var(--muted); font-size: 13px; padding: 20px 0 40px; }
.badge { display: inline-block; border: 1px solid var(--edge); border-radius: 999px;
  padding: 2px 10px; font-size: 12px; color: var(--muted); margin-right: 8px; }
"""


def page(title: str, body: str, *, home: bool = False) -> str:
    links = "".join(f'<a href="{md[:-3]}.html">{html.escape(en)}</a>' for md, en, _ in PAGES)
    prefix = "" if home else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<link rel="stylesheet" href="{prefix}assets/style.css">
</head>
<body>
<header><div class="wrap">
  <div class="brand"><b>InkBlade</b><span>ML cluster penetration testing platform · v0.2.0 preview</span></div>
  <nav class="top"><a href="index.html">Home</a>{links}</nav>
</div></header>
<main><div class="wrap">
{body}
</div></main>
<footer><div class="wrap">
  InkBlade 0.2.0 preview · Apache-2.0 · authorized testing only · no telemetry, no external assets.
</div></footer>
</body>
</html>
"""


INDEX = """<section class="hero">
<h1>InkBlade <span class="badge">v0.2.0 preview</span></h1>
<p><strong>Authorized pentesting for Kubernetes ML training and inference clusters.</strong>
Consent pinning, level gates, a backup gate for write modules and per-action auditing are enforced
in code. Without a signed record the CLI and the HTTP API refuse to run.</p>
<p>Preview build: scan, evidence and report paths are usable for pilots. The in-pod collector is
moving to the static Rust probe; Python stays the reference until that closes.</p>
</section>

<section>
<h2>Start here</h2>
<pre><code>python -m inkblade doctor            # interpreter, write access, port, optional deps
python -m inkblade pilot --dry-run   # offline rehearsal: profile + plan, no cluster contact
python -m inkblade ui                # local console on 127.0.0.1:8765
python -m inkblade exploit --list    # weapon packs and their deployment requirement</code></pre>
<p>To read a cluster you are allowed to test, run
<code>inkblade pilot --kubeconfig ~/.kube/config</code>. Running a module needs a signed scope first;
<code>inkblade quickstart</code> writes one.</p>
</section>

<section>
<h2>What it covers</h2>
<div class="grid">
  <div class="card"><h3>286 modules, 29 chains</h3><p>Recon, lateral movement, network, privilege,
  code paths, exfiltration, hybrid cloud.</p></div>
  <div class="card"><h3>Three evidence layers</h3><p>Context journal, SQLite audit tables, per-step
  archive with a SHA-256 manifest.</p></div>
  <div class="card"><h3>Bilingual reports</h3><p>PTES narrative and remediation checklist from one
  evidence tree.</p></div>
  <div class="card"><h3>Vulnerability coverage</h3><p>41 primitives, 24 components, affected
  versions; no payloads.</p></div>
</div>
</section>

<section>
<h2>Agent &amp; LLM (optional)</h2>
<p>Scanning, exploitation, evidence and reporting are deterministic and need no model. A model can
rank candidate modules or run inside L3. Both are off by default; with no endpoint the planner keeps
rule order and records the downgrade. L3 needs a signed full-impact RoE, a revocable lead token, an
allowlist and four budget caps. Prompts can carry evidence summaries; the page lists what is sent and
what stays local. <a href="AGENT-LLM.html">Configuration, data boundary, failure modes</a>.</p>
</section>

<section>
<h2>Documentation</h2>
<table><thead><tr><th>Page</th><th>What is in it</th></tr></thead><tbody>
<tr><td><a href="INSTALL.html">Install</a></td><td>Wheel, container, Helm, offline.</td></tr>
<tr><td><a href="USAGE.html">Usage</a></td><td>Commands, workspace, troubleshooting.</td></tr>
<tr><td><a href="FEATURES.html">Features</a></td><td>Verified, simulated, gap.</td></tr>
<tr><td><a href="WORKFLOW.html">Workflow</a></td><td>Eleven stages, gate by gate.</td></tr>
<tr><td><a href="MODULES.html">Modules</a></td><td>Families, levels, chains.</td></tr>
<tr><td><a href="ARCHITECTURE.html">Architecture</a></td><td>Ten coverage layers, seven runtime layers.</td></tr>
<tr><td><a href="AGENT-LLM.html">Agent &amp; LLM</a></td><td>Optional pool, L3, data boundary.</td></tr>
<tr><td><a href="VULNERABILITY-COVERAGE.html">Vulnerability coverage</a></td><td>Components, classes, versions.</td></tr>
<tr><td><a href="PILOT-KIT.html">Pilot kit</a></td><td>Read-only pilot, deliverables.</td></tr>
<tr><td><a href="PLUGIN-SDK.html">Plugin SDK</a></td><td>Manifest, trust, scaffolding.</td></tr>
<tr><td><a href="FAQ.html">FAQ</a></td><td>Short answers.</td></tr>
<tr><td><a href="VERSIONING.html">Versioning</a></td><td>Pre-1.0 policy.</td></tr>
</tbody></table>
</section>

<section>
<h2>中文</h2>
<p>面向 Kubernetes 训练与推理集群的授权渗透测试。授权范围、技术级别、写操作备份与逐动作审计都在代码里强制执行；没有签署记录时，CLI 与 HTTP API 都拒绝执行。</p>
<p>扫描、利用、证据与报告不需要 LLM。模型只给候选排序或在 L3 循环里工作，默认关闭；没有端点时回到规则排序，并把降级写进提议。</p>
<pre><code>python -m inkblade doctor            # 解释器、写权限、端口
python -m inkblade pilot --dry-run   # 离线演练，不连集群
python -m inkblade ui                # 本地控制台 127.0.0.1:8765</code></pre>
<p>有可读集群时用 <code>inkblade pilot --kubeconfig</code>；跑模块前先签授权。</p>
</section>
"""


def build() -> dict[Path, str]:
    files: dict[Path, str] = {}
    files[DOCS / "assets" / "style.css"] = CSS
    files[DOCS / "index.html"] = page("InkBlade — ML cluster penetration testing", INDEX, home=True)
    files[DOCS / ".nojekyll"] = ""
    for md_name, en, _zh in PAGES:
        src = DOCS / md_name
        if not src.is_file():
            continue
        body = render_markdown(src.read_text(encoding="utf-8"))
        files[DOCS / (md_name[:-3] + ".html")] = page(f"{en} — InkBlade", body)
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail if committed output is stale")
    args = ap.parse_args(argv)

    files = build()
    stale = []
    for path, content in files.items():
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current != content:
            stale.append(path.relative_to(ROOT).as_posix())
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="")
    if args.check:
        if stale:
            print("docs site is stale: " + ", ".join(stale), file=sys.stderr)
            return 1
        print("docs site is up to date")
        return 0
    print(f"wrote {len(files)} files ({len(stale)} changed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
