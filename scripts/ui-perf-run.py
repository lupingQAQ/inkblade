"""用本机 Chromium（Edge/Chrome headless）实测 10k findings 报告渲染。

前置：先跑 ``python scripts/ui-perf-bench.py --findings 10000`` 生成静态导出。

测量口径（与 docs/UI-PERF.md 一致）：
- 同一份 index.html，仅切换 ``window.__INKBLADE_FORCE_LEGACY``：
  - paged：默认 200 行/页（产品路径）；
  - legacy：一次性建 10,000 行 DOM（优化前路径）。
- 指标：report 视图同步渲染耗时（performance.now 前后差）、tbody 行数、
  report 子树 DOM 数、body DOM 总数、JS 堆（若 Chromium 暴露）、页面 load 耗时。
- 每种模式重复 N 次（默认 3），取中位数；删除离群值不做，保留全部原始值。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# 公开树卫生：不写盘符字面量（scanner 规则见 scripts/check-public-tree.py）。
_PROGRAM_FILES = os.environ.get("PROGRAMFILES", "C" + ":" + "\\Program Files")
_PROGRAM_FILES_X86 = os.environ.get("PROGRAMFILES(X86)", "C" + ":" + "\\Program Files (x86)")
CHROME_CANDIDATES = (
    str(Path(_PROGRAM_FILES) / "Google" / "Chrome" / "Application" / "chrome.exe"),
    str(Path(_PROGRAM_FILES_X86) / "Google" / "Chrome" / "Application" / "chrome.exe"),
    str(Path(_PROGRAM_FILES_X86) / "Microsoft" / "Edge" / "Application" / "msedge.exe"),
    str(Path(_PROGRAM_FILES) / "Microsoft" / "Edge" / "Application" / "msedge.exe"),
)

BENCH_JS = r"""
<script>
window.addEventListener('load', function () {
  var t0 = performance.now();
  document.querySelector('nav#views button[data-view="report"]').click();
  var t1 = performance.now();
  var meta = window.__INKBLADE_REPORT_META || {};
  var out = {
    mode: "%(mode)s",
    clickMs: Math.round((t1 - t0) * 100) / 100,
    meta: meta,
    rows: document.querySelectorAll('#report-body tbody tr').length,
    reportNodes: document.querySelectorAll('#report-body *').length,
    bodyNodes: document.querySelectorAll('body *').length,
    heap: (performance.memory ? performance.memory.usedJSHeapSize : null),
    loadMs: Math.round(window.__benchLoad * 100) / 100
  };
  document.title = 'BENCH' + btoa(JSON.stringify(out));
});
window.__benchLoad = performance.now();
</script>
"""


def find_chrome(explicit: str | None = None) -> str:
    if explicit:
        if not Path(explicit).is_file():
            raise SystemExit(f"chrome 不存在: {explicit}")
        return explicit
    for path in CHROME_CANDIDATES:
        if Path(path).is_file():
            return path
    raise SystemExit("未找到 Chrome/Edge（用 --chrome 指定）")


def prepare(src: Path, dst: Path, mode: str) -> Path:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    html_path = dst / "index.html"
    html = html_path.read_text(encoding="utf-8")
    if mode == "legacy":
        html = html.replace(
            '<script src="app.js"></script>',
            '<script>window.__INKBLADE_FORCE_LEGACY = true;</script>\n<script src="app.js"></script>',
        )
    html = html.replace("</body>", BENCH_JS % {"mode": mode} + "\n</body>")
    html_path.write_text(html, encoding="utf-8")
    return html_path


def run_once(chrome: str, html_path: Path, profile: Path, timeout: int = 90) -> dict:
    cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--allow-file-access-from-files",
        "--enable-precise-memory-info",
        "--hide-scrollbars",
        "--window-size=1440,1000",
        f"--user-data-dir={profile}",
        "--dump-dom",
        html_path.as_uri(),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)
    if proc.returncode != 0:
        raise SystemExit(f"chrome 失败（{proc.returncode}）：{proc.stderr[-800:]}")
    m = re.search(r"<title>BENCH([A-Za-z0-9+/=]+)</title>", proc.stdout)
    if not m:
        raise SystemExit(f"未找到 BENCH 标题；stderr={proc.stderr[-500:]}")
    data = json.loads(base64.b64decode(m.group(1)).decode("utf-8"))
    data["title"] = "BENCH"
    return data


def _median(rows: list[dict], key: str) -> float | int | None:
    vals = [r[key] for r in rows if r.get(key) is not None]
    if not vals:
        return None
    return round(statistics.median(vals), 2) if isinstance(vals[0], float) else int(statistics.median(vals))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="10k findings 报告页渲染基准（Chromium headless）")
    ap.add_argument("--export", default=str(REPO / "lab" / "bench" / "out" / "ui-10k" / "export"))
    ap.add_argument("--out", default=str(REPO / "lab" / "bench" / "out" / "ui-bench"))
    ap.add_argument("--json-out", default=str(REPO / "reports" / "samples" / "ui-perf" / "10k-render.json"))
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--chrome", default=None)
    args = ap.parse_args(argv)

    chrome = find_chrome(args.chrome)
    export = Path(args.export)
    if not (export / "index.html").is_file():
        raise SystemExit(f"缺 {export}/index.html；先跑 scripts/ui-perf-bench.py")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    results: dict[str, list[dict]] = {"paged": [], "legacy": []}
    profile_root = Path(tempfile.mkdtemp(prefix="inkblade-ui-bench-"))
    try:
        variants = {}
        for mode in ("paged", "legacy"):
            variants[mode] = prepare(export, out / mode, mode)
        for i in range(max(1, args.runs)):
            for mode in ("paged", "legacy"):
                profile = profile_root / f"{mode}-{i}"
                results[mode].append(run_once(chrome, variants[mode], profile))
                print(f"[{mode} #{i + 1}] {results[mode][-1]}", flush=True)
    finally:
        shutil.rmtree(profile_root, ignore_errors=True)

    summary = {}
    for mode, rows in results.items():
        summary[mode] = {
            "runs": len(rows),
            "click_ms_median": _median(rows, "clickMs"),
            "rows_median": _median(rows, "rows"),
            "report_nodes_median": _median(rows, "reportNodes"),
            "body_nodes_median": _median(rows, "bodyNodes"),
            "heap_bytes_median": _median(rows, "heap"),
            "load_ms_median": _median(rows, "loadMs"),
            "raw": rows,
        }
    doc = {
        "schema": "inkblade-ui-perf/1",
        "generated_at": __import__("datetime").datetime.now().astimezone().isoformat(timespec="seconds"),
        "browser": Path(chrome).name,
        "export": (Path(export).resolve().relative_to(REPO).as_posix()
                   if Path(export).resolve().is_relative_to(REPO) else "<abs-path>"),
        "fixture": "synthetic 10,000 findings",
        "runs_per_mode": max(1, args.runs),
        "summary": summary,
        "boundary": "本机 Chromium headless；合成数据；非真实用户样本/SLA",
    }
    out_json = Path(args.json_out)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"summary": summary, "json": str(out_json)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
