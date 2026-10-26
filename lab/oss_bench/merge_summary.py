"""Rebuild reports/samples/oss-bench/summary.json from per-tool JSONs.

Used when benches were run in --only batches: the summary merge only knows
files written in its own process, so a crash between batches can drop results
whose per-tool JSONs are already on disk.
"""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path

OUT = Path(r"D:\llm-audit-2026-10\projects\trident-2026-10\reports\samples\oss-bench")

per_tool = {}
for path in sorted(OUT.glob("*.json")):
    if path.name == "summary.json":
        continue
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and data.get("tool"):
        per_tool[data["tool"]] = data

summary = {
    "schema": "trident.oss-bench/1",
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "host": {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "note": "host timings; guest (QEMU TCG) timings marked per tool",
    },
    "results": sorted(per_tool.values(), key=lambda r: (r.get("category", ""), r.get("tool", ""))),
}
(OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(f"rebuilt summary with {len(per_tool)} results:", sorted(per_tool))
