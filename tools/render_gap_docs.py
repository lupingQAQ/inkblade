"""从 docs/gap-matrix.json 渲染三张差距表（功能/攻击面/payload）。可重复执行。"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "gap-matrix.json"
OUT = {
    "features": ROOT / "docs" / "GAP-FEATURES.md",
    "surfaces": ROOT / "docs" / "GAP-ATTACK-SURFACE.md",
    "payloads": ROOT / "docs" / "GAP-PAYLOADS.md",
}
TITLES = {
    "features": "功能缺失全量表（逐工具）",
    "surfaces": "攻击面缺失全量表（逐工具）",
    "payloads": "Payload 缺失全量表（逐工具）",
}


def render(key: str, data: dict) -> str:
    lines = [f"# {TITLES[key]}", "",
             f"来源：docs/gap-matrix.json（生成于 {data.get('generated', '')}）；"
             f"状态口径：{json.dumps(data.get('status_vocab', {}), ensure_ascii=False)}", "",
             "| 工具 | 类别 | 条目 | 来源 | 我们的状态 | 缺失内容 | 行动项 |", "|---|---|---|---|---|---|---|"]
    total = 0
    for tool, block in data.get("tools", {}).items():
        for item in block.get(key, []):
            total += 1
            lines.append(
                f"| {tool} | {block.get('category','')} | {item.get('name','')} "
                f"| {item.get('source','')} | {item.get('status','')} "
                f"| {item.get('missing','') or '-'} | {item.get('action','') or '-'} |"
            )
    lines += ["", f"**总计：{total} 条**（工具 {len(data.get('tools', {}))} 个）", "",
              "## 完备性声明", ""]
    for tool, block in data.get("tools", {}).items():
        v = block.get("verification", {})
        lines.append(f"- {tool}: mode={v.get('mode','?')}, completeness={v.get('completeness','?')}")
    if data.get("skipped"):
        lines += ["", "## 不可核验/不存在的工具", ""]
        for s in data["skipped"]:
            lines.append(f"- {s.get('tool')}: {s.get('reason')}（{s.get('source','')}）")
    return "\n".join(lines) + "\n"


def main() -> int:
    data = json.loads(SRC.read_text(encoding="utf-8"))
    for key, path in OUT.items():
        path.write_text(render(key, data), encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
