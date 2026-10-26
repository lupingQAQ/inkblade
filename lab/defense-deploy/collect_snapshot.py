# -*- coding: utf-8 -*-
"""部署面快照采集：把人工导出的 kubectl 文本清单折叠为 deploy_snapshot JSON。

只读输入目录（人工先用 deploy_products.py 提示的命令导出文本），输出快照 JSON；
本脚本不调用 kubectl、不访问集群。

用法：
    python lab/defense-deploy/collect_snapshot.py --dump-dir out/dump/ --out snapshot.json
"""
import argparse
import json
import re
from pathlib import Path

# 顶层字段归属：行前缀/关键字 → snapshot 键
FIELD_HINTS = [
    ("daemonsets", re.compile(r"daemonset\.?app|/elkeid-agent|ds/", re.I)),
    ("deployments", re.compile(r"deployment\.?app|deploy/", re.I)),
    ("pods", re.compile(r"pod/.+|po/", re.I)),
    ("images", re.compile(r"^\S+/\S+:\S+$")),  # registry/repo:tag
    ("rules", re.compile(r"rule", re.I)),
    ("configs", re.compile(r"configmap|\.conf|\.yaml$|_cfg|config", re.I)),
    ("kernel_modules", re.compile(r"^(?:elkeid|olehid|smith|falco|nvml)\b")),
    ("crds", re.compile(r"[a-z]+s\.[a-z.]+$")),
    ("webhooks", re.compile(r"webhook", re.I)),
    ("agent_status", re.compile(r"^(online|offline|stopped|missing)$", re.I)),
    ("kernel_params", re.compile(r"^lsm=")),
]


def fold_line(line: str, snap: dict) -> None:
    line = line.strip()
    if not line or line.startswith("#"):
        return
    for field, rx in FIELD_HINTS:
        if rx.search(line):
            snap.setdefault(field, [])
            if line not in snap[field]:
                snap[field].append(line)
            return
    snap.setdefault("unmatched", [])
    if line not in snap["unmatched"]:
        snap["unmatched"].append(line)


def main() -> None:
    ap = argparse.ArgumentParser(description="折叠 kubectl 文本 dump 为快照 JSON（只读输入）")
    ap.add_argument("--dump-dir", required=True, help="人工导出的文本清单目录")
    ap.add_argument("--out", required=True, help="输出快照 JSON 路径")
    args = ap.parse_args()
    snap: dict = {"cluster": "kind-inkblade-collected"}
    for p in sorted(Path(args.dump_dir).glob("*.txt")):
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            fold_line(line, snap)
    snap.pop("unmatched", None)
    Path(args.out).write_text(json.dumps(snap, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out} fields={sorted(snap)}")


if __name__ == "__main__":
    main()
