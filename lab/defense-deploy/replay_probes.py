# -*- coding: utf-8 -*-
"""良性探针重放准备器：物化 benign marker 到授权 scratch 目录并生成重放清单文本。

安全边界（硬约束）：
- 探针全部为技术类别级 benign marker（INKBLADE-BENIGN 前缀），不含恶意载荷；
- 物化只能写 --scratch 目录（引擎 ProbeContainmentError 强制，越界即拒）；
- 本脚本不执行任何重放动作，仅输出 replay.txt 供人工在授权实验室逐条执行。

用法：
    python lab/defense-deploy/replay_probes.py --product elkeid --scratch out/scratch
"""
import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from inkblade.core import defenseprobe as dp  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="良性探针物化与重放清单生成（不执行）")
    ap.add_argument("--product", required=True, choices=sorted(dp.PRODUCT_SPECS))
    ap.add_argument("--scratch", required=True, help="授权 scratch 目录（探针物化唯一落点）")
    args = ap.parse_args()

    probes = dp.benign_probes(args.product)
    problems = dp.audit_benign(probes)
    if problems:
        print("BENIGN AUDIT FAILED:", file=sys.stderr)
        for p in problems:
            print(" -", p, file=sys.stderr)
        sys.exit(2)

    root = Path(args.scratch).resolve()
    files = dp.materialize_probes(probes, root)

    lines = [
        f"# INKBLADE benign replay plan: {args.product}",
        f"# marker 前缀 {dp.SAFE_MARKER_PREFIX}；全部为良性探针；人工于授权实验室执行",
        "",
    ]
    for p in probes:
        lines.append(f"## {p['technique']} ({p['category']})")
        lines.append(f"action: {p['action']}")
        if p.get("exec_template"):
            lines.append(f"exec: {p['exec_template'].replace('{scratch}', str(root))}")
        if p.get("request_template"):
            lines.append(f"request: {p['request_template']}")
        if p.get("sample_name"):
            lines.append(f"image-sample: {p['sample_name']}（内容=benign marker 文件）")
        lines.append("")
    plan = root / f"replay-{args.product}.txt"
    plan.parent.mkdir(parents=True, exist_ok=True)
    plan.write_text("\n".join(lines), encoding="utf-8")
    print(f"materialized {len(files)} benign markers under {root}")
    print(f"replay plan: {plan} (NOT executed)")


if __name__ == "__main__":
    main()
