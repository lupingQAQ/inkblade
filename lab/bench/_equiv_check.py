"""一次性对照：改动前后侦察模块在同输入上的 findings 必须逐条一致（开发期校验，不参与测试发现）。

用法：python lab/bench/_equiv_check.py [--ref 128dfd4]
（`--ref` 默认取优化前最后一个提交；用 HEAD 会对比到已优化版本，失去对照意义。）
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULES = ("metadata-egress", "network-policy-coverage", "ray-control-plane")
SNAPSHOTS = ("lab/fixtures/recon/cluster-snapshot.json", "lab/fixtures/recon/cluster-clean.json")


def load(path: Path):
    spec = spec_from_file_location(f"equiv_{path.parent.name}_{path.stem}", path)
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default="128dfd4", help="对比基线 git ref（默认=优化前最后一个提交）")
    args = parser.parse_args()
    failures = 0
    with tempfile.TemporaryDirectory(prefix="inkblade-equiv-") as tmp:
        for key in MODULES:
            rel = f"inkblade/modules/{key}/run.py"
            old_dir = Path(tmp) / key
            old_dir.mkdir(parents=True)
            old_src = subprocess.run(["git", "show", f"{args.ref}:{rel}"], cwd=ROOT,
                                     capture_output=True, check=True).stdout
            old_path = old_dir / "run.py"
            old_path.write_bytes(old_src)
            # 旧模块按文件位置找 _recon-common：补一个指向真实 modules 目录的同级路径
            (old_dir.parent / "_recon-common.py").write_bytes(
                (ROOT / "inkblade" / "modules" / "_recon-common.py").read_bytes())
            old_mod = load(old_path)
            new_mod = load(ROOT / rel)
            for snap_rel in SNAPSHOTS:
                snap = json.loads((ROOT / snap_rel).read_text(encoding="utf-8"))
                old_out = old_mod.run({}, {"snapshot": snap})
                new_out = new_mod.run({}, {"snapshot": snap})
                same = json.dumps(old_out, ensure_ascii=False, sort_keys=True) == \
                    json.dumps(new_out, ensure_ascii=False, sort_keys=True)
                print(f"{'OK ' if same else 'DIFF'} {key} / {Path(snap_rel).name}: "
                      f"{len(old_out['findings'])} vs {len(new_out['findings'])} findings")
                if not same:
                    failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
