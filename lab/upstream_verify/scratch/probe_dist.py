import sys
from pathlib import Path

ROOT = Path(r"D:\llm-audit-2026-10\projects\trident-2026-10")
sys.path.insert(0, str(ROOT / "lab/upstream_verify"))
from stublib import StubTree  # noqa: E402

src = ROOT / "lab/upstream_verify/upstream/deepspeedai/DeepSpeed/v0.19.8/deepspeed/runtime/zero/stage3.py"

tree = StubTree(["deepspeed"]).install()
import torch  # noqa: E402

partition = tree.seed("deepspeed.runtime.zero.partition_parameters", torch=torch)
for name in dir(torch):
    if not name.startswith("_"):
        partition.__dict__.setdefault(name, getattr(torch, name))
tree.seed_leaks("deepspeed.runtime.zero.partition_parameters", src)
tree.seed("deepspeed.comm", get_rank=lambda group=None: 0, get_world_size=lambda group=None: 1)
module = tree.load(src, "uv_stage3")
print("dist =", module.dist, type(module.dist))
print("os =", module.os, type(module.os))
print("math =", module.math, type(module.math))
print("deepspeed.comm in sys.modules:", "deepspeed.comm" in sys.modules)
print("deepspeed attr comm:", getattr(sys.modules["deepspeed"], "comm", "MISSING"))
