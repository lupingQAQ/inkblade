import sys
from pathlib import Path

ROOT = Path(r"D:\llm-audit-2026-10\projects\trident-2026-10")
sys.path.insert(0, str(ROOT / "lab" / "upstream_verify"))
from stublib import StubTree, leaked_module_globals  # noqa: E402

src = ROOT / "lab/upstream_verify/upstream/deepspeedai/DeepSpeed/v0.19.8/deepspeed/runtime/zero/stage3.py"
print("leaked:", leaked_module_globals(src))

tree = StubTree(["deepspeed"]).install()
import torch, math  # noqa: E402

pp = tree.seed("deepspeed.runtime.zero.partition_parameters", torch=torch, math=math)
for name in dir(torch):
    if not name.startswith("_"):
        setattr(pp, name, getattr(torch, name))
pp.Tensor = torch.Tensor
tree.seed_leaks("deepspeed.runtime.zero.partition_parameters", src)
mod = tree.load(src, "uv_stage3")
print("LOADED", hasattr(mod, "DeepSpeedZeroOptimizer_Stage3"))
