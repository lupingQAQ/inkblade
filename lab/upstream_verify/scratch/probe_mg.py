import sys
from pathlib import Path

ROOT = Path(r"D:\llm-audit-2026-10\projects\trident-2026-10")
sys.path.insert(0, str(ROOT / "lab" / "upstream_verify"))
from stublib import StubTree  # noqa: E402

cache = ROOT / "lab/upstream_verify/.cache/megatron-core_v0.19.2"
sys.path.insert(0, str(cache))
tree = StubTree(["triton", "transformer_engine", "apex", "flash_attn"]).install()
import megatron.training.checkpointing as c  # noqa: E402

print("OK", c.__file__)
print("sink lines", [n for n in dir(c) if n.startswith("_load_base")])
