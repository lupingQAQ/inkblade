import sys
import types
from pathlib import Path

ROOT = Path(r"D:\llm-audit-2026-10\projects\trident-2026-10")
sys.path.insert(0, str(ROOT / "lab" / "upstream_verify"))
from stublib import StubModule  # noqa: E402

cache = ROOT / "lab/upstream_verify/.cache/megatron-core_v0.19.2"
sys.path.insert(0, str(cache))

import torch  # noqa: E402  (real torch first, before any triton shim)

# Only pre-empt the modules that hard-require triton; the rest of Megatron is real.
for name in [
    "triton",
    "triton.language",
    "megatron.core.transformer.moe.ops.paged_stash",
]:
    if name in sys.modules:
        continue
    mod = StubModule(name)
    mod.__path__ = []
    sys.modules[name] = mod
    parent, _, child = name.rpartition(".")
    if parent and parent in sys.modules:
        setattr(sys.modules[parent], child, mod)

import megatron.training.checkpointing as c  # noqa: E402

print("OK", c.__file__)
print("has _load_base_checkpoint", hasattr(c, "_load_base_checkpoint"))
