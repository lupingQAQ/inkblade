import sys
import types
from pathlib import Path

ROOT = Path(r"D:\llm-audit-2026-10\projects\trident-2026-10")
sys.path.insert(0, str(ROOT / "lab" / "upstream_verify"))
from stublib import StubTree, StubModule  # noqa: E402

tree = StubTree(["megatron"]).install()
import megatron.core.dist_checkpointing.strategies.async_utils as au  # noqa: E402

obj = au._disable_gc
print("obj", repr(obj), type(obj), callable(obj))
print("try call:", end=" ")
try:
    print(obj())
except Exception as exc:
    print("ERR", type(exc).__name__, exc)

m = StubModule("probe_mod")
print("module getattr:", repr(m.something), callable(m.something))
