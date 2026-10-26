import sys, types, importlib.util, importlib.abc, importlib.machinery, importlib
from pathlib import Path

class _Stub(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        value = type(name, (object,), {"__init__": lambda self, *a, **k: None})
        setattr(self, name, value)
        return value

class _StubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        m = _Stub(spec.name); m.__path__ = []; return m
    def exec_module(self, module): pass

class StubFinder(importlib.abc.MetaPathFinder):
    def __init__(self, roots): self.roots = tuple(roots)
    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == r or fullname.startswith(r + ".") for r in self.roots):
            return importlib.machinery.ModuleSpec(fullname, _StubLoader(), is_package=True)
        return None

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

ROOT = Path(r"D:\llm-audit-2026-10\projects\trident-2026-10")
src = ROOT / "lab/upstream_verify/upstream/deepspeedai/DeepSpeed/v0.19.8/deepspeed/runtime/zero/stage3.py"
sys.meta_path.insert(0, StubFinder(["deepspeed"]))
import torch, math
from typing import *
pp = importlib.import_module("deepspeed.runtime.zero.partition_parameters")
for k in dir(torch):
    if not k.startswith("_"): setattr(pp, k, getattr(torch, k))
pp.math = math
m = load(src, "uv_stage3")
print("LOADED", hasattr(m, "DeepSpeedZeroOptimizer_Stage3"))
