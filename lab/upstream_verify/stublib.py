"""Function-level loader for verbatim upstream modules.

The host used by this archive is a Windows workstation without CUDA, without a
C++ toolchain and without a Kubernetes runtime, so most of the audited packages
cannot be ``pip install``-ed or imported as a whole.  That must not degrade the
evidence to "static only": the *file under test* is the verbatim pinned upstream
file, the *sink* inside it is real, and the third-party library the sink calls
(``torch``, ``aiohttp``, ``transformers``, ...) is the real installed one.

Only the surrounding package tree - modules that are on no path between the
attacker-controlled input and the sink - is replaced by inert stubs.  A stub
module hands out placeholder classes on attribute access so that ``import``s,
base classes, decorators and type annotations still resolve.  Every stub is
recorded in the evidence so a reviewer can see exactly what was *not* real.

Two subtleties are handled explicitly:

``from pkg.mod import *``
    A stub has no ``__all__``, so ``import *`` copies nothing and names that the
    real module leaks into its importer (``torch`` itself, ``Tensor``,
    ``instrument_w_nvtx``, ...) disappear.  :func:`leaked_module_globals` reads
    the upstream file's symbol table to find the names it references but never
    binds, and :meth:`StubTree.seed` installs them on the star-import source.

``super().__init__()``
    Never reached: cases build the object with ``object.__new__`` and call only
    the vulnerable method, exactly like the existing verified vLLM cases.
"""

from __future__ import annotations

import builtins
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import symtable
import sys
import types
from pathlib import Path

__all__ = [
    "StubModule",
    "StubTree",
    "load_upstream_file",
    "leaked_module_globals",
]


class _Any:
    """Chainable placeholder used for enum members, attributes and call results."""

    __slots__ = ("_label",)

    def __init__(self, label: str):
        self._label = label

    def __repr__(self) -> str:
        return f"<stub {self._label}>"

    def __call__(self, *args, **kwargs):
        return _Any(f"{self._label}()")

    def __getattr__(self, item: str):
        if item.startswith("__"):
            raise AttributeError(item)
        return _Any(f"{self._label}.{item}")

    def __iter__(self):
        return iter(())

    def __bool__(self) -> bool:
        return False


class _StubMeta(type):
    def __getattr__(cls, item: str):
        if item.startswith("__"):
            raise AttributeError(item)
        return _Any(f"{cls.__name__}.{item}")


def _placeholder(name: str) -> type:
    value = _StubMeta(
        name,
        (object,),
        {
            "__init__": lambda self, *a, **k: None,
            "__call__": lambda self, *a, **k: self,
            "__iter__": lambda self: iter(()),
            "__bool__": lambda self: False,
        },
    )
    value.__module__ = "stub"
    return value


class StubModule(types.ModuleType):
    """Inert stand-in for a module outside the vulnerability path."""

    def __getattr__(self, name: str):
        if name.startswith("__"):
            raise AttributeError(name)
        value = _placeholder(name)
        setattr(self, name, value)
        return value


class _StubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        module = StubModule(spec.name)
        module.__path__ = []
        return module

    def exec_module(self, module):  # nothing to execute
        return None


class _StubFinder(importlib.abc.MetaPathFinder):
    def __init__(self, roots: tuple[str, ...]):
        self.roots = roots

    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == root or fullname.startswith(root + ".") for root in self.roots):
            return importlib.machinery.ModuleSpec(fullname, _StubLoader(), is_package=True)
        return None


class StubTree:
    """Install a stub package tree and load one real file out of it."""

    def __init__(self, roots: list[str]):
        self.roots = tuple(roots)
        self._finder = _StubFinder(self.roots)
        self.stubbed: list[str] = []

    def install(self) -> "StubTree":
        sys.meta_path.insert(0, self._finder)
        for root in self.roots:
            importlib.import_module(root)
            self.stubbed.append(root)
        return self

    def seed(self, dotted: str, **attrs) -> types.ModuleType:
        """Give a stub module real attributes (star-import and annotation leaks)."""
        module = importlib.import_module(dotted)
        for name, value in attrs.items():
            setattr(module, name, value)
        return module

    def seed_leaks(self, dotted: str, upstream: str | Path, namespace: dict | None = None) -> list[str]:
        """Seed names the upstream file reads but never binds (`import *` leakage)."""
        module = importlib.import_module(dotted)
        names = leaked_module_globals(upstream, namespace or vars(builtins))
        for name in names:
            if name in module.__dict__:
                continue
            setattr(module, name, _placeholder(name))
        return names

    def load(self, upstream: str | Path, module_name: str) -> types.ModuleType:
        module = load_upstream_file(upstream, module_name)
        self.stubbed.append(module_name + " (real upstream file)")
        return module

    def uninstall(self) -> None:
        if self._finder in sys.meta_path:
            sys.meta_path.remove(self._finder)

    def manifest(self) -> dict:
        return {"stubbed_modules": sorted(self.stubbed)}


def load_upstream_file(upstream: str | Path, module_name: str) -> types.ModuleType:
    """Execute the verbatim upstream file as ``module_name``."""
    path = Path(upstream)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load upstream file: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _bound_locally(table: symtable.SymbolTable) -> set[str]:
    return {
        symbol.get_name()
        for symbol in table.get_symbols()
        if symbol.is_assigned() or symbol.is_imported() or symbol.is_parameter() or symbol.is_namespace()
    }


def _walk(table: symtable.SymbolTable):
    yield table
    for child in table.get_children():
        yield from _walk(child)


def leaked_module_globals(upstream: str | Path, namespace: dict | None = None) -> list[str]:
    """Names a module reads but never binds itself.

    These are the names that arrive in the real package through a
    ``from somewhere import *`` statement (``partition_parameters`` re-exports
    ``torch``, ``Tensor``, ``instrument_w_nvtx``, ...).  When ``somewhere`` is
    stubbed the names vanish, so the loader must re-inject them.
    """
    source = Path(upstream).read_text(encoding="utf-8", errors="replace")
    module_table = symtable.symtable(source, str(upstream), "exec")
    bound = _bound_locally(module_table)
    ns = namespace or vars(builtins)
    leaked: set[str] = set()
    for table in _walk(module_table):
        for symbol in table.get_symbols():
            name = symbol.get_name()
            if name.startswith("__") or name in ns or name in bound:
                continue
            if symbol.is_assigned() or symbol.is_imported() or symbol.is_parameter():
                continue
            if symbol.is_global() and symbol.is_referenced():
                leaked.add(name)
    return sorted(leaked)
