"""Import alias for the hyphenated ``lab/fabric-sim`` lab directory.

Python 包名不能含 ``-``；本包把 ``lab/fabric-sim`` 加入 ``__path__``，使
``from lab.fabric_sim.sim import simulate`` 可用，同时保留用户要求的目录名。
"""
from pathlib import Path

_IMPL = Path(__file__).resolve().parent.parent / "fabric-sim"
if _IMPL.is_dir() and str(_IMPL) not in __path__:
    __path__.append(str(_IMPL))
