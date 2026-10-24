"""规则转化引擎 + 紫队验证（架构第七层）。

- generate.generate_all(chains_dir, findings, cni, out_dir) -> RulePack
- validate.validate(pack_dir, mock_base) -> CoverageMatrix（dict）
"""

from .generate import RulePack, RuleCoverageError, generate_all, load_catalog
from .validate import validate

__all__ = ["RulePack", "RuleCoverageError", "generate_all", "load_catalog", "validate"]
