"""报告引擎子包：双语渲染 + CVSS 3.1 + 术语表 + 标准条款映射 + 修复基线库。"""

from . import cvss
from .render import render_pentest, render_remediation

__all__ = ["cvss", "render_pentest", "render_remediation"]
