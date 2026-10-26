# -*- coding: utf-8 -*-
"""KubeTrail 移植（最小闭环）：in-pod 采集 / token 审计 / 三态脱敏 / manifest 云密钥扫描 /
LPE 启发式 / 持久化检测。

来源与许可：
- 上游 ``ekkoo-z/KubeTrail``（Apache-2.0，见仓库 NOTICE 与 ``docs/KUBETRAIL-PORT.md``）；
- 本包为 **独立重写**（Python/标准库，控制台侧只读分析），仅移植采集维度与检查语义，
  不含上游 Go 代码；所有检测为启发式/版本区间判定，不包含利用原语。
"""

from . import collector, lpe, manifestscan, persistence, redact3, token_audit  # noqa: F401

__all__ = ["collector", "lpe", "manifestscan", "persistence", "redact3", "token_audit"]
