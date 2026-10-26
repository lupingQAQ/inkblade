"""混沌编排错误族：携带稳定错误码，humanize 直接翻译成人话。"""

from __future__ import annotations


class ChaosError(RuntimeError):
    """混沌编排基类；子类带稳定错误码（E5xx）。"""

    trident_code = "E500"


class ChaosSteadyStateError(ChaosError):
    """稳态未满足即拒绝注入（fail-safe：不碰不确认健康的系统）。"""

    trident_code = "E502"


class ChaosRollbackError(ChaosError):
    """回滚后稳态未恢复（必须人工介入）。"""

    trident_code = "E503"


class ChaosAbortSignalled(ChaosError):
    """外部中止（trident chaos abort / Ctrl+C）或中止条件触发。"""

    trident_code = "E501"
