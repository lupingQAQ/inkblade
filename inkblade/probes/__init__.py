"""inkblade/probes — LLM 探针库（garak/PyRIT/promptfoo 对标 + 独有长上下文/KV/缓存/网关面）。

公共入口：
- load_probes()               探针库（≥80 探针 / 13 类，键=文件名=纯小写）
- CATEGORIES / FACES / DETECTOR_KINDS / SEVERITIES   分类学与契约常量
- evaluate_detector(...)      判定器引擎（正则/语义关键词/长度/拒绝检测/状态码/JSON 字段）
- run.run_matrix(...)         两态差分运行器（lab/ai_gateway_sim、mock_targets、longctx_sim）
- matrix.render_matrix_section(...)  「LLM 探针矩阵」报告节
"""
from __future__ import annotations

from .framework import (
    CATEGORIES,
    CATEGORY_ORDER,
    DETECTOR_KINDS,
    DetectorError,
    FACES,
    LIBRARY_DIR,
    ProbeValidationError,
    REFUSAL_MARKERS,
    SEVERITIES,
    evaluate_detector,
    evaluate_on_entry,
    load_probes,
    validate_probe,
    verdict_of,
)

__all__ = [
    "CATEGORIES", "CATEGORY_ORDER", "DETECTOR_KINDS", "FACES", "SEVERITIES",
    "LIBRARY_DIR", "REFUSAL_MARKERS",
    "DetectorError", "ProbeValidationError",
    "evaluate_detector", "evaluate_on_entry", "load_probes", "validate_probe", "verdict_of",
]
