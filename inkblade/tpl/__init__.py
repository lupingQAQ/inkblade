# -*- coding: utf-8 -*-
"""Declarative probe templates: schema, expression language, reference engine.

Public surface::

    from inkblade.tpl import load_template, validate, resolve_probe, execute_template

Production execution is the Rust probe (``inkblade-probe run-template``).
"""
from __future__ import annotations

from .engine import Engine, ProbeError, ReferenceProbe, RESULT_SCHEMA
from .execute import TemplateExecutionError, execute_template, prepare_params
from .expr import ExprError, evaluate, parse, render, render_value, truthy
from .probe import (ProbeFailed, ProbeTransport, ProbeUnavailable, RustProbe,
                    bootstrap_modules, install_probe, is_bootstrap,
                    reference_allowed, resolve_probe, validate_result)
from .schema import (SCHEMA_ID, TemplateError, TemplateMeta, describe,
                     iter_templates, load_template, template_path, validate)

__all__ = [
    "Engine", "ReferenceProbe", "ProbeError", "RESULT_SCHEMA",
    "TemplateExecutionError", "execute_template", "prepare_params",
    "ExprError", "evaluate", "parse", "render", "render_value", "truthy",
    "ProbeFailed", "ProbeTransport", "ProbeUnavailable", "RustProbe",
    "bootstrap_modules", "install_probe", "is_bootstrap", "reference_allowed",
    "resolve_probe", "validate_result",
    "SCHEMA_ID", "TemplateError", "TemplateMeta", "describe", "iter_templates",
    "load_template", "template_path", "validate",
]
