# -*- coding: utf-8 -*-
"""Research-depth audit primitives.

Each submodule is deliberately independent of live infrastructure: it consumes
a snapshot/fixture, applies a small semantic engine, and returns evidence that
can be replayed in unit tests and in ``trident verify-effects``.
"""

from __future__ import annotations

__all__ = ["admission", "common", "ebpf", "fabric", "gpu", "identity", "vllm"]
