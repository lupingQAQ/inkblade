# -*- coding: utf-8 -*-
"""CVE 适用性工作流：只读环境清单 + 版本/前置/实测三件套判定。"""

from .inventory import (  # noqa: F401
    SCHEMA as INVENTORY_SCHEMA,
    InventoryError,
    collect_inventory,
    default_inventory_path,
    inventory_from_snapshot,
    inventory_summary,
    load_inventory,
    load_probes,
    merge_probes,
    normalize_inventory,
    save_inventory,
)

__all__ = [
    "INVENTORY_SCHEMA",
    "InventoryError",
    "collect_inventory",
    "default_inventory_path",
    "inventory_from_snapshot",
    "inventory_summary",
    "load_inventory",
    "load_probes",
    "merge_probes",
    "normalize_inventory",
    "save_inventory",
]
