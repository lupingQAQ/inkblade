# -*- coding: utf-8 -*-
"""证据保留/删除执行（ER-27）：dry-run 默认，执行需双人角色 + legal hold 覆盖。

安全边界：
- 只处理 root 目录内、非符号链接的普通文件；
- purge 记录 sha256/size 到 audit JSONL，保留审计线索；
- archive 移动文件并写 manifest；
- legal_hold 时全部 hold，绝不 purge；
- 默认 execute=False，任何删除都必须显式传入 lead + security-owner。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path

REQUIRED_APPROVALS = ("lead", "security-owner")


class RetentionError(ValueError):
    """保留策略参数/路径/审批不满足。"""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def apply_retention(plan: dict, *, root: str | Path, execute: bool = False,
                    approvals: tuple[str, ...] | list[str] = (),
                    archive_dir: str | Path | None = None,
                    audit_path: str | Path | None = None,
                    legal_hold: bool = False,
                    now: float | None = None) -> dict:
    if not isinstance(plan, dict) or not isinstance(plan.get("actions"), list):
        raise RetentionError("plan 必须是 retention_plan 输出")
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise RetentionError(f"root 不是目录：{root}")
    hold = bool(legal_hold or plan.get("legal_hold"))
    archive = Path(archive_dir).resolve() if archive_dir else root_path / "_archive"
    if archive_dir and not _inside(root_path, archive):
        raise RetentionError("archive_dir 必须位于 root 内")
    audit = Path(audit_path) if audit_path else root_path / "retention-audit.jsonl"
    if not _inside(root_path, audit):
        raise RetentionError("audit_path 必须位于 root 内")
    approved = {str(a) for a in approvals}
    if execute and not hold and not set(REQUIRED_APPROVALS) <= approved:
        raise RetentionError("执行 purge 需要 lead + security-owner 双角色审批")

    actions: list[dict] = []
    counts = {"keep": 0, "archive": 0, "purge": 0, "hold": 0, "missing": 0, "skipped": 0}
    ts = time.time() if now is None else float(now)
    for item in plan["actions"]:
        raw = str(item.get("path") or "")
        path = Path(raw)
        candidate = path if path.is_absolute() else root_path / path
        action = str(item.get("action") or "keep")
        row = {"path": str(candidate), "action": action, "executed": False}
        if action == "missing" or not candidate.exists():
            row["action"] = "missing"
            counts["missing"] += 1
            actions.append(row)
            continue
        if not _inside(root_path, candidate):
            if execute:
                raise RetentionError(f"拒绝处理 root 外路径：{candidate}")
            row.update(action="skipped", reason="outside-root")
            counts["skipped"] += 1
            actions.append(row)
            continue
        if candidate.is_symlink() or not candidate.is_file():
            row.update(action="skipped", reason="not-regular-file")
            counts["skipped"] += 1
            actions.append(row)
            continue
        if hold or action == "hold":
            row["action"] = "hold"
            counts["hold"] += 1
            actions.append(row)
            continue
        if action == "keep":
            counts["keep"] += 1
            actions.append(row)
            continue
        if action == "archive":
            if not execute:
                row["reason"] = "dry-run"
                counts["archive"] += 1
                actions.append(row)
                continue
            rel = candidate.relative_to(root_path)
            target = archive / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                target = target.with_name(target.name + f".{int(ts)}")
            shutil.move(str(candidate), str(target))
            row.update(action="archive", executed=True, archived_to=str(target))
            counts["archive"] += 1
            actions.append(row)
            continue
        if action == "purge":
            if not execute:
                row["reason"] = "dry-run"
                counts["purge"] += 1
                actions.append(row)
                continue
            digest, size = _sha256(candidate), candidate.stat().st_size
            candidate.unlink()
            row.update(action="purge", executed=True, sha256=digest, size=size)
            counts["purge"] += 1
            actions.append(row)
            continue
        row.update(action="skipped", reason=f"unknown-action:{action}")
        counts["skipped"] += 1
        actions.append(row)

    if execute:
        audit.parent.mkdir(parents=True, exist_ok=True)
        record = {"schema": "trident-retention-execution/1", "at": ts,
                  "root": str(root_path), "legal_hold": hold,
                  "approvals": sorted(approved), "counts": counts, "actions": actions}
        with audit.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return {
        "schema": "trident-retention-execution/1",
        "execute": bool(execute),
        "legal_hold": hold,
        "approvals": sorted(approved),
        "counts": counts,
        "actions": actions,
        "audit_path": str(audit) if execute else "",
        "note": "dry-run；未删除任何文件" if not execute else "已按审批执行并写审计 JSONL",
    }
