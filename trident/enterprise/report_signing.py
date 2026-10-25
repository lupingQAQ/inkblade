# -*- coding: utf-8 -*-
"""报告签核与保留策略：SHA256 + 本机时间戳 + HMAC 签名 + 双人签核清单。

诚实边界：本机时间戳不是可信时间源；生产交付需客户 RFC3161 TSA 或 HSM 时间戳。
``retention_plan`` 只生成计划（keep/archive/purge/hold），不自动删除文件。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Iterable

MANDATORY_SIGNOFF = (
    "scope", "evidence_manifest", "findings_reviewed",
    "fp_fn_reviewed", "data_handling", "rollback_verified",
)


class SignoffError(ValueError):
    """签核清单/签署人/文件状态不满足。"""


def _key(key: str | bytes) -> bytes:
    raw = key.encode("utf-8") if isinstance(key, str) else key
    if len(raw) < 16:
        raise SignoffError("签名密钥至少 16 字节")
    return raw


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sign_report(report: str | Path, *, signer: str, key: str | bytes,
                timestamp: float | None = None, out: str | Path | None = None) -> dict:
    path = Path(report)
    if not path.is_file():
        raise SignoffError(f"报告不存在：{path}")
    if not signer:
        raise SignoffError("signer 必填")
    ts = time.time() if timestamp is None else float(timestamp)
    sha = _sha256_file(path)
    sidecar = {
        "schema": "trident-report-signature/1",
        "path": path.name,
        "sha256": sha,
        "size": path.stat().st_size,
        "signed_at": _iso(ts),
        "timestamp": {
            "source": "local-clock",
            "epoch": int(ts),
            "note": "本机时间戳；生产交付需 RFC3161 TSA 或 HSM 时间戳，不得当作可信时间证明",
        },
        "signer": str(signer),
        "method": "hmac-sha256",
    }
    material = f"{sha}|{sidecar['signed_at']}|{sidecar['signer']}".encode("utf-8")
    sidecar["signature"] = hmac.new(_key(key), material, hashlib.sha256).hexdigest()
    if out is not None:
        target = Path(out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(sidecar, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return sidecar


def verify_report(report: str | Path, sidecar: dict, key: str | bytes) -> dict:
    path = Path(report)
    if not path.is_file():
        return {"ok": False, "reason": "报告不存在"}
    if not isinstance(sidecar, dict):
        return {"ok": False, "reason": "sidecar 非 object"}
    sha = _sha256_file(path)
    if sha != sidecar.get("sha256"):
        return {"ok": False, "reason": "报告哈希不一致（被修改或替换）"}
    if sidecar.get("size") != path.stat().st_size:
        return {"ok": False, "reason": "报告大小不一致"}
    material = f"{sidecar.get('sha256')}|{sidecar.get('signed_at')}|{sidecar.get('signer')}"
    expect = hmac.new(_key(key), material.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(sidecar.get("signature") or ""), expect):
        return {"ok": False, "reason": "签名校验失败"}
    return {"ok": True, "sha256": sha, "signer": sidecar.get("signer"),
            "signed_at": sidecar.get("signed_at")}


def create_signoff(report: str | Path, *, signers: Iterable[dict], checklist: dict,
                   key: str | bytes, timestamp: float | None = None,
                   required_roles=("lead", "security-owner"),
                   out: str | Path | None = None) -> dict:
    path = Path(report)
    if not path.is_file():
        raise SignoffError(f"报告不存在：{path}")
    missing = [item for item in MANDATORY_SIGNOFF if checklist.get(item) is not True]
    if missing:
        raise SignoffError("签核项未完成：" + ", ".join(missing))
    signers = list(signers or [])
    names = [str(s.get("name") or "") for s in signers]
    roles = [str(s.get("role") or "") for s in signers]
    if any(not n for n in names):
        raise SignoffError("签署人 name 必填")
    if len(set(names)) != len(names):
        raise SignoffError("签署人重复")
    for role in required_roles:
        if role not in roles:
            raise SignoffError(f"缺少必需签署角色：{role}")
    ts = time.time() if timestamp is None else float(timestamp)
    sha = _sha256_file(path)
    sheet = {
        "schema": "trident-report-signoff/1",
        "signoff_id": "so-" + sha[:12],
        "report": path.name,
        "sha256": sha,
        "size": path.stat().st_size,
        "status": "signed",
        "signed_at": _iso(ts),
        "timestamp": {"source": "local-clock", "epoch": int(ts),
                      "note": "生产签核需 RFC3161/HSM 时间戳"},
        "checklist": {item: True for item in MANDATORY_SIGNOFF},
        "signers": [{"name": str(s.get("name")), "role": str(s.get("role")),
                     "signed_at": _iso(ts)} for s in signers],
    }
    material = f"{sha}|{_canonical(sheet['signers'])}|{sheet['signed_at']}".encode("utf-8")
    sheet["signature"] = hmac.new(_key(key), material, hashlib.sha256).hexdigest()
    if out is not None:
        target = Path(out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(sheet, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return sheet


def retention_plan(files: Iterable[str | Path], *, now: float | None = None,
                   retain_days: int = 365, archive_days: int = 180,
                   legal_hold: bool = False) -> dict:
    """生成保留计划；legal_hold 时全部 hold，绝不 purge。"""
    if retain_days <= 0:
        raise SignoffError("retain_days 必须 > 0")
    ts = time.time() if now is None else float(now)
    actions = []
    for item in files:
        path = Path(item)
        if not path.exists():
            actions.append({"path": str(path), "action": "missing", "age_days": None})
            continue
        age_days = max(0.0, (ts - path.stat().st_mtime) / 86400.0)
        if legal_hold:
            action = "hold"
        elif age_days > retain_days:
            action = "purge"
        elif age_days > archive_days:
            action = "archive"
        else:
            action = "keep"
        actions.append({"path": str(path), "action": action,
                        "age_days": round(age_days, 1),
                        "size": path.stat().st_size})
    return {
        "schema": "trident-retention-plan/1",
        "generated_at": _iso(ts),
        "retain_days": int(retain_days),
        "archive_days": int(archive_days),
        "legal_hold": bool(legal_hold),
        "actions": actions,
        "note": ("Legal hold 生效：仅保留/归档，不执行 purge"
                 if legal_hold else "本计划不自动删除；purge 需客户书面批准与双人复核"),
    }
