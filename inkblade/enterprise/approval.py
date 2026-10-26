# -*- coding: utf-8 -*-
"""多级审批链：lead → 安全负责人（双签开关），哈希链 + 时间戳。

设计：
- 默认 ``require_dual=True``：lead 先签，security-owner 后签；顺序不可颠倒；
- 同一人不能签两次、申请人不能自签、过期/已决策不可再签；
- 每条签名带 ``prev_hash`` 与 ``chain_hash``，最终 ``decision_sha256`` 覆盖签名链；
- ``verify`` 重算整条链，文件被改（含只改 approver 不重算）即失败；
- 单签开关仅用于只读/低风险试点，必须在 ROE 中显式登记（调用方负责）。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class ApprovalError(ValueError):
    """审批状态/角色/顺序/时效非法。"""


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _path_of(store_or_path) -> Path:
    if hasattr(store_or_path, "ws_dir"):
        return Path(store_or_path.ws_dir) / "approvals.json"
    return Path(store_or_path)


class ApprovalChain:
    def __init__(self, store_or_path, *, require_dual: bool = True,
                 ttl: int = 86400, now=lambda: time.time()):
        self.path = _path_of(store_or_path)
        self.require_dual = bool(require_dual)
        self.ttl = int(ttl)
        self._now = now
        self.required_roles = ["lead", "security-owner"] if self.require_dual else ["lead"]
        self._doc = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                doc = json.loads(self.path.read_text(encoding="utf-8"))
            except ValueError:
                raise ApprovalError(f"审批文件损坏：{self.path}")
            if isinstance(doc, dict) and isinstance(doc.get("approvals"), list):
                return doc
        return {"schema": "trident-approval-chain/1", "approvals": []}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(self._doc, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def _find(self, approval_id: str) -> dict:
        for item in self._doc["approvals"]:
            if item.get("id") == approval_id:
                return item
        raise ApprovalError(f"审批不存在：{approval_id}")

    def request(self, action: str, *, requester: str, run: str = "", risk: str = "high",
                metadata: dict | None = None) -> dict:
        if not action or not requester:
            raise ApprovalError("action/requester 必填")
        now = self._now()
        item = {
            "id": f"apr-{len(self._doc['approvals']) + 1:04d}-{uuid.uuid4().hex[:6]}",
            "action": str(action)[:300], "run": str(run), "risk": str(risk),
            "requester": str(requester), "status": "pending",
            "created_at": now, "expires_at": now + self.ttl,
            "required_roles": list(self.required_roles),
            "signatures": [], "metadata": metadata or {},
        }
        self._doc["approvals"].append(item)
        self._save()
        return dict(item)

    def sign(self, approval_id: str, *, approver: str, role: str, comment: str = "") -> dict:
        item = self._find(approval_id)
        now = self._now()
        if item["status"] != "pending":
            raise ApprovalError(f"审批已决策：{item['status']}")
        if now > float(item["expires_at"]):
            item["status"] = "expired"
            self._save()
            raise ApprovalError("审批已过期")
        if not approver:
            raise ApprovalError("approver 必填")
        if approver == item["requester"]:
            raise ApprovalError("申请人不能自签")
        if any(s.get("approver") == approver for s in item["signatures"]):
            raise ApprovalError("同一人不能重复签署")
        done_roles = [s.get("role") for s in item["signatures"]]
        if role not in item["required_roles"]:
            raise ApprovalError(f"角色 {role} 不在必需签署人 {item['required_roles']}")
        if role in done_roles:
            raise ApprovalError(f"角色 {role} 已签署")
        expected = item["required_roles"][len(item["signatures"])]
        if role != expected:
            raise ApprovalError(f"签署顺序错误：下一步应为 {expected}，收到 {role}")
        prev = item["signatures"][-1]["chain_hash"] if item["signatures"] else GENESIS
        signature = {
            "approver": str(approver), "role": role, "comment": str(comment)[:500],
            "at": now, "prev_hash": prev,
        }
        signature["chain_hash"] = _sha(prev + _canonical({k: v for k, v in signature.items()
                                                          if k != "chain_hash"}))
        item["signatures"].append(signature)
        if len(item["signatures"]) == len(item["required_roles"]):
            item["status"] = "approved"
            item["decided_at"] = now
            item["decision_sha256"] = _sha(_canonical({
                "id": item["id"], "action": item["action"], "run": item["run"],
                "requester": item["requester"], "signatures": item["signatures"],
            }))
        self._save()
        return dict(item)

    def reject(self, approval_id: str, *, approver: str, role: str, reason: str = "") -> dict:
        item = self._find(approval_id)
        if role not in item["required_roles"]:
            raise ApprovalError(f"角色 {role} 无拒绝权限")
        if item["status"] != "pending":
            raise ApprovalError(f"审批已决策：{item['status']}")
        item["status"] = "rejected"
        item["decided_at"] = self._now()
        item["rejected_by"] = {"approver": approver, "role": role, "reason": str(reason)[:500]}
        self._save()
        return dict(item)

    def get(self, approval_id: str) -> dict:
        return dict(self._find(approval_id))

    def list(self, *, status: str | None = None) -> list[dict]:
        items = [dict(i) for i in self._doc["approvals"]]
        if status:
            items = [i for i in items if i.get("status") == status]
        return items

    def verify(self, approval_id: str) -> dict:
        try:
            item = self._find(approval_id)
        except ApprovalError as exc:
            return {"ok": False, "reason": str(exc)}
        prev = GENESIS
        seen: set[str] = set()
        for idx, sig in enumerate(item.get("signatures") or []):
            if sig.get("approver") in seen:
                return {"ok": False, "reason": "重复签署人"}
            seen.add(str(sig.get("approver")))
            if sig.get("approver") == item.get("requester"):
                return {"ok": False, "reason": "申请人自签"}
            if sig.get("role") != item["required_roles"][idx]:
                return {"ok": False, "reason": "签署顺序/角色异常"}
            if sig.get("prev_hash") != prev:
                return {"ok": False, "reason": "prev_hash 不连续"}
            base = {k: v for k, v in sig.items() if k != "chain_hash"}
            expect = _sha(prev + _canonical(base))
            if sig.get("chain_hash") != expect:
                return {"ok": False, "reason": "chain_hash 校验失败"}
            prev = expect
        if item.get("status") == "approved" and len(seen) != len(item["required_roles"]):
            return {"ok": False, "reason": "approved 但签署人不足"}
        if item.get("status") == "approved":
            expect_decision = _sha(_canonical({
                "id": item["id"], "action": item["action"], "run": item["run"],
                "requester": item["requester"], "signatures": item["signatures"],
            }))
            if item.get("decision_sha256") != expect_decision:
                return {"ok": False, "reason": "decision_sha256 校验失败"}
        return {"ok": True, "status": item.get("status"), "chain_sha256": prev,
                "required_roles": list(item["required_roles"]),
                "signatures": len(seen)}
