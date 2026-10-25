"""备份管理器：写类模块前置快照（文件/K8s 对象/HTTP 状态）与一键回滚。

回滚状态语义（终审 Important#2，不再"假成功"）：

- ``restored``   ：文件已按快照字节还原（唯一会写 ``rollbacks.ok=1`` 的状态）；
- ``pending``    ：kube/http 恢复需外部执行器（kubectl / HTTP 客户端），只登记待办；
- ``unsupported``：未知回滚动作，本平台无执行器；
- ``failed``     ：动作已知但执行失败（快照丢失/写入异常），需人工介入。

每次 rollback 同时落 ``backups/rollback-<step>.json`` 明细回执，供 CLI/API/人工消费。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .evidence import Run

# 需外部执行器的回滚动作 → (状态, 明细模板)
_EXTERNAL_ACTIONS = {
    "kubectl-apply": ("pending", "需外部执行器：kubectl apply -f {path}（对象将回到快照 manifest）"),
    "http-restore": ("pending", "需外部执行器：按备份状态重放 HTTP 恢复请求（状态快照 {path}）"),
}


class BackupManager:
    def __init__(self, store, run: Run):
        self.store = store
        self.run = run
        self.root = run.dir / "backups"
        self.root.mkdir(exist_ok=True)

    def snapshot(self, step_key: str, targets: list[dict[str, Any]]) -> int | None:
        """对全部 targets 建快照；targets 为空返回 None（调用方必须视为无回执）。"""
        if not targets:
            return None
        rid = int(time.time() * 1000) % 10 ** 9
        snapshotted = 0
        for i, t in enumerate(targets):
            kind = t.get("kind")
            if kind == "file":
                src = Path(t["path"])
                if not src.is_file():
                    continue
                dst = self.root / f"{rid}-{step_key}-{i}.bak"
                shutil.copy2(src, dst)
                self.run.record_backup(step_key, t["path"], dst, "file-restore")
                snapshotted += 1
            elif kind == "kube":
                dst = self.root / f"{rid}-{step_key}-{i}.yaml"
                dst.write_text(str(t.get("manifest", "")), encoding="utf-8")
                self.run.record_backup(step_key, f"kube:{t.get('kind')}/{t.get('name')}",
                                       dst, "kubectl-apply")
                snapshotted += 1
            elif kind == "http":
                dst = self.root / f"{rid}-{step_key}-{i}.json"
                dst.write_text(json.dumps(t.get("state", {}), ensure_ascii=False), encoding="utf-8")
                self.run.record_backup(step_key, str(t.get("url")), dst, "http-restore")
                snapshotted += 1
        return rid if snapshotted else None

    def rollback(self, step_key: str) -> dict[str, Any]:
        """按 backups 表逐条回滚；返回明细（attempted/restored/pending/unsupported/failed + items）。"""
        rows = self.run.query(
            "SELECT id, target, backup_path, rollback_action, sha256 FROM backups"
            " WHERE run=? AND step_key=? ORDER BY id",
            (self.run.name, step_key),
        )
        items: list[dict[str, Any]] = []
        for bid, target, path, action, expected_sha in rows:
            state, detail = self._apply(target, path, action, expected_sha)
            ok = state == "restored"
            self.run.record_rollback(bid, ok)
            items.append({
                "backup_id": bid, "target": target, "action": action,
                "backup_path": path, "state": state, "detail": detail,
            })

        counts = Counter(i["state"] for i in items)
        receipt = {
            "step_key": step_key,
            "run": self.run.name,
            "generated_at": time.time(),
            "attempted": len(items),
            "restored": counts.get("restored", 0),
            "pending": counts.get("pending", 0),
            "unsupported": counts.get("unsupported", 0),
            "failed": counts.get("failed", 0),
            "items": items,
        }
        receipt_path = self.root / f"rollback-{self._safe(step_key)}.json"
        receipt["receipt"] = str(receipt_path)
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
        return receipt

    @staticmethod
    def _safe(step_key: str) -> str:
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(step_key))

    @staticmethod
    def _apply(target: str, path: str, action: str, expected_sha: str | None) -> tuple[str, str]:
        if action == "file-restore":
            src = Path(path)
            if not src.is_file():
                return "failed", f"备份快照缺失：{path}"
            try:
                data = src.read_bytes()
                if expected_sha:
                    got = hashlib.sha256(data).hexdigest()
                    if got != expected_sha:
                        return "failed", f"快照 sha256 失配（期望 {expected_sha[:12]}…，实际 {got[:12]}…）"
                Path(target).write_bytes(data)
                return "restored", f"已按快照还原（sha256 {expected_sha[:12] + '…' if expected_sha else '未登记'}）"
            except OSError as exc:  # 权限/磁盘/路径
                return "failed", f"还原失败：{exc}"
        if action in _EXTERNAL_ACTIONS:
            state, tmpl = _EXTERNAL_ACTIONS[action]
            return state, tmpl.format(path=path)
        return "unsupported", f"未知回滚动作 {action!r}：本平台无对应执行器"
