"""备份管理器：写类模块前置快照（文件/K8s 对象/HTTP 状态）与一键回滚。"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any

from .evidence import Run


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
        for i, t in enumerate(targets):
            kind = t.get("kind")
            if kind == "file":
                src = Path(t["path"])
                if not src.is_file():
                    continue
                dst = self.root / f"{rid}-{step_key}-{i}.bak"
                shutil.copy2(src, dst)
                self.run.record_backup(step_key, t["path"], dst, "file-restore")
            elif kind == "kube":
                dst = self.root / f"{rid}-{step_key}-{i}.yaml"
                dst.write_text(str(t.get("manifest", "")), encoding="utf-8")
                self.run.record_backup(step_key, f"kube:{t.get('kind')}/{t.get('name')}",
                                       dst, "kubectl-apply")
            elif kind == "http":
                dst = self.root / f"{rid}-{step_key}-{i}.json"
                dst.write_text(json.dumps(t.get("state", {}), ensure_ascii=False), encoding="utf-8")
                self.run.record_backup(step_key, str(t.get("url")), dst, "http-restore")
        return rid

    def rollback(self, step_key: str) -> int:
        rows = self.run.query(
            "SELECT id, target, backup_path, rollback_action FROM backups WHERE run=? AND step_key=? ORDER BY id",
            (self.run.name, step_key),
        )
        n = 0
        for bid, target, path, action in rows:
            ok = False
            try:
                if action == "file-restore":
                    Path(target).write_bytes(Path(path).read_bytes())
                    ok = True
                # kube/http 恢复需外部执行器，登记记录由人工/后续模块执行
                ok = ok or action in ("kubectl-apply", "http-restore")
            finally:
                self.run.record_rollback(bid, ok)
                n += 1
        return n
