"""用户与工作区：scrypt 口令哈希、角色矩阵、工作区隔离。"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

ROLES = ("admin", "lead", "tester", "auditor")

_ACTION_MATRIX = {
    "execute": {"admin", "lead", "tester"},
    "approve": {"admin", "lead"},
    "approve-zeroday": {"admin", "lead"},
    "report": {"admin", "lead", "tester", "auditor"},
    "read": {"admin", "lead", "tester", "auditor"},
    "manage": {"admin"},
}


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1).hex()


class Session:
    def __init__(self, store: "UserStore", name: str, role: str, workspaces: list[str], token: str):
        self._store = store
        self.name = name
        self.role = role
        self.workspaces = list(workspaces)
        self.token = token
        self.expires_at = time.time() + 8 * 3600

    def can(self, action: str) -> bool:
        return self.role in _ACTION_MATRIX.get(action, set())

    def visible_workspaces(self, root: Path | None = None) -> list[str]:
        if "*" in self.workspaces and root is not None:
            ev = Path(root) / "evidence"
            if ev.exists():
                return sorted(p.name for p in ev.iterdir() if p.is_dir())
            return ["local-lab"]
        return self.workspaces

    def open_store(self, root: Path | str, workspace: str):
        from .evidence import EvidenceStore

        if workspace not in self.visible_workspaces(root=Path(root)):
            raise PermissionError(f"{self.name}({self.role}) 无权访问工作区 {workspace}")
        return EvidenceStore(Path(root), workspace=workspace)


class UserStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._sessions: dict[str, Session] = {}
        if self.path.exists():
            self._users = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self._users: dict = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._users, ensure_ascii=False, indent=2), encoding="utf-8")

    def has(self, name: str) -> bool:
        return name in self._users

    def names(self) -> list[str]:
        return sorted(self._users)

    def role_of(self, name: str) -> str:
        return str((self._users.get(name) or {}).get("role") or "")

    def roles(self) -> dict[str, str]:
        return {name: self.role_of(name) for name in self.names()}

    def create_user(self, name: str, password: str, role: str, workspaces: list[str]) -> None:
        if role not in ROLES:
            raise ValueError(f"未知角色: {role}")
        salt = secrets.token_bytes(16)
        self._users[name] = {
            "salt": salt.hex(),
            "hash": _hash_password(password, salt),
            "role": role,
            "workspaces": list(workspaces),
        }
        self._save()

    def verify(self, name: str, password: str) -> Session | None:
        u = self._users.get(name)
        if not u:
            return None
        salt = bytes.fromhex(u["salt"])
        if not secrets.compare_digest(_hash_password(password, salt), u["hash"]):
            return None
        token = secrets.token_hex(16)
        s = Session(self, name, u["role"], u["workspaces"], token)
        self._sessions[token] = s
        return s

    def session(self, token: str) -> Session | None:
        s = self._sessions.get(token)
        if s and s.expires_at > time.time():
            return s
        return None
