# -*- coding: utf-8 -*-
"""Config / model file export import.

The operator points at a directory exported from a customer environment
(``kubectl cp``, backup, CMDB export).  We record path, size, SHA256 and a
coarse kind; file contents are not copied into the evidence bundle.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

MAX_FILES = 5000
MAX_HASH_BYTES = 64 * 1024 * 1024
_SKIP_DIRS = {".git", ".svn", "__pycache__", "node_modules", ".venv", "venv",
              "site-packages", "dist", "build"}
_CONFIG_EXT = {".yaml", ".yml", ".json", ".toml", ".conf", ".config", ".ini",
               ".env", ".properties", ".xml", ".j2", ".tmpl"}
_MODEL_EXT = {".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".onnx", ".gguf",
              ".h5", ".pkl", ".pickle", ".msgpack", ".npz"}
_CERT_EXT = {".pem", ".crt", ".cer", ".key", ".p12", ".pfx"}


def classify(path: str) -> str:
    low = path.lower().replace("\\", "/")
    ext = Path(low).suffix
    if ext in _MODEL_EXT or any(p in low for p in ("/weights/", "/checkpoint/", "/checkpoints/")):
        return "model-file"
    if ext in _CERT_EXT:
        return "certificate"
    if ext in _CONFIG_EXT or Path(low).name in ("Dockerfile", "Makefile", "kubeconfig"):
        return "config-file"
    if any(p in low for p in ("/bmc/", "/switch/", "/fabric/")):
        return "hardware-export"
    return "other"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    read = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
            read += len(chunk)
            if read >= MAX_HASH_BYTES:
                break
    return h.hexdigest()


def collect(root: str | Path, max_files: int = MAX_FILES) -> dict:
    base = Path(root)
    if not base.exists():
        return {"schema": "trident-files-collection-v1", "status": "unavailable",
                "root": str(base), "files": [], "errors": [f"not found: {base}"]}
    files: list[dict] = []
    errors: list[str] = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".cache")]
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if len(files) >= max_files:
                errors.append(f"truncated at {max_files} files")
                break
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                stat = path.stat()
                rel = str(path.relative_to(base)).replace("\\", "/")
                kind = classify(rel)
                files.append({
                    "path": rel,
                    "kind": kind,
                    "size": stat.st_size,
                    "sha256": _sha256(path) if stat.st_size <= MAX_HASH_BYTES else "",
                    "mtime": int(stat.st_mtime),
                    "source": "collection:files",
                })
            except OSError as exc:
                errors.append(f"{path}: {type(exc).__name__}")
        if len(files) >= max_files:
            break
    kinds: dict[str, int] = {}
    for item in files:
        kinds[item["kind"]] = kinds.get(item["kind"], 0) + 1
    status = "ok" if files or base.exists() else "unavailable"
    return {
        "schema": "trident-files-collection-v1",
        "status": status,
        "root": str(base),
        "files": files,
        "count": len(files),
        "kinds": kinds,
        "errors": errors[:50],
    }
