# -*- coding: utf-8 -*-
"""_slurm-common — Slurm/HPC 配置面模块族共享库（仅标准库，只读）。

数据源统一为 ``trident collect files`` 形态的导出目录或一个 JSON 快照：

- ``{"files": {"slurm.conf": "<text>", ...}, "inventory": {...}}``
- 目录：递归读取文本文件为 ``files``，可选 ``inventory.json`` 描述属主/权限/签名。

模块只解析导出内容，不连接 slurmctld/slurmd、不执行 ``scontrol``/``sbatch``，
不读取真实 ``munge.key`` 内容（只看权限/属主/年龄/指纹）。
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from pathlib import Path

SEVS = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVS)}
_TEXT_SUFFIXES = (".conf", ".cnf", ".env", ".json", ".yaml", ".yml", ".txt", ".ini",
                  ".cfg", ".service", ".rules", ".list")
_MAX_READ = 1 << 20


def finding(sev: str, title: str, detail: dict | str = "", *, evidence: str = "",
            mapping: str = "", fix: str = "", **extra) -> dict:
    if sev not in SEVS:
        sev = "info"
    item = {
        "sev": sev,
        "title": title,
        "detail": json.dumps(detail, ensure_ascii=False) if isinstance(detail, dict) else str(detail),
    }
    if evidence:
        item["evidence"] = evidence
    if mapping:
        item["mapping"] = mapping
    if fix:
        item["fix"] = fix
    item.update(extra)
    return item


def summary_json(family: str, findings: list[dict], *, extra: dict | None = None,
                 source: str = "") -> str:
    counts = Counter(f.get("sev", "info") for f in findings)
    top = min((f.get("sev", "info") for f in findings),
              key=lambda s: _SEV_RANK.get(s, len(_SEV_RANK)), default="none")
    payload = {
        "family": family,
        "findings": len(findings),
        "severity": {s: counts[s] for s in SEVS if counts.get(s)},
        "top": top,
        "source": source,
    }
    payload.update(extra or {})
    return json.dumps(payload, ensure_ascii=False)


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_READ:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_snapshot(params: dict) -> dict:
    """加载 dict / JSON 文件 / 导出目录；目录内文件按相对路径小写归一。"""
    raw = params.get("snapshot")
    if raw is None:
        # 允许测试/调用方直接把 slurm 配置放在 params 里；不伪造文件。
        if any(k in params for k in ("files", "slurm", "inventory")):
            return dict(params)
        raise ValueError("缺少 params.snapshot（fixture dict、JSON 快照或配置文件导出目录）")
    if isinstance(raw, dict):
        return raw
    path = Path(str(raw))
    if path.is_dir():
        files: dict[str, str] = {}
        inventory: dict = {}
        for item in sorted(path.rglob("*")):
            if not item.is_file():
                continue
            rel = item.relative_to(path).as_posix()
            if item.name == "inventory.json":
                try:
                    inventory = json.loads(item.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    inventory = {}
                continue
            if item.suffix.lower() in _TEXT_SUFFIXES or item.name in (
                    "slurm.conf", "cgroup.conf", "plugstack.conf", "slurmdbd.conf",
                    "munge.key.meta", "prolog", "epilog"):
                files[rel] = _read_text(item)
        return {"files": files, "inventory": inventory, "root": str(path)}
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    raise ValueError(f"snapshot 不存在：{path}")


# ------------------------------------------------------------------ 文件与配置


def _norm(path: str) -> str:
    return str(path or "").replace("\\", "/").lstrip("./").lower()


def files(snapshot: dict) -> dict[str, str]:
    raw = snapshot.get("files")
    if isinstance(raw, dict):
        return {_norm(k): str(v) for k, v in raw.items()}
    return {}


def find_file(snapshot: dict, *names: str) -> tuple[str, str]:
    """按 basename 或相对路径后缀找第一个文件，返回 (path, text)。"""
    pool = files(snapshot)
    wanted = [_norm(n) for n in names if n]
    for name in wanted:
        if name in pool:
            return name, pool[name]
    for name in wanted:
        for path, text in pool.items():
            if path.endswith("/" + name) or Path(path).name == name:
                return path, text
    return "", ""


def json_file(snapshot: dict, *names: str, default=None):
    path, text = find_file(snapshot, *names)
    if not text:
        return default if default is not None else {}
    try:
        doc = json.loads(text)
    except ValueError:
        return default if default is not None else {}
    return doc


_CONF_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*[=:]\s*(.*?)\s*$")


def parse_conf(text: str) -> dict[str, str]:
    """解析 Slurm ``Key=Value`` 配置；保留首个值，忽略注释与空行。"""
    out: dict[str, str] = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        match = _CONF_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if "#" in value:
            value = value.split("#", 1)[0].strip()
        out.setdefault(key, value)
    return out


def conf(snapshot: dict, *names: str) -> dict[str, str]:
    _, text = find_file(snapshot, *names)
    return parse_conf(text) if text else {}


def get(conf: dict[str, str], key: str, default: str = "") -> str:
    """大小写不敏感读取（Slurm 配置键按官方写法，但导出可能变形）。"""
    if key in conf:
        return conf[key]
    low = key.lower()
    for k, v in conf.items():
        if k.lower() == low:
            return v
    return default


def as_int(value, default: int = 0) -> int:
    try:
        text = str(value).strip().lower()
        if text.endswith("%"):
            text = text[:-1]
        return int(float(text))
    except (TypeError, ValueError):
        return default


def as_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in ("1", "yes", "true", "on", "enabled", "y"):
        return True
    if text in ("0", "no", "false", "off", "disabled", "n"):
        return False
    return default


def is_unlimited(value) -> bool:
    return str(value or "").strip().upper() in ("", "UNLIMITED", "INFINITE", "0", "-1", "NONE")


# ------------------------------------------------------------------ 文件元数据


def inventory(snapshot: dict) -> dict:
    doc = snapshot.get("inventory")
    if isinstance(doc, dict):
        return doc
    nested = snapshot.get("meta")
    return nested if isinstance(nested, dict) else {}


def meta(snapshot: dict, *names: str) -> dict:
    """查 inventory.files 中的权限/属主/签名元数据（按 basename 或后缀匹配）。"""
    inv = inventory(snapshot)
    pool = inv.get("files") if isinstance(inv.get("files"), dict) else inv
    if not isinstance(pool, dict):
        return {}
    wanted = [_norm(n) for n in names if n]
    for name in wanted:
        if name in {_norm(k) for k in pool}:
            for k, v in pool.items():
                if _norm(k) == name:
                    return v if isinstance(v, dict) else {}
    for name in wanted:
        for path, value in pool.items():
            p = _norm(path)
            if p.endswith("/" + name) or Path(p).name == name:
                return value if isinstance(value, dict) else {}
    return {}


def parse_mode(value) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit() and len(text) <= 4:
        return int(text, 8)
    try:
        return int(text, 8)
    except ValueError:
        return None


def world_writable(value) -> bool:
    mode = parse_mode(value)
    return bool(mode is not None and mode & 0o002)


def group_or_world_writable(value) -> bool:
    mode = parse_mode(value)
    return bool(mode is not None and mode & 0o022)


def age_days(value, *, now: float | None = None) -> int | None:
    """mtime 可为 epoch 秒或 ISO 日期。"""
    if value in (None, ""):
        return None
    current = time.time() if now is None else float(now)
    if isinstance(value, (int, float)):
        ts = float(value)
    else:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            ts = float(text)
        except ValueError:
            try:
                import datetime as _dt
                parsed = _dt.datetime.fromisoformat(text)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=_dt.timezone.utc)
                ts = parsed.timestamp()
            except ValueError:
                return None
    return max(0, int((current - ts) / 86400))


def sha256_text(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def mount_list(snapshot: dict, *names: str) -> list[dict]:
    doc = json_file(snapshot, *names, default={"mounts": []})
    if isinstance(doc, list):
        return [m for m in doc if isinstance(m, dict)]
    if isinstance(doc, dict):
        for key in ("mounts", "filesystems", "exports", "clients"):
            value = doc.get(key)
            if isinstance(value, list):
                return [m for m in value if isinstance(m, dict)]
    return []


def node_list(snapshot: dict) -> list[dict]:
    doc = json_file(snapshot, "nodes.json", "sinfo.json", "scontrol-nodes.json",
                    default={"nodes": []})
    if isinstance(doc, list):
        return [n for n in doc if isinstance(n, dict)]
    if isinstance(doc, dict):
        for key in ("nodes", "sinfo"):
            value = doc.get(key)
            if isinstance(value, list):
                return [n for n in value if isinstance(n, dict)]
    return []


def partition_list(snapshot: dict) -> list[dict]:
    doc = json_file(snapshot, "partitions.json", "scontrol-partitions.json",
                    default={"partitions": []})
    if isinstance(doc, list):
        return [p for p in doc if isinstance(p, dict)]
    if isinstance(doc, dict):
        for key in ("partitions", "scontrol"):
            value = doc.get(key)
            if isinstance(value, list):
                return [p for p in value if isinstance(p, dict)]
    return []


# ------------------------------------------------------------------ 输出


def write_artifact(ctx: dict, name: str, payload: dict) -> list[str]:
    run = ctx.get("run") if isinstance(ctx, dict) else None
    if run is None:
        return []
    adir = Path(run.dir) / "artifacts"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return [str(path)]


def result(ctx: dict, key: str, family: str, findings: list[dict], *,
           extra: dict | None = None, source: str = "") -> dict:
    summary = summary_json(family, findings, extra=extra, source=source)
    artifact = write_artifact(ctx, f"{key}.json", {
        "summary": json.loads(summary),
        "findings": findings,
        "note": "只读配置面判定；未连接 Slurm 守护进程，未读取密钥内容。",
    })
    return {"summary": summary, "artifacts": artifact, "findings": findings}


def no_snapshot() -> dict:
    return {"summary": json.dumps({"summary": "no-snapshot"}, ensure_ascii=False),
            "artifacts": [], "findings": []}
