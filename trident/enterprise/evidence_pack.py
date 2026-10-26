# -*- coding: utf-8 -*-
"""合规审计证据包（ER-57）：manifest + 控制项索引 + 可校验 zip。

不是认证结论：框架映射为工程归类，客户模板/评审仍需在客户环境完成。
"""

from __future__ import annotations

import hashlib
import json
import time
import zipfile
from pathlib import Path

SCHEMA = "trident-evidence-pack/1"

# 等保 2.0（GB/T 22239-2019）三级安全计算环境 + ISO/IEC 27001:2022 附录 A。
CONTROLS = {
    "djbh": [
        {"id": "8.1.4.1", "title": "身份鉴别", "globs": ["*auth*", "*oidc*", "*ldap*", "*consent*"]},
        {"id": "8.1.4.2", "title": "访问控制", "globs": ["*rbac*", "*approval*", "*policy*"]},
        {"id": "8.1.4.3", "title": "安全审计", "globs": ["*audit*", "*siem*", "*evidence*", "*manifest*"]},
        {"id": "8.1.4.4", "title": "入侵防范", "globs": ["*finding*", "*report*", "*rules*", "*poc*"]},
        {"id": "8.1.4.5", "title": "恶意代码防范", "globs": ["*scan*", "*supply*", "*sbom*", "*attest*"]},
        {"id": "8.1.4.6", "title": "可信验证", "globs": ["*sign*", "*hash*", "*provenance*", "*tee*"]},
        {"id": "8.1.4.7", "title": "数据备份恢复", "globs": ["*backup*", "*rollback*", "*retention*"]},
    ],
    "iso27001": [
        {"id": "A.5.15", "title": "访问控制", "globs": ["*rbac*", "*approval*", "*policy*"]},
        {"id": "A.8.8", "title": "技术脆弱性管理", "globs": ["*finding*", "*cve*", "*report*"]},
        {"id": "A.8.15", "title": "日志记录", "globs": ["*audit*", "*log*", "*siem*"]},
        {"id": "A.8.16", "title": "监视活动", "globs": ["*monitor*", "*metrics*", "*alert*"]},
        {"id": "A.5.7", "title": "威胁情报", "globs": ["*intel*", "*corpus*", "*threat*"]},
        {"id": "A.8.9", "title": "配置管理", "globs": ["*config*", "*baseline*", "*drift*"]},
        {"id": "A.8.32", "title": "变更管理", "globs": ["*calendar*", "*freeze*", "*approval*"]},
    ],
}


class EvidencePackError(ValueError):
    """证据包参数/校验失败。"""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect(paths: list[str | Path], root: Path) -> list[dict]:
    out = []
    for item in paths:
        path = Path(item)
        candidates = sorted(path.rglob("*")) if path.is_dir() else [path]
        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink():
                continue
            if any(part in ("__pycache__", ".git") for part in candidate.parts):
                continue
            try:
                rel = candidate.relative_to(root).as_posix()
            except ValueError:
                rel = candidate.name
            out.append({"path": rel, "source": str(candidate),
                        "size": candidate.stat().st_size, "sha256": _sha256(candidate)})
    return sorted(out, key=lambda x: x["path"])


def _match_control(entry: str, globs: list[str]) -> bool:
    low = entry.lower()
    for pattern in globs:
        needle = pattern.strip("*").lower()
        if needle and needle in low:
            return True
    return False


def build_pack(paths: list[str | Path], out_zip: str | Path, *, root: str | Path | None = None,
               framework: str = "djbh", meta: dict | None = None,
               now: float | None = None) -> dict:
    if framework not in CONTROLS:
        raise EvidencePackError(f"未知框架 {framework!r}; 支持 {', '.join(CONTROLS)}")
    root_path = Path(root).resolve() if root else Path.cwd().resolve()
    out = Path(out_zip)
    files = _collect(paths, root_path)
    if not files:
        raise EvidencePackError("没有可打包的证据文件")
    ts = time.time() if now is None else float(now)
    controls = []
    for control in CONTROLS[framework]:
        hits = [f["path"] for f in files if _match_control(f["path"], control["globs"])]
        controls.append({**control, "evidence": hits, "covered": bool(hits)})
    manifest = {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "framework": framework,
        "root": str(root_path),
        "files": files,
        "controls": controls,
        "meta": meta or {},
        "note": "工程归类，不是合规认证；客户模板/评审需在客户环境完成。",
    }
    index = ["# 审计证据包索引", "",
             f"- 框架：{framework}",
             f"- 生成时间：{manifest['generated_at']}",
             f"- 文件数：{len(files)}",
             "", "| 控制项 | 标题 | 证据数 | 证据 |", "|---|---|---:|---|"]
    for control in controls:
        index.append(f"| {control['id']} | {control['title']} | {len(control['evidence'])} | "
                     + (", ".join(control["evidence"][:5]) or "—") + " |")
    index += ["", "本索引由 Trident 生成；证据哈希见 manifest.json。"]
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        zf.writestr("index.md", "\n".join(index) + "\n")
        for entry in files:
            zf.write(entry["source"], arcname="evidence/" + entry["path"])
    return {"schema": SCHEMA, "path": str(out), "files": len(files),
            "controls": len(controls), "covered": sum(1 for c in controls if c["covered"]),
            "framework": framework, "manifest_sha256": hashlib.sha256(
                json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()}


def verify_pack(zip_path: str | Path) -> dict:
    path = Path(zip_path)
    if not path.is_file():
        raise EvidencePackError(f"证据包不存在：{path}")
    with zipfile.ZipFile(path) as zf:
        try:
            manifest = json.loads(zf.read("manifest.json"))
        except KeyError as exc:
            raise EvidencePackError("缺少 manifest.json") from exc
        mismatched, missing = [], []
        for entry in manifest.get("files") or []:
            name = "evidence/" + entry["path"]
            try:
                raw = zf.read(name)
            except KeyError:
                missing.append(entry["path"])
                continue
            actual = hashlib.sha256(raw).hexdigest()
            if actual != entry["sha256"]:
                mismatched.append({"path": entry["path"], "expected": entry["sha256"],
                                   "actual": actual})
        ok = not mismatched and not missing
        return {"ok": ok, "files": len(manifest.get("files") or []),
                "mismatched": mismatched, "missing": missing,
                "framework": manifest.get("framework"),
                "controls": len(manifest.get("controls") or [])}
