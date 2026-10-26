# -*- coding: utf-8 -*-
"""vLLM/SGLang patch-difference matrix and five-surface differential fuzzer.

The matrix is a snapshot of public advisories plus explicitly-labelled lab-only
interface rows.  The fuzzer generates 240 deterministic cases across the five
operator-visible surfaces: admin, plugin, dev-mode, serialization and weights.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from .common import hash_payload

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "corpus" / "depth" / "vllm_patch_matrix.json"
TIMEOUT = 4

SURFACES = {
    "admin": {"path": "/admin/config", "method": "GET", "control": "/v1/models"},
    "plugin": {"path": "/plugins/list", "method": "GET", "control": "/v1/models"},
    "dev-mode": {"path": "/dev/exec", "method": "POST", "control": "/v1/models"},
    "serialization": {"path": "/update_weights_from_tensor", "method": "POST",
                      "control": "/v1/models"},
    "weights": {"path": "/pull_weights", "method": "GET", "control": "/v1/models"},
}

TRANSFORMS = (
    "plain",
    "trailing_slash",
    "upper_case",
    "percent_encoded",
    "double_slash",
    "dot_segment",
    "semicolon",
    "query_override",
    "encoded_slash",
    "forwarded_header",
    "method_override",
    "space_suffix",
)

AUTH = ("anon", "low", "wrong", "admin")


def load_matrix(path: Path | str | None = None) -> dict:
    p = Path(path) if path else MATRIX
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema") != "inkblade-vllm-patch-matrix-v1":
        raise ValueError(f"unexpected matrix schema: {data.get('schema')!r}")
    seen: set[str] = set()
    for entry in data["entries"]:
        for field in ("id", "component", "title", "affected", "surface", "patch",
                      "detection", "source"):
            if not entry.get(field):
                raise ValueError(f"{entry.get('id', '?')}: missing {field}")
        if entry["surface"] not in data["surfaces"]:
            raise ValueError(f"{entry['id']}: unknown surface {entry['surface']}")
        if entry["id"] in seen:
            raise ValueError(f"duplicate matrix id {entry['id']}")
        seen.add(entry["id"])
        if entry.get("fixed") is None and not entry.get("fixed_note", "").strip():
            raise ValueError(f"{entry['id']}: fixed=null requires fixed_note")
    return data


def entries(path: Path | str | None = None) -> list[dict]:
    return list(load_matrix(path)["entries"])


def version_in_range(version: str, spec: str) -> bool:
    """Evaluate a conservative version range expression.

    Supports comma-separated AND clauses and operators >=, <=, >, <, ==, =.
    ``All versions...`` is treated as ``*``.  Malformed versions fail closed.
    """
    text = str(spec or "").strip()
    if not text or text.lower().startswith("all versions") or text == "*":
        return True
    for clause in re.split(r"\s*,\s*", text):
        clause = clause.strip()
        if not clause:
            continue
        clause = clause.replace("=<", "<=").replace("=>", ">=")
        match = re.match(r"^(>=|<=|==|=|>|<)\s*(.+)$", clause)
        op, raw = (match.group(1), match.group(2)) if match else ("==", clause)
        got, ref = _vtuple(version), _vtuple(raw)
        if got is None or ref is None:
            return False
        width = max(len(got), len(ref))
        got += (0,) * (width - len(got))
        ref += (0,) * (width - len(ref))
        ok = {"<": got < ref, "<=": got <= ref, ">": got > ref,
              ">=": got >= ref, "==": got == ref, "=": got == ref}[op]
        if not ok:
            return False
    return True


def _vtuple(value: str) -> tuple[int, ...] | None:
    text = str(value or "").strip().lower().lstrip("v")
    if not text:
        return None
    # Numeric components only; rc/post suffixes become an extra numeric
    # component so 0.11.0rc2 sorts after 0.11.0 while 0.10.9 stays below it.
    nums = re.findall(r"\d+", text)
    if not nums:
        return None
    try:
        return tuple(int(n) for n in nums[:4])
    except ValueError:
        return None


def _fixed_version(entry: dict) -> str | None:
    fixed = entry.get("fixed")
    if not fixed:
        return None
    return str(fixed).strip().lstrip(">=").strip()


def is_fixed(version: str, entry: dict) -> bool:
    fixed = _fixed_version(entry)
    if fixed is None:
        return False
    got, ref = _vtuple(version), _vtuple(fixed)
    if got is None or ref is None:
        return False
    width = max(len(got), len(ref))
    return got + (0,) * (width - len(got)) >= ref + (0,) * (width - len(ref))


def assess_version(component: str, version: str,
                   matrix: Path | str | None = None) -> list[dict]:
    out: list[dict] = []
    for entry in entries(matrix):
        if entry["component"] != component:
            continue
        if not version_in_range(version, entry["affected"]):
            continue
        if is_fixed(version, entry):
            continue
        out.append(entry)
    return out


def _apply_transform(spec: dict, transform: str) -> tuple[str, str, dict]:
    path, method = spec["path"], spec["method"]
    headers: dict[str, str] = {}
    if transform == "trailing_slash":
        path += "/"
    elif transform == "upper_case":
        path = path.upper()
    elif transform == "percent_encoded":
        path = path.replace("a", "%61", 1) if "a" in path else path.replace("e", "%65", 1)
    elif transform == "double_slash":
        path = "/" + path
    elif transform == "dot_segment":
        path = path.replace("/", "/./", 1)
    elif transform == "semicolon":
        path += ";.json"
    elif transform == "query_override":
        path += "?path=/v1/models&next=/health"
    elif transform == "encoded_slash":
        path = path.replace("/", "%2f", 1)
    elif transform == "forwarded_header":
        headers["X-Forwarded-User"] = "admin"
        headers["X-Original-URL"] = spec["path"]
    elif transform == "method_override":
        headers["X-HTTP-Method-Override"] = "GET"
    elif transform == "space_suffix":
        path += "%20"
    return path, method, headers


def fuzz_cases() -> list[dict]:
    cases: list[dict] = []
    for surface, spec in SURFACES.items():
        for auth in AUTH:
            headers = {}
            if auth == "admin":
                headers["Authorization"] = "Bearer admin-token"
            elif auth == "low":
                headers["Authorization"] = "Bearer sk-low"
            elif auth == "wrong":
                headers["Authorization"] = "Bearer wrong-key"
            for transform in TRANSFORMS:
                path, method, extra = _apply_transform(spec, transform)
                case_headers = {**headers, **extra}
                body = {"probe": "INKBLADE-DEPTH"} if method == "POST" else None
                cases.append({
                    "id": f"vllm-{surface}-{auth}-{transform}",
                    "surface": surface,
                    "interface": surface,
                    "auth": auth,
                    "transform": transform,
                    "method": method,
                    "path": path,
                    "headers": case_headers,
                    "body": body,
                })
    return cases


def _http(base: str, method: str, path: str, headers: dict | None = None,
          body=None, timeout: int = TIMEOUT) -> dict:
    url = base.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except Exception as exc:  # noqa: BLE001
        return {"status": 0, "error": f"{type(exc).__name__}: {exc}"}
    text = raw.decode("utf-8", "replace")
    try:
        payload = json.loads(text)
    except ValueError:
        payload = text
    return {"status": status, "response": payload}


class SurfaceFuzzer:
    """Run all 240 cases and compute an auth differential against /v1/models."""

    def __init__(self, base_url: str, timeout: int = TIMEOUT):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def control(self) -> int:
        return int(_http(self.base, "GET", "/v1/models", timeout=self.timeout).get("status") or 0)

    def run(self) -> dict:
        control = self.control()
        results: list[dict] = []
        surfaces: dict[str, dict] = {}
        for case in fuzz_cases():
            got = _http(self.base, case["method"], case["path"],
                        headers=case["headers"], body=case["body"], timeout=self.timeout)
            status = int(got.get("status") or 0)
            bypass = status == 200 and control in (401, 403) and case["auth"] != "admin"
            row = {
                "id": case["id"], "surface": case["surface"], "auth": case["auth"],
                "transform": case["transform"], "status": status,
                "bypass": bool(bypass), "control_status": control,
            }
            results.append(row)
            bucket = surfaces.setdefault(case["surface"], {
                "surface": case["surface"], "cases": 0, "bypasses": 0,
                "statuses": {}, "transforms": set(),
            })
            bucket["cases"] += 1
            bucket["bypasses"] += int(bypass)
            bucket["statuses"][str(status)] = bucket["statuses"].get(str(status), 0) + 1
            if bypass:
                bucket["transforms"].add(case["transform"])
        for bucket in surfaces.values():
            bucket["transforms"] = sorted(bucket["transforms"])
        bypasses = sum(1 for r in results if r["bypass"])
        return {
            "total": len(results),
            "cases": len(results),
            "bypasses": bypasses,
            "control_status": control,
            "surfaces": surfaces,
            "surfaces_hit": sorted(k for k, v in surfaces.items() if v["bypasses"]),
            "examples": [r for r in results if r["bypass"]][:8],
            "results_sha256": hash_payload(results),
            "results": results,
        }

    def run_summary(self) -> dict:
        full = self.run()
        full.pop("results", None)
        return full
