# -*- coding: utf-8 -*-
"""模型供应链与机密计算（本地 fixture 驱动，标准库实现）。

三块能力：
1. **AI SBOM**：CycloneDX 1.5 ML-BOM 风格 JSON（模型/权重 SHA-256/来源/dataset/license）；
2. **模型签名与 provenance**：cosign 风格的 bundle（artifact/source/builder 三元组）+
   本地 trust root；签名算法在 fixture 中使用 HMAC-SHA256（明确标注，不是 production
   sigstore keyless，后者列在 docs/SOTA-2026-10.md 的未达成项）；
3. **TEE 证明核验**：TDX / SEV-SNP / NVIDIA Confidential Computing attestation fixture
   解析 + 策略断言（nonce 新鲜度、report_data 绑定模型哈希、launch measurement 白名单、
   debug 关闭、TCB 状态、GPU CC 模式、签名）。

所有密钥/证明都是 **本地 fixture**，不得用于生产信任决策。
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

TOOL_NAME = "trident"
TOOL_VERSION = "0.1.0"
CYCLONEDX_SPEC = "1.5"
SUPPORTED_TEES = ("tdx", "sev-snp", "nvidia-cc")
_HMAC_ALG = "HMAC-SHA256"

_DATA = Path(__file__).resolve().parent / "data" / "supplychain"
_ATTEST_DIR = _DATA / "attestations"
_POLICY_PATH = _DATA / "policy.json"


# ---------------------------------------------------------------- 基础工具

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _json_dump(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _norm_sha(value: str) -> str:
    text = str(value).strip().lower()
    if text.startswith("sha256:"):
        text = text[7:]
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError(f"非法 SHA-256: {value!r}")
    return text


def _read_json(path: Path | str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"文件不存在: {path}") from exc
    except ValueError as exc:
        raise ValueError(f"JSON 无法解析: {path}: {exc}") from exc


def _load(path: Path | str) -> dict:
    return _read_json(path)


def _write_json(path: Path | str | None, payload: dict) -> None:
    if path is None:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- 1) AI SBOM

def _license_entry(value: str) -> dict:
    text = str(value).strip()
    if not text:
        raise ValueError("license 不能为空")
    return {"license": {"id": text}} if " " not in text and "/" not in text else {
        "license": {"name": text}
    }


def _model_hash(model: dict, root: Path) -> str:
    path = model.get("path")
    explicit = model.get("sha256")
    computed = None
    if path:
        file_path = (root / str(path)).resolve()
        try:
            file_path.relative_to(root.resolve())
        except ValueError as exc:
            raise ValueError(f"模型路径越界（必须位于 root 内）: {path}") from exc
        if not file_path.is_file():
            raise ValueError(f"权重文件不存在: {path}")
        computed = sha256_file(file_path)
    if explicit and computed and _norm_sha(explicit) != computed:
        raise ValueError(f"声明哈希与权重文件不一致: {model.get('name')}")
    if explicit:
        return _norm_sha(explicit)
    if computed:
        return computed
    raise ValueError(f"模型 {model.get('name')!r} 缺少 path 或 sha256")


def build_sbom(models: Iterable[dict], *, root: Path | str | None = None) -> dict:
    """生成 CycloneDX 1.5 ML-BOM 风格 SBOM（确定性 serialNumber，便于入库比对）。"""
    base = Path(root or ".").resolve()
    model_list = list(models or [])
    if not model_list:
        raise ValueError("models 不能为空")
    components: list[dict] = []
    model_refs: list[str] = []
    seen: set[str] = set()
    for model in model_list:
        name = str(model.get("name") or "").strip()
        version = str(model.get("version") or "").strip()
        source = str(model.get("source") or "").strip()
        license_id = str(model.get("license") or "").strip()
        if not name or not version:
            raise ValueError("每个模型必须包含 name 与 version")
        if not source:
            raise ValueError(f"{name}: 缺少 source（权重来源）")
        if not license_id:
            raise ValueError(f"{name}: 缺少 license")
        key = f"{name}@{version}"
        if key in seen:
            raise ValueError(f"模型重复: {key}")
        seen.add(key)
        digest = _model_hash(model, base)
        bom_ref = f"model:{key}"
        model_refs.append(bom_ref)
        datasets = list(model.get("dataset") or [])
        dataset_refs: list[str] = []
        for ds in datasets:
            ds_name = str(ds.get("name") or "").strip()
            ds_version = str(ds.get("version") or "unknown").strip()
            if not ds_name:
                raise ValueError(f"{name}: dataset 缺少 name")
            ds_ref = f"dataset:{ds_name}@{ds_version}"
            dataset_refs.append(ds_ref)
            comp = {
                "type": "data",
                "bom-ref": ds_ref,
                "name": ds_name,
                "version": ds_version,
                "licenses": [_license_entry(ds.get("license") or "unknown")],
                "properties": [
                    {"name": "trident:dataset:role", "value": str(ds.get("role") or "training")},
                ],
            }
            if ds.get("source"):
                comp["externalReferences"] = [{"type": "distribution", "url": str(ds["source"])}]
            components.append(comp)
        props = [
            {"name": "trident:model:format", "value": str(model.get("format") or "unknown")},
            {"name": "trident:weights:sha256", "value": digest},
        ]
        for ref in dataset_refs:
            props.append({"name": "trident:dataset", "value": ref})
        components.append({
            "type": "machine-learning-model",
            "bom-ref": bom_ref,
            "name": name,
            "version": version,
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "licenses": [_license_entry(license_id)],
            "externalReferences": [{"type": "distribution", "url": source}],
            "properties": props,
            "modelCard": {
                "modelParameters": {"task": str(model.get("task") or "unknown")},
                "quantitativeAnalysis": {"performanceMetrics": []},
            },
        })
    serial_seed = _json_dump({"models": model_refs, "components": components})
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "trident-sbom:" + serial_seed)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": [{"vendor": "Trident", "name": TOOL_NAME, "version": TOOL_VERSION}],
            "component": {
                "type": "application",
                "bom-ref": "application:trident-ai-stack",
                "name": "trident-ai-stack",
                "version": "2026.10",
            },
        },
        "components": components,
    }


# ---------------------------------------------------------------- 2) provenance

def _bundle_payload(bundle: dict) -> dict:
    return {
        "artifact": bundle.get("artifact"),
        "source": bundle.get("source"),
        "builder": bundle.get("builder"),
    }


def sign_bundle(bundle: dict, secret: str, *, keyid: str | None = None) -> dict:
    """cosign 风格 bundle 的本地 fixture 签名（HMAC-SHA256，仅用于测试/演示）。"""
    if not secret:
        raise ValueError("签名密钥不能为空")
    out = copy.deepcopy(bundle)
    sig = out.get("signature") or {}
    out["signature"] = {
        "keyid": keyid or sig.get("keyid") or "fixture-model-key-1",
        "alg": _HMAC_ALG,
        "value": hmac.new(str(secret).encode("utf-8"),
                          _json_dump(_bundle_payload(out)).encode("utf-8"),
                          hashlib.sha256).hexdigest(),
    }
    return out


def verify_model(
    weights_path: Path | str,
    bundle: dict | Path | str,
    trust_root: dict | Path | str,
    *,
    expected_source: str | None = None,
) -> dict:
    """校验「签名 / 哈希 / 来源」三元组；任何篡改都必须在 checks 中定位。"""
    checks: list[dict] = []
    errors: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            errors.append(name)

    bundle_doc = _read_json(bundle) if not isinstance(bundle, dict) else copy.deepcopy(bundle)
    trust = _read_json(trust_root) if not isinstance(trust_root, dict) else copy.deepcopy(trust_root)
    weights = Path(weights_path)

    artifact = bundle_doc.get("artifact") if isinstance(bundle_doc.get("artifact"), dict) else {}
    source = bundle_doc.get("source") if isinstance(bundle_doc.get("source"), dict) else {}
    signature = bundle_doc.get("signature") if isinstance(bundle_doc.get("signature"), dict) else {}
    cert = bundle_doc.get("certificate") if isinstance(bundle_doc.get("certificate"), dict) else {}
    schema_ok = bool(
        bundle_doc.get("mediaType")
        and artifact.get("sha256")
        and source.get("repository")
        and source.get("revision")
        and signature.get("keyid")
        and signature.get("value")
    )
    check("schema", schema_ok,
          "cosign simplesigning bundle 必备字段（mediaType/artifact/source/signature）")

    actual_sha = sha256_file(weights) if weights.is_file() else ""
    declared_sha = ""
    if artifact.get("sha256"):
        try:
            declared_sha = _norm_sha(artifact["sha256"])
        except ValueError:
            declared_sha = ""
    check("artifact-hash", bool(actual_sha) and hmac.compare_digest(actual_sha, declared_sha),
          f"weights={actual_sha or 'missing'} declared={declared_sha or 'invalid'}")

    keyid = str(signature.get("keyid") or "")
    key_cfg = (trust.get("keys") or {}).get(keyid) or {}
    check("signature-key", bool(key_cfg), f"keyid={keyid or 'missing'} trusted={bool(key_cfg)}")

    expected_sig = ""
    if key_cfg and str(key_cfg.get("alg") or _HMAC_ALG) == _HMAC_ALG:
        expected_sig = hmac.new(str(key_cfg.get("fixture_secret") or "").encode("utf-8"),
                                _json_dump(_bundle_payload(bundle_doc)).encode("utf-8"),
                                hashlib.sha256).hexdigest()
    sig_value = str(signature.get("value") or "")
    check("signature", bool(expected_sig) and signature.get("alg") == _HMAC_ALG
          and hmac.compare_digest(sig_value, expected_sig),
          f"alg={signature.get('alg') or 'missing'} keyid={keyid or 'missing'}")

    issuer = str(key_cfg.get("issuer") or "")
    check("certificate-issuer", bool(issuer) and cert.get("issuer") == issuer,
          f"cert.issuer={cert.get('issuer') or 'missing'} expected={issuer or 'missing'}")

    repo = str(source.get("repository") or "")
    allowed = [str(x) for x in (key_cfg.get("allowed_repositories") or [])]
    repo_ok = bool(repo) and repo in allowed
    if expected_source:
        repo_ok = repo_ok and repo == expected_source
    check("source-repository", repo_ok,
          f"repo={repo or 'missing'} allowed={len(allowed)} expected={expected_source or '*'}")

    require_log = bool(trust.get("require_transparency_log", True))
    log = bundle_doc.get("transparency") if isinstance(bundle_doc.get("transparency"), dict) else {}
    log_ok = (not require_log) or bool(
        isinstance(log.get("logIndex"), int) and log.get("logId") and isinstance(log.get("integratedTime"), int)
    )
    check("transparency-log", log_ok,
          "Rekor 风格透明日志条目" if require_log else "策略未要求透明日志")

    return {
        "schema": "trident-provenance-verdict/2026-10",
        "ok": all(c["ok"] for c in checks),
        "checks": checks,
        "errors": errors,
        "artifact": {"name": artifact.get("name") or weights.name,
                     "sha256": actual_sha, "path": str(weights)},
        "source": {"repository": repo, "revision": source.get("revision") or ""},
    }


# ---------------------------------------------------------------- 3) TEE attestation

def load_policy(path: Path | str | None = None) -> dict:
    return _load(path or _POLICY_PATH)


def load_attestation(tee: str, path: Path | str | None = None) -> dict:
    if path is None and tee not in SUPPORTED_TEES:
        raise ValueError(f"未知 TEE {tee!r}（支持 {', '.join(SUPPORTED_TEES)}）")
    target = Path(path) if path else _ATTEST_DIR / f"{tee}.json"
    doc = _load(target)
    if doc.get("tee") not in SUPPORTED_TEES:
        raise ValueError(f"attestation tee 非法: {doc.get('tee')!r}")
    return doc


def _attestation_payload(doc: dict) -> dict:
    out = {k: v for k, v in doc.items() if k != "signature"}
    return out


def sign_attestation(doc: dict, keyid: str, secret: str) -> dict:
    """fixture 签名（HMAC-SHA256）；生产应使用厂商 PKI 证书链校验。"""
    out = copy.deepcopy(doc)
    out["signature"] = {
        "keyid": keyid,
        "alg": _HMAC_ALG,
        "value": hmac.new(str(secret).encode("utf-8"),
                          _json_dump(_attestation_payload(out)).encode("utf-8"),
                          hashlib.sha256).hexdigest(),
    }
    return out


def _report_data(nonce: str, model_sha: str) -> str:
    return sha256_bytes(f"{nonce}:{model_sha}".encode("utf-8"))


def verify_attestation(doc: dict | Path | str, policy: dict | Path | str) -> dict:
    """解析 TDX/SEV-SNP/NVIDIA CC 证明并做策略断言（fixture 级密码学校验）。"""
    document = _read_json(doc) if not isinstance(doc, dict) else copy.deepcopy(doc)
    pol = _read_json(policy) if not isinstance(policy, dict) else copy.deepcopy(policy)
    checks: list[dict] = []
    errors: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            errors.append(name)

    tee = str(document.get("tee") or "")
    required = ("tee", "nonce", "model_sha256", "report_data", "quote", "claims", "signature")
    schema_ok = tee in SUPPORTED_TEES and all(k in document for k in required) \
        and isinstance(document.get("quote"), dict) and isinstance(document.get("claims"), dict)
    check("schema", schema_ok, f"tee={tee or 'missing'} required={list(required)}")
    if not schema_ok:
        return {"schema": "trident-attestation-verdict/2026-10", "ok": False, "tee": tee,
                "checks": checks, "errors": errors}

    allowed_tees = [str(x) for x in (pol.get("allowed_tees") or SUPPORTED_TEES)]
    check("tee-allowed", tee in allowed_tees, f"tee={tee} allowed={allowed_tees}")

    expected_nonce = str(pol.get("nonce") or "")
    check("nonce-freshness", bool(expected_nonce) and document.get("nonce") == expected_nonce,
          f"nonce={document.get('nonce')!r} expected={expected_nonce!r}")

    model_sha = str(document.get("model_sha256") or "").lower()
    policy_model = str(pol.get("model_sha256") or "").lower()
    if policy_model:
        check("model-binding", model_sha == policy_model,
              f"model={model_sha[:16]}… expected={policy_model[:16]}…")
    expected_report = _report_data(str(document.get("nonce") or ""), model_sha)
    check("report-data-binding",
          hmac.compare_digest(str(document.get("report_data") or "").lower(), expected_report),
          "report_data = SHA-256(nonce:model_sha256)")

    measurements = (pol.get("launch_measurements") or {}).get(tee) or {}
    quote = document.get("quote") or {}
    measurement_ok = bool(measurements)
    details = []
    for field, allowed in measurements.items():
        actual = str(quote.get(field) or "").lower()
        allow = [str(x).lower() for x in allowed]
        field_ok = bool(actual) and actual in allow
        measurement_ok = measurement_ok and field_ok
        details.append(f"{field}={'ok' if field_ok else 'mismatch'}")
    check("launch-measurement", measurement_ok, " ".join(details) or "策略未配置测量值")

    if pol.get("require_debug_disabled", True):
        q_debug = quote.get("debug")
        c_debug = (document.get("claims") or {}).get("debug")
        check("debug-disabled", q_debug is not True and c_debug is not True,
              f"quote.debug={q_debug} claims.debug={c_debug}")

    allowed_tcb = [str(x) for x in (pol.get("allowed_tcb_status") or ["UpToDate"])]
    tcb = quote.get("tcb") if isinstance(quote.get("tcb"), dict) else {}
    status = str(tcb.get("status") or (document.get("claims") or {}).get("tcb_status") or "")
    check("tcb-status", status in allowed_tcb, f"tcb.status={status or 'missing'} allowed={allowed_tcb}")

    if tee == "nvidia-cc":
        required_mode = str(pol.get("require_gpu_cc_mode") or "on")
        mode = str((document.get("claims") or {}).get("gpu_cc_mode") or "")
        check("gpu-cc-mode", mode == required_mode,
              f"gpu_cc_mode={mode or 'missing'} required={required_mode}")

    signature = document.get("signature") if isinstance(document.get("signature"), dict) else {}
    keyid = str(signature.get("keyid") or "")
    trusted = pol.get("trusted_keys") or {}
    secret = trusted.get(keyid)
    expected_sig = ""
    if secret:
        expected_sig = hmac.new(str(secret).encode("utf-8"),
                                _json_dump(_attestation_payload(document)).encode("utf-8"),
                                hashlib.sha256).hexdigest()
    check("signature", bool(expected_sig) and signature.get("alg") == _HMAC_ALG
          and hmac.compare_digest(str(signature.get("value") or ""), expected_sig),
          f"keyid={keyid or 'missing'} trusted={keyid in trusted}")

    return {
        "schema": "trident-attestation-verdict/2026-10",
        "ok": all(c["ok"] for c in checks),
        "tee": tee,
        "checks": checks,
        "errors": errors,
        "claims": {
            "attester": (document.get("claims") or {}).get("attester"),
            "gpu_cc_mode": (document.get("claims") or {}).get("gpu_cc_mode"),
            "tcb_status": status,
        },
    }


# ---------------------------------------------------------------- 便捷导出

def write_sbom(models: Iterable[dict], out: Path | str | None = None,
               *, root: Path | str | None = None) -> dict:
    sbom = build_sbom(models, root=root)
    _write_json(out, sbom)
    return sbom


def write_verdict(verdict: dict, out: Path | str | None = None) -> dict:
    _write_json(out, verdict)
    return verdict
