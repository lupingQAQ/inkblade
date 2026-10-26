# -*- coding: utf-8 -*-
"""Author the 11 defense-bypass templates from the product specification.

Run: python tools/defense-templates.py
Writes inkblade/modules/defense-bypass-*/template.json (declarative data only).
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inkblade.core.defenseprobe import PRODUCT_SPECS  # noqa: E402

TOKENS = {
    "elkeid": ["elkeid", "olehid"],
    "agentsmith": ["agentsmith", "smith"],
    "veinmind": ["veinmind"],
    "falco": ["falco"],
    "tetragon": ["tetragon", "tracingpolic"],
    "kubearmor": ["kubearmor"],
    "admission": ["kyverno", "gatekeeper", "constrainttemplate"],
    "imagescan": ["trivy", "grype", "veinmind", "syft"],
    "hostagent": ["wazuh", "ossec", "osquery"],
    "waf-inference": ["modsecurity", "coraza", "safeline", "ce-waf", "雷池"],
    "netobserv": ["hubble", "typha", "flowlog", "flow-log"],
}
DRIVER_INDICATORS = {
    "elkeid": [
        ("elkeid-ko", "contains(lower(str(steps.deploy.json.kernel_modules)), 'elkeid') or "
                      "contains(lower(str(steps.deploy.json.kernel_modules)), 'olehid')"),
        ("elkeid-driver", "contains(lower(str(steps.deploy.json)), 'elkeid-driver')"),
    ],
    "agentsmith": [
        ("smith-ko", "contains(lower(str(steps.deploy.json.kernel_modules)), 'smith')"),
    ],
    "falco": [
        ("falco-ko", "contains(lower(str(steps.deploy.json.kernel_modules)), 'falco')"),
        ("falco-ebpf", "contains(lower(str(steps.deploy.json)), 'falco-ebpf')"),
    ],
    "tetragon": [
        ("bpf-lsm", "contains(lower(str(steps.deploy.json.kernel_params)), 'bpf')"),
    ],
    "hostagent": [
        ("agent-online", "contains(steps.deploy.json.agent_status, 'online')"),
    ],
}


def build(product: str, spec: dict, module: dict) -> dict:
    tokens = TOKENS[product]
    hit = " or ".join(f"contains(vars.deploy_text, '{token}')" for token in tokens)
    indicators = DRIVER_INDICATORS.get(product, [])
    driver_ok = " or ".join(expr for _, expr in indicators) or "true"
    missing = ("if(len(filter([" + ", ".join(
        f"if({expr}, '', '{iid}')" for iid, expr in indicators) +
        "], it != '')) == 0, 'driver', join(filter([" + ", ".join(
        f"if({expr}, '', '{iid}')" for iid, expr in indicators) +
        "], it != ''), ','))") if indicators else "''"
    forced = ("contains(vars.deploy_text, 'no-driver') or "
              "contains(vars.deploy_text, 'degraded')")
    detected = (
        "(vars.state == 'deployed' or (vars.state == 'degraded' and not it.needs_driver)) "
        "and it.detected "
        "and (steps.ruleset.exists != true or contains(steps.ruleset.json.rules, it.id))")
    rule_line = ("'rule:product=" + product + ":technique=' + it.id + "
                 "':state=' + vars.state + ':category=' + it.category + ':建议=' + it.gap")
    absent_line = ("'rule:product=" + product + ":state=absent:category=deployment"
                   ":建议=未检出 " + spec["display"] +
                   "——确认是否需要部署；当前技术类别矩阵全盲区'")
    kernel_line = ("'rule:product=" + product + ":state=degraded:category=kernel-state"
                   ":建议=恢复内核态/健康组件（缺失: ' + vars.missing_driver + "
                   "'）；降级期间内核态依赖技术全部视为盲区'")
    hardening = ("if(vars.state == 'absent', [" + absent_line + "], "
                 "concat(if(vars.state == 'degraded', [" + kernel_line + "], []), "
                 "map(filter(vars.techniques, not (" + detected + ")), " + rule_line + ")))")
    techniques = []
    for item in spec["techniques"]:
        techniques.append({
            "id": item["id"], "name": item["name"], "category": item["category"],
            "detected": bool(item["detected"]), "needs_driver": bool(item["needs_driver"]),
            "gap": item["gap"],
        })
    key = f"defense-bypass-{product}"
    template = {
        "schema": "inkblade-probe-template-v1",
        "key": key,
        "version": "1.0.0",
        "meta": {
            "name": module["name"], "series": module["series"],
            "min_level": module["min_level"], "writes": False,
            "requires": [], "surfaces": [str(s) for s in (module.get("surfaces") or [])],
            "cves": [], "fidelity": "equivalent",
        },
        "inputs": {
            "deploy_snapshot": {"from": "coalesce(params.deploy_snapshot, params.fixture)",
                                "required": True,
                                "description": "deployed/degraded/absent deployment snapshot"},
            "ruleset": {"from": "params.ruleset", "required": False,
                        "description": "optional rule-set export {rules:[technique-id]}"},
        },
        "defaults": {"timeout_ms": 8000},
        "vars": {
            "product": product,
            "display": spec["display"],
            "vendor": spec["vendor"],
            "techniques": techniques,
            "deploy_text": "placeholder",
        },
        "computed": {
            "deploy_text": "lower(str(steps.deploy.json))",
            "hit": hit,
            "driver_ok": driver_ok,
            "forced_degraded": forced,
            "state": "if(not vars.hit, 'absent', "
                     "if(not vars.driver_ok or vars.forced_degraded, 'degraded', 'deployed'))",
            "missing_driver": f"if({driver_ok}, '', {missing})" if indicators else "''",
            "hardening": hardening,
            "detected_count": f"count_if(vars.techniques, {detected})",
            "blindspot_count": f"count_if(vars.techniques, not ({detected}))",
            "ruleset_supplied": "steps.ruleset.exists == true",
        },
        "steps": [
            {"id": "deploy", "op": "fs", "action": "read",
             "path": "{{input.deploy_snapshot}}", "json": True, "save": "deploy"},
            {"id": "ruleset", "op": "fs", "action": "read", "when": "input.ruleset != null",
             "path": "{{input.ruleset}}", "json": True, "save": "ruleset",
             "allow_failure": True},
        ],
        "checks": [
            {"id": "deploy-readable", "when": "steps.deploy.ok == true", "fatal": True,
             "message": "deployment snapshot is not readable JSON"},
        ],
        "findings": [
            {"id": "fingerprint", "sev": "info",
             "title": f"[{key}] 指纹: {{{{vars.display}}}} = {{{{vars.state}}}}",
             "detail": "matched=`{{vars.hit}}` driver_ok=`{{vars.driver_ok}}` "
                       "forced_degraded=`{{vars.forced_degraded}}` "
                       "ruleset=`{{vars.ruleset_supplied}}`",
             "evidence": "{{steps.deploy.path}}",
             "mapping": "防护产品指纹 / 部署面两态评估"},
            {"id": "coverage-blindspots", "when": "vars.blindspot_count > 0", "sev": "medium",
             "title": f"[{key}] 覆盖矩阵: detected={{{{vars.detected_count}}}} "
                      f"blindspots={{{{vars.blindspot_count}}}}",
             "detail": "检出=默认规则集能识别的技术类别；盲区=不能；benign-only 实验室断言。",
             "mapping": "core/defenseprobe 技术类别矩阵"},
            {"id": "coverage-complete", "when": "vars.blindspot_count == 0", "sev": "info",
             "title": f"[{key}] 覆盖矩阵: detected={{{{vars.detected_count}}}} blindspots=0",
             "detail": "全部技术类别均在规则集覆盖内。"},
            {"id": "blindspot", "for_each": "vars.techniques", "as": "t",
             "when": f"not ({detected})", "sev": "low",
             "title": "盲区: {{t.id}} — {{t.name}}",
             "detail": "category={{t.category}} needs_driver={{t.needs_driver}} "
                       "state={{vars.state}}",
             "evidence": "step=deploy path={{steps.deploy.path}}",
             "mapping": "rule:product=" + product + ":technique={{t.id}}:state={{vars.state}}",
             "fix": "{{t.gap}}"},
            {"id": "detected", "for_each": "vars.techniques", "as": "t",
             "when": detected, "sev": "info",
             "title": "检出: {{t.id}} — {{t.name}}",
             "detail": "category={{t.category}} needs_driver={{t.needs_driver}} "
                       "state={{vars.state}}",
             "evidence": "step=deploy path={{steps.deploy.path}}",
             "mapping": "rule:product=" + product + ":technique={{t.id}}:state={{vars.state}}"},
            {"id": "hardening", "when": "vars.blindspot_count > 0", "sev": "info",
             "title": f"[{key}] 硬化建议 ({{{{vars.blindspot_count}}}} 条)",
             "detail": "{{join(vars.hardening, ' | ')}}",
             "mapping": "hardening-advice"},
        ],
        "artifacts": [
            {"name": f"{key}-matrix.json", "kind": "json", "fields": {
                "product": "vars.product",
                "display": "vars.display",
                "vendor": "vars.vendor",
                "state": "vars.state",
                "detected": f"map(filter(vars.techniques, {detected}), it.id)",
                "blindspots": f"map(filter(vars.techniques, not ({detected})), it.id)",
                "hardening": "vars.hardening",
                "techniques": "vars.techniques",
                "ruleset_supplied": "vars.ruleset_supplied",
                "benign_only": "true",
            }},
        ],
        "payloads": {
            "benign": {"marker": "INKBLADE-BENIGN",
                       "note": "only benign markers; no malicious payload"},
        },
        "limits": {"timeout_ms": 30000, "max_http_requests": 8},
    }
    return template


def main() -> int:
    for product, spec in PRODUCT_SPECS.items():
        module_dir = ROOT / "inkblade" / "modules" / f"defense-bypass-{product}"
        module = json.loads((module_dir / "module.json").read_text(encoding="utf-8"))
        template = build(product, spec, module)
        (module_dir / "template.json").write_text(
            json.dumps(template, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("wrote", module_dir.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
