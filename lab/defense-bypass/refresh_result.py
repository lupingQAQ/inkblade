"""Refresh alert/denial fields in result.json from the raw logs.

The parser was fixed after the run (Kyverno 1.19 says "denied the request:"
instead of "denied:").  The raw logs are unchanged; this re-derives the fields
without inventing evidence.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from inkblade.core import defense_policy as dp  # noqa: E402

OUT = REPO / "reports" / "samples" / "defense-bypass-path"
doc = json.loads((OUT / "result.json").read_text(encoding="utf-8"))
control = (OUT / "logs" / "kyverno-control-apply.log").read_text(encoding="utf-8")
phase1 = (OUT / "logs" / "phase1-kyverno.log").read_text(encoding="utf-8")
denials = dp.parse_kyverno_denials(phase1) + dp.parse_kyverno_denials(control)
doc["phases"]["kyverno_scope"]["denials"] = denials
for item in doc["techniques"]:
    if item["id"] == "namespace-scope-evasion":
        item["denials"] = denials
(OUT / "result.json").write_text(
    json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
print("denials", [(d.get("policy"), d.get("message")) for d in denials])
