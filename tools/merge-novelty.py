# -*- coding: utf-8 -*-
"""Merge per-provider novelty runs into one verdict file.

Running each provider separately keeps a slow/rate-limited provider from
blocking the others and makes the evidence auditable:

    python tools/novelty-check.py --providers osv ... --out prov-osv.json
    python tools/novelty-check.py --providers nvd ... --out prov-nvd.json
    ...
    python tools/merge-novelty.py --dir corpus/novelty --out corpus/novelty/results.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROVIDERS = ("osv", "nvd", "github_advisories", "github_commits", "github_code", "vendor")
VERDICTS = ("confirmed-unpublished", "already-public", "inconclusive")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default="corpus/novelty")
    parser.add_argument("--out", default="corpus/novelty/results.json")
    parser.add_argument("--inventory", default="corpus/zeroday/inventory.json")
    args = parser.parse_args(argv)
    base = Path(args.dir)
    known_public = {}
    inv_path = Path(args.inventory)
    if inv_path.is_file():
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
        known_public = {e["id"]: e["known_public"] for e in inv.get("entries", []) if e.get("known_public")}
    merged: dict[str, dict] = {}
    filenames = {
        "osv": "prov-osv.json",
        "nvd": "prov-nvd.json",
        "github_advisories": "prov-ghsa.json",
        "github_commits": "prov-commits.json",
        "github_code": "prov-code.json",
        "vendor": "prov-vendor.json",
    }
    for provider in PROVIDERS:
        path = base / filenames[provider]
        if not path.is_file():
            print(f"missing provider file for {provider}: {path}")
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for eid, result in (data.get("verdicts") or {}).items():
            item = merged.setdefault(eid, {"id": eid, "providers": {}, "schema": "inkblade-novelty-result-v1"})
            item["providers"].update(result.get("providers") or {})
            item["checked_at"] = result.get("checked_at") or now()
    for eid, item in merged.items():
        if eid in known_public:
            ids = known_public[eid]
            item["verdict"] = "already-public"
            item["reason"] = "source audit already cites public reference(s): " + ", ".join(ids)
            item["matched"] = [{"id": ids[0], "ids": ids}]
            item["providers"]["registry"] = {
                "provider": "registry", "status": "match",
                "matches": [{"id": ids[0], "ids": ids}],
                "detail": "known_public field from the source audit/finding registry",
            }
            continue
        provs = item["providers"]
        matches = [p for p in provs.values() if p.get("status") == "match"]
        bad = [p for p in provs.values()
               if p.get("status") in ("error", "skipped")
               or (p.get("status") == "not-applicable" and p.get("provider") != "vendor"
                   and not p.get("justified"))]
        waived = [p for p in provs.values()
                  if p.get("status") == "not-applicable" and p.get("justified")]
        if matches:
            item["verdict"] = "already-public"
            parts = []
            for p in matches:
                first = (p.get("matches") or [{}])[0]
                parts.append(f"{p.get('provider')}={first.get('id') or first.get('url')}")
            item["reason"] = "public disclosure match: " + ", ".join(parts)
        elif bad:
            item["verdict"] = "inconclusive"
            item["reason"] = "provider(s) unavailable/skipped: " + "; ".join(
                f"{b.get('provider')}: {b.get('detail') or b.get('error')}" for b in bad)
        else:
            item["verdict"] = "confirmed-unpublished"
            item["reason"] = ("all required providers answered clean; no CVE/GHSA/security commit/"
                              "vendor advisory/exploit code match")
            if waived:
                item["reason"] += "; justified non-answer: " + "; ".join(
                    f"{w.get('provider')}: {w.get('detail')}" for w in waived)
        item["matched"] = [m for p in matches for m in (p.get("matches") or [])]
    payload = {"schema": "inkblade-novelty-results-v1", "generated_at": now(),
               "verdicts": merged}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    counts = Counter(v["verdict"] for v in merged.values())
    print(f"entries={len(merged)} " + " ".join(f"{k}={counts.get(k, 0)}" for k in VERDICTS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
