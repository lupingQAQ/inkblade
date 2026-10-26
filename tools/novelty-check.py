# -*- coding: utf-8 -*-
"""Novelty gate for the Trident 0day reserve.

The checker answers one question per inventory entry: is the claimed
vulnerability already public?  It queries the authoritative disclosure
channels (OSV, NVD, GitHub advisories, GitHub commit search, GitHub code
search and the vendor security pages), caches every raw answer under
``corpus/novelty/`` and fails closed:

``confirmed-unpublished``
    Every required provider answered and returned no public match.

``already-public``
    At least one provider returned a CVE/GHSA/security commit/vendor advisory.

``inconclusive``
    A provider was unreachable, rate limited, skipped, or the check ran
    offline without a cache entry.  It is never treated as unpublished.

The GitHub code-search REST endpoint requires authentication.  When no token
is configured the checker falls back to grep.app (a public GitHub code index)
plus a local scan of the pinned upstream tree; the method used is recorded in
the result so the evidence can be audited.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlparse

import requests

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
DEFAULT_CACHE = ROOT / "corpus" / "novelty" / "cache"
DEFAULT_TTL_DAYS = 7
PROVIDERS = ("osv", "nvd", "github_advisories", "github_commits", "github_code", "vendor")
VERDICTS = ("confirmed-unpublished", "already-public", "inconclusive")
USER_AGENT = "trident-novelty-check/1.0 (+authorized security audit)"
NVD_INTERVAL_S = 6.5
GITHUB_SEARCH_INTERVAL_S = 6.5
MAX_BODY = 2 * 1024 * 1024


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_DRIVE_PATH_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s\"'<>|]+")


def _safe_text(value: Any) -> str:
    """Redact host paths from third-party snippets before they enter the registry."""
    text = str(value if value is not None else "")
    for old, new in ((str(ROOT), "<repo>"), (str(WORKSPACE), "<workspace>"),
                     (str(ROOT).replace("\\", "/"), "<repo>"),
                     (str(WORKSPACE).replace("\\", "/"), "<workspace>")):
        text = text.replace(old, new)
    return _DRIVE_PATH_RE.sub("<path>", text)


GENERIC_STRONG = {
    # Endpoint/function names that appear in advisories for unrelated bugs.
    "update_weights_from_disk", "update_weights", "pause_generation", "resume",
    "load", "save", "eval", "exec", "serve", "main", "api", "jobs", "run",
    "read", "write", "open", "download", "to_base64", "encode", "decode",
    "fetch", "get", "post", "endpoint.py", "http_server.py", "api_router.py",
    "server.py", "utils.py", "app.py", "main.py", "docker-compose.yaml",
    "docker-compose.yml", "compose.yaml", "settings.py", "config.py", "auth.py",
    "loader.py", "serve.py", "server/index.ts", "protocol.py", "media_utils.py",
}


def _terms(entry: dict, cfg: dict) -> dict[str, list[str]]:
    """Return (strong, weak) search terms.

    Strong terms are function/file names or exact phrases; a generic product
    name alone must never be treated as a disclosure match.  Endpoint names
    that recur across unrelated advisories are demoted to weak terms so a CVE
    about another bug at the same route does not mask a new finding.
    """
    strong: list[str] = []
    weak: list[str] = []
    for value in cfg.get("strong_terms") or []:
        if value:
            strong.append(str(value))
    root = entry.get("root_cause") or {}
    for value in (root.get("function"), root.get("file")):
        if value:
            # Only the basename is a useful strong term.  A full path such as
            # ``.../http_server.py`` appears verbatim in unrelated advisories
            # for other bugs in the same file.
            strong.append(Path(str(value)).name)
    for value in cfg.get("keywords") or []:
        if value:
            weak.append(str(value))
    for value in (entry.get("component"), entry.get("product"), entry.get("module")):
        if value:
            weak.append(str(value))

    def uniq(items: Iterable[str]) -> list[str]:
        seen: set[str] = set()
        out = []
        for item in items:
            item = item.strip()
            if not item or item.lower() in seen:
                continue
            seen.add(item.lower())
            out.append(item)
        return out

    strong = uniq(strong)
    demoted = [t for t in strong if t.lower() in GENERIC_STRONG]
    strong = [t for t in strong if t.lower() not in GENERIC_STRONG]
    weak = uniq(weak + demoted)
    return {"strong": strong, "weak": weak}


def _contains_any(text: str, terms: Iterable[str]) -> list[str]:
    low = (text or "").lower()
    return [t for t in terms if t and t.lower() in low]


class Cache:
    def __init__(self, root: Path, ttl_days: int = DEFAULT_TTL_DAYS):
        self.root = Path(root)
        self.ttl = timedelta(days=ttl_days)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, provider: str, key: str) -> Path:
        return self.root / provider / f"{_sha256(key)}.json"

    def get(self, provider: str, key: str) -> dict | None:
        path = self._path(provider, key)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        created = data.get("_cached_at")
        if created:
            try:
                age = datetime.now(timezone.utc) - datetime.fromisoformat(created)
            except ValueError:
                age = self.ttl + timedelta(seconds=1)
            if age > self.ttl:
                return None
        return data

    def put(self, provider: str, key: str, value: dict) -> dict:
        data = dict(value)
        data["_cached_at"] = now()
        path = self._path(provider, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        return data


class Http:
    """Small requests wrapper with deterministic error objects and caching."""

    def __init__(self, cache: Cache, offline: bool = False, refresh: bool = False, timeout: int = 30):
        self.cache = cache
        self.offline = offline
        self.refresh = refresh
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self._last: dict[str, float] = {}

    def _throttle(self, key: str, interval: float) -> None:
        last = self._last.get(key, 0.0)
        wait = interval - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        self._last[key] = time.time()

    def get(self, provider: str, url: str, *, params: dict | None = None,
            headers: dict | None = None, throttle: tuple[str, float] | None = None,
            raw: bool = False, timeout: int | None = None) -> dict:
        key = json.dumps({"url": url, "params": params, "headers": headers, "raw": raw,
                          "timeout": timeout}, sort_keys=True)
        if not self.refresh:
            cached = self.cache.get(provider, key)
            if cached is not None:
                cached["_cache_hit"] = True
                return cached
        if self.offline:
            return {"status": "error", "error": "offline-cache-miss", "url": url, "cache_hit": False}
        if throttle:
            self._throttle(*throttle)
        resp = None
        for attempt in range(3):
            try:
                resp = self.session.get(url, params=params, headers=headers,
                                        timeout=timeout or self.timeout)
            except requests.RequestException as exc:
                if attempt < 2:
                    time.sleep(2 + attempt * 3)
                    continue
                return {"status": "error", "error": f"{type(exc).__name__}: {exc}", "url": url, "cache_hit": False}
            if resp.status_code not in (403, 429):
                break
            if attempt < 2:
                time.sleep(3 + attempt * 5)
        if raw:
            body = resp.text[:MAX_BODY]
            result = {"status": "ok" if resp.status_code < 400 else "http-error",
                      "http_status": resp.status_code, "url": resp.url, "body": body}
        else:
            try:
                body = resp.json()
            except ValueError:
                body = resp.text[:2000]
            result = {"status": "ok" if resp.status_code < 400 else "http-error",
                      "http_status": resp.status_code, "url": resp.url, "body": body}
        result["cache_hit"] = False
        return self.cache.put(provider, key, result) if result["status"] == "ok" else result

    def post(self, provider: str, url: str, payload: dict, *,
             throttle: tuple[str, float] | None = None) -> dict:
        key = json.dumps({"url": url, "payload": payload}, sort_keys=True)
        if not self.refresh:
            cached = self.cache.get(provider, key)
            if cached is not None:
                cached["_cache_hit"] = True
                return cached
        if self.offline:
            return {"status": "error", "error": "offline-cache-miss", "url": url, "cache_hit": False}
        if throttle:
            self._throttle(*throttle)
        try:
            resp = self.session.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}", "url": url, "cache_hit": False}
        try:
            body = resp.json()
        except ValueError:
            body = resp.text[:2000]
        result = {"status": "ok" if resp.status_code < 400 else "http-error",
                  "http_status": resp.status_code, "url": resp.url, "body": body, "cache_hit": False}
        return self.cache.put(provider, key, result) if result["status"] == "ok" else result


def _base_result(provider: str) -> dict:
    return {"provider": provider, "status": "skipped", "matches": [], "detail": ""}


def _clean(provider: str, detail: str = "", **extra) -> dict:
    out = _base_result(provider)
    out.update({"status": "ok", "detail": detail})
    out.update(extra)
    return out


def _not_applicable(provider: str, detail: str, **extra) -> dict:
    out = _base_result(provider)
    out.update({"status": "not-applicable", "detail": detail})
    out.update(extra)
    return out


def _error(provider: str, detail: str, **extra) -> dict:
    out = _base_result(provider)
    out.update({"status": "error", "detail": detail})
    out.update(extra)
    return out


def _match(provider: str, matches: list[dict], detail: str = "", **extra) -> dict:
    out = _base_result(provider)
    out.update({"status": "match", "matches": matches, "detail": detail})
    out.update(extra)
    return out


def check_osv(entry: dict, cfg: dict, http: Http) -> dict:
    provider = "osv"
    pkg = cfg.get("osv_package")
    version = cfg.get("osv_version")
    ecosystem = cfg.get("osv_ecosystem") or "PyPI"
    if not pkg:
        return _not_applicable(provider, "no package mapping in inventory")
    query: dict[str, Any] = {"package": {"name": pkg, "ecosystem": ecosystem}}
    if version:
        query["version"] = version
    elif cfg.get("osv_commit"):
        query["commit"] = cfg["osv_commit"]
    else:
        return _not_applicable(provider, "no version/commit pin; OSV cannot answer for a floating package")
    resp = http.post(provider, "https://api.osv.dev/v1/query", query)
    if resp.get("status") != "ok":
        return _error(provider, resp.get("error") or f"HTTP {resp.get('http_status')}", **{"raw": resp})
    body = resp.get("body") or {}
    vulns = body.get("vulns") or []
    if not isinstance(vulns, list):
        return _error(provider, "unexpected OSV response shape")
    terms = _terms(entry, cfg)
    strong, weak = terms["strong"], terms["weak"]
    matches = []
    related = []
    for vuln in vulns:
        text = " ".join(str(vuln.get(k) or "") for k in ("id", "summary", "details", "aliases"))
        strong_hit = _contains_any(text, strong)
        weak_hit = _contains_any(text, weak)
        record = {"id": vuln.get("id"), "aliases": vuln.get("aliases") or [],
                  "summary": _safe_text((vuln.get("summary") or "")[:300]),
                  "url": f"https://osv.dev/vulnerability/{vuln.get('id')}"}
        if strong_hit or (weak_hit and cfg.get("osv_match_weak")):
            record["matched_terms"] = strong_hit or weak_hit
            matches.append(record)
        else:
            related.append(record)
    if matches:
        return _match(provider, matches, f"{len(matches)} matching OSV record(s)", related=related[:10],
                      queried=f"{pkg}@{version or cfg.get('osv_commit')}")
    return _clean(provider, f"OSV returned {len(vulns)} advisory(ies) for the pin, none matched the sink",
                  related=related[:10], queried=f"{pkg}@{version or cfg.get('osv_commit')}")


def check_nvd(entry: dict, cfg: dict, http: Http) -> dict:
    provider = "nvd"
    keywords = cfg.get("nvd_keywords") or []
    if isinstance(keywords, str):
        keywords = [keywords]
    if not keywords:
        return _not_applicable(provider, "no NVD keyword configured")
    terms = _terms(entry, cfg)
    strong = terms["strong"] + list(cfg.get("nvd_strong_terms") or [])
    matches: list[dict] = []
    related: list[dict] = []
    for keyword in keywords[:3]:
        resp = http.get(
            provider,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 50},
            throttle=("nvd", NVD_INTERVAL_S),
        )
        if resp.get("status") != "ok":
            return _error(provider, resp.get("error") or f"HTTP {resp.get('http_status')}", **{"raw": resp})
        body = resp.get("body") or {}
        for item in body.get("vulnerabilities") or []:
            cve = (item or {}).get("cve") or {}
            cve_id = cve.get("id") or ""
            desc = " ".join(d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en")
            text = f"{cve_id} {desc}"
            record = {"id": cve_id, "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                      "summary": _safe_text(desc[:300])}
            strong_hit = _contains_any(text, strong)
            if strong_hit:
                record["matched_terms"] = strong_hit
                matches.append(record)
            else:
                related.append(record)
    if matches:
        return _match(provider, matches[:20], f"{len(matches)} NVD CVE(s) matched strong terms",
                      keywords=keywords[:3], related=related[:10])
    return _clean(provider, "NVD keyword search returned no strong-term match",
                  keywords=keywords[:3], related=related[:10])


def _gh_ecosystems(cfg: dict) -> list[str]:
    value = cfg.get("ghsa_ecosystem")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(x) for x in value]
    return ["pip"]


def check_github_advisories(entry: dict, cfg: dict, http: Http) -> dict:
    provider = "github_advisories"
    package = (cfg.get("ghsa_package") or cfg.get("osv_package") or "").lower()
    if not package:
        return _not_applicable(provider, "no package mapping in inventory")
    terms = _terms(entry, cfg)
    strong = terms["strong"]
    matches: list[dict] = []
    related: list[dict] = []
    for ecosystem in _gh_ecosystems(cfg):
        for page in range(1, 4):
            resp = http.get(provider, "https://api.github.com/advisories",
                            params={"ecosystem": ecosystem, "per_page": 100, "page": page},
                            headers={"Accept": "application/vnd.github+json"})
            if resp.get("status") != "ok":
                return _error(provider, resp.get("error") or f"HTTP {resp.get('http_status')}", **{"raw": resp})
            body = resp.get("body")
            if not isinstance(body, list):
                return _error(provider, "unexpected GitHub advisories response shape")
            for adv in body:
                vulns = adv.get("vulnerabilities") or []
                names = {(v.get("package") or {}).get("name", "").lower() for v in vulns}
                if package not in names:
                    continue
                text = " ".join(str(adv.get(k) or "") for k in ("ghsa_id", "summary", "description"))
                record = {"id": adv.get("ghsa_id"), "cve_id": adv.get("cve_id"),
                          "summary": _safe_text((adv.get("summary") or "")[:300]),
                          "url": adv.get("html_url") or f"https://github.com/advisories/{adv.get('ghsa_id')}"}
                strong_hit = _contains_any(text, strong)
                if strong_hit:
                    record["matched_terms"] = strong_hit
                    matches.append(record)
                else:
                    related.append(record)
            if len(body) < 100:
                break
    if matches:
        return _match(provider, matches[:20], f"{len(matches)} GitHub advisory(ies) matched strong terms",
                      related=related[:10])
    return _clean(provider, "GitHub advisory database has no strong-term match for the package",
                  related=related[:10])


def check_github_commits(entry: dict, cfg: dict, http: Http) -> dict:
    provider = "github_commits"
    terms = _terms(entry, cfg)
    strong = terms["strong"]
    repo = cfg.get("repo")
    if not strong:
        return _not_applicable(provider, "no function/file strong term configured")
    # Keep queries short and specific; GitHub commit search is rate limited.
    term = max(strong, key=len)
    q = f'"{term}"'
    if repo:
        q += f" repo:{repo}"
    resp = http.get(provider, "https://api.github.com/search/commits",
                    params={"q": q, "per_page": 20},
                    headers={"Accept": "application/vnd.github+json"},
                    throttle=("github_search", GITHUB_SEARCH_INTERVAL_S))
    if resp.get("status") != "ok":
        return _error(provider, resp.get("error") or f"HTTP {resp.get('http_status')}", **{"raw": resp})
    body = resp.get("body") or {}
    items = body.get("items") or []
    security_re = re.compile(
        r"cve-\d{4}-\d+|ghsa-|security|vulnerab|sanitiz|bypass|rce|pickle|deserial|"
        r"traversal|ssrf|injection|exploit|privilege|unauth", re.I)
    matches: list[dict] = []
    related: list[dict] = []
    for item in items:
        commit = item.get("commit") or {}
        message = commit.get("message") or ""
        record = {"id": (item.get("sha") or "")[:40], "url": item.get("html_url"),
                  "summary": _safe_text(message.splitlines()[0][:300]) if message else "",
                  "repo": (item.get("repository") or {}).get("full_name")}
        if security_re.search(message):
            matches.append(record)
        else:
            related.append(record)
    if matches:
        return _match(provider, matches[:20], f"{len(matches)} security-relevant commit(s) mention {term}",
                      query=q, related=related[:10])
    return _clean(provider, f"no security-relevant commit matched {term}", query=q, related=related[:10])


def _grep_app(term: str, http: Http, upstream_repo: str | None) -> dict:
    resp = http.get("github_code", "https://grep.app/api/search", params={"q": term},
                    headers={"User-Agent": "Mozilla/5.0",
                             "Accept": "application/json",
                             "Referer": "https://grep.app/"},
                    throttle=("grep_app", 1.5))
    if resp.get("status") != "ok":
        return _error("github_code", resp.get("error") or f"HTTP {resp.get('http_status')}", **{"raw": resp})
    body = resp.get("body") or {}
    hits = ((body.get("hits") or {}).get("hits") or []) if isinstance(body, dict) else []
    external = []
    for hit in hits[:20]:
        repo = hit.get("repo") or ""
        if isinstance(repo, dict):
            repo = repo.get("raw") or ""
        path = hit.get("path") or ""
        if isinstance(path, dict):
            path = path.get("raw") or ""
        content = hit.get("content") or ""
        snippet = content.get("snippet") if isinstance(content, dict) else str(content)
        if upstream_repo and str(repo).lower() == upstream_repo.lower():
            continue
        clean_snippet = _safe_text(re.sub(r"<[^>]+>", "", str(snippet))[:300])
        ids = sorted(set(re.findall(r"CVE-\d{4}-\d+|GHSA-[a-z0-9-]+", clean_snippet, re.I)))
        external.append({"repo": str(repo), "path": str(path),
                         "url": f"https://github.com/{repo}/blob/HEAD/{path}" if repo and path else None,
                         "id": ids[0] if ids else None, "ids": ids,
                         "snippet": clean_snippet})
    exploit_re = re.compile(r"cve-\d{4}-\d+|ghsa-|exploit|poc|proof.of.concept|vulnerab", re.I)
    matches = [h for h in external if exploit_re.search(h.get("snippet", ""))]
    return {"provider": "github_code", "status": "match" if matches else "ok",
            "matches": matches[:20], "external_hits": external[:20],
            "detail": f"grep.app returned {len(hits)} hit(s), {len(external)} outside the upstream repo"}


def check_github_code(entry: dict, cfg: dict, http: Http, cache: Cache) -> dict:
    provider = "github_code"
    terms = _terms(entry, cfg)
    strong = terms["strong"]
    if not strong:
        return _not_applicable(provider, "no function/file strong term configured")
    term = max(strong, key=len)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        resp = http.get(provider, "https://api.github.com/search/code",
                        params={"q": f'"{term}"', "per_page": 20},
                        headers={"Accept": "application/vnd.github+json",
                                 "Authorization": f"Bearer {token}"},
                        throttle=("github_search", GITHUB_SEARCH_INTERVAL_S))
        if resp.get("status") == "ok":
            body = resp.get("body") or {}
            items = body.get("items") or []
            upstream = (cfg.get("repo") or "").lower()
            external = []
            for item in items:
                repo = ((item.get("repository") or {}).get("full_name") or "")
                if upstream and repo.lower() == upstream:
                    continue
                external.append({"repo": repo, "path": item.get("path"), "url": item.get("html_url")})
            exploit_re = re.compile(r"cve-\d{4}-\d+|ghsa-|exploit|poc|vulnerab", re.I)
            matches = [h for h in external if exploit_re.search(str(h))]
            return _match(provider, matches[:20], "GitHub code search (authenticated)",
                          via="github-api", external_hits=external[:20]) if matches else \
                _clean(provider, "GitHub code search (authenticated) returned no external exploit hit",
                       via="github-api", external_hits=external[:20])
        # fall through to grep.app on auth/rate errors
    result = _grep_app(term, http, cfg.get("repo"))
    result["via"] = "grep.app+local-tree"
    local_source = cfg.get("local_source")
    local_hits = []
    if local_source:
        path = Path(local_source)
        if not path.is_absolute():
            path = ROOT / path
        if path.exists():
            for file in path.rglob("*.py") if path.is_dir() else [path]:
                try:
                    text = file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if term in text:
                    local_hits.append(str(file.relative_to(ROOT)).replace("\\", "/"))
                    if len(local_hits) >= 20:
                        break
    result["local_tree_hits"] = local_hits
    return result


def check_vendor(entry: dict, cfg: dict, http: Http) -> dict:
    provider = "vendor"
    urls = cfg.get("vendor_urls") or []
    if isinstance(urls, str):
        urls = [urls]
    repo = cfg.get("repo")
    derived = []
    if repo:
        derived = [
            f"https://raw.githubusercontent.com/{repo}/HEAD/SECURITY.md",
            f"https://github.com/{repo}/security/advisories",
        ]
    urls = list(dict.fromkeys(list(urls) + derived))
    if not urls:
        return _not_applicable(provider, "no vendor advisory URL or repo configured")
    terms = _terms(entry, cfg)
    strong = terms["strong"]
    matches: list[dict] = []
    fetched = []
    errors = []
    for url in urls:
        resp = http.get(provider, url, raw=True, timeout=10)
        if resp.get("status") != "ok":
            if resp.get("http_status") in (404, 410):
                continue
            errors.append(f"{url}: {resp.get('error') or resp.get('http_status')}")
            continue
        body = resp.get("body") or ""
        fetched.append(url)
        pub_re = re.compile(r"cve-\d{4}-\d+|ghsa-[a-z0-9-]+", re.I)
        strong_hit = _contains_any(body, strong)
        if pub_re.search(body) and strong_hit:
            ids = sorted(set(pub_re.findall(body)))[:10]
            matches.append({"url": url, "ids": ids, "matched_terms": strong_hit})
    if matches:
        return _match(provider, matches[:10], f"{len(matches)} vendor page(s) contain a public advisory id",
                      fetched=fetched[:10])
    if not fetched and errors:
        return _error(provider, "; ".join(errors[:3]))
    if not fetched:
        return _not_applicable(provider, "vendor pages returned 404/410 (no advisory channel found)")
    return _clean(provider, "vendor pages fetched clean", fetched=fetched[:10])


def _display_path(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def check_entry(entry: dict, *, cache_dir: Path | str = DEFAULT_CACHE, offline: bool = False,
                refresh: bool = False, providers: Iterable[str] | None = None,
                http: Http | None = None, cache: Cache | None = None) -> dict:
    known = entry.get("known_public") or []
    if known:
        match = {"id": known[0], "ids": known,
                 "url": known[0] if str(known[0]).startswith("http") else None}
        return {
            "schema": "trident-novelty-result-v1",
            "id": entry.get("id"),
            "verdict": "already-public",
            "reason": "source audit already cites public reference(s): " + ", ".join(map(str, known)),
            "checked_at": now(),
            "offline": offline,
            "providers": {
                "registry": {"provider": "registry", "status": "match", "matches": [match],
                             "detail": "known_public field from the source audit/finding registry"}
            },
            "cache_dir": _display_path(Path(cache_dir)),
        }
    cfg = dict(entry.get("novelty") or {})
    selected = tuple(providers or PROVIDERS)
    cache = cache or Cache(Path(cache_dir))
    http = http or Http(cache, offline=offline, refresh=refresh)
    results: dict[str, dict] = {}
    for provider in selected:
        if provider == "osv":
            results[provider] = check_osv(entry, cfg, http)
        elif provider == "nvd":
            results[provider] = check_nvd(entry, cfg, http)
        elif provider == "github_advisories":
            results[provider] = check_github_advisories(entry, cfg, http)
        elif provider == "github_commits":
            results[provider] = check_github_commits(entry, cfg, http)
        elif provider == "github_code":
            results[provider] = check_github_code(entry, cfg, http, cache)
        elif provider == "vendor":
            results[provider] = check_vendor(entry, cfg, http)
        else:
            results[provider] = _error(provider, "unknown provider")

    matches = [r for r in results.values() if r.get("status") == "match"]
    # A missing OSV/GHSA/commit/code query is not evidence of novelty.  Only
    # an explicit "vendor has no advisory page" is an acceptable non-answer.
    bad = [r for r in results.values()
           if r.get("status") in ("error", "skipped")
           or (r.get("status") == "not-applicable" and r.get("provider") != "vendor")]
    if matches:
        verdict = "already-public"
        reason = "public disclosure match: " + ", ".join(
            f"{m.get('provider', '?')}={(m.get('matches') or [{}])[0].get('id') or (m.get('matches') or [{}])[0].get('url')}"
            for m in matches
        )
    elif bad:
        verdict = "inconclusive"
        reason = "provider(s) unavailable/skipped: " + "; ".join(
            f"{b['provider']}: {b.get('detail') or b.get('error')}" for b in bad
        )
    else:
        verdict = "confirmed-unpublished"
        reason = "all required providers answered clean; no CVE/GHSA/security commit/vendor advisory/exploit code match"
    return {
        "schema": "trident-novelty-result-v1",
        "id": entry.get("id"),
        "verdict": verdict,
        "reason": reason,
        "checked_at": now(),
        "offline": offline,
        "providers": results,
        "cache_dir": _display_path(cache.root),
    }


def load_entries(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("entries"), list):
        return data["entries"]
    raise SystemExit(f"{path}: expected a JSON list or an object with an 'entries' list")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Novelty gate for 0day reserve entries")
    parser.add_argument("--entry", help="single entry JSON file")
    parser.add_argument("--inventory", help="inventory JSON with an entries list")
    parser.add_argument("--out", help="write results JSON here")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE))
    parser.add_argument("--offline", action="store_true", help="cache-only; missing cache => inconclusive")
    parser.add_argument("--refresh", action="store_true", help="ignore fresh cache entries")
    parser.add_argument("--providers", default=",".join(PROVIDERS))
    parser.add_argument("--only-verified", action="store_true",
                        help="check only entries whose verification.status is verified")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    if bool(args.entry) == bool(args.inventory):
        parser.error("pass exactly one of --entry/--inventory")
    if args.entry:
        entries = [json.loads(Path(args.entry).read_text(encoding="utf-8"))]
    else:
        entries = load_entries(Path(args.inventory))
    if args.only_verified:
        entries = [e for e in entries if (e.get("verification") or {}).get("status") == "verified"]
    selected = [p.strip() for p in args.providers.split(",") if p.strip()]
    cache = Cache(Path(args.cache_dir))
    http = Http(cache, offline=args.offline, refresh=args.refresh)
    results = []
    for entry in entries:
        result = check_entry(entry, cache=cache, http=http, providers=selected)
        results.append(result)
        print(f"{entry.get('id')}: {result['verdict']} - {result['reason']}", file=sys.stderr, flush=True)
        if args.out:
            payload = {"schema": "trident-novelty-results-v1", "generated_at": now(),
                       "offline": args.offline, "verdicts": {r["id"]: r for r in results}}
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    payload = {"schema": "trident-novelty-results-v1", "generated_at": now(),
               "offline": args.offline, "verdicts": {r["id"]: r for r in results}}
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    if args.summary or not args.out:
        counts: dict[str, int] = {}
        for r in results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        print(json.dumps(counts, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
