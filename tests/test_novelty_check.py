# -*- coding: utf-8 -*-
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("novelty_check", ROOT / "tools" / "novelty-check.py")
novelty = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(novelty)


def clean(provider, detail="clean", **kw):
    return novelty._clean(provider, detail, **kw)


def match(provider, ident="CVE-2026-9999", **kw):
    return novelty._match(provider, [{"id": ident, "url": f"https://example.test/{ident}"}], "match", **kw)


def error(provider, detail="network down", **kw):
    return novelty._error(provider, detail, **kw)


class TestNoveltyVerdicts(unittest.TestCase):
    def setUp(self):
        self.entry = {
            "id": "demo",
            "component": "demo",
            "title": "demo sink",
            "root_cause": {"file": "pkg/mod.py", "line": 10, "function": "danger"},
            "novelty": {"osv_package": "demo", "osv_version": "1.0", "repo": "org/demo"},
        }

    def _run(self, mapping):
        with patch.object(novelty, "check_osv", return_value=mapping["osv"]), \
             patch.object(novelty, "check_nvd", return_value=mapping["nvd"]), \
             patch.object(novelty, "check_github_advisories", return_value=mapping["ghsa"]), \
             patch.object(novelty, "check_github_commits", return_value=mapping["commits"]), \
             patch.object(novelty, "check_github_code", return_value=mapping["code"]), \
             patch.object(novelty, "check_vendor", return_value=mapping["vendor"]):
            return novelty.check_entry(self.entry, cache=novelty.Cache(Path(tempfile.mkdtemp())))

    def test_confirmed_unpublished_requires_all_clean(self):
        result = self._run({
            "osv": clean("osv"), "nvd": clean("nvd"), "ghsa": clean("github_advisories"),
            "commits": clean("github_commits"), "code": clean("github_code"), "vendor": clean("vendor"),
        })
        self.assertEqual(result["verdict"], "confirmed-unpublished")

    def test_already_public_cve(self):
        result = self._run({
            "osv": match("osv", "CVE-2026-1111"), "nvd": clean("nvd"),
            "ghsa": clean("github_advisories"), "commits": clean("github_commits"),
            "code": clean("github_code"), "vendor": clean("vendor"),
        })
        self.assertEqual(result["verdict"], "already-public")
        self.assertIn("CVE-2026-1111", result["reason"])

    def test_already_public_ghsa(self):
        result = self._run({
            "osv": clean("osv"), "nvd": clean("nvd"),
            "ghsa": match("github_advisories", "GHSA-aaaa-bbbb-cccc"),
            "commits": clean("github_commits"), "code": clean("github_code"), "vendor": clean("vendor"),
        })
        self.assertEqual(result["verdict"], "already-public")

    def test_inconclusive_network_failure_never_unpublished(self):
        result = self._run({
            "osv": clean("osv"), "nvd": error("nvd"), "ghsa": clean("github_advisories"),
            "commits": clean("github_commits"), "code": clean("github_code"), "vendor": clean("vendor"),
        })
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertIn("nvd", result["reason"])

    def test_inconclusive_skipped_provider(self):
        result = self._run({
            "osv": novelty._not_applicable("osv", "no package mapping"),
            "nvd": clean("nvd"), "ghsa": clean("github_advisories"),
            "commits": clean("github_commits"), "code": clean("github_code"), "vendor": clean("vendor"),
        })
        self.assertEqual(result["verdict"], "inconclusive")

    def test_inconclusive_offline_cache_miss(self):
        cache = novelty.Cache(Path(tempfile.mkdtemp()))
        http = novelty.Http(cache, offline=True)
        result = novelty.check_entry(self.entry, cache=cache, http=http)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertTrue(any("offline-cache-miss" in str(p.get("error") or p.get("detail"))
                            for p in result["providers"].values()))

    def test_known_public_short_circuits_without_network(self):
        entry = dict(self.entry)
        entry["known_public"] = ["CVE-2026-15978", "VU#281278"]
        result = novelty.check_entry(entry)
        self.assertEqual(result["verdict"], "already-public")
        self.assertIn("CVE-2026-15978", result["reason"])


class TestNoveltyProviders(unittest.TestCase):
    class FakeHttp:
        def __init__(self, body, status="ok"):
            self.body = body
            self.status = status
            self.calls = []

        def get(self, provider, url, **kwargs):
            self.calls.append((provider, url, kwargs))
            return {"status": self.status, "body": self.body, "url": url}

        def post(self, provider, url, payload, **kwargs):
            self.calls.append((provider, url, payload))
            return {"status": self.status, "body": self.body, "url": url}

    def test_osv_generic_package_hit_is_not_a_match(self):
        entry = {"id": "x", "component": "vllm", "root_cause": {"function": "unique_sink", "file": "a.py"}}
        http = self.FakeHttp({"vulns": [{"id": "GHSA-x", "summary": "vllm unrelated cache bug"}]})
        result = novelty.check_osv(entry, {"osv_package": "vllm", "osv_version": "0.32.0"}, http)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["matches"], [])

    def test_osv_strong_function_is_a_match(self):
        entry = {"id": "x", "component": "vllm", "root_cause": {"function": "unique_sink", "file": "a.py"}}
        http = self.FakeHttp({"vulns": [{"id": "GHSA-x", "summary": "unique_sink RCE"}]})
        result = novelty.check_osv(entry, {"osv_package": "vllm", "osv_version": "0.32.0"}, http)
        self.assertEqual(result["status"], "match")

    def test_nvd_requires_strong_term(self):
        entry = {"id": "x", "component": "vllm", "root_cause": {"function": "unique_sink", "file": "a.py"}}
        body = {"vulnerabilities": [{"cve": {"id": "CVE-2026-1", "descriptions": [
            {"lang": "en", "value": "vllm unrelated issue"}]}}]}
        result = novelty.check_nvd(entry, {"nvd_keywords": ["vllm"]}, self.FakeHttp(body))
        self.assertEqual(result["status"], "ok")
        body["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "vllm unique_sink command injection"
        result = novelty.check_nvd(entry, {"nvd_keywords": ["vllm"]}, self.FakeHttp(body))
        self.assertEqual(result["status"], "match")

    def test_github_commit_security_keyword(self):
        entry = {"id": "x", "component": "demo", "root_cause": {"function": "danger", "file": "a.py"}}
        body = {"items": [{"sha": "a" * 40, "html_url": "https://github.test/commit",
                           "commit": {"message": "fix: sanitize danger input (CVE-2026-1)"}}]}
        result = novelty.check_github_commits(entry, {"repo": "org/demo"}, self.FakeHttp(body))
        self.assertEqual(result["status"], "match")

    def test_github_commit_feature_without_security_keyword_is_clean(self):
        entry = {"id": "x", "component": "demo", "root_cause": {"function": "danger", "file": "a.py"}}
        body = {"items": [{"sha": "a" * 40, "html_url": "https://github.test/commit",
                           "commit": {"message": "add danger helper"}}]}
        result = novelty.check_github_commits(entry, {"repo": "org/demo"}, self.FakeHttp(body))
        self.assertEqual(result["status"], "ok")

    def test_github_commit_coauthored_is_not_auth_bypass(self):
        entry = {"id": "x", "component": "demo", "root_cause": {"function": "danger", "file": "a.py"}}
        body = {"items": [{"sha": "a" * 40, "html_url": "https://github.test/commit",
                           "commit": {"message": "add danger helper\n\nCo-authored-by: someone"}}]}
        result = novelty.check_github_commits(entry, {"repo": "org/demo"}, self.FakeHttp(body))
        self.assertEqual(result["status"], "ok")

    def test_osv_commit_query_used_without_version(self):
        captured = {}

        class FakePost:
            def post(self, provider, url, payload, **kwargs):
                captured.update(payload)
                return {"status": "ok", "body": {"vulns": []}}

        entry = {"id": "x", "component": "demo", "root_cause": {"function": "danger", "file": "a.py"}}
        result = novelty.check_osv(entry, {"osv_package": "demo", "osv_commit": "a" * 40}, FakePost())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(captured.get("commit"), "a" * 40)

    def test_grep_app_string_repo_shape(self):
        body = {"hits": {"hits": [
            {"repo": "org/fork", "path": "x.py",
             "content": {"snippet": "def danger(): exploit CVE-2026-1"}},
            {"repo": "demo/upstream", "path": "a.py", "content": {"snippet": "def danger()"}},
        ]}}
        http = self.FakeHttp(body)
        result = novelty._grep_app("danger", http, "demo/upstream")
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["matches"][0]["repo"], "org/fork")

    def test_vendor_weak_component_name_alone_is_clean(self):
        entry = {"id": "x", "component": "demo", "root_cause": {"function": "unique_sink", "file": "a.py"}}
        body = "GHSA-aaaa-bbbb-cccc demo release notes, many advisories"
        with patch.object(novelty.Http, "get", return_value={"status": "ok", "body": body, "url": "https://v"}):
            result = novelty.check_vendor(entry, {"vendor_urls": ["https://v"]}, novelty.Http(
                novelty.Cache(Path(tempfile.mkdtemp()))))
        self.assertEqual(result["status"], "ok")

    def test_vendor_404_is_not_applicable(self):
        entry = {"id": "x", "component": "demo", "root_cause": {"function": "danger", "file": "a.py"}}
        http = self.FakeHttp("", status="http-error")
        http.body = ""
        # Http.get returns http-status via the wrapper; emulate the 404 branch directly.
        with patch.object(novelty.Http, "get", return_value={"status": "http-error", "http_status": 404}):
            result = novelty.check_vendor(entry, {"vendor_urls": ["https://vendor.test/security"]}, novelty.Http(
                novelty.Cache(Path(tempfile.mkdtemp()))))
        self.assertEqual(result["status"], "not-applicable")

    def test_cache_roundtrip_and_expiry(self):
        with tempfile.TemporaryDirectory() as td:
            cache = novelty.Cache(Path(td), ttl_days=1)
            cache.put("osv", "k", {"status": "ok", "body": 1})
            self.assertEqual(cache.get("osv", "k")["body"], 1)
            path = next((Path(td) / "osv").glob("*.json"))
            data = json.loads(path.read_text(encoding="utf-8"))
            data["_cached_at"] = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertIsNone(cache.get("osv", "k"))


class TestNoveltyCli(unittest.TestCase):
    def test_cli_offline_without_cache_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as td:
            entry = {
                "id": "demo", "component": "demo", "title": "x",
                "root_cause": {"file": "a.py", "line": 1, "function": "danger"},
                "novelty": {"osv_package": "demo", "osv_version": "1.0", "repo": "org/demo"},
            }
            ep = Path(td) / "entry.json"
            ep.write_text(json.dumps(entry), encoding="utf-8")
            out = Path(td) / "out.json"
            rc = novelty.main(["--entry", str(ep), "--out", str(out), "--cache-dir", str(Path(td) / "cache"),
                               "--offline"])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["verdicts"]["demo"]["verdict"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
