# -*- coding: utf-8 -*-
"""本地多租户 SaaS：隔离/配额/审批原子性/多进程 worker/压测 smoke。"""

import json
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

from lab.saas.load import _req, run_load
from lab.saas.service import Service, _connect
from trident.core.evidence import EvidenceStore

TOK = "tok-tenant-00"
TOK1 = "tok-tenant-01"


class TestSaas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.svc = Service(Path(cls.tmp.name), tenants=8, workers=2, work_ms=20)
        cls.svc.configure_tenant("tenant-00", max_concurrent=2, max_runs=20,
                                 max_evidence_bytes=4096)
        cls.svc.configure_tenant("tenant-01", max_concurrent=2, max_runs=20,
                                 max_evidence_bytes=1024)
        cls.svc.start()
        cls.url = cls.svc.url

    @classmethod
    def tearDownClass(cls):
        cls.svc.stop()
        cls.tmp.cleanup()

    def setUp(self):
        conn = _connect(self.svc.db_path)
        try:
            conn.execute("DELETE FROM runs")
            conn.execute("DELETE FROM approvals")
            conn.commit()
        finally:
            conn.close()
        shutil.rmtree(self.svc.evidence_root, ignore_errors=True)
        self.svc.configure_tenant("tenant-00", max_concurrent=2, max_runs=20,
                                  max_evidence_bytes=4096, work_ms=20)
        self.svc.configure_tenant("tenant-01", max_concurrent=2, max_runs=20,
                                  max_evidence_bytes=1024, work_ms=20)

    def _submit(self, token=TOK, module="sim", evidence=2048):
        return _req(self.url, "POST", "/v1/runs", token,
                    {"module": module, "evidence_bytes": evidence})

    def _wait(self, rid, token=TOK, timeout=8):
        start = time.time()
        while time.time() - start < timeout:
            st, doc = _req(self.url, "GET", f"/v1/runs/{rid}", token)
            if doc.get("status") in ("done", "failed"):
                return st, doc
            time.sleep(0.01)
        return 0, {"status": "timeout"}

    def test_auth_required(self):
        self.assertEqual(_req(self.url, "GET", "/v1/runs")[0], 401)
        self.assertEqual(_req(self.url, "POST", "/v1/runs", None,
                              {"module": "x"})[0], 401)

    def test_login(self):
        st, doc = _req(self.url, "POST", "/v1/login", None,
                       {"tenant": "tenant-00", "token": TOK})
        self.assertEqual((st, doc["role"], doc["workspace"]), (200, "lead", "ws-tenant-00"))
        self.assertEqual(_req(self.url, "POST", "/v1/login", None,
                              {"tenant": "tenant-00", "token": "bad"})[0], 401)

    def test_tenant_isolation(self):
        st, doc = self._submit()
        self.assertEqual(st, 202)
        self._wait(doc["run_id"])
        self.assertEqual(_req(self.url, "GET", f"/v1/runs/{doc['run_id']}", TOK1)[0], 403)
        st, listing = _req(self.url, "GET", "/v1/runs", TOK1)
        self.assertTrue(all(r["tenant"] == "tenant-01" for r in listing["runs"]))

    def test_concurrency_quota(self):
        self.svc.configure_tenant("tenant-00", max_concurrent=1, work_ms=300)
        st1, d1 = self._submit()
        self.assertEqual(st1, 202)
        st2, d2 = self._submit()
        self.assertEqual(st2, 429)
        self.assertEqual(d2["quota"], "max_concurrent")
        self._wait(d1["run_id"])

    def test_run_quota(self):
        self.svc.configure_tenant("tenant-00", max_runs=1, max_concurrent=1)
        st1, d1 = self._submit()
        self.assertEqual(st1, 202)
        self._wait(d1["run_id"])
        st2, d2 = self._submit()
        self.assertEqual(st2, 429)
        self.assertEqual(d2["quota"], "max_runs")

    def test_evidence_quota(self):
        st, doc = self._submit(token=TOK1, evidence=2048)
        self.assertEqual(st, 429)
        self.assertEqual(doc["quota"], "max_evidence_bytes")

    def test_approval_role_gate(self):
        st, doc = _req(self.url, "POST", "/v1/approvals", "tok-tenant-tester",
                       {"action": "do-something"})
        self.assertEqual(st, 201)
        st2, _ = _req(self.url, "POST",
                      f"/v1/approvals/{doc['approval_id']}/approve",
                      "tok-tenant-tester", {})
        self.assertEqual(st2, 403)
        self.assertEqual(_req(self.url, "POST",
                              f"/v1/approvals/{doc['approval_id']}/approve", TOK, {})[0], 404)

    def test_approval_single_use(self):
        st, doc = _req(self.url, "POST", "/v1/approvals", TOK, {"action": "a"})
        self.assertEqual(st, 201)
        aid = doc["approval_id"]
        self.assertEqual(_req(self.url, "POST", f"/v1/approvals/{aid}/approve", TOK, {})[0], 200)
        self.assertEqual(_req(self.url, "POST", f"/v1/approvals/{aid}/approve", TOK, {})[0], 409)
        self.assertEqual(_req(self.url, "POST", f"/v1/approvals/{aid}/reject", TOK, {})[0], 409)

    def test_concurrent_duplicate_approval(self):
        st, doc = _req(self.url, "POST", "/v1/approvals", TOK, {"action": "race"})
        aid = doc["approval_id"]
        barrier = threading.Barrier(2)
        results: list[int] = []

        def approve():
            barrier.wait()
            results.append(_req(self.url, "POST", f"/v1/approvals/{aid}/approve", TOK, {})[0])

        threads = [threading.Thread(target=approve) for _ in range(2)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(sorted(results), [200, 409])

    def test_worker_completion_and_evidence(self):
        st, doc = self._submit(module="evidence", evidence=2048)
        self.assertEqual(st, 202)
        st2, run = self._wait(doc["run_id"])
        self.assertEqual((st2, run["status"]), (200, "done"))
        store = EvidenceStore(Path(self.tmp.name), workspace="ws-tenant-00")
        run_dir = store.open_run(f"saas-{doc['run_id']}")
        self.assertTrue((Path(run_dir.dir) / "artifact.bin").is_file())
        self.assertTrue(store.verify_manifest(f"saas-{doc['run_id']}"))
        content = (Path(run_dir.dir) / "artifact.bin").read_bytes()
        self.assertTrue(content.startswith(b"tenant=tenant-00 module=evidence"))

    def test_artifact_deterministic(self):
        _, d1 = self._submit(module="same", evidence=64)
        _, d2 = self._submit(module="same", evidence=64)
        self._wait(d1["run_id"])
        self._wait(d2["run_id"])
        base = Path(self.tmp.name) / "evidence" / "ws-tenant-00"
        a = (base / f"saas-{d1['run_id']}" / "artifact.bin").read_bytes()
        b = (base / f"saas-{d2['run_id']}" / "artifact.bin").read_bytes()
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_workspace_traversal_blocked(self):
        self.assertEqual(_req(self.url, "POST", "/v1/login", None,
                              {"tenant": "../evil", "token": "tok-../evil"})[0], 401)
        st, _ = _req(self.url, "POST", "/v1/runs", TOK,
                     {"module": "x", "workspace": "../ws-tenant-01", "evidence_bytes": 32})
        self.assertEqual(st, 403)

    def test_usage(self):
        st, doc = self._submit(module="usage", evidence=128)
        self._wait(doc["run_id"])
        st, usage = _req(self.url, "GET", "/v1/usage", TOK)
        self.assertEqual(st, 200)
        self.assertGreaterEqual(usage["runs_total"], 1)
        self.assertGreaterEqual(usage["done"], 1)
        self.assertEqual(usage["evidence_bytes"], 128)
        self.assertEqual(usage["limits"]["max_concurrent"], 2)

    def test_load_smoke_eight_tenants(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "load.json"
            doc = run_load(tenants=8, concurrency=4, requests=2, workers=2,
                           work_ms=5, out=out)
            self.assertTrue(out.is_file())
        self.assertEqual(doc["metrics"]["isolation_violations"], 0)
        self.assertGreater(doc["metrics"]["quota_rejects"], 0)
        self.assertTrue(doc["checks"]["tenant_isolation"])
        self.assertTrue(doc["checks"]["quota_enforced"])


if __name__ == "__main__":
    unittest.main()
