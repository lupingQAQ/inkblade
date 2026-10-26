# -*- coding: utf-8 -*-
"""企业集成适配层契约测试（无真实 IdP / SIEM / ITSM）。

- OIDC/LDAP：本地 mock，明确标注不可当作生产身份源；
- Splunk HEC / Elastic _bulk / Webhook HMAC / Jira / ServiceNow：真实本地 HTTP 收包，
  断言路径、认证头、正文格式与幂等字段；
- 双签审批链 + 报告哈希/时间戳/签核 + 保留策略。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.enterprise.approval import ApprovalChain, ApprovalError
from inkblade.enterprise.auth import AuthError, LDAPAdapter, MockLDAPDirectory, OIDCAdapter
from inkblade.enterprise.report_signing import (
    SignoffError,
    create_signoff,
    retention_plan,
    sign_report,
    verify_report,
)
from inkblade.enterprise.siem import (
    DeliveryError,
    ElasticBulk,
    JiraSink,
    ServiceNowSink,
    SplunkHEC,
    WebhookSink,
)
from inkblade.export import build_ocsf

FINDINGS = [
    {"step_key": "rbac-mapping", "severity": "critical", "title": "cluster-admin binding",
     "detail": "tenant-a SA bound to cluster-admin", "evidence_path": "steps/rbac.tar.gz"},
    {"step_key": "exposure-mapping", "severity": "medium", "title": "NodePort exposed",
     "detail": "vllm NodePort 30001", "evidence_path": "steps/exp.tar.gz"},
]


def _ocsf() -> dict:
    return build_ocsf(FINDINGS, {"workspace": "pilot", "run": "run-1",
                                 "generated_at": "2026-10-26T00:00:00Z"})


class _Capture:
    """真实本地 HTTP 收包器：记录 method/path/headers/body。"""

    def __init__(self, status: int = 200, response: dict | None = None):
        self.requests: list[dict] = []
        self.status = status
        self.response = response or {"ok": True}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                outer.requests.append({
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body,
                })
                data = json.dumps(outer.response).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestOIDC(unittest.TestCase):
    def setUp(self):
        self.adapter = OIDCAdapter(
            issuer="https://mock-idp.inkblade.local",
            audience="inkblade-pilot",
            secret=b"mock-oidc-secret-32-bytes-long!!",
        )

    def test_verify_and_group_role_mapping(self):
        token = self.adapter.issue_mock_token("alice", ["inkblade-leads"],
                                              ttl=300, nonce="n-1")
        ident = self.adapter.verify(token, nonce="n-1")
        self.assertEqual(ident["subject"], "alice")
        self.assertEqual(ident["role"], "lead")
        self.assertEqual(ident["mode"], "mock-hs256")
        self.assertIn("mock", ident["boundary"])

    def test_rejects_bad_audience_nonce_expiry_and_tamper(self):
        token = self.adapter.issue_mock_token("bob", ["inkblade-testers"], ttl=300)
        with self.assertRaises(AuthError):
            self.adapter.verify(token, audience="other")
        with self.assertRaises(AuthError):
            self.adapter.verify(token, nonce="nope")
        expired = self.adapter.issue_mock_token("bob", ["inkblade-testers"], ttl=-120)
        with self.assertRaises(AuthError):
            self.adapter.verify(expired)
        header, payload, sig = token.split(".")
        tampered = header + "." + payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB") + "." + sig
        with self.assertRaises(AuthError):
            self.adapter.verify(tampered)

    def test_unknown_group_has_no_role(self):
        token = self.adapter.issue_mock_token("eve", ["random-group"], ttl=300)
        ident = self.adapter.verify(token)
        self.assertEqual(ident["role"], "auditor", "缺省最小权限应为 auditor")
        self.assertTrue(ident["least_privilege"])

    def test_identity_to_platform_session(self):
        from inkblade.enterprise.auth import session_from_identity

        token = self.adapter.issue_mock_token("alice", ["inkblade-leads"], ttl=300)
        session = session_from_identity(self.adapter.verify(token), workspaces=["pilot"])
        self.assertEqual(session.role, "lead")
        self.assertTrue(session.can("approve"))
        self.assertEqual(session.workspaces, ["pilot"])


class TestLDAP(unittest.TestCase):
    def setUp(self):
        self.directory = MockLDAPDirectory()
        self.directory.add_user("uid=alice,ou=people,dc=inkblade,dc=local", "S3cret!",
                                ["inkblade-leads"], display="Alice")
        self.directory.add_user("uid=disabled,ou=people,dc=inkblade,dc=local", "S3cret!",
                                ["inkblade-admins"], disabled=True)
        self.adapter = LDAPAdapter(self.directory)

    def test_bind_and_group_mapping(self):
        ident = self.adapter.authenticate("alice", "S3cret!")
        self.assertEqual(ident["subject"], "alice")
        self.assertEqual(ident["role"], "lead")
        self.assertEqual(ident["mode"], "mock-ldap")
        self.assertIn("mock", ident["boundary"])

    def test_rejects_wrong_password_disabled_and_injection(self):
        with self.assertRaises(AuthError):
            self.adapter.authenticate("alice", "wrong")
        with self.assertRaises(AuthError):
            self.adapter.authenticate("disabled", "S3cret!")
        with self.assertRaises(AuthError):
            self.adapter.authenticate("a*)(uid=*", "S3cret!")
        with self.assertRaises(AuthError):
            self.adapter.authenticate("alice", "S3cret!\x00")
        with self.assertRaises(AuthError):
            self.adapter.authenticate("uid=alice,ou=people,dc=inkblade,dc=local", "S3cret!")


class TestSIEMAdapters(unittest.TestCase):
    def test_splunk_hec_contract(self):
        with _Capture() as cap:
            sink = SplunkHEC(cap.url, "Splunk-MOCK-TOKEN", index="inkblade")
            res = sink.send(_ocsf())
        self.assertTrue(res["ok"])
        req = cap.requests[0]
        self.assertEqual(req["path"], "/services/collector/event")
        self.assertEqual(req["headers"]["authorization"], "Splunk Splunk-MOCK-TOKEN")
        self.assertEqual(req["headers"]["content-type"], "application/json")
        lines = [ln for ln in req["body"].decode().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["index"], "inkblade")
        self.assertEqual(first["event"]["class_uid"], 2004)
        self.assertEqual(res["sent"], 2)

    def test_elastic_bulk_contract(self):
        with _Capture(response={"errors": False, "items": [{}, {}]}) as cap:
            sink = ElasticBulk(cap.url, index="inkblade-findings", api_key="MOCK-API-KEY")
            res = sink.send(_ocsf())
        self.assertTrue(res["ok"])
        req = cap.requests[0]
        self.assertEqual(req["path"], "/_bulk")
        self.assertEqual(req["headers"]["authorization"], "ApiKey MOCK-API-KEY")
        self.assertTrue(req["headers"]["content-type"].startswith("application/x-ndjson"))
        lines = [ln for ln in req["body"].decode().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 4)
        action = json.loads(lines[0])
        self.assertEqual(action["index"]["_index"], "inkblade-findings")
        self.assertIn("finding_info", json.loads(lines[1]))
        self.assertEqual(res["sent"], 2)

    def test_webhook_hmac_contract(self):
        secret = b"webhook-mock-secret"
        with _Capture() as cap:
            sink = WebhookSink(cap.url, secret=secret)
            res = sink.send(_ocsf())
        self.assertTrue(res["ok"])
        req = cap.requests[0]
        body = req["body"]
        sig = req["headers"]["x-inkblade-signature"]
        expect = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        self.assertEqual(sig, expect)
        self.assertIn("x-inkblade-timestamp", req["headers"])
        doc = json.loads(body)
        self.assertEqual(doc["schema"], "inkblade.webhook/1")
        self.assertEqual(doc["count"], 2)
        self.assertTrue(sink.verify(body, sig, req["headers"]["x-inkblade-timestamp"]))

    def test_jira_and_servicenow_payload_contract(self):
        finding = FINDINGS[0]
        jira = JiraSink("http://127.0.0.1:1", token="MOCK")
        payload = jira.build(finding, run="run-1")
        self.assertIn("fields", payload)
        self.assertIn("[InkBlade][critical]", payload["fields"]["summary"])
        self.assertEqual(payload["fields"]["priority"]["name"], "Highest")
        snow = ServiceNowSink("http://127.0.0.1:1", token="MOCK")
        inc = snow.build(finding, run="run-1")
        self.assertEqual(inc["severity"], "1")
        self.assertEqual(inc["correlation_id"], payload["fields"]["labels"][3][3:])
        self.assertIn("InkBlade", inc["short_description"])
        with self.assertRaises(DeliveryError):
            SplunkHEC("http://127.0.0.1:1", "")


class TestApprovalChain(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.path = Path(self.tmp.name) / "approvals.json"
        self.chain = ApprovalChain(self.path, require_dual=True, ttl=3600)

    def tearDown(self):
        self.tmp.cleanup()

    def test_dual_sign_order_same_person_and_chain(self):
        req = self.chain.request("execute-write-chain", requester="tester1", run="run-1")
        self.assertEqual(req["required_roles"], ["lead", "security-owner"])
        with self.assertRaises(ApprovalError):
            self.chain.sign(req["id"], approver="sec1", role="security-owner")
        self.chain.sign(req["id"], approver="lead1", role="lead", comment="window ok")
        with self.assertRaises(ApprovalError):
            self.chain.sign(req["id"], approver="lead1", role="lead")
        with self.assertRaises(ApprovalError):
            self.chain.sign(req["id"], approver="tester1", role="security-owner")
        done = self.chain.sign(req["id"], approver="sec1", role="security-owner")
        self.assertEqual(done["status"], "approved")
        self.assertTrue(self.chain.verify(req["id"])["ok"])
        reloaded = ApprovalChain(self.path)
        self.assertTrue(reloaded.verify(req["id"])["ok"])

    def test_tamper_detected(self):
        req = self.chain.request("x", requester="tester1")
        self.chain.sign(req["id"], approver="lead1", role="lead")
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        doc["approvals"][0]["signatures"][0]["approver"] = "mallory"
        self.path.write_text(json.dumps(doc), encoding="utf-8")
        self.assertFalse(ApprovalChain(self.path).verify(req["id"])["ok"])

    def test_single_sign_switch(self):
        chain = ApprovalChain(self.path, require_dual=False)
        req = chain.request("read-only", requester="tester1")
        done = chain.sign(req["id"], approver="lead1", role="lead")
        self.assertEqual(done["status"], "approved")
        self.assertEqual(done["required_roles"], ["lead"])


class TestReportSigning(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.report = self.root / "pilot-report.md"
        self.report.write_text("# pilot\n\nsigned body\n", encoding="utf-8")
        self.key = b"report-signing-key-32-bytes-len!"

    def tearDown(self):
        self.tmp.cleanup()

    def test_hash_timestamp_and_tamper(self):
        sidecar = sign_report(self.report, signer="lead1", key=self.key)
        self.assertEqual(sidecar["sha256"], hashlib.sha256(self.report.read_bytes()).hexdigest())
        self.assertIn("signed_at", sidecar)
        self.assertEqual(sidecar["timestamp"]["source"], "local-clock")
        self.assertIn("RFC3161", sidecar["timestamp"]["note"])
        self.assertTrue(verify_report(self.report, sidecar, self.key)["ok"])
        self.report.write_text("tampered", encoding="utf-8")
        self.assertFalse(verify_report(self.report, sidecar, self.key)["ok"])

    def test_signoff_checklist_and_retention(self):
        with self.assertRaises(SignoffError):
            create_signoff(self.report, signers=[
                {"name": "lead1", "role": "lead"}, {"name": "sec1", "role": "security-owner"}],
                checklist={"scope": True}, key=self.key)
        sheet = create_signoff(
            self.report,
            signers=[{"name": "lead1", "role": "lead"},
                     {"name": "sec1", "role": "security-owner"}],
            checklist={"scope": True, "evidence_manifest": True, "findings_reviewed": True,
                       "fp_fn_reviewed": True, "data_handling": True, "rollback_verified": True},
            key=self.key,
        )
        self.assertEqual(sheet["status"], "signed")
        self.assertTrue(sheet["sha256"])
        self.assertEqual(sheet["signoff_id"].startswith("so-"), True)
        old = self.root / "old.log"
        old.write_text("x", encoding="utf-8")
        policy = retention_plan([self.report, old], now=time.time() + 400 * 86400,
                                retain_days=365, legal_hold=False)
        actions = {Path(a["path"]).name: a["action"] for a in policy["actions"]}
        self.assertEqual(actions["pilot-report.md"], "purge")
        held = retention_plan([self.report], now=time.time() + 400 * 86400,
                              retain_days=365, legal_hold=True)
        self.assertEqual(held["actions"][0]["action"], "hold")
        self.assertIn("legal hold", held["note"].lower())


if __name__ == "__main__":
    unittest.main()
