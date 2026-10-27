# -*- coding: utf-8 -*-
"""操作/文件访问审计与统一时间线（file_ops + timeline.json + 报告 + UI 数据）。

覆盖：
- 假探针 ``audit-exec`` 的 cat/echo 采样与 ``read-file``/``list-files``；
- file_ops 落库、step 关联、宿主路径拒绝；
- timeline 排序/字段契约/落盘；
- 报告「操作与文件访问台账」节、脱敏、SOC 审计键；
- WebUI 只读端点与静态导出内嵌。
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from inkblade.channel import ProbeConnection
from inkblade.core.evidence import EvidenceStore
from inkblade.core.fileaudit import (
    FileOpRecorder,
    UnsafePath,
    file_ops,
    record,
    safe_path,
)
from inkblade.core.probe_task import translate_action
from inkblade.core.roe import init_roe
from inkblade.core.timeline import (
    EVENT_KEYS,
    build_timeline,
    build_timeline_from_db,
    load_timeline,
    write_timeline,
)
from inkblade.core.users import UserStore
from inkblade.reports.render import render_pentest
from inkblade.webui.export_static import export_static, load_run_data
from inkblade.webui.server import make_server

ROOT = Path(__file__).resolve().parents[1]
FAKE = Path(__file__).with_name("fake_probe.py")
TOKEN = "file-audit-token"


def _probe() -> ProbeConnection:
    return ProbeConnection(
        [sys.executable, str(FAKE), "--token", TOKEN], TOKEN, timeout=15
    ).start()


def _store(tmp: Path) -> EvidenceStore:
    return EvidenceStore(tmp, workspace="local-lab")


class TestSensitivePaths(unittest.TestCase):
    def test_safe_path_allows_container_and_rejects_host_escape(self):
        self.assertEqual(safe_path("/etc/hostname"), (True, ""))
        self.assertEqual(safe_path("/proc/self/fd/3")[0], True)
        for bad in (
            "/proc/1/root/etc/shadow",
            "/host/proc/1/environ",
            "/var/lib/kubelet/pods",
            "/var/run/docker.sock",
            "/tmp/../../etc/passwd",
            "",
        ):
            with self.subTest(path=bad):
                ok, reason = safe_path(bad)
                self.assertFalse(ok, bad)
                self.assertTrue(reason)

    def test_record_refuses_out_of_scope_opened_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = _store(Path(tmp)).create_run("guard")
            with self.assertRaises(UnsafePath):
                record(run, op="exec", argv=["cat", "/proc/1/root/etc/shadow"],
                       opened_files=[{"path": "/proc/1/root/etc/shadow", "mode": "read"}])
            with self.assertRaises(UnsafePath):
                record(run, op="read", path="/var/lib/kubelet/pods/x")
            self.assertEqual(file_ops(run), [])

    def test_fake_probe_refuses_host_path(self):
        probe = _probe()
        try:
            with self.assertRaises(Exception) as ctx:
                probe.request("read-file", {"path": "/proc/1/root/etc/shadow"})
            self.assertIn("refusing", str(ctx.exception))
            with self.assertRaises(Exception):
                probe.list_files("/run/containerd")
        finally:
            probe.close()


class TestProbeAuditExec(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = _store(self.root)
        self.run = self.store.create_run("audit-run")
        self.probe = _probe()

    def tearDown(self):
        self.probe.close()
        self.tmp.cleanup()

    def test_cat_records_read_file_and_stdout_hash(self):
        target = self.root / "hello.txt"
        target.write_text("hello-file-audit\n", encoding="utf-8")
        payload = self.probe.audit_exec(["cat", str(target)])
        audit = payload["audit"]
        self.assertEqual(payload["exec"]["exit_code"], 0)
        self.assertIn("hello-file-audit", payload["exec"]["stdout"])
        self.assertGreater(audit["pid"], 0)
        self.assertEqual(len(audit["env_digest"]), 64)
        self.assertEqual(
            audit["stdout_hash"],
            hashlib.sha256(payload["exec"]["stdout"].encode("utf-8")).hexdigest(),
        )
        files = [entry for entry in audit["opened_files"] if entry["path"] == str(target)]
        self.assertEqual(len(files), 1, audit["opened_files"])
        self.assertEqual(files[0]["mode"], "read")
        self.assertEqual(files[0]["sha256"], hashlib.sha256(target.read_bytes()).hexdigest())

        self.run.add_step("s-cat", "cat hello.txt", {"actor": "tester"}, "ok")
        recorder = FileOpRecorder(self.run, step_key="s-cat", probe_id=self.probe.probe_id,
                                  namespace="train")
        recorder.exec(payload, ["cat", str(target)])
        rows = file_ops(self.run)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["op"], "exec")
        self.assertEqual(row["step_key"], "s-cat")
        self.assertIsNotNone(row["step_id"])
        self.assertEqual(row["probe_id"], self.probe.probe_id)
        self.assertEqual(row["namespace"], "train")
        self.assertEqual(row["argv"], ["cat", str(target)])
        self.assertEqual(row["exit_code"], 0)
        self.assertEqual(row["opened_files"][0]["path"], str(target))
        self.assertEqual(row["result"], "ok")

    def test_echo_records_no_opened_files(self):
        payload = self.probe.audit_exec(["echo", "audit", "ok"])
        self.assertEqual(payload["exec"]["stdout"].strip(), "audit ok")
        self.assertEqual(payload["audit"]["opened_files"], [])

    def test_explicit_read_and_list_are_recorded(self):
        target = self.root / "explicit.txt"
        target.write_text("explicit-body", encoding="utf-8")
        info = self.probe.read_file(str(target))
        self.assertEqual(info["size"], len("explicit-body"))
        self.assertEqual(info["sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
        listing = self.probe.list_files(str(self.root))
        self.assertGreaterEqual(listing["count"], 1)

        recorder = FileOpRecorder(self.run, step_key="", probe_id=self.probe.probe_id)
        recorder.file_read(str(target), data=target.read_bytes())
        recorder.file_list(str(self.root), listing["entries"])
        rows = file_ops(self.run)
        self.assertEqual([row["op"] for row in rows], ["read", "list"])
        self.assertEqual(rows[0]["sha256"], info["sha256"])
        self.assertEqual(rows[1]["size_bytes"], listing["count"])

    def test_unsupported_probe_is_marked_unsampled(self):
        recorder = FileOpRecorder(self.run, step_key="")
        recorder.exec({"exit_code": 0, "stdout": "x", "duration_ms": 3},
                      ["true"], supported=False)
        row = file_ops(self.run)[0]
        self.assertEqual(row["result"], "unsampled")
        self.assertIn("audit-exec", row["detail"])
        self.assertEqual(row["opened_files"], [])

    def test_probe_task_translation(self):
        task = translate_action("audit-exec", {"argv": ["cat", "/etc/hostname"],
                                               "cwd": "/tmp", "technique": "t1059"})
        step = task["steps"][0]
        self.assertEqual(step["op"], "audit-exec")
        self.assertEqual(step["cwd"], "/tmp")
        self.assertEqual(step["technique"], "t1059")
        self.assertEqual(translate_action("read-file", {"path": "/etc/hostname"})
                         ["steps"][0]["op"], "read-file")
        self.assertEqual(translate_action("list-files", {"path": "/tmp"})
                         ["steps"][0]["op"], "list-files")

    def test_template_exec_audit_links_after_add_step(self):
        """模板 exec 的审计先落库，add_step 后回填 step_id。"""
        from inkblade.tpl.execute import _record_file_ops

        class _Client:
            probe_id = "probe-template"

        class _Backend:
            client = _Client()

        payload = self.probe.audit_exec(["echo", "template-audit"])
        result = {"steps": [{"id": "e1", "op": "exec", **payload["exec"],
                             "audit": payload["audit"]}]}
        _record_file_ops(self.run, "module-x", _Backend(), result)
        row = file_ops(self.run)[0]
        self.assertEqual(row["probe_id"], "probe-template")
        self.assertEqual(row["step_key"], "module-x")
        self.assertIsNone(row["step_id"])
        self.run.add_step("module-x", "template", {"actor": "tester"}, "ok")
        row = file_ops(self.run)[0]
        self.assertIsNotNone(row["step_id"])


class TestTimeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = _store(self.root)
        self.run = self.store.create_run("timeline-run")

    def tearDown(self):
        self.tmp.cleanup()

    def _seed(self):
        self.run.add_step("s1", "cat /etc/hostname", {"actor": "tester"}, "ok")
        self.run.query("UPDATE steps SET started_at=?, finished_at=? WHERE step_key=?",
                       (100.0, 102.0, "s1"))
        record(self.run, op="exec", step_key="s1", argv=["cat", "/etc/hostname"],
               opened_files=[{"path": "/etc/hostname", "mode": "read", "size_bytes": 12,
                              "sha256": "b" * 64}],
               exit_code=0, stdout="box\n", duration_ms=11, ts=100.5)
        self.run.log_action("tester", "execute", "s1", {"path": "/tmp/out.txt"}, "success")
        self.run.query("UPDATE actions SET ts=?", (101.0,))
        self.run.add_finding("s1", "high", "文件可读", "detail", evidence_path="steps/s1.tar.gz")

    def test_events_sorted_and_contract_complete(self):
        self._seed()
        doc = build_timeline(self.run)
        self.assertEqual(doc["schema"], "inkblade-timeline-v1")
        self.assertEqual(doc["counts"]["step"], 1)
        self.assertEqual(doc["counts"]["file_op"], 1)
        self.assertEqual(doc["counts"]["exploit"], 1)
        kinds = [event["kind"] for event in doc["events"]]
        self.assertEqual(kinds[0], "step")
        for event in doc["events"]:
            for key in EVENT_KEYS:
                self.assertIn(key, event)
        times = [event["ts"] for event in doc["events"]]
        self.assertEqual(times, sorted(times))
        # 同 ts 时按 kind 优先级：step < exploit
        step = next(e for e in doc["events"] if e["kind"] == "step")
        exploit = next(e for e in doc["events"] if e["kind"] == "exploit")
        self.assertLessEqual(step["ts"], exploit["ts"])
        self.assertEqual(len(step["evidence_sha256"]), 64)
        # 文件事件带脱敏命令与文件清单
        file_event = next(e for e in doc["events"] if e["kind"] == "file_op")
        self.assertEqual(file_event["target"], "cat /etc/hostname")
        self.assertEqual(file_event["files"][0]["path"], "/etc/hostname")
        self.assertEqual(file_event["files"][0]["mode"], "read")
        self.assertEqual(file_event["detail"]["exit_code"], 0)

    def test_write_timeline_and_reload_from_db(self):
        self._seed()
        path = write_timeline(self.run)
        self.assertTrue(path.is_file())
        doc = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], "inkblade-timeline-v1")
        self.assertEqual(load_timeline(self.run.dir)["run"], "timeline-run")
        rebuilt = build_timeline_from_db(self.run.dir / "evidence.db", "timeline-run")
        self.assertEqual(len(rebuilt["events"]), len(doc["events"]))
        self.assertEqual([e["seq"] for e in rebuilt["events"]],
                         list(range(len(rebuilt["events"]))))

    def test_finalize_writes_timeline(self):
        self._seed()
        self.run.finalize_run()
        self.assertTrue((self.run.dir / "timeline.json").is_file())


class TestReportSection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = _store(self.root)
        self.run = self.store.create_run("report-run")
        self.run.add_step("s-cat", "cat hello.txt", {"actor": "tester"}, "ok")

    def tearDown(self):
        self.tmp.cleanup()

    def _record(self):
        recorder = FileOpRecorder(self.run, step_key="s-cat", probe_id="probe-1",
                                  namespace="train")
        recorder.exec({"exit_code": 0, "stdout": "hi\n", "duration_ms": 7, "cwd": "/work"},
                      ["cat", "/work/hello.txt"])
        recorder.exec({"exit_code": 0, "stdout": "", "duration_ms": 2},
                      ["env", "PASSWORD=abcd1234efgh"])
        recorder.file_read("/work/hello.txt", data=b"hi\n")

    def test_section_present_with_soc_keys_and_redaction(self):
        self._record()
        text = render_pentest(self.store, "report-run", lang="zh")
        self.assertIn("操作与文件访问台账", text)
        self.assertIn("auditd", text)
        self.assertIn("falco", text.lower())
        self.assertIn("opentelemetry", text.lower())
        self.assertIn("/work/hello.txt", text)
        self.assertNotIn("abcd1234efgh", text)
        self.assertIn("****efgh", text)
        en = render_pentest(self.store, "report-run", lang="en")
        self.assertIn("Operation and File-Access Ledger", en)

    def test_section_without_events_is_explicit(self):
        text = render_pentest(self.store, "report-run", lang="zh")
        self.assertIn("操作与文件访问台账", text)
        self.assertIn("未记录文件/操作审计事件", text)


def _req(method, url, token=None, body=None, timeout=10):
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=payload, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


class TestWebUIData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        users = UserStore(cls.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        cls.users = users
        store = EvidenceStore(cls.root, workspace="local-lab")
        init_roe(store, fields={"level": "利用验证", "namespaces": ["train"],
                               "cidrs": ["127.0.0.0/8"], "client": "file-audit-test"})
        run = store.create_run("ui-run")
        run.add_step("s1", "cat /etc/hostname", {"actor": "tester"}, "ok")
        record(run, op="exec", step_key="s1", probe_id="probe-1", namespace="train",
               argv=["cat", "/etc/hostname"],
               opened_files=[{"path": "/etc/hostname", "mode": "read", "size_bytes": 12,
                              "sha256": "c" * 64}],
               exit_code=0, stdout="box\n", duration_ms=4)
        run.add_finding("s1", "high", "文件可读", "detail")
        run.finalize_run()
        cls.store = store
        cls.run_dir = run.dir
        cls.httpd = make_server(cls.root, users, port=0)
        cls.base = f"http://127.0.0.1:{cls.httpd.port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def _token(self):
        code, body = _req("POST", self.base + "/api/login",
                          body={"name": "tester", "password": "x"})
        self.assertEqual(code, 200, body)
        return body["token"]

    def test_timeline_endpoint(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/timeline?run=ui-run", token=token)
        self.assertEqual(code, 200, body)
        self.assertEqual(body["run"], "ui-run")
        self.assertGreaterEqual(body["count"], 3)
        kinds = {event["kind"] for event in body["events"]}
        self.assertEqual(kinds, {"step", "file_op", "exploit"})

    def test_file_ops_endpoint_filters_by_step(self):
        token = self._token()
        code, body = _req("GET", self.base + "/api/v1/file-ops?run=ui-run&step=s1",
                          token=token)
        self.assertEqual(code, 200, body)
        self.assertEqual(body["count"], 1)
        row = body["file_ops"][0]
        self.assertEqual(row["argv"], ["cat", "/etc/hostname"])
        self.assertEqual(row["opened_files"][0]["path"], "/etc/hostname")
        code, body = _req("GET", self.base + "/api/v1/file-ops?run=ui-run&step=other",
                          token=token)
        self.assertEqual((code, body["count"]), (200, 0))

    def test_static_export_embeds_timeline_and_ops(self):
        data = load_run_data(self.run_dir)
        self.assertEqual(data["timeline"]["schema"], "inkblade-timeline-v1")
        self.assertEqual(len(data["file_ops"]), 1)
        out = self.root / "static-out"
        target = export_static(self.run_dir, out)
        self.assertTrue((out / "timeline.json").is_file())
        html = target.read_text(encoding="utf-8")
        self.assertIn("INKBLADE_DATA", html)
        self.assertIn("ops-ledger", html)
        app_js = (out / "app.js").read_text(encoding="utf-8")
        self.assertIn("renderOpsLedger", app_js)
        self.assertIn("api/v1/timeline", app_js)
        self.assertIn('data-view="timeline"', html)


if __name__ == "__main__":
    unittest.main()
