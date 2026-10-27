# -*- coding: utf-8 -*-
"""Session entry modes, probe registry/tree, bootstrap adapters and manifests."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from inkblade import session as session_mod
from inkblade.channel import ProbeConnection
from inkblade.core.evidence import EvidenceStore
from inkblade.core.probes import ProbeController, ProbeRegistry
from inkblade.core.roe import ExecutionLocked, init_roe
from inkblade.entry.external import recon as external_recon
from inkblade.entry.base import build_upload_plan, deploy_probe, ExecResult
from inkblade.entry.rce import deploy as deploy_rce, executor_for
from inkblade.entry.sa import SaTokenProbe, deploy_sa
from inkblade.probe.deploy import (
    ProbeDeploySpec,
    ephemeral_manifest,
    job_manifest,
    pod_manifest,
)

FAKE = Path(__file__).with_name("fake_probe.py")


def _store(root: Path) -> EvidenceStore:
    store = EvidenceStore(root, workspace="lab")
    init_roe(store, {
        "level": "全影响演示", "namespaces": ["default", "train"],
        "cidrs": ["127.0.0.0/8", "10.0.0.0/8"],
        "window": {"start": "2026-01-01", "end": "2027-12-31"},
    })
    return store


class TestSessionModes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = _store(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_kubeconfig_session(self):
        cfg = self.root / "kubeconfig"
        cfg.write_text("apiVersion: v1\n", encoding="utf-8")
        sess = session_mod.open_session(
            self.store, "kubeconfig", kubeconfig=str(cfg), namespace="default",
            actor="lead", role="lead",
        )
        self.assertEqual(sess.state, "ready")
        self.assertEqual(sess.entry_vector, "kubeconfig")
        self.assertTrue(sess.credential_fingerprint)
        self.assertEqual(session_mod.load(self.store, sess.id).mode, "kubeconfig")
        rows = self.store.open_run(sess.run).query("SELECT action,result FROM actions")
        self.assertTrue(any("session.ready" in str(row[0]) for row in rows))
        session_mod.close_session(self.store, sess)

    def test_external_requires_proof_and_foothold_before_exploit(self):
        sess = session_mod.open_session(
            self.store, "external", target="http://127.0.0.1:8000",
            namespace="default", chain="ray-dashboard-job",
            recon_result={"reachable": True, "vulnerable": True, "version": "2.10.0",
                          "evidence": {"url": "http://127.0.0.1:8000", "status": 200}},
        )
        self.assertEqual(sess.state, "vulnerable")
        with self.assertRaises(session_mod.SessionLocked):
            session_mod.mark_foothold(self.store, sess, vector="rce", proof={})
        session_mod.mark_foothold(
            self.store, sess, vector="rce",
            proof={"evidence": {"job": "j1"}, "sha256": "a" * 64},
        )
        self.assertTrue(sess.has_foothold)
        self.assertEqual(sess.state, "foothold")
        session_mod.close_session(self.store, sess)

    def test_external_unreachable_stays_recon(self):
        sess = session_mod.open_session(
            self.store, "external", target="http://127.0.0.1:8000",
            namespace="default", chain="ray-dashboard-job",
            recon_result={"reachable": False, "vulnerable": False,
                          "reason": "no answer"},
        )
        self.assertEqual(sess.state, "recon")
        self.assertFalse(sess.has_foothold)
        with self.assertRaises(ExecutionLocked):
            session_mod.require_foothold(sess)
        session_mod.close_session(self.store, sess)

    def test_external_no_foothold_refuses_write_module(self):
        sess = session_mod.open_session(
            self.store, "external", target="http://127.0.0.1:8000",
            namespace="default", chain="ray-dashboard-job",
            recon_result={"reachable": True, "vulnerable": True,
                          "evidence": {"status": 200}},
        )
        moddir = self.root / "modules" / "fake-write"
        moddir.mkdir(parents=True)
        (moddir / "module.json").write_text(json.dumps({
            "key": "fake-write", "name": {"zh": "x", "en": "x"}, "series": "横向利用",
            "description": "x", "min_level": "利用验证", "writes": True, "requires": [],
        }), encoding="utf-8")
        (moddir / "template.json").write_text(json.dumps({
            "schema": "inkblade-probe-template-v1", "key": "fake-write", "version": "1.0.0",
            "meta": {"name": {"zh": "x", "en": "x"}, "series": "横向利用",
                     "min_level": "利用验证", "writes": True},
            "steps": [{"id": "w", "op": "fs", "action": "write", "write": True,
                       "path": "/tmp/x", "content": "x"}],
        }), encoding="utf-8")
        user = SimpleNamespace(name="tester", role="tester", can=lambda action: True)
        with self.assertRaises(session_mod.SessionLocked):
            session_mod.run_module(
                self.store, sess, user, "fake-write", {},
                self.root / "modules",
            )

    def test_foothold_mode_requires_credential_source(self):
        with self.assertRaises(session_mod.SessionError):
            session_mod.open_session(
                self.store, "foothold", namespace="default", target="127.0.0.1",
                credential_source="",
            )
        sess = session_mod.open_session(
            self.store, "foothold", namespace="default", target="10.0.0.2",
            credential_source="sa-token", credential="jwt-value",
        )
        self.assertEqual(sess.state, "foothold")
        self.assertTrue(sess.credential_fingerprint)
        session_mod.close_session(self.store, sess)

    def test_template_module_runs_through_probe(self):
        import http.server
        import threading
        from inkblade.core.users import UserStore

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"object":"list"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{httpd.server_port}"
        cfg = self.root / "k"
        cfg.write_text("x", encoding="utf-8")
        sess = session_mod.open_session(
            self.store, "kubeconfig", kubeconfig=str(cfg), namespace="default",
            actor="tester", role="tester",
        )
        mod = self.root / "modules" / "demo"
        mod.mkdir(parents=True)
        raw = {"key": "demo", "name": {"zh": "x", "en": "x"}, "series": "侦察",
               "description": "x", "min_level": "只读侦察", "writes": False,
               "requires": []}
        (mod / "module.json").write_text(json.dumps(raw), encoding="utf-8")
        template = {
            "schema": "inkblade-probe-template-v1", "key": "demo", "version": "1.0.0",
            "meta": {"name": {"zh": "x", "en": "x"}, "series": "侦察",
                     "min_level": "只读侦察", "writes": False},
            "inputs": {"target": {"from": "params.target"}},
            "steps": [{"id": "g", "op": "http", "method": "GET",
                       "url": "{{input.target}}/", "expect": {"status": [200]}}],
            "findings": [{"id": "f", "when": "steps.g.status == 200",
                          "sev": "medium", "title": "ok"}],
        }
        (mod / "template.json").write_text(json.dumps(template), encoding="utf-8")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["lab"])
        user = users.verify("tester", "x")
        probe = ProbeConnection(
            [sys.executable, str(FAKE), "--token", "t"], "t",
            env={"FAKE_PROBE_ID": "p"},
        ).start()
        controller = ProbeController(self.store)
        try:
            controller.add("p", probe, session_id=sess.id, namespace="default")
            session_mod.register_probe(self.store, sess, probe_id="p", actor="tester")
            result = session_mod.run_module(
                self.store, sess, user, "demo", {"target": url},
                self.root / "modules", controller=controller,
            )
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["findings"][0]["title"], "ok")
            self.assertIn("probe[rust]", result["summary"])
        finally:
            controller.close()
            httpd.shutdown()


class TestProbeRegistry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = _store(Path(self.tmp.name))
        self.registry = ProbeRegistry(self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parent_child_tree(self):
        self.registry.register("p", session_id="s1", caps=["collect"])
        self.registry.register("c", parent_id="p", session_id="s1", caps=["exec"])
        self.registry.register("g", parent_id="c", session_id="s1")
        self.assertEqual([row["probe_id"] for row in self.registry.tree("p")], ["p", "c", "g"])
        self.assertEqual([row["probe_id"] for row in self.registry.cleanup_order("p")], ["g", "c", "p"])
        self.assertEqual(len(self.registry.list(session_id="s1")), 3)
        self.registry.mark_offline("g")
        self.assertEqual(self.registry.get("g")["status"], "offline")

    def test_controller_spawn_and_cleanup_tree(self):
        parent = ProbeConnection(
            [sys.executable, str(FAKE), "--token", "t"], "t",
            env={"FAKE_PROBE_ID": "parent"},
        ).start()
        controller = ProbeController(self.store)
        try:
            controller.add("parent", parent, session_id="s")
            remote = str(Path(tempfile.gettempdir()) / "inkblade-probe-child-test")
            spawned = controller.spawn("parent", b"\x7fELFfake", probe_id="child",
                                       remote_path=remote)
            self.assertEqual(spawned["probe_id"], "child")
            tree = controller.registry.tree("parent")
            self.assertEqual([row["probe_id"] for row in tree], ["parent", "child"])
            receipts = controller.cleanup("parent", recursive=True)
            self.assertEqual([r["probe_id"] for r in receipts], ["child", "parent"])
            self.assertTrue(all(r["ok"] for r in receipts))
        finally:
            controller.close()

    def test_task_records(self):
        parent = ProbeConnection(
            [sys.executable, str(FAKE), "--token", "t"], "t",
            env={"FAKE_PROBE_ID": "parent"},
        ).start()
        try:
            controller = ProbeController(self.store)
            controller.add("parent", parent, session_id="s")
            result = controller.exec("parent", [sys.executable, "-c", "print(3)"])
            self.assertEqual(result["exit_code"], 0)
            tasks = controller.registry.tasks(probe_id="parent")
            self.assertTrue(any(t["kind"] == "exec" and t["status"] == "success" for t in tasks))
            controller.close()
        finally:
            pass

    def test_task_translation_and_dispatch(self):
        from inkblade.core.probe_task import (
            ProbeTask,
            ProbeTaskDispatcher,
            UnsupportedTask,
            translate_action,
            upload_task,
        )

        self.assertEqual(translate_action("http", {"url": "http://x"})["steps"][0]["op"], "http")
        with self.assertRaises(UnsupportedTask):
            translate_action("python", {"code": "print(1)"})
        with self.assertRaises(UnsupportedTask):
            translate_action("shell", {"command": "id"})
        self.assertEqual(len(upload_task("/tmp/x", b"abc", chunk_size=2)), 2)
        parent = ProbeConnection(
            [sys.executable, str(FAKE), "--token", "t"], "t",
            env={"FAKE_PROBE_ID": "parent"},
        ).start()
        dispatcher = ProbeTaskDispatcher(self.store)
        try:
            dispatcher.register("parent", parent, session_id="s")
            task = ProbeTask(kind="template", probe_id="parent",
                             payload={"template": {"name": "x", "steps": []}, "params": {}})
            result = dispatcher.dispatch("parent", task)
            self.assertTrue(result["ok"])
            row = dispatcher.registry.task(task.task_id)
            self.assertEqual(row["status"], "success")
        finally:
            parent.close()


class TestEntryAdapters(unittest.TestCase):
    def test_upload_plan_and_dry_run(self):
        plan = build_upload_plan(b"probe-binary" * 200)
        self.assertTrue(plan.remote_path.startswith("/tmp/.inkblade-probe-"))
        self.assertGreater(plan.chunks, 1)
        self.assertIn("chmod 0700", plan.commands[-1])
        calls = []

        class Executor:
            def run(self, command, timeout=30):
                calls.append(command)
                return ExecResult(exit_code=0)

        receipt = deploy_probe(Executor(), b"probe-binary" * 20, dry_run=True)
        self.assertTrue(receipt["dry_run"])
        self.assertEqual(calls, [])
        receipt = deploy_probe(Executor(), b"probe-binary" * 20)
        self.assertGreater(receipt["executed"], 1)
        self.assertEqual(len(calls), receipt["executed"])
        self.assertIn("chmod 0700", calls[-1])

    def test_rce_callback_and_dry_run(self):
        calls = []

        def callback(command, timeout):
            calls.append((command, timeout))
            return {"exit_code": 0, "stdout": "ok"}

        result = deploy_rce("custom-chain", "http://127.0.0.1", b"x" * 4096,
                            callback=callback, dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(calls, [])
        result = deploy_rce("custom-chain", "http://127.0.0.1", b"x" * 4096,
                            callback=callback)
        self.assertGreater(result["executed"], 0)
        self.assertGreater(len(calls), 0)
        self.assertEqual(executor_for("ray-dashboard-job", "http://127.0.0.1").__class__.__name__,
                         "RayDashboardExecutor")

    def test_sa_token_fake_kubectl(self):
        commands = []

        def runner(args, input_data=None, env=None):
            commands.append(list(args))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        entry = SaTokenProbe(
            namespace="default", pod="p", token="sa-token", server="https://k8s:6443",
            runner=runner, create_pod=False,
        )
        try:
            foothold = entry.deploy(b"probe", probe_token="probe-token")
        finally:
            entry.close()
        self.assertEqual(foothold.pod, "p")
        self.assertTrue(any("cp" in cmd for cmd in commands))
        self.assertTrue(any("chmod" in cmd for cmd in commands))
        self.assertIn("/tmp/.inkblade-probe", foothold.probe_path)
        self.assertTrue(foothold.channel_command())

    def test_manifest_security_defaults(self):
        spec = ProbeDeploySpec(namespace="default", name="p", token_secret="probe-token")
        pod = pod_manifest(spec)
        spec_doc = pod["spec"]
        self.assertFalse(spec_doc["automountServiceAccountToken"])
        self.assertEqual(spec_doc["securityContext"]["runAsUser"], 65532)
        container = spec_doc["containers"][0]
        self.assertFalse(container["securityContext"]["privileged"])
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertFalse(any("hostPath" in volume for volume in spec_doc["volumes"]))
        job = job_manifest(spec)
        self.assertEqual(job["spec"]["template"]["spec"]["restartPolicy"], "Never")
        eph = ephemeral_manifest(spec, target_pod="target")
        self.assertIn("ephemeralContainers", eph["spec"])
        with self.assertRaises(Exception):
            ProbeDeploySpec(host_path="/var/run/docker.sock").validate()
        with self.assertRaises(Exception):
            pod_manifest(ProbeDeploySpec(host_path="/tmp", allow_host_path=False))

    def test_external_recon_proves_version(self):
        responses = {
            "/api/version": {"status": 200, "body": '{"version":"2.10.0"}'},
            "/api/jobs/": {"status": 200, "body": "[]"},
        }

        def fetch(url):
            path = "/api/version" if url.endswith("/api/version") else "/api/jobs/"
            return {"url": url, **responses[path]}

        proof = external_recon("http://127.0.0.1:8000", "ray-dashboard-job", fetch=fetch)
        self.assertTrue(proof["reachable"])
        self.assertTrue(proof["vulnerable"])
        self.assertEqual(proof["version"], "2.10.0")
        self.assertTrue(proof["not_a_scan"])
        fixed = external_recon(
            "http://127.0.0.1:8000", "ray-dashboard-job",
            fetch=lambda url: {"url": url, "status": 200, "body": '{"version":"2.60.0"}'},
        )
        self.assertFalse(fixed["vulnerable"])


if __name__ == "__main__":
    unittest.main()
