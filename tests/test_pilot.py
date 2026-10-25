# -*- coding: utf-8 -*-
"""`trident pilot` 试点模式契约测试。

覆盖：
- kubeconfig 多文件/多 context/多 cluster 合并与冲突记录（stdlib YAML 解析路径）；
- 只读清点 → 环境画像 → 风险热图 → 分阶段测试计划 + 审批清单；
- 默认只读（mutations 必须为空），写计划需 `--allow-write` + 三闸门；
- 报告/清单落盘与 manifest 哈希可校验；
- CLI 退出码 0 / 91。
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core.evidence import EvidenceStore
from trident.core.roe import init_roe
from trident.core.users import Session
from trident.pilot import (
    PilotGateRefused,
    build_plan,
    build_profile,
    load_snapshot_bundle,
    merge_kubeconfigs,
    parse_kubeconfig,
    run_pilot,
)

REPO = Path(__file__).resolve().parents[1]
PY = sys.executable
FIXTURES = REPO / "lab" / "enterprise-fixtures"

KUBECONFIG_EAST = """apiVersion: v1
kind: Config
clusters:
- name: east-cluster
  cluster:
    server: https://east.example.test:6443
    insecure-skip-tls-verify: true
contexts:
- name: east-prod
  context:
    cluster: east-cluster
    user: east-user
    namespace: ml-inference
current-context: east-prod
users:
- name: east-user
  user:
    token: MOCK-EAST-TOKEN
"""

KUBECONFIG_WEST = """apiVersion: v1
kind: Config
clusters:
- name: west-cluster
  cluster:
    server: https://west.example.test:6443
contexts:
- name: west-prod
  context:
    cluster: west-cluster
    user: west-user
current-context: west-prod
users:
- name: west-user
  user:
    exec:
      command: mock-oidc-login
"""

KUBECONFIG_CONFLICT = """apiVersion: v1
kind: Config
clusters:
- name: east-cluster
  cluster:
    server: https://east-dr.example.test:6443
contexts:
- name: east-prod
  context:
    cluster: east-cluster
    user: east-user
users:
- name: east-user
  user:
    token: MOCK-CONFLICT-TOKEN
"""


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


class TestKubeconfig(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_stdlib_yaml(self):
        path = _write(self.root / "east.yaml", KUBECONFIG_EAST)
        doc = parse_kubeconfig(path, stdlib_only=True)
        self.assertEqual(doc["current-context"], "east-prod")
        self.assertEqual(doc["clusters"][0]["cluster"]["server"], "https://east.example.test:6443")
        self.assertEqual(doc["contexts"][0]["context"]["namespace"], "ml-inference")
        self.assertEqual(doc["users"][0]["user"]["token"], "MOCK-EAST-TOKEN")

    def test_parse_json_kubeconfig(self):
        doc = {
            "apiVersion": "v1", "kind": "Config", "current-context": "c1",
            "clusters": [{"name": "c1", "cluster": {"server": "https://one:6443"}}],
            "contexts": [{"name": "c1", "context": {"cluster": "c1", "user": "u1"}}],
            "users": [{"name": "u1", "user": {"token": "MOCK"}}],
        }
        path = _write(self.root / "kube.json", json.dumps(doc))
        self.assertEqual(parse_kubeconfig(path, stdlib_only=True)["clusters"][0]["name"], "c1")

    def test_merge_multi_file_multi_context(self):
        a = _write(self.root / "east.yaml", KUBECONFIG_EAST)
        b = _write(self.root / "west.yaml", KUBECONFIG_WEST)
        inv = merge_kubeconfigs([a, b])
        self.assertEqual(inv["context_count"], 2)
        self.assertEqual(inv["cluster_count"], 2)
        names = {c["name"] for c in inv["contexts"]}
        self.assertEqual(names, {"east-prod", "west-prod"})
        east = next(c for c in inv["contexts"] if c["name"] == "east-prod")
        self.assertEqual(east["server"], "https://east.example.test:6443")
        self.assertEqual(east["namespace"], "ml-inference")
        self.assertEqual(east["auth"], "token")
        west = next(c for c in inv["contexts"] if c["name"] == "west-prod")
        self.assertEqual(west["auth"], "exec")
        self.assertEqual(inv["conflicts"], [])

    def test_merge_records_conflict_without_losing_context(self):
        a = _write(self.root / "east.yaml", KUBECONFIG_EAST)
        c = _write(self.root / "east-dr.yaml", KUBECONFIG_CONFLICT)
        inv = merge_kubeconfigs([a, c])
        self.assertEqual(inv["context_count"], 1)
        self.assertGreaterEqual(len(inv["conflicts"]), 1)
        conflict = next(c for c in inv["conflicts"] if c["kind"] == "cluster")
        self.assertEqual(conflict["kind"], "cluster")
        self.assertEqual(conflict["name"], "east-cluster")
        self.assertEqual(set(conflict["servers"]),
                         {"https://east.example.test:6443", "https://east-dr.example.test:6443"})
        self.assertTrue(inv["warnings"])


class TestProfileAndPlan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.east = json.loads((FIXTURES / "clusters" / "east-prod.json").read_text(encoding="utf-8"))
        cls.west = json.loads((FIXTURES / "clusters" / "west-prod.json").read_text(encoding="utf-8"))
        cls.inv = merge_kubeconfigs([
            _write(root / "east.yaml", KUBECONFIG_EAST),
            _write(root / "west.yaml", KUBECONFIG_WEST),
        ])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_profile_has_heatmap_and_scale(self):
        profile = build_profile(self.inv, [
            {"context": "east-prod", "snapshot": self.east, "source": "fixture"},
            {"context": "west-prod", "snapshot": self.west, "source": "fixture"},
        ])
        self.assertEqual(profile["totals"]["clusters"], 2)
        self.assertGreaterEqual(profile["totals"]["nodes"], 10)
        self.assertGreaterEqual(profile["totals"]["gpu_nodes"], 2)
        self.assertGreaterEqual(len(profile["heatmap"]), 6)
        categories = {row["category"] for row in profile["heatmap"]}
        self.assertIn("身份与 RBAC", categories)
        self.assertIn("网络分区", categories)
        self.assertIn("模型与数据面", categories)
        for row in profile["heatmap"]:
            self.assertGreaterEqual(row["score"], 0)
            self.assertLessEqual(row["score"], 100)
            self.assertIn(row["level"], {"critical", "high", "medium", "low"})
        self.assertGreater(profile["totals"]["findings"], 0)

    def test_plan_default_is_read_only(self):
        profile = build_profile(self.inv, [{"context": "east-prod", "snapshot": self.east}])
        plan = build_plan(profile, self.inv, allow_write=False)
        self.assertTrue(plan["read_only"])
        self.assertFalse(plan["write_authorized"])
        self.assertEqual(plan["mutations"], [])
        self.assertEqual([p["id"] for p in plan["phases"]], ["P0", "P1", "P2", "P3"])
        write_phase = next(p for p in plan["phases"] if p["id"] == "P2")
        self.assertEqual(write_phase["mode"], "write")
        self.assertTrue(write_phase["blocked"])
        self.assertGreaterEqual(len(plan["approvals"]), 2)
        self.assertTrue(plan["rollback_plan"]["steps"])
        self.assertEqual(plan["metrics"]["read_only_pass_rate_target"], ">=95%")


class TestRunPilot(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.kube_a = _write(self.root / "east.yaml", KUBECONFIG_EAST)
        self.kube_b = _write(self.root / "west.yaml", KUBECONFIG_WEST)
        self.out = self.root / "pilot"
        self.store = EvidenceStore(self.root / "home", workspace="pilot")

    def tearDown(self):
        self.tmp.cleanup()

    def _snapshot_args(self):
        return [
            str(FIXTURES / "clusters" / "east-prod.json"),
            str(FIXTURES / "clusters" / "west-prod.json"),
        ]

    def test_default_read_only_outputs_and_manifest(self):
        res = run_pilot(
            kubeconfigs=[self.kube_a, self.kube_b],
            snapshot_paths=self._snapshot_args(),
            out_dir=self.out,
            workspace="pilot",
            actor="pilot-tester",
            role="auditor",
        )
        self.assertTrue(res["read_only"])
        self.assertEqual(res["mutations"], [])
        self.assertFalse(res["plan"]["write_authorized"])
        self.assertTrue((self.out / "pilot-report.json").is_file())
        self.assertTrue((self.out / "approvals.json").is_file())
        report = (self.out / "pilot-report.md").read_text(encoding="utf-8")
        for needle in ("环境画像", "风险热图", "建议测试计划", "审批清单", "回滚预案"):
            self.assertIn(needle, report)
        manifest = (self.out / "manifest.sha256").read_text(encoding="utf-8").splitlines()
        self.assertGreaterEqual(len(manifest), 3)
        for line in manifest:
            sha, rel = line.split("  ", 1)
            data = (self.out / rel).read_bytes()
            self.assertEqual(sha, hashlib.sha256(data).hexdigest(), rel)

    def test_write_requires_gate_and_refuses_without_roe(self):
        with self.assertRaises(PilotGateRefused) as ctx:
            run_pilot(
                kubeconfigs=[self.kube_a],
                snapshot_paths=[str(FIXTURES / "clusters" / "east-prod.json")],
                out_dir=self.out,
                allow_write=True,
                store=self.store,
                session=Session(None, "lead1", "lead", ["pilot"], "tok"),
            )
        self.assertEqual(getattr(ctx.exception, "exit_code", 0), 91)
        self.assertIn("授权", str(ctx.exception))

    def test_write_allowed_with_three_gates(self):
        init_roe(self.store, fields={
            "level": "利用验证",
            "namespaces": ["ml-inference", "ml-training", "tenant-a"],
            "cidrs": ["10.0.0.0/8"],
        })
        session = Session(None, "lead1", "lead", ["pilot"], "tok")
        res = run_pilot(
            kubeconfigs=[self.kube_a],
            snapshot_paths=[str(FIXTURES / "clusters" / "east-prod.json")],
            out_dir=self.out,
            allow_write=True,
            store=self.store,
            session=session,
        )
        self.assertTrue(res["plan"]["write_authorized"])
        self.assertTrue(res["plan"]["gate_receipts"]["consent"]["ok"])
        self.assertTrue(res["plan"]["gate_receipts"]["level"]["ok"])
        self.assertTrue(res["plan"]["gate_receipts"]["backup"]["ok"])
        self.assertTrue(res["read_only"], "pilot 自身仍不得执行写操作")
        self.assertEqual(res["mutations"], [])

    def test_snapshot_bundle_multi_cluster(self):
        bundle = load_snapshot_bundle(self._snapshot_args())
        self.assertEqual(len(bundle), 2)
        self.assertEqual({b["context"] for b in bundle}, {"east-prod", "west-prod"})

    def test_kubectl_collector_is_read_only_and_normalizes(self):
        script = self.root / "fake_kubectl.py"
        script.write_text(
            "import json,sys\n"
            "args=sys.argv[1:]\n"
            "if 'get' not in args:\n"
            "    sys.exit(3)\n"
            "res=args[args.index('get')+1]\n"
            "if res=='pods':\n"
            "    print(json.dumps({'items':[{'metadata':{'namespace':'ml-inference','name':'vllm'},"
            "'spec':{'containers':[{'name':'vllm','image':'vllm/vllm-openai'}]},"
            "'status':{'phase':'Running'}}]}))\n"
            "else:\n"
            "    print(json.dumps({'items':[]}))\n",
            encoding="utf-8",
        )
        from trident.pilot import KubectlCollector

        collector = KubectlCollector([PY, str(script)])
        snap = collector.collect(self.kube_a, "east-prod")
        self.assertEqual(snap["source"], "live-kubectl")
        self.assertEqual(snap["context"], "east-prod")
        self.assertEqual(len(snap["pods"]), 1)
        self.assertEqual(snap["pods"][0]["namespace"], "ml-inference")
        self.assertTrue(collector.calls)
        for call in collector.calls:
            self.assertIn("get", call["argv"])
            for forbidden in ("apply", "delete", "patch", "create", "replace", "exec"):
                self.assertNotIn(forbidden, call["argv"])

    def test_cli_read_only_and_write_gate(self):
        cmd = [PY, "-m", "trident", "--home", str(self.root / "home"), "pilot",
               "--kubeconfig", str(self.kube_a), "--kubeconfig", str(self.kube_b),
               "--snapshot", str(FIXTURES / "clusters" / "east-prod.json"),
               "--snapshot", str(FIXTURES / "clusters" / "west-prod.json"),
               "--out", str(self.out), "--format", "both"]
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        r = subprocess.run(cmd, cwd=str(REPO), capture_output=True, timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        self.assertTrue((self.out / "pilot-report.md").is_file())

        out2 = self.root / "pilot-write"
        cmd2 = cmd[:]
        cmd2[cmd2.index("--out") + 1] = str(out2)
        cmd2 += ["--allow-write", "--role", "lead", "--actor", "lead1"]
        r2 = subprocess.run(cmd2, cwd=str(REPO), capture_output=True, timeout=120, env=env)
        self.assertEqual(r2.returncode, 91, r2.stderr.decode("utf-8", "replace"))
        self.assertIn("授权", r2.stderr.decode("utf-8", "replace"))


if __name__ == "__main__":
    unittest.main()
