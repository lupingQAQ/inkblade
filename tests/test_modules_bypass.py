"""防护产品绕过模块族测试：每产品两态矩阵表驱动 + 良性探针无害性 + 契约集成。

安全边界（规格 5.2「防护产品绕过模块（v7）」）：
- 全部探针为技术类别级 benign marker，不含恶意载荷；
- 探针物化只允许写临时/授权 scratch 目录；
- 产出 = 每产品 检出/盲区 矩阵 + 硬化建议（findings.hardening，规则引擎消费）。
"""

import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core import defenseprobe as dp

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "inkblade" / "modules"
LAB_FIXTURES = REPO / "lab" / "defense-deploy" / "fixtures"

MODULE_KEYS = [
    "defense-bypass-elkeid",
    "defense-bypass-agentsmith",
    "defense-bypass-veinmind",
    "defense-bypass-falco",
    "defense-bypass-tetragon",
    "defense-bypass-kubearmor",
    "defense-bypass-admission",
    "defense-bypass-imagescan",
    "defense-bypass-hostagent",
    "defense-bypass-waf-inference",
    "defense-bypass-netobserv",
]

PRODUCTS = [k[len("defense-bypass-"):] for k in MODULE_KEYS]
DEGRADED_PRODUCTS = {"elkeid", "agentsmith", "falco", "tetragon", "hostagent"}


def _generic_cluster(extra: dict | None = None) -> dict:
    """不含任何目标产品的普通集群底噪（防误报）。"""
    snap = {
        "cluster": "kind-inkblade",
        "daemonsets": ["kube-system/kube-proxy", "kube-system/coredns"],
        "deployments": ["kube-system/coredns", "train/vllm-server"],
        "pods": ["train/vllm-server-0", "train/ray-worker-1"],
        "images": ["vllm/vllm-openai:latest", "rayproject/ray:2.9"],
        "rules": [],
        "configs": ["kubelet-config", "corefile"],
        "kernel_modules": ["nvml"],
        "agent_status": [],
        "kernel_params": [],
        "crds": ["rayclusters.ray.io"],
        "webhooks": [],
    }
    if extra:
        snap.update(extra)
    return snap


SNAPSHOTS = {
    "elkeid": {
        "deployed": {
            "cluster": "kind-inkblade",
            "daemonsets": ["kube-system/elkeid-agent", "kube-system/elkeid-manager"],
            "deployments": ["elkeid-system/elkeid-server", "elkeid-system/elkeid-web"],
            "images": ["elkeid/elkeid-agent:1.9.7"],
            "rules": ["elkeid-rule-host-2130", "elkeid-rule-container-2398"],
            "configs": ["elkeidup-agent-conf"],
            "kernel_modules": ["elkeid"],
        },
        "absent": _generic_cluster({"daemonsets": ["kube-system/kube-proxy", "kube-system/falco"]}),
    },
    "agentsmith": {
        "deployed": {
            "daemonsets": ["kube-system/agentsmith-agent"],
            "images": ["bytedance/agentsmith:latest"],
            "configs": ["agentsmith-agent-cfg"],
            "kernel_modules": ["smith"],
        },
        "absent": _generic_cluster(),
    },
    "veinmind": {
        "deployed": {
            "pods": ["inkblade-scan/veinmind-tools-abc12"],
            "images": [
                "chaitin/veinmind-tools:v2.0",
                "veinmind/veinmind-backdoor:v1",
                "veinmind/veinmind-weakpass:v1",
            ],
            "configs": ["veinmind-scanner-cfg"],
        },
        "absent": _generic_cluster(),
    },
    "falco": {
        "deployed": {
            "daemonsets": ["kube-system/falco"],
            "images": ["falcosecurity/falco:0.37.1"],
            "rules": ["falco_rules.yaml", "falco_rules.local.yaml"],
            "configs": ["/etc/falco/falco.yaml"],
            "kernel_modules": ["falco"],
        },
        "absent": _generic_cluster({"daemonsets": ["kube-system/kube-proxy", "kube-system/elkeid-agent"]}),
    },
    "tetragon": {
        "deployed": {
            "daemonsets": ["kube-system/tetragon"],
            "deployments": ["kube-system/tetragon-operator"],
            "images": ["cilium/tetragon:v1.3.0"],
            "crds": ["tracingpolicies.cilium.io"],
            "configs": ["tetragon-conf"],
            "kernel_params": ["lsm=bpf,integrity"],
        },
        "absent": _generic_cluster(),
    },
    "kubearmor": {
        "deployed": {
            "daemonsets": ["kube-system/kubearmor"],
            "deployments": ["kubearmor/kubearmor-operator"],
            "images": ["kubearmor/kubearmor:latest"],
            "crds": [
                "kubearmorpolicies.security.kubearmor.com",
                "kubearmorhostpolicies.security.kubearmor.com",
            ],
            "configs": ["kubearmor-file-posture=audit"],
        },
        "absent": _generic_cluster(),
    },
    "admission": {
        "deployed": {
            "deployments": ["kyverno/kyverno", "gatekeeper-system/gatekeeper-controller-manager"],
            "daemonsets": ["gatekeeper-system/gatekeeper-audit"],
            "images": ["kyverno/kyverno:v1.11.0", "openpolicyagent/gatekeeper:v3.15.0"],
            "crds": ["constrainttemplates.templates.gatekeeper.sh"],
            "webhooks": [
                "kyverno-resource-validating-webhook-cfg",
                "gatekeeper-validating-webhook-configuration",
            ],
            "rules": ["clusterpolicy/disallow-privileged-containers validationFailureAction=Audit"],
            "configs": ["kyverno-config"],
        },
        "absent": _generic_cluster(),
    },
    "imagescan": {
        "deployed": {
            "pods": ["scanning/trivy-scan-x7", "scanning/grype-scan-99"],
            "images": [
                "aquasecurity/trivy:0.50.0",
                "anchore/grype:v0.74.0",
                "chaitin/veinmind-tools:v2.0",
            ],
            "configs": ["trivy-config", "grype-db-cfg"],
        },
        "absent": _generic_cluster(),
    },
    "hostagent": {
        "deployed": {
            "daemonsets": ["kube-system/wazuh-agent"],
            "deployments": ["wazuh/wazuh-manager"],
            "images": ["wazuh/wazuh-agent:4.7.0", "osquery/osqueryd:5.9.1"],
            "rules": ["0020-syscheck_rules.xml", "0010-ossec_rules.xml"],
            "configs": ["ossec.conf", "osquery.conf", "osqueryd-packs"],
            "agent_status": ["online"],
        },
        "absent": _generic_cluster(),
    },
    "waf-inference": {
        "deployed": {
            "deployments": ["waf/safeline-tengine", "waf/coraza-spoa"],
            "images": [
                "chaitin/safeline-ce-waf:latest",
                "corazawaf/coraza-spoa:1.0",
                "owasp/modsecurity:2.9",
            ],
            "ingresses": ["inference/vllm-ingress modsecurity=on"],
            "rules": ["owasp-crs-3.3.2"],
            "configs": ["safeline-detector", "coraza-config"],
        },
        "absent": _generic_cluster(),
    },
    "netobserv": {
        "deployed": {
            "daemonsets": ["kube-system/cilium"],
            "deployments": [
                "kube-system/hubble-relay",
                "kube-system/hubble-ui",
                "calico-system/calico-typha",
            ],
            "images": ["cilium/hubble-relay:v1.15.0"],
            "configs": ["hubble-flowlogs"],
        },
        "absent": _generic_cluster({"daemonsets": ["kube-system/cilium", "kube-system/kube-proxy"]}),
    },
}

# 降级态 = 核心组件在、内核态/健康组件缺失
for _p in DEGRADED_PRODUCTS:
    _dep = json.loads(json.dumps(SNAPSHOTS[_p]["deployed"]))
    if _p == "falco":
        _dep["kernel_modules"] = []
        _dep["configs"] = ["falco-no-driver"]
    elif _p == "tetragon":
        _dep["kernel_params"] = ["lsm=integrity,apparmor"]
    elif _p == "hostagent":
        _dep["agent_status"] = ["offline"]
    else:
        _dep["kernel_modules"] = []
    SNAPSHOTS[_p]["degraded"] = _dep

# 默认规则集 fixture 的期望检出（部署态）；未列出的 technique = 盲区
EXPECTED_DETECTED = {
    "elkeid": {"monitored-path-write", "container-benign-write"},
    "agentsmith": {"monitored-path-write"},
    "veinmind": {"plain-layer-sample"},
    "falco": {"sensitive-path-access", "monitored-path-write"},
    "tetragon": {"lsm-hook-path", "exec-marker"},
    "kubearmor": {"posture-audit-path"},
    "admission": {"enforced-path"},
    "imagescan": {"plain-layer-sample"},
    "hostagent": {"monitored-path-write"},
    "waf-inference": {"plain-benign-request"},
    "netobserv": {"pod-path-flow"},
}


def _load_run(key: str):
    spec = importlib.util.spec_from_file_location(
        f"bypassmod_{key.replace('-', '_')}", MODULES_DIR / key / "run.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _techniques(product: str) -> set[str]:
    return {t["id"] for t in dp.PRODUCT_SPECS[product]["techniques"]}


class TestRegistryContract(unittest.TestCase):
    def test_eleven_modules_load(self):
        from inkblade.core.registry import load_modules

        mods = load_modules(MODULES_DIR)
        # inkblade/modules 为共享目录（并行任务会落其他系列）→ 断言本族 11 个全部注册且契约正确
        self.assertTrue(set(MODULE_KEYS) <= set(mods))
        for key in MODULE_KEYS:
            meta = mods[key]
            self.assertEqual(meta.key, key)
            self.assertEqual(meta.series, "横向利用")
            self.assertEqual(meta.min_level, "主动探测")
            self.assertFalse(meta.writes)  # 快照驱动的覆盖评估，不写目标面
            self.assertEqual(meta.requires, [])

class TestTwoStateMatrix(unittest.TestCase):
    """每产品：已部署(带规则集 fixture) vs 未部署/降级 两态矩阵。"""

    def _run_module(self, key: str, params: dict) -> dict:
        return _load_run(key).run({"store": None, "run": None, "marker": "test"}, params)

    def test_deployed_state(self):
        for key in MODULE_KEYS:
            product = key[len("defense-bypass-"):]
            with self.subTest(product=product):
                res = self._run_module(key, {"deploy_snapshot": SNAPSHOTS[product]["deployed"]})
                self.assertEqual(res["report"]["state"], "deployed")
                self.assertEqual(res["report"]["product"], product)
                expected = EXPECTED_DETECTED[product]
                self.assertEqual(set(res["report"]["detected"]), expected)
                self.assertEqual(set(res["report"]["blindspots"]), _techniques(product) - expected)
                self.assertTrue(res["report"]["hardening"])
                # 每个盲区 technique 都要有一条硬化规则文本
                joined = "\n".join(res["report"]["hardening"])
                for t in res["report"]["blindspots"]:
                    self.assertIn(t, joined)

    def test_absent_state(self):
        for key in MODULE_KEYS:
            product = key[len("defense-bypass-"):]
            with self.subTest(product=product):
                res = self._run_module(key, {"deploy_snapshot": SNAPSHOTS[product]["absent"]})
                rep = res["report"]
                self.assertEqual(rep["state"], "absent")
                self.assertEqual(rep["detected"], [])
                self.assertEqual(set(rep["blindspots"]), _techniques(product))
                joined = "\n".join(rep["hardening"])
                self.assertIn("state=absent", joined)

    def test_degraded_state_loses_driver_techniques(self):
        for key in MODULE_KEYS:
            product = key[len("defense-bypass-"):]
            if product not in DEGRADED_PRODUCTS:
                continue
            with self.subTest(product=product):
                res = self._run_module(key, {"deploy_snapshot": SNAPSHOTS[product]["degraded"]})
                rep = res["report"]
                self.assertEqual(rep["state"], "degraded")
                driver_techs = {
                    t["id"] for t in dp.PRODUCT_SPECS[product]["techniques"] if t.get("needs_driver")
                }
                self.assertTrue(driver_techs)
                self.assertTrue(driver_techs <= set(rep["blindspots"]))
                self.assertTrue(set(rep["detected"]) <= EXPECTED_DETECTED[product])
                joined = "\n".join(rep["hardening"])
                self.assertIn("state=degraded", joined)

    def test_state_override_param(self):
        res = self._run_module(
            "defense-bypass-elkeid",
            {"deploy_snapshot": SNAPSHOTS["elkeid"]["deployed"], "state": "absent"},
        )
        self.assertEqual(res["report"]["state"], "absent")


class TestSnapshotSources(unittest.TestCase):
    def test_deploy_snapshot_dict(self):
        mod = _load_run("defense-bypass-falco")
        res = mod.run({"run": None}, {"deploy_snapshot": SNAPSHOTS["falco"]["deployed"]})
        self.assertEqual(res["report"]["state"], "deployed")

    def test_fixture_file_source(self):
        mod = _load_run("defense-bypass-elkeid")
        fixture = LAB_FIXTURES / "elkeid-deployed.json"
        self.assertTrue(fixture.exists(), f"缺 fixture: {fixture}")
        res = mod.run({"run": None}, {"fixture": str(fixture)})
        self.assertEqual(res["report"]["state"], "deployed")

    def test_default_lab_fixture_when_no_params(self):
        for key in MODULE_KEYS:
            product = key[len("defense-bypass-"):]
            with self.subTest(product=product):
                res = _load_run(key).run({"run": None}, {})
                # 无参数 → 回退实验室 deployed fixture → 必须能评估出 deployed
                self.assertEqual(res["report"]["state"], "deployed", key)

    def test_cross_product_snapshot_is_absent(self):
        # elkeid 模块吃 falco 快照 → 不误报
        res = _load_run("defense-bypass-elkeid").run(
            {"run": None}, {"deploy_snapshot": SNAPSHOTS["falco"]["deployed"]}
        )
        self.assertEqual(res["report"]["state"], "absent")

    def test_empty_snapshot_is_absent(self):
        res = _load_run("defense-bypass-waf-inference").run({"run": None}, {"deploy_snapshot": {}})
        self.assertEqual(res["report"]["state"], "absent")


class TestFindingsContract(unittest.TestCase):
    def test_result_shape_and_hardening(self):
        for key in MODULE_KEYS:
            product = key[len("defense-bypass-"):]
            with self.subTest(product=product):
                with TemporaryDirectory() as tmp:
                    res = _load_run(key).run(
                        {"run": None},
                        {
                            "deploy_snapshot": SNAPSHOTS[product]["deployed"],
                            "artifact_dir": tmp,
                        },
                    )
                    self.assertIn("summary", res)
                    self.assertIsInstance(res["artifacts"], list)
                    self.assertTrue(res["artifacts"])  # 矩阵产物落盘
                    art = Path(res["artifacts"][0])
                    self.assertTrue(art.exists())
                    self.assertTrue(str(art).startswith(str(Path(tmp))))
                    matrix = json.loads(art.read_text(encoding="utf-8"))
                    self.assertIn("detected", matrix)
                    findings = res["findings"]
                    self.assertTrue(findings)
                    for f in findings:
                        self.assertIsInstance(f.get("sev"), str)
                        self.assertIsInstance(f.get("title"), str)
                        self.assertIsInstance(f.get("detail"), str)
                    hard = [f for f in findings if f.get("hardening")]
                    self.assertEqual(len(hard), 1)
                    self.assertTrue(hard[0]["hardening"])
                    self.assertTrue(all(isinstance(x, str) and x for x in hard[0]["hardening"]))
                    # 硬化文本须带规则引擎可解析前缀
                    self.assertTrue(all(h.startswith("rule:") for h in hard[0]["hardening"]))


class TestBenignSafety(unittest.TestCase):
    """无害性：探针全为技术类别级 benign marker，物化只写临时/授权目录。"""

    def test_all_probes_benign(self):
        for product in PRODUCTS:
            with self.subTest(product=product):
                probes = dp.benign_probes(product)
                self.assertTrue(probes)
                for p in probes:
                    self.assertTrue(p["marker"].startswith(dp.SAFE_MARKER_PREFIX), p)
                    self.assertTrue(p["benign"])
                self.assertEqual(dp.audit_benign(probes), [])

    def test_no_malicious_payload_in_probes(self):
        forbidden = ["/etc/shadow", "/dev/tcp/", "nc -e", "| sh", "msfvenom", "rootkit"]
        for product in PRODUCTS:
            blob = json.dumps(dp.benign_probes(product), ensure_ascii=False).lower()
            for bad in forbidden:
                self.assertNotIn(bad, blob, f"{product} 探针疑似含载荷: {bad}")

    def test_materialize_only_under_root(self):
        for product in PRODUCTS:
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                files = dp.materialize_probes(dp.benign_probes(product), root)
                self.assertTrue(files)
                for f in files:
                    self.assertTrue(str(f.resolve()).startswith(str(root.resolve())), f)

    def test_materialize_rejects_escape(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            evil = {
                "technique": "t", "category": "path-write",
                "marker": dp.SAFE_MARKER_PREFIX + ":x",
                "benign": True, "action": "",
                "write_target": "../../escape.marker",
            }
            with self.assertRaises(dp.ProbeContainmentError):
                dp.materialize_probes([evil], root)
            evil2 = dict(evil, write_target="/etc/inkblade-escape.marker")
            with self.assertRaises(dp.ProbeContainmentError):
                dp.materialize_probes([evil2], root)

    def test_rename_probe_only_echoes_marker(self):
        for product in PRODUCTS:
            for p in dp.benign_probes(product):
                if p["category"] == "tool-rename-exec":
                    self.assertIn("echo", p["exec_template"])
                    self.assertIn(dp.SAFE_MARKER_PREFIX, p["exec_template"])

    def test_indicator_specificity_bytedance(self):
        elkeid = " ".join(dp.indicator_patterns("elkeid")).lower()
        self.assertIn("elkeid", elkeid)
        self.assertIn("olehid", elkeid)  # 任务口径别名，保守兼容
        smith = " ".join(dp.indicator_patterns("agentsmith")).lower()
        self.assertIn("agentsmith", smith)
        self.assertIn("smith", smith)
        vein = " ".join(dp.indicator_patterns("veinmind")).lower()
        self.assertIn("veinmind", vein)
        self.assertIn("backdoor", vein)  # veinmind-* 扫描器名（公开仓库命名）


class TestRunnerIntegration(unittest.TestCase):
    def test_elkeid_full_run_records_findings(self):
        from inkblade.core.evidence import EvidenceStore
        from inkblade.core.roe import init_roe
        from inkblade.core.runner import run_module
        from inkblade.core.users import UserStore

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EvidenceStore(root, workspace="local-lab")
            users = UserStore(root / "users.json")
            users.create_user("tester", "x", "tester", ["local-lab"])
            session = users.verify("tester", "x")
            init_roe(store, fields={
                "level": "主动探测",
                "namespaces": ["train"],
                "cidrs": ["127.0.0.0/8"],
            })
            result = run_module(
                store, session, "defense-bypass-elkeid",
                params={"deploy_snapshot": SNAPSHOTS["elkeid"]["deployed"]},
                modules_dir=MODULES_DIR,
            )
            run = store.open_run(result["run"])
            rows = run.query("SELECT title FROM findings WHERE step_key='defense-bypass-elkeid'")
            self.assertGreaterEqual(len(rows), 2)
            self.assertTrue(any("硬化" in r[0] for r in rows))
            audit = run.query("SELECT result FROM actions ORDER BY id")
            self.assertEqual(audit[-1][0], "success")


if __name__ == "__main__":
    unittest.main()
