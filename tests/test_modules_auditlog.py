# -*- coding: utf-8 -*-
"""tests/test_modules_auditlog.py — K8s 审计轨迹分析（core/auditlog + kube-audit-trail-analysis 模块）TDD。

fixture（lab/fixtures/auditlog/，自建，形态取自本仓库攻击链在 apiserver 审计面的真实投影）：
- attack-trail.jsonl：RoleBinding→cluster-admin 创建 / 特权 Pod 创建（docker.sock hostPath）/
  Ray 8265 作业提交（head SA 落 runtime Pod）/ Secret 异常读 / pods/exec / 权重 PVC 异常写（claim 级 + 挂载级）
  + 两条良性噪声（gitops 普通绑定 / controller patch）+ 一条 403 已拒绝尝试
- benign-trail.jsonl：加固基线正常运维（gitops/view 绑定、调度器建普通 Pod、GC/prometheus 读 Secret、
  平台调度器挂 weights-pvc、storage-op 扩容数据盘 PVC 等 10 条）→ 期望零发现（误报断言）
- kubetrail-export.json：KubeTrail（ekkoo-z/KubeTrail）dbus.json 导出 Document 形态 → 适配器断言

联动断言：新增 Sigma×2（sigma-pods-exec-lateral / sigma-weight-pvc-abnormal-write）在规则包内登记，
且每条审计 finding 给出主体/动词/资源/时间/映射链名/建议规则键。
"""
import json
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from trident.core.auditlog import (
    DEFAULT_BASELINE_SUBJECTS,
    adapt_kubetrail,
    analyze,
    analyze_events,
    detect_kubetrail_export,
    load_events,
    parse_jsonl,
)
from trident.core.registry import load_modules
from trident.rules.generate import load_catalog

ROOT = Path(__file__).resolve().parents[1]
MODULES_DIR = ROOT / "trident" / "modules"
FIX_DIR = ROOT / "lab" / "fixtures" / "auditlog"
MODULE_KEY = "kube-audit-trail-analysis"  # 注册表禁数字键（k8s→kube），与命名规范一致


def load_run(key):
    spec = spec_from_file_location(f"auditmod_{key.replace('-', '_')}", MODULES_DIR / key / "run.py")
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AuditLogEngineTest(unittest.TestCase):
    """core/auditlog 引擎：命中断言（每攻击形态 → 对应检测器）+ 误报断言（良性零报）。"""

    @classmethod
    def setUpClass(cls):
        cls.attack = parse_jsonl((FIX_DIR / "attack-trail.jsonl").read_text(encoding="utf-8"))
        cls.benign = parse_jsonl((FIX_DIR / "benign-trail.jsonl").read_text(encoding="utf-8"))

    def test_attack_trail_six_detectors_hit(self):
        """八类攻击形态逐一命中，且互不误报（每 finding 标注检测器）。"""
        findings = analyze_events(self.attack)
        detectors = {f["detector"] for f in findings}
        self.assertEqual(detectors, {
            "rbac-clusteradmin-binding",
            "privileged-pod-create",
            "ray-job-runtime-pod",
            "secret-abnormal-read",
            "pods-exec-session",
            "sa-token-mint",
            "pods-portforward",
            "weight-pvc-abnormal-write",
        }, detectors)

    def test_finding_fields_complete(self):
        """任务口径字段：主体/动词/资源/时间/映射链名/建议规则键 全齐。"""
        for f in analyze_events(self.attack):
            for field in ("subject", "verb", "resource", "time", "chains", "rule_keys"):
                self.assertTrue(f.get(field) or f[field] == [], f"{f.get('detector')} 缺 {field}")
            self.assertTrue(f["chains"], f"{f['detector']} 无映射链名")
            self.assertTrue(f["rule_keys"], f"{f['detector']} 无建议规则键")
            self.assertIn(f["sev"], ("critical", "high", "medium", "low", "info"))
            self.assertTrue(f.get("evidence"))

    def test_rolebinding_cluster_admin_mapping(self):
        f = next(x for x in analyze_events(self.attack) if x["detector"] == "rbac-clusteradmin-binding")
        self.assertEqual(f["sev"], "critical")
        self.assertIn("ray-system", f["resource"])
        self.assertIn("cluster-admin", f["evidence"])
        self.assertIn("sigma-rolebinding-cluster-admin", f["rule_keys"])
        self.assertIn("kyverno:alert-rolebinding-creation", f["rule_keys"])
        self.assertIn("ray-dashboard-cluster-takeover", f["chains"])

    def test_privileged_pod_hostpath_socket(self):
        f = next(x for x in analyze_events(self.attack) if x["detector"] == "privileged-pod-create")
        self.assertIn(f["sev"], ("critical", "high"))
        self.assertIn("sigma-privileged-pod-create", f["rule_keys"])
        self.assertIn("kyverno:deny-privileged-pod", f["rule_keys"])
        self.assertIn("gpu-network-operator-host-escape", f["chains"])

    def test_pods_exec_maps_new_sigma_rule(self):
        f = next(x for x in analyze_events(self.attack) if x["detector"] == "pods-exec-session")
        self.assertEqual(f["sev"], "high")
        self.assertIn("sigma-pods-exec-lateral", f["rule_keys"])
        self.assertIn("ray-dashboard-cluster-takeover", f["chains"])
        self.assertIn("exec", f["resource"])

    def test_ray_job_runtime_pod(self):
        """Ray 8265 作业提交在 apiserver 审计面的投影 = head SA 落 runtime Pod（非 operator 主体）。"""
        f = next(x for x in analyze_events(self.attack) if x["detector"] == "ray-job-runtime-pod")
        self.assertIn("sigma-ray-job-submit", f["rule_keys"])
        self.assertIn("ray-dashboard-cluster-takeover", f["chains"])
        self.assertIn("ray", f["subject"].lower())

    def test_secret_abnormal_read_baseline_allowlist(self):
        """基线主体（GC/prometheus）读 Secret 不报；非基线主体读报 high。"""
        findings = analyze_events(self.attack)
        f = next(x for x in findings if x["detector"] == "secret-abnormal-read")
        self.assertEqual(f["sev"], "high")
        self.assertIn("sigma-secret-abnormal-read", f["rule_keys"])
        self.assertIn("ssrf-sa-token-cloud-metadata", f["chains"])
        # 良性流：默认白名单主体读 Secret 零报
        benign = analyze_events(self.benign)
        self.assertFalse([x for x in benign if x["detector"] == "secret-abnormal-read"])

    def test_weight_pvc_write_two_shapes(self):
        """权重 PVC 写两形态：claim 级 patch + 非 baseline 主体挂载 weights PVC 建 Pod。"""
        findings = [x for x in analyze_events(self.attack) if x["detector"] == "weight-pvc-abnormal-write"]
        resources = " ".join(x["resource"] for x in findings)
        self.assertIn("persistentvolumeclaims", resources)
        self.assertIn("weights-pvc", resources)
        for f in findings:
            self.assertIn("sigma-weight-pvc-abnormal-write", f["rule_keys"])
            self.assertIn("falco-weight-file-abnormal-write", f["rule_keys"])
            self.assertIn("shared-pvc-supply-chain-poison", f["chains"])

    def test_benign_trail_zero_findings(self):
        """误报断言：加固基线 10 条正常操作零发现。"""
        self.assertEqual(analyze_events(self.benign), [])

    def test_denied_attempts_hidden_by_default(self):
        """默认只报已完成（2xx）动作；403 拒绝尝试仅在 include_denied=True 时以 low 报。"""
        default = analyze_events(self.attack)
        self.assertEqual([f for f in default if "已拒绝" in f["title"]], [])
        with_denied = analyze_events(self.attack, include_denied=True)
        denied = [f for f in with_denied if "已拒绝" in f["title"]]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["sev"], "low")

    def test_parse_robustness_and_stats(self):
        """空行/注释/坏 JSON 行跳过不崩溃；analyze 返回统计（valid/skipped 分列）。"""
        text = '# comment\n\n{"kind": "Event", "verb": "create"}\nnot-json\n'
        events = parse_jsonl(text)
        self.assertEqual(len(events), 1)
        result = analyze([{"kind": "Event", "verb": "create"}, "junk"])
        self.assertEqual(result["stats"]["events"], 1)
        self.assertEqual(result["stats"]["skipped"], 1)
        self.assertEqual(result["stats"]["audit_findings"], 0)

    def test_load_events_from_path_and_list(self):
        by_path = load_events(FIX_DIR / "attack-trail.jsonl")
        by_list = load_events(json.loads(json.dumps(self.attack)))
        self.assertEqual(len(by_path), len(by_list))
        self.assertGreater(len(by_path), 0)


class KubeTrailAdapterTest(unittest.TestCase):
    """KubeTrail（ekkoo-z/KubeTrail）dbus.json 导出格式适配器。"""

    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads((FIX_DIR / "kubetrail-export.json").read_text(encoding="utf-8"))

    def test_detect_export_shape(self):
        self.assertTrue(detect_kubetrail_export(self.doc))
        self.assertFalse(detect_kubetrail_export({"kind": "Event", "verb": "create"}))

    def test_adapt_preserves_severity_and_maps_categories(self):
        findings = adapt_kubetrail(self.doc)
        self.assertEqual(len(findings), 3)
        by_cat = {f["kubetrail_category"]: f for f in findings}
        self.assertEqual(by_cat["rbac"]["sev"], "high")
        self.assertEqual(by_cat["escape"]["sev"], "critical")
        self.assertEqual(by_cat["lpe"]["sev"], "medium")
        for f in findings:
            self.assertIn("[KubeTrail]", f["title"])
            self.assertTrue(f["chains"], f"{f['title']} 无链映射")
            self.assertTrue(f["subject"], "KubeTrail finding 应携带 target 主体（pod/ns）")
        self.assertIn("sigma-rolebinding-cluster-admin", by_cat["rbac"]["rule_keys"])
        self.assertIn("sigma-privileged-pod-create", by_cat["escape"]["rule_keys"])

    def test_analyze_accepts_kubetrail_export(self):
        result = analyze(FIX_DIR / "attack-trail.jsonl", kubetrail_export=self.doc)
        self.assertEqual(result["stats"]["kubetrail_findings"], 3)


class AuditTrailModuleTest(unittest.TestCase):
    """kube-audit-trail-analysis 模块：注册契约 + run() 三件套 + 双输入源。"""

    CTX = {"marker": "TRIDENT-auditlog-test", "meta": {"key": MODULE_KEY}}

    def test_registry_contract(self):
        mods = load_modules(MODULES_DIR)
        self.assertIn(MODULE_KEY, mods)
        meta = mods[MODULE_KEY]
        self.assertEqual(meta.series, "侦察")
        self.assertEqual(meta.min_level, "只读侦察")
        self.assertFalse(meta.writes)
        self.assertEqual(meta.requires, [])

    def test_module_run_attack_fixture(self):
        result = load_run(MODULE_KEY).run(
            dict(self.CTX), {"auditlog": str(FIX_DIR / "attack-trail.jsonl")}
        )
        for field in ("summary", "findings", "artifacts"):
            self.assertIn(field, result)
        self.assertGreaterEqual(len(result["findings"]), 6)
        self.assertIn("审计轨迹", result["summary"])

    def test_module_run_benign_zero_and_kubetrail_input(self):
        run = load_run(MODULE_KEY)
        benign = run.run(dict(self.CTX), {"auditlog": str(FIX_DIR / "benign-trail.jsonl")})
        self.assertEqual(benign["findings"], [])
        kt = run.run(dict(self.CTX), {"kubetrail_export": str(FIX_DIR / "kubetrail-export.json")})
        self.assertEqual(len(kt["findings"]), 3)
        both = run.run(dict(self.CTX), {
            "auditlog": str(FIX_DIR / "attack-trail.jsonl"),
            "kubetrail_export": str(FIX_DIR / "kubetrail-export.json"),
        })
        self.assertEqual(len(both["findings"]), len(load_run(MODULE_KEY).run(
            dict(self.CTX), {"auditlog": str(FIX_DIR / "attack-trail.jsonl")}
        )["findings"]) + 3)

    def test_baseline_subjects_param_overridable(self):
        """baseline_subjects 参数可扩展白名单（如平台调度器）压掉挂载级误报。"""
        run = load_run(MODULE_KEY)
        findings = run.run(dict(self.CTX), {
            "auditlog": str(FIX_DIR / "attack-trail.jsonl"),
            "baseline_subjects": list(DEFAULT_BASELINE_SUBJECTS),
        })["findings"]
        self.assertTrue(findings)


class RulesIntegrationTest(unittest.TestCase):
    """与规则引擎联动：新增 Sigma×2 进目录 + 紫队重放 fixture 使其可命中。"""

    def test_sa_token_and_portforward_detectors_never_baselined(self):
        """FN 补齐：token 铸造 / portforward 命中；主体白名单和学习模式都压不掉。"""
        from trident.core import baseline as B

        events = [
            {"kind": "Event", "auditID": "g-1", "verb": "create",
             "user": {"username": "system:serviceaccount:ci:ci-runner"},
             "objectRef": {"resource": "serviceaccounts", "subresource": "token",
                           "namespace": "ci", "name": "ci-runner"},
             "responseStatus": {"code": 201},
             "stageTimestamp": "2026-10-25T10:00:00Z"},
            {"kind": "Event", "auditID": "g-2", "verb": "create",
             "user": {"username": "system:serviceaccount:ci:ci-runner"},
             "objectRef": {"resource": "pods", "subresource": "portforward",
                           "namespace": "ci", "name": "build-0"},
             "responseStatus": {"code": 200},
             "stageTimestamp": "2026-10-25T10:00:01Z"},
        ]
        everything = B.EntityBaseline(
            ci_service_accounts=["system:serviceaccount:ci:ci-runner"]).audit_subjects()
        findings = analyze_events(events, baseline_subjects=everything)
        dets = {f["detector"] for f in findings}
        self.assertEqual(dets, {"sa-token-mint", "pods-portforward"}, dets)
        self.assertIn("serviceaccounts/token", findings[0]["resource"])
        self.assertIn("pods/portforward", findings[1]["resource"])
        # 学习模式对这两个形态永不产出 allowlist 条目
        learned = B.learn_from_events(events * 30, min_occurrences=10)
        self.assertEqual([e for e in learned
                          if e["pattern"] in ("create serviceaccounts/token",
                                              "create pods/portforward")], [])

    def test_denied_token_mint_low_when_include_denied(self):
        events = [{"kind": "Event", "auditID": "g-3", "verb": "create",
                   "user": {"username": "system:serviceaccount:tenant-x:x"},
                   "objectRef": {"resource": "serviceaccounts", "subresource": "token",
                                 "namespace": "tenant-x", "name": "x"},
                   "responseStatus": {"code": 403},
                   "stageTimestamp": "2026-10-25T10:00:02Z"}]
        self.assertEqual(analyze_events(events), [])
        denied = analyze_events(events, include_denied=True)
        self.assertEqual([f["detector"] for f in denied], ["sa-token-mint"])
        self.assertEqual(denied[0]["sev"], "low")

    def test_new_sigma_rules_in_catalog(self):
        catalog = load_catalog()
        ids = {spec["id"] for spec in catalog["sigma"]}
        self.assertIn("sigma-pods-exec-lateral", ids)
        self.assertIn("sigma-weight-pvc-abnormal-write", ids)
        for spec in catalog["sigma"]:
            if spec["id"] in ("sigma-pods-exec-lateral", "sigma-weight-pvc-abnormal-write"):
                self.assertTrue(spec["blocks_modules"], spec["id"])
                self.assertTrue(spec["tuning"]["zh"] and spec["tuning"]["en"], spec["id"])

    def test_new_rules_have_replay_fixtures(self):
        """两新规则的链重放计划必须带审计 fixture（validate 零漏过前提）。"""
        catalog = load_catalog()["probes"]["chains"]
        ray_fx = catalog["ray-dashboard-cluster-takeover"]["fixtures"]
        self.assertTrue(any(
            fx.get("objectRef", {}).get("subresource") == "exec" for fx in ray_fx if fx.get("kind") == "sigma"))
        pvc_fx = catalog["shared-pvc-supply-chain-poison"]["fixtures"]
        self.assertTrue(any(
            fx.get("objectRef", {}).get("resource") == "persistentvolumeclaims"
            for fx in pvc_fx if fx.get("kind") == "sigma"))


if __name__ == "__main__":
    unittest.main()
