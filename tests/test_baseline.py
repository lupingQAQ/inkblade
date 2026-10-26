# -*- coding: utf-8 -*-
"""core/baseline.py 测试：主体/实体基线（CI/扫描器/控制器/平台工作负载）+
学习模式（历史 run / 历史事件 → allowlist）+ 抑制规则（时间窗/标签/注释）。

口径：基线是**triage 层**（检测保持纯净，抑制可审计、可溯源、可过期），
不是把检测器删掉；suppressed 结果必须带 provenance（哪条基线/哪条规则抑制的）。
"""

from __future__ import annotations

import unittest

from trident.core import baseline as B


def pod_finding(ns: str, name: str, sa: str = "", image: str = "", sev: str = "high",
                title: str = "宿主敏感目录挂载（/proc）") -> dict:
    ev = f"pod={ns}/{name} hostPath=/proc"
    if sa or image:
        ev += f" sa={sa} image={image}"
    return {"severity": sev, "title": f"{ns}/{name}：{title}", "detail": "d",
            "evidence": ev, "subject": "", "resource": "", "step_key": "escape-primitives"}


def subject_finding(subject: str, step: str = "rbac-mapping", title: str = "",
                    ev: str = "") -> dict:
    return {"severity": "high", "title": title or f"can-i：{subject} 可 exec Pod",
            "detail": "d", "evidence": ev or f"subject={subject} allowed=['pods/exec']",
            "subject": subject, "resource": "", "step_key": step}


def role_finding(name: str, scope: str = "ClusterRole") -> dict:
    return {"severity": "critical", "title": f"通配符{scope}：{name}", "detail": "d",
            "evidence": f"{scope}={name} rules=[*]", "subject": "", "resource": "",
            "step_key": "rbac-mapping"}


def binding_finding(name: str, role: str = "cluster-admin") -> dict:
    return {"severity": "critical", "title": f"cluster-admin 绑定：{name} → Group:{name}",
            "detail": "d", "evidence": f"binding={name} role={role}", "subject": "",
            "resource": "", "step_key": "rbac-mapping"}


def ns_finding(ns: str) -> dict:
    return {"severity": "high",
            "title": f"命名空间 {ns} 的 3 个 Pod 未被任何入站 NetworkPolicy 选择（覆盖缺口）",
            "detail": "d", "evidence": f"ns={ns} pods=3 policies_in_ns=0", "subject": "",
            "resource": "", "step_key": "network-policy-coverage"}


class TestEntityBaselineDefaults(unittest.TestCase):
    def test_default_lists_nonempty_and_classified(self):
        base = B.EntityBaseline.defaults()
        self.assertTrue(base.ci_service_accounts)
        self.assertTrue(any(":ci:" in s for s in base.ci_service_accounts))
        self.assertTrue(base.scanner_subjects)
        self.assertTrue(any(":security:" in s for s in base.scanner_subjects))
        self.assertTrue(base.controller_subjects)
        self.assertTrue(base.controller_roles)
        self.assertTrue(base.system_bindings)
        self.assertTrue(base.platform_namespaces)
        self.assertIn("kube-system", base.platform_namespaces)

    def test_audit_subjects_union(self):
        base = B.EntityBaseline.defaults()
        subjects = set(base.audit_subjects())
        self.assertIn("system:serviceaccount:ci:ci-runner", subjects)
        self.assertIn("system:serviceaccount:security:scanner", subjects)
        # 默认主体基线不得包含集群控制器高危动作主体之外的普通租户
        self.assertNotIn("system:serviceaccount:tenant-b:tenant-b", subjects)

    def test_platform_workload_triples_cover_common_daemonsets(self):
        base = B.EntityBaseline.defaults()
        triples = {t["service_account"] for t in base.platform_workloads}
        for sa in ("aws-node", "kube-proxy", "ebs-csi-node", "falco",
                   "node-exporter", "prometheus", "ingress-nginx"):
            self.assertIn(sa, triples, f"平台工作负载基线缺 {sa}")

    def test_merge_and_persistence_roundtrip(self):
        import json
        base = B.EntityBaseline.defaults()
        base.merge({"ci_service_accounts": ["system:serviceaccount:ci:extra"]})
        doc = base.to_doc()
        again = B.EntityBaseline.from_doc(json.loads(json.dumps(doc)))
        self.assertIn("system:serviceaccount:ci:extra", again.ci_service_accounts)
        self.assertEqual(again.platform_namespaces, base.platform_namespaces)


class TestSuppression(unittest.TestCase):
    def test_suppress_platform_pod_by_triple(self):
        base = B.EntityBaseline.defaults()
        ctx = {"pods": {"kube-system/aws-node-9k2lp": {
            "service_account": "aws-node",
            "image": "602401143452.dkr.ecr.us-east-1.amazonaws.com/amazon-k8s-cni:v1.18"}}}
        kept, log = base.suppress_findings([pod_finding("kube-system", "aws-node-9k2lp")], ctx)
        self.assertEqual(kept, [])
        self.assertEqual(log.suppressed, 1)
        self.assertIn("platform-workload", log.provenance[0]["source"])

    def test_same_sa_wrong_image_not_suppressed(self):
        base = B.EntityBaseline.defaults()
        ctx = {"pods": {"tenant-a/aws-node-evil": {"service_account": "aws-node",
                                                   "image": "evil.example/esc:v1"}}}
        kept, log = base.suppress_findings([pod_finding("tenant-a", "aws-node-evil")], ctx)
        self.assertEqual(len(kept), 1)
        self.assertEqual(log.suppressed, 0)

    def test_suppress_subject_role_binding_namespace(self):
        base = B.EntityBaseline.defaults()
        findings = [
            subject_finding("system:serviceaccount:ci:ci-runner"),
            role_finding("platform-operator"),
            role_finding("system:controller:node-controller"),
            binding_finding("system:masters"),
            ns_finding("kube-system"),
            ns_finding("tenant-b"),  # 租户命名空间不得被平台基线吞掉
            subject_finding("system:serviceaccount:tenant-b:tenant-b"),
        ]
        kept, log = base.suppress_findings(findings, {})
        kept_keys = {f["evidence"].split()[0] for f in kept}
        self.assertEqual(kept_keys, {"ns=tenant-b", "subject=system:serviceaccount:tenant-b:tenant-b"})
        self.assertEqual(log.suppressed, 5)

    def test_capability_findings_not_suppressed_for_controllers(self):
        """can-i（能力面）只有 CI/扫描器可抑制：调度器宽权限本身仍是风险。"""
        base = B.EntityBaseline.defaults()
        findings = [
            subject_finding("system:serviceaccount:ml-training:platform-scheduler",
                            title="can-i：platform-scheduler 可读 Secrets"),  # 能力面 → 保留
            subject_finding("system:serviceaccount:ml-training:platform-scheduler",
                            title="SA 逃逸矩阵：platform-scheduler 可创建 Pod",
                            ev="subject=system:serviceaccount:ml-training:platform-scheduler "
                               "create_pods=true"),  # 行为面 → 抑制
        ]
        kept, log = base.suppress_findings(findings, {})
        self.assertEqual(len(kept), 1)
        self.assertIn("可读 Secrets", kept[0]["title"])
        self.assertEqual(log.suppressed, 1)

    def test_suppression_log_is_auditable(self):
        base = B.EntityBaseline.defaults()
        _, log = base.suppress_findings([ns_finding("kube-system")], {})
        entry = log.provenance[0]
        for key in ("source", "matched", "rule", "sample"):
            self.assertIn(key, entry)
        self.assertEqual(log.entries(), log.provenance)


class TestLearningMode(unittest.TestCase):
    def test_learn_from_events_frequency_and_success_only(self):
        events = []
        for i in range(30):  # CI 高频 exec：学习窗口内的良性形态
            events.append({"verb": "create", "user": {"username": "system:serviceaccount:ci:ci-runner"},
                           "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "ci"},
                           "responseStatus": {"code": 200}})
        for i in range(3):  # 低频主体：不应入基线
            events.append({"verb": "create", "user": {"username": "system:serviceaccount:tenant-b:x"},
                           "objectRef": {"resource": "pods", "subresource": "exec", "namespace": "tenant-b"},
                           "responseStatus": {"code": 200}})
        for i in range(30):  # 高频但 403：拒绝尝试不学
            events.append({"verb": "get", "user": {"username": "system:serviceaccount:tenant-c:c"},
                           "objectRef": {"resource": "secrets"},
                           "responseStatus": {"code": 403}})
        learned = B.learn_from_events(events, min_occurrences=20)
        entry = next(e for e in learned if e["subject"] == "system:serviceaccount:ci:ci-runner")
        self.assertGreaterEqual(entry["occurrences"], 20)
        self.assertEqual(entry["pattern"], "create pods/exec")
        self.assertFalse(any(":tenant-b:" in e["subject"] for e in learned))
        self.assertFalse(any(":tenant-c:" in e["subject"] for e in learned))

    def test_learning_never_allows_high_risk_patterns(self):
        events = []
        for i in range(50):  # 高频高危：铸造 SA token —— 不得被学习为基线
            events.append({"verb": "create",
                           "user": {"username": "system:serviceaccount:attacker:loop"},
                           "objectRef": {"resource": "serviceaccounts", "subresource": "token"},
                           "responseStatus": {"code": 200}})
        learned = B.learn_from_events(events, min_occurrences=20)
        self.assertEqual(learned, [])

    def test_learn_from_runs(self):
        class FakeRun:
            def __init__(self, name, findings):
                self.name = name
                self.findings = findings

        runs = [FakeRun("run-1", [subject_finding("system:serviceaccount:ml:x")]),
                FakeRun("run-2", [subject_finding("system:serviceaccount:ml:x"),
                                  subject_finding("system:serviceaccount:ml:once")])]
        learned = B.learn_from_runs(runs, min_runs=2)
        subs = [e["subject"] for e in learned]
        self.assertIn("system:serviceaccount:ml:x", subs)
        self.assertNotIn("system:serviceaccount:ml:once", subs)
        entry = next(e for e in learned if e["subject"] == "system:serviceaccount:ml:x")
        self.assertEqual(entry["source"], "historical-runs")
        self.assertEqual(entry["runs"], 2)


class TestSuppressionRules(unittest.TestCase):
    def test_time_window_rule(self):
        rule = B.SuppressionRule.time_window(
            "maint-2026-10", start="2026-10-25T10:00:00Z", end="2026-10-25T10:02:00Z",
            reason="CI 高峰窗口", created_by="lead")
        engine = B.SuppressionEngine([rule])
        f_in = {"severity": "high", "title": "t", "detail": "d",
                "evidence": "auditID=x", "time": "2026-10-25T10:01:00Z"}
        f_out = {"severity": "high", "title": "t", "detail": "d",
                 "evidence": "auditID=y", "time": "2026-10-25T10:05:41Z"}
        kept, log = engine.apply([f_in, f_out], {})
        self.assertEqual([f["evidence"] for f in kept], ["auditID=y"])
        self.assertEqual(log.suppressed, 1)
        self.assertEqual(log.provenance[0]["rule"], "maint-2026-10")

    def test_label_and_annotation_rules(self):
        rules = [
            B.SuppressionRule.label("approved-daemonsets", {"trident.example/baseline": "approved"},
                                    reason="例外清单", created_by="lead"),
            B.SuppressionRule.annotation("ack-node-exporter", "trident.example/ack",
                                         value="node-exporter/2026-10", reason="逐例外确认",
                                         created_by="lead"),
        ]
        engine = B.SuppressionEngine(rules)
        ctx = {"labels": {"monitoring/node-exporter-h4n2p": {"trident.example/baseline": "approved"}},
               "annotations": {"monitoring/prometheus-0": {"trident.example/ack":
                                                           "node-exporter/2026-10"}}}
        f1 = pod_finding("monitoring", "node-exporter-h4n2p")
        f2 = pod_finding("monitoring", "prometheus-0")
        f3 = pod_finding("monitoring", "grafana-7d9f")
        kept, log = engine.apply([f1, f2, f3], ctx)
        self.assertEqual([f["title"].split("：")[0] for f in kept], ["monitoring/grafana-7d9f"])
        self.assertEqual(log.suppressed, 2)

    def test_rules_require_reason_and_creator(self):
        with self.assertRaises(B.BaselineError):
            B.SuppressionRule.time_window("x", start="2026-10-25T10:00:00Z",
                                          end="2026-10-25T11:00:00Z", reason="", created_by="")

    def test_expired_time_window_suppresses_nothing(self):
        rule = B.SuppressionRule.time_window(
            "old", start="2026-10-01T00:00:00Z", end="2026-10-02T00:00:00Z",
            reason="过窗", created_by="lead")
        engine = B.SuppressionEngine([rule])
        kept, log = engine.apply([{"time": "2026-10-25T10:00:00Z", "evidence": "z"}], {})
        self.assertEqual(len(kept), 1)
        self.assertEqual(log.suppressed, 0)


if __name__ == "__main__":
    unittest.main()
