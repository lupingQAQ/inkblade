import re
import unittest
from pathlib import Path

from inkblade.core.combo import ComboHit, load

DATA = Path(__file__).resolve().parent.parent / "inkblade" / "core" / "data" / "combo-matrix.json"
KEY_RE = re.compile(r"^[a-z][a-z-]*$")


class TestComboMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = load(DATA)

    def test_file_contract(self):
        """机器键纯小写单词（禁数字）；每条字段齐全。"""
        self.assertGreaterEqual(len(self.matrix.entries), 14, "spec 5.4 首批含网络组合应为 14 条")
        for e in self.matrix.entries:
            self.assertRegex(e["signature"], KEY_RE, f"签名键非法：{e['signature']}")
            for field in ("signature", "title", "components", "risk", "modules", "knowledge", "evidence"):
                self.assertIn(field, e, f"条目 {e['signature']} 缺字段 {field}")
            self.assertTrue(e["components"], "组合必须由 ≥2 组件构成")
            for m in e["modules"]:
                self.assertRegex(m, KEY_RE)

    def test_combo_requires_all_components(self):
        """单组件命中不产出组合发现。"""
        fps = {"multus": True}
        self.assertEqual(self.matrix.match(fps), [])
        fps = {"multus": True, "sriov": True}
        self.assertEqual(self.matrix.match(fps), [])

    def test_network_combo_hit(self):
        """Multus+SR-IOV+RDMA → NetworkPolicy 旁路。"""
        fps = {"multus": True, "sriov": True, "rdma": True}
        hits = self.matrix.match(fps)
        sigs = [h.signature for h in hits]
        self.assertIn("multus-sriov-rdma-bypass", sigs)
        hit = next(h for h in hits if h.signature == "multus-sriov-rdma-bypass")
        self.assertIsInstance(hit, ComboHit)
        self.assertTrue(hit.title)
        self.assertTrue(hit.knowledge)
        self.assertTrue(hit.evidence)

    def test_alternative_group_semantics(self):
        """verl / SkyRL 二选一 + KubeRay 即命中（任一组成员满足）。"""
        for fw in ("verl", "skyrl"):
            hits = self.matrix.match({fw: True, "kuberay": True})
            self.assertIn(
                "verl-skyrl-kuberay-admin-plane",
                [h.signature for h in hits],
                f"{fw}+kuberay 应命中",
            )

    def test_false_fingerprint_not_counted(self):
        """显式 False 的指纹不算命中。"""
        self.assertEqual(self.matrix.match({"multus": True, "sriov": False, "rdma": True}), [])


if __name__ == "__main__":
    unittest.main()
