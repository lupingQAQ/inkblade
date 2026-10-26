"""tests/test_chip_docs.py — 芯片安全范围文档、画像矩阵与引用核验。

要求：
- docs/CHIP-SECURITY-SCOPE.md 存在，明确 in-scope / out-of-scope；
- 明确排除硅片实验室（RTL/GDSII/DFT、功耗电磁侧信道、电压毛刺/激光、开盖探针、
  芯片逆向、counterfeit）；
- 部署画像映射覆盖六个 profile，并区分默认暴露/需配置/无面；
- 引用 NVIDIA CC/NRAS、DMTF SPDM、AMD SEV-SNP、Intel TDX、PCIe DOE、CXL 规范；
- docs/SURFACE-REALISM.md 增补芯片姿态小节与 cxl 隔离项。
"""

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "CHIP-SECURITY-SCOPE.md"
SURFACE = REPO / "docs" / "SURFACE-REALISM.md"


class ChipScopeDocTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")

    def test_doc_exists(self):
        self.assertTrue(DOC.is_file())
        self.assertGreater(len(self.text), 6000)

    def test_in_scope_items(self):
        for needle in (
            "GPU CC 证明链", "NRAS", "SPDM", "PCIe DOE", "IOMMU", "SMMU",
            "安全启动", "TPM", "PCR", "固件签名", "显存残留", "MIG", "MPS",
            "NVLink", "IMEX", "CXL", "微码",
        ):
            self.assertIn(needle, self.text, needle)

    def test_necessity_tiers(self):
        for needle in ("必要性分级", "A 真攻击路径", "B 保障性审计",
                       "C 前瞻", "research-only", "D 明确不做", "不计入"):
            self.assertIn(needle, self.text, needle)

    def test_out_of_scope_items(self):
        for needle in (
            "RTL", "GDSII", "DFT", "功耗", "电磁", "电压毛刺", "激光",
            "开盖", "探针", "芯片逆向", "counterfeit", "硅片实验室",
            "Rowhammer", "微架构", "侧信道",
        ):
            self.assertIn(needle, self.text, needle)

    def test_out_of_scope_explains_resources(self):
        for phrase in ("洁净室", "SEM", "FIB", "示波器", "X 射线", "授权分销"):
            self.assertIn(phrase, self.text, phrase)

    def test_profile_mapping(self):
        for profile in ("bare-k8s-gpu", "ray-vllm", "managed-ack-tke",
                        "slurm-hpc", "airgapped", "gpu-pooling"):
            self.assertIn(f"`{profile}`", self.text, profile)
        for state in ("默认暴露", "需配置", "无面"):
            self.assertIn(state, self.text, state)

    def test_public_sources(self):
        for url in (
            "docs.nvidia.com/attestation",
            "docs.nvidia.com/confidential-computing",
            "dmtf.org",
            "DSP0274",
            "amd.com",
            "SEV-SNP",
            "intel.com",
            "TDX",
            "pcisig.com",
            "DataObjectExchange",
            "computeexpresslink.org",
            "CXL",
            "kernel.org",
            "trustedcomputinggroup.org",
        ):
            self.assertIn(url, self.text, url)

    def test_honest_boundaries(self):
        for phrase in ("fixture", "仿真", "不等于", "无真实", "未证明",
                       "NRAS 生产", "自签", "不能"):
            self.assertIn(phrase, self.text, phrase)

    def test_report_and_sota_do_not_count_cd(self):
        for path in (REPO / "docs" / "SOTA-2026-10.md",
                     REPO / "docs" / "MASTER-REPORT.md"):
            text = path.read_text(encoding="utf-8")
            self.assertIn("不计入", text, path.name)
            self.assertIn("research-only", text, path.name)
            self.assertIn("C/D", text, path.name)

    def test_surface_doc_has_chip_section(self):
        text = SURFACE.read_text(encoding="utf-8")
        self.assertIn("Accelerator chip posture", text)
        self.assertIn("CHIP-SECURITY-SCOPE.md", text)
        for key in ("gpu-cc-attestation-chain", "spdm-pcie-doe", "iommu-smmu-config",
                    "secure-boot-chain", "firmware-signature-inventory",
                    "gpu-memory-residue-isolation", "nvlink-imex-isolation",
                    "cxl-memory-security"):
            self.assertIn(f"`{key}`", text, key)
        self.assertIn("`cxl-memory-security`", text.split("## 2.")[1].split("## 3.")[0])


if __name__ == "__main__":
    unittest.main()
