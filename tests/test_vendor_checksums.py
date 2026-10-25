"""终审 Minor#10：vendor 资产校验和清单（vendor/SHA256SUMS）+ 零外链。

- 清单覆盖 vendor 目录内全部随行资产（React / ReactDOM / React Flow UMD + CSS）；
- 逐文件重算 SHA256 必须与清单一致（防止离线包被替换/截断）；
- index.html/app.js 不得引用外部 http(s) 资源（离线可开红线）。
"""

import hashlib
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VENDOR = REPO / "trident" / "webui" / "static" / "vendor"
SUMS = VENDOR / "SHA256SUMS"
STATIC = REPO / "trident" / "webui" / "static"


def _manifest() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in SUMS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sha, _, name = line.partition("  ")
        out[name.strip()] = sha.strip().lower()
    return out


class TestVendorChecksums(unittest.TestCase):
    def test_manifest_exists_and_covers_all_vendor_files(self):
        self.assertTrue(SUMS.is_file(), "缺 vendor/SHA256SUMS")
        listed = set(_manifest())
        actual = {p.name for p in VENDOR.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
        self.assertEqual(listed, actual, f"清单与文件不一致: {listed ^ actual}")
        self.assertGreaterEqual(len(listed), 4)

    def test_each_hash_matches(self):
        for name, expect in sorted(_manifest().items()):
            with self.subTest(file=name):
                data = (VENDOR / name).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), expect,
                                 f"{name} 校验和不匹配（vendor 资产被改动？）")
                self.assertGreater(len(data), 1024, f"{name} 过小（截断？）")

    def test_no_external_references_in_static_assets(self):
        for name in ("index.html", "app.js", "style.css"):
            text = (STATIC / name).read_text(encoding="utf-8")
            for m in re.finditer(r"(?:src|href)\s*=\s*[\"'](https?://[^\"']+)", text):
                self.fail(f"{name} 含外部引用: {m.group(1)}")
            # JS 里的 fetch/XHR 目标应为相对路径（排除文档注释中的示例 URL）
            for m in re.finditer(r"fetch\(\s*[\"'](https?://[^\"']+)", text):
                self.fail(f"{name} 含外部 fetch: {m.group(1)}")

    def test_manifest_documents_sources(self):
        head = SUMS.read_text(encoding="utf-8").splitlines()[:8]
        joined = "\n".join(head)
        self.assertIn("react@18.3.1", joined)
        self.assertIn("@reactflow/core@11.11.4", joined)


if __name__ == "__main__":
    unittest.main()
