"""公开树卫生测试：内部绝对路径/工作区引用 0 命中 + fixture 注入断言。

- fixture 注入：临时目录写入盘符绝对路径、内部工作区名、内部漏洞设计基线文件名
  → 扫描器必须逐条命中（防止「扫描器坏掉导致假绿」）。
- 仓库公开树：源代码/json/md（排除 .git 与 .superpowers）→ 0 命中。
"""

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-public-tree.py"


def load_scanner():
    spec = importlib.util.spec_from_file_location("check_public_tree", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPublicTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scanner = load_scanner()

    def test_fixture_injection_detects_all_patterns(self):
        # 注意：fixture 字符串动态拼接，避免扫描器把测试自身当作违规样本。
        drive = "D" + ":" + "\\"
        workspace = "llm-" + "audit-2026-10"
        internal_doc = "VULNERABILITY" + "-MASTER"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.md").write_text(
                f"see {drive}secret\\path\\report.md\n", encoding="utf-8")
            (root / "bad.json").write_text(
                '{"root": "' + "D" + ":" + '/work/' + workspace + '/projects"}\n',
                encoding="utf-8",
            )
            (root / "bad.txt").write_text(
                internal_doc + ".md 第 1 节\n", encoding="utf-8"
            )
            (root / "ok.md").write_text(
                "服务 http://127.0.0.1:8000/v1/models 正常\n", encoding="utf-8"
            )
            hits = self.scanner.scan_tree(root)

        rules = {(Path(h["file"]).name, h["rule"]) for h in hits}
        self.assertIn(("bad.md", "windows-abs-path"), rules)
        self.assertIn(("bad.json", "workspace-name"), rules)
        self.assertIn(("bad.txt", "internal-doc"), rules)
        self.assertNotIn(("ok.md", "windows-abs-path"), rules, "http:// 不得误报为盘符路径")
        self.assertGreaterEqual(len(hits), 3)

    def test_repo_public_tree_clean(self):
        hits = self.scanner.scan_tree(REPO)
        detail = "\n".join(
            f'{h["file"]}:{h["line"]}: [{h["rule"]}] {h["excerpt"]}' for h in hits[:50]
        )
        self.assertEqual(hits, [], f"公开树仍存在内部引用:\n{detail}")


if __name__ == "__main__":
    unittest.main()
