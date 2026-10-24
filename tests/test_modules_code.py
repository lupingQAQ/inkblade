"""核心代码检测模块族测试：codescan 双通道 + 规则锚 + 模块 file:line 产出。"""

import json
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from trident.core import codescan
from trident.core.evidence import EvidenceStore
from trident.core.registry import load_modules
from trident.core.roe import init_roe
from trident.core.runner import run_module
from trident.core.users import UserStore

REPO = Path(__file__).resolve().parents[1]
MODULES_DIR = REPO / "trident" / "modules"
SAMPLE = REPO / "lab" / "sample-vuln-repo"

CODE_KEYS = [
    "python-dangerous-sinks",
    "auth-gap-detection",
    "supply-chain-pinning",
    "outbound-ssrf",
    "combo-signature-static",
]

AST_RULES = ["eval-call", "exec-call", "torch-load-unsafe", "pickle-loads", "dynamic-import"]
REGEX_RULES = ["bind-all-interfaces", "auth-fail-open", "trust-remote-code",
               "missing-revision", "file-url-accepted", "os-system-concat"]


class TestCodescan(unittest.TestCase):
    def test_rules_have_valid_ids(self):
        rules = codescan.load_rules()["rules"]
        ids = [r["id"] for r in rules]
        self.assertEqual(len(ids), len(set(ids)), "规则 id 重复")
        for rid in ids:
            self.assertRegex(rid, r"^[a-z][a-z-]*$", f"规则 id 必须纯小写单词: {rid}")

    def test_rule_anchors_resolve(self):
        """每条规则自带 file:line 案例锚，且锚必须在样本树上精确命中。"""
        rules = codescan.load_rules()["rules"]
        hits = codescan.scan_path(SAMPLE)
        hit_set = {(h["rule"], h["file"], h["line"]) for h in hits}
        for rule in rules:
            anchor = rule.get("anchor", "")
            self.assertTrue(anchor, f"规则 {rule['id']} 缺 file:line 案例锚")
            rel, line, *_ = anchor.split(":")
            self.assertIn(
                (rule["id"], rel, int(line)), hit_set,
                f"规则 {rule['id']} 锚 {anchor} 未在样本树命中",
            )

    def test_ast_channel(self):
        hits = codescan.scan_path(SAMPLE)
        for rid in AST_RULES:
            ast_hits = [h for h in hits if h["rule"] == rid and h["channel"] == "ast"]
            self.assertGreaterEqual(len(ast_hits), 1, f"ast 通道未覆盖 {rid}")
            for h in ast_hits:
                self.assertGreaterEqual(h["line"], 1)
                self.assertIn("file", h)

    def test_regex_channel(self):
        hits = codescan.scan_path(SAMPLE)
        for rid in REGEX_RULES:
            self.assertTrue(any(h["rule"] == rid for h in hits), f"regex 通道未命中 {rid}")

    def test_exact_line_numbers(self):
        serve = SAMPLE / "serve.py"
        lines = serve.read_text(encoding="utf-8").splitlines()
        expected = next(i for i, l in enumerate(lines, 1) if "return eval" in l)
        hits = codescan.scan_file(serve, root=SAMPLE)
        eval_hits = [h for h in hits if h["rule"] == "eval-call"]
        self.assertTrue(any(h["line"] == expected for h in eval_hits),
                        "eval 命中行号必须精确")

    def test_combos(self):
        data = codescan.load_rules()
        hits = codescan.scan_path(SAMPLE)
        combos = codescan.match_combos(hits, data["combos"])
        ids = [c["id"] for c in combos]
        self.assertIn("unsafe-deserialization", ids)
        self.assertIn("unauth-rce-surface", ids)
        self.assertIn("unpinned-remote-model", ids)
        for c in combos:
            joined = json.dumps(c, ensure_ascii=False)
            self.assertRegex(joined, r"\.py:\d+", "组合发现必须带 file:line 证据")


class TestCodeModules(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={
            "level": "只读侦察", "namespaces": ["train"], "cidrs": ["127.0.0.0/8"],
        })

    def tearDown(self):
        self.tmp.cleanup()

    def test_code_modules_registered(self):
        mods = load_modules(MODULES_DIR)
        for key in CODE_KEYS:
            self.assertIn(key, mods, f"缺少核心代码模块 {key}")
            self.assertEqual(mods[key].series, "核心代码")
            self.assertFalse(mods[key].writes, "静态检测模块不得写目标")

    def test_modules_emit_file_line_findings(self):
        for key in CODE_KEYS:
            with self.subTest(module=key):
                result = run_module(self.store, self.session, key,
                                    {"root": str(SAMPLE)}, modules_dir=MODULES_DIR)
                run = self.store.open_run(result["run"])
                rows = [f for f in run.findings if f["step_key"] == key]
                self.assertGreaterEqual(len(rows), 1, f"{key} 未产出 finding")
                for f in rows:
                    self.assertRegex(f["detail"], r"[\w./-]+:\d+", "发现必须含 file:line")
                inv = list((self.root / "evidence" / "local-lab" / result["run"] / "artifacts").glob("*.json"))
                self.assertTrue(inv, f"{key} 缺少扫描报告产物")


if __name__ == "__main__":
    unittest.main()
