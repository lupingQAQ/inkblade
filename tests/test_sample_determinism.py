"""终审 Minor#9/#14：样张确定性（固定 run 名 / 剥离时间戳端口耗时）+ 动态字段忽略口径。

断言：
- 同一输入两次生成报告/规则包/静态导出 → **归一化后逐字节一致**（diff=空）；
- 归档层确定性：gzip mtime=0 + tar 归零 mtime/uid/gid → 同输入 archive sha256 相同；
- 归一化器能剥离 ISO 时间戳、带时间戳 run 名、端口、耗时字段与本机绝对路径；
- ``lab/bench/out`` 为可再生输出（.gitignore），动态字段清单可从 inkblade.sampledet 取。
"""

import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.evidence import EvidenceStore
from inkblade.reports.render import render_pentest, render_remediation
from inkblade.rules.generate import generate_all
from inkblade.sampledet import DYNAMIC_FIELDS, diff_trees, normalize_text, normalize_tree
from inkblade.webui.export_static import export_static

REPO = Path(__file__).resolve().parents[1]
CHAINS = REPO / "inkblade" / "chains"


def _seed(store: EvidenceStore, run_name: str = "e2e-acceptance"):
    run = store.create_run(run_name)
    art = store.root / "artifact.txt"
    art.write_text("artifact-body-stable", encoding="utf-8")
    run.add_step("admin-probe", "curl /pause", {"actor": "tester"}, "管理面 200", artifacts=[art])
    run.add_step("weight-poison", "curl /pull_weights", {"actor": "tester"}, "权重写", artifacts=[art])
    archives = {r[0]: r[1] for r in run.query("SELECT step_key, archive FROM steps")}
    run.add_finding("admin-probe", "high", "管理面无鉴权", "detail",
                    evidence_path=archives["admin-probe"])
    run.add_finding("weight-poison", "critical", "权重投毒", "detail2",
                    evidence_path=archives["weight-poison"], is_zeroday=True)
    run.upsert_node("svc/sglang", "service", "工作负载层", {"port": 30000})
    run.add_edge("ns/train", "svc/sglang", "reachable", "CNI 语义推演", "admin-plane")
    run.finalize_run()
    return run


def _generate_tree(root: Path) -> None:
    """在两个独立目录用同一输入生成同类样张（模拟两次运行）。"""
    out = root / "samples"
    out.mkdir(parents=True, exist_ok=True)
    store = EvidenceStore(root, workspace="local-lab")
    run = _seed(store)
    (out / "pentest.md").write_text(render_pentest(store, run.name), encoding="utf-8")
    (out / "remediation.md").write_text(render_remediation(store, run.name), encoding="utf-8")
    generate_all(CHAINS, findings=[{"step_key": "admin-probe"}], out_dir=out / "rules-pack")
    export_static(run.dir, out / "static-export")
    (out / "check.json").write_text(json.dumps({
        "generated_at": "2026-10-25T12:00:00Z",
        "run": run.name,
        "elapsed_ms": 123.4,
        "port": 18787,
        "sha256": "a" * 64,
    }, ensure_ascii=False, indent=2), encoding="utf-8")


class TestSampleDeterminism(unittest.TestCase):
    def test_evidence_archives_identical_for_same_input(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            art = root / "a.txt"
            art.write_text("same-bytes", encoding="utf-8")
            shas = []
            for i in range(2):
                store = EvidenceStore(root / f"r{i}", workspace="ws")
                run = store.create_run("det")
                run.add_step("s", "cmd", {"k": "v"}, "sum", artifacts=[art])
                row = run.query("SELECT archive FROM steps")[0]
                archive = run.dir / row[0]
                data = archive.read_bytes()
                self.assertEqual(data[4:8], b"\x00\x00\x00\x00",
                                 "gzip 头 mtime 必须为 0（确定性）")
                shas.append((archive.read_bytes(), run.query(
                    "SELECT sha256 FROM evidence")[0][0]))
            self.assertEqual(shas[0][0], shas[1][0], "同输入归档字节必须一致")
            self.assertEqual(shas[0][1], shas[1][1], "同输入 manifest sha256 必须一致")

    def test_two_generations_diff_empty_after_normalize(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            a, b = base / "gen-a", base / "gen-b"
            _generate_tree(a)
            _generate_tree(b)
            normalize_tree(a / "samples")
            normalize_tree(b / "samples")
            diffs = diff_trees(a / "samples", b / "samples")
            self.assertEqual(diffs, [], f"两次生成归一化后仍存在差异: {diffs[:10]}")

    def test_normalizer_strips_dynamic_fields_but_keeps_stable_ones(self):
        drive_path = "C" + ":" + "\\Users\\x\\Temp\\inkblade\\a.json"  # 动态拼接避免公开树误报
        raw = (
            "Run: e2e-acceptance-20261025-222231\n"
            "生成时间: 2026-10-25 22:22:31\n"
            "target: http://127.0.0.1:18787/api/health\n"
            f"path: {drive_path}\n"
            '{"elapsed_ms": 12.5, "sha256": "' + "b" * 64 + '", "count": 7}\n'
            "archive: steps/s1.tar.gz\n"
        )
        out = normalize_text(raw)
        self.assertIn("e2e-acceptance-<run-ts>", out)
        self.assertIn("<timestamp>", out)
        self.assertIn("http://127.0.0.1:<port>/api/health", out)
        self.assertIn("<abs-path>", out)
        self.assertIn('"elapsed_ms": "<dynamic>"', out)
        # 稳定字段保持原样（否确定性测试无意义）
        self.assertIn("b" * 64, out)
        self.assertIn('"count": 7', out)
        self.assertIn("steps/s1.tar.gz", out)

    def test_markdown_elapsed_column_normalized(self):
        from inkblade.sampledet import normalize_markdown

        md = "| 检查项 | 耗时(ms) |\n|---|---|\n| a | 12.3 |\n| b | 0.5 |\n"
        out = normalize_markdown(md)
        self.assertIn("| a | <elapsed> |", out)
        self.assertIn("| b | <elapsed> |", out)

    def test_dynamic_field_registry_and_gitignore(self):
        self.assertIn("elapsed_ms", DYNAMIC_FIELDS)
        self.assertIn("generated_at", DYNAMIC_FIELDS)
        gitignore = (REPO / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("lab/bench/out/", gitignore,
                      "lab/bench/out 为可再生基准输出，应忽略")

    def test_e2e_check_supports_fixed_run_name(self):
        spec = importlib.util.spec_from_file_location(
            "inkblade_e2e_check", REPO / "inkblade" / "e2e-check.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertTrue(hasattr(mod, "resolve_run_name"))
        self.assertEqual(mod.resolve_run_name("e2e-acceptance"), "e2e-acceptance")
        self.assertRegex(mod.resolve_run_name(None), r"^e2e-acceptance-\d{8}-\d{6}$")


if __name__ == "__main__":
    unittest.main()
