"""链引擎测试：目录 20+ 条（长上下文/PD KV 专项新增 2 条）+ 前置三态判定 + 安全表达式求值 + dry-run + 并行执行。"""

import json
import re
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from inkblade.core.chains import (
    PreconditionError,
    dry_run,
    evaluate_expression,
    evaluate_preconditions,
    execute,
    load_chains,
)
from inkblade.core.evidence import EvidenceStore
from inkblade.core.roe import init_roe
from inkblade.core.users import UserStore

CHAINS_DIR = Path(__file__).resolve().parents[1] / "inkblade" / "chains"
KEY_RE = re.compile(r"^[a-z][a-z0-9-]*$")  # 允许端口/版本数字段（如 stage-1-entry）

FINDINGS = [
    {
        "step_key": "network-policy-coverage",
        "severity": "high",
        "title": "no-network-policy",
        "detail": {"port": 30000},
        "reachable": [{"port": 30000, "host": "worker-a"}],
    },
    {
        "step_key": "framework-port-matching",
        "severity": "high",
        "title": "admin-port-open",
        "reachable": [{"port": 30000}, {"port": 8265}],
    },
]


# ---------- 执行用 fixture 模块 ----------

def _fixture_module(root: Path, key: str, sleep: float = 0.0, touch: str = "",
                    expect_first: str = "", fail: bool = False):
    d = root / "modules" / key
    d.mkdir(parents=True, exist_ok=True)
    meta = {
        "key": key, "name": {"zh": key, "en": key}, "series": "横向利用",
        "description": "t", "min_level": "主动探测", "writes": False, "requires": [],
    }
    (d / "module.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    body = "import pathlib\nimport time\n\n\ndef run(ctx, params):\n"
    body += f"    time.sleep({sleep})\n"
    if fail:
        body += "    raise RuntimeError('boom')\n"
        (d / "run.py").write_text(body, encoding="utf-8")
        return
    if expect_first:
        body += (
            f"    got = pathlib.Path(r'{expect_first}').read_text(encoding='utf-8')\n"
            "    assert got == 'probe-first-done', '依赖步骤未先行完成: ' + got\n"
        )
    if touch:
        body += f"    pathlib.Path(r'{touch}').write_text('{key}-done', encoding='utf-8')\n"
    body += (
        "    return {'summary': 'ok', 'artifacts': [],"
        " 'findings': [{'sev': 'info', 'title': 'step-done', 'detail': 'ok'}]}\n"
    )
    (d / "run.py").write_text(body, encoding="utf-8")


def _chain_fixture(**overrides):
    chain = {
        "id": "demo-chain",
        "title": {"zh": "演示链", "en": "demo chain"},
        "category": "经典攻击链",
        "requires": [],
        "preconditions": [],
        "steps": [
            {"id": "probe-a", "module": "probe-first", "params": {}},
            {"id": "probe-b", "module": "probe-second", "params": {}},
        ],
        "evidence": ["http-trace"],
        "mitre": ["T1210"],
    }
    chain.update(overrides)
    return chain


class TestCatalog(unittest.TestCase):
    def test_catalog_complete_and_valid(self):
        chains = load_chains(CHAINS_DIR)
        # 并行任务会持续追加链：至少包含长上下文/PD KV 专项 2 条 + AI 网关链，且四条类别齐备。
        self.assertGreaterEqual(len(chains), 21)
        self.assertIn("long-context-cache-leak", chains)
        self.assertIn("pd-kv-poison", chains)
        self.assertIn("ai-gateway-key-exfil", chains)
        cats: dict[str, int] = {}
        for cid, chain in chains.items():
            self.assertRegex(cid, r"^[a-z][a-z-]*$", f"链机器键禁数字/非小写: {cid}")
            self.assertEqual((CHAINS_DIR / f"{cid}.json").name, f"{cid}.json")
            self.assertIn("zh", chain["title"])
            self.assertIn("en", chain["title"])
            self.assertTrue(chain["steps"], f"{cid} 无步骤")
            cats[chain["category"]] = cats.get(chain["category"], 0) + 1
            for st in chain["steps"]:
                self.assertRegex(st["module"], KEY_RE)
                for dep in st.get("depends_on", []):
                    self.assertRegex(dep, KEY_RE)
            for req in chain["requires"]:
                self.assertRegex(req, KEY_RE)
        # 并行任务可能追加新类别（如 AI 网关链）：只要求核心四类齐备。
        self.assertTrue({"经典攻击链", "云侧权重桶链", "网络利用链", "深度链"} <= set(cats))
        self.assertGreaterEqual(cats.get("经典攻击链"), 7)
        self.assertGreaterEqual(cats.get("云侧权重桶链"), 4)
        self.assertGreaterEqual(cats.get("网络利用链"), 7)
        self.assertGreaterEqual(cats.get("深度链"), 2)
        self.assertGreaterEqual(cats.get("AI 网关链"), 1)

    def test_load_chains_rejects_bad_definitions(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 键含数字
            (root / "bad-chain-two.json").write_text(
                json.dumps({"id": "bad-chain-two", "title": {"zh": "t", "en": "t"},
                            "requires": [], "preconditions": [], "steps": [{"module": "x"}]}),
                encoding="utf-8")
            with self.assertRaises(ValueError):
                load_chains(root)
            (root / "bad-chain-two.json").unlink()
            # 非法表达式（load 时即编译校验）
            (root / "bad-expr.json").write_text(
                json.dumps({"id": "bad-expr", "title": {"zh": "t", "en": "t"},
                            "requires": [], "preconditions": [{"expr": "eval('boom')"}],
                            "steps": [{"module": "x"}]}),
                encoding="utf-8")
            with self.assertRaises(ValueError):
                load_chains(root)
            (root / "bad-expr.json").unlink()
            # depends_on 引用不存在的步骤
            (root / "dangling-dep.json").write_text(
                json.dumps({"id": "dangling-dep", "title": {"zh": "t", "en": "t"},
                            "requires": [], "preconditions": [],
                            "steps": [{"module": "x", "depends_on": ["ghost"]}]}),
                encoding="utf-8")
            with self.assertRaises(ValueError):
                load_chains(root)


class TestPreconditions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chains = load_chains(CHAINS_DIR)

    def test_precondition_three_states(self):
        chain = self.chains["flat-network-admin-plane-weight-poison"]
        # 两条前提全真（无覆盖发现 → count==0；端口匹配命中 30000）→ 成立
        verdict, missing = evaluate_preconditions(chain, [FINDINGS[1]])
        self.assertEqual(verdict, "成立")
        self.assertEqual(missing, [])
        # 一真一假（端口未命中 30000）→ 部分成立 + 缺失清单仅含未满足者
        verdict, missing = evaluate_preconditions(
            chain, [{"step_key": "framework-port-matching",
                     "reachable": [{"port": 8265}]}])
        self.assertEqual(verdict, "部分成立")
        self.assertEqual(len(missing), 1)
        self.assertIn("framework-port-matching", missing[0])
        # 全假（存在覆盖发现且端口未命中）→ 不成立
        verdict, missing = evaluate_preconditions(
            chain, [{"step_key": "network-policy-coverage", "reachable": []}])
        self.assertEqual(verdict, "不成立")
        self.assertEqual(len(missing), 2)
        # 零前置链（novel入口）→ 恒成立
        verdict, missing = evaluate_preconditions(
            self.chains["agent-platform-zero-precondition-lateral"], [])
        self.assertEqual(verdict, "成立")
        self.assertEqual(missing, [])

    def test_expression_evaluator_subset(self):
        ev = lambda e, fs=FINDINGS: evaluate_expression(e, fs)  # noqa: E731
        self.assertIs(ev("findings('network-policy-coverage').count == 0", []), True)
        self.assertIs(ev("findings('network-policy-coverage').count == 1"), True)
        self.assertIs(ev("findings('framework-port-matching').count != 0"), True)
        self.assertIs(ev("findings('network-policy-coverage').count >= 2"), False)
        self.assertIs(ev("findings('framework-port-matching').reachable.any(port == 8265)"), True)
        self.assertIs(ev("findings('framework-port-matching').reachable.any(port == 9999)"), False)
        self.assertIs(ev("findings('network-policy-coverage').any(severity == 'high')"), True)
        self.assertIs(ev("findings('network-policy-coverage').any(detail.port == 30000)"), True)
        self.assertIs(ev("findings('network-policy-coverage').any(severity == 'low')"), False)
        self.assertIs(ev("findings('ghost-module').reachable.any(port == 80)"), False)
        # 布尔组合 + 括号 + not
        self.assertIs(ev("(findings('a').count == 0 or findings('b').count > 3)"
                         " and not findings('c').any(sev == 'low')", []), True)
        self.assertIs(ev("not (findings('a').count == 0 and findings('b').count == 0)", []), False)

    def test_expression_rejects_dangerous(self):
        for evil in [
            "eval('1+1')",
            "findings('x').count == 0 and __import__('os')",
            "1; import os",
            "__builtins__",
            "findings('x').count ==",
            "findings('x').rm_rf()",
        ]:
            with self.assertRaises(PreconditionError, msg=evil):
                evaluate_expression(evil, [])


class TestDryRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chains = load_chains(CHAINS_DIR)

    def test_dryrun_lists_backup_actions(self):
        plan = dry_run(self.chains["flat-network-admin-plane-weight-poison"], [FINDINGS[1]])
        self.assertEqual(plan["chain"], "flat-network-admin-plane-weight-poison")
        self.assertEqual(plan["verdict"], "成立")
        self.assertEqual(len(plan["steps"]), 2)
        probe, poison = plan["steps"]
        self.assertEqual(probe["module"], "sglang-admin-failopen")
        self.assertFalse(probe["writes"])
        self.assertEqual(probe["backup_actions"], [])
        # 写类步骤必须列出备份动作与预计写面
        self.assertEqual(poison["module"], "slime-weight-pull-poison")
        self.assertTrue(poison["writes"])
        self.assertTrue(poison["backup_actions"])
        self.assertTrue(poison["backup_targets"])
        self.assertTrue(poison["write_surface"])
        self.assertIn("mitre", plan)
        # 前提不满足时 plan 携带缺失清单
        plan2 = dry_run(self.chains["flat-network-admin-plane-weight-poison"],
                        [{"step_key": "network-policy-coverage", "reachable": []}])
        self.assertEqual(plan2["verdict"], "不成立")
        self.assertEqual(len(plan2["missing"]), 2)

    def test_dryrun_uses_module_registry(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 注册表声明 writes=true → dry-run 必须采信（覆盖链内声明）
            _fixture_module(root, "registry-write-demo")
            meta = json.loads((root / "modules" / "registry-write-demo" / "module.json")
                              .read_text(encoding="utf-8"))
            meta["writes"] = True
            (root / "modules" / "registry-write-demo" / "module.json").write_text(
                json.dumps(meta, ensure_ascii=False), encoding="utf-8")
            chain = _chain_fixture(steps=[{
                "id": "write-step", "module": "registry-write-demo", "writes": False,
                "params": {"backup_targets": [{"kind": "file", "path": str(root / "w.txt")}]},
            }])
            plan = dry_run(chain, [], modules_dir=root / "modules")
            step = plan["steps"][0]
            self.assertTrue(step["writes"])  # 以注册表为准
            self.assertEqual(step["backup_targets"], [{"kind": "file", "path": str(root / "w.txt")}])


class TestExecute(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = EvidenceStore(self.root, workspace="local-lab")
        users = UserStore(self.root / "users.json")
        users.create_user("tester", "x", "tester", ["local-lab"])
        self.session = users.verify("tester", "x")
        init_roe(self.store, fields={"level": "利用验证", "namespaces": ["train"],
                                     "cidrs": ["127.0.0.0/8"]})

    def tearDown(self):
        self.tmp.cleanup()

    def test_parallel_independent_steps(self):
        _fixture_module(self.root, "probe-first", sleep=0.30, touch=str(self.root / "a.txt"))
        _fixture_module(self.root, "probe-second", sleep=0.45, touch=str(self.root / "b.txt"))
        chain = _chain_fixture()
        t0 = time.monotonic()
        result = execute(chain, self.store, self.session,
                         modules_dir=self.root / "modules", findings=[], workers=2)
        elapsed = time.monotonic() - t0
        self.assertTrue(result["ok"])
        self.assertEqual(result["steps"]["probe-a"]["status"], "success")
        self.assertEqual(result["steps"]["probe-b"]["status"], "success")
        # 串行 ≥0.75s；并行必须明显低于串行下界
        self.assertLess(elapsed, 0.70, f"步骤未并行执行: {elapsed:.2f}s")
        self.assertTrue((self.root / "a.txt").exists())
        self.assertTrue((self.root / "b.txt").exists())

    def test_dependency_serial_order(self):
        _fixture_module(self.root, "probe-first", sleep=0.25, touch=str(self.root / "first.txt"))
        _fixture_module(self.root, "probe-second", expect_first=str(self.root / "first.txt"))
        chain = _chain_fixture(steps=[
            {"id": "probe-a", "module": "probe-first", "params": {}},
            {"id": "probe-b", "module": "probe-second", "params": {}, "depends_on": ["probe-a"]},
        ])
        result = execute(chain, self.store, self.session,
                         modules_dir=self.root / "modules", findings=[], workers=4)
        self.assertTrue(result["ok"])
        self.assertEqual(result["steps"]["probe-b"]["status"], "success")

    def test_failed_step_skips_dependents_only(self):
        _fixture_module(self.root, "probe-first", fail=True)
        _fixture_module(self.root, "probe-second", touch=str(self.root / "b.txt"))
        chain = _chain_fixture(steps=[
            {"id": "probe-a", "module": "probe-first", "params": {}},
            {"id": "probe-b", "module": "probe-second", "params": {}, "depends_on": ["probe-a"]},
            {"id": "free-c", "module": "probe-second", "params": {}},
        ])
        result = execute(chain, self.store, self.session,
                         modules_dir=self.root / "modules", findings=[], workers=3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["steps"]["probe-a"]["status"], "failed")
        self.assertEqual(result["steps"]["probe-b"]["status"], "skipped")
        self.assertEqual(result["steps"]["free-c"]["status"], "success")

    def test_execute_single_run_records_all_steps(self):
        _fixture_module(self.root, "probe-first", touch=str(self.root / "a.txt"))
        _fixture_module(self.root, "probe-second", touch=str(self.root / "b.txt"))
        chain = _chain_fixture()
        result = execute(chain, self.store, self.session,
                         modules_dir=self.root / "modules", findings=[], workers=2)
        run = self.store.open_run(result["run"])
        rows = run.query("SELECT step_key FROM steps ORDER BY id")
        keys = [r[0] for r in rows]
        self.assertEqual(sorted(keys), ["probe-first", "probe-second"])
        self.assertEqual(len(run.findings), 2)


if __name__ == "__main__":
    unittest.main()
