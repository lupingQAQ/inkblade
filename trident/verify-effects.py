"""trident/verify-effects.py — 实效验证：本机真实进程 + 真实 HTTP 逐项证明攻击效果。

用法::

    python -m trident.verify-effects --out reports/samples/effects/
    python trident/verify-effects.py --out reports/samples/effects/ --no-docs

验证项（全部在本机 127.0.0.1 回环完成，结果可复现）：
a) 未授权管理面利用：sglang-admin-failopen 真实 200 且服务端状态文件变更；
b) 权重投毒实效：slime-weight-pull-poison 对权重文件副本真实写入 benign marker，
   sha256 前后不同且内容含 run marker；
c) 备份回滚实效：backup_targets 快照 → 投毒 → rollback → sha256 与原始完全一致；
d) RCE 实效：areal-setenv-engine-rce 触发 mock 侧真实落地 marker 文件（含 run 标记）；
e) 数据泄露实效：training-data-leak 读到 fixture 假密钥，报告仅以尾4位出现；
f) 检测规则实效：规则引擎对本次靶场重放 validate，断言 ≥1 条规则命中；
g) 端到端链：flat-network-admin-plane-weight-poison dry-run → execute
   （全影响演示级 + 备份），断言链完成且证据三层完整。

边界（写入报告，不隐藏）：本验证是**本机真实进程/真实 HTTP 效果级**，靶场为
``lab/mock_targets.py``（仅 127.0.0.1），**不是 live K8s 集群**；KIND（hostNetwork 绕过
NetworkPolicy）与 ARTEX 黑盒对标需启用虚拟化后按 ``lab/kind/run-proof.sh`` 与
``lab/bench/artex-bench.sh`` 执行。
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.mock_targets import _safe_name, start_all  # noqa: E402
from trident.core.backup import BackupManager  # noqa: E402
from trident.core.chains import dry_run, execute, load_chains  # noqa: E402
from trident.core.evidence import EvidenceStore  # noqa: E402
from trident.core.roe import init_roe  # noqa: E402
from trident.core.runner import run_module  # noqa: E402
from trident.core.users import UserStore  # noqa: E402
from trident.reports.render import render_pentest  # noqa: E402
from trident.rules.generate import generate_all  # noqa: E402
from trident.rules.validate import validate  # noqa: E402

MODULES_DIR = REPO_ROOT / "trident" / "modules"
CHAINS_DIR = REPO_ROOT / "trident" / "chains"
THEFT_FIXTURES = REPO_ROOT / "lab" / "fixtures" / "theft"
TARGET_CHAIN = "flat-network-admin-plane-weight-poison"
FAKE_TOKEN = "hf_FAKEtokenDoNotUseSampleABCD1234wxyz"

SCOPE = (
    "本机真实进程 + 真实 HTTP（127.0.0.1 回环 mock 靶场）效果级验证；"
    "非 live K8s 集群。KIND/ARTEX 需启用虚拟化后按 lab/kind 与 lab/bench 脚本执行。"
)
LIMITATIONS = [
    "靶场为 lab/mock_targets.py 单进程仿真（仅 127.0.0.1），非真实 K8s API/容器运行时。",
    "sglang/areal/slime 的写面以 mock server 侧真实文件落盘为证据，不是远端生产文件系统。",
    "KIND hostNetwork 绕过 NetworkPolicy 实证需启用 WSL2/虚拟化后执行 lab/kind/run-proof.sh。",
    "ARTEX（AGPL）仅作外部黑盒对标，本仓库不复用其代码；对标需虚拟化环境执行 lab/bench/artex-bench.sh。",
]

_ABS_PATH_RES = (
    re.compile(r"[A-Za-z]:\\\\[^\s\"',;|()\[\]{}<>：，；（）]+"),
    re.compile(r"[A-Za-z]:\\[^\s\"',;|()\[\]{}<>：，；（）]+"),
)


# ---------------------------------------------------------------- 通用工具


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path | str) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _rel(path: Path | str, root: Path | str) -> str:
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def _scrub(text: str) -> str:
    """公开报告不落本机绝对路径。"""
    for rx in _ABS_PATH_RES:
        text = rx.sub("<abs-path>", text)
    return text


def _load_trace(run, module_key: str) -> dict:
    path = run.dir / "traces" / f"{module_key}.json"
    if not path.is_file():
        raise AssertionError(f"模块未落 HTTP trace：{path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def _trace_entry(trace: dict, method: str, suffix: str) -> dict:
    for entry in trace.get("entries", []):
        if entry.get("method") == method and str(entry.get("url", "")).endswith(suffix):
            return entry
    raise AssertionError(f"trace 未命中 {method} {suffix}")


class _Checks:
    """逐项 PASS/FAIL 清单；异常即 FAIL（不中断后续检查，便于一次看全）。"""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def run(self, cid: str, title: str, fn: Callable[[], dict[str, Any]]) -> None:
        item: dict[str, Any] = {"id": cid, "title": title, "status": "FAIL", "evidence": {}, "detail": ""}
        started = time.time()
        try:
            item["evidence"] = fn() or {}
            item["status"] = "PASS"
        except Exception as exc:  # noqa: BLE001 —— 任何断言/运行异常都记为该检查 FAIL
            item["detail"] = f"{type(exc).__name__}: {exc}"
        item["elapsed_ms"] = round((time.time() - started) * 1000, 1)
        self.items.append(item)

    @property
    def passed(self) -> int:
        return sum(1 for item in self.items if item["status"] == "PASS")

    @property
    def failed(self) -> int:
        return len(self.items) - self.passed


# ---------------------------------------------------------------- 主流程


def run_verification(out_dir: Path | str, write_docs: bool = True) -> dict[str, Any]:
    """执行 7 项实效验证；输出 effects.json + effects.md（可选写 docs/EFFECT-VERIFICATION.md）。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    checks = _Checks()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    state: dict[str, Any] = {}
    result: dict[str, Any] = {}

    with TemporaryDirectory(prefix="trident-effects-") as tmp:
        root = Path(tmp)
        lab_root = root / "lab"
        store = EvidenceStore(root / "workspace", workspace="effects-lab")
        users = UserStore(root / "users.json")
        users.create_user("effects-tester", "x", "tester", ["effects-lab"])
        tester = users.verify("effects-tester", "x")
        init_roe(store, fields={
            "level": "全影响演示",
            "namespaces": ["default", "train", "infer", "ray-system", "ml-agent"],
            "cidrs": ["127.0.0.0/8"],
            "window": f"effects-verification {stamp}",
            "client": "Trident 本机 mock 靶场（授权实验室）",
        })
        run = store.create_run(f"effects-{stamp}")
        lab = start_all(mode="vulnerable", root=lab_root)
        try:
            def admin_plane() -> dict[str, Any]:
                state_path = lab_root / "sglang" / "admin-state.json"
                state_path.parent.mkdir(parents=True, exist_ok=True)
                state_path.write_text(
                    json.dumps({"/pause": {"applied": False, "mode": "seed"}}, ensure_ascii=False),
                    encoding="utf-8",
                )
                before_sha = _sha256_file(state_path)
                run_module(
                    store, tester, "sglang-admin-failopen",
                    {"target": lab.url(""), "mode": "probe-only"},
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "sglang-admin-failopen")
                pause = _trace_entry(trace, "POST", "/pause")
                if pause.get("status") != 200:
                    raise AssertionError(f"/pause 未返回 200（实际 {pause.get('status')}）")
                response = pause.get("response") or {}
                if response.get("applied") is not True:
                    raise AssertionError("管理面未报告 applied=true")
                after = json.loads(state_path.read_text(encoding="utf-8"))
                after_sha = _sha256_file(state_path)
                if after.get("/pause", {}).get("applied") is not True:
                    raise AssertionError("服务端状态文件未变更为 applied=true")
                if before_sha == after_sha:
                    raise AssertionError("服务端状态文件 sha256 前后相同")
                return {
                    "http_status": pause["status"],
                    "route": "/pause",
                    "state_file": _rel(state_path, lab_root),
                    "state_sha256_before": before_sha,
                    "state_sha256_after": after_sha,
                    "state_applied": True,
                    "state_response_sha256": response.get("state_sha256", ""),
                }

            checks.run("admin-plane-failopen", "未授权管理面利用：真实 HTTP 200 + 服务端状态文件变更", admin_plane)

            def weight_poison() -> dict[str, Any]:
                marker = f"TRIDENT-{run.name}"
                safe = _safe_name(f"/checkpoints/victim-{marker}", "checkpoint")
                victim = lab_root / "slime" / safe / "model.safetensors"
                victim.parent.mkdir(parents=True, exist_ok=True)
                original = b"TRIDENT-MOCK-WEIGHTS-ORIGINAL\nseed=weights-copy\n"
                victim.write_bytes(original)
                before_sha = _sha256_file(victim)
                state.update({"victim": victim, "original": original, "sha_before": before_sha, "marker": marker})
                run_module(
                    store, tester, "slime-weight-pull-poison",
                    {
                        "target": lab.url(""),
                        "mode": "backup-write",
                        "backup_targets": [{"kind": "file", "path": str(victim)}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "slime-weight-pull-poison")
                pull = _trace_entry(trace, "POST", "/pull_weights")
                if pull.get("status") != 200:
                    raise AssertionError(f"/pull_weights 未返回 200（实际 {pull.get('status')}）")
                after_sha = _sha256_file(victim)
                content = victim.read_text(encoding="utf-8", errors="replace")
                if after_sha == before_sha:
                    raise AssertionError("权重文件副本 sha256 前后相同（未真实写入）")
                if marker not in content:
                    raise AssertionError("权重文件副本未含 run marker")
                response = pull.get("response") or {}
                if response.get("weights_sha256") != after_sha:
                    raise AssertionError("mock 响应 weights_sha256 与实际文件不一致")
                return {
                    "http_status": pull["status"],
                    "file": _rel(victim, lab_root),
                    "sha256_before": before_sha,
                    "sha256_after": after_sha,
                    "marker": marker,
                    "marker_present": True,
                    "server_weights_sha256": response.get("weights_sha256"),
                }

            checks.run("weight-poison-write", "权重投毒实效：文件副本 sha256 变化 + benign marker", weight_poison)

            def backup_rollback() -> dict[str, Any]:
                victim = state["victim"]
                before_sha = state["sha_before"]
                original = state["original"]
                bm = BackupManager(store, run)
                rows = bm.rollback("slime-weight-pull-poison")
                restored_sha = _sha256_file(victim)
                if rows < 1:
                    raise AssertionError("未找到备份回执（rollback 行数为 0）")
                if restored_sha != before_sha:
                    raise AssertionError(f"回滚后 sha256 不一致：{restored_sha} != {before_sha}")
                if victim.read_bytes() != original:
                    raise AssertionError("回滚后文件字节与原始副本不一致")
                backups = run.query(
                    "SELECT target, backup_path, sha256 FROM backups WHERE run=? AND step_key=? ORDER BY id",
                    (run.name, "slime-weight-pull-poison"),
                )
                if not backups or backups[0][2] != before_sha:
                    raise AssertionError("备份回执 sha256 与原始文件不一致")
                return {
                    "rollback_rows": rows,
                    "sha256_original": before_sha,
                    "sha256_after_rollback": restored_sha,
                    "exact_restore": True,
                    "backup_receipt_sha256": backups[0][2],
                }

            checks.run("backup-rollback", "备份回滚实效：快照 → 投毒 → rollback 后 sha256 与原始完全一致", backup_rollback)

            def rce_marker() -> dict[str, Any]:
                marker = f"TRIDENT-{run.name}"
                run_module(
                    store, tester, "areal-setenv-engine-rce",
                    {
                        "target": lab.url(""),
                        "mode": "backup-write",
                        "backup_targets": [{"kind": "http", "url": lab.url("/set_env"), "state": {}}],
                    },
                    modules_dir=MODULES_DIR, run=run,
                )
                trace = _load_trace(run, "areal-setenv-engine-rce")
                env = _trace_entry(trace, "POST", "/set_env")
                engine = _trace_entry(trace, "POST", "/create_engine")
                call = _trace_entry(trace, "POST", "/call")
                statuses = {"set_env": env.get("status"), "create_engine": engine.get("status"), "call": call.get("status")}
                if statuses != {"set_env": 200, "create_engine": 200, "call": 200}:
                    raise AssertionError(f"三步链状态异常：{statuses}")
                call_resp = call.get("response") or {}
                marker_path = Path(str(call_resp.get("marker", "")))
                if not marker_path.is_file():
                    raise AssertionError("mock 侧 /call 未落地 marker 文件")
                content = marker_path.read_text(encoding="utf-8", errors="replace")
                if marker not in content:
                    raise AssertionError("marker 文件内容不含 run 标记")
                env_marker = Path(str((env.get("response") or {}).get("marker", "")))
                return {
                    "http_statuses": statuses,
                    "marker_file": _rel(marker_path, lab_root),
                    "env_marker_file": _rel(env_marker, lab_root) if env_marker.is_file() else "",
                    "marker": marker,
                    "marker_present": True,
                    "engine_id": call_resp.get("engine_id", ""),
                }

            checks.run("rce-marker", "RCE 实效：AReaL 三步链触发 mock 侧真实 marker 文件（含 run 标记）", rce_marker)

            def data_leak() -> dict[str, Any]:
                run_module(
                    store, tester, "training-data-leak",
                    {"data_root": str(THEFT_FIXTURES)},
                    modules_dir=MODULES_DIR, run=run,
                )
                findings = [f for f in run.findings if f.get("step_key") == "training-data-leak"]
                joined = json.dumps(findings, ensure_ascii=False)
                tail4 = FAKE_TOKEN[-4:]
                if FAKE_TOKEN in joined:
                    raise AssertionError("finding 泄漏完整假密钥")
                if f"****{tail4}" not in joined:
                    raise AssertionError("finding 未保留尾4位指纹")
                run.finalize_run()
                report = render_pentest(store, run.name)
                if FAKE_TOKEN in report:
                    raise AssertionError("报告泄漏完整假密钥")
                if f"****{tail4}" not in report:
                    raise AssertionError("报告未以尾4位呈现假密钥")
                return {
                    "finding_count": len(findings),
                    "tail4": tail4,
                    "redacted_sample": f"****{tail4}",
                    "full_token_absent": True,
                    "report_full_token_absent": True,
                    "report_redacted_sample": f"****{tail4}",
                }

            checks.run("data-leak-redaction", "数据泄露实效：fixture 假密钥仅尾4位进入报告", data_leak)

            rule_pack = root / "rules-pack"

            def rules_detection() -> dict[str, Any]:
                if rule_pack.exists():
                    shutil.rmtree(rule_pack)
                findings = [
                    {"step_key": f["step_key"], "severity": f["severity"], "title": f["title"],
                     "detail": f["detail"], "is_zeroday": bool(f.get("is_zeroday"))}
                    for f in run.findings
                ]
                generate_all(CHAINS_DIR, findings=findings, cni="native", out_dir=rule_pack)
                matrix = validate(str(rule_pack), lab.url("/"))
                summary = matrix["summary"]
                hits = int(summary["rules_detected"]) + int(summary["rules_blocked"])
                if hits < 1:
                    raise AssertionError(f"规则引擎 0 命中：{summary}")
                sample_hit = ""
                for cid, row in matrix.get("chains", {}).items():
                    for cell in row.get("rules", []):
                        if cell.get("status") in ("检测", "拦截"):
                            sample_hit = f"{cid} · {cell['rule']} · {cell['status']}"
                            break
                    if sample_hit:
                        break
                shutil.copyfile(rule_pack / "coverage-matrix.json", out / "rules-coverage-matrix.json")
                shutil.copyfile(rule_pack / "coverage-matrix.md", out / "rules-coverage-matrix.md")
                return {
                    "rules_evaluated": int(summary["rules_evaluated"]),
                    "rules_detected": int(summary["rules_detected"]),
                    "rules_blocked": int(summary["rules_blocked"]),
                    "rules_missed": int(summary["rules_missed"]),
                    "hits": hits,
                    "sample_hit": sample_hit,
                    "matrix_ok": bool(matrix.get("ok")),
                    "coverage_file": "rules-coverage-matrix.json",
                }

            checks.run("rules-detection", "检测规则实效：规则引擎对本次靶场重放 ≥1 条命中", rules_detection)

            chain_run = store.create_run(f"effects-chain-{stamp}")

            def chain_e2e() -> dict[str, Any]:
                chain = copy.deepcopy(load_chains(CHAINS_DIR)[TARGET_CHAIN])
                chain_marker = f"TRIDENT-{chain_run.name}"
                safe = _safe_name(f"/checkpoints/victim-{chain_marker}", "checkpoint")
                chain_victim = lab_root / "slime" / safe / "model.safetensors"
                chain_victim.parent.mkdir(parents=True, exist_ok=True)
                chain_victim.write_bytes(b"TRIDENT-CHAIN-WEIGHTS-ORIGINAL\n")
                chain_before = _sha256_file(chain_victim)
                for step in chain["steps"]:
                    step.setdefault("params", {})["target"] = lab.url("")
                    if step["module"] == "slime-weight-pull-poison":
                        step["params"]["mode"] = "backup-write"
                        step["params"]["backup_targets"] = [{"kind": "file", "path": str(chain_victim)}]
                findings = run.findings
                plan = dry_run(chain, findings, modules_dir=MODULES_DIR)
                write_steps = [s for s in plan["steps"] if s["writes"]]
                if not write_steps or not write_steps[0]["backup_actions"]:
                    raise AssertionError("dry-run 计划缺少写类步骤/备份动作")
                res = execute(chain, store, tester, modules_dir=MODULES_DIR,
                              findings=findings, workers=2, run=chain_run)
                if not res.get("ok"):
                    raise AssertionError(f"链执行失败：{res['steps']}")
                statuses = {sid: st["status"] for sid, st in res["steps"].items()}
                receipts = chain_run.query(
                    "SELECT COUNT(*) FROM backups WHERE run=? AND step_key='slime-weight-pull-poison'",
                    (chain_run.name,),
                )
                receipts = int(receipts[0][0]) if receipts else 0
                if receipts < 1:
                    raise AssertionError("链内权重投毒步骤无备份回执")
                chain_after = _sha256_file(chain_victim)
                chain_content = chain_victim.read_text(encoding="utf-8", errors="replace")
                if chain_after == chain_before or chain_marker not in chain_content:
                    raise AssertionError("链内权重投毒未真实改写权重副本")
                chain_run.finalize_run()
                context_ok = (chain_run.dir / "context.jsonl.gz").is_file()
                db_ok = (chain_run.dir / "evidence.db").is_file()
                archives = [p for p in (chain_run.dir / "steps").glob("*") if p.is_file()]
                manifest_ok = store.verify_manifest(chain_run.name)
                if not (context_ok and db_ok and archives and manifest_ok):
                    raise AssertionError(
                        f"三层证据不完整：context={context_ok} db={db_ok} archives={len(archives)} manifest={manifest_ok}"
                    )
                return {
                    "chain": TARGET_CHAIN,
                    "verdict": plan["verdict"],
                    "missing": plan["missing"],
                    "ok": True,
                    "steps": statuses,
                    "backup_receipts": receipts,
                    "weights_sha256_before": chain_before,
                    "weights_sha256_after": chain_after,
                    "marker_present": chain_marker in chain_content,
                    "layers": {
                        "context": context_ok,
                        "database": db_ok,
                        "archives": len(archives),
                        "manifest": manifest_ok,
                    },
                    "run": chain_run.name,
                }

            checks.run("chain-e2e", "端到端链：dry-run → execute（全影响演示级 + 备份 + 三层证据）", chain_e2e)

            result = {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "scope": SCOPE,
                "limitations": LIMITATIONS,
                "run": run.name,
                "chain_run": chain_run.name,
                "checks": checks.items,
                "summary": {
                    "total": len(checks.items),
                    "passed": checks.passed,
                    "failed": checks.failed,
                    "ok": checks.failed == 0,
                },
                "environment": {
                    "python": sys.version.split()[0],
                    "platform": sys.platform,
                    "mock_mode": "vulnerable",
                    "mock_host": "127.0.0.1",
                },
            }
        finally:
            lab.shutdown()

    _write_outputs(out, result, write_docs=write_docs)
    return result


# ---------------------------------------------------------------- 输出


def _md_table(result: dict[str, Any]) -> list[str]:
    lines = [
        "# Trident 实效验证报告（Effect Verification）",
        "",
        f"- 生成时间：{result['generated_at']}",
        f"- 验证 Run：`{result['run']}`；链 Run：`{result['chain_run']}`",
        f"- 范围与边界：{result['scope']}",
        f"- 汇总：**{result['summary']['passed']}/{result['summary']['total']} PASS**"
        f"（FAIL {result['summary']['failed']}）",
        "",
        "> **边界声明（必须随报告阅读）**：本验证为本机真实进程/真实 HTTP 效果级"
        "（`lab/mock_targets.py`，仅 127.0.0.1），**非 live K8s 集群**。"
        "KIND hostNetwork 绕过 NetworkPolicy 与 ARTEX（AGPL，黑盒对标）需启用虚拟化后，"
        "分别执行 `lab/kind/run-proof.sh` 与 `lab/bench/artex-bench.sh`；"
        "在虚拟化启用前，这两项不构成本报告的 PASS 结论。",
        "",
        "| 项 | 验证内容 | 结果 | 证据摘要 |",
        "|---|---|---|---|",
    ]
    for item in result["checks"]:
        status = "PASS" if item["status"] == "PASS" else "**FAIL**"
        evidence = json.dumps(item.get("evidence", {}), ensure_ascii=False)
        if item.get("detail"):
            evidence = (evidence + " " + item["detail"]).strip()
        evidence = evidence.replace("|", "\\|").replace("\n", " ")
        if len(evidence) > 420:
            evidence = evidence[:417] + "…"
        lines.append(f"| `{item['id']}` | {item['title']} | {status} | {evidence} |")
    lines += ["", "## 逐项证据", ""]
    for item in result["checks"]:
        lines.append(f"### {item['id']} — {'PASS' if item['status'] == 'PASS' else 'FAIL'}")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(item.get("evidence", {}), ensure_ascii=False, indent=2))
        lines.append("```")
        if item.get("detail"):
            lines.append("")
            lines.append(f"失败明细：`{item['detail']}`")
        lines.append("")
    lines += ["## 环境与限制", ""]
    for key, value in result["environment"].items():
        lines.append(f"- {key}: `{value}`")
    for limit in result["limitations"]:
        lines.append(f"- 限制：{limit}")
    lines += [
        "",
        "## 复现命令",
        "",
        "```bash",
        "python -m trident.verify-effects --out reports/samples/effects/",
        "python -m unittest tests.test_verify_effects -v",
        "```",
        "",
    ]
    return lines


def _write_outputs(out: Path, result: dict[str, Any], write_docs: bool) -> None:
    payload = _scrub(json.dumps(result, ensure_ascii=False, indent=2))
    (out / "effects.json").write_text(payload, encoding="utf-8")
    md = _scrub("\n".join(_md_table(result)))
    (out / "effects.md").write_text(md, encoding="utf-8")
    if write_docs:
        docs = REPO_ROOT / "docs" / "EFFECT-VERIFICATION.md"
        docs.parent.mkdir(parents=True, exist_ok=True)
        docs.write_text(md, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    parser = argparse.ArgumentParser(description="Trident 实效验证（本机真实 HTTP，仅 127.0.0.1）")
    parser.add_argument("--out", default=str(REPO_ROOT / "reports" / "samples" / "effects"),
                        help="输出目录（effects.json + effects.md）")
    parser.add_argument("--no-docs", action="store_true", help="不写 docs/EFFECT-VERIFICATION.md")
    args = parser.parse_args(argv)
    result = run_verification(Path(args.out), write_docs=not args.no_docs)
    for item in result["checks"]:
        mark = "PASS" if item["status"] == "PASS" else "FAIL"
        print(f"[{mark}] {item['id']} — {item['title']}"
              + (f"（{item['detail']}）" if item.get("detail") else ""))
    print(f"verify-effects: {result['summary']['passed']}/{result['summary']['total']} PASS"
          f" → {Path(args.out) / 'effects.json'}")
    return 0 if result["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
