"""trident/e2e-check.py — 端到端验收脚本（全部本机，可重复执行）。

用法::

    python trident/e2e-check.py [--samples DIR]     # 默认 reports/samples/
    python - <<'PY'                                  # 编程调用
    from pathlib import Path
    import importlib.util
    spec = importlib.util.spec_from_file_location("e2e", "trident/e2e-check.py")
    ...

流程（集成既有组件，一次临时工作区内闭环）：
① 起 lab/mock_targets vulnerable 靶场（仅 127.0.0.1，随机端口）
② 建工作区 + 授权（level=全影响演示）+ 四角色用户
③ 九族代表性子集（每族 ≥2 模块，probe-only；写类带 backup_targets 验证回滚还原）
④ 跑一条完整链 flat-network-admin-plane-weight-poison：dry-run 出计划 → execute 落证
⑤ 验收断言逐条输出 PASS/FAIL 清单（JSON+MD → reports/samples/e2e/）：
   consent 未签 runner/API 双路拒绝 / 备份闸 91 / 零日级模块（已公开）无需闸门 /
   三层证据 + manifest 校验（含篡改检测）/ report 双语渲染含已公开细节 + 可选脱敏 /
   rules generate_all 每链 ≥1 + 紫队矩阵零漏过 / export_static 兜底产物 /
   四角色矩阵与跨工作区隔离 / 样张清单落盘（本地绝对路径已清理）。

对应 设计基线第 18 节可本机闭环的验收条目；KIND/WSL 边界项见 docs/RUNBOOK.md 实验室边界。
文件名含连字符（计划口径），外部以 importlib 按路径装载。
"""

from __future__ import annotations

import copy
import json
import re
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.mock_targets import start_all  # noqa: E402
from trident.core.backup import BackupManager  # noqa: E402
from trident.core.chains import dry_run, execute, load_chains  # noqa: E402
from trident.core.evidence import EvidenceStore  # noqa: E402
from trident.core.registry import load_modules  # noqa: E402
from trident.core.roe import ExecutionLocked, init_roe  # noqa: E402
from trident.core.runner import BackupGateRefused, run_module  # noqa: E402
from trident.core.users import UserStore  # noqa: E402
from trident.core.zeroday import filter_modules  # noqa: E402
from trident.reports.render import render_pentest, render_remediation  # noqa: E402
from trident.rules.generate import generate_all  # noqa: E402
from trident.rules.validate import validate  # noqa: E402
from trident.webui.export_static import export_static  # noqa: E402
from trident.webui.server import make_server  # noqa: E402

MODULES_DIR = REPO_ROOT / "trident" / "modules"
CHAINS_DIR = REPO_ROOT / "trident" / "chains"
FIX = REPO_ROOT / "lab" / "fixtures"
DEFENSE_FIX = REPO_ROOT / "lab" / "defense-deploy" / "fixtures"
SAMPLE_REPO = REPO_ROOT / "lab" / "sample-vuln-repo"
DEFAULT_SAMPLES = REPO_ROOT / "reports" / "samples"

TARGET_CHAIN = "flat-network-admin-plane-weight-poison"

# 已公开零日级模块：报告默认展示细节；可选脱敏开关必须能隐藏该细节。
PUBLIC_ZERODAY_DETAIL = "无 Authorization 凭据即可创建/销毁 binding"
PUBLIC_ZERODAY_KEYS = ("dify-control-plane-failopen", "open-webui-code-execute-rce")

# 混合云过权角色快照（与 tests/test_modules_hybrid.py 同构的 mock 样值）
OVERPRIV_SNAPSHOT = {
    "provider": "aws",
    "role_name": "mock-node-role",
    "permissions": [
        {"action": "s3:PutObject", "resource": "arn:aws:s3:::train-checkpoints/weights/*"},
        {"action": "s3:DeleteObject", "resource": "arn:aws:s3:::train-checkpoints/*"},
        {"action": "kms:Decrypt", "resource": "*"},
        {"action": "sts:AssumeRole", "resource": "arn:aws:iam::999999999999:role/other-account"},
    ],
}

CNI_VARIANT_FILES = (
    ("native", "network/native/network-policy-default-deny.yaml"),
    ("calico", "network/calico/global-network-policy-default-deny.yaml"),
    ("cilium", "network/cilium/cilium-network-policy-default-deny.yaml"),
)


class _Checkbook:
    """验收清单：逐项 PASS/FAIL + 明细；异常即 FAIL（不中断后续检查）。"""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    @contextmanager
    def check(self, cid: str, title: str):
        item: dict[str, Any] = {"id": cid, "title": title, "status": "FAIL", "detail": ""}
        t0 = time.time()
        try:
            yield item
            item["status"] = "PASS"
        except Exception as exc:  # noqa: BLE001 —— 任何断言/运行异常都记为该检查 FAIL
            item["detail"] = f"{type(exc).__name__}: {exc}"
        finally:
            item["elapsed_ms"] = round((time.time() - t0) * 1000, 1)
            self.items.append(item)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.items if c["status"] == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for c in self.items if c["status"] != "PASS")


def _note(item: dict, text: str) -> None:
    item["detail"] = f"{item['detail']}; {text}" if item["detail"] else str(text)


def _http_json(url: str, method: str = "GET", body: dict | None = None, token: str = "") -> tuple[int, dict]:
    data = json.dumps(body or {}).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


def _subset_cases(lab_base: str) -> list[tuple[str, str, dict]]:
    """九族代表性子集（每族 ≥2 模块）：侦察/网络/权限链/横向/混合云/窃取/核心代码/绕过/零日级。

    权限链两模块 writes=true → 检测运行同样必须带 backup_targets（备份闸门对检测+演示一致生效）。
    零日级模块已公开（private=false），在 zeroday-public-no-gate 检查内默认执行。
    """
    recon_snap = json.loads((FIX / "recon" / "cluster-snapshot.json").read_text(encoding="utf-8"))
    defense = lambda product: json.loads((DEFENSE_FIX / f"{product}-deployed.json").read_text(encoding="utf-8"))  # noqa: E731
    cases: list[tuple[str, str, dict]] = [
        ("侦察", "exposure-mapping", {"snapshot": recon_snap}),
        ("侦察", "framework-port-matching", {"snapshot": recon_snap}),
        ("网络架构", "cni-stack-capability", {"snapshot": str(FIX / "network")}),
        ("网络架构", "multus-sriov-rdma-bypass", {"snapshot": str(FIX / "network")}),
        ("权限链", "vllm-operator-rbac-escalation", {
            "fixture": str(FIX / "perm" / "clusterroles.json"),
            "backup_targets": [{"kind": "file", "path": str(FIX / "perm" / "clusterroles.json")}],
        }),
        ("权限链", "overprivileged-sa-escalation", {
            "fixture": str(FIX / "perm" / "cani-matrix.json"),
            "backup_targets": [{"kind": "file", "path": str(FIX / "perm" / "cani-matrix.json")}],
        }),
        ("横向利用", "djev-open-proxy", {"target": lab_base, "mode": "probe-only"}),
        ("横向利用", "vllm-plugin-auth-bypass", {"target": lab_base, "mode": "probe-only"}),
        ("混合云", "multi-cloud-imds-credentials", {"target": lab_base, "mode": "probe-only"}),
        ("混合云", "cloud-role-overprivilege",
         {"target": lab_base, "mode": "probe-only", "role_snapshot": OVERPRIV_SNAPSHOT}),
        ("窃取与数据泄露", "shared-volume-weight-copy",
         {"volume_root": str(FIX / "theft" / "shared-volume")}),
        ("窃取与数据泄露", "training-data-leak", {"data_root": str(FIX / "theft")}),
        ("核心代码", "python-dangerous-sinks", {"root": str(SAMPLE_REPO)}),
        ("核心代码", "auth-gap-detection", {"root": str(SAMPLE_REPO)}),
        ("防护绕过", "defense-bypass-falco", {"deploy_snapshot": defense("falco")}),
        ("防护绕过", "defense-bypass-admission", {"deploy_snapshot": defense("admission")}),
    ]
    cases.append(("零日", "dify-control-plane-failopen",
                  {"base_url": lab_base, "backup_targets": [{"kind": "http", "url": lab_base, "state": {}}]}))
    cases.append(("零日", "open-webui-code-execute-rce",
                  {"base_url": lab_base, "backup_targets": [{"kind": "http", "url": lab_base, "state": {}}]}))
    return cases


def run_e2e(samples_dir: Path | str | None = None) -> dict[str, Any]:
    """执行完整端到端验收；返回结果 dict（含逐项检查与样张清单）。"""
    samples = Path(samples_dir) if samples_dir else DEFAULT_SAMPLES
    samples.mkdir(parents=True, exist_ok=True)
    book = _Checkbook()
    families_run: dict[str, list[str]] = {}
    all_findings: list[dict] = []  # 带逐步产出（含 reachable/port 等链前置字段）
    sample_files: list[str] = []
    run_name = ""

    lab = start_all(mode="vulnerable")
    try:
        with TemporaryDirectory(prefix="trident-e2e-") as td:
            root = Path(td)
            store = EvidenceStore(root, workspace="local-lab")
            users = UserStore(root / "users.json")
            users.create_user("e2e-admin", "x", "admin", ["*"])
            users.create_user("e2e-lead", "x", "lead", ["local-lab"])
            users.create_user("e2e-tester", "x", "tester", ["local-lab", "locked-lab"])
            users.create_user("e2e-auditor", "x", "auditor", ["local-lab"])
            lead = users.verify("e2e-lead", "x")
            tester = users.verify("e2e-tester", "x")
            auditor = users.verify("e2e-auditor", "x")

            # ① 靶场在位 -------------------------------------------------------
            with book.check("lab-mock-vulnerable", "lab mock 靶场（vulnerable）启动且路由清单可达") as it:
                code, data = _http_json(lab.url("/__routes__"))
                assert code == 200, f"/__routes__ 状态码 {code}"
                assert data.get("routes"), "路由清单为空"
                _note(it, f"{len(data['routes'])} 条路由 @ {lab.url('/')}")

            # ② 授权锁：consent 未签署 → runner 与 API 双路拒绝（设计基线 18.1）------
            with book.check("consent-lock-runner", "consent 未签署：runner 执行路径拒绝（ExecutionLocked）"):
                try:
                    run_module(store, tester, "exposure-mapping",
                               {"snapshot": {}}, modules_dir=MODULES_DIR)
                    raise AssertionError("未签署授权时 runner 竟放行")
                except ExecutionLocked:
                    pass

            with book.check("consent-lock-api", "consent 未签署：API /api/execute 返回 423") as it:
                httpd = make_server(root, users)
                try:
                    code, body = _http_json(httpd.url("/api/login") if hasattr(httpd, "url") else
                                            f"http://127.0.0.1:{httpd.port}/api/login",
                                            method="POST", body={"name": "e2e-tester", "password": "x"})
                    assert code == 200, f"登录失败 {code} {body}"
                    code, body = _http_json(f"http://127.0.0.1:{httpd.port}/api/execute", method="POST",
                                            body={"workspace": "local-lab", "module": "exposure-mapping",
                                                  "params": {}},
                                            token=body["token"])
                    assert code == 423, f"未签署授权 API 应回 423，实际 {code} {body}"
                    _note(it, f"HTTP {code}: {body.get('error', '')}")
                finally:
                    httpd.shutdown()
                    httpd.server_close()

            # 签署授权（level=全影响演示，覆盖全部模块级别）
            init_roe(store, fields={
                "level": "全影响演示",
                "namespaces": ["train", "infer", "ray-system", "default", "ml-agent"],
                "cidrs": ["127.0.0.0/8"],
                "window": "2026-10-25 00:00 – 23:59（验收实验室）",
                "client": "Trident 验收实验室（本机 mock）",
            })

            # ③ 备份闸门：写类无 backup_targets → 退出码 91（设计基线 18.2）----------
            with book.check("backup-gate-exit-code-91",
                            "写类模块无备份回执：BackupGateRefused 且退出码语义 91、模块未执行") as it:
                pre_runs = store.ws_dir.exists()
                assert pre_runs
                try:
                    run_module(store, tester, "vllm-operator-rbac-escalation",
                               {"fixture": str(FIX / "perm" / "clusterroles.json")},  # 无 backup_targets
                               modules_dir=MODULES_DIR)
                    raise AssertionError("无备份回执时写类模块竟放行")
                except BackupGateRefused as exc:
                    assert exc.exit_code == 91, f"退出码 {exc.exit_code} != 91"
                    _note(it, str(exc))

            run = store.create_run(f"e2e-acceptance-{time.strftime('%Y%m%d-%H%M%S')}")
            run_name = run.name

            # ④ 九族代表性子集 + 写类回滚还原（设计基线 18.3 / 18.11–18.17 的本机面）---
            with book.check("module-family-subset",
                            "九族代表性子集（每族 ≥2 模块）全部执行且产出发现；写类 backup-write 演示可回滚还原") as it:
                zero_day_keys = {"dify-control-plane-failopen", "open-webui-code-execute-rce"}
                for family, key, params in _subset_cases(lab.url("/")):
                    if key in zero_day_keys:
                        continue  # 零日子集在启用闸门检查内执行
                    result = run_module(store, tester, key, copy.deepcopy(params),
                                        modules_dir=MODULES_DIR, run=run)
                    findings = result.get("findings", [])
                    for f in findings:
                        f.setdefault("step_key", key)
                    all_findings.extend(findings)
                    assert result.get("step") == key, f"{key} 步骤落证异常: {result}"
                    families_run.setdefault(family, []).append(key)
                for family, keys in families_run.items():
                    assert len(keys) >= 2, f"族 {family} 代表性不足: {keys}"
                # 写类演示（backup-write 写 marker → 回滚还原）：用独立模块键避免与检测步骤同键覆写归档
                demo = root / "demo-rbac.txt"
                demo.write_text("original", encoding="utf-8")
                run_module(store, tester, "privileged-gpu-pod-escape", {
                    "fixture": str(FIX / "perm" / "privileged-pods.json"),
                    "mode": "backup-write", "demo_target": str(demo),
                    "backup_targets": [{"kind": "file", "path": str(demo)}],
                }, modules_dir=MODULES_DIR, run=run)
                assert "TRIDENT-" in demo.read_text(encoding="utf-8"), "演示分支未写入 marker"
                BackupManager(store, run).rollback("privileged-gpu-pod-escape-demo")
                assert demo.read_text(encoding="utf-8") == "original", "回滚后未还原原内容"
                _note(it, " / ".join(f"{f}×{len(k)}" for f, k in sorted(families_run.items())) + "；写类演示已回滚还原")

            # ⑤ 链目录 + dry-run（设计基线 18.4）-----------------------------------
            with book.check("chain-catalog-dryrun",
                            "链目录齐全（经典/云侧/网络/零日）且 dry-run 输出可读计划（备份动作+写面）") as it:
                chains = load_chains(CHAINS_DIR)
                assert len(chains) >= 18, f"链数量 {len(chains)} < 18"
                cats = {c.get("category") for c in chains.values()}
                assert {"经典攻击链", "云侧权重桶链", "网络利用链"} <= cats, f"缺类别: {cats}"
                chain = chains[TARGET_CHAIN]
                plan = dry_run(chain, all_findings, modules_dir=MODULES_DIR)
                assert plan["verdict"] in ("成立", "部分成立", "不成立"), plan["verdict"]
                write_steps = [s for s in plan["steps"] if s["writes"]]
                assert write_steps, "计划中无写类步骤"
                assert write_steps[0]["backup_actions"], "写类步骤缺备份动作清单"
                assert write_steps[0]["write_surface"], "写类步骤缺预计写面"
                _note(it, f"{len(chains)} 链 / {len(cats)} 类；{TARGET_CHAIN} 判定={plan['verdict']}"
                          f"（缺失 {len(plan['missing'])} 条前置）")

            # ⑥ 完整链执行：dry-run 计划 → execute 落证（设计基线 18.4/18.5）---------
            with book.check("chain-execute-weight-poison",
                            "完整链执行（平网→管理面→权重投毒）：全部步骤成功 + 备份回执在库") as it:
                chain_exec = copy.deepcopy(chain)
                for st in chain_exec["steps"]:
                    st.setdefault("params", {})["target"] = lab.url("")
                    if st["module"] == "slime-weight-pull-poison":
                        st["params"]["backup_targets"] = [
                            {"kind": "http", "url": lab.url("/pull_weights"), "state": {}}]
                res = execute(chain_exec, store, tester, modules_dir=MODULES_DIR,
                              findings=all_findings, workers=2, run=run)
                assert res["ok"], f"链执行失败: {res['steps']}"
                receipts = run.query(
                    "SELECT target FROM backups WHERE run=? AND step_key='slime-weight-pull-poison'",
                    (run.name,))
                assert receipts, "权重投毒步骤无备份回执"
                for f in run.query(
                        "SELECT step_key FROM findings WHERE run=? AND step_key IN ('sglang-admin-failopen','slime-weight-pull-poison')",
                        (run.name,)):
                    all_findings.append({"step_key": f[0]})
                _note(it, "步骤 " + "、".join(f"{sid}:{st['status']}" for sid, st in res["steps"].items()))

            # ⑦ 三层证据 + manifest 完整性（设计基线 18.3；含篡改检测）----------------
            with book.check("evidence-three-layers-manifest",
                            "三层证据齐备（上下文摘要/SQLite/归档 tar+SHA256）且 manifest 校验通过、篡改可检出") as it:
                ctx_layer = run.dir / "context.jsonl.gz"
                db_layer = run.dir / "evidence.db"
                arch_layer = run.dir / "steps"
                for p in (ctx_layer, db_layer):
                    assert p.is_file(), f"缺层 {p}"
                archives = sorted(arch_layer.iterdir())
                assert archives, "归档层为空"
                rows = run.query("SELECT COUNT(*) FROM steps WHERE run=?", (run.name,))
                assert rows[0][0] >= len(families_run) + 2, f"数据库层步骤行异常: {rows[0][0]}"
                assert store.verify_manifest(run.name) is True, "manifest 校验未通过"
                # 篡改检测：改归档字节 → 校验必须失败 → 还原后复通过
                victim = archives[0]
                original = victim.read_bytes()
                victim.write_bytes(original + b"tampered")
                assert store.verify_manifest(run.name) is False, "篡改归档后 manifest 竟仍通过"
                victim.write_bytes(original)
                assert store.verify_manifest(run.name) is True, "还原后 manifest 未恢复通过"
                _note(it, f"{rows[0][0]} 步骤 / {len(archives)} 归档 / 篡改检出✓")

            # ⑧ 零日级漏洞模块（已公开）：无需零日闸门，默认可见可执行 ----------
            with book.check("zeroday-public-no-gate",
                            "零日级漏洞模块（已公开）无需零日闸门：默认可见、可直接执行，"
                            "发现带 is_zeroday 审计标记") as it:
                mods = {k: m.__dict__ for k, m in load_modules(MODULES_DIR).items()}
                visible = filter_modules(mods, store)
                for key in PUBLIC_ZERODAY_KEYS:
                    assert key in mods, f"{key} 未注册"
                    assert not mods[key].get("private"), f"{key} 已公开，不得标记 private"
                    assert key in visible, f"零日扩展未启用时 {key} 也应可见"
                zd_count = 0
                for key in PUBLIC_ZERODAY_KEYS:
                    result = run_module(store, tester, key,
                                        {"base_url": lab.url("/"),
                                         "backup_targets": [{"kind": "http", "url": lab.url("/"), "state": {}}]},
                                        modules_dir=MODULES_DIR, run=run)
                    for f in result.get("findings", []):
                        f.setdefault("step_key", key)
                        assert f.get("is_zeroday"), f"{key} 发现缺 is_zeroday"
                    all_findings.extend(result.get("findings", []))
                    families_run.setdefault("零日", []).append(key)
                zd_rows = run.query("SELECT COUNT(*) FROM findings WHERE run=? AND is_zeroday=1", (run.name,))
                zd_count = zd_rows[0][0]
                assert zd_count >= 2, f"零日级发现落库 {zd_count} < 2"
                _note(it, f"公开✓ / private=false✓ / 无需 enable✓ / is_zeroday 落库 {zd_count} 条")

            run.finalize_run()

            # ⑨ 双语报告 + 已公开零日级细节默认展示 + 可选脱敏开关（设计基线 18.5）----
            with book.check("report-bilingual-public-details",
                            "双语渗透+修复报告渲染：PTES/专节/标准映射/CVSS/证据锚齐备；"
                            "已公开零日级细节默认展示，可选脱敏开关生效") as it:
                pentest = render_pentest(store, run.name)
                remediation = render_remediation(store, run.name)
                redacted = render_pentest(store, run.name, redact_zeroday=True)
                for token in ("渗透测试报告", "Penetration Test Report", "中英对照 / Bilingual (CN/EN)",
                              "sha256:", "CVSS", "等保", "NIST"):
                    assert token in pentest, f"渗透报告缺要素 {token}"
                for token in ("修复报告", "Remediation Report", "复测计划"):
                    assert token in remediation, f"修复报告缺要素 {token}"
                assert PUBLIC_ZERODAY_DETAIL in pentest, "已公开零日级细节默认未展示"
                assert "影响已验证 + 证据哈希" not in pentest, "默认报告不应脱敏已公开模块细节"
                assert "影响已验证 + 证据哈希" in redacted, "可选脱敏开关未生效"
                assert PUBLIC_ZERODAY_DETAIL not in redacted, "可选脱敏后仍泄漏已公开模块细节"
                assert "verified" in pentest, "manifest 校验状态未注入报告"
                (samples / "pentest-report-bi.md").write_text(pentest, encoding="utf-8")
                (samples / "pentest-report-bi-redacted.md").write_text(redacted, encoding="utf-8")
                (samples / "remediation-report-bi.md").write_text(remediation, encoding="utf-8")
                sample_files += ["pentest-report-bi.md", "pentest-report-bi-redacted.md",
                                 "remediation-report-bi.md"]
                _note(it, f"渗透 {len(pentest)} 字符 / 修复 {len(remediation)} 字符；"
                          f"默认展示✓ / 可选脱敏 {len(redacted)} 字符✓")

            # ⑩ 规则包：每链 ≥1 + 三 CNI 变体 + 四引擎产物（设计基线 18.8/18.13）------
            with book.check("rules-pack-coverage",
                            "规则包 generate_all：每链 ≥1 规则，三 CNI 变体 + Sigma/Falco/Suricata 产物齐备") as it:
                pack_dir = samples / "rules-pack"
                if pack_dir.exists():
                    import shutil

                    shutil.rmtree(pack_dir)
                pack = generate_all(CHAINS_DIR, findings=all_findings, cni="native", out_dir=pack_dir)
                mapping = json.loads((pack_dir / "mapping.json").read_text(encoding="utf-8"))
                chains = load_chains(CHAINS_DIR)
                covered = {cid for r in mapping["rules"] for cid in r["blocks_chains"]}
                missing = sorted(set(chains) - covered)
                assert not missing, f"零规则链: {missing}"
                for name, rel in CNI_VARIANT_FILES:
                    assert (pack_dir / rel).is_file(), f"缺 {name} CNI 变体 {rel}"
                for engine in ("sigma", "falco", "suricata"):
                    d = pack_dir / engine
                    assert d.is_dir() and any(d.iterdir()), f"缺 {engine} 规则产物"
                assert mapping["zeroday"], "缺零日行为化签名登记"
                sample_files.append("rules-pack/**")
                _note(it, f"{pack.total_rules} 规则 / {pack.covered_chain_count} 链全覆盖 / 三变体+四引擎✓")

            # ⑪ 紫队验证覆盖率矩阵（设计基线 18.8）------------------------------------
            with book.check("purple-coverage-matrix",
                            "紫队验证：mock 靶场重放 + 简化匹配器 → 覆盖率矩阵零漏过") as it:
                matrix = validate(str(samples / "rules-pack"), lab.url("/"))
                assert matrix["ok"], f"矩阵判定失败: {matrix['summary']}"
                assert matrix["summary"]["missed"] == 0, f"漏过 {matrix['summary']['missed']} 条链"
                states = {row["state"] for row in matrix["chains"].values()}
                assert states <= {"拦截", "检测", "拦截+检测"}, f"异常态: {states}"
                _note(it, f"{matrix['summary']['chains']} 链 / 0 漏过 / 态集合 {sorted(states)}")

            # ⑫ 六视图离线兜底（设计基线 18.6）---------------------------------------
            with book.check("export-static-offline",
                            "export_static 免服务产物：index.html 内嵌 TRIDENT_DATA（file:// 可开六视图）") as it:
                html_path = export_static(run.dir, samples / "static-export")
                html = html_path.read_text(encoding="utf-8")
                assert "window.TRIDENT_DATA" in html, "静态导出未注入数据"
                assert run.name in html, "静态导出缺 run 数据"
                assert (html_path.parent / "app.js").is_file(), "静态导出缺资产"
                sample_files.append("static-export/**")
                _note(it, str(html_path.relative_to(samples)))

            # ⑬ 四角色矩阵 + 跨工作区隔离（设计基线 18.7）----------------------------
            with book.check("roles-and-workspace-isolation",
                            "四角色动作矩阵符合规格；auditor 跨工作区访问被拒、无执行权") as it:
                admin = users.verify("e2e-admin", "x")
                assert admin.can("manage") and admin.can("approve-zeroday")
                assert lead.can("approve") and lead.can("approve-zeroday") and not lead.can("manage")
                assert tester.can("execute") and not tester.can("approve")
                assert auditor.can("read") and auditor.can("report") and not auditor.can("execute")
                auditor.open_store(root, "local-lab")  # 成员工作区可读
                try:
                    auditor.open_store(root, "locked-lab")
                    raise AssertionError("auditor 跨工作区访问竟放行")
                except PermissionError:
                    pass
                try:
                    run_module(store, auditor, "exposure-mapping", {"snapshot": {}},
                               modules_dir=MODULES_DIR, run=run)
                    raise AssertionError("auditor 竟可执行模块")
                except PermissionError:
                    pass
                _note(it, "admin*/lead/tester/auditor 矩阵✓；跨工作区拒✓；auditor 执行拒✓")

            # ⑭ 样张清单落盘 ----------------------------------------------------
            with book.check("samples-written", "样张清单全部落盘 reports/samples/") as it:
                expected = [
                    "pentest-report-bi.md", "remediation-report-bi.md",
                    "rules-pack/mapping.json", "rules-pack/coverage-matrix.json",
                    "rules-pack/coverage-matrix.md", "static-export/index.html",
                ] + [f"rules-pack/{rel}" for _, rel in CNI_VARIANT_FILES]
                missing = [rel for rel in expected if not (samples / rel).exists()]
                assert not missing, f"样张缺失: {missing}"
                _note(it, f"{len(expected)}+ 项样张在库（e2e 清单收尾写入；rules-pack 全树另计）")
    finally:
        lab.shutdown()

    result = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "run": run_name,
        "checks": book.items,
        "total": len(book.items),
        "passed": book.passed,
        "failed": book.failed,
        "ok": book.failed == 0,
        "families": {f: ks for f, ks in sorted(families_run.items())},
        "samples": sample_files,
    }
    _write_checklist(samples, result)
    _scrub_public_paths(samples)
    return result


# 本地绝对路径（Windows 盘符 / 反斜杠或 JSON 双反斜杠）→ `<abs-path>`；样张为公开交付物。
_ABS_PATH_RES = (
    re.compile(r"[A-Za-z]:\\\\[^\s\"',;|()\[\]{}<>：，；（）]+"),
    re.compile(r"[A-Za-z]:\\[^\s\"',;|()\[\]{}<>：，；（）]+"),
)


def _scrub_public_paths(root: Path) -> None:
    """清理样张中的本机绝对路径（盘符路径 / 用户临时目录），避免公开树泄漏环境信息。"""
    for p in sorted(Path(root).rglob("*")):
        if not p.is_file() or p.suffix.lower() not in (".json", ".md", ".html"):
            continue
        text = p.read_text(encoding="utf-8")
        cleaned = text
        for rx in _ABS_PATH_RES:
            cleaned = rx.sub("<abs-path>", cleaned)
        if cleaned != text:
            p.write_text(cleaned, encoding="utf-8")


def _write_checklist(samples: Path, result: dict[str, Any]) -> None:
    e2e_dir = samples / "e2e"
    e2e_dir.mkdir(parents=True, exist_ok=True)
    (e2e_dir / "e2e-check.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [
        "# Trident 端到端验收清单（e2e-check）",
        "",
        f"- 运行 Run：`{result['run']}`",
        f"- 生成时间：{result['generated_at']}",
        f"- 结果：**{'全部通过' if result['ok'] else '存在失败项'}**"
        f"（{result['passed']}/{result['total']} PASS）",
        f"- 模块族覆盖：{'、'.join(f'{f}×{len(ks)}' for f, ks in result['families'].items())}",
        "",
        "| 检查项 | 标题 | 状态 | 明细 | 耗时(ms) |",
        "|---|---|---|---|---|",
    ]
    for c in result["checks"]:
        status = "PASS" if c["status"] == "PASS" else f"**{c['status']}**"
        detail = str(c.get("detail", "")).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {c['id']} | {c['title']} | {status} | {detail} | {c.get('elapsed_ms', '')} |")
    lines += [
        "",
        "> 对应 设计基线第 18 节验收标准中可本机闭环条目；KIND/WSL 边界项（规则实际拦截重放、",
        "> hostNetwork 实证、bench 对比）见 `docs/RUNBOOK.md` 实验室边界章节与 `lab/bench/BENCH-RESULT.md`。",
        "",
    ]
    (e2e_dir / "e2e-check.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    samples = DEFAULT_SAMPLES
    args = list(sys.argv[1:] if argv is None else argv)
    if "--samples" in args:
        samples = Path(args[args.index("--samples") + 1])
    result = run_e2e(samples)
    for c in result["checks"]:
        mark = "PASS" if c["status"] == "PASS" else "FAIL"
        print(f"[{mark}] {c['id']} — {c['title']}" + (f"（{c['detail']}）" if c.get("detail") else ""))
    print(f"e2e: {result['passed']}/{result['total']} PASS"
          f" → {Path(samples) / 'e2e' / 'e2e-check.json'}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
