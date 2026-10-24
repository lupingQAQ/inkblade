# Trident RUNBOOK（操作手册）

> 适用版本：v0.1.0 · 运行环境：Windows / Python 3.10+（仅标准库运行时；`zstd`/`cryptography` 可选，缺失自动降级）
> 一切执行仅限已授权工作区；无授权记录时 CLI 与 API 同源拒绝（退出/HTTP 423）。

## 1. 安装与初始化

```powershell
# 项目根（本仓库）
cd D:\llm-audit-2026-10\projects\trident-2026-10
# Python 解释器（工作区共享 reproenv）
D:\llm-audit-2026-10\env\reproenv-d\Scripts\python.exe -m unittest discover -s tests -v   # 全绿再开工
```

- 目录约定：`--home`（默认 `.`）下生成 `evidence/<workspace>/<run>/`、`users.json`、`modules/`（即 `trident/modules`，可软链/复制到 home）。
- 首次初始化：`python -m trident --home . user add admin <口令> admin --workspaces *`（口令仅此一次明文输入，库存 scrypt 哈希）。

## 2. 用户与授权（consent / ROE）

```python
# scripts/等效最小片段（授权签署 = 工作区级 consent.json）
from pathlib import Path
from trident.core.evidence import EvidenceStore
from trident.core.roe import init_roe, roe_status
from trident.core.users import UserStore

home = Path(".")
users = UserStore(home / "users.json")
users.create_user("lead1", "…", "lead", ["local-lab"])
users.create_user("tester1", "…", "tester", ["local-lab"])

store = EvidenceStore(home, workspace="local-lab")
init_roe(store, fields={
    "level": "全影响演示",            # 只读侦察 < 主动探测 < 利用验证 < 全影响演示
    "namespaces": ["train", "infer"], # 命名空间白名单
    "cidrs": ["10.0.0.0/16"],        # 目标 CIDR 白名单
    "window": "2026-10-25 00:00–23:59", "client": "甲方名称",
})
assert roe_status(store) == "complete"
```

- 角色矩阵：`admin`（全部）/ `lead`（执行+审批+零日审批，无 manage）/ `tester`（执行+报告）/ `auditor`（只读+报告）。
- 级别闸门：模块 `min_level` 高于授权级别 → `ExecutionLocked`；范围外命名空间/IP → 拒绝。
- **零日启用**（默认关，登记册不可见）：`python -c "from trident.core.zeroday import enable; enable(store, lead_session)"`——需 `approve-zeroday` 角色，写入 `workspace.json` 并留审计。

## 3. 跑模块与链（CLI + API）

### 3.1 模块清单与单模块执行

```powershell
python -m trident module list --modules-dir trident/modules   # 键/系列/级别/读写
python -m trident roe --workspace local-lab                    # complete | absent
python -m trident ui --port 8765                               # 本地控制台（六视图 SPA）
```

```python
# 编程执行（runner = 唯一执行路径：授权闸门 + 备份闸门 + 三层落证 + 审计）
from trident.core.runner import run_module
result = run_module(store, tester_session, "sglang-admin-failopen",
                    {"target": "http://127.0.0.1:30000", "mode": "probe-only"},
                    modules_dir="trident/modules")
```

- **probe-only**（默认）：仅探测不落写；**写类模块**（`writes=true`）必须 `params.backup_targets=[...]`，否则 `BackupGateRefused`（退出码语义 **91**），且演示分支需显式 `mode=backup-write`。
- marker 一律 `TRIDENT-<run>`，靶场/文件残留可按此前缀审计清理。

### 3.2 链：dry-run → execute

```python
from trident.core.chains import load_chains, dry_run, execute
chains = load_chains("trident/chains")                 # 18 条：经典/云侧权重桶/网络/零日
plan = dry_run(chains["flat-network-admin-plane-weight-poison"], findings, modules_dir=...)
# plan.verdict ∈ 成立/部分成立/不成立；plan.steps[].backup_actions / write_surface = 预览写面
res = execute(chain, store, tester_session, modules_dir=..., findings=..., workers=4)
# 全部步骤共用一个证据 run；依赖失败 → 下游 skipped；strict=True 时非「成立」拒绝执行
```

### 3.3 API（与 CLI 同源闸门）

```
POST /api/login {name,password} → {token}
POST /api/execute {workspace,module,params}   # 401 未登录 / 403 越权 / 423 未签署授权 / 409 备份闸等
GET  /api/runs?workspace=…                     # 工作区隔离过滤
```

## 4. 报告与规则导出

```python
from trident.reports.render import render_pentest, render_remediation
from trident.rules.generate import generate_all
from trident.rules.validate import validate
from trident.webui.export_static import export_static

pentest = render_pentest(store, run_name)          # 双语（bi/zh/en），零日默认脱敏
remediation = render_remediation(store, run_name)  # 立即/短期/中期基线 + 逐发现建议 + 复测计划
pack = generate_all("trident/chains", findings=..., cni="native", out_dir="reports/samples/rules-pack")
matrix = validate(pack.out_dir, "http://127.0.0.1:<mock-port>/")   # 紫队覆盖率矩阵（0 漏过）
export_static(run_dir, "reports/samples/static-export")            # file:// 免服务六视图
```

- 规则包：Kyverno + Gatekeeper 准入、NetworkPolicy per-CNI 三变体（native/Calico/Cilium）+ VPC-native 安全组补充、Sigma/Falco/Suricata 检测、RBAC 收敛清单、`mapping.json`（规则↔链矩阵，每链 ≥1 规则硬校验）；全部默认 monitor 模式 + 中英调参建议。
- 端到端一键复跑：`python trident/e2e-check.py`（15 项 PASS/FAIL 清单 → `reports/samples/e2e/`）。

## 5. 回滚与紧急停止

- **步骤回滚**：`BackupManager(store, run).rollback("<module-key>")`；整 run：逐步骤回滚（按 `backups` 表回执）。
- **备份语义**：file → 副本+sha256 还原；kube → 清单快照（`kubectl-apply` 人工执行）；http → 响应/状态存档（登记 `http-restore`）。
- **紧急停止**：API `POST /api/abort`（置全局 abort 标志）；Ctrl+C 终止 CLI/链执行——已落盘写面按 run 的 `backups` 表回执清单人工/脚本回滚。
- 每步动作全量入 `actions` 表（主体/工作区/目标/参数/结果/回滚指针，零日另标 `is_zeroday=1`）。

## 6. 实验室（mock / KIND / WSL 边界）

- **mock 靶场**（本机闭环，全部自测/验收的默认靶标）：
  `python lab/mock_targets.py --mode vulnerable|fixed [--port 0]`——单端口 25 路由：sglang 管理面/slime 权重拉取/areal 三步链/ray dashboard/vllm 插件/djev/dify-agent/open-webui/五云 IMDS；`GET /__routes__` 自描述。仅监听 127.0.0.1。
- **KIND（WSL 内）**：`lab/kind/run-proof.sh`——hostNetwork Pod 绕过 NetworkPolicy 实证（自校验 verdict：bypass-confirmed / bypass-not-observed / environment-invalid）；`lab/kind/hostnetwork-bypass.yaml`、`default-deny-netpol.yaml`。
- **bench**：`python -m lab.bench.bench smoke`（链路径/五路由兜底双态计时 + RSS 采样，结果入 `lab/bench/BENCH-RESULT.md`；ARTEX 对比 `lab/bench/artex-bench.sh` 为 manual 项）。
- **边界声明（本机 Windows 交付口径）**：
  - WSL2 当前不可用（HCS_E_HYPERV_NOT_INSTALLED）→ KIND 实证脚本与「规则实际拦截重放」「VPC-CNI hostNode 等价面实证」交付为可重复脚本 + 待实跑标注；IB/RDMA/IMEX 无硬件面以 fixture 推演 + 人工核验清单交付。
  - 紫队闭环在本机以 mock 靶场重放 + 内置简化匹配器完成（覆盖率矩阵零漏过）；Falco/Kyverno 实际部署重放按 `lab/defense-deploy/` 脚本在 WSL 恢复后执行。
