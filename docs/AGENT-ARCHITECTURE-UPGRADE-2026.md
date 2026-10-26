# Agent 架构升级实施说明（2026-10）

> 研究背景与差距反思见 `docs/AGENT-ARCHITECTURE-2026.md`；本文只写 **已落地的实现**、
> 边界与默认开关。全部模块默认只读/默认关闭写面，执行路径仍逐动作经过 runner 的三道
> 闸门（ROE 同意锁 → 备份闸门 91 → 三层落证/审计）。

## 1. 七个核心模块

| 模块 | 能力 | 默认 | 关键 API |
|---|---|---|---|
| `core/journal.py` | durable execution 事件日志：append-only JSONL + 链式 SHA256 + checkpoint + resume/replay | 仅记录，不执行 | `Journal.append/verify/resume/replay` |
| `core/supervisor.py` | 分层 supervisor-worker：持久队列 + 有界并发 1–8 + 失败重派 + 审批门 | 未批准动作拒绝入队 | `Supervisor.submit/run` |
| `core/memory.py` | 三层记忆：working（run 上下文）/ episodic（evidence DB 检索）/ semantic（资产/模块/技能图谱） | 只读检索 | `Memory.retrieve/compact` |
| `core/skills.py` | 技能库：成功 run → playbook + 版本 + 成功统计 + 审批入库 | draft→pending→approved | `SkillLibrary.extract/submit/approve/search` |
| `core/reflexion.py` | 运行后自反思：失败/降级 → 建议 → pending 技能 | **零执行** | `reflect/propose_skill/render_md` |
| `core/a2a.py` | A2A agent card + task 状态机（只读委派）+ MCP stdio 客户端（只读工具） | 写技能/写工具拒绝 | `A2AServer/agent_card/MCPClient` |
| `core/sandbox.py` | 工具执行沙箱：python -I 子进程 + 超时 + 内存限制（POSIX）+ 禁网开关 + 审计 | 不可信代码默认禁网 | `Sandbox.run_python/run_untrusted` |
| `core/agentops.py` | 门面：审批计划 → supervisor（journal）→ reflexion → 技能提案，一条可审计闭环 | 不绕过任何闸门 | `run_approved_plan` |

## 2. 硬边界（测试锁定）

1. **提议 ≠ 执行**：`reflexion.reflect()` 只读 evidence DB，不 import runner；测试用
   monkeypatch 炸弹证明零调用。
2. **worker 只执行已批准动作**：`supervisor.submit()` 校验每个动作的
   `approval.status == approved`（或所属 proposal 整体批准），否则 `ApprovalRequired`
   且队列零残留；执行器默认就是 `runner.run_module`。
3. **只读委派**：A2A 内置技能白名单（list_runs/get_findings/get_chain_plan/
   get_agent_card/search_skills）；未知/写技能直接 `rejected`。MCP 客户端仅接受
   `annotations.readOnlyHint=true` 或读前缀工具，显式 False/未知一律拒绝。
4. **沙箱不是隔离证明**：`python -I` + 禁网 monkeypatch + 墙钟超时 + POSIX rlimit；
   Windows 无 rlimit（`limits.memory=false` 如实标注）。文档不宣称内核级隔离。
5. **写面仍走 runner**：备份闸门/ROE 级别/零日闸门原样生效；supervisor 不绕过。

## 3. 组合用法（库 API）

```python
from inkblade.core.evidence import EvidenceStore
from inkblade.core.users import Session
from inkblade.core.journal import Journal
from inkblade.core.supervisor import Supervisor
from inkblade.core.skills import SkillLibrary
from inkblade.core import reflexion, memory

store = EvidenceStore(".", workspace="local-lab")
session = Session(None, "lead", "lead", ["local-lab"], "local")

# 1) 已批准动作 → supervisor 队列（默认执行器走 runner 三闸门）
sup = Supervisor(store, session, workers=4, max_attempts=2,
                 journal=Journal.for_store(store))
sup.submit([{"module": "exposure-mapping", "params": {"snapshot": "..."},
             "approval": {"status": "approved", "approved_by": "lead"}}])
result = sup.run()

# 2) 反思（零执行）→ pending 技能（仍需 lead approve）
report = reflexion.reflect(store.open_run(result["tasks"][0]["result"]["run"]))
pending = reflexion.propose_skill(report, SkillLibrary(store), session)
SkillLibrary(store).approve(session, pending["id"])

# 3) 三层记忆检索（只读）
items = memory.Memory(store, modules_dir=store.root / "modules").retrieve("特权逃逸", k=5)
```

## 4. 评测

`lab/agent-eval/`（15 任务，6 类）对比 deterministic 与 supervisor-worker 的成功率/
耗时/token/审批次数；结果见 `docs/AGENT-EVAL-RESULTS.md` 与
`reports/samples/agent-eval/agent-eval.json`。故障注入显式记录在
`config.fault_injection`（gateway-auth 首次尝试 TimeoutError），不与真实能力混淆。

## 5. 相关文档

- `docs/AGENT-ARCHITECTURE-2026.md`（研究/差距反思）
- `docs/GAP-ATTACK-SURFACE.md` / `docs/GAP-PAYLOADS.md`（缺口状态）
- `docs/KUBETRAIL-PORT.md`（KubeTrail 移植与许可）
- `NOTICE`（Apache-2.0 署名）
