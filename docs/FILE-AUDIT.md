# 操作与文件访问审计（FILE-AUDIT）

本文说明「可看执行操作、读取的文件」这条能力的实现边界：探针事件模型、
evidence DB 的 `file_ops` 表、统一 `timeline.json`、WebUI 时间线/证据浏览器
联动、报告「操作与文件访问台账」节，以及对应的 SOC 审计键。

设计原则：

1. **只读目标容器**。控制器与探针两侧执行同一份宿主逃逸拒绝规则；
   任何一侧命中都直接失败（不是「读不到就当通过」）。
2. **不伪造采样**。旧探针没有 `audit-exec` 时登记 `result=unsampled`，
   `opened_files` 为空并写明原因，不把「未采样」渲染成「没有打开文件」。
3. **证据可对账**。命令落 `stdout` 摘要（SHA256），文件落内容 SHA256；
   时间线事件带 `evidence_sha256` 与可回链 `ref`（`file_ops#N` / `actions#N`）。

---

## 1. 事件模型

`inkblade/core/fileaudit.py` 定义字段（与 `file_ops` 表一一对应）：

| 字段 | 说明 |
|---|---|
| `step_id` / `step_key` | 关联 `steps` 表；由 `resolve_step_id()` 取该 step 最新行 |
| `task_id` | 探针任务号（`probe_tasks.task_id`） |
| `probe_id` / `cluster` / `namespace` | 执行主体与目标位置 |
| `pid` | 子进程 PID（`audit-exec` 返回） |
| `argv` | 命令参数（JSON 数组，原值入库；展示层脱敏） |
| `cwd` | 工作目录 |
| `env_digest` | 环境变量排序后 SHA256（不落明文） |
| `opened_files` | `[{path, mode: read\|write\|rw, fd, size_bytes, sha256}]` |
| `path` / `mode` / `size_bytes` / `sha256` | 显式 `read`/`write`/`list` 事件的文件字段 |
| `exit_code` | 退出码（超时 `-1`） |
| `stdout_hash` | stdout SHA256 |
| `duration_ms` | 执行耗时 |
| `technique` | 可选 ATT&CK/技术标签（由调用方传入） |
| `ts` / `phase` / `op` / `result` / `detail` | 时间、阶段（pre/post）、操作、结果、备注 |

`op` 取值：

- `exec`：命令级事件，文件来自 `/proc/<pid>/fd` 采样 + argv 回退；
- `read` / `write`：显式 `read-file` / 上传写入；
- `list`：显式 `list-files`（`size_bytes` 为条目数，`sha256` 为条目清单摘要）。

`result`：`ok` / `exit:N` / `timeout` / `unsampled` / `missing`。

### 表结构（evidence.db）

```sql
CREATE TABLE IF NOT EXISTS file_ops(
  id INTEGER PRIMARY KEY, run TEXT, step_id INTEGER, step_key TEXT, task_id TEXT,
  ts REAL, phase TEXT, op TEXT, technique TEXT, probe_id TEXT, cluster TEXT,
  namespace TEXT, pid INTEGER DEFAULT 0, argv TEXT, cwd TEXT, env_digest TEXT,
  opened_files TEXT, path TEXT, mode TEXT, size_bytes INTEGER DEFAULT 0,
  sha256 TEXT, exit_code INTEGER, stdout_hash TEXT, duration_ms INTEGER,
  result TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_file_ops_run ON file_ops(run, ts);
CREATE INDEX IF NOT EXISTS idx_file_ops_step ON file_ops(run, step_id);
```

读写入口：

```python
from inkblade.core.fileaudit import FileOpRecorder, record

rec = FileOpRecorder(run, step_key="s1", probe_id="probe-1", namespace="train")
payload = probe.audit_exec(["cat", "/etc/hostname"])   # 或 controller.audit_exec(...)
rec.exec(payload, ["cat", "/etc/hostname"])
rec.file_read("/etc/hostname", data=raw)
```

## 2. 探针协议（新增 op，向后兼容）

旧客户端不受影响；新探针在 `ready.caps` 中声明
`audit-exec`、`read-file`、`list-files`，旧客户端会忽略未知 cap。

### `audit-exec`

```json
{"op": "audit-exec", "args": {"argv": ["cat", "/etc/hostname"],
  "cwd": "/tmp", "timeout_ms": 5000, "technique": "T1005"}}
```

返回：

```json
{"exec": {"exit_code": 0, "stdout": "...", "stderr": "", "timed_out": false,
          "duration_ms": 4, "argv": [...], "cwd": "/tmp", "pid": 4242,
          "stdout_hash": "<sha256>"},
 "audit": {"pid": 4242, "argv": [...], "cwd": "/tmp", "env_digest": "<sha256>",
           "opened_files": [{"path": "/etc/hostname", "mode": "read", "fd": 3,
                             "size_bytes": 12, "sha256": "<sha256>"}],
           "stdout_hash": "<sha256>", "duration_ms": 4, "exit_code": 0,
           "sampler": "proc-fd+argv"}}
```

采样策略（`probe/src/auditops.rs`）：

- 子进程存活期间每 5ms 读 `/proc/<pid>/fd`，`fdinfo/<fd>.flags & O_ACCMODE`
  区分读/写/读写；
- `cat` 这类毫秒级退出进程由 argv stat 回退覆盖（`sampler=argv`）；
- `sampler` 字段如实标注来源：`proc-fd` / `proc-fd+argv` / `argv`。

### `read-file` / `list-files`

```json
{"op": "read-file", "args": {"path": "/etc/hostname", "max_bytes": 1048576}}
{"op": "list-files", "args": {"path": "/var/log", "pattern": "*.log"}}
```

`read-file` 返回 `path/exists/size/bytes/eof/sha256/text`；`list-files` 返回
`path/exists/count/entries[{name,path,dir,size}]`。

### 宿主路径拒绝

命中即拒绝（控制器 `safe_path()` 与探针 `validate_path()` 同规则）：

- `/proc/<pid>/root`、`/proc/self/root`（hostPID/root 逃逸）；
- `/host`、`/hostfs`、`/mnt/host`、`/var/lib/kubelet`、`/var/lib/docker`；
- `/var/run/docker.sock`、`/run/docker.sock`、`/run/containerd`、
  `/var/run/containerd`；
- `/sys/kernel/debug`、`/dev/mem`、`/dev/kmem`、`/dev/kmsg`、
  `/proc/sysrq-trigger`、`/proc/kcore`；
- 含 `..` 段的路径（规范化后仍按段检查）。

## 3. 统一时间线 `timeline.json`

`inkblade/core/timeline.py` 把 `steps` / `actions` / `file_ops` / 利用标记
（findings + `exploit.*` actions）汇总为同一事件流，`Run.finalize_run()` 自动
写入 run 目录；也可显式 `run.write_timeline()`。

```json
{"schema": "inkblade-timeline-v1", "run": "run-1", "generated_at": 1793...,
 "counts": {"step": 2, "action": 3, "file_op": 5, "exploit": 1},
 "events": [{"seq": 0, "ts": 1793..., "kind": "step", "subject": "s1",
   "action": "step.run", "target": "s1", "files": [], "result": "success",
   "evidence_sha256": "<archive sha256>", "step_key": "s1", "step_id": 1,
   "probe_id": "", "namespace": "", "ref": "steps/s1.tar.gz", "detail": {}}]}
```

排序：`(ts, kind 优先级, seq)`，`kind` 优先级 `step < action < file_op < exploit`；
findings 无时间戳时继承所属 step 的起始时间（仍排在文件事件之后）。

## 4. WebUI / API / 静态导出

- 视图 ③「执行时间线」下半区新增「操作与文件访问台账」（`#ops-ledger`）：
  时间/主体/动作/目标/文件/结果/证据哈希；文件带 `读/写/读写` 徽标。
- 点击带 `data-step` 的行 → 切到视图 ④「证据浏览器」并选中同一步骤；
  步骤详情新增「文件访问（file_ops）」区块。
- 只读 API：`GET /api/v1/timeline?run=...`、`GET /api/v1/file-ops?run=...&step=...`
  （Bearer + 工作区隔离；与 steps/evidence 同级）。
- 静态导出：`window.INKBLADE_DATA` 内嵌 `timeline` 与 `file_ops`，并把
  `timeline.json` 复制到导出目录，`file://` 直接可看。

## 5. 报告节与 SOC 审计键

`render_pentest()` 在「利用验证」步骤表之后新增
「操作与文件访问台账 / Operation and File-Access Ledger」：

- 按 step 列命令（argv 脱敏）、cwd、exit、耗时、读取/写入文件、证据哈希；
- 凭据形态 argv 只保留尾 4 位（`****abcd`）；env 仅摘要；
- 空 `file_ops` 时显式声明「未记录」，不臆造访问。

SOC 审计键（报告同表输出，定义在 `core/fileaudit.SOC_AUDIT_KEYS`）：

| 面 | 审计键 | 选择器 |
|---|---|---|
| auditd | `inkblade_exec` | `-a always,exit -F arch=b64 -S execve -F key=inkblade_exec` |
| auditd | `inkblade_file_read` | `-S openat -S open -F success=1 -k inkblade_file_read` |
| Falco | `inkblade_probe_exec` | `evt.type in (execve, execveat) and proc.pname=inkblade-probe` |
| Falco | `inkblade_probe_file_read` | `evt.type in (open, openat) and fd.typechar=f and proc.pname=inkblade-probe` |
| OTel | `inkblade.process.exec` | `process.command_line / process.working_directory / process.pid / process.exit.code / file.path / file.size / file.hash` |

## 6. 测试

`tests/test_file_audit.py`（16 项）：

- `tests/fake_probe.py` 以 `audit-exec` 仿真 `cat` / `echo`（便携，Windows/Linux
  CI 都跑），断言 opened_files、stdout_hash、pid、env_digest；
- `read-file` / `list-files` 与显式台账行；
- 宿主路径拒绝（控制器 + 假探针）；
- 时间线排序、字段契约、`timeline.json` 落盘与 DB 重建；
- 报告节存在、脱敏、SOC 键、空台账显式声明；
- `/api/v1/timeline`、`/api/v1/file-ops` 与静态导出内嵌/联动标记。

```bash
python -m unittest tests.test_file_audit -v
```

## 7. 已知限制

- fd 采样是「存活窗口采样」，不是 eBPF/ptrace 全量跟踪；毫秒级进程依赖
  argv 回退，`sampler` 字段会标注；
- 探针为 linux-musl 构建；非 Linux 主机上 fd 采样为空，仅 argv 回退
  （`cargo test` 仍可通过）；
- 显式 `read-file` 返回文本（≤ `max_bytes`），大文件请用 `download`
  （后者同样受宿主路径拒绝约束）；
- `file_ops` 按 run 分库（每个 run 一个 `evidence.db`），工作区级汇总需遍历
  各 run 的 `timeline.json`。
