# ARTEX 逐功能穷举对比（FEATURE-BY-FEATURE-ARTEX）

> 生成自 `tools/extract_features.py`（源码枚举，基线 2026-10-25）。克隆：`.slim/clonedeps/repos/RuoJi6__ARTEX`。
>
> 行数 = 提取计数：路由 278｜表 59｜agent 组件 32｜页面 29｜Web 组件 107｜配置键 7｜skills 3｜合计 515 行。
>
> 状态分布：we-have 37 / partial 201 / missing 180 / N/A 97。`N/A` = 类别外（UI 基础件/桌面形态等）。
>
> 本文件的状态列是 2026-10-25 的历史快照（不再回写）；最终处置以 ARTEX-PARITY 为准。
> **2026-10 clean-room 轮次**：180 条 `missing` 已逐行处置（done 70 / 技术不可行 6 / 架构不适用 104 / missing 0），逐功能实现与测试见 [`ARTEX-PARITY.md`](ARTEX-PARITY.md)，逐行处置见 [`artex-parity-rows.json`](artex-parity-rows.json)。

## A1. HTTP 路由（server/*.go，含循环注册展开）（278 项）

| 功能 | 来源锚点 | 工具行为 | Trident 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `GET /api/auth/status` | server/server.go:692 | s.authStatus | we-have（core/users.py + webui/server.py /api/login） | - | JWT/会话登录等价 |
| `POST /api/auth/init` | server/server.go:693 | s.authInit | partial（core/users.py） | S | 首启初始化向导缺独立端点（users.py 已有种子角色） |
| `POST /api/auth/login` | server/server.go:694 | s.authLogin | we-have（core/users.py + webui/server.py /api/login） | - | JWT/会话登录等价 |
| `POST /api/auth/change-password` | server/server.go:695 | s.authChangePassword | partial（core/users.py） | S | 缺自助改密端点 |
| `GET /api/basic-auth/check` | server/server.go:696 | func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control" | missing | - | HTTP Basic Auth 外层门：部署层反代可等价，不纳入（理由见 ARTEX-PARITY） |
| `GET /api/settings/basic-auth` | server/server.go:700 | s.getBasicAuthSettings | missing | - | HTTP Basic Auth 外层门：部署层反代可等价，不纳入（理由见 ARTEX-PARITY） |
| `PUT /api/settings/basic-auth` | server/server.go:701 | s.saveBasicAuthSettings | missing | - | HTTP Basic Auth 外层门：部署层反代可等价，不纳入（理由见 ARTEX-PARITY） |
| `GET /api/health` | server/server.go:703 | s.health | partial（webui/server.py） | S | 缺 /health 探针端点 |
| `GET /api/stats` | server/server.go:704 | s.stats | partial（webui/server.py /api/runs + reports/） | S | 缺全局 stats 聚合端点 |
| `GET /api/logs` | server/server.go:705 | s.getLogs | partial（core/evidence.py JSONL artifacts） | S | 日志查询/历史/SSE 流缺端点（过程检索→CM-02） [CM-02] |
| `GET /api/logs/history` | server/server.go:706 | s.getLogsHistory | partial（core/evidence.py JSONL artifacts） | S | 日志查询/历史/SSE 流缺端点（过程检索→CM-02） [CM-02] |
| `GET /api/logs/stream` | server/server.go:707 | s.streamLogs | partial（core/evidence.py JSONL artifacts） | S | 日志查询/历史/SSE 流缺端点（过程检索→CM-02） [CM-02] |
| `GET /api/update/settings` | server/server.go:711 | s.getUpdateSettings | missing | - | 一键自更新/回滚：包管理部署形态，不纳入（理由见 ARTEX-PARITY） |
| `PUT /api/update/settings` | server/server.go:712 | s.putUpdateSettings | missing | - | 一键自更新/回滚：包管理部署形态，不纳入（理由见 ARTEX-PARITY） |
| `GET /api/update/check` | server/server.go:713 | s.updateCheck | missing | - | 一键自更新/回滚：包管理部署形态，不纳入（理由见 ARTEX-PARITY） |
| `POST /api/update/apply` | server/server.go:714 | s.updateApply | missing | - | 一键自更新/回滚：包管理部署形态，不纳入（理由见 ARTEX-PARITY） |
| `POST /api/update/rollback` | server/server.go:715 | s.updateRollback | missing | - | 一键自更新/回滚：包管理部署形态，不纳入（理由见 ARTEX-PARITY） |
| `GET /api/update/stream` | server/server.go:716 | s.updateStream | missing | - | 一键自更新/回滚：包管理部署形态，不纳入（理由见 ARTEX-PARITY） |
| `GET /api/tasks` | server/server.go:718 | s.listTasks | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks` | server/server.go:719 | s.createTask | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `GET /api/schedules` | server/server.go:720 | s.listSchedules | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `POST /api/schedules` | server/server.go:721 | s.createSchedule | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `GET /api/schedules/{id}` | server/server.go:722 | s.getSchedule | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `PATCH /api/schedules/{id}` | server/server.go:723 | s.updateSchedule | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `PATCH /api/schedules/{id}/remark` | server/server.go:724 | s.updateScheduleMetadata | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `PATCH /api/schedules/{id}/metadata` | server/server.go:725 | s.updateScheduleMetadata | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `DELETE /api/schedules/{id}` | server/server.go:726 | s.deleteSchedule | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `POST /api/schedules/{id}/pause` | server/server.go:727 | s.pauseSchedule | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `POST /api/schedules/{id}/resume` | server/server.go:728 | s.resumeSchedule | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `POST /api/schedules/{id}/run-now` | server/server.go:729 | s.runScheduleNow | we-have（core/scheduler.py + webui /api/v1/scheduler(add/remove/run-due)） | - | cron 调度等价；缺 remark/metadata 字段 |
| `GET /api/task-categories` | server/server.go:730 | s.pgListTaskCategories | missing | M | 任务分类实体（任务模型=runs，无分类维度） |
| `POST /api/task-categories` | server/server.go:731 | s.pgCreateTaskCategory | missing | M | 任务分类实体（任务模型=runs，无分类维度） |
| `PATCH /api/task-categories/{id}` | server/server.go:732 | s.pgRenameTaskCategory | missing | M | 任务分类实体（任务模型=runs，无分类维度） |
| `DELETE /api/task-categories/{id}` | server/server.go:733 | s.pgDeleteTaskCategory | missing | M | 任务分类实体（任务模型=runs，无分类维度） |
| `POST /api/tasks/category/batch` | server/server.go:734 | s.updateTasksCategoryBatch | missing | M | 批量改分类（同上） |
| `GET /api/task-templates` | server/server.go:735 | s.pgListTaskTemplates | partial（lab/ 配置 + chains/*.json 模板） | S | 任务模板实体与 CRUD 缺（链模板已有） |
| `POST /api/task-templates` | server/server.go:736 | s.pgCreateTaskTemplate | partial（lab/ 配置 + chains/*.json 模板） | S | 任务模板实体与 CRUD 缺（链模板已有） |
| `PATCH /api/task-templates/{id}` | server/server.go:737 | s.pgUpdateTaskTemplate | partial（lab/ 配置 + chains/*.json 模板） | S | 任务模板实体与 CRUD 缺（链模板已有） |
| `DELETE /api/task-templates/{id}` | server/server.go:738 | s.pgDeleteTaskTemplate | partial（lab/ 配置 + chains/*.json 模板） | S | 任务模板实体与 CRUD 缺（链模板已有） |
| `GET /api/tasks/{id}` | server/server.go:739 | s.getTask | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `PATCH /api/tasks/{id}` | server/server.go:740 | s.updateTaskMetadata | partial（core/runner.py + webui /api/runs） | L | 任务详情/改元数据：runs 有详情，缺可编辑元数据 [CM-31] |
| `PATCH /api/tasks/{id}/category` | server/server.go:741 | s.updateTaskCategory | partial（core/runner.py + webui /api/runs） | L | 任务详情/改元数据：runs 有详情，缺可编辑元数据 [CM-31] |
| `GET /api/tasks/{id}/intercept-rules` | server/server.go:743 | s.taskInterceptListRules | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/intercept-rules` | server/server.go:744 | s.taskInterceptCreateRule | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `PUT /api/tasks/{id}/intercept-rules/{rid}` | server/server.go:745 | s.taskInterceptUpdateRule | we-have（core/roe.py 目标范围/禁打规则） | S | 任务级拦截规则 CRUD 端点缺（ROE 内已有等价约束） |
| `DELETE /api/tasks/{id}/intercept-rules/{rid}` | server/server.go:746 | s.taskInterceptDeleteRule | missing | L | 任务删除（runs 为不可变证据，刻意保留） |
| `POST /api/tasks/{id}/intercept-rules/{rid}/toggle` | server/server.go:747 | s.taskInterceptToggleRule | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/control/batch` | server/server.go:748 | s.controlTasksBatch | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `GET /api/task-archives` | server/server.go:749 | s.listTaskArchives | missing | L | 冷归档/恢复/批量：runs 全量留档，无分层归档（刻意后置） |
| `GET /api/task-archives/{id}` | server/server.go:750 | s.getTaskArchive | missing | L | 冷归档/恢复/批量：runs 全量留档，无分层归档（刻意后置） |
| `POST /api/tasks/{id}/archive` | server/server.go:751 | s.queueTaskArchive | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/archive/batch` | server/server.go:752 | s.queueTaskArchivesBatch | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/task-archives/{id}/restore` | server/server.go:753 | s.queueTaskArchiveRestore | missing | L | 冷归档/恢复/批量：runs 全量留档，无分层归档（刻意后置） |
| `POST /api/task-archives/restore/batch` | server/server.go:754 | s.restoreTaskArchivesBatch | missing | L | 冷归档/恢复/批量：runs 全量留档，无分层归档（刻意后置） |
| `DELETE /api/task-archives/{id}` | server/server.go:755 | s.queueTaskArchiveDelete | missing | M | 未归类路由：待人工归类（完备性要求下不得长期存在） |
| `POST /api/task-archives/delete/batch` | server/server.go:756 | s.deleteTaskArchivesBatch | missing | L | 冷归档/恢复/批量：runs 全量留档，无分层归档（刻意后置） |
| `GET /api/tasks/{id}/coverage` | server/server.go:757 | s.taskCoverage | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `GET /api/tasks/{id}/coverage-graph` | server/server.go:758 | s.taskCoverageGraph | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `GET /api/tasks/{id}/asset-refs` | server/server.go:759 | s.taskAssetRefs | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/assets` | server/server.go:760 | s.attachTaskAssets | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `DELETE /api/tasks/{id}/assets/{assetID}` | server/server.go:761 | s.detachTaskAsset | missing | L | 任务删除（runs 为不可变证据，刻意保留） |
| `GET /api/tasks/{id}/intent-assets` | server/server.go:762 | s.taskIntentAssets | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `GET /api/workspace/list` | server/server.go:765 | s.wsList | missing | M | run 工作区文件管理器（离线 artifacts 模型，不纳入（理由见 ARTEX-PARITY） UI） |
| `GET /api/workspace/read` | server/server.go:766 | s.wsRead | missing | M | run 工作区文件管理器（离线 artifacts 模型，不纳入（理由见 ARTEX-PARITY） UI） |
| `POST /api/workspace/write` | server/server.go:767 | s.wsWrite | missing | M | run 工作区文件管理器（离线 artifacts 模型，不纳入（理由见 ARTEX-PARITY） UI） |
| `POST /api/workspace/mkdir` | server/server.go:768 | s.wsMkdir | missing | M | run 工作区文件管理器（离线 artifacts 模型，不纳入（理由见 ARTEX-PARITY） UI） |
| `DELETE /api/workspace/delete` | server/server.go:769 | s.wsDelete | missing | M | run 工作区文件管理器（离线 artifacts 模型，不纳入（理由见 ARTEX-PARITY） UI） |
| `GET /api/workspace/download` | server/server.go:770 | s.wsDownload | missing | M | run 工作区文件管理器（离线 artifacts 模型，不纳入（理由见 ARTEX-PARITY） UI） |
| `POST /api/workspace/upload` | server/server.go:771 | s.wsUpload | missing | M | run 工作区文件管理器（离线 artifacts 模型，不纳入（理由见 ARTEX-PARITY） UI） |
| `GET /api/tasks/{id}/scope` | server/server.go:772 | s.taskScopeList | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/scope` | server/server.go:773 | s.taskScopeAdd | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `DELETE /api/tasks/{id}/scope/{sid}` | server/server.go:774 | s.taskScopeDelete | missing | L | 任务删除（runs 为不可变证据，刻意保留） |
| `GET /api/tasks/{id}/goals` | server/server.go:775 | s.listGoals | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/goals` | server/server.go:776 | s.addGoal | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `PATCH /api/tasks/{id}/goals/{gid}` | server/server.go:777 | s.editGoal | partial（agent_planner.py 推荐+审批） | M | goal 实体 CRUD 缺（planner 输出即目标集） [CM-16] |
| `DELETE /api/tasks/{id}/goals/{gid}` | server/server.go:778 | s.deleteGoal | missing | L | 任务删除（runs 为不可变证据，刻意保留） |
| `GET /api/tasks/{id}/constraints` | server/server.go:779 | s.listConstraints | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/constraints` | server/server.go:780 | s.addConstraint | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `PATCH /api/tasks/{id}/constraints/{cid}` | server/server.go:781 | s.editConstraint | we-have（core/roe.py 约束） | S | 运行中动态增删约束端点缺 |
| `DELETE /api/tasks/{id}/constraints/{cid}` | server/server.go:782 | s.deleteConstraint | missing | L | 任务删除（runs 为不可变证据，刻意保留） |
| `POST /api/tasks/{id}/control` | server/server.go:783 | s.control | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `PUT /api/tasks/{id}/llm` | server/server.go:784 | s.updateTaskLLMProfiles | missing | M | 未归类路由：待人工归类（完备性要求下不得长期存在） |
| `GET /api/tasks/{id}/llm/resolution` | server/server.go:785 | s.taskLLMResolutionHandler | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/intents/{iid}/control` | server/server.go:786 | s.controlIntent | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/intents/{iid}/messages` | server/server.go:787 | s.sendWorkerMessage | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/intents/{iid}/rerun` | server/server.go:788 | s.rerunIntent | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/intents/rerun-blocked` | server/server.go:789 | s.rerunBlocked | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/active` | server/server.go:790 | s.setActive | missing | L | 全局活动任务切换（单活动 run 模型） |
| `GET /api/llm` | server/server.go:792 | s.getLLM | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `POST /api/llm` | server/server.go:793 | s.setLLM | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `POST /api/llm/test` | server/server.go:794 | s.testLLM | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `GET /api/assets` | server/server.go:797 | s.listAssets | partial（core/discovery.py + webui /api/v1/assets） | S | 资产插入/删除端点缺（发现+导入已有） |
| `GET /api/assets/counts` | server/server.go:798 | s.assetCounts | partial（core/discovery.py + webui /api/v1/assets） | S | 资产插入/删除端点缺（发现+导入已有） |
| `POST /api/assets` | server/server.go:799 | s.insertAssets | partial（core/discovery.py + webui /api/v1/assets） | S | 资产插入/删除端点缺（发现+导入已有） |
| `DELETE /api/assets` | server/server.go:800 | s.deleteAssets | partial（core/discovery.py + webui /api/v1/assets） | S | 资产插入/删除端点缺（发现+导入已有） |
| `GET /api/companies` | server/server.go:803 | s.listCompanies | missing | M | 公司/归属/重归属实体（多租户工作区另有 users.py 四角色） |
| `POST /api/companies` | server/server.go:804 | s.createCompany | missing | M | 公司/归属/重归属实体（多租户工作区另有 users.py 四角色） |
| `GET /api/companies/{id}` | server/server.go:805 | s.getCompany | missing | M | 公司/归属/重归属实体（多租户工作区另有 users.py 四角色） |
| `DELETE /api/companies/{id}` | server/server.go:806 | s.deleteCompany | missing | M | 公司/归属/重归属实体（多租户工作区另有 users.py 四角色） |
| `POST /api/companies/{id}/scope` | server/server.go:807 | s.addCompanyScope | missing | M | 公司/归属/重归属实体（多租户工作区另有 users.py 四角色） |
| `POST /api/companies/reattribute` | server/server.go:808 | s.reattribute | missing | M | 公司/归属/重归属实体（多租户工作区另有 users.py 四角色） |
| `GET /api/exploration/frontier` | server/server.go:810 | s.frontier | partial（agent_planner.py 推荐排序） | - | frontier 视图缺独立端点 |
| `GET /api/exploration/findings` | server/server.go:811 | s.findings | partial（core/evidence.py findings + webui /api/runs） | S | 单 finding 读取/批注/删除端点缺 |
| `GET /api/exploration/findings/groups` | server/server.go:812 | s.findingGroups | partial（core/combo.py 组合签名） | M | finding 分组视图缺 |
| `GET /api/exploration/finding-cases` | server/server.go:813 | s.listFindingCases | missing | M | 同根因案例归并/评审工作流 [CM-17] |
| `POST /api/exploration/finding-cases` | server/server.go:814 | s.mergeFindingCase | missing | M | 同根因案例归并/评审工作流 [CM-17] |
| `GET /api/exploration/finding-cases/{id}` | server/server.go:815 | s.getFindingCase | missing | M | 同根因案例归并/评审工作流 [CM-17] |
| `GET /api/exploration/finding-cases/{id}/members` | server/server.go:816 | s.getFindingCaseMembers | missing | M | 同根因案例归并/评审工作流 [CM-17] |
| `DELETE /api/exploration/finding-cases/{id}/members/{fid}` | server/server.go:817 | s.removeFindingCaseMember | missing | M | 同根因案例归并/评审工作流 [CM-17] |
| `PUT /api/exploration/finding-cases/{id}/report` | server/server.go:818 | s.updateCaseReport | missing | M | 同根因案例归并/评审工作流 [CM-17] |
| `GET /api/exploration/finding-case-suggestions` | server/server.go:819 | s.caseSuggestions | missing | M | 案例归并建议/裁决 [CM-17] |
| `POST /api/exploration/finding-case-suggestions/{id}` | server/server.go:820 | s.resolveCaseSuggestion | missing | M | 案例归并建议/裁决 [CM-17] |
| `POST /api/exploration/finding-case-review` | server/server.go:821 | s.reviewFindingCases | missing | M | 案例评审 run [CM-17] |
| `GET /api/exploration/finding-case-review` | server/server.go:822 | s.caseReviewRuns | missing | M | 案例评审 run [CM-17] |
| `GET /api/exploration/findings/asset-tree` | server/server.go:823 | s.findingAssetTree | partial（core/discovery.py + core/graph.py） | S | 资产树端点缺 |
| `GET /api/exploration/findings/stats` | server/server.go:824 | s.findingStats | partial（reports/render.py 统计） | S | finding stats 端点缺 |
| `GET /api/exploration/findings/export` | server/server.go:825 | s.findingsExport | we-have（export.py SARIF/OCSF/VEX） | - | 导出等价 |
| `GET /api/exploration/findings/{id}` | server/server.go:827 | s.getFinding | partial（core/evidence.py findings + webui /api/runs） | S | 单 finding 读取/批注/删除端点缺 |
| `GET /api/exploration/findings/{id}/lineage` | server/server.go:828 | s.findingLineage | partial（core/graph.py） | M | finding 血缘/深挖工作流缺 [CM-16] |
| `POST /api/exploration/findings/{id}/deepen` | server/server.go:829 | s.deepenFinding | partial（core/graph.py） | M | finding 血缘/深挖工作流缺 [CM-16] |
| `GET /api/exploration/findings/{id}/retests` | server/server.go:830 | s.listFindingRetests | partial（webui /api/v1/poc/reverify + verify-effects.py） | M | finding 级 retest 实体/活跃 run 列表缺 [CM-14] |
| `GET /api/exploration/findings/retests/active` | server/server.go:831 | s.listActiveFindingRetests | partial（webui /api/v1/poc/reverify + verify-effects.py） | M | finding 级 retest 实体/活跃 run 列表缺 [CM-14] |
| `POST /api/exploration/findings/{id}/retests` | server/server.go:832 | s.startFindingRetest | partial（webui /api/v1/poc/reverify + verify-effects.py） | M | finding 级 retest 实体/活跃 run 列表缺 [CM-14] |
| `PATCH /api/exploration/findings/{id}` | server/server.go:833 | s.patchFinding | partial（core/evidence.py findings + webui /api/runs） | S | 单 finding 读取/批注/删除端点缺 |
| `DELETE /api/exploration/findings/{id}` | server/server.go:834 | s.deleteFinding | partial（core/evidence.py findings + webui /api/runs） | S | 单 finding 读取/批注/删除端点缺 |
| `GET /api/exploration/intents` | server/server.go:835 | s.intents | partial（core/graph.py） | M | 探索图/节点/意图查询端点缺 [CM-16] |
| `GET /api/exploration/graph` | server/server.go:836 | s.explorationGraph | partial（core/graph.py） | M | 探索图/节点/意图查询端点缺 [CM-16] |
| `GET /api/exploration/nodes` | server/server.go:837 | s.explorationNodes | partial（core/graph.py） | M | 探索图/节点/意图查询端点缺 [CM-16] |
| `GET /api/exploration/activity` | server/server.go:838 | s.activity | partial（core/evidence.py 事件流） | S | 活动流/历史/SSE 端点缺 |
| `GET /api/exploration/activity/history` | server/server.go:839 | s.activityHistory | partial（core/evidence.py 事件流） | S | 活动流/历史/SSE 端点缺 |
| `GET /api/exploration/main-sessions` | server/server.go:840 | s.mainSessions | missing | - | 主 agent 会话（自主执行循环不纳入（理由见 ARTEX-PARITY），Ruling 规划≠执行） |
| `POST /api/exploration/main-session/new` | server/server.go:841 | s.newMainSession | missing | - | 主 agent 会话（自主执行循环不纳入（理由见 ARTEX-PARITY），Ruling 规划≠执行） |
| `GET /api/exploration/activity/stream` | server/server.go:842 | s.streamActivity | partial（core/evidence.py 事件流） | S | 活动流/历史/SSE 端点缺 |
| `GET /api/exploration/activity/{seq}` | server/server.go:843 | s.activityDetail | partial（core/evidence.py 事件流） | S | 活动流/历史/SSE 端点缺 |
| `GET /api/exploration/tokens` | server/server.go:844 | s.tokenStats | missing | - | token 用量统计：本轮由 core/llmpool.py 调用留档提供（见 ARTEX-PARITY） |
| `GET /api/tokens/daily` | server/server.go:845 | s.tokenDailyStats | missing | - | token 用量统计：本轮由 core/llmpool.py 调用留档提供（见 ARTEX-PARITY） |
| `GET /api/tokens/conversations` | server/server.go:846 | s.conversationTokens | missing | - | token 用量统计：本轮由 core/llmpool.py 调用留档提供（见 ARTEX-PARITY） |
| `GET /api/tokens/usage` | server/server.go:847 | s.pgUsageStats | missing | - | token 用量统计：本轮由 core/llmpool.py 调用留档提供（见 ARTEX-PARITY） |
| `GET /api/audit` | server/server.go:849 | s.getAudit | partial（core/evidence.py manifest 篡改检测） | S | 独立审计查询端点缺 |
| `POST /api/gc` | server/server.go:850 | s.gc | partial（core/backup.py） | S | 显式 GC 端点缺 |
| `GET /api/traffic` | server/server.go:851 | s.getTraffic | partial（core/traffic.py ingest/replay + webui /api/v1/traffic） | S | 按主机/正文浏览与批量删除端点缺 |
| `GET /api/traffic/hosts` | server/server.go:852 | s.getTrafficHosts | partial（core/traffic.py ingest/replay + webui /api/v1/traffic） | S | 按主机/正文浏览与批量删除端点缺 |
| `DELETE /api/traffic` | server/server.go:853 | s.deleteTraffic | partial（core/traffic.py ingest/replay + webui /api/v1/traffic） | S | 按主机/正文浏览与批量删除端点缺 |
| `DELETE /api/traffic/hosts` | server/server.go:854 | s.deleteTrafficHosts | partial（core/traffic.py ingest/replay + webui /api/v1/traffic） | S | 按主机/正文浏览与批量删除端点缺 |
| `DELETE /api/traffic/all` | server/server.go:855 | s.deleteAllTraffic | partial（core/traffic.py ingest/replay + webui /api/v1/traffic） | S | 按主机/正文浏览与批量删除端点缺 |
| `GET /api/traffic/exchange` | server/server.go:856 | s.getTrafficExchange | partial（core/traffic.py ingest/replay + webui /api/v1/traffic） | S | 按主机/正文浏览与批量删除端点缺 |
| `GET /api/traffic/blob` | server/server.go:857 | s.getTrafficBlob | partial（core/traffic.py ingest/replay + webui /api/v1/traffic） | S | 按主机/正文浏览与批量删除端点缺 |
| `GET /api/commands` | server/server.go:858 | s.pgListCommands | partial（core/evidence.py 命令记录） | S | 命令审计/按工具聚合视图缺 |
| `GET /api/commands/stats` | server/server.go:859 | s.pgToolStats | partial（core/evidence.py 命令记录） | S | 命令审计/按工具聚合视图缺 |
| `GET /api/llm/records` | server/server.go:860 | s.pgListLLMRecords | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `DELETE /api/llm/records` | server/server.go:861 | s.pgDeleteLLMRecords | missing | - | LLM 调用留档（0-token 原则） |
| `GET /api/llm/records/tasks` | server/server.go:862 | s.pgLLMTasks | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `GET /api/llm/records/by-model` | server/server.go:863 | s.pgTokenByModel | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `GET /api/llm/records/{id}` | server/server.go:864 | s.pgGetLLMRecord | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `GET /api/tasks/{id}/intelligence` | server/server.go:865 | s.listIntelligence | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `GET /api/tasks/{id}/intelligence/{intelID}` | server/server.go:866 | s.getIntelligence | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `PATCH /api/tasks/{id}/intelligence/{intelID}` | server/server.go:867 | s.updateIntelligence | missing | S | 任务情报登记（凭据/线索集中 registry） [CM-01] |
| `POST /api/tasks/{id}/intelligence/{intelID}/credentials/retry` | server/server.go:868 | s.retryCredentials | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `GET /api/tasks/{id}/intelligence/{intelID}/traffic/{trafficID}` | server/server.go:869 | s.credentialTrafficDetail | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `GET /api/assets/{id}/intelligence/{intelID}/traffic/{trafficID}` | server/server.go:870 | func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("scope" | partial（core/discovery.py + webui /api/v1/assets） | S | 资产插入/删除端点缺（发现+导入已有） |
| `GET /api/assets/{id}/intelligence` | server/server.go:874 | func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("scope" | partial（core/discovery.py + webui /api/v1/assets） | S | 资产插入/删除端点缺（发现+导入已有） |
| `GET /api/assets/{id}/intelligence/{intelID}` | server/server.go:878 | func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("scope" | partial（core/discovery.py + webui /api/v1/assets） | S | 资产插入/删除端点缺（发现+导入已有） |
| `GET /api/settings` | server/server.go:882 | s.getSettings | partial（lab/ 实验配置 + CLI 参数） | S | 集中设置端点缺 |
| `PUT /api/settings` | server/server.go:883 | s.putSettings | partial（lab/ 实验配置 + CLI 参数） | S | 集中设置端点缺 |
| `GET /api/notify/meta` | server/server.go:886 | s.notifyMeta | missing | S | IM 推送渠道/投递/重试（输出多路分发同族） [CM-10] |
| `GET /api/notify/channels` | server/server.go:887 | s.notifyListChannels | missing | S | IM 推送渠道/投递/重试（输出多路分发同族） [CM-10] |
| `POST /api/notify/channels` | server/server.go:888 | s.notifyCreateChannel | missing | S | IM 推送渠道/投递/重试（输出多路分发同族） [CM-10] |
| `PATCH /api/notify/channels/{id}` | server/server.go:889 | s.notifyUpdateChannel | missing | S | IM 推送渠道/投递/重试（输出多路分发同族） [CM-10] |
| `DELETE /api/notify/channels/{id}` | server/server.go:890 | s.notifyDeleteChannel | missing | S | IM 推送渠道/投递/重试（输出多路分发同族） [CM-10] |
| `POST /api/notify/channels/{id}/test` | server/server.go:891 | s.notifyTestChannel | missing | S | IM 推送渠道/投递/重试（输出多路分发同族） [CM-10] |
| `GET /api/notify/deliveries` | server/server.go:892 | s.notifyListDeliveries | missing | S | IM 推送渠道/投递/重试（输出多路分发同族） [CM-10] |
| `POST /api/notify/deliveries/{id}/retry` | server/server.go:893 | s.notifyRetryDelivery | missing | S | IM 推送渠道/投递/重试（输出多路分发同族） [CM-10] |
| `POST /api/settings/web-search/test` | server/server.go:894 | s.testWebSearch | missing | - | 内置 web 搜索（外部检索由 librarian/websearch 会话承担） |
| `GET /api/report` | server/server.go:895 | s.getReport | we-have（reports/render.py + compliance） | - | 报告等价 |
| `GET /api/chat/mentions` | server/server.go:896 | s.searchChatMentions | missing | - | 对话式主 agent/上传/mentions（自主执行循环不纳入（理由见 ARTEX-PARITY）） |
| `POST /api/chat` | server/server.go:897 | s.chat | missing | - | 对话式主 agent/上传/mentions（自主执行循环不纳入（理由见 ARTEX-PARITY）） |
| `POST /api/chat/upload` | server/server.go:898 | s.chatUpload | missing | - | 对话式主 agent/上传/mentions（自主执行循环不纳入（理由见 ARTEX-PARITY）） |
| `GET /api/tasks/{id}/chat/status` | server/server.go:899 | s.taskChatStatus | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `POST /api/tasks/{id}/chat/stop` | server/server.go:900 | s.stopChat | partial（core/runner.py runs + webui /api/runs） | L | 任务实体 CRUD/元数据缺（runs 不可变）→ 多任务模型=CM-31 同源 [CM-31] |
| `DELETE /api/tasks/{id}` | server/server.go:903 | s.pgDeleteTask | partial（core/runner.py + webui /api/runs） | L | 任务详情/改元数据：runs 有详情，缺可编辑元数据 [CM-31] |
| `GET /api/conversations` | server/server.go:906 | s.pgListConversations | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `POST /api/conversations` | server/server.go:907 | s.pgCreateConversation | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `POST /api/conversations/delete/batch` | server/server.go:908 | s.pgDeleteConversationsBatch | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `PATCH /api/conversations/{id}` | server/server.go:909 | s.pgRenameConversation | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `PATCH /api/conversations/{id}/profile` | server/server.go:910 | s.pgUpdateConversation | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `DELETE /api/conversations/{id}` | server/server.go:911 | s.pgDeleteConversation | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `GET /api/conversations/{id}/messages` | server/server.go:912 | s.pgConversationMessages | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `POST /api/conversations/{id}/messages` | server/server.go:913 | s.pgSendConversationMessage | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `POST /api/conversations/{id}/stop` | server/server.go:914 | s.pgStopConversation | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `GET /api/conversations/{id}/messages/{seq}` | server/server.go:915 | s.pgConversationMsgDetail | missing | - | 多会话管理（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `GET /api/agents` | server/server.go:917 | s.pgListAgents | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `POST /api/agents` | server/server.go:918 | s.pgCreateAgent | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `GET /api/agents/{key}` | server/server.go:919 | s.pgGetAgent | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `PATCH /api/agents/{key}` | server/server.go:920 | s.pgUpdateAgent | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `DELETE /api/agents/{key}` | server/server.go:921 | s.pgDeleteAgent | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `PUT /api/agents/{key}/config` | server/server.go:922 | s.pgSaveAgentConfig | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `PUT /api/agents/{key}/prompt` | server/server.go:923 | s.pgSavePrompt | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `POST /api/agents/{key}/prompt/reset` | server/server.go:924 | s.pgResetPrompt | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `PUT /api/agents/{key}/wrapup` | server/server.go:925 | s.pgSaveWrapup | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `POST /api/agents/{key}/wrapup/reset` | server/server.go:926 | s.pgResetWrapup | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `PUT /api/agents/{key}/wrapup/task-timeout` | server/server.go:927 | s.pgSaveTaskTimeoutWrapup | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `POST /api/agents/{key}/wrapup/task-timeout/reset` | server/server.go:928 | s.pgResetTaskTimeoutWrapup | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `GET /api/agents/{key}/triggers` | server/server.go:929 | s.pgListTriggers | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `POST /api/agents/{key}/triggers` | server/server.go:930 | s.pgCreateTrigger | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `PATCH /api/triggers/{id}` | server/server.go:931 | s.pgUpdateTrigger | missing | S | 事件/间隔触发器（调度器族） [CM-04] |
| `DELETE /api/triggers/{id}` | server/server.go:932 | s.pgDeleteTrigger | missing | S | 事件/间隔触发器（调度器族） [CM-04] |
| `GET /api/agents/{key}/prompts` | server/server.go:933 | s.pgListPromptVersions | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `GET /api/agents/{key}/variables` | server/server.go:934 | s.pgPromptVars | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `POST /api/agents/{key}/prompt/preview` | server/server.go:935 | s.pgPreviewPrompt | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `GET /api/agents/{key}/visibility` | server/server.go:936 | s.pgGetAgentVisibility | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `PUT /api/agents/{key}/visibility` | server/server.go:937 | s.pgSetAgentVisibility | missing | - | 多 agent 实体/提示词版本/可见性/wrap-up（多 agent 平台不纳入（理由见 ARTEX-PARITY），REFLECTION §2） |
| `GET /api/tools` | server/server.go:939 | s.pgListTools | partial（core/registry.py 模块动态加载） | S | 内置工具目录改描述/默认值缺（模块即工具） |
| `PUT /api/tools/{key}` | server/server.go:940 | s.pgUpdateTool | partial（core/registry.py 模块动态加载） | S | 内置工具目录改描述/默认值缺（模块即工具） |
| `POST /api/tools/custom` | server/server.go:941 | s.pgCreateCustomTool | partial（core/registry.py 模块动态加载） | S | 内置工具目录改描述/默认值缺（模块即工具） |
| `POST /api/tools/custom/test` | server/server.go:942 | s.pgTestCustomTool | partial（core/registry.py 模块动态加载） | S | 内置工具目录改描述/默认值缺（模块即工具） |
| `PUT /api/tools/custom/{key}` | server/server.go:943 | s.pgUpdateCustomTool | partial（core/registry.py 模块动态加载） | S | 内置工具目录改描述/默认值缺（模块即工具） |
| `DELETE /api/tools/custom/{key}` | server/server.go:944 | s.pgDeleteCustomTool | partial（core/registry.py 模块动态加载） | S | 内置工具目录改描述/默认值缺（模块即工具） |
| `POST /api/settings/python/detect` | server/server.go:945 | s.pgDetectPython | missing | S | 自定义脚本工具解释器检测 |
| `POST /api/tools/{key}/reset` | server/server.go:946 | s.pgResetTool | partial（core/registry.py 模块动态加载） | S | 内置工具目录改描述/默认值缺（模块即工具） |
| `GET /api/mcp` | server/server.go:948 | s.pgListMCP | partial（mcp_server.py（服务端 10 只读工具）） | M | 作为 client 挂载外部 MCP 的 CRUD 缺 |
| `POST /api/mcp` | server/server.go:949 | s.pgSaveMCP | partial（mcp_server.py（服务端 10 只读工具）） | M | 作为 client 挂载外部 MCP 的 CRUD 缺 |
| `DELETE /api/mcp/{id}` | server/server.go:950 | s.pgDeleteMCP | partial（mcp_server.py（服务端 10 只读工具）） | M | 作为 client 挂载外部 MCP 的 CRUD 缺 |
| `GET /api/mcp/{id}/tools` | server/server.go:951 | s.pgMCPTools | partial（mcp_server.py（服务端 10 只读工具）） | M | 作为 client 挂载外部 MCP 的 CRUD 缺 |
| `POST /api/mcp/{id}/refresh` | server/server.go:952 | s.pgRefreshMCP | partial（mcp_server.py（服务端 10 只读工具）） | M | 作为 client 挂载外部 MCP 的 CRUD 缺 |
| `GET /api/sync/scopesentry/status` | server/server.go:954 | s.syncSSStatus | missing | S | ScopeSentry 资产同步（外部输入适配器族） [CM-13] |
| `POST /api/sync/scopesentry/datasource` | server/server.go:955 | s.syncSSDatasource | missing | S | ScopeSentry 资产同步（外部输入适配器族） [CM-13] |
| `GET /api/sync/scopesentry/projects` | server/server.go:956 | s.syncSSProjects | missing | S | ScopeSentry 资产同步（外部输入适配器族） [CM-13] |
| `GET /api/sync/scopesentry/tasks` | server/server.go:957 | s.syncSSTasks | missing | S | ScopeSentry 资产同步（外部输入适配器族） [CM-13] |
| `POST /api/sync/scopesentry/sync` | server/server.go:958 | s.syncSSRun | missing | S | ScopeSentry 资产同步（外部输入适配器族） [CM-13] |
| `GET /api/skills` | server/server.go:960 | s.fsListSkills | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `POST /api/skills` | server/server.go:961 | s.fsCreateSkill | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `POST /api/skills/upload` | server/server.go:962 | s.fsUploadSkill | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `DELETE /api/skills/{name}` | server/server.go:963 | s.fsDeleteSkill | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `GET /api/skills/missing` | server/server.go:964 | s.fsMissingSkills | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `GET /api/skills/{name}/usage` | server/server.go:965 | s.fsSkillUsage | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `PUT /api/skills/{name}/meta` | server/server.go:966 | s.fsUpdateSkillMeta | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `POST /api/skills/{name}/dirs` | server/server.go:967 | s.fsCreateDir | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `GET /api/skills/{name}/files` | server/server.go:968 | s.fsListFiles | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `GET /api/skills/{name}/files/{file...}` | server/server.go:970 | s.fsReadFile | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `PUT /api/skills/{name}/files/{file...}` | server/server.go:971 | s.fsWriteFile | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `DELETE /api/skills/{name}/files/{file...}` | server/server.go:972 | s.fsDeletePath | partial（lab/ 脚本 + rules/templates/） | M | skill 实体 CRUD/上传/使用统计缺 |
| `GET /api/visibility/{kind}/{id}` | server/server.go:974 | s.pgResourceVisibility | missing | - | 按 agent 的资源可见性（多 agent 模型外） |
| `POST /api/visibility/toggle` | server/server.go:975 | s.pgToggleVisibility | missing | - | 按 agent 的资源可见性（多 agent 模型外） |
| `GET /api/visibility/skill/{name}` | server/server.go:977 | s.pgSkillVisibility | missing | - | 按 agent 的资源可见性（多 agent 模型外） |
| `POST /api/visibility/skill/toggle` | server/server.go:978 | s.pgToggleSkillVisibility | missing | - | 按 agent 的资源可见性（多 agent 模型外） |
| `GET /api/llm/profiles` | server/server.go:980 | s.pgListProfiles | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `POST /api/llm/profiles` | server/server.go:981 | s.pgSaveProfile | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `DELETE /api/llm/profiles/{id}` | server/server.go:982 | s.pgDeleteProfile | missing | M | 未归类路由：待人工归类（完备性要求下不得长期存在） |
| `POST /api/llm/profiles/active` | server/server.go:983 | s.pgActivateProfile | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `GET /api/llm/retry-policy` | server/server.go:984 | s.pgGetLLMRetryPolicy | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `POST /api/llm/retry-policy` | server/server.go:985 | s.pgSaveLLMRetryPolicy | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `GET /api/llm/pool` | server/server.go:986 | s.pgLLMPoolStatus | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `POST /api/llm/pool/reset` | server/server.go:987 | s.pgLLMPoolReset | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `POST /api/llm/models` | server/server.go:988 | s.pgListModels | missing | - | LLM 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `GET /api/intercept/rules` | server/server.go:991 | s.interceptListRules | partial（core/roe.py + core/explorer.py 审批） | S | 拦截规则持久化 CRUD 缺（ROE 内置规则） |
| `POST /api/intercept/rules` | server/server.go:992 | s.interceptCreateRule | partial（core/roe.py + core/explorer.py 审批） | S | 拦截规则持久化 CRUD 缺（ROE 内置规则） |
| `PUT /api/intercept/rules/{id}` | server/server.go:993 | s.interceptUpdateRule | partial（core/roe.py + core/explorer.py 审批） | S | 拦截规则持久化 CRUD 缺（ROE 内置规则） |
| `DELETE /api/intercept/rules/{id}` | server/server.go:994 | s.interceptDeleteRule | partial（core/roe.py + core/explorer.py 审批） | S | 拦截规则持久化 CRUD 缺（ROE 内置规则） |
| `POST /api/intercept/rules/{id}/toggle` | server/server.go:995 | s.interceptToggleRule | partial（core/roe.py + core/explorer.py 审批） | S | 拦截规则持久化 CRUD 缺（ROE 内置规则） |
| `GET /api/asset-intercept/rules` | server/server.go:998 | s.assetInterceptListRules | we-have（core/roe.py 禁打范围） | S | 全局资产黑名单 CRUD 端点缺 |
| `POST /api/asset-intercept/rules` | server/server.go:999 | s.assetInterceptCreateRule | we-have（core/roe.py 禁打范围） | S | 全局资产黑名单 CRUD 端点缺 |
| `PUT /api/asset-intercept/rules/{id}` | server/server.go:1000 | s.assetInterceptUpdateRule | we-have（core/roe.py 禁打范围） | S | 全局资产黑名单 CRUD 端点缺 |
| `DELETE /api/asset-intercept/rules/{id}` | server/server.go:1001 | s.assetInterceptDeleteRule | we-have（core/roe.py 禁打范围） | S | 全局资产黑名单 CRUD 端点缺 |
| `POST /api/asset-intercept/rules/{id}/toggle` | server/server.go:1002 | s.assetInterceptToggleRule | we-have（core/roe.py 禁打范围） | S | 全局资产黑名单 CRUD 端点缺 |
| `GET /api/intercept/pending` | server/server.go:1004 | s.interceptListPending | we-have（core/explorer.py propose/approve + webui /approve //reject） | - | 待审/裁决等价 |
| `GET /api/intercept/pending/{id}` | server/server.go:1005 | s.interceptGetOne | we-have（core/explorer.py propose/approve + webui /approve //reject） | - | 待审/裁决等价 |
| `POST /api/intercept/pending/{id}/decide` | server/server.go:1006 | s.interceptDecide | we-have（core/explorer.py propose/approve + webui /approve //reject） | - | 待审/裁决等价 |
| `GET /api/intercept/history` | server/server.go:1007 | s.interceptHistory | partial（core/evidence.py 审批留档） | S | 拦截历史/执行细节端点缺 |
| `GET /api/intercept/history/{id}` | server/server.go:1008 | s.interceptDetail | partial（core/evidence.py 审批留档） | S | 拦截历史/执行细节端点缺 |
| `GET /api/intercept/history/{id}/execution` | server/server.go:1009 | s.interceptExecution | partial（core/evidence.py 审批留档） | S | 拦截历史/执行细节端点缺 |
| `GET /api/intercept/task/{taskID}` | server/server.go:1010 | s.interceptListTaskItems | partial（core/evidence.py run 事件） | S | 按任务拦截项列表缺 |
| `GET /api/intercept/tool-config` | server/server.go:1011 | s.interceptGetToolConfig | partial（core/roe.py 工具边界） | S | 按工具拦截配置端点缺 |
| `PUT /api/intercept/tool-config` | server/server.go:1012 | s.interceptSetToolConfig | partial（core/roe.py 工具边界） | S | 按工具拦截配置端点缺 |
| `GET /api/intercept/judge` | server/server.go:1013 | s.interceptGetJudgeConfig | missing | M | LLM 兜底审批（模型判定未命中规则的命令） |
| `PUT /api/intercept/judge` | server/server.go:1014 | s.interceptSetJudgeConfig | missing | M | LLM 兜底审批（模型判定未命中规则的命令） |
| `GET /api/intercept/judge/usage` | server/server.go:1015 | s.interceptJudgeUsage | missing | M | LLM 兜底审批（模型判定未命中规则的命令） |
| `GET /api/side-questions/{requestID}/events` | server/side_questions.go:359 | s.sideEvents | missing | M | agent 侧问/澄清队列（人在环单向审批已对齐，反向提问缺） |
| `POST /api/side-questions/{requestID}/cancel` | server/side_questions.go:360 | s.cancelSideRequest | missing | M | agent 侧问/澄清队列（人在环单向审批已对齐，反向提问缺） |

## A2. 数据库表（db/schema.sql）（59 项）

| 功能 | 来源锚点 | 工具行为 | Trident 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `companies` | db/schema.sql:27 | 表 companies | partial（core/discovery.py AssetInventory） | M | 资产/公司实体持久化缺（发现结果入 evidence） |
| `assets` | db/schema.sql:40 | 表 assets | partial（core/discovery.py AssetInventory） | M | 资产/公司实体持久化缺（发现结果入 evidence） |
| `company_scope` | db/schema.sql:115 | 表 company_scope | partial（core/discovery.py AssetInventory） | M | 资产/公司实体持久化缺（发现结果入 evidence） |
| `explorations` | db/schema.sql:153 | 表 explorations | partial（core/graph.py + core/explorer.py） | M | 探索图持久化表缺（内存图+runs） [CM-16] |
| `exploration_nodes` | db/schema.sql:170 | 表 exploration_nodes | partial（core/graph.py + core/explorer.py） | M | 探索图持久化表缺（内存图+runs） [CM-16] |
| `exploration_edges` | db/schema.sql:248 | 表 exploration_edges | partial（core/graph.py + core/explorer.py） | M | 探索图持久化表缺（内存图+runs） [CM-16] |
| `exploration_anchors` | db/schema.sql:276 | 表 exploration_anchors | partial（core/graph.py + core/explorer.py） | M | 探索图持久化表缺（内存图+runs） [CM-16] |
| `task_constraints` | db/schema.sql:287 | 表 task_constraints | we-have（core/roe.py） | S | 约束/范围持久化表缺（ROE YAML 内） |
| `activity` | db/schema.sql:298 | 表 activity | partial（core/evidence.py JSONL） | S | 活动/日志独立表缺（事件入证据库） |
| `main_sessions` | db/schema.sql:346 | 表 main_sessions | partial（core/evidence.py JSONL） | S | 活动/日志独立表缺（事件入证据库） |
| `settings` | db/schema.sql:356 | 表 settings | partial（lab/ 配置） | S | 集中设置表缺 |
| `llm_profiles` | db/schema.sql:362 | 表 llm_profiles | missing | - | 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY） |
| `llm_profile_health` | db/schema.sql:479 | 表 llm_profile_health | missing | - | 多模型池：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY） |
| `task_categories` | db/schema.sql:493 | 表 task_categories | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `tasks` | db/schema.sql:505 | 表 tasks | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `task_archives` | db/schema.sql:572 | 表 task_archives | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `task_templates` | db/schema.sql:614 | 表 task_templates | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `task_relations` | db/schema.sql:637 | 表 task_relations | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `task_asset_links` | db/schema.sql:649 | 表 task_asset_links | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `task_llm_profiles` | db/schema.sql:697 | 表 task_llm_profiles | missing | - | 任务级 LLM profile 关联：架构不适用（无任务实体；见 ARTEX-PARITY） |
| `task_scope` | db/schema.sql:739 | 表 task_scope | we-have（core/roe.py） | S | 约束/范围持久化表缺（ROE YAML 内） |
| `agents` | db/schema.sql:767 | 表 agents | missing | - | 多 agent 实体族（不纳入（理由见 ARTEX-PARITY）） |
| `agent_prompts` | db/schema.sql:805 | 表 agent_prompts | missing | - | 多 agent 实体族（不纳入（理由见 ARTEX-PARITY）） |
| `agent_prompt_vars` | db/schema.sql:821 | 表 agent_prompt_vars | missing | - | 多 agent 实体族（不纳入（理由见 ARTEX-PARITY）） |
| `mcp_servers` | db/schema.sql:834 | 表 mcp_servers | partial（mcp_server.py） | M | 外部 MCP 挂载表缺（服务端已有） |
| `mcp_tools_cache` | db/schema.sql:865 | 表 mcp_tools_cache | partial（mcp_server.py） | M | 外部 MCP 挂载表缺（服务端已有） |
| `agent_visibility` | db/schema.sql:878 | 表 agent_visibility | missing | - | 多 agent 实体族（不纳入（理由见 ARTEX-PARITY）） |
| `agent_skill_visibility` | db/schema.sql:889 | 表 agent_skill_visibility | missing | - | 多 agent 实体族（不纳入（理由见 ARTEX-PARITY）） |
| `skill_usage` | db/schema.sql:901 | 表 skill_usage | partial（core/registry.py） | S | 工具/技能使用统计缺 |
| `tool_usage` | db/schema.sql:920 | 表 tool_usage | partial（core/registry.py） | S | 工具/技能使用统计缺 |
| `tools` | db/schema.sql:936 | 表 tools | partial（core/registry.py） | S | 工具/技能使用统计缺 |
| `conversations` | db/schema.sql:955 | 表 conversations | missing | - | 会话持久化（对话式平台不纳入（理由见 ARTEX-PARITY）） |
| `conversation_activities` | db/schema.sql:971 | 表 conversation_activities | missing | M | 未归类表：待人工归类 |
| `agent_triggers` | db/schema.sql:994 | 表 agent_triggers | missing | - | 多 agent 实体族（不纳入（理由见 ARTEX-PARITY）） |
| `scheduler_state` | db/schema.sql:1026 | 表 scheduler_state | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `task_schedules` | db/schema.sql:1034 | 表 task_schedules | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `task_schedule_tasks` | db/schema.sql:1066 | 表 task_schedule_tasks | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `intercept_rules` | db/schema.sql:1081 | 表 intercept_rules | we-have（core/explorer.py 审批队列） | S | 拦截规则/待审持久化表缺（内存队列+ROE） |
| `intercept_pending` | db/schema.sql:1101 | 表 intercept_pending | we-have（core/explorer.py 审批队列） | S | 拦截规则/待审持久化表缺（内存队列+ROE） |
| `findings` | db/schema.sql:1134 | 表 findings | we-have（core/evidence.py findings） | S | 独立 findings 表缺（入 run 证据库） |
| `finding_retests` | db/schema.sql:1165 | 表 finding_retests | partial（webui /api/v1/poc/reverify） | M | retest 实体表缺 [CM-14] |
| `traffic_evidence_snapshots` | db/schema.sql:1199 | 表 traffic_evidence_snapshots | partial（core/traffic.py） | M | 流量快照/绑定表缺 [CM-18] |
| `finding_traffic_bindings` | db/schema.sql:1216 | 表 finding_traffic_bindings | partial（core/traffic.py） | M | 流量快照/绑定表缺 [CM-18] |
| `server_logs` | db/schema.sql:1232 | 表 server_logs | partial（core/evidence.py JSONL） | S | 活动/日志独立表缺（事件入证据库） |
| `side_question_sessions` | db/schema.sql:1242 | 表 side_question_sessions | missing | M | 侧问会话/请求 |
| `side_question_requests` | db/schema.sql:1268 | 表 side_question_requests | missing | M | 侧问会话/请求 |
| `asset_intercept_rules` | db/schema.sql:1302 | 表 asset_intercept_rules | we-have（core/explorer.py 审批队列） | S | 拦截规则/待审持久化表缺（内存队列+ROE） |
| `task_intercept_rules` | db/schema.sql:1328 | 表 task_intercept_rules | we-have（core/explorer.py 审批队列） | S | 拦截规则/待审持久化表缺（内存队列+ROE） |
| `notification_channels` | db/schema.sql:1364 | 表 notification_channels | missing | S | 通知渠道/事件/投递表 [CM-10] |
| `notification_events` | db/schema.sql:1402 | 表 notification_events | missing | S | 通知渠道/事件/投递表 [CM-10] |
| `notification_deliveries` | db/schema.sql:1420 | 表 notification_deliveries | missing | S | 通知渠道/事件/投递表 [CM-10] |
| `finding_cases` | db/schema.sql:1450 | 表 finding_cases | missing | M | 案例归并族表 [CM-17] |
| `finding_case_members` | db/schema.sql:1464 | 表 finding_case_members | missing | M | 案例归并族表 [CM-17] |
| `finding_case_events` | db/schema.sql:1470 | 表 finding_case_events | missing | M | 案例归并族表 [CM-17] |
| `finding_case_suggestions` | db/schema.sql:1479 | 表 finding_case_suggestions | missing | M | 案例归并族表 [CM-17] |
| `finding_case_blocks` | db/schema.sql:1492 | 表 finding_case_blocks | missing | M | 案例归并族表 [CM-17] |
| `finding_case_review_runs` | db/schema.sql:1527 | 表 finding_case_review_runs | missing | M | 案例归并族表 [CM-17] |
| `task_schedule_history` | db/schema.sql:1540 | 表 task_schedule_history | partial（core/scheduler.py + core/runner.py runs） | M | 任务实体族表缺；调度等价（cron+diff_findings），历史/状态持久化缺 [CM-31] |
| `task_intelligence` | db/schema.sql:1552 | 表 task_intelligence | missing | S | 任务情报表 [CM-01] |

## A3. Agent 组件（agent/*.go）（32 项）

| 功能 | 来源锚点 | 工具行为 | Trident 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `assembly.go` | agent/assembly.go:1 | 组件文件（types: DeferredInfo, guardedTool） | partial（core/chains.py + core/evidence.py） | S | 工具装配/捕获留档差异 |
| `cancelcause.go` | agent/cancelcause.go:1 | 组件文件（types: AbortCause） | partial（core/runner.py abort/timeout） | S | 任务钟/终止原因留档细节缺 |
| `capture.go` | agent/capture.go:1 | 组件文件（types: -） | partial（core/chains.py + core/evidence.py） | S | 工具装配/捕获留档差异 |
| `chat.go` | agent/chat.go:1 | 组件文件（types: ChatAgent, chatVars） | partial（agent_planner.py + core/explorer.py） | - | 规划/探索循环：推荐+lead 审批等价；自主多轮执行不纳入（审批边界；见 ARTEX-PARITY） |
| `coldgraph.go` | agent/coldgraph.go:1 | 组件文件（types: block, cgEdge, cgNode, coldGraph, coldParams, stampOp, unionFind） | partial（core/graph.py） | M | 冷启动图重建缺 [CM-16] |
| `compaction.go` | agent/compaction.go:1 | 组件文件（types: Compactor） | missing | - | 上下文压缩（无多轮对话运行时，不纳入（理由见 ARTEX-PARITY）） |
| `constraints.go` | agent/constraints.go:1 | 组件文件（types: -） | we-have（core/roe.py） | S | 延迟动作/约束执行缺端点 |
| `credentials.go` | agent/credentials.go:1 | 组件文件（types: -） | missing | S | 情报/凭据登记 [CM-01] |
| `deferred.go` | agent/deferred.go:1 | 组件文件（types: -） | we-have（core/roe.py） | S | 延迟动作/约束执行缺端点 |
| `finding_cases.go` | agent/finding_cases.go:1 | 组件文件（types: findingReviewKey） | partial（core/evidence.py + core/combo.py） | M | finding 工作流/案例缺 [CM-17] |
| `finding_recorder.go` | agent/finding_recorder.go:1 | 组件文件（types: -） | partial（core/evidence.py + core/combo.py） | M | finding 工作流/案例缺 [CM-17] |
| `finding_workflow.go` | agent/finding_workflow.go:1 | 组件文件（types: -） | partial（core/evidence.py + core/combo.py） | M | finding 工作流/案例缺 [CM-17] |
| `goals.go` | agent/goals.go:1 | 组件文件（types: GoalSpec） | partial（agent_planner.py） | M | goal 实体/复活任务缺 [CM-16] |
| `intelligence.go` | agent/intelligence.go:1 | 组件文件（types: -） | missing | S | 情报/凭据登记 [CM-01] |
| `mainagent.go` | agent/mainagent.go:1 | 组件文件（types: MainAgent） | partial（agent_planner.py + core/explorer.py） | - | 规划/探索循环：推荐+lead 审批等价；自主多轮执行不纳入（审批边界；见 ARTEX-PARITY） |
| `noa.go` | agent/noa.go:1 | 组件文件（types: -） | missing | - | 上下文压缩（无多轮对话运行时，不纳入（理由见 ARTEX-PARITY）） |
| `planner.go` | agent/planner.go:1 | 组件文件（types: Planner, TriggerEvent） | partial（agent_planner.py + core/explorer.py） | - | 规划/探索循环：推荐+lead 审批等价；自主多轮执行不纳入（审批边界；见 ARTEX-PARITY） |
| `prompt.go` | agent/prompt.go:1 | 组件文件（types: GoalsVars, MainVars, PlannerVars, WorkerVars） | partial（core/registry.py + rules/templates/） | S | 提示词/工具目录机制差异（模块即工具） |
| `promptcatalog.go` | agent/promptcatalog.go:1 | 组件文件（types: -） | partial（core/registry.py + rules/templates/） | S | 提示词/工具目录机制差异（模块即工具） |
| `provider.go` | agent/provider.go:1 | 组件文件（types: Config, RetryConfig, quotaAwareTransport） | missing | - | 多模型 provider/限流：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `request_limiter.go` | agent/request_limiter.go:1 | 组件文件（types: RequestLimiter, rateLimitedTransport, requestWindow） | missing | - | 多模型 provider/限流：本轮 clean-room 实现（core/llmpool.py；见 ARTEX-PARITY）|
| `retester.go` | agent/retester.go:1 | 组件文件（types: -） | partial（poc reverify + verify-effects.py） | M | 自动复测 worker 缺 [CM-14] |
| `runinfo.go` | agent/runinfo.go:1 | 组件文件（types: RunInfo, runInfoKey） | partial（core/runner.py abort/timeout） | S | 任务钟/终止原因留档细节缺 |
| `side_questions.go` | agent/side_questions.go:1 | 组件文件（types: -） | missing | M | 侧问 |
| `taskclock.go` | agent/taskclock.go:1 | 组件文件（types: TaskClock, taskClockKey） | partial（core/runner.py abort/timeout） | S | 任务钟/终止原因留档细节缺 |
| `terminalreason.go` | agent/terminalreason.go:1 | 组件文件（types: runTrace） | partial（core/runner.py abort/timeout） | S | 任务钟/终止原因留档细节缺 |
| `toolcatalog.go` | agent/toolcatalog.go:1 | 组件文件（types: ToolSeed, overriddenTool） | partial（core/registry.py + rules/templates/） | S | 提示词/工具目录机制差异（模块即工具） |
| `tools.go` | agent/tools.go:1 | 组件文件（types: ToolSet, WriteCounts, constraintItem, factItem, goalItem, hintItem, intentItem, overviewTextBudget） | partial（core/registry.py + rules/templates/） | S | 提示词/工具目录机制差异（模块即工具） |
| `tools_digest.go` | agent/tools_digest.go:1 | 组件文件（types: -） | partial（core/registry.py + rules/templates/） | S | 提示词/工具目录机制差异（模块即工具） |
| `tools_insert.go` | agent/tools_insert.go:1 | 组件文件（types: assetInputItem） | partial（core/registry.py + rules/templates/） | S | 提示词/工具目录机制差异（模块即工具） |
| `worker.go` | agent/worker.go:1 | 组件文件（types: WebSearchOpts, Worker） | partial（agent_planner.py + core/explorer.py） | - | 规划/探索循环：推荐+lead 审批等价；自主多轮执行不纳入（审批边界；见 ARTEX-PARITY） |
| `wrapup.go` | agent/wrapup.go:1 | 组件文件（types: -） | missing | - | 收尾 prompt（对话式运行时外） |

## A4. Web 页面（web/src/app/**/page.tsx）（29 项）

| 功能 | 来源锚点 | 工具行为 | Trident 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `/(auth)/login` | web/src/app/(auth)/login/page.tsx | Next.js 页面 | N/A | - | 外部落地页/类别外 |
| `/(auth)/setup` | web/src/app/(auth)/setup/page.tsx | Next.js 页面 | N/A | - | 外部落地页/类别外 |
| `/(external)` | web/src/app/(external)/page.tsx | Next.js 页面 | N/A | - | 外部落地页/类别外 |
| `/(main)/chat` | web/src/app/(main)/chat/page.tsx | Next.js 页面 | missing | - | 对话页（不纳入（理由见 ARTEX-PARITY）） |
| `/(main)/dashboard` | web/src/app/(main)/dashboard/page.tsx | Next.js 页面 | we-have（webui SPA 总览视图） | - |  |
| `/(main)/function/assets` | web/src/app/(main)/function/assets/page.tsx | Next.js 页面 | we-have（webui assets 视图） | - |  |
| `/(main)/function/commands` | web/src/app/(main)/function/commands/page.tsx | Next.js 页面 | partial（webui + evidence 命令记录） | S | 命令审计页缺 |
| `/(main)/function/findings/case` | web/src/app/(main)/function/findings/case/page.tsx | Next.js 页面 | missing | M | 案例归并页 [CM-17] |
| `/(main)/function/findings/detail` | web/src/app/(main)/function/findings/detail/page.tsx | Next.js 页面 | partial（webui findings 视图） | S | finding 详情/批注缺 |
| `/(main)/function/findings` | web/src/app/(main)/function/findings/page.tsx | Next.js 页面 | partial（webui findings 视图） | S | finding 详情/批注缺 |
| `/(main)/function/llm-records` | web/src/app/(main)/function/llm-records/page.tsx | Next.js 页面 | missing | - | LLM 调用记录（0-token） |
| `/(main)/function/schedules` | web/src/app/(main)/function/schedules/page.tsx | Next.js 页面 | we-have（webui 调度视图） | - |  |
| `/(main)/function/sync` | web/src/app/(main)/function/sync/page.tsx | Next.js 页面 | missing | S | ScopeSentry 同步页 [CM-13] |
| `/(main)/function/tasks/detail` | web/src/app/(main)/function/tasks/detail/page.tsx | Next.js 页面 | partial（webui runs 视图） | M | 任务详情/控制 UI 部分对齐（缺任务元数据编辑） [CM-31] |
| `/(main)/function/tasks` | web/src/app/(main)/function/tasks/page.tsx | Next.js 页面 | partial（webui runs 视图） | M | 任务详情/控制 UI 部分对齐（缺任务元数据编辑） [CM-31] |
| `/(main)/function/traffic` | web/src/app/(main)/function/traffic/page.tsx | Next.js 页面 | partial（webui traffic 回放视图） | S | 流量浏览/删除 UI 缺 |
| `/(main)/function/workspace` | web/src/app/(main)/function/workspace/page.tsx | Next.js 页面 | missing | M | 工作区文件管理页 |
| `/(main)/system/agents/detail` | web/src/app/(main)/system/agents/detail/page.tsx | Next.js 页面 | missing | - | 多 agent 管理页（不纳入（理由见 ARTEX-PARITY）） |
| `/(main)/system/agents` | web/src/app/(main)/system/agents/page.tsx | Next.js 页面 | missing | - | 多 agent 管理页（不纳入（理由见 ARTEX-PARITY）） |
| `/(main)/system/intercept/approvals` | web/src/app/(main)/system/intercept/approvals/page.tsx | Next.js 页面 | we-have（webui /approve //reject 审批页） | - |  |
| `/(main)/system/intercept/assets` | web/src/app/(main)/system/intercept/assets/page.tsx | Next.js 页面 | partial（webui 审批 + core/roe.py） | S | 拦截规则/资产黑名单管理页缺 |
| `/(main)/system/intercept` | web/src/app/(main)/system/intercept/page.tsx | Next.js 页面 | partial（webui 审批 + core/roe.py） | S | 拦截规则/资产黑名单管理页缺 |
| `/(main)/system/llm` | web/src/app/(main)/system/llm/page.tsx | Next.js 页面 | missing | - | LLM 配置页（不纳入（理由见 ARTEX-PARITY）） |
| `/(main)/system/logs` | web/src/app/(main)/system/logs/page.tsx | Next.js 页面 | partial（evidence JSONL + webui） | S | 日志流页缺 [CM-02] |
| `/(main)/system/mcp` | web/src/app/(main)/system/mcp/page.tsx | Next.js 页面 | partial（mcp_server.py） | M | 外部 MCP 挂载页缺 |
| `/(main)/system/notify` | web/src/app/(main)/system/notify/page.tsx | Next.js 页面 | missing | S | 通知渠道页 [CM-10] |
| `/(main)/system/settings` | web/src/app/(main)/system/settings/page.tsx | Next.js 页面 | partial（lab/ 配置 + CLI） | S | 设置页缺 |
| `/(main)/system/skills` | web/src/app/(main)/system/skills/page.tsx | Next.js 页面 | partial（lab/ + rules/templates/） | M | skill 管理页缺 |
| `/(main)/system/tools` | web/src/app/(main)/system/tools/page.tsx | Next.js 页面 | partial（core/registry.py） | S | 工具目录页缺 |

## A5. Web 组件（components + (main)/_components）（107 项）

| 功能 | 来源锚点 | 工具行为 | Trident 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `components/agent-editor.tsx` | web/src/components/agent-editor.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/approval-execution-focus.tsx` | web/src/components/approval-execution-focus.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/approval-records.tsx` | web/src/components/approval-records.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/asset-dsl-search.tsx` | web/src/components/asset-dsl-search.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/asset-intercept-rules-editor.tsx` | web/src/components/asset-intercept-rules-editor.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/calendar/event-calendar-views.tsx` | web/src/components/calendar/event-calendar-views.tsx | UI 组件 | partial（core/scheduler.py） | S | 日历式调度视图缺 |
| `components/copy-button.tsx` | web/src/components/copy-button.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/credential-content.tsx` | web/src/components/credential-content.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/date-range-picker.tsx` | web/src/components/date-range-picker.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/date-select.tsx` | web/src/components/date-select.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/exploration-graph.tsx` | web/src/components/exploration-graph.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/finding-case-list.tsx` | web/src/components/finding-case-list.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/finding-retest-dialog.tsx` | web/src/components/finding-retest-dialog.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/finding-retest-panel.tsx` | web/src/components/finding-retest-panel.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/finding-traffic-panel.tsx` | web/src/components/finding-traffic-panel.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/http-code-block.tsx` | web/src/components/http-code-block.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/intelligence-panel.tsx` | web/src/components/intelligence-panel.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/link-traffic-dialog.tsx` | web/src/components/link-traffic-dialog.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/markdown.tsx` | web/src/components/markdown.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/mention-textarea.tsx` | web/src/components/mention-textarea.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/remark-editor.tsx` | web/src/components/remark-editor.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/scope-text-editor.tsx` | web/src/components/scope-text-editor.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/side-question-workspace.tsx` | web/src/components/side-question-workspace.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/simple-icon.tsx` | web/src/components/simple-icon.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/status-badge.tsx` | web/src/components/status-badge.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/table-pagination.tsx` | web/src/components/table-pagination.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/task-llm-profile-chain.tsx` | web/src/components/task-llm-profile-chain.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/task-template-controls.tsx` | web/src/components/task-template-controls.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/time-select.tsx` | web/src/components/time-select.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/todo-popover.tsx` | web/src/components/todo-popover.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/traffic-evidence-viewer.tsx` | web/src/components/traffic-evidence-viewer.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/traffic-picker-dialog.tsx` | web/src/components/traffic-picker-dialog.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/transcript.tsx` | web/src/components/transcript.tsx | UI 组件 | N/A | - | 未归类组件 |
| `components/ui/accordion.tsx` | web/src/components/ui/accordion.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/alert-dialog.tsx` | web/src/components/ui/alert-dialog.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/alert.tsx` | web/src/components/ui/alert.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/aspect-ratio.tsx` | web/src/components/ui/aspect-ratio.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/attachment.tsx` | web/src/components/ui/attachment.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/avatar.tsx` | web/src/components/ui/avatar.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/badge.tsx` | web/src/components/ui/badge.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/breadcrumb.tsx` | web/src/components/ui/breadcrumb.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/bubble.tsx` | web/src/components/ui/bubble.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/button-group.tsx` | web/src/components/ui/button-group.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/button.tsx` | web/src/components/ui/button.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/calendar.tsx` | web/src/components/ui/calendar.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/card.tsx` | web/src/components/ui/card.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/carousel.tsx` | web/src/components/ui/carousel.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/chart.tsx` | web/src/components/ui/chart.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/checkbox.tsx` | web/src/components/ui/checkbox.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/collapsible.tsx` | web/src/components/ui/collapsible.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/combobox.tsx` | web/src/components/ui/combobox.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/command.tsx` | web/src/components/ui/command.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/context-menu.tsx` | web/src/components/ui/context-menu.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/dialog.tsx` | web/src/components/ui/dialog.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/direction.tsx` | web/src/components/ui/direction.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/drawer.tsx` | web/src/components/ui/drawer.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/dropdown-menu.tsx` | web/src/components/ui/dropdown-menu.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/empty.tsx` | web/src/components/ui/empty.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/field.tsx` | web/src/components/ui/field.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/hover-card.tsx` | web/src/components/ui/hover-card.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/input-group.tsx` | web/src/components/ui/input-group.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/input-otp.tsx` | web/src/components/ui/input-otp.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/input.tsx` | web/src/components/ui/input.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/item.tsx` | web/src/components/ui/item.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/kbd.tsx` | web/src/components/ui/kbd.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/label.tsx` | web/src/components/ui/label.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/marker.tsx` | web/src/components/ui/marker.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/menubar.tsx` | web/src/components/ui/menubar.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/message-scroller.tsx` | web/src/components/ui/message-scroller.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/message.tsx` | web/src/components/ui/message.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/native-select.tsx` | web/src/components/ui/native-select.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/navigation-menu.tsx` | web/src/components/ui/navigation-menu.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/pagination.tsx` | web/src/components/ui/pagination.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/popover.tsx` | web/src/components/ui/popover.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/progress.tsx` | web/src/components/ui/progress.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/radio-group.tsx` | web/src/components/ui/radio-group.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/resizable.tsx` | web/src/components/ui/resizable.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/scroll-area.tsx` | web/src/components/ui/scroll-area.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/select.tsx` | web/src/components/ui/select.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/separator.tsx` | web/src/components/ui/separator.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/sheet.tsx` | web/src/components/ui/sheet.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/sidebar.tsx` | web/src/components/ui/sidebar.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/skeleton.tsx` | web/src/components/ui/skeleton.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/slider.tsx` | web/src/components/ui/slider.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/sonner.tsx` | web/src/components/ui/sonner.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/sortable-head.tsx` | web/src/components/ui/sortable-head.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/spinner.tsx` | web/src/components/ui/spinner.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/switch.tsx` | web/src/components/ui/switch.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/table.tsx` | web/src/components/ui/table.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/tabs.tsx` | web/src/components/ui/tabs.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/textarea.tsx` | web/src/components/ui/textarea.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/toggle-group.tsx` | web/src/components/ui/toggle-group.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/toggle.tsx` | web/src/components/ui/toggle.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `components/ui/tooltip.tsx` | web/src/components/ui/tooltip.tsx | UI 组件 | N/A | - | shadcn/ui 基础件（非功能特性） |
| `app/(main)/_components/main-content.tsx` | web/src/app/(main)/_components/main-content.tsx | 主布局组件 | N/A | - | 未归类组件 |
| `app/(main)/_components/sidebar/account-switcher.tsx` | web/src/app/(main)/_components/sidebar/account-switcher.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/app-sidebar.tsx` | web/src/app/(main)/_components/sidebar/app-sidebar.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/change-password-dialog.tsx` | web/src/app/(main)/_components/sidebar/change-password-dialog.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/layout-controls.tsx` | web/src/app/(main)/_components/sidebar/layout-controls.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/nav-documents.tsx` | web/src/app/(main)/_components/sidebar/nav-documents.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/nav-main.tsx` | web/src/app/(main)/_components/sidebar/nav-main.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/nav-secondary.tsx` | web/src/app/(main)/_components/sidebar/nav-secondary.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/nav-user.tsx` | web/src/app/(main)/_components/sidebar/nav-user.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/search-dialog.tsx` | web/src/app/(main)/_components/sidebar/search-dialog.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/sidebar-support-card.tsx` | web/src/app/(main)/_components/sidebar/sidebar-support-card.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/sidebar/theme-switcher.tsx` | web/src/app/(main)/_components/sidebar/theme-switcher.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |
| `app/(main)/_components/update-badge.tsx` | web/src/app/(main)/_components/update-badge.tsx | 主布局组件 | partial（webui SPA 导航） | S | 侧栏/账号切换/主题切换/全局搜索 UI 细节缺 |

## A6. 配置键（config.example.json）（7 项）

| 功能 | 来源锚点 | 工具行为 | Trident 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `database.host` | config.example.json | 配置键 = '127.0.0.1' | missing | - | PG 依赖（单机零依赖 evidence store，部署形态刻意差异） |
| `database.port` | config.example.json | 配置键 = 5433 | missing | - | PG 依赖（单机零依赖 evidence store，部署形态刻意差异） |
| `database.user` | config.example.json | 配置键 = 'artex' | missing | - | PG 依赖（单机零依赖 evidence store，部署形态刻意差异） |
| `database.password` | config.example.json | 配置键 = '' | missing | - | PG 依赖（单机零依赖 evidence store，部署形态刻意差异） |
| `database.dbname` | config.example.json | 配置键 = 'artex' | missing | - | PG 依赖（单机零依赖 evidence store，部署形态刻意差异） |
| `database.sslmode` | config.example.json | 配置键 = 'disable' | missing | - | PG 依赖（单机零依赖 evidence store，部署形态刻意差异） |
| `skill_dir` | config.example.json | 配置键 = '/opt/artex/skills' | partial（lab/ 脚本目录约定） | S | 可配置 skill 根目录缺 |

## A7. 内置 skills（skills/）（3 项）

| 功能 | 来源锚点 | 工具行为 | Trident 状态 | 行动项 | 备注 |
|---|---|---|---|---|---|
| `api-recon` | skills/api-recon/ | 内置 skill 目录 | partial（modules/recon 族（exposure-mapping 等）） | - | API 面侦察细分模块 |
| `playwright-cli` | skills/playwright-cli/ | 内置 skill 目录 | missing | M | 浏览器自动化 skill（Web UI 攻击面） |
| `scopesentry` | skills/scopesentry/ | 内置 skill 目录 | missing | S | ScopeSentry 对接 skill [CM-13] |
