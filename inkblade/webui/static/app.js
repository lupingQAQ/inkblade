/* InkBlade 十视图 SPA — 原生 JS + vendor UMD（React / ReactDOM / React Flow v11），无构建步骤。
 *
 * 数据源：
 *  - 静态导出模式：window.INKBLADE_DATA（由 export_static.py 注入，免服务打开）
 *  - 服务模式：POST api/login、GET api/runs、GET api/v1/{workspaces,consent,steps,graph,
 *    timeline,file-ops,evidence,report,assets,drift,explorer,scheduler}
 *
 * 首屏：
 *  - 未登录：真实环境接入向导（登录卡 + kubeconfig/授权/探针三步）
 *  - 登录后：工作区、运行列表、最近发现、链状态总览
 *
 * 十视图：DAG / 攻击链 / 时间线 / 证据 / 报告 / 规则 / 资产 / 差异 / 审批 / 计划。
 */
(function () {
  "use strict";

  /* ================= 基础工具 ================= */

  var SVG_NS = "http://www.w3.org/2000/svg";

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }
  function svgEl(tag, attrs) {
    var n = document.createElementNS(SVG_NS, tag);
    for (var k in attrs || {}) n.setAttribute(k, attrs[k]);
    return n;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function esc(s) {
    return String(s === undefined || s === null ? "" : s);
  }
  function fmtTime(ts) {
    if (!ts) return "—";
    var d = new Date(ts * 1000);
    var p = function (x) { return (x < 10 ? "0" : "") + x; };
    return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }
  function fmtDur(ms) {
    if (ms === undefined || ms === null || isNaN(ms)) return "—";
    if (ms < 1000) return Math.round(ms) + "ms";
    if (ms < 60000) return (ms / 1000).toFixed(1) + "s";
    return (ms / 60000).toFixed(1) + "min";
  }

  var STATUS_ZH = {
    pending: "待执行", running: "运行中", success: "成功",
    degraded: "降级", blocked: "阻断",
  };
  var SEV_ORDER = ["critical", "high", "medium", "low", "info"];

  /* ================= 状态 ================= */

  var STATE = {
    token: null, role: null, user: null, workspace: "local-lab",
    runs: [], data: window.INKBLADE_DATA || null,
    selectedStep: null, selectedRun: "", view: "dag", reportRemote: null, redactZeroday: false,
    remoteTimeline: null, remoteFileOps: null,
    remoteSteps: null, remoteNodes: null, remoteEdges: null, remoteGraph: null,
    remoteEvidence: null, remoteManifestVerified: null, remoteReport: null,
    remoteAuditLoaded: false, remoteAuditLoading: false, remoteAuditRun: "",
    consent: null, workspaces: [], runLoading: false, runError: "", runGen: 0,
    connectInit: false, connectUserToggled: false, connectOpen: false,
    lang: "zh",
  };
  var STATIC_MODE = !!window.INKBLADE_DATA;

  /* 视图宿主：view-dag / view-chain / view-timeline / view-evidence / view-report /
   * view-rules / view-assets / view-drift / view-approvals / view-schedules */
  var VIEW_IDS = ["dag", "chain", "timeline", "evidence", "report",
    "rules", "assets", "drift", "approvals", "schedules"];

  /* ================= 双语（zh/en） =================
   * 静态文案走 index.html 的 data-i18n；动态视图走 t(key)。
   * 没有构建步骤，字典随 app.js 全离线内嵌。 */
  var I18N = {
    zh: {
      "brand.sub": "ML 集群渗透测试控制台 · 十视图",
      "mode.offline": "本地控制台",
      "mode.static": "静态导出 · 免服务打开",
      "mode.service": "服务模式 · 本地",
      "topbar.workspace": "工作区",
      "lang.switch": "切换语言 / Switch language",
      "login.user": "用户名", "login.pass": "密码", "login.ws": "工作区",
      "login.submit": "登录", "login.abort": "紧急停止",
      "login.subtitle": "授权范围内的 ML 集群渗透测试控制台",
      "connect.kicker": "CONNECT",
      "connect.title": "接入",
      "connect.hasRuns": "已有运行 · 可折叠",
      "connect.noRuns": "尚无运行 · 按探针优先接入",
      "connect.recommended": "推荐",
      "connect.assumption": "默认立足点：普通/最低权限 Pod（非 root、无 hostPath/privileged、无 kubeconfig，仅出站 TCP）。",
      "connect.existing.title": "已有探针 / 立足点",
      "connect.existing.body": "已有投放的探针、foothold shell 或低权限 Pod 可主动回连控制端；不需要 kubeconfig。",
      "connect.existing.step1": "控制端监听",
      "connect.existing.step2": "Pod 内探针回连",
      "connect.existing.step3": "确认探针注册",
      "connect.first.title": "首次投放",
      "connect.first.body": "没有现成探针时，从 foothold 进入并投放；默认立足点为普通/最低权限 Pod，仅需出站 TCP。",
      "connect.first.step1": "控制端监听",
      "connect.first.step2": "建立 foothold 会话",
      "connect.first.step3": "RCE 投放探针",
      "connect.first.sa": "SA token 投放（备选）",
      "connect.first.reverse": "Pod 内探针回连",
      "connect.first.confirm": "确认探针注册",
      "connect.advanced.summary": "kubeconfig 批量投放（可选）",
      "connect.advanced.body": "仅当直接持有 kubeconfig 且需要批量投放时使用；不是接入前提。",
      "connect.advanced.step1": "kubeconfig 会话",
      "connect.advanced.step2": "批量投放",
      "connect.advanced.step3": "确认探针注册",
      "dash.eyebrow": "WORKSPACE OVERVIEW", "dash.workspace": "工作区",
      "dash.runs": "运行列表", "dash.findings": "最近发现", "dash.chain": "链状态",
      "dash.loading": "正在读取工作区…", "dash.refresh": "刷新", "dash.run": "运行",
      "dash.role": "角色", "dash.consent": "授权", "dash.consentComplete": "已签署",
      "dash.consentPending": "未签署", "dash.runCount": "运行数", "dash.latest": "最近运行",
      "dash.noRuns": "还没有运行。完成 CLI 接入后刷新。",
      "dash.noWorkspace": "未连接工作区", "dash.loadingRun": "正在载入运行数据…",
      "dash.noRunData": "该运行暂无步骤数据。",
      "dash.findingsTotal": "发现总数", "dash.steps": "步骤", "dash.graph": "图节点",
      "dash.chainEdges": "链边", "dash.chainStatus": "运行状态",
      "dash.statusSuccess": "成功", "dash.statusRunning": "运行中",
      "dash.statusDegraded": "降级", "dash.statusBlocked": "阻断", "dash.statusPending": "待执行",
      "dash.selectRun": "选择运行查看发现与链状态。",
      "dash.runLoadFail": "运行数据加载失败：",
      "dash.refreshing": "正在刷新…", "dash.refreshed": "已刷新",
      "dash.abortSent": "已发送紧急停止",
      "nav.dag": "工作流 DAG", "nav.chain": "攻击链图", "nav.timeline": "执行时间线",
      "nav.evidence": "证据浏览器", "nav.report": "报告预览", "nav.rules": "规则视图",
      "nav.assets": "资产图", "nav.drift": "差异视图", "nav.approvals": "审批队列",
      "nav.schedules": "计划任务",
      "status.pending": "待执行", "status.running": "运行中", "status.success": "成功",
      "status.degraded": "降级", "status.blocked": "阻断",
      "dag.sidebar": "步骤详情",
      "dag.sidebarHint": "点击节点查看 prompt/命令、环境、结果与三层证据指针。",
      "chain.filter": "链过滤", "chain.all": "全部链",
      "chain.legend": "边色：红=可达利用 / 橙=高危路径 / 黄虚线=降级 / 灰虚线=阻断·不可达",
      "timeline.title": "执行瀑布",
      "ops.title": "操作与文件访问台账",
      "ops.hint": "逐条列出探针执行的命令（argv/cwd/exit/耗时/stdout 摘要）与读取/写入的文件；点击行跳到证据浏览器对应步骤。",
      "ops.empty": "本 run 未记录文件/操作审计事件（file_ops 为空）。",
      "ops.col.time": "时间", "ops.col.subject": "主体", "ops.col.action": "动作",
      "ops.col.target": "目标", "ops.col.files": "文件", "ops.col.result": "结果",
      "ops.col.hash": "证据哈希",
      "ops.badge.read": "读", "ops.badge.write": "写", "ops.badge.rw": "读写",
      "ops.badge.list": "列目录", "ops.badge.exploit": "利用",
      "ops.jump": "查看证据",
      "ops.summary": "共 {total} 条事件 · 命令/文件 {file} · 步骤 {step} · 利用标记 {exploit}",
      "evidence.files": "文件访问（file_ops）",
      "evidence.steps": "运行步骤", "evidence.threeLayers": "三层证据",
      "evidence.pickHint": "选择左侧步骤查看 prompt/命令、环境、归档哈希与上下文摘要指针。",
      "evidence.manifest": "归档清单 manifest.sha256",
      "rules.title": "规则 ↔ 攻击链映射矩阵",
      "rules.hint": "行=防御/检测规则（Kyverno·Gatekeeper·NetworkPolicy·PSS·Sigma·Falco·Suricata），列=攻击链；●=规则覆盖该链。",
      "assets.title": "资产图（增量资产清单）",
      "assets.hint": "种子（命名空间/服务清单/kubeconfig 快照）→ core/discovery 增量入库；模块经资产解析目标而非散装参数。",
      "drift.title": "重测差异（drift）",
      "drift.hint": "scheduler 到期跑链子集，与上次 findings 逐键差异：新增（红）/已修复（绿）/未变。",
      "approvals.title": "审批队列（审批制自主探索）",
      "approvals.hint": "LLM 可选（OpenAI 兼容 env）+ 规则兜底；逐动作 dry-run 预览（写面/备份闸门），lead 批准后才可执行。",
      "schedules.title": "计划任务（周期重测）",
      "schedules.hint": "cron/interval 计划 → 到期自动跑指定链子集 → drift 报告。",
      "footer.line": "InkBlade · 资产全部本地内嵌（无 CDN）· 证据三层：上下文摘要 / 数据库 / 归档（tar+SHA256）",
      "common.copy": "复制", "common.copied": "已复制",
      "common.probe": "启动探针", "common.cluster": "连接真实集群",
      "run.staticMeta": "运行 {run} · 状态 {status} · 步骤 {steps} · 发现 {findings}",
      "run.serviceMeta": "本工作区运行数：{n}（{runs}）",
      "run.serviceEmpty": "已登录，等待本工作区的运行数据。",
      "run.loadFail": "获取运行失败：",
      "report.total": "发现总数", "report.steps": "执行步骤",
      "report.findings": "发现清单（Findings）",
      "report.redact": "零日级细节脱敏（可选；默认展示已公开细节）",
      "report.showing": "已渲染 {shown} / {total} 条（分页渲染，避免一次性构建 {total} 个 DOM 行）",
      "report.showMore": "显示更多（+{n}）",
      "report.legacy": "legacy 基准模式：全量渲染（仅用于优化前后对比）",
      "report.severity": "严重度", "report.titleCol": "标题", "report.step": "步骤",
      "report.evidence": "证据（归档层引用）", "report.zeroday": "零日",
      "report.sectionTitle": "结构对齐（PTES / NIST SP 800-115 / 等保 2.0 · GB/T 20984 / CVSS 3.1 / ATT&CK·ATLAS）",
      "report.sectionBody": "预览页仅渲染发现表与统计；正式双语报告由报告引擎生成（渗透 + 修复 + 防御规则包交付文档），含组合层风险 / 训练数据泄露面 / 核心代码清单 / 网络分层威胁模型 / 混合云边界专节。",
      "report.remote": "服务端 /api/v1/report 已返回报告（{bytes} 字节）；以下为 Markdown 原文：",
      "report.fallback": "服务端报告暂不可用：{msg}。请先登录并选择一次运行。",
      "report.noRun": "请先从运行列表选择一次运行。",
      "report.loading": "正在从服务端生成报告…",
      "report.zerodayYes": "是（零日级，已公开）", "report.zerodayRedacted": "是（可选脱敏）",
      "report.no": "否", "report.redactedTitle": "【脱敏】影响已验证（零日级，已公开；未展示细节）",
      "timeline.summary": "步骤 {steps} · 总耗时 {total} · 累计执行 {sum} · 峰值并行度 {par}",
      "empty.dag.title": "这个视图还没有步骤",
      "empty.dag.body": "DAG 来自一次 run 的 steps 表。已有探针/立足点直接回连控制端，或先投放探针并启动 Agent；步骤与三层证据会出现在这里。",
      "empty.dag.action": "inkblade channel listen --host 0.0.0.0 --port 8443",
      "empty.dag.next": "Pod 内探针回连：./inkblade-probe reverse --host <controller-host> --port 8443",
      "empty.chain.title": "还没有攻击链图",
      "empty.chain.body": "图数据来自 graph_nodes / graph_edges。完成探针回连并启动 Agent 后，可达性边会写入本次 run。",
      "empty.chain.action": "inkblade channel listen --host 0.0.0.0 --port 8443",
      "empty.chain.next": "已有探针：inkblade probe list --workspace ./work",
      "empty.timeline.title": "还没有执行时间线",
      "empty.timeline.body": "时间线需要带起止时间的 steps 记录。探针回连并启动 Agent 后自动加载。",
      "empty.timeline.action": "inkblade channel listen --host 0.0.0.0 --port 8443",
      "empty.timeline.next": "Pod 内探针回连：./inkblade-probe reverse --host <controller-host> --port 8443",
      "empty.evidence.title": "还没有证据可浏览",
      "empty.evidence.body": "三层证据（context.jsonl.gz / evidence.db / tar+SHA256 归档）由 run 产生；完成探针回连与一次运行后回到此页。",
      "empty.evidence.action": "inkblade channel listen --host 0.0.0.0 --port 8443",
      "empty.evidence.next": "已有探针：inkblade probe list --workspace ./work",
      "empty.report.title": "还没有发现（findings）",
      "empty.report.body": "报告预览从本次 run 的 findings 读取。",
      "empty.report.action": "inkblade report --run <run-id> --lang bi",
      "empty.report.next": "先接入探针：inkblade probe list --workspace ./work",
      "empty.rules.title": "规则目录为空",
      "empty.rules.body": "规则包由规则引擎生成；本地仓库应自带 Kyverno/PSS/Sigma/Falco/Suricata 规则目录。",
      "empty.rules.action": "python -m inkblade rules generate --help",
      "empty.rules.next": "规则校验：python -m inkblade rules validate <pack>",
      "empty.assets.title": "资产库为空",
      "empty.assets.body": "资产图来自 assets 表（种子 → 增量发现）。真实集群用 discover 或 pilot 建立基线。",
      "empty.assets.action": "inkblade discover --seeds <seeds.json>",
      "empty.assets.next": "资产发现：inkblade discover --seeds <seeds.json>",
      "empty.drift.title": "还没有 drift 报告",
      "empty.drift.body": "drift 由周期重测生成：scheduler 到期跑链子集，与上次 findings 逐键比较。",
      "empty.drift.action": "python -m inkblade schedule list",
      "empty.drift.next": "立即跑到期计划：python -m inkblade schedule run-due",
      "empty.approvals.title": "审批队列为空",
      "empty.approvals.body": "审批制自主探索的提议由 explorer propose 生成；lead 批准后才会执行。",
      "empty.approvals.action": "python -m inkblade explore propose --help",
      "empty.approvals.next": "查看队列：python -m inkblade explore list",
      "empty.schedules.title": "还没有计划任务",
      "empty.schedules.body": "周期重测用 cron/interval 计划驱动；先创建计划，再 run-due 生成 drift。",
      "empty.schedules.action": "python -m inkblade schedule add --help",
      "empty.schedules.next": "查看计划：python -m inkblade schedule list",
      "assets.loading": "资产清单加载中…", "assets.loadFail": "资产清单加载失败（未发现或未登录）。",
      "assets.login": "登录后加载资产清单（api/v1/assets）。",
      "drift.empty": "无漂移数据（周期重测后由 scheduler 生成 drift.json）。",
      "drift.login": "登录后加载差异视图（api/v1/drift）。",
      "drift.fail": "差异数据加载失败（{msg}）；周期重测 run-due 后生成 drift.json，或查看静态导出。",
      "approvals.empty": "审批队列为空（explorer propose 生成提议）。",
      "approvals.login": "登录后加载审批队列（api/v1/explorer）。",
      "schedules.empty": "无周期重测计划（api/v1/scheduler/add 创建）。",
      "schedules.login": "登录后加载计划任务（api/v1/scheduler）。",
    },
    en: {
      "brand.sub": "ML cluster pentest console · 10 views",
      "mode.offline": "Local console",
      "mode.static": "Static export · open without server",
      "mode.service": "Service mode · local",
      "topbar.workspace": "Workspace",
      "lang.switch": "Switch language / 切换语言",
      "login.user": "User", "login.pass": "Password", "login.ws": "Workspace",
      "login.submit": "Sign in", "login.abort": "Abort",
      "login.subtitle": "Authorized operations console for ML clusters",
      "connect.kicker": "CONNECT",
      "connect.title": "Connect",
      "connect.hasRuns": "Runs available · collapsible",
      "connect.noRuns": "No runs yet · probe-first setup",
      "connect.recommended": "Recommended",
      "connect.assumption": "Default foothold: an ordinary, least-privilege Pod (non-root, no hostPath/privileged, no kubeconfig, outbound TCP only).",
      "connect.existing.title": "Existing probe / foothold",
      "connect.existing.body": "An already deployed probe, foothold shell or low-privilege Pod can reverse-connect to the controller; kubeconfig is not required.",
      "connect.existing.step1": "Listen on the controller",
      "connect.existing.step2": "Probe reverse-connect from the Pod",
      "connect.existing.step3": "Confirm the probe is registered",
      "connect.first.title": "First deployment",
      "connect.first.body": "Without an existing probe, enter through a foothold and deploy; the default foothold is an ordinary, least-privilege Pod with outbound TCP only.",
      "connect.first.step1": "Listen on the controller",
      "connect.first.step2": "Create the foothold session",
      "connect.first.step3": "Deploy via RCE",
      "connect.first.sa": "Deploy via SA token (alternative)",
      "connect.first.reverse": "Probe reverse-connect from the Pod",
      "connect.first.confirm": "Confirm the probe is registered",
      "connect.advanced.summary": "kubeconfig bulk deployment (optional)",
      "connect.advanced.body": "Only when you already hold a kubeconfig and need bulk deployment; this is not a prerequisite.",
      "connect.advanced.step1": "kubeconfig session",
      "connect.advanced.step2": "Bulk deployment",
      "connect.advanced.step3": "Confirm the probe is registered",
      "dash.eyebrow": "WORKSPACE OVERVIEW", "dash.workspace": "Workspace",
      "dash.runs": "Runs", "dash.findings": "Recent findings", "dash.chain": "Chain status",
      "dash.loading": "Reading workspace…", "dash.refresh": "Refresh", "dash.run": "Run",
      "dash.role": "Role", "dash.consent": "Authorization", "dash.consentComplete": "Signed",
      "dash.consentPending": "Not signed", "dash.runCount": "Runs", "dash.latest": "Latest run",
      "dash.noRuns": "No runs yet. Refresh after completing the CLI setup.",
      "dash.noWorkspace": "No workspace connected", "dash.loadingRun": "Loading run data…",
      "dash.noRunData": "This run has no step data yet.",
      "dash.findingsTotal": "Total findings", "dash.steps": "Steps", "dash.graph": "Graph nodes",
      "dash.chainEdges": "Chain edges", "dash.chainStatus": "Run status",
      "dash.statusSuccess": "Success", "dash.statusRunning": "Running",
      "dash.statusDegraded": "Degraded", "dash.statusBlocked": "Blocked", "dash.statusPending": "Pending",
      "dash.selectRun": "Select a run to inspect findings and chain status.",
      "dash.runLoadFail": "Failed to load run data: ",
      "dash.refreshing": "Refreshing…", "dash.refreshed": "Refreshed",
      "dash.abortSent": "Emergency stop sent",
      "nav.dag": "Workflow DAG", "nav.chain": "Attack chain", "nav.timeline": "Timeline",
      "nav.evidence": "Evidence", "nav.report": "Report", "nav.rules": "Rules",
      "nav.assets": "Assets", "nav.drift": "Drift", "nav.approvals": "Approvals",
      "nav.schedules": "Schedules",
      "status.pending": "Pending", "status.running": "Running", "status.success": "Success",
      "status.degraded": "Degraded", "status.blocked": "Blocked",
      "dag.sidebar": "Step detail",
      "dag.sidebarHint": "Click a node to inspect prompt/command, environment, result and three-layer evidence pointers.",
      "chain.filter": "Chain filter", "chain.all": "All chains",
      "chain.legend": "Edge colors: red=reachable exploit / orange=high-risk path / dashed yellow=degraded / dashed grey=blocked",
      "timeline.title": "Execution waterfall",
      "evidence.steps": "Run steps", "evidence.threeLayers": "Three-layer evidence",
      "evidence.pickHint": "Select a step to inspect prompt/command, environment, archive hash and context-summary pointer.",
      "evidence.manifest": "Archive manifest.sha256",
      "rules.title": "Rule ↔ attack-chain matrix",
      "rules.hint": "Rows=defense/detection rules (Kyverno·Gatekeeper·NetworkPolicy·PSS·Sigma·Falco·Suricata), columns=attack chains; ●=covered.",
      "assets.title": "Asset graph (incremental inventory)",
      "assets.hint": "Seeds (namespaces/services/kubeconfig snapshot) → core/discovery; modules resolve targets from assets.",
      "drift.title": "Retest drift",
      "drift.hint": "Scheduler re-runs chain subsets and diffs findings: new (red) / fixed (green) / unchanged.",
      "approvals.title": "Approval queue (approval-gated autonomy)",
      "approvals.hint": "LLM optional (OpenAI-compatible env) + rule fallback; dry-run preview per action, lead approval required.",
      "schedules.title": "Schedules (periodic retest)",
      "schedules.hint": "cron/interval schedule → run chain subset when due → drift report.",
      "footer.line": "InkBlade · all assets embedded locally (no CDN) · three evidence layers: context summary / database / archive (tar+SHA256)",
      "common.copy": "Copy", "common.copied": "Copied",
      "common.probe": "Deploy probe", "common.cluster": "Connect cluster",
      "run.staticMeta": "Run {run} · status {status} · steps {steps} · findings {findings}",
      "run.serviceMeta": "Runs in this workspace: {n} ({runs})",
      "run.serviceEmpty": "Signed in; waiting for run data in this workspace.",
      "run.loadFail": "Failed to load runs: ",
      "report.total": "Total findings", "report.steps": "Steps",
      "report.findings": "Findings",
      "report.redact": "Redact zero-day details (optional; public details shown by default)",
      "report.showing": "Rendered {shown} / {total} rows (paged to avoid building {total} DOM rows at once)",
      "report.showMore": "Show more (+{n})",
      "report.legacy": "legacy benchmark mode: render all rows (before/after comparison only)",
      "report.severity": "Severity", "report.titleCol": "Title", "report.step": "Step",
      "report.evidence": "Evidence (archive ref)", "report.zeroday": "Zero-day",
      "report.sectionTitle": "Structural alignment (PTES / NIST SP 800-115 / GB/T 20984 / CVSS 3.1 / ATT&CK·ATLAS)",
      "report.sectionBody": "Preview renders findings and counts only; the report engine produces the full bilingual pentest + remediation + defense rule pack, including combo risk, training-data exposure, code inventory, network threat model and hybrid-cloud boundary.",
      "report.remote": "Server /api/v1/report returned {bytes} bytes; Markdown follows:",
      "report.fallback": "Server report unavailable: {msg}. Sign in and select a run first.",
      "report.noRun": "Select a run from the run list first.",
      "report.loading": "Generating the report on the server…",
      "report.zerodayYes": "Yes (zero-day, public)", "report.zerodayRedacted": "Yes (redacted)",
      "report.no": "No", "report.redactedTitle": "[Redacted] impact verified (zero-day, public; details hidden)",
      "timeline.summary": "Steps {steps} · span {total} · cumulative {sum} · peak parallelism {par}",
      "ops.title": "Operation and file-access ledger",
      "ops.hint": "Per-event commands (argv/cwd/exit/duration/stdout digest) plus files read or written; click a row to jump to the matching step in the evidence browser.",
      "ops.empty": "No file/operation audit events recorded for this run (file_ops empty).",
      "ops.col.time": "Time", "ops.col.subject": "Subject", "ops.col.action": "Action",
      "ops.col.target": "Target", "ops.col.files": "Files", "ops.col.result": "Result",
      "ops.col.hash": "Evidence hash",
      "ops.badge.read": "read", "ops.badge.write": "write", "ops.badge.rw": "rw",
      "ops.badge.list": "list", "ops.badge.exploit": "exploit",
      "ops.jump": "Open evidence",
      "ops.summary": "{total} events · file ops {file} · steps {step} · exploit markers {exploit}",
      "evidence.files": "File access (file_ops)",
      "empty.dag.title": "No steps in this view yet",
      "empty.dag.body": "The DAG comes from a run's steps table. Reverse-connect an existing probe or foothold, or deploy a probe and start the Agent; steps and evidence will appear here.",
      "empty.dag.action": "inkblade channel listen --host 0.0.0.0 --port 8443",
      "empty.dag.next": "Probe reverse-connect from the Pod: ./inkblade-probe reverse --host <controller-host> --port 8443",
      "empty.chain.title": "No attack-chain graph yet",
      "empty.chain.body": "Graph data comes from graph_nodes / graph_edges. After the probe reverse-connects and the Agent runs, reachability edges are written to this run.",
      "empty.chain.action": "inkblade channel listen --host 0.0.0.0 --port 8443",
      "empty.chain.next": "Existing probe: inkblade probe list --workspace ./work",
      "empty.timeline.title": "No execution timeline yet",
      "empty.timeline.body": "The timeline needs steps with start/end times. It loads after the probe reverse-connects and the Agent starts.",
      "empty.timeline.action": "inkblade channel listen --host 0.0.0.0 --port 8443",
      "empty.timeline.next": "Probe reverse-connect from the Pod: ./inkblade-probe reverse --host <controller-host> --port 8443",
      "empty.evidence.title": "No evidence to browse yet",
      "empty.evidence.body": "Three evidence layers (context.jsonl.gz / evidence.db / tar+SHA256 archive) are produced by a run; return after the probe reverse-connects and one run completes.",
      "empty.evidence.action": "inkblade channel listen --host 0.0.0.0 --port 8443",
      "empty.evidence.next": "Existing probe: inkblade probe list --workspace ./work",
      "empty.report.title": "No findings yet",
      "empty.report.body": "Report preview reads findings for this run.",
      "empty.report.action": "inkblade report --run <run-id> --lang bi",
      "empty.report.next": "Connect a probe first: inkblade probe list --workspace ./work",
      "empty.rules.title": "Rule catalog is empty",
      "empty.rules.body": "Rule packs are generated by the rules engine; a local checkout ships Kyverno/PSS/Sigma/Falco/Suricata rules.",
      "empty.rules.action": "python -m inkblade rules generate --help",
      "empty.rules.next": "Validate: python -m inkblade rules validate <pack>",
      "empty.assets.title": "Asset inventory is empty",
      "empty.assets.body": "The asset graph comes from the assets table (seed → incremental discovery). Use discover or pilot for a real-cluster baseline.",
      "empty.assets.action": "inkblade discover --seeds <seeds.json>",
      "empty.assets.next": "Discover: inkblade discover --seeds <seeds.json>",
      "empty.drift.title": "No drift report yet",
      "empty.drift.body": "Drift is produced by periodic retests: scheduler runs chain subsets and diffs findings against the previous run.",
      "empty.drift.action": "python -m inkblade schedule list",
      "empty.drift.next": "Run due schedules: python -m inkblade schedule run-due",
      "empty.approvals.title": "Approval queue is empty",
      "empty.approvals.body": "Approval-gated exploration proposals come from explorer propose; execution only starts after lead approval.",
      "empty.approvals.action": "python -m inkblade explore propose --help",
      "empty.approvals.next": "Inspect queue: python -m inkblade explore list",
      "empty.schedules.title": "No schedules yet",
      "empty.schedules.body": "Periodic retests are driven by cron/interval schedules; create one, then run-due to produce drift.",
      "empty.schedules.action": "python -m inkblade schedule add --help",
      "empty.schedules.next": "List schedules: python -m inkblade schedule list",
      "assets.loading": "Loading asset inventory…", "assets.loadFail": "Failed to load assets (none found or not signed in).",
      "assets.login": "Sign in to load asset inventory (api/v1/assets).",
      "drift.empty": "No drift data (scheduler writes drift.json after a periodic retest).",
      "drift.login": "Sign in to load drift view (api/v1/drift).",
      "drift.fail": "Failed to load drift ({msg}); run scheduler run-due or use a static export.",
      "approvals.empty": "Approval queue is empty (explorer propose creates proposals).",
      "approvals.login": "Sign in to load the approval queue (api/v1/explorer).",
      "schedules.empty": "No schedules (create one via api/v1/scheduler/add).",
      "schedules.login": "Sign in to load schedules (api/v1/scheduler).",
    },
  };

  function t(key, vars) {
    var table = I18N[STATE.lang] || I18N.zh;
    var text = table[key] !== undefined ? table[key] : (I18N.zh[key] !== undefined ? I18N.zh[key] : key);
    if (vars) {
      Object.keys(vars).forEach(function (k) {
        text = text.replace(new RegExp("\\{" + k + "\\}", "g"), String(vars[k]));
      });
    }
    return text;
  }

  function statusLabel(st) { return t("status." + (st || "pending")); }

  function steps() {
    if (STATE.data && STATE.data.steps) return STATE.data.steps;
    return STATE.remoteSteps || [];
  }
  function findings() {
    if (STATE.data && STATE.data.findings) return STATE.data.findings;
    return [];
  }
  function nodes() {
    if (STATE.data && STATE.data.nodes) return STATE.data.nodes;
    return STATE.remoteNodes || [];
  }
  function edges() {
    if (STATE.data && STATE.data.edges) return STATE.data.edges;
    return STATE.remoteEdges || [];
  }
  function stepStatus(s) { return s && STATUS_ZH[s.status] ? s.status : "pending"; }

  function stepFindingCount(s) {
    var summary = (s && (s.result_summary || s.result || "")) || "";
    var m = /(\d+)\s+finding/i.exec(summary);
    return m ? parseInt(m[1], 10) : 0;
  }
  function derivedFindings() {
    var out = [];
    steps().forEach(function (s) {
      var n = stepFindingCount(s);
      if (n > 0) out.push({ step_key: s.step_key, count: n, status: stepStatus(s), summary: s.result_summary || "" });
    });
    return out;
  }
  function totalDerivedFindings() {
    return derivedFindings().reduce(function (a, f) { return a + f.count; }, 0);
  }
  function runStatus() {
    var list = steps();
    if (!list.length) return "pending";
    var order = ["blocked", "running", "degraded", "pending", "success"];
    var seen = {};
    list.forEach(function (s) { seen[stepStatus(s)] = true; });
    for (var i = 0; i < order.length; i++) if (seen[order[i]]) return order[i];
    return "success";
  }
  function selectedRunName() {
    return STATE.selectedRun || (STATE.runs && STATE.runs[0]) || "";
  }

  /* ================= 操作/文件访问台账数据 ================= */

  function timelineDoc() { return (STATE.data && STATE.data.timeline) || STATE.remoteTimeline; }
  function timelineEvents() { return (timelineDoc() && timelineDoc().events) || []; }
  function fileOpsRows() {
    return (STATE.data && STATE.data.file_ops) || STATE.remoteFileOps || [];
  }
  function loadRemoteAudit() {
    if (STATIC_MODE || !STATE.token) return;
    var run = selectedRunName();
    if (!run) return;
    if (STATE.remoteAuditRun === run && (STATE.remoteAuditLoaded || STATE.remoteAuditLoading)) return;
    STATE.remoteAuditRun = run;
    STATE.remoteAuditLoading = true;
    var qs = "?workspace=" + encodeURIComponent(STATE.workspace) + "&run=" + encodeURIComponent(run);
    api("api/v1/timeline" + qs)
      .then(function (body) {
        STATE.remoteTimeline = { events: body.events || [], counts: body.counts || {} };
        return api("api/v1/file-ops" + qs);
      })
      .then(function (body) {
        if (STATE.remoteAuditRun !== run) return;
        STATE.remoteFileOps = body.file_ops || [];
        STATE.remoteAuditLoaded = true;
        STATE.remoteAuditLoading = false;
        renderOpsLedger();
        if (STATE.view === "evidence") renderEvidence();
      })
      .catch(function () { if (STATE.remoteAuditRun === run) STATE.remoteAuditLoading = false; });
  }
  function opsForStep(key) {
    if (!key) return [];
    return fileOpsRows().filter(function (row) { return row.step_key === key; });
  }
  function fmtTs(ts) {
    if (!ts) return "—";
    var d = new Date(ts * 1000);
    var p = function (x) { return (x < 10 ? "0" : "") + x; };
    return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }
  function fileBadges(files) {
    var box = el("div", "ops-files");
    (files || []).forEach(function (f) {
      var mode = f.mode || "read";
      var badge = el("span", "ops-file mode-" + mode);
      badge.appendChild(el("b", null, t("ops.badge." + (mode === "write" ? "write" : (mode === "rw" ? "rw" : "read")))));
      badge.appendChild(document.createTextNode(" " + (f.path || "")));
      if (f.size_bytes) badge.appendChild(el("i", null, " " + f.size_bytes + "B"));
      if (f.sha256) badge.title = f.sha256;
      box.appendChild(badge);
    });
    if (!(files || []).length) box.appendChild(el("span", "hint", "—"));
    return box;
  }

  function renderOpsLedger() {
    var host = document.getElementById("ops-ledger");
    if (!host) return;
    clear(host);
    var events = timelineEvents();
    if (!events.length) {
      host.appendChild(el("div", "hint", t("ops.empty")));
      return;
    }
    var table = el("table", "ops-table");
    var head = el("tr");
    ["time", "subject", "action", "target", "files", "result", "hash"].forEach(function (key) {
      head.appendChild(el("th", null, t("ops.col." + key)));
    });
    table.appendChild(head);
    events.forEach(function (ev) {
      var row = el("tr", "ops-row kind-" + (ev.kind || "action"));
      row.setAttribute("data-step", ev.step_key || "");
      row.setAttribute("data-kind", ev.kind || "");
      row.appendChild(el("td", "ops-ts", fmtTs(ev.ts)));
      row.appendChild(el("td", "ops-subject", ev.subject || "—"));
      row.appendChild(el("td", "ops-action",
        (ev.kind === "exploit" ? t("ops.badge.exploit") + " · " : "") + (ev.action || "—")));
      row.appendChild(el("td", "ops-target", ev.target || "—"));
      var filesCell = el("td");
      filesCell.appendChild(fileBadges(ev.files));
      row.appendChild(filesCell);
      row.appendChild(el("td", "ops-result", ev.result || "—"));
      row.appendChild(el("td", "ops-hash", (ev.evidence_sha256 || "").slice(0, 16) || "—"));
      if (ev.step_key) {
        row.title = t("ops.jump") + ": " + ev.step_key;
        row.addEventListener("click", function () {
          STATE.selectedStep = ev.step_key;
          showView("evidence");
        });
      }
      table.appendChild(row);
    });
    host.appendChild(table);
    var counts = {};
    events.forEach(function (ev) { counts[ev.kind || "action"] = (counts[ev.kind || "action"] || 0) + 1; });
    host.appendChild(el("div", "hint", t("ops.summary", {
      total: events.length, file: counts.file_op || 0, step: counts.step || 0,
      exploit: counts.exploit || 0,
    })));
  }


  /* ================= 引导空态（十个视图统一） ================= */

  var EMPTY_STATES = {
    dag: "01", chain: "02", timeline: "03", evidence: "04", report: "05",
    rules: "06", assets: "07", drift: "08", approvals: "09", schedules: "10",
  };

  function copyText(text, btn) {
    function done() {
      btn.textContent = t("common.copied");
      setTimeout(function () { btn.textContent = t("common.copy"); }, 1400);
    }
    function fallback() {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        done();
      } catch (e) { /* 复制不可用时保留命令文本供手动选择 */ }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(fallback);
    } else {
      fallback();
    }
  }

  function cmdRow(cmd, label) {
    var row = el("div", "cmd-row");
    if (label) row.appendChild(el("span", "hint", label));
    row.appendChild(el("code", null, cmd));
    var btn = el("button", null, t("common.copy"));
    btn.type = "button";
    btn.addEventListener("click", function () { copyText(cmd, btn); });
    row.appendChild(btn);
    return row;
  }

  function emptyState(view, opts) {
    opts = opts || {};
    var box = el("div", "empty-state");
    box.setAttribute("data-empty-state", view);
    box.appendChild(el("div", "empty-state-icon", opts.icon || EMPTY_STATES[view] || "◇"));
    box.appendChild(el("h4", null, opts.title || t("empty." + view + ".title")));
    box.appendChild(el("p", null, opts.body || t("empty." + view + ".body")));
    var actions = el("div", "empty-actions");
    actions.appendChild(cmdRow(t("empty." + view + ".action"), t("common.probe")));
    actions.appendChild(cmdRow("inkblade session open --mode kubeconfig --workspace ./work --kubeconfig ~/.kube/config", t("common.cluster")));
    box.appendChild(actions);
    var next = opts.next || t("empty." + view + ".next");
    if (next) box.appendChild(el("div", "empty-next", next));
    if (opts.extra) box.appendChild(opts.extra);
    return box;
  }

  function applyI18n() {
    document.documentElement.lang = STATE.lang === "zh" ? "zh-CN" : "en";
    document.querySelectorAll("[data-i18n]").forEach(function (n) {
      n.textContent = t(n.getAttribute("data-i18n"));
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(function (n) {
      n.setAttribute("placeholder", t(n.getAttribute("data-i18n-placeholder")));
    });
    var toggle = document.getElementById("lang-toggle");
    if (toggle) {
      toggle.textContent = STATE.lang === "zh" ? "EN" : "中文";
      toggle.title = t("lang.switch");
      toggle.setAttribute("aria-label", t("lang.switch"));
    }
    var modePill = document.getElementById("mode-pill");
    if (modePill) modePill.textContent = t(STATIC_MODE ? "mode.static" : "mode.service");
  }

  function setLang(lang, persist) {
    STATE.lang = lang === "en" ? "en" : "zh";
    if (persist !== false) {
      try { localStorage.setItem("inkblade-lang", STATE.lang); } catch (e) { /* file:// 隐私模式 */ }
    }
    applyI18n();
    renderCurrent();
    renderDashboard();
    renderRunMeta();
  }

  function bindLang() {
    var saved = null;
    try { saved = localStorage.getItem("inkblade-lang"); } catch (e) { /* ignore */ }
    STATE.lang = saved === "en" ? "en" : "zh";
    var toggle = document.getElementById("lang-toggle");
    if (toggle) {
      toggle.addEventListener("click", function () {
        setLang(STATE.lang === "zh" ? "en" : "zh", true);
      });
    }
    applyI18n();
  }


  /* ================= 导航 ================= */

  function bindNav() {
    var btns = document.querySelectorAll("nav#views button");
    btns.forEach(function (b) {
      b.addEventListener("click", function () { showView(b.getAttribute("data-view")); });
    });
  }
  function showView(v) {
    if (VIEW_IDS.indexOf(v) < 0) return;
    STATE.view = v;
    document.querySelectorAll("nav#views button").forEach(function (b) {
      b.classList.toggle("active", b.getAttribute("data-view") === v);
    });
    document.querySelectorAll("section.view").forEach(function (s) {
      s.classList.toggle("active", s.id === "view-" + v);
    });
    renderCurrent();
  }
  function renderCurrent() {
    if (!isAuthed()) return;
    switch (STATE.view) {
      case "dag": renderDag(); break;
      case "chain": renderChain(); break;
      case "timeline": renderTimeline(); break;
      case "evidence": renderEvidence(); break;
      case "report": renderReport(); break;
      case "rules": renderRules(); break;
      case "assets": renderAssets(); break;
      case "drift": renderDrift(); break;
      case "approvals": renderApprovals(); break;
      case "schedules": renderSchedules(); break;
    }
  }
  function renderAll() {
    if (!isAuthed()) return;
    renderCurrent();
    renderRunMeta();
    renderDashboard();
  }

  /* ================= 登录 / 工作区 / 运行数据 ================= */

  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (STATE.token) opts.headers["Authorization"] = "Bearer " + STATE.token;
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok) {
          var err = new Error((body && body.error) || ("HTTP " + r.status));
          err.status = r.status;
          throw err;
        }
        return body;
      });
    });
  }

  function isAuthed() { return STATIC_MODE || !!STATE.token; }

  function showApp() {
    document.body.classList.add("authed");
    var dashboard = document.getElementById("dashboard");
    if (dashboard) dashboard.hidden = false;
    var abort = document.getElementById("btn-abort");
    if (abort) abort.hidden = STATIC_MODE;
  }

  function showOnboarding() {
    document.body.classList.remove("authed");
    var dashboard = document.getElementById("dashboard");
    if (dashboard) dashboard.hidden = true;
  }

  function metric(label, value, cls) {
    var box = el("div", "metric");
    box.appendChild(el("div", "value " + (cls || ""), String(value)));
    box.appendChild(el("div", "label", label));
    return box;
  }

  function populateWorkspaceSelect() {
    var sel = document.getElementById("ws-select");
    if (!sel) return;
    clear(sel);
    var list = STATE.workspaces.length ? STATE.workspaces : (STATE.workspace ? [STATE.workspace] : []);
    if (!list.length) {
      sel.appendChild(el("option", null, t("dash.noWorkspace"))).value = "";
      sel.disabled = true;
      return;
    }
    list.forEach(function (ws) {
      var o = el("option", null, ws);
      o.value = ws;
      sel.appendChild(o);
    });
    sel.value = STATE.workspace;
    sel.disabled = false;
  }

  function showLoginError(message) {
    var box = document.getElementById("login-error");
    if (!box) return;
    box.textContent = message || "";
    box.hidden = !message;
  }

  function bindCopyCommands() {
    document.querySelectorAll(".copy-cmd").forEach(function (btn) {
      btn.addEventListener("click", function () {
        copyText(btn.getAttribute("data-copy") || "", btn);
      });
    });
  }

  function bindSession() {
    var form = document.getElementById("login-form");
    var abort = document.getElementById("btn-abort");
    if (abort) {
      abort.addEventListener("click", function () {
        if (!isAuthed()) return;
        api("api/abort", { method: "POST" })
          .then(function () {
            abort.textContent = t("dash.abortSent");
            setTimeout(function () { abort.textContent = t("login.abort"); }, 1800);
          })
          .catch(function () {});
      });
    }
    var refresh = document.getElementById("btn-refresh");
    if (refresh) {
      refresh.addEventListener("click", function () {
        if (STATIC_MODE) { renderAll(); return; }
        refresh.textContent = t("dash.refreshing");
        loadRuns().then(function () { refresh.textContent = t("dash.refreshed"); });
        setTimeout(function () { refresh.textContent = t("dash.refresh"); }, 1200);
      });
    }
    var runSel = document.getElementById("run-select");
    if (runSel) runSel.addEventListener("change", function () { selectRun(runSel.value); });
    var wsSel = document.getElementById("ws-select");
    if (wsSel) wsSel.addEventListener("change", function () { switchWorkspace(wsSel.value); });
    bindCopyCommands();
    if (STATIC_MODE) {
      document.getElementById("mode-pill").textContent = t("mode.static");
      document.getElementById("mode-pill").classList.add("static");
      initStaticMode();
      return;
    }
    document.getElementById("mode-pill").textContent = t("mode.service");
    showOnboarding();
    var wsInput = document.getElementById("in-ws");
    if (wsInput) {
      try {
        var asked = new URLSearchParams(window.location.search).get("workspace") ||
          localStorage.getItem("inkblade-ws");
        if (asked) wsInput.value = asked;
      } catch (e) { /* file:// 或隐私模式 */ }
    }
    if (form) {
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        login();
      });
    }
  }

  function login() {
    var name = document.getElementById("in-user").value.trim();
    var pass = document.getElementById("in-pass").value;
    var ws = document.getElementById("in-ws").value.trim() || "local-lab";
    var btn = document.getElementById("btn-login");
    showLoginError("");
    if (btn) { btn.disabled = true; btn.textContent = t("dash.loading"); }
    api("api/login", { method: "POST", body: JSON.stringify({ name: name, password: pass }) })
      .then(function (body) {
        STATE.token = body.token;
        STATE.role = body.role || "";
        STATE.user = name;
        STATE.workspace = ws;
        STATE.selectedRun = "";
        try { localStorage.setItem("inkblade-ws", ws); } catch (e) { /* 隐私模式 */ }
        var pill = document.getElementById("session-pill");
        pill.hidden = false;
        pill.classList.add("ok");
        pill.textContent = name + " · " + STATE.role + " · " + STATE.workspace;
        showApp();
        populateWorkspaceSelect();
        loadWorkspaces();
        loadConsent();
        return loadRuns();
      })
      .catch(function (e) {
        showLoginError(e.status === 401 ? "用户名或密码不正确" : e.message);
        var pill = document.getElementById("session-pill");
        pill.hidden = false;
        pill.classList.remove("ok");
        pill.textContent = "登录失败：" + e.message;
      })
      .then(function () {
        if (btn) { btn.disabled = false; btn.textContent = t("login.submit"); }
      });
  }

  function switchWorkspace(ws) {
    if (!ws || ws === STATE.workspace) return;
    STATE.workspace = ws;
    STATE.selectedRun = "";
    STATE.runs = [];
    STATE.remoteSteps = null; STATE.remoteNodes = null; STATE.remoteEdges = null;
    STATE.remoteGraph = null; STATE.remoteEvidence = null; STATE.remoteReport = null;
    STATE.remoteTimeline = null; STATE.remoteFileOps = null;
    STATE.remoteAuditLoaded = false; STATE.remoteAuditRun = "";
    var pill = document.getElementById("session-pill");
    if (pill) pill.textContent = (STATE.user || "") + " · " + (STATE.role || "") + " · " + STATE.workspace;
    loadConsent();
    loadRuns();
  }

  function loadWorkspaces() {
    return api("api/v1/workspaces?workspace=" + encodeURIComponent(STATE.workspace))
      .then(function (body) {
        STATE.workspaces = body.workspaces || [STATE.workspace];
        populateWorkspaceSelect();
      })
      .catch(function () {
        STATE.workspaces = [STATE.workspace];
        populateWorkspaceSelect();
      });
  }

  function loadConsent() {
    if (STATIC_MODE) {
      STATE.consent = { status: "static", fields: {} };
      renderDashboard();
      return Promise.resolve();
    }
    return api("api/v1/consent?workspace=" + encodeURIComponent(STATE.workspace))
      .then(function (body) { STATE.consent = body; renderDashboard(); })
      .catch(function () { STATE.consent = { status: "unknown", fields: {} }; renderDashboard(); });
  }

  function loadRuns() {
    if (STATIC_MODE) {
      var run = (STATE.data && STATE.data.run) || {};
      STATE.runs = run.name ? [run.name] : [];
      STATE.selectedRun = run.name || "";
      renderDashboard();
      renderRunMeta();
      return Promise.resolve();
    }
    return api("api/runs?workspace=" + encodeURIComponent(STATE.workspace))
      .then(function (body) {
        STATE.runs = (body.runs || []).slice().reverse();
        renderDashboard();
        var run = STATE.selectedRun && STATE.runs.indexOf(STATE.selectedRun) >= 0
          ? STATE.selectedRun : (STATE.runs[0] || "");
        if (run) return selectRun(run);
        STATE.selectedRun = "";
        clearRunData();
        renderAll();
      })
      .catch(function (e) {
        var pill = document.getElementById("session-pill");
        if (pill) pill.textContent = t("run.loadFail") + e.message;
        renderDashboard();
      });
  }

  function clearRunData() {
    STATE.remoteSteps = null; STATE.remoteNodes = null; STATE.remoteEdges = null;
    STATE.remoteGraph = null; STATE.remoteEvidence = null; STATE.remoteManifestVerified = null;
    STATE.remoteTimeline = null; STATE.remoteFileOps = null; STATE.remoteReport = null;
    STATE.remoteAuditLoaded = false; STATE.remoteAuditRun = "";
    STATE.selectedStep = null;
  }

  function safeApi(path) {
    return api(path).then(
      function (body) { return { ok: true, body: body }; },
      function (err) { return { ok: false, error: err.message || "HTTP error" }; }
    );
  }

  function selectRun(run) {
    if (!run) return Promise.resolve();
    STATE.selectedRun = run;
    if (STATIC_MODE) { renderAll(); return Promise.resolve(); }
    STATE.runGen += 1;
    var gen = STATE.runGen;
    STATE.runLoading = true;
    STATE.runError = "";
    clearRunData();
    renderDashboard();
    renderRunMeta();
    renderCurrent();
    var qs = "?workspace=" + encodeURIComponent(STATE.workspace) + "&run=" + encodeURIComponent(run);
    return Promise.all([
      safeApi("api/v1/steps" + qs),
      safeApi("api/v1/graph" + qs),
      safeApi("api/v1/timeline" + qs),
      safeApi("api/v1/file-ops" + qs),
      safeApi("api/v1/evidence" + qs),
    ]).then(function (results) {
      if (gen !== STATE.runGen) return;
      var stepsRes = results[0], graphRes = results[1], timelineRes = results[2],
        opsRes = results[3], evidenceRes = results[4];
      STATE.runLoading = false;
      if (stepsRes.ok) STATE.remoteSteps = stepsRes.body.steps || [];
      else STATE.runError = stepsRes.error;
      if (graphRes.ok) {
        STATE.remoteGraph = graphRes.body;
        STATE.remoteNodes = graphRes.body.nodes || [];
        STATE.remoteEdges = graphRes.body.edges || [];
      }
      if (timelineRes.ok) STATE.remoteTimeline = { events: timelineRes.body.events || [], counts: timelineRes.body.counts || {} };
      if (opsRes.ok) STATE.remoteFileOps = opsRes.body.file_ops || [];
      if (evidenceRes.ok) {
        STATE.remoteEvidence = evidenceRes.body.evidence || [];
        STATE.remoteManifestVerified = evidenceRes.body.manifest_verified;
      }
      STATE.remoteAuditLoaded = true;
      STATE.remoteAuditRun = run;
      renderAll();
    });
  }

  function syncRunSelect() {
    var sel = document.getElementById("run-select");
    if (!sel) return;
    clear(sel);
    if (!STATE.runs.length) {
      sel.appendChild(el("option", null, t("dash.noRuns"))).value = "";
      sel.disabled = true;
      return;
    }
    STATE.runs.forEach(function (run) {
      var o = el("option", null, run);
      o.value = run;
      sel.appendChild(o);
    });
    sel.value = selectedRunName();
    sel.disabled = false;
  }

  function renderRunMeta() {
    if (STATIC_MODE) {
      var d = STATE.data;
      var host = document.getElementById("tl-summary");
      if (host) {
        host.textContent = t("run.staticMeta", {
          run: (d.run && d.run.name) || "—", status: (d.run && d.run.status) || "—",
          steps: (d.steps || []).length, findings: (d.findings || []).length,
        });
      }
      return;
    }
    var meta = document.getElementById("tl-summary");
    if (meta) {
      meta.textContent = STATE.runs.length
        ? t("run.serviceMeta", { n: STATE.runs.length, runs: STATE.runs.join(", ") })
        : t("run.serviceEmpty");
    }
  }

  /* ================= 接入面板（探针优先） ================= */

  function connectPath(titleKey, bodyKey, rows, badgeKey) {
    var card = el("section", "connect-path" + (badgeKey ? " primary" : ""));
    var head = el("div", "connect-path-head");
    if (badgeKey) head.appendChild(el("span", "path-badge", t(badgeKey)));
    head.appendChild(el("h4", null, t(titleKey)));
    card.appendChild(head);
    card.appendChild(el("p", "connect-copy", t(bodyKey)));
    rows.forEach(function (row) {
      card.appendChild(cmdRow(row[0], t(row[1])));
    });
    return card;
  }

  function buildConnectPanel(hasRuns) {
    var panel = document.createElement("details");
    panel.id = "connect-panel";
    panel.className = "connect-panel";
    var summary = document.createElement("summary");
    summary.className = "connect-summary";
    var main = el("div", "connect-summary-main");
    main.appendChild(el("span", "card-kicker", t("connect.kicker")));
    main.appendChild(el("span", "connect-title", t("connect.title")));
    main.appendChild(el("span", "connect-state",
      hasRuns ? t("connect.hasRuns") : t("connect.noRuns")));
    summary.appendChild(main);
    summary.appendChild(el("span", "chev", "▾"));
    panel.appendChild(summary);

    var body = el("div", "connect-body");
    body.appendChild(el("p", "connect-assumption", t("connect.assumption")));
    var grid = el("div", "connect-grid");

    grid.appendChild(connectPath("connect.existing.title", "connect.existing.body", [
      ["inkblade channel listen --host 0.0.0.0 --port 8443", "connect.existing.step1"],
      ["./inkblade-probe reverse --host <controller-host> --port 8443", "connect.existing.step2"],
      ["inkblade probe list --workspace ./work", "connect.existing.step3"],
    ], "connect.recommended"));

    grid.appendChild(connectPath("connect.first.title", "connect.first.body", [
      ["inkblade channel listen --host 0.0.0.0 --port 8443", "connect.first.step1"],
      ["inkblade session open --mode foothold --target <target> --pod <pod>",
        "connect.first.step2"],
      ["inkblade probe deploy --session <id> --via rce --binary ./inkblade-probe-linux-amd64",
        "connect.first.step3"],
      ["inkblade probe deploy --session <id> --via sa-token --binary ./inkblade-probe-linux-amd64",
        "connect.first.sa"],
      ["./inkblade-probe reverse --host <controller-host> --port 8443",
        "connect.first.reverse"],
      ["inkblade probe list --workspace ./work", "connect.first.confirm"],
    ]));

    body.appendChild(grid);

    var advanced = document.createElement("details");
    advanced.className = "connect-advanced";
    var advSummary = document.createElement("summary");
    advSummary.textContent = t("connect.advanced.summary");
    advanced.appendChild(advSummary);
    advanced.appendChild(el("p", "connect-copy", t("connect.advanced.body")));
    [
      ["inkblade session open --mode kubeconfig --workspace ./work --kubeconfig ~/.kube/config",
        "connect.advanced.step1"],
      ["inkblade probe deploy --session <session-id> --via kubectl --binary ./inkblade-probe-linux-amd64",
        "connect.advanced.step2"],
      ["inkblade probe list --workspace ./work", "connect.advanced.step3"],
    ].forEach(function (row) {
      advanced.appendChild(cmdRow(row[0], t(row[1])));
    });
    body.appendChild(advanced);
    panel.appendChild(body);
    return panel;
  }

  function renderConnectPanel() {
    var host = document.getElementById("post-auth-panel");
    if (!host) return;
    var hasRuns = STATE.runs.length > 0;
    var previous = document.getElementById("connect-panel");
    if (previous && STATE.connectUserToggled) {
      STATE.connectOpen = previous.open;
    }
    clear(host);
    var panel = buildConnectPanel(hasRuns);
    host.appendChild(panel);
    var desired;
    if (!hasRuns) desired = true;
    else if (!STATE.connectInit) desired = false;
    else if (STATE.connectUserToggled) desired = !!STATE.connectOpen;
    else desired = false;
    STATE.connectInit = true;
    panel.open = desired;
    panel.addEventListener("toggle", function () {
      if (panel.open !== desired) {
        STATE.connectUserToggled = true;
        STATE.connectOpen = panel.open;
      }
    });
  }

  /* ================= 工作区总览 ================= */

  function renderDashboard() {
    if (!isAuthed()) return;
    var title = document.getElementById("dash-title");
    if (title) title.textContent = STATE.workspace || t("dash.noWorkspace");
    var sub = document.getElementById("dash-subtitle");
    if (sub) {
      if (STATIC_MODE) {
        var r = (STATE.data && STATE.data.run) || {};
        sub.textContent = t("run.staticMeta", {
          run: r.name || "—", status: r.status || "—",
          steps: (STATE.data && STATE.data.steps || []).length,
          findings: (STATE.data && STATE.data.findings || []).length,
        });
      } else if (STATE.runLoading) {
        sub.textContent = t("dash.loadingRun");
      } else if (STATE.runs.length) {
        sub.textContent = STATE.workspace + " · " + t("run.serviceMeta", {
          n: STATE.runs.length, runs: STATE.runs[0],
        });
      } else {
        sub.textContent = t("dash.noRuns");
      }
    }
    syncRunSelect();
    renderConnectPanel();
    renderDashWorkspace();
    renderDashRuns();
    renderDashFindings();
    renderDashChain();
    renderRunMeta();
  }

  function renderDashWorkspace() {
    var host = document.getElementById("dash-workspace");
    if (!host) return;
    clear(host);
    var grid = el("div", "metric-grid");
    var consent = STATE.consent || {};
    var cstatus = consent.status || "unknown";
    var consentText = cstatus === "complete" ? t("dash.consentComplete")
      : (cstatus === "static" ? "—" : t("dash.consentPending"));
    grid.appendChild(metric(t("dash.role"), STATE.role || (STATIC_MODE ? "static" : "—"), "dim"));
    grid.appendChild(metric(t("dash.consent"), consentText,
      cstatus === "complete" ? "ok" : (cstatus === "unknown" || cstatus === "static" ? "dim" : "warn")));
    grid.appendChild(metric(t("dash.runCount"), STATE.runs.length, "dim"));
    grid.appendChild(metric(t("dash.latest"), selectedRunName() || "—", "dim"));
    host.appendChild(grid);
    var extra = el("div", "dash-empty");
    extra.style.marginTop = "11px";
    extra.textContent = STATIC_MODE
      ? "静态导出：证据与图数据来自内嵌快照。"
      : (consent.status === "complete"
        ? "授权记录已签署，执行路径按 RoE 范围放行。"
        : "授权未完成：执行类 API 在执行前返回 423。");
    host.appendChild(extra);
  }

  function renderDashRuns() {
    var host = document.getElementById("dash-runs");
    if (!host) return;
    clear(host);
    if (!STATE.runs.length) {
      host.appendChild(el("div", "dash-empty", t("dash.noRuns")));
      return;
    }
    STATE.runs.forEach(function (run) {
      var btn = el("button", "run-item" + (run === STATE.selectedRun ? " active" : ""));
      btn.type = "button";
      btn.appendChild(el("span", "run-name", run));
      btn.appendChild(el("span", "run-state", run === STATE.selectedRun ? "ACTIVE" : "SELECT"));
      btn.addEventListener("click", function () { selectRun(run); });
      host.appendChild(btn);
    });
  }

  function renderDashFindings() {
    var host = document.getElementById("dash-findings");
    if (!host) return;
    clear(host);
    if (STATE.runLoading) {
      host.appendChild(el("div", "dash-empty", t("dash.loadingRun")));
      return;
    }
    if (STATE.runError) {
      host.appendChild(el("div", "dash-empty", t("dash.runLoadFail") + STATE.runError));
      return;
    }
    var list = [];
    if (STATIC_MODE) {
      list = findings().slice(0, 6).map(function (f) {
        return {
          title: f.title || f.step_key || "—",
          meta: (f.severity || "info") + " · " + (f.step_key || ""),
          sev: String(f.severity || "info").toLowerCase(),
        };
      });
    } else {
      list = derivedFindings().slice(0, 6).map(function (f) {
        return {
          title: f.step_key,
          meta: f.count + " finding(s) · " + f.status,
          sev: f.status === "blocked" ? "blocked" : (f.status === "degraded" ? "degraded" : "info"),
        };
      });
    }
    if (!list.length) {
      host.appendChild(el("div", "dash-empty",
        STATE.selectedRun ? t("dash.noRunData") : t("dash.selectRun")));
      return;
    }
    var box = el("div", "dash-list");
    list.forEach(function (f) {
      var row = el("div", "dash-list-item");
      row.appendChild(el("span", "dot " + (f.sev === "critical" || f.sev === "high" || f.sev === "blocked"
        ? "blocked" : (f.sev === "degraded" ? "degraded" : ""))));
      var body = el("div", "body");
      body.appendChild(el("div", "title", f.title));
      body.appendChild(el("div", "meta", f.meta));
      row.appendChild(body);
      box.appendChild(row);
    });
    host.appendChild(box);
  }

  function renderDashChain() {
    var host = document.getElementById("dash-chain");
    if (!host) return;
    clear(host);
    var list = steps();
    var ns = nodes(), es = edges();
    if (!list.length && !ns.length) {
      host.appendChild(el("div", "dash-empty", STATE.selectedRun ? t("dash.noRunData") : t("dash.selectRun")));
      return;
    }
    var status = runStatus();
    var head = el("div", "dash-list-item");
    head.appendChild(el("span", "dot " + (status === "blocked" ? "blocked" : (status === "degraded" ? "degraded" : ""))));
    var body = el("div", "body");
    body.appendChild(el("div", "title",
      t("dash.chainStatus") + " · " + (t("dash.status" + status.charAt(0).toUpperCase() + status.slice(1)) || status)));
    body.appendChild(el("div", "meta", selectedRunName() || "—"));
    head.appendChild(body);
    host.appendChild(head);
    var grid = el("div", "metric-grid");
    grid.style.marginTop = "10px";
    grid.appendChild(metric(t("dash.steps"), list.length, "dim"));
    grid.appendChild(metric(t("dash.findingsTotal"), totalDerivedFindings(), totalDerivedFindings() ? "warn" : "dim"));
    grid.appendChild(metric(t("dash.graph"), ns.length, "dim"));
    grid.appendChild(metric(t("dash.chainEdges"), es.length, "dim"));
    host.appendChild(grid);
  }

  function initStaticMode() {
    var run = (STATE.data && STATE.data.run) || {};
    STATE.workspace = run.workspace || "static-export";
    STATE.user = "static";
    STATE.role = "read-only";
    STATE.runs = run.name ? [run.name] : [];
    STATE.selectedRun = run.name || "";
    STATE.workspaces = [STATE.workspace];
    STATE.consent = { status: "static", fields: {} };
    showApp();
    populateWorkspaceSelect();
    renderDashboard();
    renderAll();
  }

  /* ================= ① 工作流 DAG ================= */

  var dagRoot = null;

  function renderDag() {
    var host = document.getElementById("dag-canvas");
    var list = steps();
    clear(host);
    if (STATE.runLoading) {
      host.appendChild(el("div", "dag-empty", t("dash.loadingRun")));
      return;
    }
    if (!list.length) {
      host.appendChild(emptyState("dag", { icon: "01" }));
      return;
    }
    var RF = window.ReactFlowCore;
    if (RF && window.React && window.ReactDOM) {
      renderReactFlow(host, list, RF);
    } else {
      new DagCanvas(host, list, selectStep); // 自绘兜底
    }
  }

  /* --- React Flow 渲染（vendor UMD，全局 ReactFlowCore）--- */
  function rfStepNode(props) {
    var e = React.createElement;
    var d = props.data || {};
    var st = d.status || "pending";
    return e("div", { className: "rf-step-node st-" + st },
      e("div", { className: "rf-step-title" }, d.label),
      e("div", { className: "rf-step-status" }, statusLabel(st)),
      e(window.ReactFlowCore.Handle, { type: "target", position: window.ReactFlowCore.Position.Left }),
      e(window.ReactFlowCore.Handle, { type: "source", position: window.ReactFlowCore.Position.Right }));
  }

  function renderReactFlow(host, list, RF) {
    var e = React.createElement;
    var nodeTypes = { step: rfStepNode };
    var rfNodes = list.map(function (s, i) {
      return {
        id: s.step_key,
        type: "step",
        position: { x: 30 + (i % 4) * 230, y: 30 + Math.floor(i / 4) * 115 },
        data: { label: s.step_key, status: stepStatus(s) },
      };
    });
    var rfEdges = [];
    for (var i = 1; i < list.length; i++) {
      rfEdges.push({
        id: "e" + i,
        source: list[i - 1].step_key,
        target: list[i].step_key,
        animated: stepStatus(list[i]) === "running",
      });
    }
    if (!dagRoot) dagRoot = ReactDOM.createRoot(host);
    dagRoot.render(e(RF.ReactFlow, {
      nodes: rfNodes,
      edges: rfEdges,
      nodeTypes: nodeTypes,
      fitView: true,
      minZoom: 0.2,
      onNodeClick: function (_ev, node) { selectStep(node.id); },
    }));
  }

  /* --- 自绘 SVG DAG 兜底（无 React Flow 时）--- */
  function DagCanvas(host, list, onClick) {
    var W = Math.max(760, 240 * Math.min(4, list.length) + 60);
    var H = Math.max(300, 130 * Math.ceil(list.length / 4) + 40);
    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, class: "dag-svg" });
    var defs = svgEl("defs");
    var marker = svgEl("marker", {
      id: "dag-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5,
      markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse",
    });
    marker.appendChild(svgEl("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "#94a3b8" }));
    defs.appendChild(marker);
    svg.appendChild(defs);

    var NW = 180, NH = 46, GX = 230, GY = 120;
    var pos = list.map(function (s, i) {
      return {
        x: 30 + (i % 4) * GX,
        y: 26 + Math.floor(i / 4) * GY,
      };
    });
    for (var i = 1; i < list.length; i++) {
      var a = pos[i - 1], b = pos[i];
      var running = stepStatus(list[i]) === "running";
      if (Math.abs(a.y - b.y) < 10) {
        svg.appendChild(svgEl("path", {
          d: "M " + (a.x + NW) + " " + (a.y + NH / 2) + " L " + b.x + " " + (b.y + NH / 2),
          class: "dag-edge" + (running ? " running" : ""),
          "marker-end": "url(#dag-arrow)",
        }));
      } else {
        var mx = (a.x + NW + b.x) / 2;
        svg.appendChild(svgEl("path", {
          d: "M " + (a.x + NW / 2) + " " + (a.y + NH) +
             " C " + (a.x + NW / 2) + " " + (a.y + NH + 40) + ", " + (b.x + NW / 2) + " " + (b.y - 40) + ", " +
             (b.x + NW / 2) + " " + b.y,
          class: "dag-edge" + (running ? " running" : ""),
        }));
      }
    }
    list.forEach(function (s, i) {
      var p = pos[i], st = stepStatus(s);
      var g = svgEl("g", { class: "dag-node " + st, "data-step": s.step_key });
      g.appendChild(svgEl("rect", { x: p.x, y: p.y, width: NW, height: NH, rx: 8, ry: 8 }));
      var title = svgEl("text", { x: p.x + NW / 2, y: p.y + 19, "text-anchor": "middle" });
      title.textContent = s.step_key.length > 26 ? s.step_key.slice(0, 25) + "…" : s.step_key;
      var stz = svgEl("text", { x: p.x + NW / 2, y: p.y + 36, "text-anchor": "middle" });
      stz.textContent = statusLabel(st);
      g.appendChild(title); g.appendChild(stz);
      g.addEventListener("click", function () { onClick(s.step_key); });
      g.style.cursor = "pointer";
      svg.appendChild(g);
    });
    host.appendChild(svg);
  }

  /* --- 侧栏步骤详情 --- */
  function selectStep(stepKey) {
    STATE.selectedStep = stepKey;
    var side = document.getElementById("dag-sidebar");
    clear(side);
    var s = null;
    steps().forEach(function (x) { if (x.step_key === stepKey) s = x; });
    if (!s) return;
    side.appendChild(el("h3", null, "步骤详情"));
    var head = el("div", "panel");
    head.appendChild(el("div", null, "")).className = "hint";
    head.textContent = "";
    clear(head);
    head.appendChild(el("div", null, s.step_key)).style.fontWeight = "700";
    head.appendChild(el("div", null, "")).className = "badge st-" + stepStatus(s);
    head.lastChild.textContent = statusLabel(stepStatus(s));
    side.appendChild(head);

    var p = el("div", "panel");
    p.appendChild(el("h3", null, "Prompt / 命令"));
    var prompts = s.prompts || [];
    if (!prompts.length) p.appendChild(el("div", "hint", "（无记录）"));
    prompts.forEach(function (pr) {
      var box = el("div");
      box.appendChild(el("div", "hint", "[" + (pr.kind || "cmd") + "]"));
      var code = el("code", null, pr.content || "");
      box.appendChild(code);
      p.appendChild(box);
    });
    side.appendChild(p);

    var env = el("div", "panel");
    env.appendChild(el("h3", null, "环境"));
    var keys = Object.keys(s.env || {});
    if (!keys.length) env.appendChild(el("div", "hint", "（无）"));
    keys.forEach(function (k) {
      var row = el("div", null, k + " = ");
      row.appendChild(el("code", null, s.env[k]));
      env.appendChild(row);
    });
    side.appendChild(env);

    var res = el("div", "panel");
    res.appendChild(el("h3", null, "结果摘要"));
    res.appendChild(el("div", "hint", s.result_summary || "（无）"));
    res.appendChild(el("h3", null, "三层证据指针"));
    var archive = el("div", null, "归档：");
    archive.appendChild(el("code", null, s.archive || "—"));
    res.appendChild(archive);
    var evs = s.evidence || [];
    evs.forEach(function (ev) {
      var hrow = el("div", null, "SHA256：");
      hrow.appendChild(el("code", null, ev.sha256 || "—"));
      res.appendChild(hrow);
    });
    res.appendChild(el("div", "hint", "上下文摘要层：context.jsonl.gz（压缩，LLM 可重载）"));
    side.appendChild(res);
  }

  /* ================= ② 攻击链图 ================= */

  var KIND_ORDER = ["pod", "sa", "service", "volume", "node", "cloud"];
  var VERDICT_CLASS = function (v) {
    v = String(v || "").toLowerCase();
    if (v.indexOf("不可达") >= 0 || v.indexOf("unreachable") >= 0 || v.indexOf("blocked") >= 0) return "v-blocked";
    if (v.indexOf("降级") >= 0 || v.indexOf("degraded") >= 0) return "v-degraded";
    if (v.indexOf("critical") >= 0 || v.indexOf("严重") >= 0) return "v-critical";
    if (v.indexOf("可达") >= 0 || v.indexOf("reachable") >= 0 || v.indexOf("probed") >= 0) return "v-high";
    return "v-high";
  };

  function renderChain() {
    var host = document.getElementById("chain-canvas");
    var filter = document.getElementById("chain-filter");
    var ns = nodes(), es = edges();
    clear(host);
    if (!ns.length && !es.length) {
      host.appendChild(emptyState("chain", { icon: "②" }));
      return;
    }
    // 链过滤选项
    var chains = {};
    es.forEach(function (e2) { if (e2.chain) chains[e2.chain] = true; });
    var cur = filter.value || "*";
    clear(filter);
    filter.appendChild(el("option", null, t("chain.all"))).value = "*";
    Object.keys(chains).forEach(function (c) {
      var o = el("option", null, c);
      o.value = c;
      filter.appendChild(o);
    });
    filter.value = Object.keys(chains).indexOf(cur) >= 0 ? cur : "*";
    filter.onchange = function () { renderChain(); };

    var shown = es.filter(function (e2) { return filter.value === "*" || e2.chain === filter.value; });

    // 列布局：按 kind 分列（未知 kind 追加）
    var cols = KIND_ORDER.slice();
    ns.forEach(function (n) { if (cols.indexOf(n.kind) < 0) cols.push(n.kind); });
    var colIndex = {};
    cols.forEach(function (k, i) { colIndex[k] = i; });

    var CW = 190, CH = 64, GAPX = 60, PADX = 30, PADY = 30;
    var perCol = Math.max(1, Math.ceil(ns.length / Math.max(1, cols.length)) || 1);
    var positions = {};
    var colCount = {};
    ns.forEach(function (n) {
      var ci = colIndex[n.kind] !== undefined ? colIndex[n.kind] : cols.length - 1;
      var ri = colCount[ci] || 0;
      colCount[ci] = ri + 1;
      positions[n.node_id] = { x: PADX + ci * (CW + GAPX), y: PADY + ri * (CH + 26), col: ci };
    });
    var W = PADX * 2 + cols.length * (CW + GAPX);
    var H = PADY * 2 + Math.max(1, perCol) * (CH + 26);

    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, class: "chain-svg",
      width: Math.max(760, W), height: H });

    // 边（利用路径，严重度着色）
    shown.forEach(function (e2) {
      var a = positions[e2.src], b = positions[e2.dst];
      if (!a || !b) return;
      var x1 = a.x + CW, y1 = a.y + CH / 2, x2 = b.x, y2 = b.y + CH / 2;
      var mx = (x1 + x2) / 2;
      var path = svgEl("path", {
        d: "M " + x1 + " " + y1 + " C " + mx + " " + y1 + ", " + mx + " " + y2 + ", " + x2 + " " + y2,
        class: "chain-edge " + VERDICT_CLASS(e2.verdict),
      });
      var title = svgEl("title");
      title.textContent = (e2.chain || "（未命名链）") + " · " + (e2.verdict || "") +
        (e2.method ? " · 判定:" + e2.method : "");
      path.appendChild(title);
      svg.appendChild(path);
      var mid = svgEl("text", {
        x: mx, y: (y1 + y2) / 2 - 6, "text-anchor": "middle", class: "edge-label",
      });
      mid.textContent = e2.verdict || "";
      svg.appendChild(mid);
    });

    // 节点（资产）
    ns.forEach(function (n) {
      var p = positions[n.node_id];
      var g = svgEl("g");
      g.appendChild(svgEl("rect", {
        x: p.x, y: p.y, width: CW, height: CH, rx: 10, ry: 10, class: "asset-box",
      }));
      var label = svgEl("text", { x: p.x + 12, y: p.y + 24, class: "asset-label" });
      label.textContent = n.node_id.length > 24 ? n.node_id.slice(0, 23) + "…" : n.node_id;
      var kind = svgEl("text", { x: p.x + 12, y: p.y + 42, class: "asset-kind" });
      kind.textContent = (n.kind || "?") + (n.layer ? " · " + n.layer : "");
      var t = svgEl("title");
      t.textContent = n.node_id + "\n" + (n.attrs || "");
      g.appendChild(label); g.appendChild(kind); g.appendChild(t);
      svg.appendChild(g);
    });

    host.appendChild(svg);

    // 链成立状态标记
    var legend = el("div", "legend");
    Object.keys(chains).forEach(function (c) {
      var hit = es.some(function (e2) { return e2.chain === c && VERDICT_CLASS(e2.verdict) !== "v-blocked"; });
      var s = el("span");
      s.appendChild(el("i"));
      s.firstChild.style.background = hit ? "var(--status-degraded)" : "var(--status-pending)";
      s.appendChild(document.createTextNode((hit ? "成立" : "不成立") + " · " + c));
      legend.appendChild(s);
    });
    host.appendChild(legend);
  }

  /* ================= ③ 执行时间线 ================= */

  function renderTimeline() {
    var body = document.getElementById("timeline-body");
    loadRemoteAudit();
    clear(body);
    var list = steps();
    if (!list.length) {
      body.appendChild(emptyState("timeline", { icon: "③" }));
      renderOpsLedger();
      return;
    }
    var rows = list.map(function (s) {
      return {
        key: s.step_key, st: stepStatus(s),
        start: s.started_at || 0, end: s.finished_at || s.started_at || 0,
      };
    }).sort(function (a, b) { return a.start - b.start; });
    var t0 = Infinity, t1 = -Infinity;
    rows.forEach(function (r) {
      if (r.start) t0 = Math.min(t0, r.start);
      if (r.end) t1 = Math.max(t1, r.end);
    });
    if (!isFinite(t0) || t1 <= t0) { t0 = 0; t1 = 1; }

    var axis = el("div", "tl-axis");
    axis.appendChild(el("div", null, t("report.step")));
    var marks = el("div", "marks");
    marks.appendChild(el("span", null, fmtTime(t0)));
    marks.appendChild(el("span", null, fmtTime((t0 + t1) / 2)));
    marks.appendChild(el("span", null, fmtTime(t1)));
    axis.appendChild(marks);
    axis.appendChild(el("div", null, STATE.lang === "zh" ? "耗时" : "Duration"));
    body.appendChild(axis);

    var maxPar = 1;
    rows.forEach(function (r, i) {
      var row = el("div", "tl-row");
      var name = el("div", "tl-name");
      name.textContent = (i + 1) + ". " + r.key;
      row.appendChild(name);
      var track = el("div", "tl-track");
      var bar = el("div", "tl-bar st-" + r.st);
      var left = ((r.start - t0) / (t1 - t0)) * 100;
      var width = Math.max(0.5, ((r.end - r.start) / (t1 - t0)) * 100);
      bar.style.left = left + "%";
      bar.style.width = width + "%";
      bar.title = fmtTime(r.start) + " → " + fmtTime(r.end) + " · " + statusLabel(r.st);
      track.appendChild(bar);
      row.appendChild(track);
      row.appendChild(el("div", "tl-dur", (r.end && r.start) ? fmtDur((r.end - r.start) * 1000) : "—"));
      body.appendChild(row);
    });

    // 并行度：按 100ms 桶粗估
    var buckets = {};
    rows.forEach(function (r) {
      for (var t = r.start; t < r.end; t += 0.1) {
        var k = Math.round(t * 10);
        buckets[k] = (buckets[k] || 0) + 1;
        maxPar = Math.max(maxPar, buckets[k]);
      }
    });
    var sum = rows.reduce(function (a, r) { return a + Math.max(0, (r.end - r.start)); }, 0);
    body.appendChild(el("div", "hint", t("timeline.summary", {
      steps: rows.length, total: fmtDur((t1 - t0) * 1000),
      sum: fmtDur(sum * 1000), par: maxPar,
    })));
    renderOpsLedger();
  }

  /* ================= ④ 证据浏览器 ================= */

  function renderEvidence() {
    var list = document.getElementById("ev-steps");
    var detail = document.getElementById("ev-detail");
    var manifest = document.getElementById("ev-manifest");
    loadRemoteAudit();
    clear(list); clear(detail);
    var st = steps();
    if (STATE.runLoading) {
      list.appendChild(el("div", "hint", t("dash.loadingRun")));
      detail.appendChild(el("h3", null, t("evidence.threeLayers")));
      detail.appendChild(el("div", "hint", "（—）"));
    } else if (!st.length) {
      list.appendChild(emptyState("evidence", { icon: "④" }));
      detail.appendChild(el("h3", null, t("evidence.threeLayers")));
      detail.appendChild(el("div", "hint", "（—）"));
    } else {
      st.forEach(function (s) {
        var card = el("div", "ev-step" + (STATE.selectedStep === s.step_key ? " selected" : ""));
        var head = el("div");
        head.appendChild(el("span", "badge st-" + stepStatus(s), statusLabel(stepStatus(s))));
        head.appendChild(document.createTextNode(" " + s.step_key));
        card.appendChild(head);
        var evs = s.evidence || [];
        evs.forEach(function (ev) {
          var h = el("div", "hash");
          h.textContent = (ev.sha256 || "").slice(0, 16) + "… " + (ev.path || "");
          card.appendChild(h);
        });
        card.addEventListener("click", function () {
          STATE.selectedStep = s.step_key;
          renderEvidence();
        });
        list.appendChild(card);
      });
      renderStepDetail(detail, STATE.selectedStep || st[0].step_key);
    }
    // 归档清单
    if (STATE.data && STATE.data.manifest) {
      manifest.textContent = STATE.data.manifest;
    } else if (STATE.remoteManifestVerified === true) {
      var rows = [];
      steps().forEach(function (s) {
        (s.evidence || []).forEach(function (ev) {
          if (ev.sha256) rows.push((ev.sha256 + "  " + (ev.path || "")).trim());
        });
      });
      manifest.textContent = "manifest.sha256 · 已验证（/api/v1/evidence）" +
        (rows.length ? "\n" + rows.join("\n") : "");
    } else if (STATE.remoteManifestVerified === false) {
      manifest.textContent = "manifest.sha256 · 验证未通过：请检查运行归档。";
    } else {
      manifest.textContent = "该运行未返回 manifest.sha256（或尚未产生归档）。";
    }
  }

  function renderStepDetail(host, stepKey) {
    clear(host);
    host.appendChild(el("h3", null, "三层证据 · " + stepKey));
    var s = null;
    steps().forEach(function (x) { if (x.step_key === stepKey) s = x; });
    if (!s) { host.appendChild(el("div", "hint", "（未找到）")); return; }

    var tbl = el("table", "kv");
    function kv(k, vNode) {
      var tr = el("tr");
      tr.appendChild(el("td", null, k));
      var td = el("td");
      td.appendChild(vNode);
      tr.appendChild(td);
      tbl.appendChild(tr);
    }
    kv("状态", el("span", "badge st-" + stepStatus(s), statusLabel(stepStatus(s))));
    var promptDiv = el("div");
    (s.prompts || []).forEach(function (pr) {
      var b = el("div");
      b.appendChild(el("div", "hint", "[" + (pr.kind || "cmd") + "]"));
      b.appendChild(el("code", null, pr.content || ""));
      promptDiv.appendChild(b);
    });
    if (!(s.prompts || []).length) promptDiv.appendChild(el("span", "hint", "（无）"));
    kv("Prompt/命令", promptDiv);
    var envDiv = el("div");
    var ek = Object.keys(s.env || {});
    if (!ek.length) envDiv.appendChild(el("span", "hint", "（无）"));
    ek.forEach(function (k) {
      var r = el("div");
      r.textContent = k + " = ";
      r.appendChild(el("code", null, s.env[k]));
      envDiv.appendChild(r);
    });
    kv("环境", envDiv);
    var opsDiv = el("div", "ops-detail");
    var ops = opsForStep(stepKey);
    if (!ops.length) opsDiv.appendChild(el("span", "hint", t("ops.empty")));
    ops.forEach(function (row) {
      var line = el("div", "ops-detail-row");
      line.appendChild(el("span", "badge ops-op", row.op || "exec"));
      line.appendChild(el("code", null, (row.argv || []).join(" ") || row.path || "—"));
      if (row.cwd) line.appendChild(el("span", "hint", " cwd=" + row.cwd));
      if (row.exit_code !== undefined && row.exit_code !== null) {
        line.appendChild(el("span", "hint", " exit=" + row.exit_code));
      }
      if (row.duration_ms) line.appendChild(el("span", "hint", " " + row.duration_ms + "ms"));
      (row.opened_files || []).forEach(function (f) {
        var badge = el("span", "ops-file mode-" + (f.mode || "read"),
          (f.mode || "read") + " " + (f.path || ""));
        if (f.sha256) badge.title = f.sha256;
        line.appendChild(badge);
      });
      opsDiv.appendChild(line);
    });
    kv(t("evidence.files"), opsDiv);
    kv("结果摘要", el("span", null, s.result_summary || "（无）"));
    var archDiv = el("div");
    archDiv.appendChild(el("code", null, s.archive || "—"));
    kv("归档层（tar+压缩）", archDiv);
    var shaDiv = el("div");
    (s.evidence || []).forEach(function (ev) {
      var r = el("div");
      r.appendChild(el("code", null, ev.sha256 || "—"));
      r.appendChild(el("span", "hint", "  " + (ev.kind || "") + " " + (ev.path || "")));
      shaDiv.appendChild(r);
    });
    if (!(s.evidence || []).length) shaDiv.appendChild(el("span", "hint", "（无）"));
    kv("归档 SHA256", shaDiv);
    kv("上下文摘要层", el("span", "hint", "context.jsonl.gz（压缩 · LLM 可重载）"));
    kv("数据库层", el("span", "hint", "evidence.db · steps/prompts/env/findings/evidence 表（行 " + (s.id != null ? "#" + s.id : "?") + "）"));
    host.appendChild(tbl);
  }

  /* ================= ⑤ 报告预览 ================= */

  /* 10k findings 实测：一次性建 10k 行 DOM 会阻塞主线程数百毫秒。
   * 默认按 200 行/页渐进渲染；`?perf=legacy` 保留全量渲染，仅用于优化前后
   * 对照（docs/UI-PERF.md 的基准口径），不影响普通用户路径。 */
  var REPORT_PAGE_SIZE = 200;
  var reportVisible = REPORT_PAGE_SIZE;
  var LEGACY_PERF = !!window.__INKBLADE_FORCE_LEGACY ||
    /(?:^|[?&])perf=legacy(?:&|$)/.test(window.location.search);

  function renderReport() {
    var host = document.getElementById("report-body");
    clear(host);
    if (STATIC_MODE) { renderReportData(host); return; }
    var run = selectedRunName();
    if (!STATE.token || !run) {
      host.appendChild(emptyState("report", { icon: "05", body: t("report.noRun") }));
      return;
    }
    if (STATE.runLoading) {
      host.appendChild(el("div", "panel hint", t("dash.loadingRun")));
      return;
    }
    host.appendChild(el("div", "panel hint", t("report.loading")));
    var qs = "?workspace=" + encodeURIComponent(STATE.workspace) +
      "&run=" + encodeURIComponent(run) + "&kind=pentest&lang=bi&redact=" +
      (STATE.redactZeroday ? "1" : "0");
    api("api/v1/report" + qs)
      .then(function (body) {
        if (selectedRunName() !== run) return;
        STATE.remoteReport = body;
        clear(host);
        renderRemoteReport(host, body);
      })
      .catch(function (e) {
        clear(host);
        var panel = el("div", "panel");
        panel.appendChild(el("div", "hint", t("report.fallback", { msg: e.message })));
        panel.appendChild(emptyState("report", { icon: "05" }));
        host.appendChild(panel);
      });
  }

  function reportStatCard(num, label, color) {
    var c = el("div", "rep-card");
    var n = el("div", "num", String(num));
    if (color) n.style.color = color;
    c.appendChild(n);
    c.appendChild(el("div", "lbl", label));
    return c;
  }

  function renderRemoteReport(host, body) {
    var cards = el("div", "rep-cards");
    cards.appendChild(reportStatCard(totalDerivedFindings(), t("report.total")));
    cards.appendChild(reportStatCard(steps().length, t("report.steps")));
    cards.appendChild(reportStatCard(body.bytes || 0, "BYTES", "var(--text-dim)"));
    cards.appendChild(reportStatCard(statusLabel(runStatus()), t("dash.chainStatus"), "var(--accent)"));
    host.appendChild(cards);

    var panel = el("div", "panel");
    var bar = el("div", "report-toolbar");
    bar.appendChild(el("h3", null, t("report.findings") + " · " + (body.run || selectedRunName())));
    var toggle = el("label", "hint");
    var cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = !!STATE.redactZeroday;
    cb.addEventListener("change", function () {
      STATE.redactZeroday = cb.checked;
      renderReport();
    });
    toggle.appendChild(cb);
    toggle.appendChild(document.createTextNode(" " + t("report.redact")));
    bar.appendChild(toggle);
    panel.appendChild(bar);
    var message = el("div", "hint report-progress",
      t("report.remote", { bytes: body.bytes || (body.markdown || "").length }));
    panel.appendChild(message);
    if (body.markdown) {
      var pre = el("pre", "report-doc");
      pre.textContent = body.markdown;
      panel.appendChild(pre);
    } else {
      panel.appendChild(emptyState("report", { icon: "05" }));
    }
    host.appendChild(panel);
  }

  function renderReportData(host) {
    var startedAt = (window.performance && performance.now) ? performance.now() : Date.now();
    var fs = findings();
    var total = fs.length;
    var cards = el("div", "rep-cards");
    function card(num, lbl, color) {
      var c = el("div", "rep-card");
      var n = el("div", "num", String(num));
      if (color) n.style.color = color;
      c.appendChild(n);
      c.appendChild(el("div", "lbl", lbl));
      return c;
    }
    var bySev = {};
    fs.forEach(function (f) { var s = (f.severity || "info").toLowerCase(); bySev[s] = (bySev[s] || 0) + 1; });
    cards.appendChild(card(total, t("report.total")));
    SEV_ORDER.forEach(function (s) {
      cards.appendChild(card(bySev[s] || 0, s.toUpperCase(), "var(--sev-" + s + ")"));
    });
    cards.appendChild(card(steps().length, t("report.steps")));
    host.appendChild(cards);

    var panel = el("div", "panel");
    panel.appendChild(el("h3", null, t("report.findings")));
    // 可选脱敏开关：默认关闭（零日级漏洞模块已公开，细节正常展示）；供未来真私有发现使用。
    var toggle = el("label", "hint");
    var cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = !!STATE.redactZeroday;
    cb.addEventListener("change", function () {
      STATE.redactZeroday = cb.checked;
      renderReport();
    });
    toggle.appendChild(cb);
    toggle.appendChild(document.createTextNode(" " + t("report.redact")));
    panel.appendChild(toggle);

    if (!total) {
      panel.appendChild(emptyState("report", { icon: "⑤" }));
    } else {
      var limit = LEGACY_PERF ? total : Math.min(reportVisible, total);
      var visibleFindings = LEGACY_PERF ? fs : fs.slice(0, limit);
      panel.appendChild(el("div", "hint report-progress", t("report.showing", {
        shown: visibleFindings.length, total: total,
      })));
      if (LEGACY_PERF) panel.appendChild(el("div", "hint", t("report.legacy")));

      var tbl = el("table", "data");
      tbl.setAttribute("data-rendered-rows", String(visibleFindings.length));
      var thead = el("thead");
      var htr = el("tr");
      [t("report.severity"), t("report.titleCol"), t("report.step"),
       t("report.evidence"), t("report.zeroday")].forEach(function (h) {
        htr.appendChild(el("th", null, h));
      });
      thead.appendChild(htr); tbl.appendChild(thead);
      var tbody = el("tbody");
      var fragment = document.createDocumentFragment();
      visibleFindings.forEach(function (f) {
        var tr = el("tr");
        var sev = (f.severity || "info").toLowerCase();
        tr.appendChild(el("td")).appendChild(el("span", "badge sev-" + (SEV_ORDER.indexOf(sev) >= 0 ? sev : "info"), sev.toUpperCase()));
        // 默认展示全部细节；勾选可选脱敏后仅对 is_zeroday 发现隐藏细节（保留证据哈希引用）。
        var redact = !!STATE.redactZeroday && !!f.is_zeroday;
        var titleTd = el("td");
        titleTd.textContent = redact ? t("report.redactedTitle") : (f.title || "");
        if (!redact && f.detail) {
          titleTd.appendChild(el("div", "hint", f.detail));
        }
        if (redact && f.evidence_path) {
          titleTd.appendChild(el("div", "hint", "evidence: " + f.evidence_path));
        }
        tr.appendChild(titleTd);
        tr.appendChild(el("td", null, f.step_key || ""));
        tr.appendChild(el("td")).appendChild(el("code", null, f.evidence_path || "—"));
        tr.appendChild(el("td", null, f.is_zeroday
          ? (redact ? t("report.zerodayRedacted") : t("report.zerodayYes"))
          : t("report.no")));
        fragment.appendChild(tr);
      });
      tbody.appendChild(fragment);
      tbl.appendChild(tbody);
      panel.appendChild(tbl);
      if (!LEGACY_PERF && visibleFindings.length < total) {
        var more = el("button", "report-more", t("report.showMore", {
          n: Math.min(REPORT_PAGE_SIZE, total - visibleFindings.length),
        }));
        more.type = "button";
        more.addEventListener("click", function () {
          reportVisible += REPORT_PAGE_SIZE;
          clear(host);
          renderReportData(host);
        });
        panel.appendChild(more);
      }
    }
    host.appendChild(panel);

    var sec = el("div", "panel rep-section");
    sec.appendChild(el("h4", null, t("report.sectionTitle")));
    sec.appendChild(el("div", "hint", t("report.sectionBody")));
    host.appendChild(sec);

    // 基准与自动化测试可读的渲染元数据（不含发现内容）。
    var endedAt = (window.performance && performance.now) ? performance.now() : Date.now();
    window.__INKBLADE_REPORT_META = {
      total: total,
      renderedRows: (document.querySelectorAll("#report-body tbody tr") || []).length,
      pageSize: REPORT_PAGE_SIZE,
      legacy: LEGACY_PERF,
      renderMs: Math.round((endedAt - startedAt) * 100) / 100,
    };
  }

  /* ================= ⑥ 规则视图（规则↔链映射矩阵） ================= */

  var CHAIN_CATALOG = [
    ["flat-network-admin-plane-weight-poison", "平网→管理面→权重投毒"],
    ["ray-dashboard-cluster-control", "Ray Dashboard→集群控制"],
    ["nccl-gradient-injection", "NCCL→梯度注入"],
    ["shared-pvc-supply-chain-poison", "共享PVC+模型加载→供应链投毒"],
    ["ssrf-sa-token-cloud-metadata", "SSRF/SA Token→云元数据"],
    ["observability-precision-strike", "观测面→精准打点"],
    ["pickle-channel-unauth-exec", "pickle通道→未授权执行"],
    ["cloud-role-weight-bucket", "云角色→权重桶"],
    ["ib-rdma-collective-injection", "IB/RDMA平面→集合通信注入"],
    ["pd-kv-channel-manipulation", "预填充-解码KV通道→推理操纵"],
    ["gpu-operator-host-escape", "GPU与网络Operator→宿主逃逸"],
    ["vpc-cni-dual-plane-mismatch", "VPC-CNI双控制面错配→云内横向"],
    ["imex-computedomain-gpu-memory", "IMEX/ComputeDomain→跨节点GPU内存越权"],
    ["agent-platform-zeroprep-lateral", "智能体平台零前置执行→训练集群横向"],
  ];
  var CHAIN_ZH = {};
  CHAIN_CATALOG.forEach(function (p) { CHAIN_ZH[p[0]] = p[1]; });
  function chainZh(id) { return CHAIN_ZH[id] || id; }

  var RULE_CATALOG = [
    ["deny-privileged-pods", "Kyverno/PSS", "禁 privileged/hostPID/hostIPC/敏感 hostPath（restricted 基线 + GPU 例外通道）",
      ["gpu-operator-host-escape", "ray-dashboard-cluster-control"]],
    ["restrict-rbac-creation", "Kyverno/Gatekeeper", "限制 roles/rolebindings 创建扩散（create RoleBinding 告警/阻断）",
      ["ray-dashboard-cluster-control", "gpu-operator-host-escape"]],
    ["block-automount-sa-token", "Kyverno", "禁 automountServiceAccountToken + operator SA 约束",
      ["ray-dashboard-cluster-control", "ssrf-sa-token-cloud-metadata"]],
    ["default-deny-netpol", "NetworkPolicy(per-CNI)", "默认拒绝入出站 + 按域放行（管理端口仅网段可达；RDMA/SR-IOV 需 IB Partition 补充）",
      ["flat-network-admin-plane-weight-poison", "nccl-gradient-injection", "pickle-channel-unauth-exec", "ib-rdma-collective-injection", "agent-platform-zeroprep-lateral"]],
    ["mgmt-port-ingress-restrict", "NetworkPolicy/安全组", "推理引擎管理端口（30000 等）仅运维网段可达",
      ["flat-network-admin-plane-weight-poison", "pickle-channel-unauth-exec", "pd-kv-channel-manipulation"]],
    ["image-combo-admission", "Kyverno(组合签名)", "镜像/端口组合准入（权重写端点 + 补丁栈镜像共存拦截）",
      ["flat-network-admin-plane-weight-poison", "shared-pvc-supply-chain-poison"]],
    ["rwx-volume-guard", "NetworkPolicy/Kyverno", "共享 RWX 卷写面收敛 + 跨租户挂载限制",
      ["shared-pvc-supply-chain-poison"]],
    ["sigma-rolebinding-cluster-admin", "Sigma", "创建指向 cluster-admin 的 RoleBinding（K8s 审计日志）",
      ["ray-dashboard-cluster-control"]],
    ["sigma-ray-job-submit", "Sigma", "Ray 作业提交（8265）异常主体",
      ["ray-dashboard-cluster-control"]],
    ["sigma-secret-anomalous-read", "Sigma", "异常主体读取 Secret / 云凭据枚举",
      ["agent-platform-zeroprep-lateral", "cloud-role-weight-bucket"]],
    ["falco-weight-file-write", "Falco", "权重文件被非训练进程打开写",
      ["flat-network-admin-plane-weight-poison", "shared-pvc-supply-chain-poison"]],
    ["falco-pickle-deserialization", "Falco", "pickle/torch.load 反序列化调用（容器内）",
      ["pickle-channel-unauth-exec"]],
    ["falco-nccl-socket-join", "Falco", "NCCL socket 异常入组",
      ["nccl-gradient-injection", "ib-rdma-collective-injection"]],
    ["suricata-mgmt-endpoint-paths", "Suricata", "无鉴权管理端点访问特征（/pull_weights /set_env /create_engine /fetch_weights /awex）",
      ["flat-network-admin-plane-weight-poison", "pickle-channel-unauth-exec"]],
    ["suricata-imds-egress", "Suricata", "云元数据出网探测（IMDS）",
      ["ssrf-sa-token-cloud-metadata", "cloud-role-weight-bucket"]],
    ["suricata-kv-transport-ports", "Suricata", "NCCL TCPStore / NIXL·Mooncake KV 传输异常端口与跨域流量",
      ["nccl-gradient-injection", "pd-kv-channel-manipulation"]],
    ["ib-partition-isolation", "IB Partition/SM（建议）", "IB 无 Partition 平面收敛（声明 NetworkPolicy 不覆盖）",
      ["ib-rdma-collective-injection"]],
  ];

  function renderRules() {
    var host = document.getElementById("rules-body");
    clear(host);
    if (!RULE_CATALOG.length) {
      host.appendChild(emptyState("rules", { icon: "⑥" }));
      return;
    }
    // 列 = 数据中出现的链 ∪ 目录链（数据优先排序）
    var dataChains = [];
    edges().forEach(function (e2) {
      if (e2.chain && dataChains.indexOf(e2.chain) < 0) dataChains.push(e2.chain);
    });
    var cols = dataChains.slice();
    CHAIN_CATALOG.forEach(function (p) { if (cols.indexOf(p[0]) < 0) cols.push(p[0]); });

    var wrap = el("div", "matrix-wrap");
    var tbl = el("table", "matrix");
    var thead = el("thead");
    var htr = el("tr");
    htr.appendChild(el("th", null, "规则（机器键）"));
    htr.appendChild(el("th", null, "类型"));
    htr.appendChild(el("th", null, "说明"));
    cols.forEach(function (c) {
      var th = el("th", "rot");
      th.textContent = chainZh(c);
      th.title = c;
      htr.appendChild(th);
    });
    htr.appendChild(el("th", null, "紫队验证"));
    thead.appendChild(htr);
    tbl.appendChild(thead);

    var tbody = el("tbody");
    RULE_CATALOG.forEach(function (r) {
      var tr = el("tr");
      var ktd = el("td");
      ktd.appendChild(el("code", null, r[0]));
      tr.appendChild(ktd);
      tr.appendChild(el("td", null, r[1]));
      tr.appendChild(el("td", null, r[2]));
      var covered = 0;
      cols.forEach(function (c) {
        var hit = r[3].indexOf(c) >= 0;
        if (hit) covered++;
        tr.appendChild(el("td", hit ? "hit" : "miss", hit ? "●" : ""));
      });
      tr.appendChild(el("td", "miss", "未验证")); // 紫队验证结果由规则引擎回填
      tr.title = "覆盖列数 " + covered;
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    wrap.appendChild(tbl);
    host.appendChild(wrap);

    var note = el("div", "hint");
    note.textContent = "当前数据命中链：" + (dataChains.length ? dataChains.map(chainZh).join("、") : "（无 —— 展示全目录）") +
      "。规则包由规则转化引擎导出（defense bundle = 规则文件 + 映射矩阵 + 紫队验证报告），零日规则为行为化签名（不含利用细节）。";
    host.appendChild(note);
  }

  /* ================= ⑦ 资产图 / 差异 / 审批队列 / 计划任务（XBow 对标，服务模式 api/v1，静态模式内嵌） ================= */

  function assetsData() { return (STATE.data && STATE.data.assets) || { nodes: [], edges: [] }; }
  function driftData() { return (STATE.data && STATE.data.drift) || null; }
  function approvalsData() { return (STATE.data && STATE.data.proposals) || []; }
  function schedulesData() { return (STATE.data && STATE.data.schedules) || []; }

  function ensureSection(id) {
    var host = document.getElementById(id);
    if (!host) return null;
    clear(host);
    return host;
  }

  function renderAssets() {
    var body = ensureSection("assets-body");
    if (!body) return;
    var render = function (data, opts) {
      opts = opts || {};
      var g = data.graph || data || { nodes: [], edges: [] };
      var allNodes = g.nodes || [];
      if (!allNodes.length) {
        body.appendChild(emptyState("assets", { icon: "⑦" }));
        return;
      }
      var wrap = el("div", "chain-controls");
      wrap.appendChild(el("span", "hint",
        "资产 " + allNodes.length + " · 关系 " + (g.edges || []).length + " · 来源：core/discovery（assets 表，种子→增量）"));
      if (!STATIC_MODE && STATE.token) {
        var kindSel = el("select", "filter");
        [["", "全部类型"], ["namespace", "命名空间"], ["service", "服务"],
         ["kubeconfig", "kubeconfig"], ["other", "其他"]].forEach(function (kv) {
          var o = el("option", null, kv[1]); o.value = kv[0]; kindSel.appendChild(o);
        });
        kindSel.value = opts.kind || "";
        kindSel.onchange = function () { load(kindSel.value); };
        wrap.appendChild(kindSel);
        var prodIn = el("input", "filter");
        prodIn.placeholder = "产品过滤（如 sglang）";
        prodIn.value = opts.product || "";
        prodIn.onchange = function () { load(kindSel.value, prodIn.value.trim()); };
        wrap.appendChild(prodIn);
      }
      body.appendChild(wrap);
      /* 复用攻击链图的分层画法：namespace → service，产品着色，缺失资产灰显 */
      var ns = allNodes.filter(function (n) { return n.kind === "namespace"; });
      var svc = allNodes.filter(function (n) { return n.kind !== "namespace"; });
      var cols = ["namespace"].concat(["service", "kubeconfig", "other"]);
      var colIndex = {};
      cols.forEach(function (k, i) { colIndex[k] = i; });
      var W = Math.max(320, cols.length * 240), H = Math.max(180, (ns.length + svc.length + 2) * 46);
      var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, class: "chain-svg" });
      var colX = function (i) { return 40 + i * 240; };
      var pos = {};
      ns.forEach(function (n, i) { pos[n.id] = { x: colX(0), y: 30 + i * 46 }; });
      svc.forEach(function (n, i) { pos[n.id] = { x: colX(colIndex[n.kind] || 1), y: 30 + i * 46 }; });
      (g.edges || []).forEach(function (e2) {
        var a = pos[e2.src], b = pos[e2.dst];
        if (!a || !b) return;
        svg.appendChild(svgEl("line", { x1: a.x + 130, y1: a.y, x2: b.x, y2: b.y, class: "v-blocked" }));
      });
      g.nodes.forEach(function (n) {
        var p = pos[n.id];
        if (!p) return;
        var g2 = svgEl("g", {});
        g2.appendChild(svgEl("rect", { x: p.x, y: p.y - 14, width: 130, height: 30, rx: 6,
          class: n.missing ? "node-ns node-missing" : "node-ns" }));
        var label = n.label + (n.product ? " · " + n.product : "");
        g2.appendChild(svgEl("text", { x: p.x + 8, y: p.y + 6, "font-size": 11 }, label.slice(0, 24)));
        g2.title = n.id + (n.addr ? " " + n.addr + (n.port ? ":" + n.port : "") : "");
        svg.appendChild(g2);
      });
      body.appendChild(svg);
      var tbl = el("table", "rules-matrix");
      tbl.appendChild((function () {
        var h = el("tr");
        ["资产键", "类型", "产品", "命名空间", "地址", "状态"].forEach(function (t) { h.appendChild(el("th", null, t)); });
        return h;
      })());
      allNodes.forEach(function (n) {
        var tr = el("tr");
        [n.id, n.kind, n.product || "—", n.namespace || "—",
         (n.addr ? n.addr + (n.port ? ":" + n.port : "") : "—"),
         n.missing ? "缺失" : "在册"].forEach(function (v, i) {
           tr.appendChild(el(i === 0 ? "td" : "td", i === 0 ? "k" : null, String(v)));
         });
        tbl.appendChild(tr);
      });
      body.appendChild(tbl);
    };
    var load = function (kind, product) {
      var qs = "api/v1/assets?workspace=" + encodeURIComponent(STATE.workspace);
      if (kind) qs += "&kind=" + encodeURIComponent(kind);
      if (product) qs += "&product=" + encodeURIComponent(product);
      return api(qs).then(function (data) {
        clear(body);
        render(data, { kind: kind, product: product });
      }).catch(function () {
        clear(body);
        body.appendChild(emptyState("assets", { icon: "⑦" }));
      });
    };
    if (STATIC_MODE || STATE.data) return render(assetsData(), {});
    if (!STATE.token) { body.appendChild(emptyState("assets", { icon: "⑦" })); return; }
    load("");
  }

  function renderDrift() {
    var body = ensureSection("drift-body");
    if (!body) return;
    var render = function (d) {
      if (!d) { body.appendChild(emptyState("drift", { icon: "⑧" })); return; }
      var c = (d.counts) || {};
      var cards = el("div", "sev-cards");
      [["新增", c.new || 0, "critical"], ["已修复", c.fixed || 0, "success-ish"], ["未变", c.unchanged || 0, "info"]].forEach(function (x) {
        var card = el("div", "sev-card " + x[2]);
        card.appendChild(el("div", "num", String(x[1])));
        card.appendChild(el("div", "lbl", x[0]));
        cards.appendChild(card);
      });
      body.appendChild(cards);
      [["新增发现", d.new || [], "v-reachable"], ["已修复", d.fixed || [], "v-degraded"]].forEach(function (grp) {
        var h = el("h3", null, grp[0] + "（" + grp[1].length + "）");
        body.appendChild(h);
        var tbl = el("table", "rules-matrix");
        var hr = el("tr"); ["模块", "标题", "严重度"].forEach(function (t) { hr.appendChild(el("th", null, t)); });
        tbl.appendChild(hr);
        grp[1].forEach(function (f) {
          var tr = el("tr");
          tr.appendChild(el("td", "k", f.step_key || ""));
          tr.appendChild(el("td", null, f.title || ""));
          tr.appendChild(el("td", null, f.severity || ""));
          tbl.appendChild(tr);
        });
        body.appendChild(tbl);
      });
    };
    if (STATIC_MODE || STATE.data) return render(driftData());
    if (!STATE.token) { body.appendChild(emptyState("drift", { icon: "⑧" })); return; }
    var qs = "api/v1/drift?workspace=" + encodeURIComponent(STATE.workspace);
    if (STATE.selectedRun) qs += "&run=" + encodeURIComponent(STATE.selectedRun);
    api(qs).then(function (body2) { render(body2.drift || body2); })
      .catch(function (e) {
        body.appendChild(el("div", "hint", t("drift.fail", { msg: e.message })));
      });
  }

  var APPROVAL_ZH = {
    "pending_approval": "待审批", "approved": "已批准", "rejected": "已拒绝", "executed": "已执行",
  };

  function renderApprovals() {
    var body = ensureSection("approvals-body");
    if (!body) return;
    var render = function (list) {
      if (!list.length) { body.appendChild(emptyState("approvals", { icon: "⑨" })); return; }
      var tbl = el("table", "rules-matrix");
      var hr = el("tr"); ["提议", "模式", "动作序列", "写面", "状态", "创建者"].forEach(function (t) { hr.appendChild(el("th", null, t)); });
      tbl.appendChild(hr);
      list.forEach(function (p) {
        var tr = el("tr");
        tr.appendChild(el("td", "k", p.id || ""));
        tr.appendChild(el("td", null, p.mode === "llm" ? "LLM" : "规则"));
        var acts = (p.actions || []).map(function (a) { return (a.seq || "") + "." + (a.module || ""); }).join(" → ");
        tr.appendChild(el("td", null, acts));
        tr.appendChild(el("td", null, (p.actions || []).some(function (a) { return a.writes; }) ? "含写类（备份闸门）" : "只读"));
        tr.appendChild(el("td", p.status === "executed" ? "hit" : (p.status === "approved" ? "warn" : "miss"),
          APPROVAL_ZH[p.status] || p.status));
        tr.appendChild(el("td", null, p.created_by || ""));
        tbl.appendChild(tr);
      });
      body.appendChild(tbl);
      body.appendChild(el("div", "hint", "审批制自主探索：propose（只读）→ lead 批准 → 人触发执行；LLM 可选、规则兜底。"));
    };
    if (STATIC_MODE || STATE.data) return render(approvalsData());
    if (!STATE.token) { body.appendChild(emptyState("approvals", { icon: "⑨" })); return; }
    api("api/v1/explorer?workspace=" + encodeURIComponent(STATE.workspace))
      .then(function (b) { render(b.proposals || []); })
      .catch(function () { render([]); });
  }

  function renderSchedules() {
    var body = ensureSection("schedules-body");
    if (!body) return;
    var render = function (list, due) {
      if (!list.length) { body.appendChild(emptyState("schedules", { icon: "⑩" })); return; }
      var tbl = el("table", "rules-matrix");
      var hr = el("tr"); ["计划", "触发", "链子集", "启用", "上次 run", "下次触发"].forEach(function (t) { hr.appendChild(el("th", null, t)); });
      tbl.appendChild(hr);
      list.forEach(function (s) {
        var tr = el("tr");
        tr.appendChild(el("td", "k", s.id || ""));
        tr.appendChild(el("td", null, s.cron ? ("cron " + s.cron) : ("每 " + (s.interval_seconds || "?") + "s")));
        tr.appendChild(el("td", null, (s.chains || []).join("、")));
        tr.appendChild(el("td", null, s.enabled ? "启用" : "停用"));
        tr.appendChild(el("td", null, s.last_run_name || "—"));
        tr.appendChild(el("td", due && due.indexOf(s.id) >= 0 ? "hit" : null, due && due.indexOf(s.id) >= 0 ? "到期" : (s.next_fire || "—")));
        tbl.appendChild(tr);
      });
      body.appendChild(tbl);
      body.appendChild(el("div", "hint", "到期自动跑链子集并与上次 findings 差异（新增/已修复），drift 报告落 run 目录。"));
    };
    if (STATIC_MODE || STATE.data) return render(schedulesData(), []);
    if (!STATE.token) { body.appendChild(emptyState("schedules", { icon: "⑩" })); return; }
    api("api/v1/scheduler?workspace=" + encodeURIComponent(STATE.workspace))
      .then(function (b) { render(b.schedules || [], b.due || []); })
      .catch(function () { render([], []); });
  }

  /* ================= 启动 ================= */

  document.addEventListener("DOMContentLoaded", function () {
    bindLang();
    bindNav();
    bindSession();
    applyI18n();
    if (isAuthed()) {
      renderDashboard();
      renderAll();
    }
  });
})();
