/* Trident 六视图 SPA — 原生 JS + vendor UMD（React / ReactDOM / React Flow v11），无构建步骤。
 *
 * 数据源：
 *  - 静态导出模式：window.TRIDENT_DATA（由 export_static.py 注入，免服务打开）
 *  - 服务模式：POST api/login（会话）、GET api/runs（运行列表）；步骤级数据无只读端点 → 空数据兜底提示
 *
 * 六视图：
 *  ① view-dag       工作流 DAG（React Flow；缺库时自绘 DagCanvas SVG 兜底），状态色 待执行/运行中/成功/降级/阻断
 *  ② view-chain     攻击链图（资产节点 + 利用边，严重度着色，链过滤）
 *  ③ view-timeline  执行时间线（瀑布：起止/耗时/并行度）
 *  ④ view-evidence  证据浏览器（runs → steps → 归档哈希，三层穿透）
 *  ⑤ view-report    报告预览（服务模式试 api/report，失败/静态模式内嵌渲染 findings 表）
 *  ⑥ view-rules     规则视图（规则↔链映射矩阵 + 紫队验证标记）
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
    token: null, role: null, workspace: "local-lab",
    runs: [], data: window.TRIDENT_DATA || null,
    selectedStep: null, view: "dag", reportRemote: null, redactZeroday: false,
  };
  var STATIC_MODE = !!window.TRIDENT_DATA;

  function steps() { return (STATE.data && STATE.data.steps) || []; }
  function findings() { return (STATE.data && STATE.data.findings) || []; }
  function nodes() { return (STATE.data && STATE.data.nodes) || []; }
  function edges() { return (STATE.data && STATE.data.edges) || []; }
  function stepStatus(s) { return s && STATUS_ZH[s.status] ? s.status : "pending"; }

  /* ================= 导航 ================= */

  function bindNav() {
    var btns = document.querySelectorAll("nav#views button");
    btns.forEach(function (b) {
      b.addEventListener("click", function () { showView(b.getAttribute("data-view")); });
    });
  }
  function showView(v) {
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
    renderCurrent();
    renderRunMeta();
  }

  /* ================= 登录 / 服务模式 ================= */

  function bindSession() {
    var form = document.getElementById("login-form");
    if (STATIC_MODE) {
      document.getElementById("mode-pill").textContent = "静态导出 · 免服务打开";
      document.getElementById("mode-pill").classList.add("static");
      return; // 静态模式无登录
    }
    form.hidden = false;
    document.getElementById("mode-pill").textContent = "服务模式 · 本地";
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      login();
    });
    document.getElementById("btn-runs").addEventListener("click", loadRuns);
    document.getElementById("btn-abort").addEventListener("click", function () {
      fetch("api/abort", { method: "POST" }).catch(function () {});
      this.textContent = "已请求停止";
    });
  }
  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (STATE.token) opts.headers["Authorization"] = "Bearer " + STATE.token;
    return fetch(path, opts).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }
  function login() {
    var name = document.getElementById("in-user").value.trim();
    var pass = document.getElementById("in-pass").value;
    STATE.workspace = document.getElementById("in-ws").value.trim() || "local-lab";
    api("api/login", { method: "POST", body: JSON.stringify({ name: name, password: pass }) })
      .then(function (body) {
        STATE.token = body.token; STATE.role = body.role;
        var pill = document.getElementById("session-pill");
        pill.hidden = false;
        pill.textContent = name + " · " + (body.role || "") + " · " + STATE.workspace;
        pill.classList.add("ok");
        document.getElementById("btn-runs").hidden = false;
        document.getElementById("btn-abort").hidden = false;
        loadRuns();
      })
      .catch(function (e) {
        var pill = document.getElementById("session-pill");
        pill.hidden = false;
        pill.classList.remove("ok");
        pill.textContent = "登录失败：" + e.message;
      });
  }
  function loadRuns() {
    api("api/runs?workspace=" + encodeURIComponent(STATE.workspace))
      .then(function (body) { STATE.runs = body.runs || []; renderRunMeta(); })
      .catch(function (e) {
        var pill = document.getElementById("session-pill");
        pill.textContent = "获取运行失败：" + e.message;
      });
  }
  function renderRunMeta() {
    var host = document.getElementById("tl-summary"); // 顶部数据状态（时间线页顺便展示）
    if (!host) return;
    if (STATIC_MODE) {
      var d = STATE.data;
      host.textContent = "运行 " + d.run.name + " · 状态 " + (d.run.status || "—") +
        " · 步骤 " + d.steps.length + " · 发现 " + d.findings.length;
      return;
    }
    host.textContent = STATE.runs.length
      ? "本工作区运行数：" + STATE.runs.length + "（" + STATE.runs.join("、") + "）"
      : "已登录（服务模式暂无步骤只读端点；步骤级数据请用静态导出查看）";
  }

  /* ================= ① 工作流 DAG ================= */

  var dagRoot = null;

  function renderDag() {
    var host = document.getElementById("dag-canvas");
    var list = steps();
    clear(host);
    if (!list.length) {
      var empty = el("div", "dag-empty",
        STATIC_MODE ? "该运行无步骤记录" : "服务模式暂无步骤只读端点 —— 用静态导出（trident ui --export-static）查看完整 DAG");
      host.appendChild(empty);
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
      e("div", { className: "rf-step-status" }, STATUS_ZH[st] || st),
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
      stz.textContent = STATUS_ZH[st] || st;
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
    head.lastChild.textContent = STATUS_ZH[stepStatus(s)];
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
      host.appendChild(el("div", "empty",
        STATIC_MODE ? "该运行未记录图数据（graph_nodes/graph_edges）" :
          "服务模式暂无图数据端点 —— 静态导出包含可达性图（资产节点 + 利用边）"));
      return;
    }
    // 链过滤选项
    var chains = {};
    es.forEach(function (e2) { if (e2.chain) chains[e2.chain] = true; });
    var cur = filter.value || "*";
    clear(filter);
    filter.appendChild(el("option", null, "全部链")).value = "*";
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
    clear(body);
    var list = steps();
    if (!list.length) {
      body.appendChild(el("div", "empty", STATIC_MODE ? "该运行无步骤" : "服务模式无时间线数据（静态导出含起止时间）"));
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
    axis.appendChild(el("div", null, "步骤"));
    var marks = el("div", "marks");
    marks.appendChild(el("span", null, fmtTime(t0)));
    marks.appendChild(el("span", null, fmtTime((t0 + t1) / 2)));
    marks.appendChild(el("span", null, fmtTime(t1)));
    axis.appendChild(marks);
    axis.appendChild(el("div", null, "耗时"));
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
      bar.title = fmtTime(r.start) + " → " + fmtTime(r.end) + " · " + STATUS_ZH[r.st];
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
    body.appendChild(el("div", "hint",
      "步骤 " + rows.length + " · 总耗时 " + fmtDur((t1 - t0) * 1000) +
      " · 累计执行 " + fmtDur(sum * 1000) + " · 峰值并行度 " + maxPar));
  }

  /* ================= ④ 证据浏览器 ================= */

  function renderEvidence() {
    var list = document.getElementById("ev-steps");
    var detail = document.getElementById("ev-detail");
    var manifest = document.getElementById("ev-manifest");
    clear(list); clear(detail);
    var st = steps();
    if (!st.length) {
      list.appendChild(el("div", "empty", STATIC_MODE ? "无步骤" : "服务模式：登录后运行列表见时间线页头部；步骤级三层证据请用静态导出"));
      detail.appendChild(el("h3", null, "三层证据"));
      detail.appendChild(el("div", "hint", "（未选择）"));
    } else {
      st.forEach(function (s) {
        var card = el("div", "ev-step" + (STATE.selectedStep === s.step_key ? " selected" : ""));
        var head = el("div");
        head.appendChild(el("span", "badge st-" + stepStatus(s), STATUS_ZH[stepStatus(s)]));
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
    manifest.textContent = (STATE.data && STATE.data.manifest) ? STATE.data.manifest : "（静态导出未含 manifest 或运行未产生归档）";
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
    kv("状态", el("span", "badge st-" + stepStatus(s), STATUS_ZH[stepStatus(s)]));
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

  function renderReport() {
    var host = document.getElementById("report-body");
    clear(host);
    if (STATIC_MODE) { renderReportData(host); return; }
    // 服务模式：尝试 /api/report 占位端点，失败则内嵌渲染（空数据兜底）
    api("api/report?run=&lang=bi")
      .then(function (body) {
        STATE.reportRemote = body;
        host.appendChild(el("div", "panel", "服务端报告已返回（占位端点）；以下为本地内嵌渲染："));
        renderReportData(host);
      })
      .catch(function () {
        host.appendChild(el("div", "panel hint",
          "api/report 不可用（未实现或未登录）——以内嵌渲染兜底；完整报告请运行报告引擎或使用静态导出。"));
        renderReportData(host);
      });
  }

  function renderReportData(host) {
    var fs = findings();
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
    cards.appendChild(card(fs.length, "发现总数"));
    SEV_ORDER.forEach(function (s) {
      cards.appendChild(card(bySev[s] || 0, s.toUpperCase(), "var(--sev-" + s + ")"));
    });
    cards.appendChild(card(steps().length, "执行步骤"));
    host.appendChild(cards);

    var panel = el("div", "panel");
    panel.appendChild(el("h3", null, "发现清单（Findings）"));
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
    toggle.appendChild(document.createTextNode(" 零日级细节脱敏（可选；默认展示已公开细节）"));
    panel.appendChild(toggle);
    if (!fs.length) {
      panel.appendChild(el("div", "hint", STATIC_MODE ? "该运行无发现" : "服务模式无发现数据（静态导出内嵌 findings 表）"));
    } else {
      var tbl = el("table", "data");
      var thead = el("thead");
      var htr = el("tr");
      ["严重度", "标题", "步骤", "证据（归档层引用）", "零日"].forEach(function (h) { htr.appendChild(el("th", null, h)); });
      thead.appendChild(htr); tbl.appendChild(thead);
      var tbody = el("tbody");
      fs.forEach(function (f) {
        var tr = el("tr");
        var sev = (f.severity || "info").toLowerCase();
        tr.appendChild(el("td")).appendChild(el("span", "badge sev-" + (SEV_ORDER.indexOf(sev) >= 0 ? sev : "info"), sev.toUpperCase()));
        // 默认展示全部细节；勾选可选脱敏后仅对 is_zeroday 发现隐藏细节（保留证据哈希引用）。
        var redact = !!STATE.redactZeroday && !!f.is_zeroday;
        var titleTd = el("td");
        titleTd.textContent = redact ? "【脱敏】影响已验证（零日级，已公开；未展示细节）" : (f.title || "");
        if (!redact && f.detail) {
          titleTd.appendChild(el("div", "hint", f.detail));
        }
        if (redact && f.evidence_path) {
          titleTd.appendChild(el("div", "hint", "证据：" + f.evidence_path));
        }
        tr.appendChild(titleTd);
        tr.appendChild(el("td", null, f.step_key || ""));
        tr.appendChild(el("td")).appendChild(el("code", null, f.evidence_path || "—"));
        tr.appendChild(el("td", null, f.is_zeroday ? (redact ? "是（可选脱敏）" : "是（零日级，已公开）") : "否"));
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      panel.appendChild(tbl);
    }
    host.appendChild(panel);

    var sec = el("div", "panel rep-section");
    sec.appendChild(el("h4", null, "结构对齐（PTES / NIST SP 800-115 / 等保 2.0 · GB/T 20984 / CVSS 3.1 / ATT&CK·ATLAS）"));
    sec.appendChild(el("div", "hint",
      "预览页仅渲染发现表与统计；正式双语报告由报告引擎生成（渗透 + 修复 + 防御规则包交付文档），" +
      "含组合层风险 / 训练数据泄露面 / 核心代码清单 / 网络分层威胁模型 / 混合云边界专节。"));
    host.appendChild(sec);
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
      var g = data.graph || { nodes: [], edges: [] };
      var allNodes = g.nodes || [];
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
        body.appendChild(el("div", "hint", "资产清单加载失败（未发现或未登录）。"));
      });
    };
    if (STATIC_MODE || STATE.data) return render(assetsData(), {});
    if (!STATE.token) { body.appendChild(el("div", "hint", "登录后加载资产清单（api/v1/assets）。")); return; }
    load("");
  }

  function renderDrift() {
    var body = ensureSection("drift-body");
    if (!body) return;
    var render = function (d) {
      if (!d) { body.appendChild(el("div", "hint", "无漂移数据（周期重测后由 scheduler 生成 drift.json）。")); return; }
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
    if (!STATE.token) { body.appendChild(el("div", "hint", "登录后加载差异视图（api/v1/drift）。")); return; }
    var qs = "api/v1/drift?workspace=" + encodeURIComponent(STATE.workspace);
    if (STATE.selectedRun) qs += "&run=" + encodeURIComponent(STATE.selectedRun);
    api(qs).then(function (body2) { render(body2.drift || body2); })
      .catch(function (e) {
        body.appendChild(el("div", "hint", "差异数据加载失败（" + e.message +
          "）；周期重测 run-due 后生成 drift.json，或查看静态导出。"));
      });
  }

  var APPROVAL_ZH = {
    "pending_approval": "待审批", "approved": "已批准", "rejected": "已拒绝", "executed": "已执行",
  };

  function renderApprovals() {
    var body = ensureSection("approvals-body");
    if (!body) return;
    var render = function (list) {
      if (!list.length) { body.appendChild(el("div", "hint", "审批队列为空（explorer propose 生成提议）。")); return; }
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
    if (!STATE.token) { body.appendChild(el("div", "hint", "登录后加载审批队列（api/v1/explorer）。")); return; }
    api("api/v1/explorer?workspace=" + encodeURIComponent(STATE.workspace))
      .then(function (b) { render(b.proposals || []); })
      .catch(function () { render([]); });
  }

  function renderSchedules() {
    var body = ensureSection("schedules-body");
    if (!body) return;
    var render = function (list, due) {
      if (!list.length) { body.appendChild(el("div", "hint", "无周期重测计划（api/v1/scheduler/add 创建）。")); return; }
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
    if (!STATE.token) { body.appendChild(el("div", "hint", "登录后加载计划任务（api/v1/scheduler）。")); return; }
    api("api/v1/scheduler?workspace=" + encodeURIComponent(STATE.workspace))
      .then(function (b) { render(b.schedules || [], b.due || []); })
      .catch(function () { render([], []); });
  }

  /* ================= 启动 ================= */

  document.addEventListener("DOMContentLoaded", function () {
    bindNav();
    bindSession();
    renderAll();
  });
})();
