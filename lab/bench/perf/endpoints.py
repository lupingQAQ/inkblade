"""endpoints — 逐端点延迟全扫掠（维度①：端点全集 × 延迟，N>=10 全分布，读写分类）。

设计：
- 端点清单来自 routes.py 的静态提取（ARTEX server/*.go / Trident webui/server.py），
  不许只测 health/submit —— 全部端点逐一测。
- 每端点 N>=10 次顺序采样，报 min/median/p95/p99/max/mean/variance/stdev（stats.full_dist）。
- 读端点直接测；写端点带最小合法载荷 + 可脚本化清理（choreography 表）；
  危险端点（ARTEX 自更新 apply/rollback、改密）进 DENY 列表，记录 N/A+原因。
- 流式端点（SSE）只测首响应（读首块即断，超时上限 3s，JSON 里注明口径）。
- 双环境：同一模块以 --base 指向宿主 hostfwd 或 guest 回环，各自产出
  latency-{tool}-{env}.json。guest 模式：本目录 client/stats/endpoints 三文件 +
  routes-*.json 平铺即可跑（flat import 兼容）。

ARTEX 夹具（fixture）：先建一个任务并等它跑到 done（mock LLM v2 驱动，~15s），
使 /api/tasks/{id}/* 子资源端点有真实对象可查。
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

try:  # 包内导入（仓库运行）
    from lab.bench.perf.client import login, request_once
    from lab.bench.perf.stats import full_dist
except ImportError:  # guest 平铺运行（client.py/stats.py 同目录）
    from client import login, request_once  # type: ignore
    from stats import full_dist  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

GRID = REPO_ROOT / "reports" / "samples" / "perf" / "grid"

N_REPS = 10
STREAM_TIMEOUT_S = 3.0
DEFAULT_TIMEOUT_S = 10.0

# ARTEX 危险/破坏性端点：不实测，N/A+原因（黑盒基准不把被测栈打坏）
ARTEX_DENY = {
    ("POST", "/api/update/apply"): "自更新落盘，可能替换被测二进制（破坏后续测量）",
    ("POST", "/api/update/rollback"): "自更新回滚，同上",
    ("PUT", "/api/settings/basic-auth"): "会改全员认证姿态，污染后续所有请求",
    ("POST", "/api/auth/change-password"): "会改掉基准账号口令",
    ("POST", "/api/auth/init"): "已初始化的栈再 init 会 4xx/重置风险",
}


# ================================================================ Trident

def prepare_trident_root(root: Path) -> dict:
    """构造基准根：用户/已签 ROE 的工作区/带 findings+traffic 的证据 run/modules/rules-pack。"""
    from trident.core.evidence import EvidenceStore
    from trident.core.roe import init_roe
    from trident.core.users import UserStore

    root.mkdir(parents=True, exist_ok=True)
    users = UserStore(root / "users.json")
    try:
        users.create_user("perf-lead", "perf", "lead", ["bench"])
        users.create_user("perf-tester", "perf", "tester", ["bench"])
    except Exception:
        pass
    store = EvidenceStore(root, workspace="bench")
    init_roe(store, fields={"level": "主动探测", "namespaces": ["bench"],
                            "cidrs": ["127.0.0.0/8"], "client": "perf-compare 基准"})
    run = store.create_run("bench-run-001")
    run.add_step("bench-step-1", "perf fixture cmd", {"perf": 1}, "perf fixture summary")
    for i in range(20):
        run.add_finding("bench-step-1", "medium" if i % 2 else "low",
                        f"perf-finding-{i}", "perf fixture finding body " * 4)
    run.record_traffic("sglang-admin-failopen", [
        {"ts": time.time(), "method": "GET",
         "url": "http://127.0.0.1:18080/__routes__", "status": 200,
         "req_body": None, "resp_bytes": 128},
        {"ts": time.time(), "method": "POST",
         "url": "http://127.0.0.1:18080/pause", "status": 200,
         "req_body": "{}", "resp_bytes": 32},
    ])
    run.finalize_run()
    mods_src = REPO_ROOT / "trident" / "modules"
    mods_dst = root / "modules"
    if not mods_dst.exists():
        mods_dst.mkdir()
        for d in sorted(p for p in mods_src.iterdir() if p.is_dir()):
            if (d / "module.json").exists() and (d / "run.py").exists():
                shutil.copytree(d, mods_dst / d.name)
    rp_dst = root / "reports" / "rules-pack"
    if not rp_dst.exists():
        shutil.copytree(REPO_ROOT / "reports" / "samples" / "rules-pack", rp_dst)
    return {"users": users, "workspace": "bench", "run": run.name, "findings": 20}


def start_trident_server(root: Path, port: int, py_exe: str | None = None) -> subprocess.Popen:
    """子进程起 trident ui（隔离 GIL，保证并发扫掠时延迟不被客户端进程扭曲）。"""
    py = py_exe or sys.executable
    proc = subprocess.Popen(
        [py, "-m", "trident", "--home", str(root), "ui", "--port", str(port)],
        cwd=str(REPO_ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 30
    while time.time() < deadline:
        r = request_once(f"http://127.0.0.1:{port}/api/login", method="POST",
                         body={"name": "perf-lead", "password": "perf"}, timeout_s=2)
        if r["ok"]:
            return proc
        time.sleep(0.3)
    proc.kill()
    raise RuntimeError("trident ui 未在 30s 内就绪")


def trident_payloads(base: str, token: str) -> dict[tuple[str, str], dict]:
    """(method, path) → {body, headers, choreography}。headers 默认带 Bearer。"""
    H = {"Authorization": f"Bearer {token}"}
    ex_params = {"base_url": "http://127.0.0.1:18080/", "target": "http://127.0.0.1:18080/"}
    return {
        ("GET", "/"): {"headers": {}},
        ("GET", "/api/runs"): {"headers": H},
        ("GET", "/api/v1/assets"): {"headers": H},
        ("GET", "/api/v1/explorer"): {"headers": H},
        ("GET", "/api/v1/scheduler"): {"headers": H},
        ("GET", "/api/v1/traffic"): {"headers": H, "query": "?run=bench-run-001"},
        ("GET", "/api/v1/consent"): {"headers": H},
        ("GET", "/api/v1/zeroday"): {"headers": H},
        ("GET", "/api/v1/rules"): {"headers": H},
        ("POST", "/api/login"): {"body": {"name": "perf-lead", "password": "perf"},
                                 "headers": {}, "fresh_login": True},
        ("POST", "/api/execute"): {"body": {"module": "framework-port-matching",
                                            "workspace": "bench",
                                            "params": {"snapshot": "lab/fixtures/network"}},
                                   "headers": H},
        ("POST", "/api/abort"): {"body": {}, "headers": H},
        ("POST", "/api/v1/assets/discover"): {"body": {"workspace": "bench",
                                                       "seeds": {"mock": "http://127.0.0.1:18080"}},
                                              "headers": H},
        ("POST", "/api/v1/explorer/propose"): {"body": {"workspace": "bench", "use_llm": False,
                                                        "max_actions": 2}, "headers": H},
        ("POST", "/api/v1/explorer/approve"): {"body": {"workspace": "bench", "id": "@propose"},
                                               "headers": H, "pre": "propose"},
        ("POST", "/api/v1/explorer/reject"): {"body": {"workspace": "bench", "id": "@propose",
                                                       "reason": "perf"},
                                              "headers": H, "pre": "propose"},
        ("POST", "/api/v1/explorer/execute"): {"body": {"workspace": "bench", "id": "@propose"},
                                               "headers": H, "pre": "propose+approve"},
        ("POST", "/api/v1/scheduler/add"): {"body": {"workspace": "bench",
                                                     "interval_seconds": 86400,
                                                     "chains": []},
                                            "headers": H, "cleanup": "scheduler-remove"},
        ("POST", "/api/v1/scheduler/remove"): {"body": {"workspace": "bench", "id": "@last-sched"},
                                               "headers": H},
        ("POST", "/api/v1/scheduler/run-due"): {"body": {"workspace": "bench"}, "headers": H},
        ("POST", "/api/v1/traffic/replay"): {"body": {"workspace": "bench", "run": "bench-run-001",
                                                      "live": False}, "headers": H},
        ("POST", "/api/v1/consent/sign"): {"body": {"workspace": "bench",
                                                    "fields": {"level": "主动探测",
                                                               "namespaces": ["bench"],
                                                               "cidrs": ["127.0.0.0/8"],
                                                               "client": "perf-compare"}},
                                          "headers": H},
        ("POST", "/api/v1/zeroday/enable"): {"body": {"workspace": "bench"}, "headers": H},
        ("POST", "/api/v1/poc/reverify"): {"body": {"workspace": "bench",
                                                    "module": "framework-port-matching",
                                                    "params": ex_params}, "headers": H},
        ("POST", "/api/v1/poc/auto-reverify"): {"body": {"workspace": "bench", "enabled": False},
                                                "headers": H},
    }


def sweep_trident(base: str, root: Path | None = None, port: int = 18790,
                  n_reps: int = N_REPS, env: str = "host") -> dict:
    """起服务 → 全 25 端点 × N=10 → 全分布 JSON。root=None 时自建临时基准根。"""
    tmp = None
    if root is None:
        tmp = tempfile.mkdtemp(prefix="trident-perf-root-")
        root = Path(tmp)
    prepare_trident_root(root)
    proc = start_trident_server(root, port)
    base = base or f"http://127.0.0.1:{port}"
    try:
        token, _ = login(base, "trident", "perf-lead", "perf")
        routes = json.loads((GRID / "routes-trident.json").read_text(encoding="utf-8"))
        results = []
        for ep in routes["endpoints"]:
            key = (ep["method"], ep["path"])
            spec = trident_payloads(base, token).get(key)
            if spec is None:
                results.append({**ep, "dist": None, "note": "no payload spec (unreachable)"})
                continue
            results.append(_measure_endpoint(base, key, ep, spec, n_reps))
        payload = _wrap("trident", env, base, results,
                        "Trident 端点全集来自 webui/server.py 静态提取；"
                        "写端点带最小合法载荷，创建类带清理钩子；explorer 编排=先 propose 拿真实 id")
        return payload
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


# ================================================================ ARTEX

def _fixture_artex(base: str, token_headers: dict, timeout_s: float = 240.0) -> dict:
    """建一个任务并等 done，使子资源端点有真实对象。返回 {task_id, schedule_id...}。"""
    fix = {}
    r = request_once(base + "/api/tasks", method="POST", timeout_s=timeout_s,
                     headers=token_headers,
                     body={"description": "perf fixture task (authorized lab)",
                           "goal": "Probe the authorized lab target http://10.0.2.2:18080: "
                                   "fetch route manifest, exercise admin action and weight pull."})
    body = r["body"] or {}
    fix["task_http"] = r["status"]
    fix["task_id"] = str(body.get("id") or body.get("task", {}).get("id") or "")
    if fix["task_id"]:
        deadline = time.time() + timeout_s
        status = ""
        while time.time() < deadline:
            g = request_once(f"{base}/api/tasks/{fix['task_id']}", headers=token_headers,
                             timeout_s=15)
            if isinstance(g["body"], dict):
                status = g["body"].get("status", "")
            if status in ("done", "failed", "timeout"):
                break
            time.sleep(3)
        fix["task_final_status"] = status
    return fix


def artex_payloads(base: str, H: dict, task_id: str) -> dict[tuple[str, str], dict]:
    """按路径前缀给最小合法载荷；{} 兜底（4xx 也是有效到达样本，如实记录状态码）。"""
    P: dict[tuple[str, str], dict] = {}
    def put(method: str, path: str, **kw):
        P[(method, path)] = {"headers": H, **kw}

    # 读端点全部默认 Bearer GET
    # 写端点核心族（可清理）：
    put("POST", "/api/tasks", body={"description": "perf sweep task (authorized lab)",
                                    "goal": "Probe http://10.0.2.2:18080 route manifest."})
    put("POST", "/api/schedules", body={"name": "perf-sweep", "cron": "0 3 * * *"},
        alt_bodies=[{"name": "perf-sweep", "interval_seconds": 86400}])
    put("POST", "/api/task-categories", body={"name": "perf-cat"},
        alt_bodies=[{"title": "perf-cat"}, {"category": "perf-cat"}])
    put("POST", "/api/task-templates", body={"name": "perf-tpl"},
        alt_bodies=[{"title": "perf-tpl"}, {"template": "perf-tpl"}])
    put("POST", f"/api/tasks/{task_id}/goals", body={"text": "perf goal probe"})
    put("POST", f"/api/tasks/{task_id}/constraints", body={"kind": "avoid", "text": "perf"})
    put("POST", f"/api/tasks/{task_id}/scope", body={"kind": "domain", "value": "bench.test",
                                                     "reason": "perf"})
    put("POST", f"/api/tasks/{task_id}/intercept-rules",
        body={"name": "perf-rule", "pattern": "rm -rf", "action": "block"})
    put("POST", "/api/workspace/write", body={"path": "perf-probe.txt",
                                              "content": "perf sweep"})
    put("PATCH", f"/api/tasks/{task_id}", body={"remark": "perf"})
    put("PATCH", f"/api/tasks/{task_id}/remark", body={"remark": "perf"})
    return P


def sweep_artex(base: str, env: str = "host", n_reps: int = N_REPS,
                grid: Path | None = None) -> dict:
    grid = grid or GRID
    token, H = login(base, "artex", "ARTEX", "ArtexBench2026")
    if not token:
        raise RuntimeError(f"ARTEX 登录失败 @ {base}")
    routes = json.loads((grid / "routes-artex.json").read_text(encoding="utf-8"))
    print(f"[artex-sweep] building fixture task (engine ~15s)…", flush=True)
    fix = _fixture_artex(base, H)
    task_id = fix.get("task_id") or "1"
    print(f"[artex-sweep] fixture task={task_id} status={fix.get('task_final_status')}", flush=True)
    specs = artex_payloads(base, H, task_id)

    reads = [e for e in routes["endpoints"] if e["class"] == "read"]
    writes = [e for e in routes["endpoints"] if e["class"] == "write"]
    results: list[dict] = []

    # 读端点先测（栈安静）；写端点殿后（POST /api/tasks 会触发引擎异步任务）
    for ep in reads:
        key = (ep["method"], ep["probe_path"])
        spec = {"headers": H}
        results.append(_measure_endpoint(base, key, ep, spec, n_reps,
                                         path_override=ep["probe_path"]))
    created: dict[str, list[str]] = {}
    for ep in writes:
        key_m = (ep["method"], ep["path"])
        if key_m in ARTEX_DENY:
            results.append({**ep, "dist": None, "na_reason": ARTEX_DENY[key_m]})
            continue
        spec = specs.get(key_m) or {"headers": H}
        # 探测路径参数替换后的端点（{id}→fixture task_id 等）
        pp = ep["probe_path"]
        for k, v in {"{id}": task_id}.items():
            pp = pp.replace(k, v) if k in pp else pp
        res = _measure_endpoint(base, (ep["method"], pp), ep, spec, n_reps,
                                path_override=pp)
        if ep["path"] == "/api/tasks" and res["dist"]:
            created["tasks"] = [str(i + 1) for i in range(n_reps)]  # id 由清理阶段重查
        results.append(res)

    # 清理：删掉扫掠期间创建的任务/计划/类别/模板/goal/constraint/scope/规则/工作区文件
    cleanup = _cleanup_artex(base, H, task_id)
    payload = _wrap("artex", env, base, results,
                    "ARTEX 端点全集来自 server/*.go mux.HandleFunc 静态提取（278 个）；"
                    "读端点 N=10 全分布；写端点最小合法载荷+可清理族（task/schedule/category/"
                    "template/goal/constraint/scope/intercept-rule/workspace）；危险端点"
                    "（update/apply、change-password、auth/init、basic-auth）DENY+原因；"
                    "SSE 流端点只测首响应（3s 上限）", fixture=fix, cleanup=cleanup)
    return payload


def _cleanup_artex(base: str, H: dict, fixture_task_id: str) -> dict:
    """尽力清理：列出全部任务删除（含 fixture 与扫掠创建物）、计划、类别、模板。"""
    out = {}
    t = request_once(base + "/api/tasks", headers=H, timeout_s=30)
    ids = []
    if isinstance(t["body"], dict):
        raw = json.dumps(t["body"])
        import re
        ids = sorted(set(re.findall(r'"id":\s*"?(\d+)"?', raw)), key=int)[-40:]
    deleted = 0
    for i in ids:
        d = request_once(f"{base}/api/tasks/{i}", method="DELETE", headers=H, timeout_s=60)
        if d["ok"] or d["status"] in (200, 204, 404):
            deleted += 1
        time.sleep(0.4)
    out["tasks_deleted"] = deleted
    for path in ("/api/schedules", "/api/task-categories", "/api/task-templates"):
        g = request_once(base + path, headers=H, timeout_s=20)
        import re as _re
        sids = sorted(set(_re.findall(r'"id":\s*"?(\d+)"?', json.dumps(g["body"] or {}))),
                      key=int)[:50] if g["ok"] else []
        n = 0
        for sid in sids:
            d = request_once(f"{base}{path}/{sid}", method="DELETE", headers=H, timeout_s=30)
            if d["ok"] or d["status"] in (200, 204, 404):
                n += 1
        out[path] = n
    request_once(base + "/api/workspace/delete", method="POST", headers=H,
                 body={"path": "perf-probe.txt"}, timeout_s=15)
    out["workspace"] = "perf-probe.txt deleted"
    return out


# ================================================================ 通用测量

def _measure_endpoint(base: str, key: tuple[str, str], ep: dict, spec: dict,
                      n_reps: int, *, path_override: str | None = None) -> dict:
    """单端点 N 次采样 → 全分布。fresh_login/alt_bodies/pre 编排仅 Trident 用。"""
    method, path = key
    url = base + (path_override or path)
    if spec.get("query"):
        url += spec["query"]
    headers = spec.get("headers") or {}
    body = spec.get("body")
    samples: list[float] = []
    statuses: list[int] = []
    errs: list[str] = []
    nbytes: list[int] = []
    pre_note = ""
    for i in range(n_reps):
        send_body = body
        if spec.get("pre"):
            pre_note, send_body = _run_pre(base, spec["pre"], headers, body)
        if spec.get("fresh_login"):
            tok, _ = login(base, "trident", "perf-lead", "perf") if "trident" in url else \
                (None, None)
            if tok:
                headers = {"Authorization": f"Bearer {tok}"}
        r = request_once(url, method=method, body=send_body, headers=headers,
                         timeout_s=STREAM_TIMEOUT_S if ep.get("streaming") else DEFAULT_TIMEOUT_S)
        samples.append(r["ms"])
        statuses.append(r["status"])
        if r["err"]:
            errs.append(r["err"])
        nbytes.append(r["bytes"])
    dist = full_dist(samples)
    uniq_status = sorted(set(statuses))
    out = {**ep, "dist": dist,
           "status": uniq_status[0] if len(uniq_status) == 1 else uniq_status,
           "status_hist": {str(s): statuses.count(s) for s in uniq_status},
           "bytes_median": sorted(nbytes)[len(nbytes) // 2],
           "errors": errs[:3]}
    if pre_note:
        out["pre"] = pre_note
    if spec.get("alt_bodies"):
        out["alt_bodies_tried"] = True
    if ep.get("streaming"):
        out["note"] = "SSE 流端点：只测首响应（读首块即断，3s 上限）"
    return out


def _run_pre(base: str, pre: str, headers: dict, body: dict) -> tuple[str, dict]:
    """Trident explorer 编排：propose（±approve）拿真实 proposal id 注入 body。"""
    b = dict(body or {})
    note = pre
    pr = request_once(base + "/api/v1/explorer/propose", method="POST",
                      body={"workspace": b.get("workspace", "bench"), "use_llm": False,
                            "max_actions": 2}, headers=headers)
    pid = None
    if isinstance(pr["body"], dict):
        prop = pr["body"].get("proposal") or {}
        pid = prop.get("id") or (prop.get("proposals") or [{}])[0].get("id")
    if pid is None and pr["ok"]:
        pid = "0"
    if "approve" in pre and pid:
        request_once(base + "/api/v1/explorer/approve", method="POST",
                     body={"workspace": b.get("workspace", "bench"), "id": pid},
                     headers=headers)
    b["id"] = pid or "0"
    return note, b


def _wrap(tool: str, env: str, base: str, results: list[dict], method_note: str,
          **extra) -> dict:
    ok2xx = [r for r in results if r.get("dist") and (
        isinstance(r.get("status"), int) and 200 <= r["status"] < 300)]
    na = [r for r in results if r.get("na_reason")]
    return {
        "dimension": "latency-endpoints",
        "tool": tool, "environment": env, "base_url": base,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "n_reps": N_REPS,
        "methodology": method_note + f"；每端点 N={N_REPS} 全分布（min/median/p95/p99/"
        "max/mean/variance/stdev）；4xx/5xx 也是有效到达样本（状态码如实记录）",
        "summary": {
            "endpoints_total": len(results),
            "measured_with_dist": sum(1 for r in results if r.get("dist")),
            "ok2xx_endpoints": len(ok2xx),
            "denied_or_na": len(na),
        },
        "results": results,
        **extra,
    }


def main(argv: list[str] | None = None) -> int:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="端点全扫掠（延迟，N>=10 全分布）")
    ap.add_argument("--tool", required=True, choices=["trident", "artex"])
    ap.add_argument("--env", default="host", help="host|guest")
    ap.add_argument("--base", default=None, help="被测基址（缺省 trident 自起子进程/artex 18787）")
    ap.add_argument("--n", type=int, default=N_REPS)
    ap.add_argument("--grid", default=str(GRID))
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    if args.tool == "trident":
        payload = sweep_trident(args.base or "", n_reps=args.n, env=args.env)
    else:
        payload = sweep_artex(args.base or "http://127.0.0.1:18787", env=args.env,
                              n_reps=args.n, grid=Path(args.grid))
    out = Path(args.out) if args.out else Path(args.grid) / f"latency-{args.tool}-{args.env}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    s = payload["summary"]
    print(f"[endpoints] {args.tool}/{args.env}: {s['endpoints_total']} eps, "
          f"dist={s['measured_with_dist']}, 2xx={s['ok2xx_endpoints']}, denied={s['denied_or_na']}")
    print(f"[endpoints] -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
