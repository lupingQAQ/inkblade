# -*- coding: utf-8 -*-
"""企业黄项本地可验证部分的统一执行器（ER-06/08/16/26/27/34/39/40/50/57）。

产物：``local-checks.json`` + ``local-checks.md``；所有检查只在本机临时目录/
127.0.0.1 mock 上运行，不接触客户网络/账号。
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .delivery import Deduplicator, DeliveryQueue, EgressPolicy, DeliveryPolicyError
from .evidence_pack import build_pack, verify_pack
from .governance import (ChangeCalendar, ExceptionPolicy, GovernanceError,
                         assert_no_regression)
from .gpu_contract import compatibility_matrix, validate_device_plugin, validate_dra
from .registry import (ProxyConfig, RegistryClient, manifest_digest, parse_reference,
                       reference_policy)
from .retention import RetentionError, apply_retention
from .scale import daily_million_projection, run_scale


class _Registry:
    def __init__(self):
        self.requests: list[str] = []
        self.manifest = json.dumps({"schemaVersion": 2, "config": {"digest": "sha256:" + "0" * 64}},
                                   separators=(",", ":")).encode()
        self.digest = manifest_digest(self.manifest)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status: int, body: bytes = b"", headers: dict | None = None):
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.requests.append(self.path)
                auth = self.headers.get("Authorization", "")
                if self.path.startswith("/token"):
                    if not auth.startswith("Basic "):
                        self._send(401)
                        return
                    self._send(200, json.dumps({"token": "fixture-token", "expires_in": 300}).encode())
                    return
                if self.path == "/v2/":
                    if auth != "Bearer fixture-token":
                        self._send(401, b"{}", {
                            "WWW-Authenticate":
                                f'Bearer realm="http://127.0.0.1:{outer.port}/token",'
                                'service="fixture-registry"'})
                        return
                    self._send(200, b"{}")
                    return
                if self.path.startswith("/v2/demo/app/manifests/"):
                    if auth != "Bearer fixture-token":
                        self._send(401)
                        return
                    self._send(200, outer.manifest,
                               {"Docker-Content-Digest": outer.digest,
                                "Content-Type": "application/vnd.oci.image.manifest.v1+json"})
                    return
                if self.path.startswith("/v2/demo/bad/manifests/"):
                    if auth != "Bearer fixture-token":
                        self._send(401)
                        return
                    self._send(200, outer.manifest,
                               {"Docker-Content-Digest": "sha256:" + "f" * 64})
                    return
                self._send(404)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class _Proxy:
    def __init__(self):
        self.paths: list[str] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                body = b'{"proxied": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class _FlakyAdapter:
    def __init__(self, fail_first: int = 1):
        self.calls = 0
        self.fail_first = fail_first

    def send(self, event):
        self.calls += 1
        if self.calls <= self.fail_first:
            return {"ok": False, "status": 503, "error": "HTTP 503"}
        return {"ok": True, "status": 200}


def _check(cid: str, title: str, fn) -> dict:
    started = time.perf_counter()
    try:
        evidence = fn()
        status = "PASS"
        error = ""
    except Exception as exc:  # noqa: BLE001
        evidence = {}
        status = "FAIL"
        error = f"{type(exc).__name__}: {exc}"
    return {"id": cid, "title": title, "status": status, "error": error,
            "evidence": evidence, "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)}


def run_local_checks(out_dir: str | Path) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    checks: list[dict] = []
    tmp_root = Path(tempfile.mkdtemp(prefix="inkblade-ent-"))
    registry = _Registry()
    proxy = _Proxy()
    try:
        def registry_probe():
            ref = f"127.0.0.1:{registry.port}/demo/app@{registry.digest}"
            parsed = parse_reference(ref)
            client = RegistryClient(f"http://127.0.0.1:{registry.port}", username="u", password="p")
            good = client.probe(ref)
            bad_ref = f"127.0.0.1:{registry.port}/demo/bad@{registry.digest}"
            bad = client.probe(bad_ref)
            tag_policy = reference_policy(f"127.0.0.1:{registry.port}/demo/app:latest")
            if not good.get("ok"):
                raise AssertionError(f"registry auth/digest probe failed: {good}")
            if bad.get("digest_match"):
                raise AssertionError("bad digest 未被检出")
            if "tag-only" not in tag_policy["risks"]:
                raise AssertionError("tag-only 未标记")
            return {"reference": ref, "pinned": parsed["pinned"], "auth": good["auth"],
                    "digest_match": good["digest_match"], "bad_digest_match": bad["digest_match"],
                    "bad_status": bad.get("status"), "tag_only_risks": tag_policy["risks"],
                    "requests": len(registry.requests)}

        checks.append(_check("er-08-registry-auth-digest",
                             "私有 registry：Bearer 认证链 + manifest digest + tag-only 策略",
                             registry_probe))

        def proxy_path():
            conf = ProxyConfig(http_proxy=proxy.base, no_proxy="")
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": conf.http_proxy}))
            with opener.open("http://registry.invalid/v2/", timeout=5) as resp:
                body = resp.read().decode()
            if not proxy.paths:
                raise AssertionError("请求未经过本地代理")
            return {"proxy": proxy.base, "absolute_uri": proxy.paths[0],
                    "status": resp.status, "body": body,
                    "bypass_localhost": ProxyConfig(no_proxy="localhost").bypass("localhost")}

        checks.append(_check("er-08-proxy-absolute-uri",
                             "代理路径：绝对 URI 经本地 HTTP 代理转发", proxy_path))

        def retention():
            root = tmp_root / "retention"
            (root / "old").mkdir(parents=True)
            (root / "fresh").mkdir(parents=True)
            old = root / "old" / "report.json"
            fresh = root / "fresh" / "keep.json"
            old.write_text('{"old": true}', encoding="utf-8")
            fresh.write_text('{"fresh": true}', encoding="utf-8")
            old_time = time.time() - 400 * 86400
            import os
            os.utime(old, (old_time, old_time))
            plan = {"legal_hold": False, "actions": [
                {"path": str(old), "action": "purge"},
                {"path": str(fresh), "action": "keep"}]}
            dry = apply_retention(plan, root=root, execute=False)
            try:
                apply_retention(plan, root=root, execute=True, approvals=("lead",))
                raise AssertionError("单角色审批未被拒绝")
            except RetentionError:
                pass
            held = apply_retention(plan, root=root, execute=True,
                                   approvals=("lead", "security-owner"), legal_hold=True)
            if not old.exists():
                raise AssertionError("legal hold 下文件被删除")
            done = apply_retention(plan, root=root, execute=True,
                                   approvals=("lead", "security-owner"))
            if old.exists() or not (root / "retention-audit.jsonl").is_file():
                raise AssertionError("purge/审计记录未按预期执行")
            try:
                outside = tmp_root.parent / "outside-retention.txt"
                outside.write_text("outside", encoding="utf-8")
                apply_retention({"actions": [{"path": str(outside), "action": "purge"}]},
                                root=root, execute=True,
                                approvals=("lead", "security-owner"))
                raise AssertionError("越界路径未被拒绝")
            except RetentionError:
                pass
            return {"dry_run": dry["counts"], "held": held["counts"], "executed": done["counts"],
                    "audit_exists": (root / "retention-audit.jsonl").is_file(),
                    "boundary_rejected": True}

        checks.append(_check("er-27-retention-execution",
                             "保留/删除执行：dry-run/legal hold/双角色/越界拒绝/审计 JSONL",
                             retention))

        def change_calendar():
            cal = ChangeCalendar(tmp_root / "calendar.json")
            now = time.time()
            cal.add_freeze("quarter-end", now - 3600, now + 3600, reason="财报",
                           ticket="CAB-100", owner="ops")
            try:
                cal.assert_change_allowed(now, now + 600)
                raise AssertionError("冻结期重叠未被拒绝")
            except GovernanceError:
                pass
            cal.assert_change_allowed(now + 7200, now + 9000)
            if "BEGIN:VCALENDAR" not in cal.ics():
                raise AssertionError("ICS 导出缺失")
            return {"freeze": cal.upcoming(now=now), "overlap_rejected": True,
                    "ics_bytes": len(cal.ics())}

        checks.append(_check("er-26-change-freeze",
                             "变更窗口：冻结期重叠拒绝 + ICS 导出", change_calendar))

        def exceptions():
            policy = ExceptionPolicy()
            now = time.time()
            policy.add(image="nvcr.io/nvidia/gpu-operator", digest="sha256:" + "a" * 64,
                       namespace="gpu-operator", service_account="gpu-operator",
                       approver="security-owner", expires_at=now + 86400,
                       reason="vendor DaemonSet", now=now)
            ok = policy.evaluate({"image": "nvcr.io/nvidia/gpu-operator",
                                  "digest": "sha256:" + "a" * 64,
                                  "namespace": "gpu-operator",
                                  "service_account": "gpu-operator"}, now=now)
            tag = policy.evaluate({"image": "nvcr.io/nvidia/gpu-operator", "digest": "",
                                   "namespace": "gpu-operator",
                                   "service_account": "gpu-operator"}, now=now)
            expired = policy.evaluate({"image": "nvcr.io/nvidia/gpu-operator",
                                       "digest": "sha256:" + "a" * 64,
                                       "namespace": "gpu-operator",
                                       "service_account": "gpu-operator"}, now=now + 2 * 86400)
            try:
                policy.add(image="x", digest="sha256:" + "b" * 64, namespace="*",
                           service_account="sa", approver="lead", expires_at=now + 86400)
                raise AssertionError("通配 namespace 未被拒绝")
            except GovernanceError:
                pass
            return {"allowed": ok, "tag_only": tag, "expired": expired}

        checks.append(_check("er-34-vendor-exception-policy",
                             "云厂商 DaemonSet 例外：digest/ns/SA/审批/到期", exceptions))

        def rule_regression():
            baseline = {"rules": {"r1": {"chains": ["c1"]}, "r2": {"chains": ["c2"]}},
                        "coverage": {"c1": "拦截", "c2": "检测"}}
            good = {"rules": {"r1": {"chains": ["c1"]}, "r2": {"chains": ["c2"]}},
                    "coverage": {"c1": "拦截+检测", "c2": "检测"}}
            bad = {"rules": {"r1": {"chains": ["c1"]}},
                   "coverage": {"c1": "漏过", "c2": "检测"}}
            assert_no_regression(baseline, good)
            try:
                assert_no_regression(baseline, bad)
                raise AssertionError("规则回归未被检出")
            except GovernanceError:
                pass
            return {"good_ok": True, "bad_rejected": True}

        checks.append(_check("er-40-rule-regression",
                             "规则升级回归：覆盖降级/规则删除即拒绝", rule_regression))

        def delivery():
            dedupe = Deduplicator(window_seconds=3600)
            adapter = _FlakyAdapter(fail_first=1)
            queue = DeliveryQueue(adapter, dedupe=dedupe, max_attempts=3, backoff=0,
                                  dead_letter_path=tmp_root / "dlq.jsonl")
            events = [{"step_key": "m", "title": "t", "resource": "r"}]
            first = queue.send(events, tenant="a")
            second = queue.send(events, tenant="a")
            if first["sent"] != 1 or first["attempts"] != 2:
                raise AssertionError(f"重试/投递统计异常：{first}")
            if second["duplicates"] != 1:
                raise AssertionError("窗口内重复未去重")
            failing = DeliveryQueue(_FlakyAdapter(fail_first=99), max_attempts=2,
                                    dead_letter_path=tmp_root / "dlq2.jsonl")
            bad = failing.send([{"step_key": "x", "title": "y", "resource": "z"}])
            if bad["dead_letters"] != 1 or not (tmp_root / "dlq2.jsonl").is_file():
                raise AssertionError("死信未落盘")
            return {"first": first, "second": second, "dead": bad}

        checks.append(_check("er-39-siem-dedupe-dlq",
                             "SIEM 闭环：去重/重试/死信 JSONL", delivery))

        def egress():
            policy = EgressPolicy(["127.0.0.1", "splunk.customer.example"], require_tls=True)
            ok = policy.check_url("http://127.0.0.1:8088/services/collector")
            try:
                policy.check_url("http://splunk.customer.example/services/collector")
                raise AssertionError("非回环 HTTP 未被拒绝")
            except DeliveryPolicyError:
                pass
            try:
                policy.check_url("https://evil.example/")
                raise AssertionError("非 allowlist host 未被拒绝")
            except DeliveryPolicyError:
                pass
            return {"loopback": ok, "http_rejected": True, "host_rejected": True}

        checks.append(_check("er-50-siem-egress-policy",
                             "SIEM 出网：allowlist + 非回环强制 TLS + CA/代理", egress))

        def pack():
            root = tmp_root / "pack"
            (root / "evidence").mkdir(parents=True)
            (root / "evidence" / "audit-log.json").write_text('{"ok": true}', encoding="utf-8")
            (root / "evidence" / "rbac-approval.json").write_text('{"ok": true}', encoding="utf-8")
            (root / "evidence" / "sign-manifest.json").write_text('{"sig": "x"}', encoding="utf-8")
            out = tmp_root / "pack.zip"
            built = build_pack([root / "evidence"], out, root=root, framework="djbh",
                               meta={"workspace": "local-lab"})
            verified = verify_pack(out)
            if not verified["ok"]:
                raise AssertionError(f"证据包校验失败：{verified}")
            return {"built": built, "verified": verified}

        checks.append(_check("er-57-evidence-pack",
                             "等保/ISO 证据包：manifest + 控制项索引 + 哈希校验", pack))

        def scale():
            result = run_scale(200_000)
            projection = daily_million_projection(result)
            if result["rows"] != 200_000:
                raise AssertionError(f"读回行数不一致：{result['rows']}")
            return {"scale": result, "projection": projection}

        checks.append(_check("er-16-audit-stream-scale",
                             "审计事件流：20 万合成事件写入/读回/容量外推", scale))

        def gpu_contract():
            plugin = validate_device_plugin({
                "resource_name": "kubernetes.io/gpu", "version": "v1alpha1",
                "endpoint": "/tmp/plugin.sock", "devices": []})
            dra = validate_dra({"apiVersion": "v1", "kind": "ResourceSlice"})
            matrix = compatibility_matrix({"gpu_operator": "25.3.0", "driver": "580.65.06",
                                           "cuda": "12.4", "container_runtime": "containerd"})
            if plugin["ok"] or dra["ok"] or not matrix["ok"]:
                raise AssertionError("GPU 契约校验结果不符合预期")
            return {"device_plugin_findings": len(plugin["findings"]),
                    "dra_findings": len(dra["findings"]), "matrix": matrix}

        checks.append(_check("er-06-gpu-contract",
                             "GPU Operator/device plugin/DRA 契约（本地 schema/版本矩阵）",
                             gpu_contract))
    finally:
        proxy.close()
        registry.close()
        shutil.rmtree(tmp_root, ignore_errors=True)

    passed = sum(1 for c in checks if c["status"] == "PASS")
    result = {
        "schema": "inkblade-enterprise-local-checks/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {"total": len(checks), "passed": passed, "failed": len(checks) - passed,
                    "ok": passed == len(checks)},
        "checks": checks,
        "boundary": "本机 mock/临时目录；不是客户 registry/SIEM/GPU/合规环境验收。",
    }
    result = _scrub_paths(result)
    (out / "local-checks.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "local-checks.md").write_text(render_md(result), encoding="utf-8")
    return result


def _scrub_paths(value):
    """公开树卫生：证据里不留本机绝对路径。"""
    if isinstance(value, str):
        return re.sub(r"[A-Za-z]:[\\/][^\s\"']*", "<local-path>", value)
    if isinstance(value, list):
        return [_scrub_paths(v) for v in value]
    if isinstance(value, dict):
        return {k: _scrub_paths(v) for k, v in value.items()}
    return value


def render_md(result: dict) -> str:
    lines = [
        "# 企业黄项本地补验结果（Enterprise local checks）",
        "",
        f"- 生成时间：{result['generated_at']}",
        f"- 汇总：**{result['summary']['passed']}/{result['summary']['total']} PASS**",
        f"- 边界：{result['boundary']}",
        "",
        "| 检查 | 结果 | 耗时 | 证据摘要 |",
        "|---|---:|---:|---|",
    ]
    for item in result["checks"]:
        ev = json.dumps(item.get("evidence") or {}, ensure_ascii=False)
        evidence_cell = ev[:220].replace("|", "\\|")
        lines.append(f"| `{item['id']}` {item['title']} | {item['status']} | "
                     f"{item['elapsed_ms']} ms | {evidence_cell} |")
        if item.get("error"):
            error_cell = item['error'].replace("|", "\\|")
            lines.append(f"| ↳ error | {error_cell} | | |")
    lines += ["", "复跑：`python -m inkblade.enterprise.localcheck` 或 `inkblade enterprise local-checks`。"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="企业黄项本地可验证部分")
    parser.add_argument("--out", default="reports/samples/enterprise-local")
    args = parser.parse_args()
    doc = run_local_checks(args.out)
    print(json.dumps(doc["summary"], ensure_ascii=False))
    raise SystemExit(0 if doc["summary"]["ok"] else 1)
