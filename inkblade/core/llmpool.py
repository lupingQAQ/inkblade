# -*- coding: utf-8 -*-
"""LLM 多模型池（clean-room 等价实现）：端点/模型/权重/健康检查/失败切换/配额。

定位与边界：
- **默认关闭**：无 config、``enabled=false`` 或未显式开启时，``complete`` 一律抛
  :class:`PoolDisabled`；``status`` 只读可用。工作区配置 ``llm_pool.json``。
- 仅 OpenAI 兼容协议（``POST {base_url}/chat/completions``，``GET {base_url}/models``
  用于健康检查）；不绑定任何厂商 SDK。
- 加权平滑轮询（smooth weighted round-robin）→ 失败标记冷却（30s 起指数退避，上限 600s）
  → 同一次调用内切换到下一个健康端点；全部失败抛 :class:`NoHealthyEndpoint`。
- 配额：端点级 ``quota_requests`` / ``quota_tokens`` 每日额度（UTC 日切），超额端点
  视为不可选；用量与健康状态持久化在工作区（不存 prompt 正文）。
- 密钥：支持 ``api_key`` 或 ``api_key_env``（推荐后者）；``status`` 只返回是否已配置，
  审计只记录端点 id/模型/token 数，不落 prompt 与密钥。
- 供 explorer 候选排序与报告叙述使用；任何失败都必须由调用方降级到确定性路径。

审计：每次成功/失败的调用追加工作区 ``audit.jsonl``（动作 ``llm.complete``）。
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from . import jsonio
from .env import getenv, lookup

POOL_RELPATH = "llm_pool.json"
RECORDS_RELPATH = "llm_pool_records.jsonl"
DEFAULT_TIMEOUT = 20
MAX_COOLDOWN = 600
MAX_WEIGHT = 100


class PoolError(ValueError):
    """配置/参数非法。"""


class PoolDisabled(PoolError):
    """池未开启（默认状态）。"""


class QuotaExceeded(PoolError):
    """端点/全局配额耗尽。"""


class NoHealthyEndpoint(PoolError):
    """无可用端点（全部失败/冷却/配额耗尽）。"""


def _default_poster(endpoint: dict, messages: list[dict], timeout: float) -> dict:
    url = endpoint["base_url"].rstrip("/") + "/chat/completions"
    body = {"model": endpoint["model"], "temperature": 0, "messages": messages}
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    key = endpoint.get("_resolved_key") or ""
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _default_probe(endpoint: dict, timeout: float) -> bool:
    url = endpoint["base_url"].rstrip("/") + "/models"
    req = urllib.request.Request(url, method="GET")
    key = endpoint.get("_resolved_key") or ""
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= int(resp.status) < 300
    except Exception:
        return False


class LLMPool:
    """工作区级模型池。所有写操作要求 lead/admin（approve）与合法配置。"""

    def __init__(self, store, *, clock: Callable[[], float] = time.time,
                 poster: Callable[[dict, list[dict], float], dict] | None = None):
        self.store = store
        self.path = jsonio.ws_path(store, POOL_RELPATH)
        self._clock = clock
        self._poster = poster or _default_poster
        self._lock = threading.RLock()
        self._credit: dict[str, float] = {}

    # ------------------------------------------------------------ 配置
    def _load(self) -> dict:
        doc = jsonio.read_json(self.path, None)
        if not isinstance(doc, dict):
            doc = {"enabled": False, "endpoints": [], "health": {}, "usage": {}}
        doc.setdefault("enabled", False)
        doc.setdefault("endpoints", [])
        doc.setdefault("health", {})
        doc.setdefault("usage", {})
        return doc

    def _save(self, doc: dict) -> None:
        jsonio.write_json(self.path, doc)

    @property
    def enabled(self) -> bool:
        doc = self._load()
        env = getenv("LLM_POOL", "")
        return bool(doc.get("enabled")) or env == "1"

    def _endpoint(self, doc: dict, ep_id: str) -> dict:
        for ep in doc.get("endpoints", []):
            if ep.get("id") == ep_id:
                return ep
        raise PoolError(f"未知端点 {ep_id}")

    @staticmethod
    def _validate(base_url: str, model: str, weight: int, q_req: int, q_tok: int) -> None:
        if not str(base_url).startswith(("http://", "https://")):
            raise PoolError("base_url 须为 http(s) 地址")
        if not str(model).strip():
            raise PoolError("model 不能为空")
        if not (1 <= int(weight) <= MAX_WEIGHT):
            raise PoolError(f"weight 须在 1-{MAX_WEIGHT}")
        if int(q_req) < 0 or int(q_tok) < 0:
            raise PoolError("配额不能为负")

    def add_endpoint(self, session, *, base_url: str, model: str, api_key: str = "",
                     api_key_env: str = "", weight: int = 1, quota_requests: int = 0,
                     quota_tokens: int = 0, endpoint_id: str = "") -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        self._validate(base_url, model, weight, quota_requests, quota_tokens)
        with self._lock:
            doc = self._load()
            ids = {ep.get("id") for ep in doc["endpoints"]}
            eid = endpoint_id or f"ep-{len(ids) + 1:02d}"
            if eid in ids:
                raise PoolError(f"端点 id 重复 {eid}")
            ep = {
                "id": eid, "base_url": str(base_url).rstrip("/"), "model": str(model),
                "api_key": api_key or "", "api_key_env": api_key_env or "",
                "weight": int(weight), "enabled": True,
                "quota_requests": int(quota_requests), "quota_tokens": int(quota_tokens),
                "created_by": session.name, "created_at": self._clock(),
            }
            doc["endpoints"].append(ep)
            self._save(doc)
        jsonio.append_audit(self.store, session.name, "llm.endpoint.add", eid,
                            {"base_url": ep["base_url"], "model": ep["model"],
                             "weight": ep["weight"]}, "ok")
        return self._mask_endpoint(ep)

    def remove_endpoint(self, session, endpoint_id: str) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        with self._lock:
            doc = self._load()
            self._endpoint(doc, endpoint_id)
            doc["endpoints"] = [e for e in doc["endpoints"] if e.get("id") != endpoint_id]
            doc["health"].pop(endpoint_id, None)
            doc["usage"].pop(endpoint_id, None)
            self._save(doc)
        jsonio.append_audit(self.store, session.name, "llm.endpoint.remove", endpoint_id, {}, "ok")
        return {"removed": endpoint_id}

    def set_enabled(self, session, enabled: bool) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        with self._lock:
            doc = self._load()
            doc["enabled"] = bool(enabled)
            doc["enabled_by"] = session.name
            doc["enabled_at"] = self._clock()
            self._save(doc)
        jsonio.append_audit(self.store, session.name, "llm.pool.enable", "",
                            {"enabled": bool(enabled)}, "ok")
        return {"enabled": bool(enabled)}

    # ------------------------------------------------------------ 选择/健康/配额
    def _api_key(self, ep: dict) -> str:
        if ep.get("api_key_env"):
            return lookup(str(ep["api_key_env"]), "")
        return ep.get("api_key") or ""

    def _health(self, doc: dict, ep_id: str) -> dict:
        h = doc["health"].get(ep_id)
        if not isinstance(h, dict):
            h = {"failures": 0, "cooldown_until": 0.0, "last_error": "", "last_ok": 0.0}
            doc["health"][ep_id] = h
        return h

    @staticmethod
    def _day(now: float) -> str:
        # Windows 的 time.gmtime 不接受负时间戳；用 epoch 偏移保证测试/历史时间可用
        return (datetime(1970, 1, 1, tzinfo=timezone.utc)
                + timedelta(seconds=float(now))).strftime("%Y-%m-%d")

    def _usage(self, doc: dict, ep_id: str, now: float) -> dict:
        day = self._day(now)
        per_ep = doc["usage"].setdefault(ep_id, {})
        # 只保留当日与最近一天，防无限增长
        for old in [d for d in per_ep if d not in (day, self._day(now - 86400))]:
            per_ep.pop(old, None)
        u = per_ep.setdefault(day, {"requests": 0, "tokens": 0})
        u.setdefault("requests", 0)
        u.setdefault("tokens", 0)
        return u

    def _quota_ok(self, ep: dict, doc: dict, now: float) -> bool:
        u = self._usage(doc, ep["id"], now)
        if ep.get("quota_requests") and u["requests"] >= int(ep["quota_requests"]):
            return False
        if ep.get("quota_tokens") and u["tokens"] >= int(ep["quota_tokens"]):
            return False
        return True

    def _eligible(self, doc: dict, now: float) -> list[dict]:
        out = []
        for ep in doc["endpoints"]:
            if not ep.get("enabled", True):
                continue
            h = self._health(doc, ep["id"])
            if float(h.get("cooldown_until") or 0) > now:
                continue
            if not self._quota_ok(ep, doc, now):
                continue
            out.append(ep)
        return out

    def _pick(self, eligible: list[dict]) -> dict:
        """平滑加权轮询：每个端点累加权重，取最高者并扣减总权重。"""
        total = sum(max(1, int(e.get("weight", 1))) for e in eligible)
        for ep in eligible:
            eid = ep["id"]
            self._credit[eid] = self._credit.get(eid, 0.0) + max(1, int(ep.get("weight", 1)))
        chosen = max(eligible, key=lambda e: self._credit.get(e["id"], 0.0))
        self._credit[chosen["id"]] = self._credit.get(chosen["id"], 0.0) - total
        return chosen

    def _failure(self, doc: dict, ep: dict, error: str, now: float) -> None:
        h = self._health(doc, ep["id"])
        h["failures"] = int(h.get("failures", 0)) + 1
        backoff = min(MAX_COOLDOWN, 30 * (2 ** (h["failures"] - 1)))
        h["cooldown_until"] = now + backoff
        h["last_error"] = error[:300]

    def _success(self, doc: dict, ep: dict, now: float) -> None:
        h = self._health(doc, ep["id"])
        h["failures"] = 0
        h["cooldown_until"] = 0.0
        h["last_error"] = ""
        h["last_ok"] = now

    # ------------------------------------------------------------ 调用
    def complete(self, messages: list[dict], *, purpose: str = "", temperature: float = 0.0,
                 max_tokens: int | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict:
        """按权重选择端点调用；失败自动切换；返回文本/端点/用量。"""
        if not self.enabled:
            raise PoolDisabled("LLM 池未开启（默认关闭；lead 审批后 set_enabled(true)）")
        if not messages:
            raise PoolError("messages 为空")
        attempts: list[dict] = []
        with self._lock:
            doc = self._load()
            now = self._clock()
            eligible = self._eligible(doc, now)
            if not eligible:
                raise NoHealthyEndpoint("无可用端点（全部禁用/冷却/配额耗尽）")
            last_err = ""
            for _ in range(len(eligible)):
                ep = self._pick(eligible)
                ep = dict(ep)
                ep["_resolved_key"] = self._api_key(ep)
                start = self._clock()
                try:
                    payload = self._poster(ep, messages, float(timeout))
                    content = _content_of(payload)
                    if not content:
                        raise ValueError("空响应内容")
                    usage = payload.get("usage") or {}
                    tokens = int(usage.get("total_tokens") or
                                 int(usage.get("prompt_tokens") or 0) +
                                 int(usage.get("completion_tokens") or 0) or
                                 max(1, len(content) // 4))
                    u = self._usage(doc, ep["id"], now)
                    u["requests"] += 1
                    u["tokens"] += tokens
                    self._success(doc, ep, now)
                    self._save(doc)
                    latency = round((self._clock() - start) * 1000, 1)
                    jsonio.append_audit(self.store, "llmpool", "llm.complete", ep["id"],
                                        {"purpose": purpose, "model": ep["model"],
                                         "tokens": tokens, "latency_ms": latency}, "ok")
                    self._append_record({"ok": True, "endpoint": ep["id"], "model": ep["model"],
                                         "purpose": purpose, "tokens": tokens,
                                         "latency_ms": latency, "ts": self._clock()})
                    return {"text": content, "endpoint": ep["id"], "model": ep["model"],
                            "usage": {"tokens": tokens},
                            "latency_ms": latency, "attempts": attempts + [{"endpoint": ep["id"], "ok": True}]}
                except Exception as exc:
                    last_err = f"{type(exc).__name__}: {exc}"
                    self._failure(doc, ep, last_err, now)
                    self._save(doc)
                    attempts.append({"endpoint": ep["id"], "ok": False, "error": last_err})
                    eligible = [e for e in eligible if e["id"] != ep["id"]]
                    if not eligible:
                        break
            jsonio.append_audit(self.store, "llmpool", "llm.complete", "",
                                {"purpose": purpose, "attempts": attempts}, "failed")
        self._append_record({"ok": False, "endpoint": "", "model": "", "purpose": purpose,
                             "tokens": 0, "latency_ms": 0, "ts": self._clock(),
                             "error": last_err[:300]})
        raise NoHealthyEndpoint(f"全部端点失败：{last_err}")

    def complete_text(self, prompt: str, **kwargs) -> dict:
        return self.complete([{"role": "user", "content": prompt}], **kwargs)

    def health_check(self, session, *, probe: Callable[[dict, float], bool] | None = None,
                     timeout: float = 5.0) -> dict:
        """主动健康检查（网络动作，须 approve 且池已开启）。"""
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        if not self.enabled:
            raise PoolDisabled("LLM 池未开启，拒绝发起健康检查")
        probe = probe or _default_probe
        results: dict[str, dict] = {}
        with self._lock:
            doc = self._load()
            now = self._clock()
            for ep in doc["endpoints"]:
                if not ep.get("enabled", True):
                    results[ep["id"]] = {"ok": False, "skipped": "disabled"}
                    continue
                e = dict(ep)
                e["_resolved_key"] = self._api_key(ep)
                try:
                    ok = bool(probe(e, float(timeout)))
                except Exception:
                    ok = False
                if ok:
                    self._success(doc, ep, now)
                else:
                    self._failure(doc, ep, "health check failed", now)
                results[ep["id"]] = {"ok": ok,
                                     "cooldown_until": self._health(doc, ep["id"]).get("cooldown_until", 0)}
            self._save(doc)
        jsonio.append_audit(self.store, session.name, "llm.pool.health", "",
                            {"results": results}, "ok")
        return {"results": results, "checked_at": self._clock()}

    def reset(self, session, endpoint_id: str = "", *, usage: bool = False) -> dict:
        """重置健康状态（可选同时清用量）；不改变 enabled 与端点配置。"""
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        with self._lock:
            doc = self._load()
            ids = [ep["id"] for ep in doc["endpoints"]]
            if endpoint_id:
                self._endpoint(doc, endpoint_id)
                ids = [endpoint_id]
            for eid in ids:
                doc["health"].pop(eid, None)
                self._credit.pop(eid, None)
                if usage:
                    doc["usage"].pop(eid, None)
            self._save(doc)
        jsonio.append_audit(self.store, session.name, "llm.pool.reset", endpoint_id,
                            {"usage": bool(usage)}, "ok")
        return {"reset": ids, "usage_cleared": bool(usage)}

    # ------------------------------------------------------------ 调用留档（仅元数据）
    def _records_path(self) -> Path:
        return jsonio.ws_path(self.store, RECORDS_RELPATH)

    def _append_record(self, record: dict) -> None:
        path = self._records_path()
        rows = self._read_records(limit=100000)
        rec = {"id": f"llm-{len(rows) + 1:06d}", **record,
               "workspace": getattr(self.store, "workspace", "")}
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True, default=str) + "\n")

    def _read_records(self, limit: int = 500) -> list[dict]:
        return jsonio.tail_jsonl(self._records_path(), limit)

    def records(self, *, limit: int = 100, model: str = "", purpose: str = "") -> list[dict]:
        """调用留档（仅元数据：端点/模型/用途/token/时延/错误；不存 prompt 与响应）。"""
        rows = self._read_records(limit=5000)
        if model:
            rows = [r for r in rows if r.get("model") == model]
        if purpose:
            rows = [r for r in rows if r.get("purpose") == purpose]
        return list(reversed(rows[-max(1, min(int(limit), 1000)):]))

    def record(self, record_id: str) -> dict:
        for r in self.records(limit=1000):
            if r.get("id") == record_id:
                return r
        raise PoolError(f"未知调用记录 {record_id}")

    def records_by_model(self) -> dict:
        out: dict[str, dict] = {}
        for r in self._read_records(limit=100000):
            model = str(r.get("model") or "unknown")
            item = out.setdefault(model, {"model": model, "calls": 0, "tokens": 0,
                                          "errors": 0, "last_ts": 0})
            item["calls"] += 1
            item["tokens"] += int(r.get("tokens") or 0)
            item["errors"] += 0 if r.get("ok") else 1
            item["last_ts"] = max(item["last_ts"], float(r.get("ts") or 0))
        return {"by_model": sorted(out.values(), key=lambda x: -x["calls"])}

    def token_stats(self, *, days: int = 14) -> dict:
        rows = self._read_records(limit=100000)
        buckets: dict[str, dict] = {}
        for r in rows:
            day = self._day(float(r.get("ts") or 0))
            b = buckets.setdefault(day, {"date": day, "calls": 0, "tokens": 0, "errors": 0})
            b["calls"] += 1
            b["tokens"] += int(r.get("tokens") or 0)
            b["errors"] += 0 if r.get("ok") else 1
        ordered = sorted(buckets.values(), key=lambda x: x["date"])[-max(1, int(days)):]
        return {"days": ordered,
                "totals": {"calls": sum(b["calls"] for b in ordered),
                           "tokens": sum(b["tokens"] for b in ordered),
                           "errors": sum(b["errors"] for b in ordered)}}

    def models(self) -> list[dict]:
        return [{"endpoint": ep["id"], "model": ep.get("model", ""),
                 "base_url": ep.get("base_url", "")}
                for ep in self._load().get("endpoints", []) if ep.get("enabled", True)]

    def clear_records(self, session) -> dict:
        if not session.can("approve"):
            raise PermissionError(f"{session.name}({session.role}) 无 approve 权限")
        path = self._records_path()
        n = len(self._read_records(limit=100000))
        if path.exists():
            path.write_text("", encoding="utf-8")
        jsonio.append_audit(self.store, session.name, "llm.records.clear", "",
                            {"cleared": n}, "ok")
        return {"cleared": n}

    # ------------------------------------------------------------ 只读视图
    @staticmethod
    def _mask_endpoint(ep: dict) -> dict:
        out = {k: v for k, v in ep.items() if k not in ("api_key",)
               and not k.startswith("_")}
        out["api_key_set"] = bool(ep.get("api_key") or ep.get("api_key_env"))
        if ep.get("api_key_env"):
            out["api_key_env"] = ep["api_key_env"]
            out["api_key_env_set"] = bool(lookup(str(ep["api_key_env"])))
        return out

    def status(self) -> dict:
        doc = self._load()
        now = self._clock()
        endpoints = []
        for ep in doc["endpoints"]:
            h = self._health(doc, ep["id"])
            u = self._usage(doc, ep["id"], now)
            endpoints.append({
                **self._mask_endpoint(ep),
                "healthy": float(h.get("cooldown_until") or 0) <= now and bool(ep.get("enabled", True)),
                "cooldown_until": h.get("cooldown_until", 0.0),
                "failures": h.get("failures", 0),
                "last_error": h.get("last_error", ""),
                "used_today": dict(u),
                "quota_ok": self._quota_ok(ep, doc, now),
            })
        return {"enabled": self.enabled, "config_path": str(self.path),
                "endpoints": endpoints, "count": len(endpoints),
                "healthy": sum(1 for e in endpoints if e["healthy"] and e["quota_ok"])}


def _content_of(payload: dict) -> str:
    try:
        choice = (payload.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        return str(msg.get("content") or choice.get("text") or "").strip()
    except Exception:
        return ""


def pool_available(store) -> bool:
    """ explorer/报告叙述的探测入口：默认关闭时恒 False。"""
    try:
        return LLMPool(store).enabled and bool(LLMPool(store).status()["endpoints"])
    except Exception:
        return False


def _json_sequence(text: str) -> list[str]:
    raw = text.strip()
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1] if raw.count("```") >= 2 else raw
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw
    start, end = raw.find("{"), raw.rfind("}")
    if start >= 0 and end > start:
        raw = raw[start:end + 1]
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise PoolError(f"LLM 输出非 JSON：{exc}") from exc
    seq = doc.get("sequence") if isinstance(doc, dict) else None
    if not isinstance(seq, list):
        raise PoolError("LLM 输出缺少 sequence 列表")
    return [str(s) for s in seq]


def rank_candidates(store, candidates: list[dict], context: dict, *,
                    purpose: str = "explorer.rank") -> list[str]:
    """用池对候选模块排序；调用方负责在异常时降级 rules。"""
    pool = LLMPool(store)
    prompt = json.dumps({
        "role": "You are an authorized pentest planner. Rank the NEXT module sequence "
                "(max 5) for an ML-cluster pentest from candidates only. "
                "Reply JSON: {\"sequence\": [\"module-key\", ...]}.",
        "candidates": [c.get("module") for c in candidates],
        "context": context,
    }, ensure_ascii=False)
    res = pool.complete_text(prompt, purpose=purpose)
    return _json_sequence(res["text"])


def narrate(store, facts: dict) -> dict:
    """报告叙述：池开启时用 LLM，否则确定性模板；任何异常均降级。"""
    runs = int(facts.get("runs", 0) or 0)
    findings = int(facts.get("findings", 0) or 0)
    critical = int(facts.get("critical", 0) or 0)
    chains = int(facts.get("chains", 0) or 0)
    fallback = (
        f"本工作区累计 {runs} 个 run、{findings} 条发现（critical {critical} 条）、"
        f"{chains} 条攻击链评估。所有结论均可回链到 run 证据库（actions/findings/归档三层）。"
    )
    if not pool_available(store):
        return {"mode": "deterministic", "text": fallback}
    try:
        prompt = (
            "你是授权红队报告撰写者。仅依据下列事实写一段不超过 160 字的中文摘要，"
            "不得编造未给出的事实：\n" + json.dumps(facts, ensure_ascii=False)
        )
        res = LLMPool(store).complete_text(prompt, purpose="report.narrative")
        return {"mode": "llm", "text": res["text"], "endpoint": res["endpoint"]}
    except Exception as exc:
        return {"mode": "deterministic", "text": fallback,
                "note": f"LLM 降级：{type(exc).__name__}: {exc}"}
