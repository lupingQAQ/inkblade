# -*- coding: utf-8 -*-
"""三层记忆：working（run 上下文）/ episodic（evidence DB 检索）/ semantic（资产与技能图谱）。

- **working**：有界队列，超限按「头部保留 + 中部摘要 + 尾部保留」压缩（head-tail-digest），
  摘要保留被压缩条目的 refs 与 sha256，引用不丢；
- **episodic**：跨 run 检索 evidence.db 的 findings/steps（标题/明细/摘要），
  返回 ``{layer, score, text, ref}``；
- **semantic**：资产库（assets.db）+ 模块注册表 knowledge + 已批准技能；
- ``retrieve`` 融合三层并按分数降序；``compact`` 输出压缩前后计数与摘要。

打分：CJK 逐字、拉丁按词；score = 命中词数 / 查询词数（0..1），确定性可复现。
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

LAYERS = ("working", "episodic", "semantic")
_WORD_RE = re.compile(r"[a-z0-9]+")
_CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def _tokens(text: str) -> set[str]:
    text = (text or "").lower()
    return set(_WORD_RE.findall(text)) | set(_CJK_RE.findall(text))


def score(query: str, text: str) -> float:
    q = _tokens(query)
    if not q:
        return 0.0
    return round(len(q & _tokens(text)) / len(q), 4)


class WorkingMemory:
    """run 级工作记忆：有界、可压缩、引用可追溯。"""

    def __init__(self, capacity: int = 32):
        if capacity < 2:
            raise ValueError("capacity 须 ≥2")
        self.capacity = capacity
        self._items: list[dict] = []

    def add(self, text: str, *, kind: str = "note", ref: str = "") -> dict:
        item = {"text": str(text), "kind": kind, "ref": ref}
        self._items.append(item)
        if len(self._items) > self.capacity:
            self._items = self._items[-self.capacity:]
        return dict(item)

    def items(self) -> list[dict]:
        return [dict(i) for i in self._items]

    def __len__(self) -> int:
        return len(self._items)

    def context(self) -> list[dict]:
        return self.items()

    def compact(self, *, max_items: int | None = None, keep_tail: int = 1) -> dict:
        before = len(self._items)
        if max_items is None:
            max_items = min(self.capacity, max(3, before // 2))
        if before <= max_items:
            return {"strategy": "head-tail-digest", "before": before, "after": before,
                    "dropped": 0, "digest": ""}
        head_n = 1 if max_items >= 3 else 0
        tail_n = max(1, keep_tail) if max_items >= 2 else 0
        tail_n = min(tail_n, max_items - head_n - (1 if max_items - head_n - tail_n >= 0 else 0))
        middle = self._items[head_n:before - tail_n] if tail_n else self._items[head_n:]
        if not middle:  # 没有可压缩内容
            return {"strategy": "head-tail-digest", "before": before, "after": before,
                    "dropped": 0, "digest": ""}
        payload = json.dumps([m["text"] for m in middle], ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        digest_item = {
            "text": f"[compacted {len(middle)} items digest={digest}]",
            "kind": "compacted",
            "ref": f"sha256:{digest}",
            "refs": [m.get("ref", "") for m in middle if m.get("ref")],
        }
        head = self._items[:head_n]
        tail = self._items[before - tail_n:] if tail_n else []
        self._items = head + [digest_item] + tail
        return {"strategy": "head-tail-digest", "before": before, "after": len(self._items),
                "dropped": len(middle), "digest": digest}


class Memory:
    def __init__(self, store, *, modules_dir: Path | str | None = None,
                 skills=None, capacity: int = 32):
        self.store = store
        self.working = WorkingMemory(capacity=capacity)
        self.modules_dir = Path(modules_dir) if modules_dir else Path(store.root) / "modules"
        self.skills = skills

    # ---------------------------------------------------------------- episodic
    def _runs(self) -> list[Path]:
        ws = Path(self.store.ws_dir)
        if not ws.exists():
            return []
        return sorted(p for p in ws.iterdir()
                      if p.is_dir() and not p.name.startswith("_")
                      and (p / "evidence.db").is_file())

    def episodic(self, query: str, k: int = 5) -> list[dict]:
        items: list[dict] = []
        for run_dir in self._runs():
            try:
                run = self.store.open_run(run_dir.name)
                findings = run.query(
                    "SELECT step_key, severity, title, detail FROM findings ORDER BY id")
                steps = run.query("SELECT step_key, result_summary FROM steps ORDER BY id")
            except Exception:  # 损坏/在写的 run 跳过，不阻断检索
                continue
            for step_key, sev, title, detail in findings:
                text = f"{title} {detail}"
                items.append({"layer": "episodic", "text": text.strip(),
                              "kind": "finding", "severity": sev,
                              "ref": f"{run_dir.name}/{step_key}"})
            for step_key, summary in steps:
                items.append({"layer": "episodic", "text": f"{step_key}: {summary}".strip(),
                              "kind": "step", "ref": f"{run_dir.name}/{step_key}"})
        return _rank(query, items, k)

    # ---------------------------------------------------------------- semantic
    def semantic(self, query: str, k: int = 5) -> list[dict]:
        items: list[dict] = []
        # 资产图谱（可选）
        try:
            from .discovery import AssetInventory

            for asset in AssetInventory(self.store).list():
                text = (f"{asset.get('asset_key', '')} {asset.get('kind', '')} "
                        f"{asset.get('product', '')} {asset.get('address', '')}")
                items.append({"layer": "semantic", "text": text.strip(),
                              "kind": "asset", "ref": f"asset:{asset.get('asset_key', '')}"})
        except Exception:
            pass
        # 模块知识图谱
        if self.modules_dir.exists():
            try:
                from .registry import load_modules

                for key, meta in load_modules(self.modules_dir).items():
                    text = " ".join([key, meta.series, meta.description or "", meta.knowledge or ""])
                    items.append({"layer": "semantic", "text": text.strip(),
                                  "kind": "module", "ref": f"module:{key}"})
            except Exception:
                pass
        # 已批准技能
        if self.skills is not None:
            try:
                for skill in self.skills.search(""):
                    text = f"{skill['name']} " + " ".join(s["module"] for s in skill["playbook"])
                    items.append({"layer": "semantic", "text": text.strip(),
                                  "kind": "skill", "ref": f"skill:{skill['id']}"})
            except Exception:
                pass
        return _rank(query, items, k)

    # ---------------------------------------------------------------- 融合
    def retrieve(self, query: str, k: int = 5, layers: tuple[str, ...] = LAYERS) -> list[dict]:
        bad = [layer for layer in layers if layer not in LAYERS]
        if bad:
            raise ValueError(f"未知记忆层 {bad}（仅 {LAYERS}）")
        items: list[dict] = []
        if "working" in layers:
            for i, item in enumerate(self.working.context()):
                items.append({"layer": "working", "text": item["text"], "kind": item.get("kind", ""),
                              "ref": item.get("ref", ""), "_order": i})
        if "episodic" in layers:
            items += self.episodic(query, k=max(k, 5))
        if "semantic" in layers:
            items += self.semantic(query, k=max(k, 5))
        return _rank(query, items, k)

    def compact(self) -> dict:
        return self.working.compact(max_items=min(self.working.capacity,
                                                  max(3, len(self.working) // 2)))


def _rank(query: str, items: list[dict], k: int) -> list[dict]:
    order = {layer: i for i, layer in enumerate(LAYERS)}
    scored = []
    for item in items:
        s = score(query, item.get("text", ""))
        if query and s <= 0:
            continue
        scored.append({**item, "score": s})
    scored.sort(key=lambda it: (-it["score"], order.get(it["layer"], 9),
                                it.get("ref", ""), it.get("_order", 0)))
    out = []
    for item in scored[: max(0, k)]:
        item.pop("_order", None)
        out.append(item)
    return out
