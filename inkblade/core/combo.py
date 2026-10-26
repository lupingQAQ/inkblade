"""组合签名矩阵：单组件检测不报、组合成立才产出组合级发现（spec 5.4）。

指纹（fingerprints）= 侦察模块输出的组件存在性布尔表；组合条目的 components
中，字符串为必需指纹键，数组为「任一成员满足即可」的替代组。全部 required
组件命中才产出 ComboHit。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# 命名规范：机器键纯小写单词（禁数字编号）
KEY_RE = re.compile(r"^[a-z][a-z-]*$")

DEFAULT_PATH = Path(__file__).resolve().parent / "data" / "combo-matrix.json"


@dataclass
class ComboHit:
    """组合级发现：signature/title/knowledge/evidence 指针齐全。"""

    signature: str
    title: str
    title_en: str
    category: str
    components: list
    risk: str
    risk_en: str
    modules: list[str]
    knowledge: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "signature": self.signature,
            "title": self.title,
            "title_en": self.title_en,
            "category": self.category,
            "components": self.components,
            "risk": self.risk,
            "risk_en": self.risk_en,
            "modules": list(self.modules),
            "knowledge": self.knowledge,
            "evidence": list(self.evidence),
        }


def _component_satisfied(comp, fingerprints: dict) -> bool:
    if isinstance(comp, list):
        return any(_component_satisfied(c, fingerprints) for c in comp)
    return fingerprints.get(comp) is True


class ComboMatrix:
    def __init__(self, entries: list[dict]):
        self._entries = entries
        for e in entries:
            sig = e.get("signature", "")
            if not KEY_RE.match(sig):
                raise ValueError(f"组合签名键非法（须纯小写单词）：{sig!r}")
            for m in e.get("modules", []):
                if not KEY_RE.match(m):
                    raise ValueError(f"条目 {sig} 模块键非法：{m!r}")

    @property
    def entries(self) -> list[dict]:
        return self._entries

    def match(self, fingerprints: dict) -> list[ComboHit]:
        """全部 required 组件命中才产出；显式 False / 缺失均不算命中。"""
        hits: list[ComboHit] = []
        for e in self._entries:
            if not all(_component_satisfied(c, fingerprints) for c in e["components"]):
                continue
            hits.append(
                ComboHit(
                    signature=e["signature"],
                    title=e["title"]["zh"],
                    title_en=e["title"]["en"],
                    category=e.get("category", ""),
                    components=e["components"],
                    risk=e["risk"]["zh"],
                    risk_en=e["risk"]["en"],
                    modules=list(e.get("modules", [])),
                    knowledge=e.get("knowledge", ""),
                    evidence=list(e.get("evidence", [])),
                )
            )
        return hits


def load(path: str | Path | None = None) -> ComboMatrix:
    p = Path(path) if path is not None else DEFAULT_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    return ComboMatrix(data["entries"])


def match(fingerprints: dict, path: str | Path | None = None) -> list[ComboHit]:
    """便捷入口：加载默认矩阵并匹配。"""
    return load(path).match(fingerprints)
