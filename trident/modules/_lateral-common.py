"""横向模块共用：payload 变体探测（core/payloads 驱动，版本矩阵变体数据源）。

用法（HTTP 横向模块 run.py）：
    from trident.modules._lateral_common import VariantProber
    vp = VariantProber(trace, MODULE_KEY)
    hits = vp.probe(method="GET", path="/plugins/list", base_url=target)
    # hits: [{variant, kind, method, url, status}] —— 变体命中差异写 finding detail

策略：
- 变体全部沿用模块主探针的语义面（同一端点），只变形 路径/大小写/点段/编码/方法/头；
- 主探针成功后逐变体重放（默认 ≤2 变体），失败的变体记录 status 差异（指纹稳健性数据）；
- 不引入新写面：POST/PUT 变体仅用于本来即是写语义的端点，body 沿用主探针（含清理语义）。
"""

from __future__ import annotations

from trident.core.payloads import http_variants


class VariantProber:
    """把版本矩阵变体物化并经模块 Trace 执行；返回逐变体命中记录。"""

    def __init__(self, trace, module_key: str, *, limit: int = 2):
        self.trace = trace
        self.module_key = module_key
        self.limit = limit

    def probe(self, *, method: str, path: str, body=None, headers: dict | None = None,
              base_url: str = "") -> list[dict]:
        base = {"method": method, "path": path, "body": body, "headers": headers or {}}
        try:
            variants = http_variants(self.module_key, base, limit=self.limit)
        except ValueError:  # 模块不在矩阵/非 http 面：变体探测降级为空（主探针不受影响）
            return []
        out: list[dict] = []
        for v in variants:
            url = (base_url.rstrip("/") + v["path"]) if base_url else v["path"]
            entry = self.trace.call(v["method"], url, v.get("body"), v.get("headers"))
            out.append({"variant": v["variant"], "kind": v["kind"],
                        "method": v["method"], "url": url,
                        "status": entry.get("status", 0)})
        return out
