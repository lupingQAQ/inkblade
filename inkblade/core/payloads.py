# -*- coding: utf-8 -*-
"""payload 变体库（参数化生成）：版本矩阵变体 → 具体请求/参数变体。

设计：
- 每个横向/绕过模块 ≥2 探针变体（version-matrix.json variants）；
- 本模块把 base 请求（method/path/body/headers）或 base 参数 params 物化为
  逐变体具体形态（路径/大小写/点段/百分号编码/方法/空鉴权头/参数别名）；
- 变体请求一律携带良性语义（沿用 INKBLADE-BENIGN marker 规约），仅用于
  指纹稳健性与绕过面探测，不引入新的写面。

transform 文法（白名单，未知 op 抛 PayloadError）：
  path_suffix  arg=str          追加后缀（通常 "/"）
  path_case                     首段路径改为首字母大写（/pause → /Pause）
  path_dotseg                   最后一段前插入 /./
  pct_encode                    对路径最后段的一个字母做 % 编码
  double_pct_encode             同上再编码一层（%25xx）
  method       arg=METHOD       替换 HTTP 方法（仅 GET/POST/PUT/HEAD）
  header       arg=[name,value] 增设/覆盖请求头（空值探针用）
  query        arg=[key,value]  追加 URL 查询参数
  body_merge   arg={k:v}        JSON body 合并（不新增写语义）
  param        arg=[key,value]  参数面变体（surface=params 模块）
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from .version_matrix import entry, variants_for

_ALLOWED_METHODS = {"GET", "POST", "PUT", "HEAD"}


class PayloadError(ValueError):
    """非法 transform / base 形态。"""


def _pct_encode_once(path: str) -> str:
    segs = path.split("/")
    if len(segs) < 2 or not segs[-1]:
        raise PayloadError(f"路径无法百分号编码: {path!r}")
    last = segs[-1]
    for i, ch in enumerate(last):
        if ch.isalpha():
            enc = f"%{ord(ch):02x}"
            segs[-1] = last[:i] + enc + last[i + 1:]
            return "/".join(segs)
    raise PayloadError(f"路径无可编码字母: {path!r}")


def _apply(op: str, arg: Any, base: dict) -> dict:
    out = {"method": base.get("method", "GET"), "path": base.get("path", "/"),
           "body": base.get("body"), "headers": dict(base.get("headers") or {})}
    path = out["path"]
    if op == "path_suffix":
        if not isinstance(arg, str):
            raise PayloadError("path_suffix 需要 str 参数")
        if arg and not path.endswith(arg):
            out["path"] = path + arg
    elif op == "path_case":
        segs = [s for s in path.split("/") if s]
        if not segs:
            raise PayloadError(f"路径无段可改大小写: {path!r}")
        first = segs[0]
        segs[0] = first[0].upper() + first[1:]
        out["path"] = "/" + "/".join(segs)
    elif op == "path_dotseg":
        if "/" not in path[1:]:
            raise PayloadError(f"路径无中间段可插点段: {path!r}")
        head, _, tail = path[1:].rpartition("/")
        out["path"] = f"/{head}/./{tail}"
    elif op == "pct_encode":
        out["path"] = _pct_encode_once(path)
    elif op == "double_pct_encode":
        once = _pct_encode_once(path)
        out["path"] = once.replace("%", "%25", 1)
    elif op == "method":
        if arg not in _ALLOWED_METHODS:
            raise PayloadError(f"方法变体仅允许 {sorted(_ALLOWED_METHODS)}: {arg!r}")
        out["method"] = arg
    elif op == "header":
        if not (isinstance(arg, (list, tuple)) and len(arg) == 2):
            raise PayloadError("header 需要 [name, value] 参数")
        out["headers"][str(arg[0])] = str(arg[1])
    elif op == "query":
        if not (isinstance(arg, (list, tuple)) and len(arg) == 2):
            raise PayloadError("query 需要 [key, value] 参数")
        joiner = "&" if "?" in path else "?"
        out["path"] = f"{path}{joiner}{urllib.parse.quote(str(arg[0]))}={urllib.parse.quote(str(arg[1]))}"
    elif op == "body_merge":
        if not isinstance(arg, dict):
            raise PayloadError("body_merge 需要 dict 参数")
        body = out.get("body")
        if not isinstance(body, dict):
            raise PayloadError("body_merge 仅适用于 JSON dict body")
        merged = dict(body)
        merged.update(arg)
        out["body"] = merged
    else:
        raise PayloadError(f"未知 transform 操作 {op!r}")
    return out


def materialize(base: dict, transform: dict) -> dict:
    """把单个 transform 应用到 base 请求，返回具体请求形态。"""
    if not isinstance(transform, dict) or "op" not in transform:
        raise PayloadError(f"transform 缺 op: {transform!r}")
    return _apply(transform["op"], transform.get("arg"), base)


def http_variants(module_key: str, base: dict, *, limit: int = 0) -> list[dict]:
    """对 surface=http 模块：返回 [原始请求 + 全部变体请求]，每项带 variant 元数据。

    limit>0 时最多取前 limit 个变体（原始请求不计入）。
    """
    e = entry(module_key)
    if e is None:
        raise PayloadError(f"模块不在版本矩阵: {module_key}")
    if e["surface"] != "http":
        raise PayloadError(f"{module_key}: surface={e['surface']!r}，请用 param_variants")
    variants = variants_for(module_key)
    if limit > 0:
        variants = variants[:limit]
    out: list[dict] = []
    for v in variants:
        req = materialize(base, v["transform"])
        out.append({"variant": v["id"], "kind": v["kind"], "request": v["request"],
                    **req, "url": req["path"]})
    return out


def build_url(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + ("/" + path.lstrip("/") if not path.startswith(base_url) else path)


def param_variants(module_key: str, params: dict, *, limit: int = 0) -> list[dict]:
    """对 surface=params 模块：返回 [原始参数 + 全部变体参数]，每项带 variant 元数据。"""
    e = entry(module_key)
    if e is None:
        raise PayloadError(f"模块不在版本矩阵: {module_key}")
    if e["surface"] != "params":
        raise PayloadError(f"{module_key}: surface={e['surface']!r}，请用 http_variants")
    variants = variants_for(module_key)
    if limit > 0:
        variants = variants[:limit]
    out: list[dict] = []
    for v in variants:
        tr = v["transform"]
        if tr["op"] != "param":
            raise PayloadError(f"{module_key}: params 面只允许 param 变体，得到 {tr['op']!r}")
        if not (isinstance(tr.get("arg"), (list, tuple)) and len(tr["arg"]) == 2):
            raise PayloadError(f"{module_key}: param 变体需要 [key, value]")
        merged = dict(params)
        merged[str(tr["arg"][0])] = tr["arg"][1]
        out.append({"variant": v["id"], "kind": v["kind"], "request": v["request"],
                    "params": merged})
    return out


def variants(module_key: str, base: dict) -> list[dict]:
    """入口分派：按矩阵 surface 自动选择 http/params 物化。base=params dict 时走参数面。"""
    e = entry(module_key)
    if e is None:
        raise PayloadError(f"模块不在版本矩阵: {module_key}")
    if e["surface"] == "http" and {"method", "path"} & set(base):
        return http_variants(module_key, base)
    return param_variants(module_key, base)
