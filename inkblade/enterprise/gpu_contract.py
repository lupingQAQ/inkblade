# -*- coding: utf-8 -*-
"""GPU Operator / device plugin / DRA 本地契约校验（ER-06 的本地部分）。

只做 schema/版本矩阵校验，不启动 kubelet、不注册真实 device plugin、不调用 GPU。
真实 device plugin / DRA / GPU Operator 兼容仍需客户 GPU 节点。
"""

from __future__ import annotations

import re

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


def _finding(sev: str, title: str, detail: dict, fix: str = "") -> dict:
    item = {"sev": sev, "title": title, "detail": detail}
    if fix:
        item["fix"] = fix
    return item


def validate_device_plugin(payload: dict) -> dict:
    """kubelet device plugin v1beta1 注册/ListAndWatch 契约。"""
    findings = []
    resource = str(payload.get("resource_name") or payload.get("resourceName") or "")
    version = str(payload.get("version") or "")
    endpoint = str(payload.get("endpoint") or "")
    devices = [d for d in (payload.get("devices") or []) if isinstance(d, dict)]
    if not resource or "/" not in resource:
        findings.append(_finding("high", "device plugin resourceName 缺少域前缀",
                                 {"resource_name": resource},
                                 "使用 vendor.com/gpu 形式，禁止裸 gpu"))
    elif resource.startswith("kubernetes.io/"):
        findings.append(_finding("high", "device plugin 使用保留域 kubernetes.io",
                                 {"resource_name": resource},
                                 "改用厂商自有域"))
    if version not in ("v1beta1", "v1"):
        findings.append(_finding("medium", "device plugin API 版本非 v1beta1/v1",
                                 {"version": version}, "升级到 v1beta1"))
    if not endpoint.startswith("unix://") and not endpoint.startswith("/var/lib/kubelet/"):
        findings.append(_finding("medium", "device plugin endpoint 非 kubelet 插件目录",
                                 {"endpoint": endpoint},
                                 "endpoint 放 /var/lib/kubelet/device-plugins/"))
    if not devices:
        findings.append(_finding("high", "device plugin 未上报设备", {"devices": 0},
                                 "检查 nvidia-device-plugin 与驱动"))
    for device in devices:
        if not device.get("id") or not device.get("health"):
            findings.append(_finding("medium", "device 缺少 id/health",
                                     {"device": device}, "补全 id/health/topology"))
    return {"ok": not findings, "findings": findings,
            "resource_name": resource, "devices": len(devices), "version": version}


def validate_dra(payload: dict) -> dict:
    """DRA ResourceSlice / DeviceClass 基本结构。"""
    findings = []
    api = str(payload.get("apiVersion") or "")
    kind = str(payload.get("kind") or "")
    if not api.startswith("resource.k8s.io/"):
        findings.append(_finding("high", "DRA apiVersion 非 resource.k8s.io/*",
                                 {"apiVersion": api}, "使用 resource.k8s.io/v1beta1 或 v1"))
    if kind not in ("ResourceSlice", "DeviceClass"):
        findings.append(_finding("high", "DRA kind 非 ResourceSlice/DeviceClass",
                                 {"kind": kind}, "导出 ResourceSlice 与 DeviceClass"))
    if kind == "ResourceSlice":
        driver = str(payload.get("driver") or "")
        pool = payload.get("pool") or {}
        devices = [d for d in (payload.get("devices") or []) if isinstance(d, dict)]
        if not driver:
            findings.append(_finding("high", "ResourceSlice 缺少 driver", {}, "设置 driver 名称"))
        if not pool.get("name"):
            findings.append(_finding("medium", "ResourceSlice pool 缺少 name", {}, "补 pool.name"))
        if not devices:
            findings.append(_finding("high", "ResourceSlice 无 devices", {}, "检查 DRA driver"))
        for device in devices:
            if not device.get("name"):
                findings.append(_finding("medium", "DRA device 缺少 name", {"device": device},
                                         "补 name/attributes/capacity"))
    if kind == "DeviceClass":
        selector = payload.get("selectors") or []
        if not selector:
            findings.append(_finding("medium", "DeviceClass 无 CEL selectors",
                                     {"selectors": 0}, "用 CEL 限制设备属性"))
    return {"ok": not findings, "findings": findings, "kind": kind, "apiVersion": api}


def _v(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(text))[:4])


def compatibility_matrix(matrix: dict) -> dict:
    """GPU Operator/驱动/CUDA/容器运行时版本矩阵（本地规则，不是上游认证）。"""
    operator = str(matrix.get("gpu_operator") or "0")
    driver = str(matrix.get("driver") or "0")
    cuda = str(matrix.get("cuda") or "0")
    runtime = str(matrix.get("container_runtime") or "")
    findings = []
    if _v(operator) < (24, 9):
        findings.append(_finding("medium", "GPU Operator < 24.9（DRA/新驱动支持不足）",
                                 {"gpu_operator": operator}, "升级到 >=24.9"))
    if _v(driver) < (550,):
        findings.append(_finding("high", "驱动 < 550 不支持 CUDA 12.4+ 新特性",
                                 {"driver": driver}, "升级驱动并核对 GPU 型号"))
    if _v(cuda) >= (12, 4) and _v(driver) < (550,):
        findings.append(_finding("high", "CUDA 12.4+ 与驱动版本不匹配",
                                 {"cuda": cuda, "driver": driver}, "按 NVIDIA 矩阵升级驱动"))
    if runtime and not runtime.lower().startswith(("containerd", "cri-o", "docker")):
        findings.append(_finding("medium", "未知容器运行时", {"container_runtime": runtime},
                                 "使用 containerd/CRI-O 并启用 CDI"))
    return {"ok": not findings, "findings": findings,
            "gpu_operator": operator, "driver": driver, "cuda": cuda,
            "container_runtime": runtime,
            "note": "本地版本规则；真实兼容需 GPU 节点 + device plugin/DRA 联调。"}


def check_digest_pin(image: str, digest: str) -> dict:
    return {"ok": bool(_SHA.match(str(digest or ""))), "image": image, "digest": digest,
            "pinned": _SHA.match(str(digest or "")) is not None}
