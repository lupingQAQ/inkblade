# -*- coding: utf-8 -*-
"""Generate hardened Pod / EphemeralContainer / Job manifests for the probe.

The probe binary is a static Rust/musl executable.  Manifests default to:

* non-root (65532), no privilege escalation, all capabilities dropped;
* read-only root filesystem, RuntimeDefault seccomp;
* no hostPath volumes, no service-account token automount;
* an explicit token Secret mount and a small memory-backed /tmp;
* the probe itself in ``--read-only`` mode.

HostPath is only possible through ``allow_host_path=True``, which callers must
surface as a deliberate, audited choice.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

PROBE_IMAGE_DEFAULT = "ghcr.io/inkblade/inkblade-probe:0.1.0"
PROBE_BINARY = "/opt/inkblade/inkblade-probe"
PROBE_TMP = "/tmp"
DEFAULT_USER = 65532


class ProbeDeployError(ValueError):
    pass


@dataclass
class ProbeDeploySpec:
    namespace: str = "default"
    name: str = "inkblade-probe"
    image: str = PROBE_IMAGE_DEFAULT
    probe_path: str = PROBE_BINARY
    token_secret: str | None = None
    token_key: str = "token"
    token_file: str = "/var/run/inkblade/token"
    read_only: bool = True
    allow_write: bool = False
    service_account: str | None = None
    automount_token: bool = False
    session: str | None = None
    node_name: str | None = None
    allow_cmds: list[str] = field(default_factory=list)
    mounts: list[dict[str, Any]] = field(default_factory=list)
    host_path: str | None = None
    allow_host_path: bool = False
    resources: dict[str, Any] = field(default_factory=lambda: {
        "requests": {"cpu": "10m", "memory": "24Mi"},
        "limits": {"cpu": "250m", "memory": "128Mi"},
    })
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    active_deadline_seconds: int | None = 900
    ttl_seconds_after_finished: int = 300

    def validate(self) -> None:
        if not self.namespace or not self.name:
            raise ProbeDeployError("namespace and name are required")
        if self.allow_write:
            self.read_only = False
        if self.host_path and not self.allow_host_path:
            raise ProbeDeployError(
                "hostPath is disabled by default; pass allow_host_path=True explicitly"
            )
        if self.token_secret is None and self.token_file:
            # The caller can upload a token file after deployment; the manifest
            # simply omits the Secret volume.
            pass
        for mount in self.mounts:
            if mount.get("hostPath") and not self.allow_host_path:
                raise ProbeDeployError("hostPath mounts are disabled by default")


def _labels(spec: ProbeDeploySpec) -> dict[str, str]:
    labels = {
        "app.kubernetes.io/name": "inkblade-probe",
        "app.kubernetes.io/component": "in-pod-probe",
        "inkblade.io/probe": "true",
    }
    if spec.session:
        labels["inkblade.io/session"] = spec.session
    labels.update({str(k): str(v) for k, v in spec.labels.items()})
    return labels


def _security_context() -> dict[str, Any]:
    return {
        "runAsNonRoot": True,
        "runAsUser": DEFAULT_USER,
        "runAsGroup": DEFAULT_USER,
        "fsGroup": DEFAULT_USER,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _container_security_context() -> dict[str, Any]:
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "privileged": False,
        "capabilities": {"drop": ["ALL"]},
    }


def _mounts(spec: ProbeDeploySpec) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    volumes: list[dict[str, Any]] = [
        {"name": "probe-tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "32Mi"}},
    ]
    mounts: list[dict[str, Any]] = [
        {"name": "probe-tmp", "mountPath": PROBE_TMP, "readOnly": False},
    ]
    if spec.token_secret:
        volumes.append({
            "name": "probe-token",
            "secret": {
                "secretName": spec.token_secret,
                "items": [{"key": spec.token_key, "path": "token"}],
                "defaultMode": 0o400,
            },
        })
        mounts.append({
            "name": "probe-token",
            "mountPath": str(Path(spec.token_file).parent),
            "readOnly": True,
        })
    if spec.host_path:
        volumes.append({
            "name": "probe-hostpath",
            "hostPath": {"path": spec.host_path, "type": "Directory"},
        })
        mounts.append({
            "name": "probe-hostpath",
            "mountPath": "/host",
            "readOnly": True,
        })
    for index, mount in enumerate(spec.mounts):
        name = str(mount.get("name") or f"probe-mount-{index}")
        volume: dict[str, Any] = {"name": name}
        if mount.get("configMap"):
            volume["configMap"] = {"name": str(mount["configMap"])}
        elif mount.get("secret"):
            volume["secret"] = {"secretName": str(mount["secret"])}
        elif mount.get("pvc"):
            volume["persistentVolumeClaim"] = {"claimName": str(mount["pvc"])}
        elif mount.get("hostPath"):
            if not spec.allow_host_path:
                raise ProbeDeployError("hostPath mounts require allow_host_path=True")
            volume["hostPath"] = {"path": str(mount["hostPath"])}
        else:
            raise ProbeDeployError(f"mount {name} needs configMap/secret/pvc/hostPath")
        volumes.append(volume)
        mounts.append({
            "name": name,
            "mountPath": str(mount.get("mountPath") or f"/mnt/probe-{index}"),
            "readOnly": bool(mount.get("readOnly", True)),
        })
    return volumes, mounts


def _container(spec: ProbeDeploySpec) -> dict[str, Any]:
    command = [
        spec.probe_path, "run", "--stdio",
        "--token-file", spec.token_file,
        "--read-only" if spec.read_only else "--allow-write",
    ]
    for command_name in spec.allow_cmds:
        command += ["--allow-cmd", str(command_name)]
    volumes, mounts = _mounts(spec)
    del volumes
    return {
        "name": "probe",
        "image": spec.image,
        "imagePullPolicy": "IfNotPresent",
        "command": command,
        "securityContext": _container_security_context(),
        "volumeMounts": mounts,
        "resources": spec.resources,
        "terminationMessagePolicy": "FallbackToLogsOnError",
    }


def _pod_spec(spec: ProbeDeploySpec) -> dict[str, Any]:
    volumes, _ = _mounts(spec)
    pod_spec: dict[str, Any] = {
        "automountServiceAccountToken": bool(spec.automount_token),
        "securityContext": _security_context(),
        "containers": [_container(spec)],
        "volumes": volumes,
        "terminationGracePeriodSeconds": 5,
    }
    if spec.service_account:
        pod_spec["serviceAccountName"] = spec.service_account
    if spec.node_name:
        pod_spec["nodeName"] = spec.node_name
    if spec.active_deadline_seconds:
        pod_spec["activeDeadlineSeconds"] = int(spec.active_deadline_seconds)
    return pod_spec


def pod_manifest(spec: ProbeDeploySpec) -> dict[str, Any]:
    spec.validate()
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": spec.name,
            "namespace": spec.namespace,
            "labels": _labels(spec),
            "annotations": {
                "inkblade.io/runtime": "rust-probe",
                "inkblade.io/read-only": str(spec.read_only).lower(),
                **{str(k): str(v) for k, v in spec.annotations.items()},
            },
        },
        "spec": _pod_spec(spec),
    }


def ephemeral_manifest(spec: ProbeDeploySpec, *, target_pod: str) -> dict[str, Any]:
    spec.validate()
    if not spec.token_secret:
        raise ProbeDeployError("ephemeral containers cannot mount a new token volume; set token_secret")
    container = _container(spec)
    container["name"] = spec.name
    # Ephemeral containers cannot add volumes or resources.  Use an env var
    # from a Secret instead of a token-file mount; existing pod volumes are not
    # assumed.  This is a one-shot collect/debug surface, not a file channel.
    container.pop("resources", None)
    container.pop("volumeMounts", None)
    container["command"] = [
        spec.probe_path, "run", "--stdio",
        "--read-only" if spec.read_only else "--allow-write",
    ]
    container["env"] = [{
        "name": "INKBLADE_PROBE_TOKEN",
        "valueFrom": {"secretKeyRef": {"name": spec.token_secret,
                                        "key": spec.token_key}},
    }]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": target_pod,
            "namespace": spec.namespace,
            "annotations": {
                "inkblade.io/runtime": "rust-probe",
                "inkblade.io/ephemeral": "true",
            },
        },
        "spec": {"ephemeralContainers": [container]},
    }


def job_manifest(spec: ProbeDeploySpec) -> dict[str, Any]:
    spec.validate()
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": spec.name,
            "namespace": spec.namespace,
            "labels": _labels(spec),
        },
        "spec": {
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": int(spec.ttl_seconds_after_finished),
            "template": {
                "metadata": {"labels": _labels(spec)},
                "spec": {**_pod_spec(spec), "restartPolicy": "Never"},
            },
        },
    }


def manifest(kind: str, spec: ProbeDeploySpec, *, target_pod: str | None = None) -> dict[str, Any]:
    kind = kind.lower()
    if kind == "pod":
        return pod_manifest(spec)
    if kind in ("ephemeral", "ephemeralcontainer", "ephemeral-container"):
        if not target_pod:
            raise ProbeDeployError("ephemeral manifest requires target_pod")
        return ephemeral_manifest(spec, target_pod=target_pod)
    if kind == "job":
        return job_manifest(spec)
    raise ProbeDeployError(f"unknown manifest kind {kind!r}")


def render_manifest(document: dict[str, Any]) -> str:
    """JSON is valid YAML and parses with kubectl without a YAML dependency."""
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def _asset_names() -> list[str]:
    return [
        "inkblade-probe-linux-amd64",
        "inkblade-probe-linux-arm64",
        "inkblade-probe",
        "inkblade-probe.exe",
    ]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def find_probe_binary(explicit: str | Path | None = None) -> Path | None:
    if explicit:
        path = Path(explicit)
        return path if path.is_file() else None
    env = os.environ.get("INKBLADE_PROBE_BIN")
    if env and Path(env).is_file():
        return Path(env)
    root = _repo_root()
    candidates = [
        *[root / "dist" / name for name in _asset_names()],
        root / "probe" / "target" / "release" / "inkblade-probe",
        root / "probe" / "target" / "release" / "inkblade-probe.exe",
        root / "probe" / "target" / "debug" / "inkblade-probe",
        root / "probe" / "target" / "debug" / "inkblade-probe.exe",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def load_probe_binary(
    path: str | Path | None = None,
    *,
    allow_non_elf: bool = False,
) -> tuple[bytes, str, str]:
    """Return (bytes, sha256, arch).  Linux deployment requires an ELF binary."""
    resolved = find_probe_binary(path)
    if resolved is None:
        raise ProbeDeployError(
            "probe binary not found; build it with cargo (linux-musl) or set INKBLADE_PROBE_BIN"
        )
    data = resolved.read_bytes()
    if len(data) < 20 or data[:4] != b"\x7fELF":
        if not allow_non_elf:
            raise ProbeDeployError(
                f"{resolved} is not a Linux ELF binary; use the CI-built musl asset"
            )
        return data, hashlib.sha256(data).hexdigest(), "unknown"
    machine = int.from_bytes(data[18:20], "little")
    arch = {0x3E: "x86_64", 0xB7: "aarch64"}.get(machine, f"elf-{machine}")
    return data, hashlib.sha256(data).hexdigest(), arch


def release_assets(dist: str | Path) -> list[dict[str, str]]:
    """Describe release asset names and checksums (used by CI/docs)."""
    root = Path(dist)
    rows = []
    for name in _asset_names():
        path = root / name
        if path.is_file():
            rows.append({
                "name": name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": str(path.stat().st_size),
            })
    return rows
