# -*- coding: utf-8 -*-
"""SA-token / Pod-shell bootstrap for the first probe.

Uses kubectl (or an injected runner for tests) only for bootstrap: apply/wait,
``cp`` the static probe, and start the runtime.  The SA token is never written
to a command line; a private temporary kubeconfig carries it.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from .base import EntryError, ExecResult
from ..channel import kubectl_probe_command, mask_token
from ..probe.deploy import ProbeDeploySpec, pod_manifest, render_manifest

REMOTE_PROBE = "/tmp/.inkblade-probe"
REMOTE_TOKEN = "/tmp/.inkblade-probe-token"


@dataclass
class Foothold:
    namespace: str
    pod: str
    container: str = ""
    probe_path: str = REMOTE_PROBE
    token_file: str = REMOTE_TOKEN
    kubeconfig: str | None = None
    created_pod: bool = False
    kubectl: str = "kubectl"
    commands: list[str] = field(default_factory=list)
    manifest: dict[str, Any] | None = None
    cleanup: list[str] = field(default_factory=list)

    def channel_command(self, *, read_only: bool = True, allow_cmds: Sequence[str] = ()) -> list[str]:
        return kubectl_probe_command(
            self.kubectl,
            namespace=self.namespace,
            pod=self.pod,
            probe_path=self.probe_path,
            token_file=self.token_file,
            container=self.container or None,
            kubeconfig=self.kubeconfig,
            read_only=read_only,
            allow_cmds=allow_cmds,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace, "pod": self.pod, "container": self.container,
            "probe_path": self.probe_path, "token_file": self.token_file,
            "kubeconfig": self.kubeconfig, "created_pod": self.created_pod,
            "kubectl": self.kubectl,
            "commands": list(self.commands), "manifest": self.manifest,
            "cleanup": list(self.cleanup),
        }


class KubeconfigFactory:
    """Create a private JSON kubeconfig from an SA token + CA.  JSON is YAML."""

    def __init__(self, *, server: str, token: str, ca_path: str | None = None,
                 namespace: str = "default", ca_data: str | None = None):
        self.server = str(server).rstrip("/")
        self.token = token
        self.ca_path = ca_path
        self.ca_data = ca_data
        self.namespace = namespace
        self.path: str | None = None

    def create(self) -> str:
        ca_data = self.ca_data or ""
        if not ca_data and self.ca_path:
            import base64
            try:
                ca_data = base64.b64encode(Path(self.ca_path).read_bytes()).decode("ascii")
            except OSError as exc:
                raise EntryError(f"cannot read CA {self.ca_path}: {exc}") from exc
        document = {
            "apiVersion": "v1", "kind": "Config",
            "clusters": [{"name": "inkblade-sa", "cluster": {
                "server": self.server, "certificate-authority-data": ca_data,
            }}],
            "users": [{"name": "inkblade-sa", "user": {"token": self.token}}],
            "contexts": [{"name": "inkblade-sa", "context": {
                "cluster": "inkblade-sa", "user": "inkblade-sa",
                "namespace": self.namespace,
            }}],
            "current-context": "inkblade-sa",
        }
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".kubeconfig", delete=False)
        try:
            json.dump(document, handle, ensure_ascii=False)
            handle.flush()
            handle.close()
            os.chmod(handle.name, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            try:
                os.unlink(handle.name)
            except OSError:
                pass
            raise
        self.path = handle.name
        return self.path

    def cleanup(self) -> None:
        if self.path:
            try:
                os.unlink(self.path)
            except OSError:
                pass
            self.path = None


class SaTokenProbe:
    def __init__(
        self,
        *,
        namespace: str,
        pod: str = "",
        container: str = "",
        token: str = "",
        server: str = "",
        ca_path: str | None = None,
        kubeconfig: str | None = None,
        create_pod: bool = False,
        image: str = "busybox:1.36",
        name: str = "",
        kubectl: str = "kubectl",
        read_only: bool = True,
        allow_cmds: Sequence[str] = (),
        runner: Callable[..., Any] | None = None,
        dry_run: bool = False,
        timeout: int = 60,
    ):
        if not token and not kubeconfig:
            raise EntryError("SA entry needs --token/--token-file or --kubeconfig")
        self.namespace = namespace
        self.pod = pod
        self.container = container
        self.token = token
        self.server = server
        self.ca_path = ca_path
        self.kubeconfig = kubeconfig
        self.create_pod = create_pod
        self.image = image
        self.name = name or f"inkblade-probe-{int(time.time()) % 100000}"
        self.kubectl = kubectl
        self.read_only = read_only
        self.allow_cmds = list(allow_cmds)
        self.runner = runner or self._default_runner
        self.dry_run = dry_run
        self.timeout = int(timeout)
        self.factory: KubeconfigFactory | None = None
        self._local_files: list[str] = []
        self.commands: list[str] = []

    @staticmethod
    def _default_runner(args: Sequence[str], input_data: bytes | None = None,
                        env: dict[str, str] | None = None):
        return subprocess.run(
            list(args), input=input_data, env=env,
            capture_output=True, timeout=120,
        )

    def _kubeconfig_path(self) -> str | None:
        if self.kubeconfig:
            return self.kubeconfig
        if self.factory is None:
            if not self.server:
                raise EntryError("SA entry needs --server (or a kubeconfig)")
            self.factory = KubeconfigFactory(
                server=self.server, token=self.token, ca_path=self.ca_path,
                namespace=self.namespace,
            )
        return self.factory.create()

    def _base_args(self) -> list[str]:
        args = [self.kubectl]
        kubeconfig = self._kubeconfig_path()
        if kubeconfig:
            args += ["--kubeconfig", kubeconfig]
        return args

    def run(self, args: Sequence[str], input_data: bytes | None = None) -> ExecResult:
        command = [*self._base_args(), *args]
        if self.dry_run:
            self.commands.append(" ".join(command))
            return ExecResult(exit_code=0, stdout="(dry-run)")
        result = self.runner(command, input_data=input_data)
        stdout = getattr(result, "stdout", b"") or b""
        stderr = getattr(result, "stderr", b"") or b""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        code = int(getattr(result, "returncode", 1))
        return ExecResult(exit_code=code, stdout=str(stdout), stderr=str(stderr))

    def _temp_file(self, data: bytes, suffix: str) -> str:
        handle = tempfile.NamedTemporaryFile("wb", suffix=suffix, delete=False)
        handle.write(data)
        handle.close()
        os.chmod(handle.name, stat.S_IRUSR | stat.S_IWUSR)
        self._local_files.append(handle.name)
        return handle.name

    def _pod_manifest(self) -> dict[str, Any]:
        spec = ProbeDeploySpec(
            namespace=self.namespace, name=self.name, image=self.image,
            probe_path=REMOTE_PROBE, token_file=REMOTE_TOKEN,
            read_only=self.read_only, allow_write=not self.read_only,
            allow_cmds=self.allow_cmds,
        )
        document = pod_manifest(spec)
        # The probe is copied in after the Pod is running; the image only has
        # to provide a shell/tar (busybox is enough).
        document["spec"]["containers"][0]["command"] = ["sleep", "infinity"]
        document["spec"]["containers"][0].pop("args", None)
        return document

    def deploy(self, probe_bytes: bytes, *, probe_token: str, remote_probe: str = REMOTE_PROBE,
               remote_token: str = REMOTE_TOKEN) -> Foothold:
        if not probe_bytes:
            raise EntryError("probe binary is empty")
        self.commands = []
        manifest = self._pod_manifest() if self.create_pod else None
        if self.create_pod:
            if not self.pod:
                self.pod = self.name
            self.run(["apply", "-f", "-"], input_data=render_manifest(manifest).encode("utf-8"))
            self.run(["wait", "--for=condition=Ready", f"pod/{self.pod}", "--timeout",
                      f"{self.timeout}s"])
        if not self.pod:
            raise EntryError("SA entry needs --pod or --create-pod")
        local_probe = self._temp_file(probe_bytes, ".probe")
        local_token = self._temp_file(probe_token.encode("utf-8"), ".token")
        target = f"{self.namespace}/{self.pod}"
        self.run(["cp", local_probe, f"{target}:{remote_probe}"])
        self.run(["exec", "-n", self.namespace, self.pod,
                  *(("-c", self.container) if self.container else ()),
                  "--", "chmod", "0700", remote_probe])
        self.run(["cp", local_token, f"{target}:{remote_token}"])
        self.run(["exec", "-n", self.namespace, self.pod,
                  *(("-c", self.container) if self.container else ()),
                  "--", "chmod", "0400", remote_token])
        foothold = Foothold(
            namespace=self.namespace, pod=self.pod, container=self.container,
            probe_path=remote_probe, token_file=remote_token,
            kubeconfig=self.factory.path if self.factory else self.kubeconfig,
            created_pod=self.create_pod, commands=list(self.commands),
            manifest=manifest, kubectl=self.kubectl,
            cleanup=[
                f"kubectl -n {self.namespace} exec {self.pod} -- rm -f {remote_probe} {remote_token}",
                *([f"kubectl -n {self.namespace} delete pod {self.pod}"] if self.create_pod else []),
            ],
        )
        return foothold

    def close(self, foothold: Foothold | None = None) -> None:
        for path in self._local_files:
            try:
                os.unlink(path)
            except OSError:
                pass
        self._local_files.clear()
        if self.factory:
            self.factory.cleanup()


def deploy_sa(
    probe_bytes: bytes,
    *,
    namespace: str,
    probe_token: str,
    token: str = "",
    server: str = "",
    ca_path: str | None = None,
    kubeconfig: str | None = None,
    pod: str = "",
    container: str = "",
    create_pod: bool = False,
    image: str = "busybox:1.36",
    read_only: bool = True,
    allow_cmds: Sequence[str] = (),
    dry_run: bool = False,
    runner: Callable[..., Any] | None = None,
) -> Foothold:
    entry = SaTokenProbe(
        namespace=namespace, pod=pod, container=container, token=token,
        server=server, ca_path=ca_path, kubeconfig=kubeconfig,
        create_pod=create_pod, image=image, read_only=read_only,
        allow_cmds=allow_cmds, runner=runner, dry_run=dry_run,
    )
    return entry.deploy(probe_bytes, probe_token=probe_token)
