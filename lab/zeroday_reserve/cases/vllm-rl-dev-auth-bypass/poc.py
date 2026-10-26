"""vLLM 0.32.0 RL control router bypasses --api-key (real router + real middleware).

The PoC loads the verbatim upstream router and AuthenticationMiddleware, builds
the same FastAPI surface (real routes + real auth middleware) and drives it with
Starlette's TestClient.  The engine client is a stub because this host has no
GPU; the auth decision and route dispatch are the real vLLM code.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any, Literal

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import poclib  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _stub_vllm() -> None:
    """Install only the interfaces the upstream RL router imports."""
    packages = [
        "vllm", "vllm.distributed", "vllm.distributed.weight_transfer",
        "vllm.engine", "vllm.entrypoints", "vllm.entrypoints.rl",
        "vllm.entrypoints.rl.online", "vllm.v1",
    ]
    for name in packages:
        mod = types.ModuleType(name)
        mod.__path__ = []  # type: ignore[attr-defined]
        sys.modules[name] = mod

    base = types.ModuleType("vllm.distributed.weight_transfer.base")

    class WeightTransferInitRequest:
        def __init__(self, init_info=None):
            self.init_info = init_info or {}

    class WeightTransferUpdateRequest:
        def __init__(self, update_info=None):
            self.update_info = update_info or {}

    base.WeightTransferInitRequest = WeightTransferInitRequest
    base.WeightTransferUpdateRequest = WeightTransferUpdateRequest
    base.WeightTransferUpdatePayload = dict[str, Any] | list[dict[str, Any]]
    sys.modules["vllm.distributed.weight_transfer.base"] = base

    protocol = types.ModuleType("vllm.engine.protocol")
    protocol.EngineClient = object
    sys.modules["vllm.engine.protocol"] = protocol

    metrics = types.ModuleType("vllm.entrypoints.rl.online.metrics")

    class _Metrics:
        @contextlib.contextmanager
        def record(self, operation):
            yield

    metrics.weight_operation_metrics = lambda: _Metrics()
    sys.modules["vllm.entrypoints.rl.online.metrics"] = metrics

    logger = types.ModuleType("vllm.logger")
    logger.init_logger = lambda name: __import__("logging").getLogger(name)
    sys.modules["vllm.logger"] = logger

    v1 = types.ModuleType("vllm.v1.engine")
    v1.PauseMode = Literal["abort", "wait", "keep"]
    sys.modules["vllm.v1.engine"] = v1


class FakeEngine:
    def __init__(self):
        self.calls: list[str] = []

    async def pause_generation(self, mode="abort", clear_cache=True):
        self.calls.append(f"pause_generation(mode={mode},clear_cache={clear_cache})")
        poclib.mark(poclib.MARKER_TEXT + ":pause")

    async def resume_generation(self):
        self.calls.append("resume_generation")

    async def abort(self, request_ids, internal=False):
        self.calls.append(f"abort({len(request_ids)},internal={internal})")

    async def is_paused(self):
        return False

    async def get_weight_version(self):
        self.calls.append("get_weight_version")
        return "w0"

    async def collective_rpc(self, name):
        self.calls.append(f"collective_rpc({name})")
        poclib.mark(poclib.MARKER_TEXT + ":reset_weights")
        return [0]

    async def update_weights(self, request):
        self.calls.append("update_weights")
        return None

    async def init_weight_transfer_engine(self, request):
        self.calls.append("init_weight_transfer_engine")

    async def shutdown_weight_transfer_engine(self):
        self.calls.append("shutdown_weight_transfer_engine")

    async def start_weight_update(self):
        self.calls.append("start_weight_update")

    async def start_draft_weight_update(self):
        self.calls.append("start_draft_weight_update")

    async def finish_weight_update(self, weight_version=None):
        self.calls.append("finish_weight_update")

    async def update_weight_version(self, version):
        self.calls.append("update_weight_version")

    async def compute_weight_checksums(self):
        self.calls.append("compute_weight_checksums")
        return [{"w": "abc"}]

    @property
    def vllm_config(self):
        return types.SimpleNamespace(parallel_config=types.SimpleNamespace(world_size_across_dp=8, world_size=1))


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    _stub_vllm()

    upstream = poclib.UPSTREAM / "vllm-0.32.0"
    auth_path = upstream / "vllm/entrypoints/serve/middleware/authenticate.py"
    router_path = upstream / "vllm/entrypoints/rl/online/api_router.py"
    factories_path = upstream / "vllm/entrypoints/rl/factories.py"
    for path in (auth_path, router_path, factories_path):
        if not path.is_file():
            poclib.fail(f"missing pinned upstream source: {path}")

    poclib.start_marker()
    auth = _load("vllm.entrypoints.serve.middleware.authenticate", auth_path)
    router = _load("vllm.entrypoints.rl.online.api_router", router_path)
    factories = _load("vllm.entrypoints.rl.factories", factories_path)

    app = FastAPI()

    @app.get("/v1/ping")
    async def ping():
        return {"ok": True}

    # Real registration helper from 0.32.0: app.include_router(rl_router) with no prefix.
    factories.register_rl_api_routers(app)
    app.state.engine_client = FakeEngine()
    app.add_middleware(auth.AuthenticationMiddleware, tokens=["secret-key"])

    observed = []
    with TestClient(app) as client:
        observed.append(("GET /v1/ping no token", client.get("/v1/ping").status_code))
        observed.append(("GET /v1/ping bearer", client.get("/v1/ping", headers={"Authorization": "Bearer secret-key"}).status_code))
        observed.append(("POST /pause no token", client.post("/pause").status_code))
        observed.append(("POST /weight_checker reset no token", client.post("/weight_checker", json={"action": "reset"}).status_code))
        observed.append(("GET /weight_info no token", client.get("/weight_info").status_code))
        observed.append(("POST /update_weights no token", client.post("/update_weights", json={"update_info": {}}).status_code))
        observed.append(("POST /pause wrong token", client.post("/pause", headers={"Authorization": "Bearer wrong"}).status_code))

    status = {name: code for name, code in observed}
    if status["GET /v1/ping no token"] != 401:
        poclib.fail("/v1/ping was not protected; the middleware fixture is not faithful", observed=observed)
    if status["POST /pause no token"] != 200 or status["POST /weight_checker reset no token"] != 200:
        poclib.fail("root-mounted RL control routes did not execute without a token", observed=observed)
    if not poclib.marker_ok():
        poclib.fail("marker was not written inside the real RL route handlers", observed=observed)

    poclib.finish_verified({
        "transport": {
            "type": "FastAPI/Starlette ASGI TestClient",
            "upstream": "vLLM v0.32.0",
            "router": poclib.rel(router_path),
            "middleware": poclib.rel(auth_path),
            "mount": "app.include_router(rl_router) with no prefix",
            "guarded_prefix": list(auth.GUARDED_PREFIX),
            "source_sha256": {
                "router": poclib.sha256_file(router_path),
                "middleware": poclib.sha256_file(auth_path),
                "factories": poclib.sha256_file(factories_path),
            },
            "commit": manifest["version_ref"]["commit"],
        },
        "request_response": [{"request": k, "status": v} for k, v in observed],
        "engine_calls": app.state.engine_client.calls,
        "state_before": "marker=ABSENT",
        "state_after": "marker contains proof text from /pause and /weight_checker",
    })


if __name__ == "__main__":
    main()
