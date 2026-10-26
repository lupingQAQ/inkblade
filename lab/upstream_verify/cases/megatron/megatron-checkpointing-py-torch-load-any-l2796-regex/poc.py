"""megatron-checkpointing-py-torch-load-any-l2796-regex: sink exists but is unreachable.

``load_biencoder_checkpoint`` builds the checkpoint path with

    get_checkpoint_name(load_path, iteration, args.use_distributed_optimizer, release=False)

while the callee signature is ``get_checkpoint_name(checkpoints_path, iteration,
release=False, ...)``.  The third positional argument already binds ``release``,
so the additional ``release=False`` keyword raises ``TypeError`` on every call -
``torch.load`` at line 2796 is never reached.

This PoC drives the real upstream function against a real poisoned checkpoint
directory and records the observed failure instead of claiming a reproduction.
"""

from __future__ import annotations

import json
import pickle
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "lab" / "upstream_verify"))
from stublib import StubTree  # noqa: E402


def _materialize(marker_path: str):
    Path(marker_path).write_text("UNREACHABLE", encoding="utf-8")
    return {"model": []}


class _Payload:
    def __reduce__(self):
        return (_materialize, (str(poclib.MARKER_FILE),))


def main() -> None:
    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    source = poclib.upstream_path(manifest["root_cause"]["source"])
    if not source.is_file():
        poclib.fail(f"missing pinned upstream source: {source}")

    tree = StubTree(["megatron"]).install()
    tree.seed("megatron.core.msc_utils")
    tree.seed("megatron.core", mpu=types.SimpleNamespace(get_data_parallel_rank=lambda: 0))
    tree.seed("megatron.training")
    module = tree.load(source, "megatron.training.checkpointing")

    poclib.start_marker("ABSENT")
    root = poclib.EVIDENCE_DIR / "checkpoint"
    if root.exists():
        import shutil

        shutil.rmtree(root)
    (root / "iter_0000001" / "mp_rank_00").mkdir(parents=True)
    (root / "latest_checkpointed_iteration.txt").write_text("1", encoding="utf-8")
    (root / "iter_0000001" / "mp_rank_00" / "model_optim_rng.pt").write_bytes(
        pickle.dumps(_Payload(), protocol=4)
    )

    module.get_args = lambda: types.SimpleNamespace(load=str(root), use_distributed_optimizer=False)
    module.unwrap_model = lambda model: model
    error = None
    try:
        module.load_biencoder_checkpoint([object()], custom_load_path=str(root))
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    reached_sink = poclib.marker_ok()
    signature = None
    try:
        import inspect

        signature = str(inspect.signature(module.get_checkpoint_name))
    except Exception:
        pass

    if reached_sink:
        poclib.fail("sink unexpectedly reachable; re-classify this case as verified", error=error)

    poclib.unsupported_result(
        manifest,
        reason=(
            "sink unreachable in core_v0.19.2: load_biencoder_checkpoint passes "
            "args.use_distributed_optimizer as the third positional argument of "
            "get_checkpoint_name (already bound to `release`) and also passes release=False, "
            "so every call raises TypeError before torch.load(line 2796)"
        ),
        evidence={
            "entrypoint": "megatron.training.checkpointing.load_biencoder_checkpoint",
            "source": poclib.rel(source),
            "source_sha256": poclib.sha256_file(source),
            "get_checkpoint_name_signature": signature,
            "observed_error": error,
            "sink_reached": reached_sink,
            "marker_after": poclib.read_text(poclib.MARKER_FILE, "").strip(),
            "stubbed_modules": tree.manifest()["stubbed_modules"],
        },
    )


if __name__ == "__main__":
    main()
